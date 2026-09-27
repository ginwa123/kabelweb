//! h2c server glue: socket loop + dispatch onto the existing router.
//!
//! This file is the bridge between the protocol driver (`connection.zig`, which
//! knows nothing about sockets or routes) and the HTTP/1.1 server
//! (`../http_server.zig`, which owns the router, CORS/security gates and the
//! per-request arena).
//!
//! Dispatch is deliberately a *parallel* implementation of the h1 path in
//! `http_server.zig:handle` rather than a refactor of it: the h1 path interleaves
//! `sendToClient` calls with its dispatch decisions, so extracting a shared
//! dispatcher would have touched the hot path this change is not allowed to
//! disturb. The shared building blocks (`security.*`, `router.matchRoute`,
//! `http_parser.parseRequest/notFound`) are reused verbatim, so behaviour stays
//! aligned; see docs/http2.md for the follow-up that unifies them.

const std = @import("std");
const builtin = @import("builtin");

const constants = @import("constants.zig");
const connection = @import("connection.zig");
const hpack = @import("hpack.zig");
const stream_mod = @import("../stream.zig");

const http_server = @import("../http_server.zig");
const http_parser = @import("../http_parser.zig");
const gserverz_context = @import("../context.zig");
const router = @import("../router.zig");
const security = @import("../security.zig");

pub const Options = connection.Options;

/// Largest single read from the socket. 16 KiB matches the default maximum frame
/// size, so a full DATA frame usually arrives in one read.
const read_chunk = 16 * 1024;

/// Serve one HTTP/2 connection over `conn` — a plaintext socket (h2c, chosen by
/// the connection-preface sniff) or a TLS connection whose ALPN negotiated `h2`
/// (chosen after the handshake, which is how browsers get HTTP/2 at all).
pub fn serveConnection(
    server: *http_server.GinwaServer,
    conn: stream_mod.Stream,
    alloc: std.mem.Allocator,
    initial: []const u8,
    opts: Options,
) !void {
    var h2_conn = connection.Connection.init(alloc, opts);
    defer h2_conn.deinit();

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    var scratch: [read_chunk]u8 = undefined;

    try h2_conn.feed(initial);

    while (true) {
        try serveReady(server, alloc, &h2_conn);
        try h2_conn.flush();
        try h2_conn.drain(&out);
        if (out.items.len > 0) {
            conn.writeAll(out.items) catch break;
            out.clearRetainingCapacity();
        }
        if (h2_conn.isClosed()) break;
        // The peer asked to shut down: finish what is queued, then close.
        if (h2_conn.isClosing() and !h2_conn.hasPendingOutput()) break;

        const n = conn.read(&scratch) catch break;
        if (n == 0) break; // clean EOF
        h2_conn.feed(scratch[0..n]) catch break;
    }
}

/// Run every request the driver has fully received, in arrival order.
fn serveReady(server: *http_server.GinwaServer, alloc: std.mem.Allocator, conn: *connection.Connection) !void {
    while (conn.nextRequest()) |req| {
        var pairs: std.ArrayList(hpack.Pair) = .empty;
        defer pairs.deinit(alloc);
        var status: u16 = 500;
        var body: []const u8 = "Internal Server Error";

        dispatch(server, alloc, req, &pairs, &status, &body) catch |err| {
            std.debug.print("HTTP2: dispatch failed for {s} {s}: {s}\n", .{ req.method, req.path, @errorName(err) });
            status = 500;
            body = "Internal Server Error";
            pairs.clearRetainingCapacity();
        };

        try conn.respond(req.stream_id, .{ .status = status, .headers = pairs.items, .body = body });
        conn.recycleRequestMemory();
    }
}

/// Route a decoded h2 request and produce (status, headers, body).
fn dispatch(
    server: *http_server.GinwaServer,
    alloc: std.mem.Allocator,
    req: *const connection.Request,
    pairs: *std.ArrayList(hpack.Pair),
    status: *u16,
    body: *[]const u8,
) !void {
    // Reuse the h1 parser by synthesizing a request line + headers. That keeps
    // query-string decoding, `params` plumbing, cookie/session extraction and
    // Content-Length handling byte-for-byte identical across both codecs.
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(alloc);
    try raw.appendSlice(alloc, req.method);
    try raw.append(alloc, ' ');
    try raw.appendSlice(alloc, req.path);
    try raw.appendSlice(alloc, " HTTP/2\r\n");
    for (req.headers) |h| {
        try raw.appendSlice(alloc, h.name);
        try raw.appendSlice(alloc, ": ");
        try raw.appendSlice(alloc, h.value);
        try raw.appendSlice(alloc, "\r\n");
    }
    var cl_buf: [24]u8 = undefined;
    const cl = std.fmt.bufPrint(&cl_buf, "content-length: {d}\r\n\r\n", .{req.body.len}) catch unreachable;
    try raw.appendSlice(alloc, cl);
    try raw.appendSlice(alloc, req.body);

    var hreq = try http_parser.parseRequest(raw.items, alloc, server.io, 0);
    const lookup: gserverz_context.LookupResult = if (server.context_store) |store|
        gserverz_context.contextFromRequest(hreq, store)
    else
        .{ .context = null, .id = null };
    var session = http_parser.Session.init(server.context_store, lookup.context, lookup.id);
    defer session.deinit();
    hreq.session = &session;

    // ─── Engine pre-gate (body cap + origin allowlist) ───────────────────────
    const gate = security.preGateCheck(&hreq, server.cors, server.max_body_bytes) catch .pass;
    if (gate != .pass) {
        const origin = headerValue(hreq, "origin");
        const host = if (server.cors.allowed_origins.len > 0) server.cors.allowed_origins[0] else "your-domain";
        var page = security.buildEngineBlockPage(alloc, gate, origin, host) catch return error.OutOfMemory;
        applySecurityHeaders(server, &page);
        try applyCors(server, &hreq, &page);
        return toResponse(alloc, &page, pairs, status, body);
    }

    // CORS preflight is browser-driven and h2 clients do not send it, but keep
    // the behaviour aligned with h1 if one ever does.
    if (server.cors.enabled and std.mem.eql(u8, hreq.method, "OPTIONS")) {
        var preflight = security.buildPreflightResponse(alloc, &hreq, server.cors) catch return error.OutOfMemory;
        try applyCors(server, &hreq, &preflight);
        return toResponse(alloc, &preflight, pairs, status, body);
    }

    const http_ctx = http_parser.HttpContext{
        .allocator = alloc,
        .io = server.io,
        .allowed_origins = server.cors.allowed_origins,
    };

    const result = server.router.matchRoute(hreq.method, hreq.path, &hreq, http_ctx) orelse {
        // Route miss. The static-dir fallback is fd/h1-shaped, so h2 clients get
        // the same 404 the h1 path would produce for an unknown API route.
        return notFound(alloc, status, body);
    };

    switch (result) {
        .handler => |h| {
            if (h.max_body_bytes != 0 and h.max_body_bytes != server.max_body_bytes) {
                const route_gate = security.preGateCheck(&h.req, .{ .enabled = false }, h.max_body_bytes) catch .pass;
                if (route_gate != .pass) {
                    var page = security.buildEngineBlockPage(alloc, route_gate, null, "this route") catch return error.OutOfMemory;
                    applySecurityHeaders(server, &page);
                    return toResponse(alloc, &page, pairs, status, body);
                }
            }
            if (h.chain.on_pre_handler_fail) |fail_base| {
                const maybe_fail: ?security.HttpResponse = security.buildPreHandlerFailRedirect(
                    alloc,
                    &h.req,
                    server.cors,
                    if (h.max_body_bytes != 0) h.max_body_bytes else security.MAX_BODY_BYTES,
                    fail_base,
                ) catch null;
                if (maybe_fail) |fail_resp| {
                    var gated = fail_resp;
                    try applyCors(server, &h.req, &gated);
                    applySecurityHeaders(server, &gated);
                    return toResponse(alloc, &gated, pairs, status, body);
                }
            }

            var final_res = h.chain.run(h.ctx, h.req, h.res) catch http_parser.internalError("Handler error", alloc);
            try applyCors(server, &h.req, &final_res);
            applySecurityHeaders(server, &final_res);
            return toResponse(alloc, &final_res, pairs, status, body);
        },
        // Streaming transports are HTTP/1.1-only in phase 1 — a browser still
        // uses the h1 connection for them, and an h2 client gets an explicit
        // answer instead of a hang (see docs/http2.md).
        .sse, .websocket => {
            status.* = 501;
            pairs.clearRetainingCapacity();
            body.* = "SSE and WebSocket routes are not available over HTTP/2; use HTTP/1.1";
            try pairs.append(alloc, .{ .name = "content-type", .value = "text/plain; charset=utf-8" });
        },
    }
}

fn notFound(alloc: std.mem.Allocator, status: *u16, body: *[]const u8) !void {
    const res = http_parser.notFound(alloc);
    status.* = res.status_code;
    body.* = res.body;
}

/// CORS response headers, mirroring `GinwaServer.applyCORSResponse` (which is not
/// public) by calling the same `security` helper it wraps.
fn applyCors(server: *http_server.GinwaServer, req: *const http_parser.HttpRequest, resp: *http_parser.HttpResponse) !void {
    return security.applyCORSResponse(resp, req, server.cors);
}

/// Convert an `HttpResponse` into h2 (status, header pairs). Header names are
/// lowercased because RFC 9113 §8.2.1 makes an uppercase field name a
/// PROTOCOL_ERROR on the peer's side — nghttp2 (and therefore curl) rejects it.
fn toResponse(
    alloc: std.mem.Allocator,
    resp: *http_parser.HttpResponse,
    pairs: *std.ArrayList(hpack.Pair),
    status: *u16,
    body: *[]const u8,
) !void {
    status.* = resp.status_code;
    body.* = resp.body;
    pairs.clearRetainingCapacity();
    var it = resp.headers.iterator();
    while (it.next()) |entry| {
        try pairs.append(alloc, .{
            .name = try lowerDup(alloc, entry.key_ptr.*),
            .value = entry.value_ptr.*,
        });
    }
}

/// Server-level security headers (CSP etc.). Wraps the same `security` helper the
/// h1 path uses via `GinwaServer.applySecurityHeadersTo`.
fn applySecurityHeaders(server: *http_server.GinwaServer, resp: *http_parser.HttpResponse) void {
    security.applySecurityHeadersWith(resp, server.security_headers);
}

fn lowerDup(alloc: std.mem.Allocator, name: []const u8) ![]const u8 {
    const out = try alloc.alloc(u8, name.len);
    for (name, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

fn headerValue(req: http_parser.HttpRequest, name: []const u8) ?[]const u8 {
    var it = req.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, name)) return entry.value_ptr.*;
    }
    return null;
}

fn writeAll(fd: i32, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n: isize = if (builtin.os.tag == .windows) blk: {
            const winsock = struct {
                extern "ws2_32" fn send(s: usize, buf: [*]const u8, len: c_int, flags: c_int) c_int;
            };
            break :blk winsock.send(@intCast(fd), bytes.ptr + off, @intCast(bytes.len - off), 0);
        } else blk: {
            const posix_socket = struct {
                extern "c" fn write(fd: c_int, buf: [*]const u8, nbyte: usize) isize;
            };
            break :blk posix_socket.write(fd, bytes.ptr + off, bytes.len - off);
        };
        if (n <= 0) return error.SendFailed;
        off += @intCast(n);
    }
}

fn recvFromSock(fd: i32, buf: []u8, len: usize) isize {
    if (builtin.os.tag == .windows) {
        const winsock = struct {
            extern "ws2_32" fn recv(s: usize, buf_ptr: [*]u8, len: c_int, flags: c_int) c_int;
        };
        return winsock.recv(@intCast(fd), buf.ptr, @intCast(len), 0);
    }
    const posix_socket = struct {
        extern "c" fn read(fd: c_int, buf_ptr: [*]u8, nbyte: usize) isize;
    };
    return posix_socket.read(fd, buf.ptr, len);
}

// ============================================================================
// Tests — moved here from `server_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = server_tests; }` below pulls them into the run.
// ============================================================================

const server_tests = struct {
    const testing = std.testing;

    const frame = @import("frame.zig");
    const server_h2 = @import("server.zig");

    const test_helpers = @import("../test_helpers.zig");

    /// A real `GinwaServer` (no listening socket) driven through a socketpair: this
    /// is the end-to-end contract between the protocol driver and the router.
    fn healthHandler(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
        return res.withBody("ok");
    }

    fn echoHandler(_: http_parser.HttpContext, req: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(res.allocator);
        try out.appendSlice(res.allocator, "echo:");
        try out.appendSlice(res.allocator, req.body);
        return res.withBody(try out.toOwnedSlice(res.allocator));
    }

    fn sseHandler(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
        return res.withBody("nope");
    }

    fn writeAll_server(fd: i32, bytes: []const u8) !void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n: isize = if (builtin.os.tag == .windows) blk: {
                const winsock = struct {
                    extern "ws2_32" fn send(s: usize, buf: [*]const u8, len: c_int, flags: c_int) c_int;
                };
                break :blk winsock.send(@intCast(fd), bytes.ptr + off, @intCast(bytes.len - off), 0);
            } else blk: {
                const posix_socket = struct {
                    extern "c" fn write(fd: c_int, buf: [*]const u8, nbyte: usize) isize;
                };
                break :blk posix_socket.write(fd, bytes.ptr + off, bytes.len - off);
            };
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }

    fn readAll(fd: i32, buf: []u8) !usize {
        var off: usize = 0;
        while (off < buf.len) {
            const n: isize = if (builtin.os.tag == .windows) blk: {
                const winsock = struct {
                    extern "ws2_32" fn recv(s: usize, buf_ptr: [*]u8, len: c_int, flags: c_int) c_int;
                };
                break :blk winsock.recv(@intCast(fd), buf.ptr + off, @intCast(buf.len - off), 0);
            } else blk: {
                const posix_socket = struct {
                    extern "c" fn read(fd: c_int, buf_ptr: [*]u8, nbyte: usize) isize;
                };
                break :blk posix_socket.read(fd, buf.ptr + off, buf.len - off);
            };
            if (n <= 0) return off;
            off += @intCast(n);
        }
        return off;
    }

    /// Everything a test needs: a server with the sample routes, a socketpair and a
    /// request-building helper.
    const Fixture = struct {
        /// Backing allocator for the fixture itself + the captured response bytes.
        alloc: std.mem.Allocator,
        /// Mirrors production: the server and connection allocate from ONE arena that
        /// is reclaimed when the connection ends (`http_server.zig` does the same per
        /// connection), so per-request bookkeeping cannot leak.
        arena: std.heap.ArenaAllocator,
        server: *http_server.GinwaServer,
        pair: [2]std.c.fd_t,
        client: i32,
        server_fd: i32,
        /// Owned by the fixture: `run` returns a slice of this allocation, so the
        /// tests must not free what they get back.
        last_out: []u8 = &.{},

        fn init(alloc: std.mem.Allocator) !*Fixture {
            const f = try alloc.create(Fixture);
            errdefer alloc.destroy(f);
            // The arena must live INSIDE the heap-allocated fixture BEFORE any
            // `.allocator()` handle is taken from it. Taking `.allocator()` from a
            // stack local and then copying the ArenaAllocator into the struct leaves
            // every handle pointing at the dead stack slot (`Allocator.ptr` is the
            // address of the arena itself), so later allocations/frees read garbage.
            // That is exactly what crashed the macOS CI: `ws_manager.destroy()` freed
            // through a stale arena and hit `ArenaAllocator.free`'s
            // `loadFirstNode().?` with an empty node list. Linux only passed because
            // the stale stack bytes happened to survive.
            f.* = .{
                .alloc = alloc,
                .arena = std.heap.ArenaAllocator.init(alloc),
                .server = undefined,
                .pair = undefined,
                .client = -1,
                .server_fd = -1,
                .last_out = &.{},
            };
            const salloc = f.arena.allocator();
            const address = try http_server.Address.init("127.0.0.1", 0);
            const gs = try http_server.GinwaServer.init(salloc, testing.io, address);
            try gs.router.get("/health", healthHandler);
            try gs.router.post("/echo", echoHandler);
            try gs.router.sse("/events", sseHandler);
            const pair = try test_helpers.createSocketPair();
            f.server = gs;
            f.pair = pair;
            f.client = test_helpers.toI32(pair[0]);
            f.server_fd = test_helpers.toI32(pair[1]);
            return f;
        }

        fn deinit(self: *Fixture) void {
            if (self.last_out.len > 0) self.alloc.free(self.last_out);
            test_helpers.closeSocketPair(self.pair);
            self.server.deinit();
            self.arena.deinit();
            self.alloc.destroy(self);
        }

        /// Send the preface + SETTINGS + a GET, then run the server loop to
        /// completion (the peer closes its end, so the loop returns on EOF).
        fn run(self: *Fixture, request: []const u8) ![]u8 {
            var inbound: std.ArrayList(u8) = .empty;
            defer inbound.deinit(self.alloc);
            try inbound.appendSlice(self.alloc, constants.PREFACE);
            try frame.writeFrame(self.alloc, &inbound, .{
                .length = 0,
                .type = .settings,
                .flags = 0,
                .stream_id = 0,
            }, "");
            try inbound.appendSlice(self.alloc, request);
            try writeAll_server(self.client, inbound.items);

            // Close the client's write side so the server loop sees EOF and returns.
            shutdownWrite(self.client);
            try server_h2.serveConnection(self.server, .{ .plain = self.server_fd }, self.arena.allocator(), "", .{});
            // ...then shut OUR write side down so the client's read sees EOF instead
            // of blocking until the fixture is destroyed.
            shutdownWrite(self.server_fd);

            if (self.last_out.len > 0) self.alloc.free(self.last_out);
            const out = try self.alloc.alloc(u8, 64 * 1024);
            const n = try readAll(self.client, out);
            self.last_out = out;
            return out[0..n];
        }
    };

    fn shutdownWrite(fd: i32) void {
        if (builtin.os.tag == .windows) {
            const winsock = struct {
                extern "ws2_32" fn shutdown(s: usize, how: c_int) c_int;
            };
            _ = winsock.shutdown(@intCast(fd), 1); // SD_SEND
        } else {
            const posix_socket = struct {
                extern "c" fn shutdown(fd: c_int, how: c_int) c_int;
            };
            _ = posix_socket.shutdown(fd, 1); // SHUT_WR
        }
    }

    fn writeRequest(alloc: std.mem.Allocator, out: *std.ArrayList(u8), stream_id: u32, method: []const u8, path: []const u8, body: []const u8) !void {
        var pairs = std.ArrayList(hpack.Pair).empty;
        defer pairs.deinit(alloc);
        try pairs.append(alloc, .{ .name = ":method", .value = method });
        try pairs.append(alloc, .{ .name = ":scheme", .value = "http" });
        try pairs.append(alloc, .{ .name = ":path", .value = path });
        try pairs.append(alloc, .{ .name = ":authority", .value = "127.0.0.1" });
        if (body.len > 0) try pairs.append(alloc, .{ .name = "content-type", .value = "text/plain" });

        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(alloc);
        var enc = hpack.Encoder.init(alloc);
        try enc.encode(pairs.items, &block);

        var flags: u8 = constants.flag_end_headers;
        if (body.len == 0) flags |= constants.flag_end_stream;
        try frame.writeFrame(alloc, out, .{
            .length = @intCast(block.items.len),
            .type = .headers,
            .flags = flags,
            .stream_id = stream_id,
        }, block.items);
        if (body.len > 0) {
            try frame.writeFrame(alloc, out, .{
                .length = @intCast(body.len),
                .type = .data,
                .flags = constants.flag_end_stream,
                .stream_id = stream_id,
            }, body);
        }
    }

    fn findFrame(bytes: []const u8, want: constants.FrameType) ?frame.Frame {
        var pos: usize = 0;
        while (pos < bytes.len) {
            const d = frame.decode(bytes[pos..], constants.max_allowed_frame_size) catch return null;
            if (d.frame.header.type == want) return d.frame;
            pos += d.consumed;
        }
        return null;
    }

    fn decodeHeaders(alloc: std.mem.Allocator, payload: []const u8, pairs: *std.ArrayList(hpack.Pair)) !void {
        var dec = hpack.Decoder.init(alloc, 4096, 65536);
        defer dec.deinit();
        try dec.decode(payload, pairs);
    }

    test "fixture: stored allocators point at the fixture's OWN arena, not a stack copy" {
        // Regression for the macOS CI crash (5 h2 server tests, signal ABRT in
        // `ArenaAllocator.free`): taking `.allocator()` from a stack local and THEN
        // copying the ArenaAllocator into the fixture left every allocator inside the
        // server pointing at a dead stack frame. Later frees (`ws_manager.destroy()`)
        // then read garbage and hit `loadFirstNode().?` with an empty node list.
        //
        // Asserting the POINTER IDENTITY makes this deterministic on every platform —
        // the old code only worked by accident (stale stack bytes happening to
        // survive), so the Linux run was green while macOS aborted.
        const f = try Fixture.init(testing.allocator);
        defer f.deinit();

        const arena_addr = @intFromPtr(&f.arena);
        try testing.expectEqual(arena_addr, @intFromPtr(f.arena.allocator().ptr));
        try testing.expectEqual(arena_addr, @intFromPtr(f.server.allocator.ptr));
        try testing.expectEqual(arena_addr, @intFromPtr(f.server.ws_manager.allocator.ptr));
        try testing.expectEqual(arena_addr, @intFromPtr(f.server.sse_manager.allocator.ptr));
    }

    test "server: GET /health over h2 returns 200 with the handler body" {
        const f = try Fixture.init(testing.allocator);
        defer f.deinit();

        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(testing.allocator);
        try writeRequest(testing.allocator, &req, 1, "GET", "/health", "");

        const out = try f.run(req.items);

        // The server must answer with SETTINGS, then HEADERS, then the body.
        _ = findFrame(out, .settings) orelse return error.NoSettings;

        const headers_frame = findFrame(out, .headers) orelse return error.NoHeaders;
        var pairs = std.ArrayList(hpack.Pair).empty;
        defer {
            for (pairs.items) |p| {
                testing.allocator.free(p.name);
                testing.allocator.free(p.value);
            }
            pairs.deinit(testing.allocator);
        }
        try decodeHeaders(testing.allocator, headers_frame.payload, &pairs);
        try testing.expect(pairs.items.len > 0);
        try testing.expectEqualStrings(":status", pairs.items[0].name);
        try testing.expectEqualStrings("200", pairs.items[0].value);

        // Header names must be lowercase on the h2 wire (RFC 9113 §8.2.1).
        for (pairs.items) |p| {
            for (p.name) |c| try testing.expect(!std.ascii.isUpper(c));
        }

        const data = findFrame(out, .data) orelse return error.NoData;
        try testing.expectEqualStrings("ok", data.payload);
        try testing.expect(data.header.flags & constants.flag_end_stream != 0);
    }

    test "server: POST body reaches the handler and its response comes back" {
        const f = try Fixture.init(testing.allocator);
        defer f.deinit();

        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(testing.allocator);
        try writeRequest(testing.allocator, &req, 1, "POST", "/echo", "hello h2");

        const out = try f.run(req.items);

        const data = findFrame(out, .data) orelse return error.NoData;
        try testing.expectEqualStrings("echo:hello h2", data.payload);
    }

    test "server: an SSE route answers 501 over h2 instead of hanging" {
        const f = try Fixture.init(testing.allocator);
        defer f.deinit();

        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(testing.allocator);
        try writeRequest(testing.allocator, &req, 1, "GET", "/events", "");

        const out = try f.run(req.items);

        const headers_frame = findFrame(out, .headers) orelse return error.NoHeaders;
        var pairs = std.ArrayList(hpack.Pair).empty;
        defer {
            for (pairs.items) |p| {
                testing.allocator.free(p.name);
                testing.allocator.free(p.value);
            }
            pairs.deinit(testing.allocator);
        }
        try decodeHeaders(testing.allocator, headers_frame.payload, &pairs);
        try testing.expectEqualStrings("501", pairs.items[0].value);
    }

    test "server: an unknown route is a 404" {
        const f = try Fixture.init(testing.allocator);
        defer f.deinit();

        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(testing.allocator);
        try writeRequest(testing.allocator, &req, 1, "GET", "/nope", "");

        const out = try f.run(req.items);

        const headers_frame = findFrame(out, .headers) orelse return error.NoHeaders;
        var pairs = std.ArrayList(hpack.Pair).empty;
        defer {
            for (pairs.items) |p| {
                testing.allocator.free(p.name);
                testing.allocator.free(p.value);
            }
            pairs.deinit(testing.allocator);
        }
        try decodeHeaders(testing.allocator, headers_frame.payload, &pairs);
        try testing.expectEqualStrings("404", pairs.items[0].value);
    }

    test "server: two requests multiplexed on one connection both get answers" {
        const f = try Fixture.init(testing.allocator);
        defer f.deinit();

        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(testing.allocator);
        try writeRequest(testing.allocator, &req, 1, "GET", "/health", "");
        try writeRequest(testing.allocator, &req, 3, "POST", "/echo", "second");

        const out = try f.run(req.items);

        var pos: usize = 0;
        var headers_count: usize = 0;
        var bodies: usize = 0;
        while (pos < out.len) {
            const d = try frame.decode(out[pos..], constants.max_allowed_frame_size);
            pos += d.consumed;
            switch (d.frame.header.type) {
                .headers => headers_count += 1,
                .data => bodies += 1,
                else => {},
            }
        }
        try testing.expectEqual(@as(usize, 2), headers_count);
        try testing.expectEqual(@as(usize, 2), bodies);
    }
};

comptime {
    _ = server_tests;
}
