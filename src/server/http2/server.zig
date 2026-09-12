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

test {
    _ = @import("server_test.zig");
}
