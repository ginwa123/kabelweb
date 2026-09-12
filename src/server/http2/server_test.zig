const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const constants = @import("constants.zig");
const connection = @import("connection.zig");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const server_h2 = @import("server.zig");

const http_server = @import("../http_server.zig");
const http_parser = @import("../http_parser.zig");
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
        try writeAll(self.client, inbound.items);

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
