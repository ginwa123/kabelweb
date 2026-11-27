//! Socket-level proof that gzip reaches the wire; the unit tests live in compression.zig.

const std = @import("std");
const http_server = @import("http_server.zig");
const event_loop = @import("event_loop.zig");
const compression = @import("compression.zig");
const test_tcp = @import("test_tcp.zig");

/// A JSON body comfortably over `compression.default_min_bytes`.
const json_body = "{\"users\":[" ++
    ("{\"id\":1,\"name\":\"ada\",\"role\":\"member\"}," ** 20) ++
    "{\"id\":21,\"name\":\"grace\",\"role\":\"member\"}]}";

fn usersHandler(
    _: http_server.HttpContext,
    _: http_server.HttpRequest,
    res: http_server.HttpResponse,
) anyerror!http_server.HttpResponse {
    return res.withJson(json_body);
}

const ServerThread = struct {
    server: *http_server.GinwaServer,
    cfg: event_loop.Config = .{},
    err: ?anyerror = null,

    fn run(self: *ServerThread) void {
        self.server.listenEventLoop(self.cfg) catch |err| {
            self.err = err;
        };
    }
};

fn readResponse(fd: i32, buf: []u8) ![]u8 {
    var len: usize = 0;
    while (true) {
        if (event_loop.findHeaderEnd(buf[0..len])) |header_end| {
            const content_length = try event_loop.parseContentLength(buf[0..header_end]);
            if (len >= header_end + content_length) return buf[0 .. header_end + content_length];
        }
        if (len >= buf.len) return error.TooMuch;
        const n = try test_tcp.read(fd, buf[len..]);
        if (n == 0) return error.Closed;
        len += n;
    }
}

fn headOf(raw: []const u8) []const u8 {
    const end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return raw;
    return raw[0..end];
}

fn bodyOf(raw: []const u8) []const u8 {
    const end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return "";
    return raw[end + 4 ..];
}

fn inflate(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    var source = std.Io.Reader.fixed(compressed);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress = std.compress.flate.Decompress.init(&source, .gzip, &window);
    return decompress.reader.allocRemaining(allocator, .unlimited);
}

test "a json route is gzipped for an accepting client and identity for one without" {
    const alloc = std.testing.allocator;

    const addr = try http_server.Address.init("127.0.0.1", 0);
    const port = try test_tcp.boundPort(addr.sock_fd);
    try std.testing.expect(port != 0);

    var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
    defer server.destroy(alloc);
    try server.router.get("/users", usersHandler);

    var st = ServerThread{
        .server = server,
        .cfg = .{ .max_conns = 32, .idle_timeout_ms = 10_000, .header_timeout_ms = 2_000 },
    };
    const thread = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
    defer {
        server.shutdown();
        thread.join();
    }
    std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
    if (st.err) |err| return err;

    const fd = try test_tcp.connect(port);
    defer test_tcp.close(fd);

    var buf: [16 * 1024]u8 = undefined;

    // 1. A client that negotiates gzip gets a gzip stream it can inflate.
    try test_tcp.writeAll(fd, "GET /users HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip, deflate\r\n" ++
        "Connection: keep-alive\r\n\r\n");
    const gzipped = try readResponse(fd, &buf);
    const gzipped_head = headOf(gzipped);
    const gzipped_body = bodyOf(gzipped);

    try std.testing.expect(std.mem.indexOf(u8, gzipped_head, "Content-Encoding: gzip") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(gzipped_head, "accept-encoding") != null);
    try std.testing.expectEqual(gzipped_body.len, try event_loop.parseContentLength(gzipped_head));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x1f, 0x8b }, gzipped_body[0..2]);
    try std.testing.expect(gzipped_body.len < json_body.len);
    const decoded = try inflate(alloc, gzipped_body);
    defer alloc.free(decoded);
    try std.testing.expectEqualStrings(json_body, decoded);

    // 2. The same route on the same connection, for a client without the header.
    try test_tcp.writeAll(fd, "GET /users HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    const plain = try readResponse(fd, &buf);
    const plain_head = headOf(plain);
    const plain_body = bodyOf(plain);

    try std.testing.expect(std.mem.indexOf(u8, plain_head, "Content-Encoding") == null);
    try std.testing.expectEqualStrings(json_body, plain_body);
    try std.testing.expectEqual(plain_body.len, try event_loop.parseContentLength(plain_head));
}
