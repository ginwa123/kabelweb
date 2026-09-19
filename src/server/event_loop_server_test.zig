//! End-to-end test for `GinwaServer.listenEventLoop` (Phase 6).
//!
//! Spins a real server with a registered route on an ephemeral loopback
//! port, serves it through the poll reactor in a helper thread, and speaks
//! HTTP/1.1 over blocking TCP: keep-alive reuse, POST echo, 404 framing,
//! and the 501 upgrade responses for SSE/WS routes. This is the dual-path
//! proof that the event-loop dispatch matches the threaded `listen()` path
//! for plain routes.

const std = @import("std");

const http_server = @import("http_server.zig");
const event_loop = @import("event_loop.zig");
const test_tcp = @import("test_tcp.zig");

fn helloHandler(
    ctx: http_server.HttpContext,
    req: http_server.HttpRequest,
    res: http_server.HttpResponse,
) anyerror!http_server.HttpResponse {
    _ = ctx;
    _ = req;
    return res.withBody("event-loop-hi");
}

fn echoHandler(
    ctx: http_server.HttpContext,
    req: http_server.HttpRequest,
    res: http_server.HttpResponse,
) anyerror!http_server.HttpResponse {
    _ = ctx;
    return res.withBody(req.body);
}

fn sseStub(
    ctx: http_server.HttpContext,
    req: http_server.HttpRequest,
    res: http_server.HttpResponse,
) anyerror!http_server.HttpResponse {
    _ = ctx;
    _ = req;
    _ = res;
    return error.Unreachable; // never runs on the event-loop path (501 first)
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

fn tcpConnect(port: u16) !i32 {
    return test_tcp.connect(port);
}

fn writeAll(fd: i32, data: []const u8) !void {
    return test_tcp.writeAll(fd, data);
}

fn readHttpResponse(fd: i32, buf: []u8) ![]u8 {
    var len: usize = 0;
    while (true) {
        if (event_loop.findHeaderEnd(buf[0..len])) |he| {
            const cl = try event_loop.parseContentLength(buf[0..he]);
            if (len >= he + cl) return buf[0 .. he + cl];
        }
        if (len >= buf.len) return error.TooMuch;
        const n = try test_tcp.read(fd, buf[len..]);
        if (n == 0) return error.Closed;
        len += n;
    }
}

/// Ephemeral port of a bound server socket (port 0 → OS-picked).
fn serverPort(sock_fd: i32) !u16 {
    const port = try test_tcp.boundPort(sock_fd);
    try std.testing.expect(port != 0);
    return port;
}

test "listenEventLoop serves routes, echo, 404 and 501s" {
    const alloc = std.testing.allocator;

    // Ephemeral port: bind 0, then discover via getsockname.
    const addr = try http_server.Address.init("127.0.0.1", 0);
    const port = try serverPort(addr.sock_fd);

    var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
    defer server.destroy(alloc);

    try server.router.get("/hello", helloHandler);
    try server.router.post("/echo", echoHandler);
    try server.router.sse("/stream", sseStub);

    var st = ServerThread{
        .server = server,
        .cfg = .{
            .max_conns = 32,
            .idle_timeout_ms = 10_000,
            .header_timeout_ms = 2_000,
        },
    };
    const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
    defer {
        server.shutdown();
        t.join();
    }
    std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
    if (st.err) |err| return err;

    const cfd = try tcpConnect(port);
    defer test_tcp.close(cfd);

    var buf: [8192]u8 = undefined;

    // 1. plain GET route, keep-alive.
    try writeAll(cfd, "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n");
    const r1 = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, r1, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, r1, "event-loop-hi") != null);

    // 2. POST echo with body on the SAME connection.
    const body = "hello-event-loop";
    const req2 = try std.fmt.allocPrint(
        alloc,
        "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\nConnection: keep-alive\r\n\r\n{s}",
        .{ body.len, body },
    );
    defer alloc.free(req2);
    try writeAll(cfd, req2);
    const r2 = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, r2, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, r2, body) != null);

    // 3. unknown path → 404, connection still reusable.
    try writeAll(cfd, "GET /nope HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n");
    const r3 = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, r3, "404") != null);

    // 4. SSE route → 501 + close (v1 scope, documented).
    try writeAll(cfd, "GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    const r4 = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, r4, "501") != null);
}

test "listenEventLoop worker_pool mode serves correctly" {
    const alloc = std.testing.allocator;

    const addr = try http_server.Address.init("127.0.0.1", 0);
    const port = try serverPort(addr.sock_fd);

    var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
    defer server.destroy(alloc);

    try server.router.get("/hello", helloHandler);
    try server.router.post("/echo", echoHandler);

    var st = ServerThread{
        .server = server,
        .cfg = .{
            .max_conns = 32,
            .idle_timeout_ms = 10_000,
            .header_timeout_ms = 2_000,
            .dispatch_mode = .worker_pool,
            .worker_threads = 2,
            .worker_queue_depth = 64,
        },
    };
    const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
    std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
    if (st.err) |err| return err;

    const cfd = try tcpConnect(port);
    defer test_tcp.close(cfd);

    var buf: [8192]u8 = undefined;

    // Keep-alive reuse across pool dispatches.
    try writeAll(cfd, "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n");
    const r1 = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, r1, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, r1, "event-loop-hi") != null);

    // Pipelined pair on the same connection (second arrives while the
    // first is still on the pool — ordering must hold).
    const p1 = "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";
    const p2 = "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping";
    try writeAll(cfd, p1);
    try writeAll(cfd, p2);
    const rp1 = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, rp1, "event-loop-hi") != null);
    const rp2 = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, rp2, "ping") != null);

    // All three responses were received, so every offload completed before
    // shutdown: stats must show 3 pool dispatches, 3 served, no fallback.
    // (Explicit shutdown+join — no defer — so `el_stats` is populated.)
    server.shutdown();
    t.join();
    if (st.err) |err| return err;
    try std.testing.expectEqual(@as(u64, 3), server.el_stats.offloaded);
    try std.testing.expectEqual(@as(u64, 3), server.el_stats.served);
    try std.testing.expectEqual(@as(u64, 0), server.el_stats.inline_fallback);
}

test "listenEventLoop loop_count=2 serves across loops with agg stats (POSIX)" {
    // Multi-loop needs SO_REUSEPORT: POSIX-only by design.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    const addr = try http_server.Address.init("127.0.0.1", 0);
    const port = try serverPort(addr.sock_fd);

    var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
    defer server.destroy(alloc);

    try server.router.get("/hello", helloHandler);

    const MultiThread = struct {
        srv: *http_server.GinwaServer,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.srv.listenEventLoop(.{
                .max_conns = 64,
                .idle_timeout_ms = 10_000,
                .header_timeout_ms = 2_000,
                .loop_count = 2,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var mt = MultiThread{ .srv = server };
    const t = try std.Thread.spawn(.{}, MultiThread.run, .{&mt});
    std.Io.sleep(std.testing.io, .{ .nanoseconds = 150 * std.time.ns_per_ms }, .real) catch {};
    if (mt.err) |err| return err;

    // 8 connections × 2 keep-alive requests = 16 served, spread by the
    // kernel across both REUSEPORT loops.
    const n_conns = 8;
    var fds: [n_conns]i32 = undefined;
    for (&fds) |*fd| fd.* = try tcpConnect(port);
    defer {
        for (fds) |fd| test_tcp.close(fd);
    }

    var buf: [8192]u8 = undefined;
    for (fds) |fd| {
        for (0..2) |k| {
            const ka: []const u8 = if (k == 0) "keep-alive" else "close";
            const req = try std.fmt.allocPrint(
                alloc,
                "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: {s}\r\n\r\n",
                .{ka},
            );
            defer alloc.free(req);
            try writeAll(fd, req);
            const resp = try readHttpResponse(fd, &buf);
            try std.testing.expect(std.mem.indexOf(u8, resp, "200 OK") != null);
            try std.testing.expect(std.mem.indexOf(u8, resp, "event-loop-hi") != null);
        }
    }

    // Explicit shutdown+join so `el_stats` (summed across loops) is out.
    server.shutdown();
    t.join();
    if (mt.err) |err| return err;
    try std.testing.expectEqual(@as(u64, 16), server.el_stats.served);
    try std.testing.expectEqual(@as(u64, 8), server.el_stats.accepted);
}
