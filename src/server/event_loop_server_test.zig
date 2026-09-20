//! End-to-end tests for `GinwaServer.listenEventLoop` (now the single
//! serve path): plain routes, static-dir hijack, SSE hijack, WS hijack,
//! H2C hijack, worker-pool dispatch, and multi-loop aggregation.

const std = @import("std");

const http_server = @import("http_server.zig");
const event_loop = @import("event_loop.zig");
const test_tcp = @import("test_tcp.zig");
const ws_frames = http_server.ws_frames;

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

    // 4. SSE route → 200 event-stream (hijacked to an SSE worker thread).
    // The stub handler returns error.Unreachable immediately, so the
    // stream closes right after the headers + terminator.
    try writeAll(cfd, "GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    const r4 = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, r4, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, r4, "text/event-stream") != null);
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
    if (mt.err) |err| {
        // Log the name: on CI the interesting case is a macOS REUSEPORT
        // bind failure, and the bare `return err` hides which step failed.
        std.debug.print("listenEventLoop(multi) failed: {s}\n", .{@errorName(err)});
        return err;
    }

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

// --- static-dir hijack -----------------------------------------------------

fn staticTestHandler(
    cfg: *const anyopaque,
    alloc: std.mem.Allocator,
    io: std.Io,
    request_path: []const u8,
    range_header: ?[]const u8,
    stream: http_server.Stream,
) anyerror!void {
    _ = cfg;
    _ = io;
    _ = range_header;
    // Minimal wire format owned by the handler (status + headers + body).
    const body = try std.fmt.allocPrint(alloc, "static:{s}", .{request_path});
    defer alloc.free(body);
    const head = try std.fmt.allocPrint(
        alloc,
        "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n",
        .{body.len},
    );
    defer alloc.free(head);
    try stream.writeAll(head);
    try stream.writeAll(body);
}

test "listenEventLoop serves static-dir fallback via hijack (direct)" {
    const alloc = std.testing.allocator;
    const addr = try http_server.Address.init("127.0.0.1", 0);
    const port = try serverPort(addr.sock_fd);

    var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
    defer server.destroy(alloc);

    try server.router.get("/hello", helloHandler);
    var static_cfg: u8 = 0;
    server.setStaticDirHandler(staticTestHandler, @ptrCast(&static_cfg));

    var st = ServerThread{
        .server = server,
        .cfg = .{
            .max_conns = 32,
            .idle_timeout_ms = 10_000,
            .header_timeout_ms = 2_000,
        },
    };
    const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
    std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
    if (st.err) |err| return err;

    // Unmatched path → static handler (200 + echoed path), conn closes.
    {
        const cfd = try tcpConnect(port);
        defer test_tcp.close(cfd);
        var buf: [8192]u8 = undefined;
        try writeAll(cfd, "GET /file.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        const r = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, r, "200 OK") != null);
        try std.testing.expect(std.mem.indexOf(u8, r, "static:/file.txt") != null);
    }
    // Server still serves plain routes afterwards (static close is clean).
    {
        const cfd = try tcpConnect(port);
        defer test_tcp.close(cfd);
        var buf: [8192]u8 = undefined;
        try writeAll(cfd, "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        const r = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, r, "event-loop-hi") != null);
    }

    server.shutdown();
    t.join();
    if (st.err) |err| return err;
    try std.testing.expect(server.el_stats.hijacked >= 1);
    try std.testing.expectEqual(@as(u64, 1), server.el_stats.served);
}

test "listenEventLoop serves static-dir fallback via hijack (pool)" {
    const alloc = std.testing.allocator;
    const addr = try http_server.Address.init("127.0.0.1", 0);
    const port = try serverPort(addr.sock_fd);

    var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
    defer server.destroy(alloc);

    var static_cfg: u8 = 0;
    server.setStaticDirHandler(staticTestHandler, @ptrCast(&static_cfg));

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
    try writeAll(cfd, "GET /pool-file.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    const r = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "static:/pool-file.txt") != null);

    server.shutdown();
    t.join();
    if (st.err) |err| return err;
    try std.testing.expect(server.el_stats.hijacked >= 1);
}

// --- SSE hijack ------------------------------------------------------------

var sse_test_server: ?*http_server.GinwaServer = null;

fn sseTestHandler(
    ctx: http_server.HttpContext,
    req: http_server.HttpRequest,
    res: http_server.HttpResponse,
) anyerror!http_server.HttpResponse {
    _ = ctx;
    _ = req;
    _ = res;
    // Registered before this runs (worker registers, then calls us):
    // broadcast one event, linger briefly, then return (conn closes).
    if (sse_test_server) |s| {
        s.sse_manager.broadcast("sse-ok") catch {};
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .real) catch {};
    }
    return error.WouldBlock;
}

test "listenEventLoop serves SSE stream via hijack" {
    const alloc = std.testing.allocator;
    const addr = try http_server.Address.init("127.0.0.1", 0);
    const port = try serverPort(addr.sock_fd);

    var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
    defer server.destroy(alloc);

    try server.router.sse("/events", sseTestHandler);
    sse_test_server = server;
    defer sse_test_server = null;

    var st = ServerThread{
        .server = server,
        .cfg = .{
            .max_conns = 32,
            .idle_timeout_ms = 10_000,
            .header_timeout_ms = 2_000,
        },
    };
    const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
    std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
    if (st.err) |err| return err;

    const cfd = try tcpConnect(port);
    defer test_tcp.close(cfd);
    var buf: [8192]u8 = undefined;
    try writeAll(cfd, "GET /events HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n");
    // Headers first (no Content-Length on SSE: returns after head).
    const head = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, head, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, head, "text/event-stream") != null);
    // Then the broadcast chunked event, then EOF after handler returns.
    var evbuf: [1024]u8 = undefined;
    var evlen: usize = 0;
    while (std.mem.indexOf(u8, evbuf[0..evlen], "data: sse-ok") == null) {
        if (evlen >= evbuf.len) break;
        const n = try test_tcp.read(cfd, evbuf[evlen..]);
        if (n == 0) break;
        evlen += n;
    }
    try std.testing.expect(std.mem.indexOf(u8, evbuf[0..evlen], "data: sse-ok") != null);

    server.shutdown();
    t.join();
    if (st.err) |err| return err;
    try std.testing.expect(server.el_stats.hijacked >= 1);
}

// --- WebSocket hijack ------------------------------------------------------

fn wsTestHandler(
    ctx: http_server.HttpContext,
    req: http_server.HttpRequest,
    server_ptr: *anyopaque,
    client_fd: i32,
    client_id: *[16]u8,
) anyerror!void {
    _ = req;
    _ = client_id;
    const server: *http_server.GinwaServer = @ptrCast(@alignCast(server_ptr));
    var buf: [4096]u8 = undefined;
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(ctx.allocator);
    while (true) {
        const n = try server.recvFromClient(client_fd, &buf);
        if (n == 0) return;
        try acc.appendSlice(ctx.allocator, buf[0..n]);
        var frame = ws_frames.parseFrame(ctx.allocator, acc.items) catch |err| {
            // Partial frame: read more (loopback may split frames).
            if (err == error.IncompleteFrame) continue;
            return err;
        };
        defer frame.deinit(ctx.allocator);
        switch (frame.opcode) {
            .text => {
                const echo = try ws_frames.encodeFrame(ctx.allocator, .{
                    .opcode = .text,
                    .payload = frame.payload,
                });
                defer ctx.allocator.free(echo);
                _ = try server.sendToClient(client_fd, echo);
            },
            .ping => {
                const pong = try ws_frames.encodeFrame(ctx.allocator, .{
                    .opcode = .pong,
                    .payload = frame.payload,
                });
                defer ctx.allocator.free(pong);
                _ = try server.sendToClient(client_fd, pong);
            },
            .close => return,
            else => {},
        }
        acc.clearRetainingCapacity();
    }
}

/// Read exactly `buf.len` bytes (blocking).
fn readExact(fd: i32, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try test_tcp.read(fd, buf[off..]);
        if (n == 0) return error.Closed;
        off += n;
    }
}

test "listenEventLoop serves WebSocket echo via hijack" {
    const alloc = std.testing.allocator;
    _ = alloc;
    const addr = try http_server.Address.init("127.0.0.1", 0);
    const port = try serverPort(addr.sock_fd);

    var server = try http_server.GinwaServer.init(std.testing.allocator, std.testing.io, addr);
    defer server.destroy(std.testing.allocator);

    try server.router.ws("/ws", wsTestHandler);

    var st = ServerThread{
        .server = server,
        .cfg = .{
            .max_conns = 32,
            .idle_timeout_ms = 10_000,
            .header_timeout_ms = 2_000,
        },
    };
    const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
    std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
    if (st.err) |err| return err;

    const cfd = try tcpConnect(port);
    defer test_tcp.close(cfd);

    // RFC 6455 handshake (example key → well-known accept).
    try writeAll(cfd, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    var buf: [8192]u8 = undefined;
    const hs = try readHttpResponse(cfd, &buf);
    try std.testing.expect(std.mem.indexOf(u8, hs, "101") != null);
    try std.testing.expect(std.mem.indexOf(u8, hs, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);

    // Masked text frame "hi" (client MUST mask). Second byte 0x82 =
    // MASK + length 2 (NOT 0x84: that declares 4 payload bytes and the
    // server would rightly wait for 2 more bytes forever).
    const mask = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
    var masked = [2 + 4 + 2]u8{ 0x81, 0x82, mask[0], mask[1], mask[2], mask[3], 'h' ^ mask[0], 'i' ^ mask[1] };
    try writeAll(cfd, &masked);
    // Unmasked echo "hi" back.
    var echo: [4]u8 = undefined;
    try readExact(cfd, &echo);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x81, 0x02, 'h', 'i' }, &echo);

    // Masked close → server close frame + EOF.
    var close_req = [2 + 4]u8{ 0x88, 0x80, mask[0], mask[1], mask[2], mask[3] };
    try writeAll(cfd, &close_req);
    var close_resp: [4]u8 = undefined;
    try readExact(cfd, &close_resp);
    try std.testing.expectEqual(@as(u8, 0x88), close_resp[0]);
    var tail: [64]u8 = undefined;
    const n = try test_tcp.read(cfd, &tail);
    try std.testing.expectEqual(@as(usize, 0), n);

    server.shutdown();
    t.join();
    if (st.err) |err| return err;
    try std.testing.expect(server.el_stats.hijacked >= 1);
}

// --- H2C hijack smoke ------------------------------------------------------

test "listenEventLoop hijacks H2 preface to H2 driver" {
    const alloc = std.testing.allocator;
    _ = alloc;
    const addr = try http_server.Address.init("127.0.0.1", 0);
    const port = try serverPort(addr.sock_fd);

    var server = try http_server.GinwaServer.init(std.testing.allocator, std.testing.io, addr);
    defer server.destroy(std.testing.allocator);

    try server.router.get("/hello", helloHandler);
    server.enable_h2c = true;

    var st = ServerThread{
        .server = server,
        .cfg = .{
            .max_conns = 32,
            .idle_timeout_ms = 10_000,
            .header_timeout_ms = 2_000,
        },
    };
    const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
    std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
    if (st.err) |err| return err;

    const cfd = try tcpConnect(port);
    defer test_tcp.close(cfd);

    // H2 connection preface + empty SETTINGS frame.
    try writeAll(cfd, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try writeAll(cfd, &[_]u8{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 });
    // Server's first frame must be its SETTINGS (type 0x4).
    var head: [9]u8 = undefined;
    try readExact(cfd, &head);
    try std.testing.expectEqual(@as(u8, 0x04), head[3]);

    server.shutdown();
    t.join();
    if (st.err) |err| return err;
    try std.testing.expect(server.el_stats.hijacked >= 1);
}
