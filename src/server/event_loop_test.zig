//! Tests for the poll reactor (Phase 2-3).
//!
//! Framing helpers are pure and fast (no sockets). The live test spins a
//! real `EventLoop` on an ephemeral loopback port with a stub dispatcher and
//! speaks HTTP/1.1 over blocking TCP — proving the reactor serves requests
//! without the threaded `listen()` path.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const event_loop = @import("event_loop.zig");
const EventLoop = event_loop.EventLoop;
const Config = event_loop.Config;
const nb = @import("nb_socket.zig");

test "framing: incomplete head needs more bytes" {
    const r = try event_loop.extractRequestLen("GET / HTTP/1.1\r\nHost: x", 1024);
    try std.testing.expect(r == null);
}

test "framing: GET without body is complete at header end" {
    const raw = "GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    const r = try event_loop.extractRequestLen(raw, 1024);
    try std.testing.expect(r != null);
    try std.testing.expectEqual(raw.len, r.?);
}

test "framing: POST waits for Content-Length body" {
    const head = "POST /users HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n";
    const partial = try event_loop.extractRequestLen(head ++ "hello", 1024);
    try std.testing.expect(partial == null);
    const full = try event_loop.extractRequestLen(head ++ "hello world", 1024);
    try std.testing.expect(full != null);
    try std.testing.expectEqual(head.len + 11, full.?);
}

test "framing: oversize request errors" {
    const raw = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
    const r = event_loop.extractRequestLen(raw, 10);
    try std.testing.expectError(error.RequestTooLarge, r);
}

test "framing: garbage Content-Length is BadRequest" {
    const raw = "POST /x HTTP/1.1\r\nContent-Length: banana\r\n\r\n";
    const r = event_loop.extractRequestLen(raw, 1024);
    try std.testing.expectError(error.BadRequest, r);
}

test "framing: pipelined second request detected after drain" {
    const first = "GET /a HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";
    const second = "GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    var buf: [512]u8 = undefined;
    @memcpy(buf[0..first.len], first);
    @memcpy(buf[first.len .. first.len + second.len], second);
    const total = first.len + second.len;
    const len1 = try event_loop.extractRequestLen(buf[0..total], 4096);
    try std.testing.expect(len1 != null);
    try std.testing.expectEqual(first.len, len1.?);
    const len2 = try event_loop.extractRequestLen(buf[len1.?..total], 4096);
    try std.testing.expect(len2 != null);
    try std.testing.expectEqual(second.len, len2.?);
}

// --- live loopback test (POSIX only) ---------------------------------------

fn stubDispatch(
    _: *anyopaque,
    alloc: std.mem.Allocator,
    req: *const event_loop.HttpRequest,
    http_ctx: event_loop.HttpContext,
) anyerror!event_loop.HttpResponse {
    _ = http_ctx;
    var res = event_loop.HttpResponse.init(200, "OK", alloc).withBody("loop-ok");
    // Echo keep-alive intent from the request so the test can exercise reuse.
    var want_close = false;
    var it = req.headers.iterator();
    while (it.next()) |e| {
        if (std.ascii.eqlIgnoreCase(e.key_ptr.*, "connection") and
            std.ascii.indexOfIgnoreCase(e.value_ptr.*, "close") != null)
        {
            want_close = true;
            break;
        }
    }
    res.keep_alive = !want_close and !std.mem.eql(u8, req.version, "HTTP/1.0");
    return res;
}

fn readHttpResponse(fd: i32, buf: []u8) ![]u8 {
    const sys = posix.system;
    var len: usize = 0;
    while (true) {
        const head_end = event_loop.findHeaderEnd(buf[0..len]);
        if (head_end) |he| {
            const cl = try event_loop.parseContentLength(buf[0..he]);
            if (len >= he + cl) return buf[0 .. he + cl];
        }
        if (len >= buf.len) return error.TooMuch;
        const n: isize = sys.read(fd, buf.ptr + len, buf.len - len);
        if (n <= 0) return error.Closed;
        len += @as(usize, @intCast(n));
    }
}

fn tcpConnect(port: u16) !i32 {
    const sys = posix.system;
    const raw = sys.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    if (raw < 0) return error.SocketFailed;
    const fd: i32 = @intCast(raw);
    errdefer _ = sys.close(fd);
    var caddr: sys.sockaddr.in = .{
        .family = 2,
        .port = @byteSwap(port),
        .addr = @bitCast(@as(u32, 0x0100007f)),
        .zero = undefined,
    };
    const rc = sys.connect(fd, @ptrCast(&caddr), @sizeOf(sys.sockaddr.in));
    if (rc != 0) return error.ConnectFailed;
    return fd;
}

fn writeAll(fd: i32, data: []const u8) !void {
    const sys = posix.system;
    var off: usize = 0;
    while (off < data.len) {
        const n: isize = sys.write(fd, data.ptr + off, data.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @as(usize, @intCast(n));
    }
}

test "event loop serves GET over loopback (POSIX)" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const sys = posix.system;

    // Bind ephemeral loopback listener (same raw-syscall shape as
    // `http_server.zig:Address`, which is why `rc < 0` checks read oddly —
    // raw syscalls return -errno on failure).
    const lfd_raw = sys.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    if (lfd_raw < 0) return error.SocketFailed;
    const lfd: i32 = @intCast(lfd_raw);
    defer _ = sys.close(lfd);
    const opt: i32 = 1;
    try posix.setsockopt(
        lfd,
        @intCast(posix.SOL.SOCKET),
        @intCast(posix.SO.REUSEADDR),
        std.mem.asBytes(&opt),
    );
    var addr: sys.sockaddr.in = .{
        .family = 2,
        .port = 0, // ephemeral
        .addr = @bitCast(@as(u32, 0x0100007f)), // 127.0.0.1 LE
        .zero = undefined,
    };
    {
        const rc = sys.bind(lfd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in));
        if (rc < 0) return error.BindFailed;
    }
    {
        const rc = sys.listen(lfd, 16);
        if (rc < 0) return error.ListenFailed;
    }
    var bound: sys.sockaddr.in = undefined;
    var bound_len: posix.socklen_t = @sizeOf(sys.sockaddr.in);
    {
        const rc = sys.getsockname(lfd, @ptrCast(&bound), &bound_len);
        if (rc != 0) return error.GetSockNameFailed;
    }
    const port = @byteSwap(bound.port);

    var loop = EventLoop.init(alloc, std.testing.io, .{
        .max_conns = 16,
        .idle_timeout_ms = 5_000,
        .header_timeout_ms = 2_000,
    });
    defer loop.deinit();

    var ctx_dummy: u8 = 0;
    const http_ctx: event_loop.HttpContext = .{ .allocator = alloc, .io = std.testing.io };
    const t = try std.Thread.spawn(.{}, struct {
        fn run(l: *EventLoop, fd: i32, ctxp: *u8, hctx: event_loop.HttpContext) void {
            l.run(fd, stubDispatch, @ptrCast(ctxp), hctx) catch {};
        }
    }.run, .{ &loop, lfd, &ctx_dummy, http_ctx });
    defer {
        loop.requestShutdown();
        // Wake poll: connect+close a dummy client (poll timeout is 250 ms
        // max anyway, so this just speeds the join).
        if (tcpConnect(port)) |w| {
            _ = posix.system.close(w);
        } else |_| {}
        t.join();
    }

    // Give the loop a moment to enter poll.
    std.Io.sleep(std.testing.io, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .real) catch {};

    const cfd = try tcpConnect(port);
    defer _ = posix.system.close(cfd);

    // Request 1: keep-alive.
    const req1 = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n";
    try writeAll(cfd, req1);
    var resp_buf: [4096]u8 = undefined;
    const resp1 = try readHttpResponse(cfd, &resp_buf);
    try std.testing.expect(std.mem.indexOf(u8, resp1, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp1, "loop-ok") != null);

    // Request 2 on the SAME connection (keep-alive reuse), then close.
    const req2 = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    try writeAll(cfd, req2);
    var resp_buf2: [4096]u8 = undefined;
    const resp2 = try readHttpResponse(cfd, &resp_buf2);
    try std.testing.expect(std.mem.indexOf(u8, resp2, "200 OK") != null);

    try std.testing.expect(loop.stats.served >= 2);
}
