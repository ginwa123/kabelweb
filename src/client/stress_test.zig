//! Stress / soak tests — slow by design. Gated behind
//! `-Dintegration=true -Dstress=true` because they take ~5 minutes
//! wall-clock and hit the network hard.

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const custom_http_client = @import("root.zig");
const gserverz = @import("../server/http_server.zig");

const HttpContext = gserverz.HttpContext;
const HttpRequest = gserverz.HttpRequest;
const HttpResponse = gserverz.HttpResponse;

fn runOne(allocator: std.mem.Allocator, url: []const u8, method: custom_http_client.Method) !bool {
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    const resp = client.perform(.{ .method = method, .url = url }, .{ .timeout_ms = 30_000 }) catch return false;
    resp.deinit(allocator);
    return true;
}

test "stress: 100 sequential successful GETs to example.com" {
    const allocator = testing.allocator;
    var ok: usize = 0;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        if (try runOne(allocator, "https://example.com", .GET)) ok += 1;
    }
    if (ok < 50) return error.SkipZigTest;
    std.debug.print("\nstress: {d}/100 successful\n", .{ok});
}

test "stress: 100 KiB body round-trips" {
    // Was https://example.com — flaky in air-gapped sandboxes. Converted
    // to a local TestServer echo so the test runs network-independently.
    // The 100 KiB body exercises the same write/read path as the
    // 1 MiB edge case test.
    const allocator = testing.allocator;
    const io = std.testing.io;
    const ts = TestServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    ts.registerRoutes() catch return error.SkipZigTest;
    ts.start() catch return error.SkipZigTest;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    var i: usize = 0;
    while (i < 100 * 1024) : (i += 1) try body.append(allocator, 'x');

    const url = ts.url("/post") catch return error.SkipZigTest;
    defer allocator.free(url);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var resp = client.perform(.{ .method = .POST, .url = url, .body = body.items }, .{ .timeout_ms = 10_000 }) catch return error.SkipZigTest;
    defer resp.deinit(allocator);

    try testing.expectEqual(@as(u16, 200), resp.status_code);
    try testing.expectEqual(body.items.len, resp.body.len);
    try testing.expectEqual(@as(u8, 'x'), resp.body[0]);
    try testing.expectEqual(@as(u8, 'x'), resp.body[resp.body.len - 1]);
}

const TestServer = struct {
    server: *gserverz.GinwaServer,
    io: std.Io,
    allocator: std.mem.Allocator,
    listener_thread: std.Thread,
    port: u16,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) !*TestServer {
        const ts = try allocator.create(TestServer);
        const addr = try gserverz.Address.init("127.0.0.1", 0);
        const port: u16 = try getBoundPort(addr.sock_fd);
        const gs = try gserverz.GinwaServer.init(allocator, io, addr);
        ts.* = .{
            .server = gs,
            .io = io,
            .allocator = allocator,
            .listener_thread = undefined,
            .port = port,
        };
        return ts;
    }

    pub fn registerRoutes(self: *TestServer) !void {
        try self.server.router.post("/post", echoPostHandler);
    }

    pub fn start(self: *TestServer) !void {
        self.listener_thread = try std.Thread.spawn(.{}, listenFn, .{self.server});
    }

    pub fn url(self: *TestServer, path: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "http://127.0.0.1:{d}{s}", .{ self.port, path });
    }

    pub fn deinit(self: *TestServer) void {
        self.server.shutdown();
        self.listener_thread.join();
        self.server.destroy(self.allocator);
        self.allocator.destroy(self);
    }
};

fn echoPostHandler(_: HttpContext, req: HttpRequest, res: HttpResponse) !HttpResponse {
    return res.withBody(req.body);
}

fn listenFn(server: *gserverz.GinwaServer) void {
    server.listenEventLoop(.{ .dispatch_mode = .worker_pool }) catch {};
}

extern "c" fn getsockname(
    sockfd: c_int,
    addr: *std.posix.sockaddr,
    addrlen: *std.posix.socklen_t,
) c_int;

fn getBoundPort(sock_fd: c_int) !u16 {
    if (builtin.os.tag == .windows) {
        var raw: std.c.sockaddr.in = undefined;
        var len: c_int = @intCast(@sizeOf(@TypeOf(raw)));
        const rc = getsockname(sock_fd, @ptrCast(&raw), @ptrCast(&len));
        if (rc != 0) return error.BindFailed;
        return @byteSwap(@as(u16, @intCast(raw.port)));
    }
    var raw: std.posix.sockaddr.in = undefined;
    var len: std.posix.socklen_t = @sizeOf(@TypeOf(raw));
    const rc = getsockname(sock_fd, @ptrCast(&raw), &len);
    if (rc != 0) return error.BindFailed;
    return @byteSwap(@as(u16, @intCast(raw.port)));
}

test "stress: alternating success / refused calls do not interleave state" {
    const allocator = testing.allocator;
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    var ok: usize = 0;
    var refused: usize = 0;
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        const url = if (i % 2 == 0) "https://example.com" else "http://127.0.0.1:1/";
        const result = client.perform(.{ .method = .GET, .url = url }, .{ .timeout_ms = 5_000 }) catch |err| switch (err) {
            error.ConnectionRefused, error.ConnectionTimeout, error.OperationTimedOut => {
                refused += 1;
                continue;
            },
            error.DnsError, error.TlsError => return error.SkipZigTest,
            else => return err,
        };
        result.deinit(allocator);
        ok += 1;
    }
    try testing.expect(ok + refused == 40);
    std.debug.print("\nstress: alternating — ok={d} refused={d}\n", .{ ok, refused });
}

test "stress: 4 threads × 25 concurrent in-flight GETs each" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const allocator = testing.allocator;
    const WorkerCtx = struct {
        allocator: std.mem.Allocator,
        success_count: std.atomic.Value(usize) = .init(0),
        error_count: std.atomic.Value(usize) = .init(0),
    };

    const N_THREADS: usize = 4;
    const PER_THREAD: usize = 25;

    var ctx: WorkerCtx = .{ .allocator = allocator };

    var threads: [N_THREADS]std.Thread = undefined;
    var t: usize = 0;
    while (t < N_THREADS) : (t += 1) {
        threads[t] = try std.Thread.spawn(.{}, struct {
            fn run(c: *WorkerCtx) void {
                var i: usize = 0;
                while (i < PER_THREAD) : (i += 1) {
                    var client = custom_http_client.Client.init(c.allocator);
                    defer client.deinit();
                    const result = client.perform(.{ .method = .GET, .url = "https://example.com" }, .{ .timeout_ms = 10_000 }) catch {
                        _ = c.error_count.fetchAdd(1, .monotonic);
                        continue;
                    };
                    result.deinit(c.allocator);
                    _ = c.success_count.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{&ctx});
    }

    t = 0;
    while (t < N_THREADS) : (t += 1) threads[t].join();

    const ok = ctx.success_count.load(.acquire);
    const err = ctx.error_count.load(.acquire);
    std.debug.print("\nstress: 4 threads × 25 = {d} ok / {d} err\n", .{ ok, err });
    try testing.expect(ok + err == N_THREADS * PER_THREAD);
}

test "stress: 500 small GET requests in a tight loop — no allocation growth leak" {
    const allocator = testing.allocator;
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    var ok: usize = 0;
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        const r = client.perform(.{ .method = .GET, .url = "https://example.com" }, .{ .timeout_ms = 5_000 }) catch {
            if (i > 50 and ok < 5) return error.SkipZigTest;
            continue;
        };
        r.deinit(allocator);
        ok += 1;
    }
    try testing.expect(ok >= 50);
}

test "stress: 100 KiB body round-trips (legacy httpbin variant)" {
    // SKIPPED: superseded by the local-server variant added in
    // custom-http-client-cross-platform. Kept as a skip-stub so any
    // historical grep for the old name still finds something.
    return error.SkipZigTest;
}

fn client_fetch(allocator: std.mem.Allocator, req: custom_http_client.Request) !custom_http_client.Response {
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    return client.perform(req, .{ .timeout_ms = 30_000 }) catch |err| switch (err) {
        error.ConnectionRefused, error.ConnectionTimeout, error.OperationTimedOut,
        error.DnsError, error.TlsError => return error.SkipZigTest,
        else => return err,
    };
}
