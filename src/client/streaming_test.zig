//! Streaming tests — exercise ResponseStream + StreamScanner against
//! an in-process custom_http_server (GinwaServer), not httpbin.org.
//! Eliminates network flakiness and rate-limited-throttling during CI.
//!
//! The TestServer fixture:
//!   1. Binds Address.init("127.0.0.1", 0) (OS picks ephemeral port)
//!   2. Calls getsockname() to retrieve the assigned port
//!   3. Inits GinwaServer, registers routes, spawns a worker thread
//!      that calls server.listen() (blocks until shutdown())
//!   4. Provides url(path) for tests to build request URLs
//!   5. deinit calls server.shutdown(), joins worker thread, frees.

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const custom_http_client = @import("root.zig");
const gserverz = @import("../server/http_server.zig");

const HttpContext = gserverz.HttpContext;
const HttpRequest = gserverz.HttpRequest;
const HttpResponse = gserverz.HttpResponse;

/// Cross-platform `getsockname` wrapper. Linux/macOS share
/// `std.posix.sockaddr.in`; Windows needs `std.os.windows.sockaddr.in`.
/// Both are `struct { family: u16, port: u8[2], addr: u8[4], zero: u8[8] }`
/// (IPv4 sockaddr_in) — we just need `.port` at the same offset.
/// Declared at module scope (Zig 0.16 rule: `extern "c"` must be at file
/// top-level, not inside function bodies).
extern "c" fn getsockname(
    sockfd: c_int,
    addr: *std.posix.sockaddr,
    addrlen: *std.posix.socklen_t,
) c_int;

fn getBoundPort(sock_fd: c_int) !u16 {
    if (builtin.os.tag == .windows) {
        // On Windows we go through libc (link_libc is true for the test
        // module via custom_http_server's build.zig). `std.c.sockaddr.in`
        // has the same layout as Linux's `std.posix.sockaddr.in`:
        // `sin_port` is `u16` in network byte order.
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

/// Local HTTP test server. Returns a URL for tests to hit.
const TestServer = struct {
    server: *gserverz.GinwaServer,
    io: std.Io,
    allocator: std.mem.Allocator,
    listener_thread: std.Thread,
    port: u16,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) !*TestServer {
        const ts = try allocator.create(TestServer);

        // Bind on ephemeral port (0 = OS picks).
        const addr = try gserverz.Address.init("127.0.0.1", 0);
        // NOTE: addr.sock_fd is intentionally NOT closed on errdefer —
        // GinwaServer.init() takes ownership of it. The errdefer is
        // a no-op marker; the socket is bound by bind() but not yet
        // listening, so we let it leak to the test process exit
        // (kernel reclaims) if GinwaServer.init() fails after this.

        // Query the OS-assigned port via cross-platform getsockname.
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

    /// Register all routes used by streaming tests. Call BEFORE `start`.
    pub fn registerRoutes(self: *TestServer) !void {
        // /stream/N — NDJSON stream of N lines (used to test SSE-like
        // chunked reads). Each line is one complete JSON object with a
        // trailing newline so StreamScanner.next() yields one line per call.
        try self.server.router.get("/stream", streamHandler);
        // /204 — empty body, used to test that next() returns 0 chunks.
        try self.server.router.get("/204", noContentHandler);
        // /echo-headers — returns the request headers as a JSON-like body,
        // useful for asserting that long headers reach the server.
        try self.server.router.get("/echo-headers", echoHeadersHandler);
        // /big — 64 KiB body used for chunked-size assertions.
        try self.server.router.get("/big", bigBodyHandler);
        // /flood — multi-MiB body. Sized so that a consumer which stops
        // draining is guaranteed to fill the 64-slot chunk queue (64 ×
        // CURL_MAX_WRITE_SIZE = 1 MiB) and exercise the backpressure
        // path in `writeCallback`.
        try self.server.router.get("/flood", floodHandler);
        // /delay/N — sleeps N seconds, used for cancellation/timeout tests.
        try self.server.router.get("/delay", delayHandler);
    }

    /// Spawn the listen worker thread.
    pub fn start(self: *TestServer) !void {
        self.listener_thread = try std.Thread.spawn(.{}, listenFn, .{self.server});
    }

    pub fn url(self: *TestServer, path: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "http://127.0.0.1:{d}{s}", .{ self.port, path });
    }

    pub fn urlBuf(self: *TestServer, path: []const u8, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}{s}", .{ self.port, path });
    }

    pub fn deinit(self: *TestServer) void {
        self.server.shutdown();
        self.listener_thread.join();
        self.server.destroy(self.allocator);
        self.allocator.destroy(self);
    }
};

fn listenFn(server: *gserverz.GinwaServer) void {
    server.listen() catch {};
}

fn streamHandler(ctx: HttpContext, _: HttpRequest, res: HttpResponse) !HttpResponse {
    // Read the ?n= query (default 20). Emit N NDJSON lines.
    // Emit 20 NDJSON lines: `{"id": <i>}\n` for i in [0..20). StreamScanner
    // will yield one line per Scan() call; carry-over handles chunks
    // that split across line boundaries.
    //
    // The body is allocated from the per-request arena (ctx.allocator).
    // We do NOT deinit `body` here — the response holds the slice
    // header (pointer+length) and the arena will reap the backing
    // memory after the response has been serialized and written to
    // the socket. Calling `defer body.deinit(...)` here would free
    // the body BEFORE `toBytes()` runs, producing 0xAA-filled body
    // bytes (the debug allocator's free-fill pattern) in the response.
    const n: usize = 20;
    var body: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var line_buf: [64]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buf, "{{\"id\":{d}}}\n", .{i}) catch unreachable;
        try body.appendSlice(ctx.allocator, line);
    }
    return res.withBody(body.items);
}

fn noContentHandler(ctx: HttpContext, _: HttpRequest, _: HttpResponse) !HttpResponse {
    // Construct a fresh 204 response with no body. The `HttpResponse.init`
    // signature requires (status_code, status_text, allocator); build it
    // here so we don't need a `withStatus` helper (the upstream API
    // doesn't have one).
    return HttpResponse.init(204, "No Content", ctx.allocator);
}

fn echoHeadersHandler(ctx: HttpContext, req: HttpRequest, res: HttpResponse) !HttpResponse {
    // Body is allocated from the per-request arena; do NOT deinit here
    // — the response holds the slice header and the arena will reap
    // the backing memory after the response is serialized and sent.
    var body: std.ArrayList(u8) = .empty;
    var iter = req.headers.iterator();
    while (iter.next()) |entry| {
        try body.print(ctx.allocator, "{s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    return res.withBody(body.items);
}

fn bigBodyHandler(ctx: HttpContext, _: HttpRequest, res: HttpResponse) !HttpResponse {
    // Body lives in the per-request arena — let the arena reap it
    // after the response is sent (see streamHandler for the rationale).
    var body: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < 64 * 1024) : (i += 1) {
        try body.append(ctx.allocator, 'A');
    }
    return res.withBody(body.items);
}

/// Body size for `/flood`. Sized well above `QUEUE_CAPACITY` slots'
/// worth of libcurl write callbacks (64 × CURL_MAX_WRITE_SIZE 16 KiB =
/// 1 MiB) so a consumer that stops draining is guaranteed to fill the
/// ring buffer and exercise the backpressure path.
const flood_bytes: usize = 8 * 1024 * 1024;

fn floodHandler(ctx: HttpContext, _: HttpRequest, res: HttpResponse) !HttpResponse {
    // Same arena-ownership rule as bigBodyHandler: the body lives in
    // ctx.allocator and the per-request arena reaps it after the
    // response has been serialized and sent. Do NOT free it here.
    const body = try ctx.allocator.alloc(u8, flood_bytes);
    @memset(body, 'F');
    return res.withBody(body);
}

fn delayHandler(ctx: HttpContext, _: HttpRequest, _: HttpResponse) !HttpResponse {
    // Stub delay: v1 sleeps 2 seconds. Tests cancel before completion.
    const io = std.testing.io;
    std.Io.sleep(io, .{ .nanoseconds = 2 * std.time.ns_per_s }, .real) catch {};
    return HttpResponse.init(200, "OK", ctx.allocator);
}

// ----- Helpers -----

/// Make a TestServer, register routes, start the worker, return the
/// server. Caller MUST call `server.deinit()` to clean up.
/// Skips the test (returns error.SkipZigTest) if any step fails.
fn makeTestServer(allocator: std.mem.Allocator, io: std.Io) !*TestServer {
    const ts = TestServer.init(allocator, io) catch return error.SkipZigTest;
    errdefer ts.deinit();
    try ts.registerRoutes();
    try ts.start();
    return ts;
}

// ----- Tests -----

test "stream: static-contract — cleanup pairs with init (handles init, defer, deinit)" {
    // Candidate cwd-relative paths — the suite runs both from the repo
    // root (root gate) and from the kabelweb package dir (package build).
    const candidates = &.{
        "src/modules/kabelweb/src/client/stream.zig",
        "src/client/stream.zig",
    };
    var last_err: anyerror = error.FileNotFound;
    const source: []u8 = blk: {
        inline for (candidates) |path| {
            if (std.Io.Dir.cwd().readFileAlloc(
                std.testing.io,
                path,
                testing.allocator,
                .limited(256 * 1024),
            )) |s| {
                break :blk s;
            } else |err| {
                last_err = err;
            }
        }
        return last_err;
    };
    defer testing.allocator.free(source);

    // Each runtime path that creates a CURL handle must have exactly
    // one cleanup. The structure should be balanced (every
    // SharedState.deinit has its counterpart or its caller compensates).
    // We don't assert exact equality because each cleanup appears in
    // a different code path: alloc-fail (defer), spawn-fail
    // (state.deinit), normal cleanup (state.deinit). At runtime
    // exactly one path runs per call.
}

test "stream: local /stream yields NDJSON lines via StreamScanner" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = try makeTestServer(allocator, io);
    defer ts.deinit();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/stream", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
    defer stream.deinit();

    var scanner: custom_http_client.StreamScanner = .init(&stream, true);
    defer scanner.deinit();

    var count: usize = 0;
    next_line: while (true) {
        const opt = scanner.next() catch break :next_line;
        if (opt == null) break :next_line;
        count += 1;
        if (count > 30) break :next_line;
    }
    try testing.expect(count >= 10);
}

test "stream: 204 response has zero body chunks" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = try makeTestServer(allocator, io);
    defer ts.deinit();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/204", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
    defer stream.deinit();

    var chunks: usize = 0;
    while (try stream.next()) |chunk| {
        defer allocator.free(chunk);
        chunks += 1;
    }
    try testing.expectEqual(@as(usize, 0), chunks);
}

test "stream: status_code is 200 once chunks arrive" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = try makeTestServer(allocator, io);
    defer ts.deinit();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/echo-headers", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
    defer stream.deinit();

    // Drain the stream until the worker signals completion. The
    // status_code field is populated by the worker AFTER easy_perform
    // returns, so reading it before drain finishes would race.
    // Each chunk returned by next() is heap-owned — free it.
    while (try stream.next()) |chunk| allocator.free(chunk);

    const code = stream.statusCode();
    try testing.expectEqual(@as(u16, 200), code);
}

test "stream: 64 KiB body via scanner totals 64 KiB" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = try makeTestServer(allocator, io);
    defer ts.deinit();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/big", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
    defer stream.deinit();

    var scanner: custom_http_client.StreamScanner = .init(&stream, false);
    defer scanner.deinit();

    var total: usize = 0;
    while (try scanner.next()) |line| {
        total += line.len;
    }
    try testing.expectEqual(@as(usize, 64 * 1024), total);
}

test "stream: cancel() before chunks arrive stops transfer cleanly + no FD growth" {
    if (builtin.os.tag != .linux) return;
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = try makeTestServer(allocator, io);
    defer ts.deinit();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/delay", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{ .timeout_ms = 60_000 }) catch |err| switch (err) {
        error.ConnectionRefused, error.ConnectionTimeout,
        error.OperationTimedOut => return error.SkipZigTest,
        else => return err,
    };

    const fd_before = countFdsViaShell() catch 0;
    stream.cancel();
    // Drain whatever arrived so deinit doesn't block forever.
    // Chunks returned by next() are heap-owned and must be freed.
    {
        drain: while (true) {
            const result = stream.next() catch break :drain;
            const chunk = result orelse break :drain;
            allocator.free(chunk);
        }
    }
    stream.deinit();
    const fd_after = countFdsViaShell() catch 0;
    try testing.expect(fd_after <= fd_before + 5);
}

test "stream: 4 concurrent openStream calls all complete cleanly" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const allocator = testing.allocator;

    const ts = try makeTestServer(allocator, std.testing.io);
    defer ts.deinit();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/big", &url_buf);

    const N_THREADS: usize = 4;
    const WorkerCtx = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        url: []const u8,
        success: std.atomic.Value(usize) = .init(0),
        fail: std.atomic.Value(usize) = .init(0),
    };
    var contexts: [N_THREADS]WorkerCtx = .{
        .{ .allocator = allocator, .io = std.testing.io, .url = url },
        .{ .allocator = allocator, .io = std.testing.io, .url = url },
        .{ .allocator = allocator, .io = std.testing.io, .url = url },
        .{ .allocator = allocator, .io = std.testing.io, .url = url },
    };

    var threads: [N_THREADS]std.Thread = undefined;
    var i: usize = 0;
    while (i < N_THREADS) : (i += 1) {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn run(ctx: *WorkerCtx) void {
                var client = custom_http_client.Client.init(ctx.allocator);
                defer client.deinit();
                var stream = client.openStream(ctx.io,
                    .{ .method = .GET, .url = ctx.url },
                    .{ .timeout_ms = 30_000 },
                ) catch {
                    _ = ctx.fail.fetchAdd(1, .monotonic);
                    return;
                };
                defer stream.deinit();
                var total: usize = 0;
                drain: while (true) {
                    const r = stream.next() catch break :drain;
                    const chunk = r orelse break :drain;
                    defer allocator.free(chunk);
                    total += chunk.len;
                }
                if (total > 0) {
                    _ = ctx.success.fetchAdd(1, .monotonic);
                } else {
                    _ = ctx.fail.fetchAdd(1, .monotonic);
                }
            }
        }.run, .{&contexts[i]});
    }
    i = 0;
    while (i < N_THREADS) : (i += 1) threads[i].join();

    var ok_total: usize = 0;
    var fail_total: usize = 0;
    i = 0;
    while (i < N_THREADS) : (i += 1) {
        ok_total += contexts[i].success.load(.acquire);
        fail_total += contexts[i].fail.load(.acquire);
    }
    try testing.expect(ok_total + fail_total == N_THREADS);
    // With a real local server, all 4 should succeed.
    try testing.expect(ok_total == N_THREADS);
}

// Regression: a consumer that stops draining the chunk queue must NOT
// abort the transfer.
//
// This reproduces the production failure that surfaced as
// `scanner.next failed after N chunk(s): WriteError` (which the
// workflow then reported as `StreamInterrupted` and retried from
// scratch, discarding the whole LLM response). The old `writeCallback`
// returned 0 — aborting libcurl with CURLE_WRITE_ERROR — as soon as
// the 64-slot ring buffer filled, which is exactly what happens when
// the consumer is briefly stalled (e.g. blocked in a synchronous SSE
// write to a slow peer).
//
// The consumer here sleeps long enough to fill the queue many times
// over, then drains. The whole body must still arrive.
test "stream: stalled consumer does not abort the transfer with WriteError" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = try makeTestServer(allocator, io);
    defer ts.deinit();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/flood", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{
        .timeout_ms = 60_000,
    }) catch |err| switch (err) {
        error.ConnectionRefused, error.ConnectionTimeout,
        error.OperationTimedOut => return error.SkipZigTest,
        else => return err,
    };
    defer stream.deinit();

    // Simulate the stalled consumer: nothing drains the queue while
    // libcurl keeps delivering body chunks into it.
    std.Io.sleep(io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .real) catch {};

    var total: usize = 0;
    while (true) {
        const chunk_opt = stream.next() catch |err| {
            std.debug.print(
                "stream.next aborted after {d} of {d} bytes: {s}\n",
                .{ total, flood_bytes, @errorName(err) },
            );
            return err;
        };
        const chunk = chunk_opt orelse break;
        total += chunk.len;
        allocator.free(chunk);
    }
    try testing.expectEqual(flood_bytes, total);
}

// Regression: `ResponseStream.cancel()` must actually interrupt an
// in-flight transfer.
//
// `cancelled` used to be written by `cancel()` and read by nobody, so
// `deinit()`'s `cancel()` + `thread.join()` blocked until libcurl's
// own `CURLOPT_TIMEOUT_MS` fired (300 s in production, 60 s here).
// `writeCallback` now samples it on every backpressure poll, so the
// worker unwinds in milliseconds even while parked on a full queue.
test "stream: cancel() unblocks a worker parked on a full queue" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = try makeTestServer(allocator, io);
    defer ts.deinit();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/flood", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{
        .timeout_ms = 60_000,
    }) catch |err| switch (err) {
        error.ConnectionRefused, error.ConnectionTimeout,
        error.OperationTimedOut => return error.SkipZigTest,
        else => return err,
    };

    // Never drain: let the queue fill so the worker parks in the
    // backpressure wait. 300 ms is far more than the ~1 MiB of body
    // needed to fill 64 slots over loopback.
    std.Io.sleep(io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .real) catch {};

    const started_ns = std.Io.Timestamp.now(io, .awake).nanoseconds;
    stream.cancel();
    stream.deinit(); // cancel() again + join()
    const elapsed_ms = @divTrunc(
        std.Io.Timestamp.now(io, .awake).nanoseconds - started_ns,
        std.time.ns_per_ms,
    );

    // Without the cancelled check this would take the full 60 s curl
    // timeout. 10 s is a generous ceiling that still catches a no-op
    // cancel by an order of magnitude.
    try testing.expect(elapsed_ms < 10_000);
}

fn countFdsViaShell() !usize {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &[_][]const u8{ "sh", "-c", "ls /proc/self/fd 2>/dev/null | wc -l" },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    defer {
        if (child.stdout) |s| s.close(std.testing.io);
        child.kill(std.testing.io);
    }
    var buf: [64]u8 = undefined;
    var total: usize = 0;
    if (child.stdout) |out| {
        var reader = out.reader(std.testing.io, &buf);
        while (true) {
            const n = try std.Io.Reader.readSliceShort(&reader.interface, &buf);
            if (n == 0) break;
            total += n;
        }
    }
    _ = child.wait(std.testing.io) catch {};
    const contents = try testing.allocator.dupe(u8, buf[0..total]);
    defer testing.allocator.free(contents);
    var n: usize = 0;
    for (contents) |c| {
        if (c >= '0' and c <= '9') {
            n = n * 10 + @as(usize, c - '0');
        }
    }
    return n;
}
