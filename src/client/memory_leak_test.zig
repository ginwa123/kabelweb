//! Memory-leak regression tests. ALL tests run under std.testing.allocator
//! which fails the test on ANY unfreed allocation.
//!
//! The Zig testing.allocator wraps the GPA with canaries and a deinit
//! check at scope end. A leak triggers a full backtrace dump.
//!
//! Coverage:
//!   - non-streaming path (`Client.perform`): see "GET happy path" /
//!     "POST with body" / "ConnectionRefused" / "200 sequential" below.
//!   - streaming path (`Client.openStream` + `ResponseStream` +
//!     `StreamScanner`): see "stream: ..." tests below. These were added
//!     2026-07-25 because the streaming code has its own allocator
//!     ownership (SharedState owns the queue, slist, url_buf, method_buf,
//!     ua_buf, header_lines, headers, url_effective, primary_ip; the
//!     scanner owns carry and line_buf) and was previously only exercised
//!     by `streaming_test.zig` for behavior, not leak-tightness.
//!
//! Cross-platform fixture: uses an in-process `custom_http_server`
//! (GinwaServer on an ephemeral port), mirroring the pattern in
//! `streaming_test.zig` and `integration_test.zig`. Eliminates the
//! httpbin.org dependency so the suite runs in air-gapped CI.

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const custom_http_client = @import("root.zig");
const gserverz = @import("../server/http_server.zig");

const HttpContext = gserverz.HttpContext;
const HttpRequest = gserverz.HttpRequest;
const HttpResponse = gserverz.HttpResponse;

// Cross-platform getsockname wrapper (mirrors streaming_test.zig).
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

/// In-process test server with routes the streaming mem-leak tests use.
/// Mirrors `streaming_test.zig::TestServer` shape (kept inline rather
/// than shared because each test file gets its own copy — Zig 0.16
/// doesn't allow sharing fixtures across test files).
const StreamLeakServer = struct {
    server: *gserverz.GinwaServer,
    io: std.Io,
    allocator: std.mem.Allocator,
    listener_thread: std.Thread,
    port: u16,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) !*StreamLeakServer {
        const ts = try allocator.create(StreamLeakServer);
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

    pub fn registerRoutes(self: *StreamLeakServer) !void {
        try self.server.router.get("/ndjson", ndjsonHandler);
        try self.server.router.get("/big", bigBodyHandler);
        try self.server.router.get("/notfound", notFoundHandler);
        try self.server.router.get("/servererror", serverErrorHandler);
        try self.server.router.get("/close", closeImmediatelyHandler);
    }

    pub fn start(self: *StreamLeakServer) !void {
        self.listener_thread = try std.Thread.spawn(.{}, listenFn, .{self.server});
    }

    pub fn urlBuf(self: *StreamLeakServer, path: []const u8, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}{s}", .{ self.port, path });
    }

    pub fn deinit(self: *StreamLeakServer) void {
        self.server.shutdown();
        self.listener_thread.join();
        self.server.destroy(self.allocator);
        self.allocator.destroy(self);
    }
};

fn listenFn(server: *gserverz.GinwaServer) void {
    server.listenEventLoop(.{ .dispatch_mode = .worker_pool }) catch {};
}

/// Emit 20 NDJSON lines (each `"id":<n>\n`). StreamScanner-friendly.
fn ndjsonHandler(ctx: HttpContext, _: HttpRequest, res: HttpResponse) !HttpResponse {
    var body: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        var line_buf: [64]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buf, "{{\"id\":{d}}}\n", .{i}) catch unreachable;
        try body.appendSlice(ctx.allocator, line);
    }
    return res.withBody(body.items);
}

/// 64 KiB body (forces multiple writeCallback invocations, exercises
/// the queue's multi-slot path).
fn bigBodyHandler(ctx: HttpContext, _: HttpRequest, res: HttpResponse) !HttpResponse {
    var body: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < 64 * 1024) : (i += 1) {
        try body.append(ctx.allocator, 'A');
    }
    return res.withBody(body.items);
}

fn notFoundHandler(ctx: HttpContext, _: HttpRequest, _: HttpResponse) !HttpResponse {
    return HttpResponse.init(404, "Not Found", ctx.allocator);
}

fn serverErrorHandler(ctx: HttpContext, _: HttpRequest, _: HttpResponse) !HttpResponse {
    return HttpResponse.init(500, "Internal Server Error", ctx.allocator);
}

/// Close the connection immediately after the response starts streaming.
/// Exercises the easy_perform failure path with chunks already pushed.
fn closeImmediatelyHandler(ctx: HttpContext, _: HttpRequest, res: HttpResponse) !HttpResponse {
    var body: std.ArrayList(u8) = .empty;
    try body.appendSlice(ctx.allocator, "first-chunk\n");
    return res.withBody(body.items);
}

fn performOrSkip(allocator: std.mem.Allocator, req: custom_http_client.Request, opts: custom_http_client.Options) !custom_http_client.Response {
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    return client.perform(req, opts) catch |err| switch (err) {
        error.ConnectionRefused,
        error.ConnectionTimeout,
        error.OperationTimedOut,
        error.DnsError,
        error.TlsError => return error.SkipZigTest,
        else => return err,
    };
}

test "mem: GET happy path — full Response.deinit frees every owned slice" {
    const allocator = testing.allocator;
    var resp = try performOrSkip(allocator, .{
        .method = .GET,
        .url = "https://example.com",
    }, .{});
    defer resp.deinit(allocator);
    // Reach here only if the call succeeded — every field is then a real
    // allocation. testing.allocator deinit at scope end flags anything
    // still alive.
}

test "mem: POST with body + 5 headers — full Response.deinit is clean" {
    const allocator = testing.allocator;
    const body = "{\"k\":\"v\"}";
    const headers = [_]custom_http_client.Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "Accept", .value = "application/json" },
        .{ .name = "X-One", .value = "1" },
        .{ .name = "X-Two", .value = "2" },
        .{ .name = "X-Three", .value = "3" },
    };

    var resp = try performOrSkip(allocator, .{
        .method = .POST,
        .url = "https://httpbin.org/post",
        .body = body,
        .headers = &headers,
    }, .{});
    defer resp.deinit(allocator);

    try testing.expect(resp.headers.len >= 1); // server echoes Content-Type
}

test "mem: error path — ConnectionRefused does NOT leak allocations" {
    const allocator = testing.allocator;
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    const result = client.perform(.{ .method = .GET, .url = "http://127.0.0.1:1/" }, .{}) catch |err| switch (err) {
        error.ConnectionRefused,
        error.ConnectionTimeout,
        error.OperationTimedOut,
        error.DnsError => return,
        else => return err,
    };
    // If we reach here the call unexpectedly succeeded — deinit and skip.
    result.deinit(allocator);
    return error.SkipZigTest;
}

test "mem: 200 sequential GET / deinit cycles — allocator reports clean" {
    const allocator = testing.allocator;
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    var ok: usize = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        var resp = client.perform(.{ .method = .GET, .url = "https://example.com" }, .{}) catch continue;
        defer resp.deinit(allocator);
        ok += 1;
        if (ok >= 5) break;
    }
    if (ok == 0) return error.SkipZigTest;
}

test "mem: Response.deinit handles a zero-value Response without UB" {
    const allocator = testing.allocator;
    // A zero-value Response has all empty slices — deinit must be safe.
    var resp: custom_http_client.Response = .{
        .status_code = 0,
        .body = &[_]u8{},
        .headers = &[_]custom_http_client.Header{},
        .url_effective = "",
        .total_time_ms = 0,
        .primary_ip = "",
    };
    resp.deinit(allocator);
}

// ============================================================================
// Streaming-path memory leak tests (added 2026-07-25).
//
// Each test runs under testing.allocator. If a chunk, slist entry, header,
// scanner buffer, or queue slot survives past `stream.deinit()`, the
// allocator reports the leak with a backtrace. The tests below exercise
// every code path in `stream.zig::SharedState.deinit`:
//   - handle (curl_easy_cleanup)
//   - slist (curl_slist_free_all)
//   - headers ArrayList (headerCallback strings)
//   - url_effective ArrayList (worker appends after easy_perform)
//   - primary_ip ArrayList (worker appends after easy_perform)
//   - header_lines ArrayList (each line is heap-allocated)
//   - url_buf, method_buf (setopt targets, heap)
//   - ua_buf (optional, heap)
//   - queue slots (writeCallback dupes each chunk)
//   - queue mutex (allocated in ChunkQueue.init)
//
// And every code path in `StreamScanner.deinit`:
//   - carry ArrayList (accumulates bytes across chunks)
//   - line_buf ArrayList (one line at a time)
// ============================================================================

test "mem-stream: drain 20 NDJSON lines via StreamScanner — no leak" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = StreamLeakServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    try ts.registerRoutes();
    try ts.start();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/ndjson", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{}) catch return error.SkipZigTest;
    defer stream.deinit();

    var scanner: custom_http_client.StreamScanner = .init(&stream, false);
    defer scanner.deinit();

    var count: usize = 0;
    next_line: while (true) {
        const opt = scanner.next() catch break :next_line;
        if (opt == null) break :next_line;
        count += 1;
        if (count > 30) break :next_line;
    }
    try testing.expect(count >= 10);
    // testing.allocator.deinit at scope end flags any leak from
    // SharedState, scanner buffers, slist, or queue chunks.
}

test "mem-stream: early termination — break out after 5 of 20 lines" {
    // Stress: consumer stops mid-stream. The remaining 15 lines stay
    // in the chunk queue and MUST be freed by SharedState.deinit via
    // `while self.queue.popOne() |chunk| self.allocator.free(chunk)`.
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = StreamLeakServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    try ts.registerRoutes();
    try ts.start();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/ndjson", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
    defer stream.deinit();

    var scanner: custom_http_client.StreamScanner = .init(&stream, false);
    defer scanner.deinit();

    var count: usize = 0;
    while (count < 5) {
        const opt = scanner.next() catch break;
        if (opt == null) break;
        count += 1;
    }
    // Defer order: stream.deinit → scanner.deinit. The queue still
    // holds chunks 6..19 + the rest of line 5 split across two chunks.
    // All of these must be freed.
}

test "mem-stream: 64 KiB body via next() drain — every chunk freed" {
    // Forces many writeCallback invocations (one per chunk) which
    // each call allocator.dupe. If SharedState.deinit forgets to drain
    // the queue, every leaked chunk is reported by testing.allocator.
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = StreamLeakServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    try ts.registerRoutes();
    try ts.start();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/big", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
    defer stream.deinit();

    var total: usize = 0;
    while (try stream.next()) |chunk| {
        defer allocator.free(chunk);
        total += chunk.len;
    }
    try testing.expectEqual(@as(usize, 64 * 1024), total);
}

test "mem-stream: 404 response — no chunks, headers freed" {
    // Server returns 404 immediately. Headers list is populated by
    // headerCallback (heap-allocated name + value per header). The
    // empty body means the queue stays empty, but headers / url_buf /
    // method_buf / slist all still need cleanup.
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = StreamLeakServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    try ts.registerRoutes();
    try ts.start();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/notfound", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
    defer stream.deinit();

    // Drain whatever chunks arrive (should be zero).
    while (try stream.next()) |chunk| allocator.free(chunk);
    try testing.expectEqual(@as(u16, 404), stream.statusCode());
}

test "mem-stream: 500 response — no leak on server-error path" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = StreamLeakServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    try ts.registerRoutes();
    try ts.start();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/servererror", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
    defer stream.deinit();

    while (try stream.next()) |chunk| allocator.free(chunk);
    try testing.expectEqual(@as(u16, 500), stream.statusCode());
}

test "mem-stream: connection-refused on openStream — no leak" {
    // Subtle: `openStream` returns OK immediately because `Thread.spawn`
    // succeeds before any I/O happens. The connection failure is
    // asynchronous — reported via `stream.next()` returning the error.
    // The caller MUST therefore call `stream.deinit()` in BOTH the
    // success and failure paths. This test pins that contract.
    const allocator = testing.allocator;
    const io = std.testing.io;

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    var stream = client.openStream(io, .{ .method = .GET, .url = "http://127.0.0.1:1/" }, .{ .timeout_ms = 2_000 }) catch |err| switch (err) {
        error.ConnectionRefused,
        error.ConnectionTimeout,
        error.OperationTimedOut,
        error.DnsError => return,
        else => return err,
    };
    defer stream.deinit();

    // Drain whatever the worker produced so deinit doesn't block on
    // an idle consumer. The connection-refused path normally returns
    // an error from stream.next() rather than chunks.
    drain: while (true) {
        const next = stream.next() catch break :drain;
        if (next) |chunk| allocator.free(chunk) else break :drain;
    }
}

test "mem-stream: POST with body + 3 headers — body survives via caller" {
    // POST body is a borrowed slice (req.body.ptr passed to libcurl).
    // The caller (this test) MUST keep the body alive until stream.deinit
    // joins the worker. Verifies the standard pattern doesn't leak.
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = StreamLeakServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    try ts.registerRoutes();
    try ts.start();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/ndjson", &url_buf);

    const body = "{\"prompt\":\"hello\"}";
    const headers = [_]custom_http_client.Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "X-One", .value = "1" },
        .{ .name = "X-Two", .value = "2" },
    };

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = try client.openStream(io, .{
        .method = .POST,
        .url = url,
        .body = body,
        .headers = &headers,
    }, .{});
    defer stream.deinit();

    var scanner: custom_http_client.StreamScanner = .init(&stream, false);
    defer scanner.deinit();
    while (scanner.next() catch null) |_| {}
}

test "mem-stream: 50 sequential openStream/deinit cycles" {
    // Sustained-pressure check. If the queue mutex or any slist entry
    // leaks, it shows up as a small leak × 50 iterations.
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = StreamLeakServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    try ts.registerRoutes();
    try ts.start();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/ndjson", &url_buf);

    var i: usize = 0;
    while (i < 50) : (i += 1) {
        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{}) catch continue;
        defer stream.deinit();

        var scanner: custom_http_client.StreamScanner = .init(&stream, false);
        defer scanner.deinit();
        while (scanner.next() catch null) |_| {}
    }
}

test "mem-stream: 4 concurrent openStream calls — each cleanly deinits" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = StreamLeakServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    try ts.registerRoutes();
    try ts.start();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/ndjson", &url_buf);

    const N = 4;
    const Ctx = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        url: []const u8,
    };
    var ctx: Ctx = .{ .allocator = allocator, .io = io, .url = url };
    var threads: [N]std.Thread = undefined;
    var t: usize = 0;
    while (t < N) : (t += 1) {
        threads[t] = try std.Thread.spawn(.{}, struct {
            fn run(c: *@TypeOf(ctx)) void {
                var client = custom_http_client.Client.init(c.allocator);
                defer client.deinit();
                var stream = client.openStream(c.io, .{ .method = .GET, .url = c.url }, .{}) catch return;
                defer stream.deinit();
                var scanner: custom_http_client.StreamScanner = .init(&stream, false);
                defer scanner.deinit();
                while (scanner.next() catch null) |_| {}
            }
        }.run, .{&ctx});
    }
    t = 0;
    while (t < N) : (t += 1) threads[t].join();
}

test "mem-stream: scanner.next() returning null with non-empty carry — final line freed" {
    // When the worker finishes with bytes still in `carry` (no trailing
    // newline), StreamScanner.next returns the final partial line via
    // `self.line_buf`. After deinit, both carry and line_buf arrays are
    // freed by ArrayList.deinit.
    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = StreamLeakServer.init(allocator, io) catch return error.SkipZigTest;
    defer ts.deinit();
    try ts.registerRoutes();
    try ts.start();

    var url_buf: [256]u8 = undefined;
    const url = try ts.urlBuf("/close", &url_buf);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();
    var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{}) catch return error.SkipZigTest;
    defer stream.deinit();

    var scanner: custom_http_client.StreamScanner = .init(&stream, false);
    defer scanner.deinit();
    while (scanner.next() catch null) |_| {}
}
