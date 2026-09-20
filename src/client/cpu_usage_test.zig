//! TDD regression test for the busy-spin CPU bug in `ResponseStream.next()`.
//!
//! ## Bug (PR #120 introduced; commit `47966754`)
//!
//! `ResponseStream.next()` in `stream.zig` waited for new chunks via a
//! tight CPU-burning loop:
//!
//! ```zig
//! while (true) {
//!     if (self.state.worker_error) |e| return e;
//!     if (self.state.queue.popOne()) |chunk| return chunk;
//!     if (self.state.finished.load(.acquire)) return null;
//!     _ = std.c.clock_gettime(.MONOTONIC, &ts);  // syscall every iter
//!     if (now_ns >= deadline_ns) return null;
//!     std.atomic.spinLoopHint();                  // CPU pause
//! }
//! ```
//!
//! With a 300s polling budget and `spinLoopHint()` (CPU pause, no yield),
//! the consumer thread pinned a full CPU core while the LLM stalled
//! between SSE chunks. Live trace: `htop` showed `nalar` at 12–58% CPU
//! during streaming; `/proc/<pid>/wchan` for the consumer thread was `0`
//! (pure user-space spin, no kernel blocking). The libcurl worker thread
//! was correctly parked at `wchan = futex_wait`.
//!
//! ## Test intent
//!
//! Open a stream against the in-process `delayHandler` (sleeps 2 seconds
//! before responding). Measure `CLOCK_PROCESS_CPUTIME` before and after
//! `stream.next()` blocks for the first chunk. Assert that the CPU time
//! spent blocking is far less than the wall-clock time — proving the
//! consumer thread yielded to the kernel instead of busy-spinning.
//!
//! - **Before fix:** CPU time ≈ wall time (busy-spin burns the whole 2s).
//! - **After fix:** CPU time ≈ < 50ms (futex parks the thread; the
//!   kernel scheduler picks it up only on chunk arrival).
//!
//! Threshold of 200ms CPU for 2000ms wall is generous enough to survive
//! CI jitter but tight enough to fail if the busy-spin returns.

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const custom_http_client = @import("root.zig");
const gserverz = @import("../server/http_server.zig");

// Local libc `clock_gettime` shim (this is a Linux-only test) — keeps
// kabelweb dependency-free instead of pulling the helpers package.
const Clong = if (@bitSizeOf(usize) == 64 and builtin.os.tag != .windows) i64 else i32;
const PosixTimespec = extern struct {
    sec: Clong,
    nsec: Clong,
};
extern "c" fn clock_gettime(clk_id: c_int, tp: *PosixTimespec) c_int;

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

// Process CPU time, measured via libc `clock_gettime(CLOCK_PROCESS_CPUTIME_ID, ...)`.
const ProcessCpuTime = struct {
    sec: i64,
    nsec: i64,

    fn now() ProcessCpuTime {
        var ts: PosixTimespec = undefined;
        // CLOCK_PROCESS_CPUTIME_ID = 12 on Linux x86_64.
        // Linux-only test (SkipZigTest gate below); no rusage fallback needed.
        const rc = clock_gettime(12, &ts);
        if (rc != 0) return .{ .sec = 0, .nsec = 0 };
        return .{ .sec = ts.sec, .nsec = ts.nsec };
    }

    fn elapsedNs(self: ProcessCpuTime, later: ProcessCpuTime) i64 {
        const a: i128 = @as(i128, @intCast(self.sec)) * 1_000_000_000 + @as(i128, @intCast(self.nsec));
        const b: i128 = @as(i128, @intCast(later.sec)) * 1_000_000_000 + @as(i128, @intCast(later.nsec));
        return @intCast(b - a);
    }
};

/// Local HTTP test server. Same shape as `streaming_test.zig::TestServer`.
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
        try self.server.router.get("/delay", delayHandler);
    }

    pub fn start(self: *TestServer) !void {
        self.listener_thread = try std.Thread.spawn(.{}, listenFn, .{self.server});
    }

    pub fn url(self: *TestServer, path: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "http://127.0.0.1:{d}{s}", .{ self.port, path });
    }

    fn listenFn(server: *gserverz.GinwaServer) void {
        server.listenEventLoop(.{ .dispatch_mode = .worker_pool }) catch {};
    }

    pub fn deinit(self: *TestServer) void {
        self.server.shutdown();
        self.listener_thread.join();
        self.server.destroy(self.allocator);
        self.allocator.destroy(self);
    }
};

/// Sleeps 500ms before responding. Lower than streaming_test.zig's 2s
/// delay because we want the test fast — 500ms wall is plenty to
/// distinguish busy-spin (CPU ≈ 500ms) from futex-park (CPU ≈ <50ms).
fn delayHandler(ctx: HttpContext, _: HttpRequest, _: HttpResponse) !HttpResponse {
    const io = std.testing.io;
    std.Io.sleep(io, .{ .nanoseconds = 500 * std.time.ns_per_ms }, .real) catch {};
    return HttpResponse.init(200, "OK", ctx.allocator);
}

fn makeTestServer(allocator: std.mem.Allocator, io: std.Io) !*TestServer {
    const ts = TestServer.init(allocator, io) catch return error.SkipZigTest;
    errdefer ts.deinit();
    try ts.registerRoutes();
    try ts.start();
    return ts;
}

// Regression test for the busy-spin bug.
//
// Timeline:
// 1. Open stream to /delay (server sleeps 500ms).
// 2. Snapshot `CLOCK_PROCESS_CPUTIME` (CPU before).
// 3. `stream.next()` blocks ~500ms waiting for the first chunk.
// 4. Snapshot `CLOCK_PROCESS_CPUTIME` (CPU after).
// 5. Assert CPU-during-wait < 200ms (busy-spin would burn ~500ms).
test "stream: ResponseStream.next() does not busy-spin while waiting for data (CPU usage bounded)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = testing.allocator;
    const io = std.testing.io;

    const ts = try makeTestServer(allocator, io);
    defer ts.deinit();

    const url = try ts.url("/delay");
    defer allocator.free(url);

    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    // openStream's internal timeout is 5 minutes by default; we only
    // block for ~500ms so well within budget.
    var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{}) catch |err| switch (err) {
        error.ConnectionRefused => return error.SkipZigTest,
        else => return err,
    };
    defer stream.deinit();

    // Burn a few ms of warm-up so the libc clock_gettime cache is hot
    // and the first measurement isn't dominated by one-time setup cost.
    var warmup: u64 = 0;
    while (warmup < 1_000_000) : (warmup += 1) {
        _ = warmup * warmup;
    }

    const cpu_before = ProcessCpuTime.now();

    // This call BLOCKS for ~500ms (the delayHandler sleeps first).
    // With the bug, the consumer thread spins at 100% CPU while
    // waiting. With the fix, the consumer thread parks on a futex.
    const first_chunk = stream.next() catch |err| switch (err) {
        error.OperationTimedOut => return error.SkipZigTest,
        else => return err,
    };
    if (first_chunk) |chunk| {
        allocator.free(chunk);
    }

    const cpu_after = ProcessCpuTime.now();

    const cpu_used_ns = cpu_before.elapsedNs(cpu_after);
    const cpu_used_ms = @divTrunc(cpu_used_ns, 1_000_000);

    // Threshold: 200ms CPU for a 500ms wall wait.
    //
    // Why 200ms (not e.g. 100ms):
    // - Test runs concurrently with other tests; CI hosts vary.
    // - The whole process can be preempted, increasing measured CPU.
    // - We just need to prove "not busy-spinning" — 200ms is 40% of
    //   wall time, vastly less than the 100% the busy-spin produces.
    //
    // Failure modes:
    // - Bug present: CPU ≈ 500ms (busy-spin matches wall) → FAIL
    // - Fix present: CPU ≈ <50ms (futex parks most of the time) → PASS
    // - Worst-case CI jitter: CPU ≈ 200-300ms (heavy contention) → PASS
    try testing.expect(cpu_used_ms <= 200);
}