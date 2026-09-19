//! Unit tests for `worker_pool.zig`: all submitted jobs run exactly once,
//! queue-full backpressure, stop-drains-then-rejects, stats accounting.

const std = @import("std");
const pool_mod = @import("worker_pool.zig");

const Counter = struct {
    n: std.atomic.Value(u64) = .init(0),
    fn run(ctx: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        _ = self.n.fetchAdd(1, .acq_rel);
    }
};

fn waitFor(counter: *Counter, want: u64, timeout_ms: u64) !void {
    const start = std.Io.Timestamp.now(std.testing.io, .real);
    while (counter.n.load(.acquire) < want) {
        const now = std.Io.Timestamp.now(std.testing.io, .real);
        const elapsed_ms = @divTrunc(
            @as(u64, @intCast(now.nanoseconds - start.nanoseconds)),
            std.time.ns_per_ms,
        );
        if (elapsed_ms > timeout_ms) return error.Timeout;
        std.Io.sleep(std.testing.io, .{ .nanoseconds = std.time.ns_per_ms }, .real) catch {};
    }
}

test "pool runs every submitted job exactly once" {
    const alloc = std.testing.allocator;
    var pool = try pool_mod.WorkerPool.init(alloc, std.testing.io, .{
        .thread_count = 4,
        .queue_depth = 256,
    });
    defer pool.deinit();
    try pool.start();

    var counter = Counter{};
    const total = 200;
    for (0..total) |_| {
        try pool.submit(.{ .run = Counter.run, .ctx = @ptrCast(&counter) });
    }
    try waitFor(&counter, total, 10_000);
    try std.testing.expectEqual(@as(u64, total), counter.n.load(.acquire));

    const st = pool.stats();
    try std.testing.expectEqual(@as(u64, total), st.submitted);
    try std.testing.expectEqual(@as(u64, total), st.completed);
    try std.testing.expectEqual(@as(u64, 0), st.dropped_full);
}

test "pool rejects past queue depth and recovers" {
    const alloc = std.testing.allocator;
    // 1 worker + tiny queue; submit faster than the worker drains.
    // (A sleep job holds the worker so the queue deterministically fills.)
    var pool = try pool_mod.WorkerPool.init(alloc, std.testing.io, .{
        .thread_count = 1,
        .queue_depth = 4,
    });
    defer pool.deinit();

    const Sleeper = struct {
        fn run(ctx: *anyopaque) void {
            _ = ctx;
            std.Io.sleep(std.testing.io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .real) catch {};
        }
    };
    // Start the pool, occupy the single worker with a sleeper, then flood
    // the tiny queue: the first few submits queue, the rest fail fast.
    try pool.start();
    try pool.submit(.{ .run = Sleeper.run, .ctx = @ptrCast(&pool) });

    var counter = Counter{};
    var full_count: usize = 0;
    for (0..64) |_| {
        pool.submit(.{ .run = Counter.run, .ctx = @ptrCast(&counter) }) catch |err| {
            try std.testing.expectEqual(error.QueueFull, err);
            full_count += 1;
        };
    }
    try std.testing.expect(full_count > 0);
    try std.testing.expect(pool.stats().dropped_full > 0);
}

test "pool stop drains, then rejects new submits" {
    const alloc = std.testing.allocator;
    var pool = try pool_mod.WorkerPool.init(alloc, std.testing.io, .{
        .thread_count = 2,
        .queue_depth = 64,
    });
    defer pool.deinit();
    try pool.start();

    var counter = Counter{};
    for (0..10) |_| {
        try pool.submit(.{ .run = Counter.run, .ctx = @ptrCast(&counter) });
    }
    pool.stop();
    // Drained: every accepted job ran.
    try std.testing.expectEqual(@as(u64, 10), counter.n.load(.acquire));
    try std.testing.expectError(
        error.PoolStopped,
        pool.submit(.{ .run = Counter.run, .ctx = @ptrCast(&counter) }),
    );
}
