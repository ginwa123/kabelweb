//! Unit tests for `cronjob_manager.zig` (single-threaded portion).
//!
//! The thread-related tests (`start` / `stop`) live in the same file but
//! are gated on `builtin.os.tag != .windows` because std.Thread.spawn has
//! slightly different semantics there and the project's CI runs on Linux.

const std = @import("std");
const builtin = @import("builtin");
const cron_expr = @import("cron_expression.zig");
const cronjob_manager_mod = @import("cronjob_manager.zig");
const CronjobManager = cronjob_manager_mod.CronjobManager;
const CronJob = cronjob_manager_mod.CronJob;

const testing = std.testing;

// ============================================================================
// Test helpers
// ============================================================================

fn testCallback(ctx: ?*anyopaque, now_unix: i64) void {
    const counter: *u32 = @ptrCast(@alignCast(ctx.?));
    counter.* += 1;
    _ = now_unix;
}

const TestCounter = struct {
    value: u32 = 0,
};

// ============================================================================
// Registry tests — register / unregister / list
// ============================================================================

test "register: stores job and returns monotonic id" {
    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    const id1 = try mgr.register("* * * * *", "every-minute", testCallback, null, 0);
    const id2 = try mgr.register("0 0 * * *", "midnight", testCallback, null, 0);

    try testing.expect(id2 > id1);
    try testing.expectEqual(@as(usize, 2), mgr.list().len);
}

test "register: rejects invalid expression with CronError" {
    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    // 7-field expression → InvalidExpression
    try testing.expectError(error.InvalidExpression, mgr.register("* * * * * * *", "bad", testCallback, null, 0));
    // Hour out of range → InvalidField
    try testing.expectError(error.InvalidField, mgr.register("* 24 * * *", "bad-hour", testCallback, null, 0));
    // Minute out of range → InvalidField
    try testing.expectError(error.InvalidField, mgr.register("60 * * * *", "bad-minute", testCallback, null, 0));
}

test "register: duplicate names are allowed (id is the unique key)" {
    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    const id1 = try mgr.register("0 0 * * *", "same-name", testCallback, null, 0);
    const id2 = try mgr.register("0 12 * * *", "same-name", testCallback, null, 0);

    try testing.expect(id1 != id2);
    try testing.expectEqual(@as(usize, 2), mgr.list().len);
}

test "unregister: by id removes the job; missing id is a no-op (idempotent)" {
    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    const id = try mgr.register("* * * * *", "housekeeping", testCallback, null, 0);
    try testing.expectEqual(@as(usize, 1), mgr.list().len);

    mgr.unregister(id);
    try testing.expectEqual(@as(usize, 0), mgr.list().len);

    // Missing id must not crash (idempotent).
    mgr.unregister(9999);
    try testing.expectEqual(@as(usize, 0), mgr.list().len);
}

test "list: returns all registered jobs in registration order" {
    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    _ = try mgr.register("0 0 * * *", "first", testCallback, null, 0);
    _ = try mgr.register("0 12 * * *", "second", testCallback, null, 0);
    _ = try mgr.register("*/5 * * * *", "third", testCallback, null, 0);

    const jobs = mgr.list();
    try testing.expectEqual(@as(usize, 3), jobs.len);
    try testing.expectEqualStrings("first", jobs[0].name);
    try testing.expectEqualStrings("second", jobs[1].name);
    try testing.expectEqualStrings("third", jobs[2].name);
}

// ============================================================================
// Tick tests — driven by a fake "now" parameter, no real clock
// ============================================================================

test "tick: before nextFireAfter, no callback fires" {
    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    var counter: u32 = 0;
    // Register at 11:00 — the next "0 12 * * *" match is 12:00 today.
    const register_time: i64 = 1735689600 + 11 * 3600;
    _ = try mgr.register("0 12 * * *", "noon", testCallback, &counter, register_time);

    // Tick at 11:30 — no match yet, callback should not fire.
    mgr.tick(1735689600 + 11 * 3600 + 30 * 60); // 2025-01-01T11:30:00Z
    try testing.expectEqual(@as(u32, 0), counter);
}

test "tick: at or after nextFireAfter, callback fires once" {
    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    var counter: u32 = 0;
    // Register at 11:00 — next "0 12 * * *" match is 12:00 today.
    const register_time: i64 = 1735689600 + 11 * 3600;
    _ = try mgr.register("0 12 * * *", "noon", testCallback, &counter, register_time);

    const noon_unix: i64 = 1735689600 + 12 * 3600; // 2025-01-01T12:00:00Z
    mgr.tick(noon_unix);
    try testing.expectEqual(@as(u32, 1), counter);
}

test "tick: callback fires once per tick that matches; subsequent ticks at later times fire again" {
    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    var counter: u32 = 0;
    // Register at 11:00 — first match is today's noon.
    const register_time: i64 = 1735689600 + 11 * 3600;
    _ = try mgr.register("0 12 * * *", "noon", testCallback, &counter, register_time);

    const day1_noon: i64 = 1735689600 + 12 * 3600;
    const day2_noon: i64 = day1_noon + 86400;

    mgr.tick(day1_noon);
    try testing.expectEqual(@as(u32, 1), counter);

    // Same minute, no second tick → counter stays at 1.
    mgr.tick(day1_noon);
    try testing.expectEqual(@as(u32, 1), counter);

    // Next day, same time → counter increments.
    mgr.tick(day2_noon);
    try testing.expectEqual(@as(u32, 2), counter);
}

test "tick: every-minute job fires on every minute-aligned tick" {
    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    var counter: u32 = 0;
    // Register at exactly 00:00:00 — first match is the next minute.
    const register_time: i64 = 1735689600;
    _ = try mgr.register("* * * * *", "every-minute", testCallback, &counter, register_time);

    const t0: i64 = 1735689600;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        mgr.tick(t0 + @as(i64, @intCast(i)) * 60);
    }
    try testing.expectEqual(@as(u32, 5), counter);
}

// ============================================================================
// Threading tests — start / stop (Linux / macOS only)
// ============================================================================

test "start + stop: spawns and joins the thread cleanly" {
    if (builtin.os.tag == .windows) return; // skip on Windows

    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    try mgr.start();
    mgr.stop();
    // Stop must be idempotent.
    mgr.stop();
}

test "start: every-minute job fires within 3 seconds" {
    if (builtin.os.tag == .windows) return;

    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    var counter: u32 = 0;
    _ = try mgr.register("* * * * *", "tick", testCallback, &counter, 0);

    try mgr.start();
    defer mgr.stop();

    // Wait up to 3 seconds for at least one callback.
    const deadline = std.Io.Clock.now(.real, testing.io).toMilliseconds() + 3000;
    while (std.Io.Clock.now(.real, testing.io).toMilliseconds() < deadline) {
        std.Io.sleep(testing.io, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .real) catch {};
        if (counter >= 1) break;
    }
    try testing.expect(counter >= 1);
}

test "start: register after start is allowed (no race with the tick loop)" {
    if (builtin.os.tag == .windows) return;

    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    try mgr.start();
    defer mgr.stop();

    var counter: u32 = 0;
    _ = try mgr.register("* * * * *", "post-start", testCallback, &counter, 0);

    const deadline = std.Io.Clock.now(.real, testing.io).toMilliseconds() + 3000;
    while (std.Io.Clock.now(.real, testing.io).toMilliseconds() < deadline) {
        std.Io.sleep(testing.io, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .real) catch {};
        if (counter >= 1) break;
    }
    try testing.expect(counter >= 1);
}

test "start: double-start is a no-op (idempotent)" {
    if (builtin.os.tag == .windows) return;

    const allocator = testing.allocator;
    var mgr = CronjobManager.init(allocator, testing.io);
    defer mgr.deinit();

    try mgr.start();
    try mgr.start(); // must not crash or spawn a second thread
    mgr.stop();
}