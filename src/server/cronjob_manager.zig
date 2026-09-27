//! Cronjob manager — registry of cron-scheduled callbacks.
//!
//! Each registered job holds:
//!   - a parsed `CronExpression`
//!   - a user callback `fn (ctx, now_unix) void`
//!   - a name (for log lines)
//!   - the timestamp of the last fire (so `tick` doesn't fire the same
//!     minute twice if it's called repeatedly)
//!
//! The manager is thread-safe: `register`, `unregister`, `list` may be
//! called from request handlers; the background `start` thread holds the
//! same lock during `tick`. Callbacks run OUTSIDE the lock so a
//! callback may safely call `register` / `unregister`.
//!
//! Background thread: when `start` is called, a thread is spawned that
//! wakes once per second and calls `tick(now)`. `stop` signals the
//! thread to exit and joins it. `start` is idempotent (second call is a
//! no-op); `stop` is idempotent.

const std = @import("std");
const builtin = @import("builtin");
const cron_expr = @import("cron_expression.zig");
const CronExpression = cron_expr.CronExpression;
const CronError = cron_expr.CronError;

/// One registered cron job.
pub const CronJob = struct {
    id: u64,
    expr: CronExpression,
    callback: *const fn (ctx: ?*anyopaque, now_unix: i64) void,
    ctx: ?*anyopaque,
    name: []const u8, // owned by the manager's allocator
    /// Unix-seconds timestamp of the most recent fire, or 0 if never
    /// fired. Used by `tick` to avoid firing the same minute twice.
    last_fired_at: i64 = 0,
};

pub const CronjobManager = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    jobs: std.ArrayListUnmanaged(CronJob) = .empty,
    lock: std.Io.Mutex = .init,
    next_id: u64 = 1,

    // Background-thread state (only used by `start` / `stop`).
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = .init(false),

    /// Construct a new manager. Does not allocate the background thread
    /// — call `start` to begin ticking.
    pub fn init(allocator: std.mem.Allocator, io: std.Io) CronjobManager {
        return .{
            .allocator = allocator,
            .io = io,
        };
    }

    /// Free all registered jobs and their owned strings. Does NOT call
    /// `stop` — the caller is responsible for that ordering. (If the
    /// background thread is still running, `deinit` is a use-after-free.)
    pub fn deinit(self: *CronjobManager) void {
        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);
        for (self.jobs.items) |job| {
            self.allocator.free(job.name);
        }
        self.jobs.deinit(self.allocator);
    }

    /// Register a new cron job. Returns the assigned job id (monotonic).
    ///
    /// `now_unix` is the Unix-seconds anchor for `last_fired_at`. The
    /// job will NOT fire until the first scheduled time STRICTLY AFTER
    /// `now_unix` — this prevents a fresh registration from
    /// back-filling every historical match.
    ///
    /// Errors:
    ///   - `CronError.InvalidExpression` / `CronError.InvalidField` if
    ///     the expression is malformed (validation happens at register
    ///     time, per design decision).
    ///   - `std.mem.Allocator.Error` if the manager cannot grow its
    ///     jobs list or duplicate the name.
    pub fn register(
        self: *CronjobManager,
        expression: []const u8,
        name: []const u8,
        callback: *const fn (ctx: ?*anyopaque, now_unix: i64) void,
        ctx: ?*anyopaque,
        now_unix: i64,
    ) (CronError || std.mem.Allocator.Error)!u64 {
        const expr = try CronExpression.parse(expression);
        const name_copy = try self.allocator.dupe(u8, name);

        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);

        const id = self.next_id;
        self.next_id += 1;

        try self.jobs.append(self.allocator, .{
            .id = id,
            .expr = expr,
            .callback = callback,
            .ctx = ctx,
            .name = name_copy,
            .last_fired_at = now_unix,
        });
        return id;
    }

    /// Remove a job by id. Idempotent — removing an unknown id is a no-op.
    pub fn unregister(self: *CronjobManager, id: u64) void {
        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);

        for (self.jobs.items, 0..) |job, i| {
            if (job.id == id) {
                self.allocator.free(job.name);
                _ = self.jobs.orderedRemove(i);
                return;
            }
        }
    }

    /// Return a snapshot of the registered jobs in registration order.
    /// The returned slice is invalidated by any subsequent `register` /
    /// `unregister` call.
    pub fn list(self: *CronjobManager) []const CronJob {
        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);
        return self.jobs.items;
    }

    /// Fire every job whose `nextFireAfter(last_fired_at) <= now`. Each
    /// job fires at most once per call. Safe to invoke from any thread.
    ///
    /// Callbacks run OUTSIDE the registry lock so a callback may call
    /// `register` / `unregister` without deadlocking.
    pub fn tick(self: *CronjobManager, now_unix: i64) void {
        // Snapshot the jobs list under the lock. Then iterate outside
        // the lock to invoke callbacks — this avoids holding the lock
        // across user code that may re-enter the manager.
        var snapshot: std.ArrayListUnmanaged(CronJob) = .empty;
        defer snapshot.deinit(self.allocator);

        {
            self.lock.lock(self.io) catch unreachable;
            defer self.lock.unlock(self.io);
            snapshot.appendSlice(self.allocator, self.jobs.items) catch return;
        }

        for (snapshot.items) |job| {
            const next = job.expr.nextFireAfter(job.last_fired_at) orelse continue;
            if (next > now_unix) continue;

            // Update last_fired_at under the lock so a concurrent tick
            // (rare — only one background thread in practice) doesn't
            // double-fire. Bump by 60s (one minute past the match) so
            // a re-tick at the same `now` won't re-fire: `nextFireAfter`
            // returns the next match `>= last_fired_at`, and we'd be
            // comparing against a future match next time.
            {
                self.lock.lock(self.io) catch unreachable;
                defer self.lock.unlock(self.io);
                for (self.jobs.items) |*mutable_job| {
                    if (mutable_job.id == job.id) {
                        if (mutable_job.last_fired_at < next + 60) {
                            mutable_job.last_fired_at = next + 60;
                        }
                        break;
                    }
                }
            }

            // Invoke the user callback OUTSIDE the lock.
            job.callback(job.ctx, next);
        }
    }

    // =========================================================================
    // Background thread — `start` / `stop`
    // =========================================================================

    /// Spawn the background tick thread. Idempotent: a second call is a
    /// no-op. The thread runs until `stop` is called.
    pub fn start(self: *CronjobManager) !void {
        // Atomically transition false → true; if already true, no-op.
        const was_running = self.running.cmpxchgStrong(false, true, .seq_cst, .seq_cst);
        if (was_running == null) {
            // We won the transition — spawn the thread.
            self.thread = try std.Thread.spawn(.{}, tickLoop, .{self});
            return;
        }
        // Already running — nothing to do.
    }

    /// Signal the background thread to stop and join it. Idempotent.
    pub fn stop(self: *CronjobManager) void {
        if (!self.running.load(.seq_cst)) return;
        self.running.store(false, .seq_cst);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Background thread entry point. Sleeps ~1 second between ticks,
    /// breaks on `running == false`.
    fn tickLoop(self: *CronjobManager) void {
        while (self.running.load(.seq_cst)) {
            std.Io.sleep(self.io, .{ .nanoseconds = std.time.ns_per_s }, .real) catch break;
            if (!self.running.load(.seq_cst)) break;

            const now = std.Io.Clock.now(.real, self.io).toSeconds();
            self.tick(now);
        }
    }
};

// ============================================================================
// Tests — moved here from `cronjob_manager_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = cronjob_manager_tests; }` below pulls them into the run.
// ============================================================================

const cronjob_manager_tests = struct {
    // Unit tests for `cronjob_manager.zig` (single-threaded portion).
    //
    // The thread-related tests (`start` / `stop`) live in the same file but
    // are gated on `builtin.os.tag != .windows` because std.Thread.spawn has
    // slightly different semantics there and the project's CI runs on Linux.

    const cronjob_manager_mod = @import("cronjob_manager.zig");

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
};

comptime {
    _ = cronjob_manager_tests;
}
