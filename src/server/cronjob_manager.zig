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