//! Bounded worker pool for the event-loop migration (Phase 5).
//!
//! The reactor (`event_loop.zig`) must never block: slow handlers run here
//! instead. Generic function-pointer jobs — the loop submits offloaded
//! request dispatches; nothing in this file knows about HTTP.
//!
//! Sync primitives follow the repo's Zig 0.16 rules: `std.Io.Mutex` +
//! `std.Io.Condition` (both take `io`, futex-based; same pattern as
//! `cronjob_manager.zig`'s tick thread), atomics for stats. POSIX + Windows
//! (no fd use here at all).
//!
//! Backpressure: `submit` returns `error.QueueFull` instead of blocking, so
//! the loop thread can fall back to inline dispatch and keep serving.

const std = @import("std");

/// One unit of work. `run` executes on a pool thread; it must not touch
/// loop-thread-only state (the caller arranges handoff, e.g. a completion
/// queue + wake fd — see `event_loop.zig`).
pub const Job = struct {
    run: *const fn (ctx: *anyopaque) void,
    ctx: *anyopaque,
};

pub const Config = struct {
    /// Worker thread count. 0 = one per CPU (min 2).
    thread_count: usize = 0,
    /// Max queued (not yet started) jobs. `submit` fails past this.
    queue_depth: usize = 1024,
    /// OS thread stack per worker. Dispatch runs handlers + templates;
    /// keep the default unless RSS measurements say otherwise.
    stack_size: usize = 8 * 1024 * 1024,
};

pub const Stats = struct {
    submitted: u64 = 0,
    completed: u64 = 0,
    dropped_full: u64 = 0,
};

pub const WorkerPool = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    cfg: Config,
    threads: []std.Thread = &.{},
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    /// Ring buffer of pending jobs, capacity = queue_depth.
    buf: []Job = &.{},
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    running: std.atomic.Value(bool) = .init(false),
    submitted: std.atomic.Value(u64) = .init(0),
    completed: std.atomic.Value(u64) = .init(0),
    dropped_full: std.atomic.Value(u64) = .init(0),

    pub fn init(alloc: std.mem.Allocator, io: std.Io, cfg: Config) !WorkerPool {
        var thread_count = cfg.thread_count;
        if (thread_count == 0) {
            thread_count = @max(2, std.Thread.getCpuCount() catch 4);
        }
        const depth = @max(1, cfg.queue_depth);
        return .{
            .alloc = alloc,
            .io = io,
            .cfg = .{
                .thread_count = thread_count,
                .queue_depth = depth,
                .stack_size = cfg.stack_size,
            },
            .buf = try alloc.alloc(Job, depth),
        };
    }

    /// Spawn workers. Idempotent-ish: calling twice without `stop` leaks
    /// the first set — callers (`EventLoop.run`) start exactly once.
    pub fn start(self: *WorkerPool) !void {
        self.threads = try self.alloc.alloc(std.Thread, self.cfg.thread_count);
        errdefer self.alloc.free(self.threads);
        self.running.store(true, .release);
        for (self.threads) |*t| {
            t.* = try std.Thread.spawn(
                .{ .stack_size = self.cfg.stack_size },
                workerLoop,
                .{self},
            );
        }
    }

    /// Stop accepting, drain already-queued jobs, join workers. `submit`
    /// after `stop` fails with `error.PoolStopped`. Every accepted job
    /// runs exactly once, so job-ctx ownership always resolves in `run`.
    pub fn stop(self: *WorkerPool) void {
        if (!self.running.load(.acquire)) return;
        self.mutex.lockUncancelable(self.io);
        self.running.store(false, .release);
        self.cond.broadcast(self.io);
        self.mutex.unlock(self.io);
        for (self.threads) |t| t.join();
        self.alloc.free(self.threads);
        self.threads = &.{};
    }

    pub fn deinit(self: *WorkerPool) void {
        self.stop();
        self.alloc.free(self.buf);
        self.buf = &.{};
    }

    pub fn stats(self: *const WorkerPool) Stats {
        return .{
            .submitted = self.submitted.load(.acquire),
            .completed = self.completed.load(.acquire),
            .dropped_full = self.dropped_full.load(.acquire),
        };
    }

    /// Enqueue a job. Never blocks: `error.QueueFull` when at capacity,
    /// `error.PoolStopped` after `stop`.
    pub fn submit(self: *WorkerPool, job: Job) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (!self.running.load(.acquire)) return error.PoolStopped;
        if (self.count >= self.buf.len) {
            _ = self.dropped_full.fetchAdd(1, .acq_rel);
            return error.QueueFull;
        }
        self.buf[self.tail] = job;
        self.tail = (self.tail + 1) % self.buf.len;
        self.count += 1;
        _ = self.submitted.fetchAdd(1, .acq_rel);
        self.cond.signal(self.io);
    }

    fn popLocked(self: *WorkerPool) Job {
        const job = self.buf[self.head];
        self.head = (self.head + 1) % self.buf.len;
        self.count -= 1;
        return job;
    }

    fn workerLoop(self: *WorkerPool) void {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            while (self.count == 0 and self.running.load(.acquire)) {
                self.cond.waitUncancelable(self.io, &self.mutex);
            }
            // Stopped AND drained: exit. Leftover jobs submitted before
            // `stop` are still RUN (not dropped) so every accepted job's
            // ctx is released exactly once by its `run` fn — the event
            // loop then frees unclaimed completions in `deinit`.
            if (self.count == 0) {
                self.mutex.unlock(self.io);
                return;
            }
            const job = self.popLocked();
            self.mutex.unlock(self.io);
            job.run(job.ctx);
            _ = self.completed.fetchAdd(1, .acq_rel);
        }
    }
};

test {
    _ = @import("worker_pool_test.zig");
}
