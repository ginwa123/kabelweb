//! Single-threaded poll reactor for plain HTTP/1.1 (Phase 2-3).
//!
//! Non-breaking companion to `http_server.zig:listen` (thread-per-connection).
//! `GinwaServer.listenEventLoop` runs this instead of the accept+
//! `group.concurrent` loop. Scope of v1:
//!
//!   - POSIX only (`nb_socket` returns `Unsupported` on Windows).
//!   - Plain HTTP/1.1 only. SSE / WebSocket / H2 / TLS routes get a
//!     `501 Not Implemented` (same status the threaded path already uses
//!     for SSE+WS-over-TLS) so long-lived upgrades never silently hang.
//!   - One poll loop per `listenEventLoop` call. Multi-loop
//!     (SO_REUSEPORT, one per core) is Phase 6 — the `Config` already
//!     carries `loop_id`/`loop_count` so the cutover is additive.
//!
//! Framing (no blocking reads anywhere):
//!   read_buf accumulates bytes; `extractRequest` returns a complete
//!   request (headers + Content-Length body) or null when more bytes are
//!   needed.
//!
//! Dispatch modes (`Config.dispatch_mode`):
//!   - `.direct` (default): dispatch runs on the loop thread. Fastest for
//!     fast handlers; a slow handler stalls every conn on this loop.
//!   - `.worker_pool`: complete requests are handed to a bounded
//!     `worker_pool.zig:WorkerPool`; the loop thread only does I/O.
//!     Completions return via a mutex queue + socketpair wake fd. Queue-full
//!     falls back to direct (counted in `Stats.inline_fallback`).
//!     The loop allocator must be thread-safe in this mode.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const nb = @import("nb_socket.zig");
const http_parser = @import("http_parser.zig");
const worker_pool_mod = @import("worker_pool.zig");

pub const HttpRequest = http_parser.HttpRequest;
pub const HttpResponse = http_parser.HttpResponse;
pub const HttpContext = http_parser.HttpContext;

/// Where request dispatch runs.
pub const DispatchMode = enum {
    /// On the loop thread (fast handlers; slow ones stall the loop).
    direct,
    /// On `worker_pool.zig` threads (loop thread does I/O only).
    worker_pool,
};

/// Tuning knobs for one reactor loop.
pub const Config = struct {
    /// Max simultaneous connections on this loop (backpressure: beyond this
    /// the reactor closes the newest fd immediately and counts `dropped`).
    max_conns: usize = 1024,
    /// Idle keep-alive deadline per connection (ms). 0 = no timeout.
    idle_timeout_ms: i64 = 60_000,
    /// Deadline to complete request HEADERS after first byte (ms). 0 = none.
    header_timeout_ms: i64 = 5_000,
    /// Hard cap on buffered request bytes per conn (headers+body).
    /// Beyond this the conn gets `413` + close (mirrors `max_body_bytes`).
    max_request_bytes: usize = 8 * 1024 * 1024,
    /// Max requests served per keep-alive connection before close.
    /// Mirrors the threaded path's `keep_alive_count < 1000` rule.
    max_requests_per_conn: u32 = 1000,
    /// This loop's index / total loops (Phase 6 multi-loop; informational v1).
    loop_id: usize = 0,
    loop_count: usize = 1,
    /// Where dispatch runs (see `DispatchMode`).
    dispatch_mode: DispatchMode = .direct,
    /// Pool threads in `worker_pool` mode. 0 = one per CPU (min 2).
    worker_threads: usize = 0,
    /// Max queued (undispatched) offload jobs. Past this, dispatch falls
    /// back to inline so the loop keeps serving (counted, not dropped).
    worker_queue_depth: usize = 1024,
};

/// Dispatch callback supplied by `http_server.zig`. Receives the parsed
/// request; returns the response to serialize (ownership: arena in `alloc`).
/// Returning an error makes the reactor send `500` + close.
pub const OnRequestFn = *const fn (
    ctx: *anyopaque,
    alloc: std.mem.Allocator,
    req: *const HttpRequest,
    http_ctx: HttpContext,
) anyerror!HttpResponse;

/// Per-connection state.
pub const ConnState = enum {
    reading,
    writing,
    closing,
};

pub const Conn = struct {
    fd: i32,
    /// Stable identity for offload completions (indices shift on remove).
    id: u64 = 0,
    state: ConnState = .reading,
    read_buf: std.ArrayList(u8) = .empty,
    write_buf: std.ArrayList(u8) = .empty,
    write_off: usize = 0,
    /// ms timestamp of first byte of current request (header timeout).
    req_start_ms: i64 = 0,
    /// ms timestamp of last successful read/write (idle timeout).
    last_active_ms: i64 = 0,
    keep_alive_count: u32 = 0,
    /// Set by dispatch: false → close after outbox flushes.
    keep_alive_next: bool = false,
    /// A dispatch job is in flight on the pool for this conn. While set,
    /// the loop buffers but never dispatches (ordering) — the completion
    /// clears it. Idle timeout still applies (a stuck worker can't pin
    /// the conn; its late completion is then dropped).
    pending: bool = false,
    /// Set when EOF/error seen; reactor closes after flushing (never here —
    /// v1 always closes immediately since responses are small).
    closed: bool = false,

    pub fn deinit(self: *Conn, alloc: std.mem.Allocator) void {
        self.read_buf.deinit(alloc);
        self.write_buf.deinit(alloc);
    }
};

pub const Stats = struct {
    accepted: u64 = 0,
    served: u64 = 0,
    dropped_backpressure: u64 = 0,
    closed_idle: u64 = 0,
    closed_error: u64 = 0,
    err_413: u64 = 0,
    err_400: u64 = 0,
    err_500: u64 = 0,
    /// Requests handed to the pool (worker_pool mode).
    offloaded: u64 = 0,
    /// Pool-full fallbacks served inline instead.
    inline_fallback: u64 = 0,
    /// Completions dropped (conn gone, or push OOM).
    completion_dropped: u64 = 0,

    /// Field-wise sum (multi-loop aggregation into `el_stats`).
    pub fn combine(self: Stats, other: Stats) Stats {
        return .{
            .accepted = self.accepted + other.accepted,
            .served = self.served + other.served,
            .dropped_backpressure = self.dropped_backpressure + other.dropped_backpressure,
            .closed_idle = self.closed_idle + other.closed_idle,
            .closed_error = self.closed_error + other.closed_error,
            .err_413 = self.err_413 + other.err_413,
            .err_400 = self.err_400 + other.err_400,
            .err_500 = self.err_500 + other.err_500,
            .offloaded = self.offloaded + other.offloaded,
            .inline_fallback = self.inline_fallback + other.inline_fallback,
            .completion_dropped = self.completion_dropped + other.completion_dropped,
        };
    }
};

/// A finished offload job, owned by the loop thread from push to consume.
/// `body` is the fully serialized HTTP response (loop allocator).
pub const Completion = struct {
    conn_id: u64,
    body: []u8,
    keep_alive: bool,
};

/// Heap ctx for one offloaded request (loop allocator; freed by the worker
/// that runs it — exactly once, since every accepted job runs exactly once).
const OffloadJob = struct {
    loop: *EventLoop,
    conn_id: u64,
    /// Owned copy of the complete request bytes (framing already done).
    req_bytes: []u8,
    /// Conn's keep_alive_count at offload time (for the reuse cap).
    ka_count: u32,
    /// Client fd at offload time (for `parseRequest`'s `_client_fd`).
    client_fd: i32,
};

/// Find the end of headers. Returns index just past `\r\n\r\n`, or null.
pub fn findHeaderEnd(buf: []const u8) ?usize {
    const idx = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    return idx + 4;
}

/// Parse Content-Length from a header block (bytes before header end).
/// Returns 0 when absent. Returns error.BadRequest on garbage value.
pub fn parseContentLength(header_block: []const u8) !usize {
    var lines = std.mem.splitSequence(u8, header_block, "\r\n");
    _ = lines.next(); // request line
    while (lines.next()) |line| {
        if (line.len > 15 and std.ascii.eqlIgnoreCase(line[0..14], "content-length")) {
            const colon = std.mem.indexOf(u8, line, ":") orelse continue;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            return std.fmt.parseInt(usize, value, 10) catch return error.BadRequest;
        }
    }
    return 0;
}

/// If `buf` holds at least one complete request (headers + body), return its
/// total length. Else return null (need more bytes). Errors on oversize/bad CL.
pub fn extractRequestLen(buf: []const u8, max_request_bytes: usize) !?usize {
    const head_end = findHeaderEnd(buf) orelse {
        if (buf.len > max_request_bytes) return error.RequestTooLarge;
        return null;
    };
    const cl = parseContentLength(buf[0..head_end]) catch return error.BadRequest;
    const total = head_end + cl;
    if (total > max_request_bytes) return error.RequestTooLarge;
    if (buf.len < total) return null;
    return total;
}

fn nowMs(io: std.Io) i64 {
    // Same clock source as `sse_manager.zig:timestamp` (Zig 0.16 has no
    // `std.time.milliTimestamp`; time goes through `std.Io.Timestamp`).
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}

fn closeFd(fd: i32) void {
    if (comptime nb.is_windows) return;
    _ = posix.system.close(fd);
}

/// The reactor. Owns its conns; borrows listener fd + dispatch callback.
///
/// Threading contract: every field is loop-thread-only EXCEPT
/// `completions` / `compl_lock` / `compl_dropped` / `wake_write` (written
/// by pool workers via `pushCompletion`) and the immutable-after-start
/// `cfg` / `on_request` / `on_request_ctx` / `http_ctx_template` / `io` /
/// `alloc` (read by workers; `alloc` must be thread-safe in pool mode).
pub const EventLoop = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    cfg: Config,
    listener_fd: i32 = -1,
    conns: std.ArrayList(Conn) = .empty,
    running: bool = false,
    stats: Stats = .{},
    on_request: ?OnRequestFn = null,
    on_request_ctx: ?*anyopaque = null,
    http_ctx_template: HttpContext = undefined,
    next_conn_id: u64 = 1,
    /// Pool for `worker_pool` mode. Value-embedded (not pointer): assigned
    /// BEFORE `start()` so worker threads never see a moved struct.
    pool: ?worker_pool_mod.WorkerPool = null,
    /// Completed offloads waiting for the loop thread (worker-pushed).
    completions: std.ArrayList(Completion) = .empty,
    compl_lock: std.atomic.Mutex = .unlocked,
    /// Push-side OOM drops, folded into `stats` on drain (under lock).
    compl_dropped: u64 = 0,
    /// socketpair wake channel in pool mode (loop polls `wake_read`,
    /// workers write one byte to `wake_write` per completion). -1 = unused.
    wake_read: i32 = -1,
    wake_write: i32 = -1,

    pub fn init(alloc: std.mem.Allocator, io: std.Io, cfg: Config) EventLoop {
        return .{ .alloc = alloc, .io = io, .cfg = cfg };
    }

    pub fn deinit(self: *EventLoop) void {
        if (self.pool) |*p| {
            p.stop();
            p.deinit();
            self.pool = null;
        }
        // Free any completions nobody claimed (conn closed while its job
        // was in flight, or jobs that finished during shutdown).
        self.freeCompletions();
        self.completions.deinit(self.alloc);
        for (self.conns.items) |*c| {
            closeFd(c.fd);
            c.deinit(self.alloc);
        }
        self.conns.deinit(self.alloc);
        if (self.wake_read != -1) {
            closeFd(self.wake_read);
            self.wake_read = -1;
        }
        if (self.wake_write != -1) {
            closeFd(self.wake_write);
            self.wake_write = -1;
        }
    }

    /// Move every queued completion back to the caller and reset the queue.
    /// Loop-thread-only (call with no workers running, or accept that new
    /// pushes may land right after — `run`'s teardown drains again after
    /// `pool.stop()` joins every worker, so nothing is lost).
    fn freeCompletions(self: *EventLoop) void {
        // std.atomic.Mutex is a spinlock (tryLock/unlock only).
        while (!self.compl_lock.tryLock()) std.atomic.spinLoopHint();
        defer self.compl_lock.unlock();
        for (self.completions.items) |cm| self.alloc.free(cm.body);
        self.completions.clearRetainingCapacity();
        self.stats.completion_dropped += self.compl_dropped;
        self.compl_dropped = 0;
    }

    pub fn requestShutdown(self: *EventLoop) void {
        self.running = false;
    }

    fn removeAt(self: *EventLoop, idx: usize, reason: enum { idle, err }) void {
        var c = self.conns.orderedRemove(idx);
        closeFd(c.fd);
        c.deinit(self.alloc);
        if (reason == .idle) self.stats.closed_idle += 1 else self.stats.closed_error += 1;
    }

    /// Run until `requestShutdown` (or listener closed). Listener must
    /// already be bound; this takes it non-blocking + `listen(2)`-ed by the
    /// caller (`GinwaServer.listenEventLoop` does that).
    pub fn run(
        self: *EventLoop,
        listener_fd: i32,
        on_request: OnRequestFn,
        on_request_ctx: *anyopaque,
        http_ctx_template: HttpContext,
    ) !void {
        if (comptime nb.is_windows) return error.Unsupported;
        self.listener_fd = listener_fd;
        self.on_request = on_request;
        self.on_request_ctx = on_request_ctx;
        self.http_ctx_template = http_ctx_template;
        try nb.setNonBlocking(listener_fd);

        const use_pool = self.cfg.dispatch_mode == .worker_pool;
        if (use_pool) {
            // Wake channel: loop polls wake_read, workers write one byte
            // per completion. socketpair (not pipe) so both ends are
            // pollable sockets, same primitive as the test helpers.
            var fds: [2]std.c.fd_t = undefined;
            if (posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds) < 0)
                return error.SocketPairFailed;
            self.wake_read = @intCast(fds[0]);
            self.wake_write = @intCast(fds[1]);
            errdefer {
                closeFd(self.wake_read);
                closeFd(self.wake_write);
                self.wake_read = -1;
                self.wake_write = -1;
            }
            try nb.setNonBlocking(self.wake_read);
            try nb.setNonBlocking(self.wake_write);
            // Assign BEFORE start (threading contract above).
            self.pool = try worker_pool_mod.WorkerPool.init(self.alloc, self.io, .{
                .thread_count = self.cfg.worker_threads,
                .queue_depth = self.cfg.worker_queue_depth,
            });
            errdefer {
                self.pool.?.deinit();
                self.pool = null;
            }
            try self.pool.?.start();
        }
        // Teardown: stop pool first (drains queued jobs; every accepted
        // job ran exactly once), then free unclaimed completions, then
        // close the wake channel. Conns close in `deinit`.
        defer if (self.pool) |*p| {
            p.stop();
            p.deinit();
            self.pool = null;
            self.freeCompletions();
            closeFd(self.wake_read);
            closeFd(self.wake_write);
            self.wake_read = -1;
            self.wake_write = -1;
        };

        self.running = true;
        var pollfds_buf: [4096 + 2]posix.pollfd = undefined;

        while (self.running) {
            const n_conns = self.conns.items.len;
            // Slots: listener + wake? + conns.
            const extra: usize = if (use_pool) 2 else 1;
            if (n_conns + extra > pollfds_buf.len) {
                // Defensive: config cap should prevent this; drop scan tick.
                std.Io.sleep(self.io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .real) catch {};
                continue;
            }
            pollfds_buf[0] = nb.pollIn(listener_fd);
            const conn_base: usize = extra;
            if (use_pool) pollfds_buf[1] = nb.pollIn(self.wake_read);
            for (self.conns.items, 0..) |*c, i| {
                pollfds_buf[conn_base + i] = if (c.state == .writing)
                    nb.pollInOut(c.fd)
                else
                    nb.pollIn(c.fd);
            }
            const timeout = self.pollTimeoutMs();
            const ready = try nb.pollOnce(pollfds_buf[0 .. n_conns + extra], timeout);

            if (!self.running) break;
            _ = ready;

            // 1. listener first (accept drain, cap 64/tick)
            if ((pollfds_buf[0].revents & nb.POLL.IN) != 0) self.acceptDrain();
            if (nb.isErrorHungup(pollfds_buf[0].revents)) {
                // Listener died — stop the loop; caller owns shutdown.
                break;
            }

            // 2. worker completions before conn I/O (frees pending flags so
            // freshly-completed conns can dispatch buffered pipelined data).
            if (use_pool and (pollfds_buf[1].revents & nb.POLL.IN) != 0) {
                self.drainCompletions();
                if (!self.running) break;
            }

            // 3. conns (iterate backwards so removal is index-safe)
            var i: usize = n_conns;
            while (i > 0) {
                i -= 1;
                if (i >= self.conns.items.len) continue;
                const re = pollfds_buf[conn_base + i].revents;
                if (re == 0) continue;
                if (nb.isErrorHungup(re) and (re & nb.POLL.IN) == 0 and (re & nb.POLL.OUT) == 0) {
                    self.removeAt(i, .err);
                    continue;
                }
                self.serviceConn(i, re);
                if (!self.running) break;
            }

            // 4. timer sweep (idle + header timeouts)
            self.sweepTimeouts();
        }
    }

    fn pollTimeoutMs(self: *EventLoop) i32 {
        if (self.cfg.idle_timeout_ms <= 0 and self.cfg.header_timeout_ms <= 0) return 250;
        const now = nowMs(self.io);
        var min_wait: i64 = 250;
        for (self.conns.items) |*c| {
            if (self.cfg.idle_timeout_ms > 0) {
                const idle_left = (c.last_active_ms + self.cfg.idle_timeout_ms) - now;
                if (idle_left < min_wait) min_wait = idle_left;
            }
            if (self.cfg.header_timeout_ms > 0 and c.read_buf.items.len > 0 and c.state == .reading) {
                const head_left = (c.req_start_ms + self.cfg.header_timeout_ms) - now;
                if (head_left < min_wait) min_wait = head_left;
            }
        }
        if (min_wait < 0) return 0;
        if (min_wait > 250) return 250;
        return @intCast(min_wait);
    }

    fn acceptDrain(self: *EventLoop) void {
        var accepted: usize = 0;
        while (accepted < 64) : (accepted += 1) {
            const fd = nb.acceptNonBlocking(self.listener_fd) catch |err| {
                if (err == error.WouldBlock) return;
                return; // AcceptFailed — try again next tick
            };
            self.stats.accepted += 1;
            if (self.conns.items.len >= self.cfg.max_conns) {
                self.stats.dropped_backpressure += 1;
                closeFd(fd);
                continue;
            }
            nb.setNonBlocking(fd) catch {
                closeFd(fd);
                continue;
            };
            const now = nowMs(self.io);
            const id = self.next_conn_id;
            self.next_conn_id += 1;
            self.conns.append(self.alloc, .{
                .fd = fd,
                .id = id,
                .req_start_ms = now,
                .last_active_ms = now,
            }) catch {
                closeFd(fd);
                continue;
            };
        }
    }

    fn serviceConn(self: *EventLoop, idx: usize, revents: i16) void {
        if (idx >= self.conns.items.len) return;
        var c = &self.conns.items[idx];

        if ((revents & nb.POLL.IN) != 0 and c.state == .reading) {
            self.readAvailable(idx) orelse return; // closed inside
            if (idx >= self.conns.items.len) return;
            c = &self.conns.items[idx];
        }
        // Flush pending writes whenever writable OR just queued (optimistic).
        if (c.state == .writing and ((revents & nb.POLL.OUT) != 0 or (revents & nb.POLL.IN) != 0)) {
            self.flushWrites(idx) orelse return;
        } else if (c.state == .writing) {
            // Not yet writable — will flush on next POLLOUT.
        }
    }

    /// Read all available bytes into conn buffer; dispatch complete requests.
    /// Returns null when the conn was closed/removed (caller must stop).
    fn readAvailable(self: *EventLoop, idx: usize) ?void {
        var c = &self.conns.items[idx];
        var tmp: [8192]u8 = undefined;
        while (true) {
            const r = nb.recvNonBlocking(c.fd, &tmp) catch {
                self.removeAt(idx, .err);
                return null;
            };
            const n = r orelse break; // would block — drained
            if (n == 0) { // EOF
                self.removeAt(idx, .err);
                return null;
            }
            if (c.req_start_ms == 0) c.req_start_ms = nowMs(self.io);
            c.last_active_ms = nowMs(self.io);
            c.read_buf.appendSlice(self.alloc, tmp[0..n]) catch {
                self.removeAt(idx, .err);
                return null;
            };
            if (c.read_buf.items.len > self.cfg.max_request_bytes) {
                self.sendErrorAndClose(idx, 413, "Content Too Large");
                self.stats.err_413 += 1;
                return null;
            }
        }
        self.dispatchBuffered(idx) orelse return null;
    }

    /// Dispatch complete requests already sitting in the conn's read buffer
    /// (up to 4 per call — starvation bound). Shared by the read path and
    /// the completion path (pipelined data that arrived while offloaded).
    /// Returns null when the conn was closed/removed.
    fn dispatchBuffered(self: *EventLoop, idx: usize) ?void {
        var dispatched: usize = 0;
        while (dispatched < 4) {
            if (idx >= self.conns.items.len) return null;
            var c = &self.conns.items[idx];
            // One in-flight offload at a time: buffer, don't reorder.
            if (c.pending) return;
            const req_len = extractRequestLen(c.read_buf.items, self.cfg.max_request_bytes) catch |err| {
                if (err == error.RequestTooLarge) {
                    self.sendErrorAndClose(idx, 413, "Content Too Large");
                    self.stats.err_413 += 1;
                } else {
                    self.sendErrorAndClose(idx, 400, "Bad Request");
                    self.stats.err_400 += 1;
                }
                return null;
            };
            const len = req_len orelse return; // need more bytes
            if (self.cfg.dispatch_mode == .worker_pool and self.pool != null) {
                self.dispatchOffload(idx, len) orelse return null;
            } else {
                self.dispatchOne(idx, len) orelse return null;
            }
            dispatched += 1;
            if (idx >= self.conns.items.len) return null;
            c = &self.conns.items[idx];
            if (c.pending or c.state != .reading) break;
        }
    }

    /// Drop the first `len` bytes of the conn's read buffer (a request the
    /// caller has taken ownership of — inline serialize or offload copy).
    fn consumeReadBytes(self: *EventLoop, idx: usize, len: usize) void {
        const c = &self.conns.items[idx];
        const remaining = c.read_buf.items.len - len;
        if (remaining > 0) {
            std.mem.copyForwards(u8, c.read_buf.items[0..remaining], c.read_buf.items[len..]);
        }
        c.read_buf.shrinkRetainingCapacity(remaining);
    }

    /// Hand one complete request to the pool. Bytes are consumed from the
    /// read buffer only AFTER a successful submit; on alloc/submit failure
    /// the request stays buffered and runs inline instead (never lost).
    /// Returns null when the conn was closed/removed.
    fn dispatchOffload(self: *EventLoop, idx: usize, len: usize) ?void {
        const use_inline_fallback = struct {
            fn run(loop: *EventLoop, i: usize, l: usize) ?void {
                loop.stats.inline_fallback += 1;
                return loop.dispatchOne(i, l);
            }
        }.run;
        const c = &self.conns.items[idx];
        const job = self.alloc.create(OffloadJob) catch {
            return use_inline_fallback(self, idx, len);
        };
        // No errdefer: every failure branch below frees explicitly, and on
        // success the worker owns the job (exactly-once run guarantee).
        const req_copy = self.alloc.dupe(u8, c.read_buf.items[0..len]) catch {
            self.alloc.destroy(job);
            return use_inline_fallback(self, idx, len);
        };
        job.* = .{
            .loop = self,
            .conn_id = c.id,
            .req_bytes = req_copy,
            .ka_count = c.keep_alive_count,
            .client_fd = c.fd,
        };
        self.pool.?.submit(.{ .run = offloadRun, .ctx = @ptrCast(job) }) catch {
            self.alloc.free(job.req_bytes);
            self.alloc.destroy(job);
            return use_inline_fallback(self, idx, len);
        };
        // Submitted: the worker owns the copy; drop it from our buffer.
        self.consumeReadBytes(idx, len);
        const cc = &self.conns.items[idx];
        cc.pending = true;
        cc.req_start_ms = 0;
        cc.last_active_ms = nowMs(self.io);
        self.stats.offloaded += 1;
    }

    /// Dispatch a single complete request at read_buf[0..len].
    /// Returns null when conn closed (caller stops); else conn stays valid.
    fn dispatchOne(self: *EventLoop, idx: usize, len: usize) ?void {
        var c = &self.conns.items[idx];
        const req_bytes = c.read_buf.items[0..len];

        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        var req = http_parser.parseRequest(req_bytes, arena_alloc, self.io, c.fd) catch {
            self.sendErrorAndClose(idx, 400, "Bad Request");
            self.stats.err_400 += 1;
            return null;
        };

        var http_ctx = self.http_ctx_template;
        http_ctx.allocator = arena_alloc;

        const on_req = self.on_request orelse {
            self.sendErrorAndClose(idx, 500, "No Handler");
            return null;
        };
        var resp = on_req(self.on_request_ctx.?, arena_alloc, &req, http_ctx) catch {
            self.sendErrorAndClose(idx, 500, "Internal Server Error");
            self.stats.err_500 += 1;
            return null;
        };
        // Keep-alive decision mirrors threaded path: response flag AND count.
        const want_keep = resp.keep_alive and
            (c.keep_alive_count + 1 < self.cfg.max_requests_per_conn);
        resp.keep_alive = want_keep;

        const bytes = resp.toBytes() catch {
            self.sendErrorAndClose(idx, 500, "Internal Server Error");
            self.stats.err_500 += 1;
            return null;
        };
        defer arena_alloc.free(bytes);

        // Consume request bytes BEFORE append (realloc may move buffer).
        // Copy response into outbox first, then drain read_buf.
        c.write_buf.clearRetainingCapacity();
        c.write_buf.appendSlice(self.alloc, bytes) catch {
            self.removeAt(idx, .err);
            return null;
        };
        c.write_off = 0;
        // Drain consumed request bytes.
        const remaining = c.read_buf.items.len - len;
        if (remaining > 0) {
            std.mem.copyForwards(u8, c.read_buf.items[0..remaining], c.read_buf.items[len..]);
        }
        c.read_buf.shrinkRetainingCapacity(remaining);
        c.keep_alive_count += 1;
        c.req_start_ms = 0;
        c.last_active_ms = nowMs(self.io);
        c.state = .writing;
        c.keep_alive_next = want_keep;
        self.stats.served += 1;

        // Optimistic flush: small responses usually fit in one send.
        self.flushWrites(idx) orelse return null;
    }

    /// Pool-worker entry point: parse + dispatch + serialize off the loop
    /// thread, then hand the finished bytes back via `pushCompletion`.
    /// Runs EXACTLY once per accepted job (pool guarantee) and frees the
    /// job ctx here — the loop never touches it again after submit.
    ///
    /// Reads (never writes, except the completion queue): `loop.cfg`,
    /// `loop.on_request*`, `loop.http_ctx_template`, `loop.io`,
    /// `loop.alloc` (must be thread-safe — documented on `Config`).
    fn offloadRun(raw: *anyopaque) void {
        const job: *OffloadJob = @ptrCast(@alignCast(raw));
        const loop = job.loop;
        defer loop.alloc.destroy(job);
        defer loop.alloc.free(job.req_bytes);

        var arena = std.heap.ArenaAllocator.init(loop.alloc);
        defer arena.deinit();
        const aa = arena.allocator();

        var req = http_parser.parseRequest(job.req_bytes, aa, loop.io, job.client_fd) catch {
            pushErrorCompletion(loop, job.conn_id, 400, "Bad Request");
            return;
        };
        var hctx = loop.http_ctx_template;
        hctx.allocator = aa;
        const on_req = loop.on_request orelse {
            pushErrorCompletion(loop, job.conn_id, 500, "No Handler");
            return;
        };
        var resp = on_req(loop.on_request_ctx.?, aa, &req, hctx) catch {
            pushErrorCompletion(loop, job.conn_id, 500, "Internal Server Error");
            return;
        };
        const want_keep = resp.keep_alive and
            (job.ka_count + 1 < loop.cfg.max_requests_per_conn);
        resp.keep_alive = want_keep;
        const bytes = resp.toBytes() catch {
            pushErrorCompletion(loop, job.conn_id, 500, "Internal Server Error");
            return;
        };
        defer aa.free(bytes);
        const owned = loop.alloc.dupe(u8, bytes) catch {
            // Serialized fine but the handoff copy failed: send a 500.
            // (The arena copy dies with us; the conn gets a clean close.)
            pushErrorCompletion(loop, job.conn_id, 500, "Internal Server Error");
            return;
        };
        pushCompletion(loop, .{
            .conn_id = job.conn_id,
            .body = owned,
            .keep_alive = want_keep,
        });
    }

    /// Worker → loop handoff. Appends under spinlock, then wakes the loop
    /// with one byte (non-blocking; EAGAIN just means the loop is already
    /// awake — it drains the whole queue per wakeup). On queue-append OOM
    /// the body is freed and the drop counted (conn will idle-timeout).
    fn pushCompletion(loop: *EventLoop, cm: Completion) void {
        while (!loop.compl_lock.tryLock()) std.atomic.spinLoopHint();
        const ok = blk: {
            loop.completions.append(loop.alloc, cm) catch {
                loop.compl_dropped += 1;
                break :blk false;
            };
            break :blk true;
        };
        loop.compl_lock.unlock();
        if (!ok) {
            loop.alloc.free(cm.body);
            return;
        }
        // Best-effort wake: a full socketpair buffer still leaves earlier
        // bytes unread, which is all the loop needs to trigger a drain.
        _ = nb.sendNonBlocking(loop.wake_write, "x") catch 0;
    }

    /// Minimal serialized error response for worker-side failures (no
    /// handler/arena involved — fully owned by the loop allocator).
    fn pushErrorCompletion(loop: *EventLoop, conn_id: u64, code: u16, text: []const u8) void {
        const status_text: []const u8 = switch (code) {
            400 => "Bad Request",
            500 => "Internal Server Error",
            else => "Error",
        };
        const body = std.fmt.allocPrint(loop.alloc, "{d} {s}", .{ code, text }) catch return;
        defer loop.alloc.free(body);
        const raw = std.fmt.allocPrint(
            loop.alloc,
            "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n{s}",
            .{ code, status_text, body.len, body },
        ) catch return;
        pushCompletion(loop, .{ .conn_id = conn_id, .body = raw, .keep_alive = false });
    }

    fn findConn(self: *EventLoop, id: u64) ?usize {
        for (self.conns.items, 0..) |*c, i| {
            if (c.id == id) return i;
        }
        return null;
    }

    /// Loop-thread side of the handoff: drain the wake fd, swap out every
    /// queued completion, and install each onto its conn (or drop it when
    /// the conn is gone / no longer pending). After installing, buffered
    /// pipelined data dispatches immediately via `dispatchBuffered`.
    fn drainCompletions(self: *EventLoop) void {
        // Drain the wake bytes first (level-triggered safety: poll only
        // re-fires on NEW bytes, so leave none unread).
        var tmp: [64]u8 = undefined;
        while (true) {
            const r = nb.recvNonBlocking(self.wake_read, &tmp) catch break;
            const n = r orelse break;
            if (n == 0) break;
        }
        while (!self.compl_lock.tryLock()) std.atomic.spinLoopHint();
        var ready = self.completions;
        self.completions = .empty;
        const dropped = self.compl_dropped;
        self.compl_dropped = 0;
        self.compl_lock.unlock();
        defer ready.deinit(self.alloc);
        self.stats.completion_dropped += dropped;

        for (ready.items) |cm| {
            const idx = self.findConn(cm.conn_id) orelse {
                self.alloc.free(cm.body);
                self.stats.completion_dropped += 1;
                continue;
            };
            var c = &self.conns.items[idx];
            if (!c.pending) {
                // Stale (conn reused the slot? No — ids are unique per
                // accept, so this means the conn already got another
                // completion... impossible with one-in-flight. Defensive.)
                self.alloc.free(cm.body);
                self.stats.completion_dropped += 1;
                continue;
            }
            c.write_buf.clearRetainingCapacity();
            c.write_buf.appendSlice(self.alloc, cm.body) catch {
                self.alloc.free(cm.body);
                self.removeAt(idx, .err);
                continue;
            };
            self.alloc.free(cm.body);
            c.write_off = 0;
            c.keep_alive_next = cm.keep_alive;
            c.keep_alive_count += 1;
            c.req_start_ms = 0;
            c.last_active_ms = nowMs(self.io);
            c.pending = false;
            c.state = .writing;
            self.stats.served += 1;
            self.flushWrites(idx) orelse continue;
            if (idx >= self.conns.items.len) continue;
            // Flush done and reusable: pipelined bytes may already wait.
            self.dispatchBuffered(idx) orelse continue;
        }
    }

    /// Flush conn outbox. Returns null when conn closed.
    fn flushWrites(self: *EventLoop, idx: usize) ?void {
        var c = &self.conns.items[idx];
        while (c.write_off < c.write_buf.items.len) {
            const w = nb.sendNonBlocking(c.fd, c.write_buf.items[c.write_off..]) catch {
                self.removeAt(idx, .err);
                return null;
            };
            if (w == 0) return; // buffer full — wait for POLLOUT
            c.write_off += w;
            c.last_active_ms = nowMs(self.io);
        }
        // Fully written: reuse or close per the dispatch decision.
        const reuse = c.keep_alive_next;
        c.write_buf.clearRetainingCapacity();
        c.write_off = 0;
        c.keep_alive_next = false;
        if (!reuse) {
            self.removeAt(idx, .err);
            return null;
        }
        c.state = .reading;
        c.req_start_ms = if (c.read_buf.items.len > 0) nowMs(self.io) else 0;
    }

    fn sendErrorAndClose(self: *EventLoop, idx: usize, code: u16, text: []const u8) void {
        if (idx >= self.conns.items.len) return;
        const c = &self.conns.items[idx];
        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const body = std.fmt.allocPrint(arena.allocator(), "{d} {s}", .{ code, text }) catch {
            self.removeAt(idx, .err);
            return;
        };
        const status_text: []const u8 = switch (code) {
            400 => "Bad Request",
            413 => "Content Too Large",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            else => "Error",
        };
        var resp = HttpResponse.init(code, status_text, arena.allocator()).withBody(body);
        resp.keep_alive = false;
        const bytes = resp.toBytes() catch {
            self.removeAt(idx, .err);
            return;
        };
        defer arena.allocator().free(bytes);
        // Best-effort blocking-ish send (error path only): loop non-blocking
        // sends until done or EAGAIN, then close regardless.
        var off: usize = 0;
        var rounds: usize = 0;
        while (off < bytes.len and rounds < 32) : (rounds += 1) {
            const w = nb.sendNonBlocking(c.fd, bytes[off..]) catch break;
            if (w == 0) break;
            off += w;
        }
        self.removeAt(idx, .err);
    }

    fn sweepTimeouts(self: *EventLoop) void {
        if (self.cfg.idle_timeout_ms <= 0 and self.cfg.header_timeout_ms <= 0) return;
        const now = nowMs(self.io);
        var i: usize = self.conns.items.len;
        while (i > 0) {
            i -= 1;
            const c = &self.conns.items[i];
            if (self.cfg.idle_timeout_ms > 0 and
                now - c.last_active_ms > self.cfg.idle_timeout_ms)
            {
                self.removeAt(i, .idle);
                continue;
            }
            if (self.cfg.header_timeout_ms > 0 and
                c.state == .reading and c.read_buf.items.len > 0 and
                c.req_start_ms != 0 and now - c.req_start_ms > self.cfg.header_timeout_ms)
            {
                self.removeAt(i, .idle);
            }
        }
    }
};

test {
    _ = @import("event_loop_test.zig");
}
