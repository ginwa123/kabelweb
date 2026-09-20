//! Single-threaded poll reactor for plain HTTP/1.1 (Phase 2-3).
//!
//! Non-breaking companion to `http_server.zig:listen` (thread-per-connection).
//! `GinwaServer.listenEventLoop` runs this instead of the accept+
//! `group.concurrent` loop. Scope of v1:
//!
//!   - Cross-platform: `poll(2)` on POSIX, `WSAPoll` on Windows
//!     (see `nb_socket.zig`). Plain HTTP/1.1 only. SSE / WebSocket / H2 /
//!     TLS routes get a `501 Not Implemented` (same status the threaded
//!     path already uses for SSE+WS-over-TLS) so long-lived upgrades
//!     never silently hang.
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

const nb = @import("nb_socket.zig");
const http_parser = @import("http_parser.zig");
const worker_pool_mod = @import("worker_pool.zig");
const connection_reader = @import("connection_reader.zig");
const h2_constants = @import("http2/constants.zig");

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
    /// This loop's index (`listenEventLoop` sets it per loop in multi
    /// mode) and the total loop count. Read-only inside the loop.
    loop_id: usize = 0,
    /// Loop shape for `GinwaServer.listenEventLoop`: `0`/`1` = single
    /// loop on the calling thread, `>1` = that many `SO_REUSEPORT` loops
    /// (POSIX-only, clamped to `max_multi_loops`).
    loop_count: usize = 1,
    /// Transport routing, filled by `listenEventLoop` from server state
    /// (callers normally leave these alone):
    /// - `tls_enabled`: every accepted conn hijacks to a TLS worker at
    ///   accept time (handshake + serve); the loop never reads it.
    /// - `h2c_enabled`: fresh conns are sniffed for the H2 preface before
    ///   H1 framing; H2 conns hijack to the H2 driver thread.
    tls_enabled: bool = false,
    h2c_enabled: bool = false,
    /// Where dispatch runs (see `DispatchMode`).
    dispatch_mode: DispatchMode = .direct,
    /// Pool threads in `worker_pool` mode. 0 = one per CPU (min 2).
    worker_threads: usize = 0,
    /// Max queued (undispatched) offload jobs. Past this, dispatch falls
    /// back to inline so the loop keeps serving (counted, not dropped).
    worker_queue_depth: usize = 1024,
};

/// Dispatch callback supplied by `http_server.zig`. Receives the raw framed
/// request bytes (borrowed — valid for the call only) plus the parsed
/// request; returns either a response to serialize or a hijack (fd handoff
/// to a worker thread — see `Hijack`). Returning an error makes the reactor
/// send `500` + close.
pub const OnRequestFn = *const fn (
    ctx: *anyopaque,
    alloc: std.mem.Allocator,
    req_bytes: []const u8,
    req: *const HttpRequest,
    http_ctx: HttpContext,
) anyerror!DispatchResult;

/// One hijacked connection: the loop forgets the fd (no close, no further
/// I/O) and a worker thread owns it from here. `run` restores blocking
/// mode, serves with the existing blocking managers, closes the fd, and
/// returns. `data` is the complete framed bytes the loop already read
/// (an H1 request, or the H2 preface+frames); ownership rules are per
/// call site — the spawner documents who frees.
pub const HijackRunFn = *const fn (
    ctx: *anyopaque,
    alloc: std.mem.Allocator,
    io: std.Io,
    fd: i32,
    data: []const u8,
) void;

pub const Hijack = struct {
    ctx: *anyopaque,
    run: HijackRunFn,
};

/// What dispatch decided for one complete request.
pub const DispatchResult = union(enum) {
    /// Serialize + write through the loop (fast H1 path).
    respond: HttpResponse,
    /// Static-dir fallback: short-lived blocking file serve.
    hijack_static: Hijack,
    /// SSE stream: long-lived, dedicated thread per conn.
    hijack_sse: Hijack,
    /// WebSocket session: long-lived, dedicated thread per conn.
    hijack_ws: Hijack,
};

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
    /// H2C sniff done: the conn is confirmed HTTP/1.1. Fresh conns with
    /// `h2c_enabled` are sniffed for the H2 preface before framing.
    h1_confirmed: bool = false,
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
    /// Conns handed off to worker threads (static/SSE/WS/H2/TLS).
    /// The loop forgets the fd (no close); the worker serves + closes.
    hijacked: u64 = 0,
    /// Static jobs dropped (static pool full at handoff).
    static_dropped: u64 = 0,

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
            .hijacked = self.hijacked + other.hijacked,
            .static_dropped = self.static_dropped + other.static_dropped,
        };
    }
};

/// A finished offload job, owned by the loop thread from push to consume.
/// Either a serialized response (`body != null`, `hijacked == false`) or
/// a hijack handoff (`hijacked == true`, `body == null` — the worker owns
/// the fd now; the loop just forgets the conn without closing).
pub const Completion = struct {
    conn_id: u64,
    body: ?[]u8 = null,
    keep_alive: bool = false,
    hijacked: bool = false,
};

/// Heap args for one hijacked connection's worker thread (loop allocator;
/// freed by the thread itself — see `serveThreadMain`). Covers static
/// pool jobs, SSE/WS/H2 dedicated threads, and TLS accept threads
/// (`req_bytes` is null for TLS: nothing was read before the handshake).
const ServeArgs = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    run: HijackRunFn,
    ctx: *anyopaque,
    fd: i32,
    req_bytes: ?[]u8,
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
    nb.closeSocket(fd);
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
    /// Small pool for static-dir hijacks (short-lived blocking file
    /// serves). Lazy: created on first hijack, loop-thread-only in
    /// `.direct` mode; in `worker_pool` mode offload workers also submit
    /// here, guarded by `static_lock`.
    static_pool: ?worker_pool_mod.WorkerPool = null,
    static_lock: std.atomic.Mutex = .unlocked,
    /// Hijacked-conn worker threads (SSE/WS/H2/TLS dedicated threads).
    /// Joined in `deinit` so server teardown never outruns a worker that
    /// still touches managers (broadcast/removeClient after free). Same
    /// join-on-shutdown contract the old threaded path had via its
    /// worker group. Appended under `hijack_lock` (loop + offload threads
    /// both spawn); if the append itself fails, the thread is detached
    /// instead (untracked fallback, counted nowhere — spawn already won).
    hijack_threads: std.ArrayList(std.Thread) = .empty,
    /// Fds handed off to hijacked-conn workers (same set as the threads
    /// above, plus static-pool jobs). Recorded by `forgetConn` under
    /// `hijack_lock`. `deinit` runs `nb.shutdownSocket` over this list
    /// BEFORE joining: a hijacked worker parks in a blocking read() that
    /// only returns when its peer goes away, so without the active
    /// shutdown an idle keep-alive/WS/H2 client would deadlock teardown
    /// (join waits on the worker, the worker waits on the peer). The loop
    /// never closes these fds — the worker owns and closes them.
    hijacked_fds: std.ArrayList(i32) = .empty,
    hijack_lock: std.atomic.Mutex = .unlocked,
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
        // Unblock every hijacked-conn worker BEFORE the joins below. Those
        // workers park in a blocking read() that only returns once the
        // PEER goes away, so an idle keep-alive / WS / H2 client would
        // deadlock teardown (join waits on the worker, worker waits on the
        // peer). `shutdownSocket` is the same trick `shutdown()` uses to
        // wake a blocked accept(); it does NOT close — the worker still
        // owns the fd and closes it on its way out. Covers the static pool
        // too, whose `stop()` joins its in-flight jobs below.
        for (self.hijacked_fds.items) |fd| nb.shutdownSocket(fd);
        self.hijacked_fds.deinit(self.alloc);
        if (self.pool) |*p| {
            p.stop();
            p.deinit();
            self.pool = null;
        }
        if (self.static_pool) |*p| {
            p.stop();
            p.deinit();
            self.static_pool = null;
        }
        // Join hijacked-conn workers BEFORE freeing anything they might
        // touch (managers live past the loop in server.destroy). Safe from
        // the deadlock above because their fds were just shut down.
        for (self.hijack_threads.items) |t| t.join();
        self.hijack_threads.deinit(self.alloc);
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
        for (self.completions.items) |cm| {
            if (cm.body) |b| self.alloc.free(b);
        }
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

    /// Forget a hijacked conn WITHOUT closing: a worker thread owns the fd
    /// from here (serves + closes). Loop-thread-only (like `removeAt`).
    /// The fd is recorded first (under `hijack_lock`) so `deinit` can
    /// actively shut it down before joining that worker — see the
    /// `hijacked_fds` field contract.
    fn forgetConn(self: *EventLoop, idx: usize) void {
        var c = self.conns.orderedRemove(idx);
        while (!self.hijack_lock.tryLock()) std.atomic.spinLoopHint();
        self.hijacked_fds.append(self.alloc, c.fd) catch {};
        self.hijack_lock.unlock();
        c.deinit(self.alloc);
        self.stats.hijacked += 1;
    }

    /// Free a hijack data copy (loop allocator) on a failed handoff.
    fn freeHijackData(self: *EventLoop, data: ?[]u8) void {
        if (data) |b| self.alloc.free(b);
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
        self.listener_fd = listener_fd;
        self.on_request = on_request;
        self.on_request_ctx = on_request_ctx;
        self.http_ctx_template = http_ctx_template;
        try nb.setNonBlocking(listener_fd);

        const use_pool = self.cfg.dispatch_mode == .worker_pool;
        if (use_pool) {
            // Wake channel: loop polls wake_read, workers write one byte
            // per completion. `nb.socketPair` is socketpair(2) on POSIX,
            // TCP loopback on Windows (Winsock has no socketpair).
            const pair = try nb.socketPair();
            self.wake_read = pair.read;
            self.wake_write = pair.write;
            errdefer {
                closeFd(self.wake_read);
                closeFd(self.wake_write);
                self.wake_read = -1;
                self.wake_write = -1;
            }
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
        // Teardown: stop pools first (drains queued jobs; every accepted
        // job ran exactly once), then free unclaimed completions, then
        // close the wake channel. Conns close in `deinit`. Static pool
        // stops after the dispatch pool so in-flight offloads that submit
        // static jobs are already joined. (Separate defers: the static
        // pool exists in `.direct` mode too, where `self.pool` is null.)
        defer if (self.static_pool) |*sp| {
            sp.stop();
            sp.deinit();
            self.static_pool = null;
        };
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
        var pollfds_buf: [4096 + 2]nb.PollFd = undefined;

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
            if ((pollfds_buf[0].revents & nb.POLL.IN) != 0) {
                const before = self.conns.items.len;
                self.acceptDrain();
                // TLS mode: the loop never reads encrypted bytes — every
                // fresh conn hijacks to a TLS worker at accept time.
                if (self.cfg.tls_enabled) self.hijackNewConns(before);
            }
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
            // Same TCP tuning the old threaded accept path applied
            // (keepalive + NODELAY); best-effort.
            nb.applyTcpTuning(fd);
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
            // H2C sniff runs BEFORE H1 framing: the 24-byte preface
            // contains the CRLFCRLF the H1 reader stops at, so parsing H1
            // first would eat the preface. Mirrors the threaded path's
            // ConnectionReader sniff (same classifier).
            if (self.cfg.h2c_enabled and !c.h1_confirmed) {
                switch (connection_reader.sniff(c.read_buf.items)) {
                    .h2 => return self.hijackH2(idx),
                    .maybe_h2 => return, // proper prefix, need more bytes
                    .h1 => c.h1_confirmed = true,
                }
                if (idx >= self.conns.items.len) return null;
                c = &self.conns.items[idx];
            }
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

    /// Hand buffered H2 preface+frames to a dedicated H2 driver thread.
    /// Loop-thread-only (sniff runs pre-dispatch, so no offload involved).
    /// Returns null always (conn is gone either way).
    fn hijackH2(self: *EventLoop, idx: usize) ?void {
        const c = &self.conns.items[idx];
        const data = self.alloc.dupe(u8, c.read_buf.items) catch {
            return self.sendErrorAndClose(idx, 500, "Internal Server Error");
        };
        // H2 runner ctx is the server (same pointer dispatch gets).
        const h = Hijack{ .ctx = self.on_request_ctx.?, .run = h2HijackRun };
        if (!self.spawnServeThread(h, c.fd, data)) {
            self.alloc.free(data);
            return self.removeAt(idx, .err);
        }
        self.forgetConn(idx);
        return null;
    }

    /// Placeholder H2 runner — replaced by http_server's real runner via
    /// `setH2HijackRun` when `h2c_enabled` can trigger. (The loop must not
    /// import the H2 driver: cycle.)
    var h2_hijack_run: ?HijackRunFn = null;

    /// Called by `listenEventLoop` when H2C sniffing is enabled.
    pub fn setH2HijackRun(hook: HijackRunFn) void {
        h2_hijack_run = hook;
    }

    fn h2HijackRun(ctx: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: i32, data: []const u8) void {
        if (h2_hijack_run) |hook| {
            hook(ctx, alloc, io, fd, data);
        } else {
            nb.closeSocket(fd);
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

    /// Dedicated-thread entry point for one hijacked conn (SSE/WS/H2/TLS).
    /// Runs `run` (blocking serve + close), then frees the data copy and
    /// the args. Runners must NOT free `req_bytes` themselves.
    fn serveThreadMain(raw: *anyopaque) void {
        const args: *ServeArgs = @ptrCast(@alignCast(raw));
        args.run(args.ctx, args.alloc, args.io, args.fd, args.req_bytes orelse &[_]u8{});
        if (args.req_bytes) |b| args.alloc.free(b);
        args.alloc.destroy(args);
    }

    /// Spawn a tracked worker thread for a hijacked conn. Returns true
    /// when spawned (caller must forget the conn WITHOUT closing — the
    /// thread owns the fd now). Returns false on spawn failure (caller
    /// keeps ownership: free the data copy, close via `removeAt`).
    /// Spawned threads are tracked for joining in `deinit` (see the
    /// `hijack_threads` field contract); if tracking fails the thread is
    /// detached instead so nothing leaks the handle.
    fn spawnServeThread(self: *EventLoop, h: Hijack, fd: i32, req_bytes: ?[]u8) bool {
        const args = self.alloc.create(ServeArgs) catch return false;
        args.* = .{
            .alloc = self.alloc,
            .io = self.io,
            .run = h.run,
            .ctx = h.ctx,
            .fd = fd,
            .req_bytes = req_bytes,
        };
        const t = std.Thread.spawn(.{}, serveThreadMain, .{args}) catch {
            self.alloc.destroy(args);
            return false;
        };
        while (!self.hijack_lock.tryLock()) std.atomic.spinLoopHint();
        self.hijack_threads.append(self.alloc, t) catch {
            self.hijack_lock.unlock();
            t.detach();
            return true;
        };
        self.hijack_lock.unlock();
        return true;
    }

    /// Static pool, created on first hijack. `hijackToStaticPool` runs on
    /// the loop thread; offload workers take `static_lock` around
    /// get-or-create + submit (see `offloadRun`).
    fn getStaticPool(self: *EventLoop) !*worker_pool_mod.WorkerPool {
        if (self.static_pool == null) {
            self.static_pool = try worker_pool_mod.WorkerPool.init(self.alloc, self.io, .{
                .thread_count = 4,
                .queue_depth = 64,
            });
            errdefer {
                self.static_pool.?.deinit();
                self.static_pool = null;
            }
            try self.static_pool.?.start();
        }
        return &self.static_pool.?;
    }

    /// Static pool entry point (pool-job wrapper around the hijack runner).
    /// Frees the data copy + job here — runners must NOT free `data`.
    fn staticPoolRun(raw: *anyopaque) void {
        const args: *ServeArgs = @ptrCast(@alignCast(raw));
        args.run(args.ctx, args.alloc, args.io, args.fd, args.req_bytes orelse &[_]u8{});
        if (args.req_bytes) |b| args.alloc.free(b);
        args.alloc.destroy(args);
    }

    /// Hand a static-dir request to the static pool (short-lived blocking
    /// file serve). Loop-thread-only. The pool owns fd + data after a
    /// successful submit (conn forgotten, no close); every failure path
    /// frees explicitly and closes via `sendErrorAndClose`/`removeAt`
    /// (these return null, not errors, so no errdefer — it would never fire).
    /// Returns null when conn is gone.
    fn hijackToStaticPool(self: *EventLoop, idx: usize, len: usize, h: Hijack) ?void {
        const c = &self.conns.items[idx];
        const data = self.alloc.dupe(u8, c.read_buf.items[0..len]) catch {
            return self.sendErrorAndClose(idx, 500, "Internal Server Error");
        };
        const args = self.alloc.create(ServeArgs) catch {
            self.alloc.free(data);
            return self.sendErrorAndClose(idx, 500, "Internal Server Error");
        };
        args.* = .{
            .alloc = self.alloc,
            .io = self.io,
            .run = h.run,
            .ctx = h.ctx,
            .fd = c.fd,
            .req_bytes = data,
        };
        const pool = self.getStaticPool() catch {
            self.alloc.destroy(args);
            self.alloc.free(data);
            return self.sendErrorAndClose(idx, 500, "Internal Server Error");
        };
        pool.submit(.{ .run = staticPoolRun, .ctx = @ptrCast(args) }) catch {
            self.alloc.destroy(args);
            self.alloc.free(data);
            self.stats.static_dropped += 1;
            return self.sendErrorAndClose(idx, 503, "Service Unavailable");
        };
        // Submitted: the pool owns fd + data; forget without closing.
        // (No consume needed — the whole conn leaves with the worker.)
        self.forgetConn(idx);
    }

    /// Hand an H1 request to a dedicated thread (SSE/WS: long-lived).
    /// Dupes read_buf[0..len]; on spawn failure closes via `removeAt`.
    /// Returns null when conn is gone.
    fn hijackToThread(self: *EventLoop, idx: usize, len: usize, h: Hijack) ?void {
        const c = &self.conns.items[idx];
        const data = self.alloc.dupe(u8, c.read_buf.items[0..len]) catch {
            return self.sendErrorAndClose(idx, 500, "Internal Server Error");
        };
        if (!self.spawnServeThread(h, c.fd, data)) {
            self.alloc.free(data);
            return self.removeAt(idx, .err);
        }
        self.forgetConn(idx);
    }

    /// Hijack freshly-accepted conns to TLS workers (TLS mode: the loop
    /// never reads encrypted bytes). Indices [from..len) are the new ones;
    /// iterate backwards so `forgetConn`/`removeAt` stay index-safe.
    fn hijackNewConns(self: *EventLoop, from: usize) void {
        var i: usize = self.conns.items.len;
        while (i > from) {
            i -= 1;
            const c = &self.conns.items[i];
            // TLS runner ctx is the server (same pointer dispatch gets).
            const h = Hijack{ .ctx = self.on_request_ctx.?, .run = tlsHijackRun };
            if (!self.spawnServeThread(h, c.fd, null)) {
                self.removeAt(i, .err);
                continue;
            }
            self.forgetConn(i);
        }
    }

    /// Placeholder runner for TLS hijacks — replaced by http_server's
    /// real runner via `setTlsHijackRun` before `run()` in TLS mode.
    /// (The loop must not import the TLS module: cycle.)
    var tls_hijack_run: ?HijackRunFn = null;

    /// Called by `listenEventLoop` when `tls_ctx` is set.
    pub fn setTlsHijackRun(hook: HijackRunFn) void {
        tls_hijack_run = hook;
    }

    fn tlsHijackRun(ctx: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: i32, data: []const u8) void {
        _ = data;
        if (tls_hijack_run) |hook| {
            hook(ctx, alloc, io, fd, &[_]u8{});
        } else {
            nb.closeSocket(fd);
        }
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
        const result = on_req(self.on_request_ctx.?, arena_alloc, req_bytes, &req, http_ctx) catch {
            self.sendErrorAndClose(idx, 500, "Internal Server Error");
            self.stats.err_500 += 1;
            return null;
        };
        switch (result) {
            .respond => |r| {
                var rr = r;
                // Keep-alive decision mirrors threaded path: response flag AND count.
                const want_keep = rr.keep_alive and
                    (c.keep_alive_count + 1 < self.cfg.max_requests_per_conn);
                rr.keep_alive = want_keep;

                const bytes = rr.toBytes() catch {
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
            },
            .hijack_static => |h| return self.hijackToStaticPool(idx, len, h),
            .hijack_sse, .hijack_ws => |h| return self.hijackToThread(idx, len, h),
        }
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
        // Ownership-transferable: hijack arms null these out when the
        // request bytes move to a static job / serve thread.
        var job_opt: ?*OffloadJob = job;
        defer if (job_opt) |j| loop.alloc.destroy(j);
        var req_opt: ?[]u8 = job.req_bytes;
        defer if (req_opt) |b| loop.alloc.free(b);

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
        const result = on_req(loop.on_request_ctx.?, aa, job.req_bytes, &req, hctx) catch {
            pushErrorCompletion(loop, job.conn_id, 500, "Internal Server Error");
            return;
        };
        switch (result) {
            .respond => |r| {
                var rr = r;
                const want_keep = rr.keep_alive and
                    (job.ka_count + 1 < loop.cfg.max_requests_per_conn);
                rr.keep_alive = want_keep;
                const bytes = rr.toBytes() catch {
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
            },
            .hijack_static => |h| {
                // Short-lived: transfer the request copy to a static-pool
                // job (pool shared with the loop thread — take the lock
                // for get-or-create + submit). Then push a forget
                // completion so the loop drops the conn WITHOUT closing
                // (the static job owns the fd now).
                //
                // Race note: if the loop already closed this conn (idle
                // timeout), the completion drops as stale but the static
                // job still runs against a possibly-reused fd number. The
                // window needs a >idle-timeout stall between submit and
                // run (default 60s vs ms in practice); the runner treats
                // any write error as drop. Same class as the threaded
                // path's shutdown races.
                const conn_id = job.conn_id;
                const args = loop.alloc.create(ServeArgs) catch {
                    pushErrorCompletion(loop, conn_id, 500, "Internal Server Error");
                    return;
                };
                args.* = .{
                    .alloc = loop.alloc,
                    .io = loop.io,
                    .run = h.run,
                    .ctx = h.ctx,
                    .fd = job.client_fd,
                    .req_bytes = req_opt,
                };
                while (!loop.static_lock.tryLock()) std.atomic.spinLoopHint();
                const pool = loop.getStaticPool() catch {
                    loop.static_lock.unlock();
                    loop.alloc.destroy(args);
                    pushErrorCompletion(loop, conn_id, 500, "Internal Server Error");
                    return;
                };
                pool.submit(.{ .run = staticPoolRun, .ctx = @ptrCast(args) }) catch {
                    loop.static_lock.unlock();
                    loop.alloc.destroy(args);
                    pushErrorCompletion(loop, conn_id, 503, "Service Unavailable");
                    return;
                };
                loop.static_lock.unlock();
                // Transferred: static job owns args + req bytes; destroy
                // the offload job explicitly (job_opt nulled to skip it).
                req_opt = null;
                job_opt = null;
                loop.alloc.destroy(job);
                pushCompletion(loop, .{ .conn_id = conn_id, .hijacked = true });
            },
            .hijack_sse, .hijack_ws => |h| {
                // Long-lived: dedicated thread takes fd + request copy
                // (tracked for joining in deinit via spawnServeThread).
                const conn_id = job.conn_id;
                const fd = job.client_fd;
                const data = req_opt;
                req_opt = null;
                loop.alloc.destroy(job);
                job_opt = null;
                if (!loop.spawnServeThread(h, fd, data)) {
                    if (data) |b| loop.alloc.free(b);
                    pushErrorCompletion(loop, conn_id, 500, "Internal Server Error");
                    return;
                }
                pushCompletion(loop, .{ .conn_id = conn_id, .hijacked = true });
            },
        }
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
            if (cm.body) |b| loop.alloc.free(b);
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
                if (cm.body) |b| self.alloc.free(b);
                self.stats.completion_dropped += 1;
                continue;
            };
            var c = &self.conns.items[idx];
            if (!c.pending) {
                // Stale (conn reused the slot? No — ids are unique per
                // accept, so this means the conn already got another
                // completion... impossible with one-in-flight. Defensive.)
                if (cm.body) |b| self.alloc.free(b);
                self.stats.completion_dropped += 1;
                continue;
            }
            if (cm.hijacked) {
                // Worker owns the fd now (static/SSE/WS handoff): forget
                // WITHOUT closing. (Stale-guard above already handled a
                // conn that timed out first.)
                self.forgetConn(idx);
                continue;
            }
            const body = cm.body orelse {
                self.removeAt(idx, .err);
                continue;
            };
            c.write_buf.clearRetainingCapacity();
            c.write_buf.appendSlice(self.alloc, body) catch {
                self.alloc.free(body);
                self.removeAt(idx, .err);
                continue;
            };
            self.alloc.free(body);
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
