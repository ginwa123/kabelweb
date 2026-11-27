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

// .direct runs on the loop thread; .worker_pool requires a thread-safe allocator.
pub const DispatchMode = enum {
    direct,
    worker_pool,
};

pub const Config = struct {
    max_conns: usize = 1024,
    idle_timeout_ms: i64 = 60_000,
    header_timeout_ms: i64 = 5_000,
    max_request_bytes: usize = 8 * 1024 * 1024,
    max_requests_per_conn: u32 = 1000,
    loop_id: usize = 0,
    loop_count: usize = 1,
    tls_enabled: bool = false,
    h2c_enabled: bool = false,
    dispatch_mode: DispatchMode = .worker_pool,
    worker_threads: usize = 0,
    worker_queue_depth: usize = 1024,
};

pub const OnRequestFn = *const fn (
    ctx: *anyopaque,
    alloc: std.mem.Allocator,
    req_bytes: []const u8,
    req: *const HttpRequest,
    http_ctx: HttpContext,
) anyerror!DispatchResult;

// Hijack runners borrow data; the spawner frees it after run returns.
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

pub const DispatchResult = union(enum) {
    respond: HttpResponse,
    hijack_static: Hijack,
    hijack_sse: Hijack,
    hijack_ws: Hijack,
};

pub const ConnState = enum {
    reading,
    writing,
    closing,
};

pub const Conn = struct {
    fd: i32,
    id: u64 = 0,
    state: ConnState = .reading,
    read_buf: std.ArrayList(u8) = .empty,
    write_buf: std.ArrayList(u8) = .empty,
    write_off: usize = 0,
    req_start_ms: i64 = 0,
    last_active_ms: i64 = 0,
    keep_alive_count: u32 = 0,
    keep_alive_next: bool = false,
    pending: bool = false,
    h1_confirmed: bool = false,
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
    offloaded: u64 = 0,
    inline_fallback: u64 = 0,
    completion_dropped: u64 = 0,
    hijacked: u64 = 0,
    static_dropped: u64 = 0,

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

pub const Completion = struct {
    conn_id: u64,
    body: ?[]u8 = null,
    keep_alive: bool = false,
    hijacked: bool = false,
};

const ServeArgs = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    run: HijackRunFn,
    ctx: *anyopaque,
    fd: i32,
    req_bytes: ?[]u8,
};

const OffloadJob = struct {
    loop: *EventLoop,
    conn_id: u64,
    req_bytes: []u8,
    ka_count: u32,
    client_fd: i32,
};

const request_storage_bytes = 2 * 1024;

// Each slab owns a standard fixed-buffer allocator with arena spill.
const RequestSlab = struct {
    fallback: std.heap.ArenaAllocator,
    fixed: std.heap.StackFallbackAllocator(request_storage_bytes),
    request_allocator: std.mem.Allocator,
    in_use: bool = false,

    fn init(self: *RequestSlab, alloc: std.mem.Allocator) void {
        self.fallback = std.heap.ArenaAllocator.init(alloc);
        self.fixed = std.heap.stackFallback(request_storage_bytes, self.fallback.allocator());
        self.request_allocator = self.fixed.get();
        self.in_use = false;
    }

    fn reset(self: *RequestSlab) void {
        self.fixed.fixed_buffer_allocator.reset();
        _ = self.fallback.reset(.retain_capacity);
    }

    fn deinit(self: *RequestSlab) void {
        self.fallback.deinit();
    }
};

// Fixed slabs are reused; exhaustion falls back to a request arena.
const RequestStoragePool = struct {
    alloc: std.mem.Allocator,
    slabs: []RequestSlab,
    lock: std.atomic.Mutex = .unlocked,

    fn init(alloc: std.mem.Allocator, count: usize) !RequestStoragePool {
        const slabs = try alloc.alloc(RequestSlab, @max(1, count));
        for (slabs) |*slab| slab.init(alloc);
        return .{ .alloc = alloc, .slabs = slabs };
    }

    fn acquire(self: *RequestStoragePool) ?*RequestSlab {
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        defer self.lock.unlock();
        for (self.slabs) |*slab| {
            if (slab.in_use) continue;
            slab.in_use = true;
            slab.reset();
            return slab;
        }
        return null;
    }

    fn release(self: *RequestStoragePool, slab: *RequestSlab) void {
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        defer self.lock.unlock();
        std.debug.assert(slab.in_use);
        slab.in_use = false;
    }

    fn deinit(self: *RequestStoragePool) void {
        for (self.slabs) |*slab| {
            std.debug.assert(!slab.in_use);
            slab.deinit();
        }
        self.alloc.free(self.slabs);
        self.slabs = &.{};
    }
};

// Uses a pooled slab when available, otherwise a private request arena.
const RequestStorage = struct {
    pool: ?*RequestStoragePool,
    fallback: std.heap.ArenaAllocator,
    slab: ?*RequestSlab = null,

    fn init(pool: ?*RequestStoragePool, alloc: std.mem.Allocator) RequestStorage {
        return .{
            .pool = pool,
            .fallback = std.heap.ArenaAllocator.init(alloc),
            .slab = if (pool) |p| p.acquire() else null,
        };
    }

    fn allocator(self: *RequestStorage) std.mem.Allocator {
        if (self.slab) |slab| return slab.request_allocator;
        return self.fallback.allocator();
    }

    fn deinit(self: *RequestStorage) void {
        if (self.slab) |slab| self.pool.?.release(slab);
        self.fallback.deinit();
    }
};

pub fn findHeaderEnd(buf: []const u8) ?usize {
    const idx = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    return idx + 4;
}

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
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}

fn closeFd(fd: i32) void {
    nb.closeSocket(fd);
}

// Workers share request_pool/completions; alloc must be thread-safe; other state is loop-thread-only.
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
    pool: ?worker_pool_mod.WorkerPool = null,
    request_pool: ?RequestStoragePool = null,
    static_pool: ?worker_pool_mod.WorkerPool = null,
    static_lock: std.atomic.Mutex = .unlocked,
    hijack_threads: std.ArrayList(std.Thread) = .empty,
    hijacked_fds: std.ArrayList(i32) = .empty,
    hijack_lock: std.atomic.Mutex = .unlocked,
    completions: std.ArrayList(Completion) = .empty,
    compl_lock: std.atomic.Mutex = .unlocked,
    compl_dropped: u64 = 0,
    wake_read: i32 = -1,
    wake_write: i32 = -1,

    pub fn init(alloc: std.mem.Allocator, io: std.Io, cfg: Config) EventLoop {
        return .{ .alloc = alloc, .io = io, .cfg = cfg };
    }

    fn requestStorage(self: *EventLoop) RequestStorage {
        return RequestStorage.init(if (self.request_pool) |*pool| pool else null, self.alloc);
    }

    // Shutdown hijacked fds BEFORE joining: a parked read() deadlocks teardown; the worker owns and closes its fd.
    pub fn deinit(self: *EventLoop) void {
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
        if (self.request_pool) |*p| {
            p.deinit();
            self.request_pool = null;
        }
        for (self.hijack_threads.items) |t| t.join();
        self.hijack_threads.deinit(self.alloc);
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

    fn freeCompletions(self: *EventLoop) void {
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

    // Transfer fd ownership to the hijack worker without closing it here.
    fn forgetConn(self: *EventLoop, idx: usize) void {
        var c = self.conns.orderedRemove(idx);
        while (!self.hijack_lock.tryLock()) std.atomic.spinLoopHint();
        self.hijacked_fds.append(self.alloc, c.fd) catch {};
        self.hijack_lock.unlock();
        c.deinit(self.alloc);
        self.stats.hijacked += 1;
    }

    fn freeHijackData(self: *EventLoop, data: ?[]u8) void {
        if (data) |b| self.alloc.free(b);
    }

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
        const worker_count = if (self.cfg.worker_threads == 0)
            @max(2, std.Thread.getCpuCount() catch 4)
        else
            self.cfg.worker_threads;
        const request_slabs = if (use_pool) worker_count + 1 else 1;
        self.request_pool = try RequestStoragePool.init(self.alloc, request_slabs);
        defer if (self.request_pool) |*p| {
            p.deinit();
            self.request_pool = null;
        };
        if (use_pool) {
            const pair = try nb.socketPair();
            self.wake_read = pair.read;
            self.wake_write = pair.write;
            errdefer {
                if (self.wake_read != -1) {
                    closeFd(self.wake_read);
                    closeFd(self.wake_write);
                    self.wake_read = -1;
                    self.wake_write = -1;
                }
            }
            self.pool = try worker_pool_mod.WorkerPool.init(self.alloc, self.io, .{
                .thread_count = self.cfg.worker_threads,
                .queue_depth = self.cfg.worker_queue_depth,
            });
            errdefer {
                if (self.pool) |*p| {
                    p.deinit();
                    self.pool = null;
                }
            }
            try self.pool.?.start();
        }
        // Stop and join workers before releasing request slabs.
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
        var poll_ids_buf: [4096]u64 = undefined;

        while (self.running) {
            const n_conns = self.conns.items.len;
            const extra: usize = if (use_pool) 2 else 1;
            if (n_conns + extra > pollfds_buf.len) {
                std.Io.sleep(self.io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .real) catch {};
                continue;
            }
            pollfds_buf[0] = nb.pollIn(listener_fd);
            const conn_base: usize = extra;
            if (use_pool) pollfds_buf[1] = nb.pollIn(self.wake_read);
            var n_polled: usize = 0;
            for (self.conns.items) |*c| {
                if (c.pending) continue;
                poll_ids_buf[n_polled] = c.id;
                pollfds_buf[conn_base + n_polled] = if (c.state == .writing)
                    nb.pollInOut(c.fd)
                else
                    nb.pollIn(c.fd);
                n_polled += 1;
            }
            const timeout = self.pollTimeoutMs();
            const ready = try nb.pollOnce(pollfds_buf[0 .. n_polled + extra], timeout);

            if (!self.running) break;
            _ = ready;

            if ((pollfds_buf[0].revents & nb.POLL.IN) != 0) {
                const before = self.conns.items.len;
                self.acceptDrain();
                if (self.cfg.tls_enabled) self.hijackNewConns(before);
            }
            if (nb.isErrorHungup(pollfds_buf[0].revents)) {
                break;
            }

            if (use_pool and (pollfds_buf[1].revents & nb.POLL.IN) != 0) {
                self.drainCompletions();
                if (!self.running) break;
            }

            var i: usize = n_polled;
            while (i > 0) {
                i -= 1;
                const re = pollfds_buf[conn_base + i].revents;
                if (re == 0) continue;
                const idx = self.findConn(poll_ids_buf[i]) orelse continue;
                if (nb.isErrorHungup(re) and (re & nb.POLL.IN) == 0 and (re & nb.POLL.OUT) == 0) {
                    if (self.conns.items[idx].pending) continue;
                    self.removeAt(idx, .err);
                    continue;
                }
                self.serviceConn(idx, re);
                if (!self.running) break;
            }

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

        if (c.pending) return;

        if ((revents & nb.POLL.IN) != 0 and c.state == .reading) {
            self.readAvailable(idx) orelse return; // closed inside
            if (idx >= self.conns.items.len) return;
            c = &self.conns.items[idx];
        }
        if (c.state == .writing and ((revents & nb.POLL.OUT) != 0 or (revents & nb.POLL.IN) != 0)) {
            self.flushWrites(idx) orelse return;
        } else if (c.state == .writing) {}
    }

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

    fn dispatchBuffered(self: *EventLoop, idx: usize) ?void {
        var dispatched: usize = 0;
        while (dispatched < 4) {
            if (idx >= self.conns.items.len) return null;
            var c = &self.conns.items[idx];
            if (c.pending) return;
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

    fn hijackH2(self: *EventLoop, idx: usize) ?void {
        const c = &self.conns.items[idx];
        const data = self.alloc.dupe(u8, c.read_buf.items) catch {
            return self.sendErrorAndClose(idx, 500, "Internal Server Error");
        };
        const h = Hijack{ .ctx = self.on_request_ctx.?, .run = h2HijackRun };
        if (!self.spawnServeThread(h, c.fd, data)) {
            self.alloc.free(data);
            return self.removeAt(idx, .err);
        }
        self.forgetConn(idx);
        return null;
    }

    var h2_hijack_run: ?HijackRunFn = null;

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

    fn consumeReadBytes(self: *EventLoop, idx: usize, len: usize) void {
        const c = &self.conns.items[idx];
        const remaining = c.read_buf.items.len - len;
        if (remaining > 0) {
            std.mem.copyForwards(u8, c.read_buf.items[0..remaining], c.read_buf.items[len..]);
        }
        c.read_buf.shrinkRetainingCapacity(remaining);
    }

    fn serveThreadMain(raw: *anyopaque) void {
        const args: *ServeArgs = @ptrCast(@alignCast(raw));
        args.run(args.ctx, args.alloc, args.io, args.fd, args.req_bytes orelse &[_]u8{});
        if (args.req_bytes) |b| args.alloc.free(b);
        args.alloc.destroy(args);
    }

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

    fn staticPoolRun(raw: *anyopaque) void {
        const args: *ServeArgs = @ptrCast(@alignCast(raw));
        args.run(args.ctx, args.alloc, args.io, args.fd, args.req_bytes orelse &[_]u8{});
        if (args.req_bytes) |b| args.alloc.free(b);
        args.alloc.destroy(args);
    }

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
        self.forgetConn(idx);
    }

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

    fn hijackNewConns(self: *EventLoop, from: usize) void {
        var i: usize = self.conns.items.len;
        while (i > from) {
            i -= 1;
            const c = &self.conns.items[i];
            const h = Hijack{ .ctx = self.on_request_ctx.?, .run = tlsHijackRun };
            if (!self.spawnServeThread(h, c.fd, null)) {
                self.removeAt(i, .err);
                continue;
            }
            self.forgetConn(i);
        }
    }

    var tls_hijack_run: ?HijackRunFn = null;

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
        self.consumeReadBytes(idx, len);
        const cc = &self.conns.items[idx];
        cc.pending = true;
        cc.req_start_ms = 0;
        cc.last_active_ms = nowMs(self.io);
        self.stats.offloaded += 1;
    }

    fn dispatchOne(self: *EventLoop, idx: usize, len: usize) ?void {
        var c = &self.conns.items[idx];
        const req_bytes = c.read_buf.items[0..len];

        var storage = self.requestStorage();
        defer storage.deinit();
        const arena_alloc = storage.allocator();

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
                const want_keep = rr.keep_alive and
                    (c.keep_alive_count + 1 < self.cfg.max_requests_per_conn);
                rr.keep_alive = want_keep;

                const bytes = rr.toBytes() catch {
                    self.sendErrorAndClose(idx, 500, "Internal Server Error");
                    self.stats.err_500 += 1;
                    return null;
                };
                defer arena_alloc.free(bytes);

                c.write_buf.clearRetainingCapacity();
                c.write_buf.appendSlice(self.alloc, bytes) catch {
                    self.removeAt(idx, .err);
                    return null;
                };
                c.write_off = 0;
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

                self.flushWrites(idx) orelse return null;
            },
            .hijack_static => |h| return self.hijackToStaticPool(idx, len, h),
            .hijack_sse, .hijack_ws => |h| return self.hijackToThread(idx, len, h),
        }
    }

    fn offloadRun(raw: *anyopaque) void {
        const job: *OffloadJob = @ptrCast(@alignCast(raw));
        const loop = job.loop;
        var job_opt: ?*OffloadJob = job;
        defer if (job_opt) |j| loop.alloc.destroy(j);
        var req_opt: ?[]u8 = job.req_bytes;
        defer if (req_opt) |b| loop.alloc.free(b);

        var storage = loop.requestStorage();
        defer storage.deinit();
        const aa = storage.allocator();

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
                req_opt = null;
                job_opt = null;
                loop.alloc.destroy(job);
                pushCompletion(loop, .{ .conn_id = conn_id, .hijacked = true });
            },
            .hijack_sse, .hijack_ws => |h| {
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
        _ = nb.sendNonBlocking(loop.wake_write, "x") catch 0;
    }

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

    fn drainCompletions(self: *EventLoop) void {
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
                if (cm.body) |b| self.alloc.free(b);
                self.stats.completion_dropped += 1;
                continue;
            }
            if (cm.hijacked) {
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
            self.dispatchBuffered(idx) orelse continue;
        }
    }

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

const event_loop_tests = struct {
    const event_loop = @import("event_loop.zig");
    const test_tcp = @import("test_tcp.zig");

    const CountingAllocator = struct {
        backing: std.mem.Allocator,
        allocations: usize = 0,

        fn allocator(self: *CountingAllocator) std.mem.Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, return_address: usize) ?[*]u8 {
            const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
            self.allocations += 1;
            return self.backing.rawAlloc(len, alignment, return_address);
        }

        fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) bool {
            const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
            return self.backing.rawResize(memory, alignment, new_len, return_address);
        }

        fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) ?[*]u8 {
            const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
            return self.backing.rawRemap(memory, alignment, new_len, return_address);
        }

        fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, return_address: usize) void {
            const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
            self.backing.rawFree(memory, alignment, return_address);
        }
    };

    test "framing: incomplete head needs more bytes" {
        const r = try event_loop.extractRequestLen("GET / HTTP/1.1\r\nHost: x", 1024);
        try std.testing.expect(r == null);
    }

    test "framing: GET without body is complete at header end" {
        const raw = "GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        const r = try event_loop.extractRequestLen(raw, 1024);
        try std.testing.expect(r != null);
        try std.testing.expectEqual(raw.len, r.?);
    }

    test "framing: POST waits for Content-Length body" {
        const head = "POST /users HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n";
        const partial = try event_loop.extractRequestLen(head ++ "hello", 1024);
        try std.testing.expect(partial == null);
        const full = try event_loop.extractRequestLen(head ++ "hello world", 1024);
        try std.testing.expect(full != null);
        try std.testing.expectEqual(head.len + 11, full.?);
    }

    test "framing: oversize request errors" {
        const raw = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
        const r = event_loop.extractRequestLen(raw, 10);
        try std.testing.expectError(error.RequestTooLarge, r);
    }

    test "framing: garbage Content-Length is BadRequest" {
        const raw = "POST /x HTTP/1.1\r\nContent-Length: banana\r\n\r\n";
        const r = event_loop.extractRequestLen(raw, 1024);
        try std.testing.expectError(error.BadRequest, r);
    }

    test "framing: pipelined second request detected after drain" {
        const first = "GET /a HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";
        const second = "GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        var buf: [512]u8 = undefined;
        @memcpy(buf[0..first.len], first);
        @memcpy(buf[first.len .. first.len + second.len], second);
        const total = first.len + second.len;
        const len1 = try event_loop.extractRequestLen(buf[0..total], 4096);
        try std.testing.expect(len1 != null);
        try std.testing.expectEqual(first.len, len1.?);
        const len2 = try event_loop.extractRequestLen(buf[len1.?..total], 4096);
        try std.testing.expect(len2 != null);
        try std.testing.expectEqual(second.len, len2.?);
    }

    test "request storage: repeated small requests do not allocate from the fallback" {
        var counting = CountingAllocator{ .backing = std.testing.allocator };
        var pool = try RequestStoragePool.init(counting.allocator(), 1);
        defer pool.deinit();
        counting.allocations = 0;

        const raw = "GET /hello?name=bench HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
        for (0..100) |_| {
            var storage = RequestStorage.init(&pool, counting.allocator());
            defer storage.deinit();
            const alloc = storage.allocator();
            var req = try http_parser.parseRequest(raw, alloc, undefined, -1);
            try std.testing.expectEqualStrings("bench", req.query.get("name").?);
            var res = http_parser.HttpResponse.init(200, "OK", alloc).withBody("OK").withSecurityHeaders();
            const bytes = try res.toBytes();
            try std.testing.expect(std.mem.endsWith(u8, bytes, "\r\n\r\nOK"));
        }

        try std.testing.expectEqual(@as(usize, 0), counting.allocations);
    }

    test "request storage: oversized allocations spill without truncation" {
        var counting = CountingAllocator{ .backing = std.testing.allocator };
        var pool = try RequestStoragePool.init(counting.allocator(), 1);
        defer pool.deinit();
        counting.allocations = 0;

        var storage = RequestStorage.init(&pool, counting.allocator());
        defer storage.deinit();
        const bytes = try storage.allocator().alloc(u8, request_storage_bytes + 1);
        @memset(bytes, 0x5a);
        try std.testing.expectEqual(@as(usize, request_storage_bytes + 1), bytes.len);
        try std.testing.expectEqual(@as(u8, 0x5a), bytes[request_storage_bytes]);
        try std.testing.expect(counting.allocations > 0);
    }

    test "request storage: an exhausted pool falls back without losing data" {
        var pool = try RequestStoragePool.init(std.testing.allocator, 1);
        defer pool.deinit();
        var first = RequestStorage.init(&pool, std.testing.allocator);
        defer first.deinit();
        var second = RequestStorage.init(&pool, std.testing.allocator);
        defer second.deinit();

        try std.testing.expect(first.slab != null);
        try std.testing.expect(second.slab == null);
        const first_bytes = try first.allocator().alloc(u8, 8);
        const second_bytes = try second.allocator().alloc(u8, 8);
        @memset(first_bytes, 0x11);
        @memset(second_bytes, 0x22);
        try std.testing.expectEqual(@as(u8, 0x11), first_bytes[7]);
        try std.testing.expectEqual(@as(u8, 0x22), second_bytes[7]);
    }

    fn stubDispatch(
        _: *anyopaque,
        alloc: std.mem.Allocator,
        req_bytes: []const u8,
        req: *const event_loop.HttpRequest,
        http_ctx: event_loop.HttpContext,
    ) anyerror!event_loop.DispatchResult {
        _ = req_bytes;
        _ = http_ctx;
        var res = event_loop.HttpResponse.init(200, "OK", alloc).withBody("loop-ok");
        var want_close = false;
        var it = req.headers.iterator();
        while (it.next()) |e| {
            if (std.ascii.eqlIgnoreCase(e.key_ptr.*, "connection") and
                std.ascii.indexOfIgnoreCase(e.value_ptr.*, "close") != null)
            {
                want_close = true;
                break;
            }
        }
        res.keep_alive = !want_close and !std.mem.eql(u8, req.version, "HTTP/1.0");
        return .{ .respond = res };
    }

    fn readHttpResponse(fd: i32, buf: []u8) ![]u8 {
        var len: usize = 0;
        while (true) {
            const head_end = event_loop.findHeaderEnd(buf[0..len]);
            if (head_end) |he| {
                const cl = try event_loop.parseContentLength(buf[0..he]);
                if (len >= he + cl) return buf[0 .. he + cl];
            }
            if (len >= buf.len) return error.TooMuch;
            const n = try test_tcp.read(fd, buf[len..]);
            if (n == 0) return error.Closed;
            len += n;
        }
    }

    fn tcpConnect(port: u16) !i32 {
        return test_tcp.connect(port);
    }

    fn writeAll(fd: i32, data: []const u8) !void {
        return test_tcp.writeAll(fd, data);
    }

    test "event loop serves GET over loopback" {
        const alloc = std.testing.allocator;

        const listener = try test_tcp.listenEphemeral();
        const lfd = listener.fd;
        const port = listener.port;
        defer test_tcp.close(lfd);

        var loop = EventLoop.init(alloc, std.testing.io, .{
            .max_conns = 16,
            .idle_timeout_ms = 5_000,
            .header_timeout_ms = 2_000,
        });
        defer loop.deinit();

        var ctx_dummy: u8 = 0;
        const http_ctx: event_loop.HttpContext = .{ .allocator = alloc, .io = std.testing.io };
        const t = try std.Thread.spawn(.{}, struct {
            fn run(l: *EventLoop, fd: i32, ctxp: *u8, hctx: event_loop.HttpContext) void {
                l.run(fd, stubDispatch, @ptrCast(ctxp), hctx) catch {};
            }
        }.run, .{ &loop, lfd, &ctx_dummy, http_ctx });
        defer {
            loop.requestShutdown();
            if (tcpConnect(port)) |w| {
                test_tcp.close(w);
            } else |_| {}
            t.join();
        }

        std.Io.sleep(std.testing.io, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .real) catch {};

        const cfd = try tcpConnect(port);
        defer test_tcp.close(cfd);

        const req1 = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n";
        try writeAll(cfd, req1);
        var resp_buf: [4096]u8 = undefined;
        const resp1 = try readHttpResponse(cfd, &resp_buf);
        try std.testing.expect(std.mem.indexOf(u8, resp1, "200 OK") != null);
        try std.testing.expect(std.mem.indexOf(u8, resp1, "loop-ok") != null);

        const req2 = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        try writeAll(cfd, req2);
        var resp_buf2: [4096]u8 = undefined;
        const resp2 = try readHttpResponse(cfd, &resp_buf2);
        try std.testing.expect(std.mem.indexOf(u8, resp2, "200 OK") != null);

        try std.testing.expect(loop.stats.served >= 2);
    }

    const HamCtx = struct {
        hijacks: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        responded: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        bare_close: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        bare_close_hijack: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    };

    fn hamHijack(ctx: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: i32, data: []const u8) void {
        _ = alloc;
        _ = io;
        _ = data;
        const c: *HamCtx = @ptrCast(@alignCast(ctx));
        _ = c.hijacks.fetchAdd(1, .monotonic);
        nb.setBlocking(fd) catch {
            test_tcp.close(fd);
            return;
        };
        const body = "ham-hijack-ok";
        var buf: [160]u8 = undefined;
        const resp = std.fmt.bufPrint(
            &buf,
            "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
            .{ body.len, body },
        ) catch {
            test_tcp.close(fd);
            return;
        };
        test_tcp.writeAll(fd, resp) catch {};
        test_tcp.close(fd);
    }

    fn hamDispatch(
        ctx: *anyopaque,
        alloc: std.mem.Allocator,
        req_bytes: []const u8,
        req: *const event_loop.HttpRequest,
        http_ctx: event_loop.HttpContext,
    ) anyerror!event_loop.DispatchResult {
        _ = req_bytes;
        _ = http_ctx;
        const c: *HamCtx = @ptrCast(@alignCast(ctx));
        if (std.mem.eql(u8, req.path, "/hijack")) {
            return .{ .hijack_static = .{ .ctx = ctx, .run = hamHijack } };
        }
        _ = c.responded.fetchAdd(1, .monotonic);
        var res = event_loop.HttpResponse.init(200, "OK", alloc).withBody("ham-respond-ok");
        res.keep_alive = false;
        return .{ .respond = res };
    }

    fn hamNowMs() i64 {
        const ns = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds;
        return @intCast(@divTrunc(ns, std.time.ns_per_ms));
    }

    const HamArgs = struct {
        port: u16,
        ctx: *HamCtx,
        deadline_ms: i64,
    };

    fn hamOnce(port: u16, want_hijack: bool, ctx: *HamCtx) void {
        const fd = tcpConnect(port) catch return; // refused != the bug
        _ = ctx.requests.fetchAdd(1, .monotonic);
        defer test_tcp.close(fd);
        var req_buf: [160]u8 = undefined;
        const req = std.fmt.bufPrint(
            &req_buf,
            "GET {s} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            .{if (want_hijack) "/hijack" else "/keep"},
        ) catch return;
        writeAll(fd, req) catch return;
        var buf: [1024]u8 = undefined;
        var len: usize = 0;
        var quiet: usize = 0;
        while (len < buf.len) {
            var pfd = [_]nb.PollFd{nb.pollIn(fd)};
            const ready = nb.pollOnce(&pfd, 250) catch break;
            if (ready == 0) {
                quiet += 1;
                if (quiet >= 8) break; // ~2 s of silence: give up + unblock
                continue;
            }
            quiet = 0;
            const n = test_tcp.read(fd, buf[len..]) catch break;
            if (n == 0) break;
            len += n;
        }
        if (len == 0 or std.mem.indexOf(u8, buf[0..len], "200 OK") == null) {
            _ = ctx.bare_close.fetchAdd(1, .monotonic);
            if (want_hijack) _ = ctx.bare_close_hijack.fetchAdd(1, .monotonic);
        }
    }

    fn hamClient(a: HamArgs) void {
        var flip = false;
        while (hamNowMs() < a.deadline_ms) {
            hamOnce(a.port, flip, a.ctx);
            flip = !flip;
        }
    }

    test "event loop: a hijacked conn's closed fd never kills another connection" {
        if (builtin.os.tag == .windows) return error.SkipZigTest;

        const alloc = std.testing.allocator;
        const listener = try test_tcp.listenEphemeral();
        const lfd = listener.fd;
        const port = listener.port;
        defer test_tcp.close(lfd);

        var ctx = HamCtx{};
        var loop = EventLoop.init(alloc, std.testing.io, .{
            .max_conns = 512,
            .idle_timeout_ms = 5_000,
            .header_timeout_ms = 3_000,
        });
        defer loop.deinit();

        const http_ctx: event_loop.HttpContext = .{ .allocator = alloc, .io = std.testing.io };
        const t = try std.Thread.spawn(.{}, struct {
            fn run(l: *EventLoop, fd: i32, ctxp: *HamCtx, hctx: event_loop.HttpContext) void {
                l.run(fd, hamDispatch, @ptrCast(ctxp), hctx) catch {};
            }
        }.run, .{ &loop, lfd, &ctx, http_ctx });
        defer {
            loop.requestShutdown();
            if (tcpConnect(port)) |w| {
                test_tcp.close(w);
            } else |_| {}
            t.join();
        }

        std.Io.sleep(std.testing.io, .{ .nanoseconds = 50 * std.time.ns_per_ms }, .real) catch {};

        const deadline = hamNowMs() + 1_500;
        var threads: [5]std.Thread = undefined;
        for (&threads) |*th| {
            th.* = try std.Thread.spawn(.{}, hamClient, .{HamArgs{
                .port = port,
                .ctx = &ctx,
                .deadline_ms = deadline,
            }});
        }
        for (&threads) |*th| th.join();

        try std.testing.expect(ctx.hijacks.load(.monotonic) > 0);
        try std.testing.expect(ctx.responded.load(.monotonic) > 0);
        try std.testing.expect(ctx.requests.load(.monotonic) > 0);

        const bare = ctx.bare_close.load(.monotonic);
        const total = ctx.requests.load(.monotonic);
        const budget: u64 = if (comptime builtin.os.tag == .windows)
            @max(total / 20, 8)
        else
            0;
        if (bare > budget) {
            std.log.info(
                "static serve closed {d} of {d} connections with ZERO bytes " ++
                    "({d} of them on the hijack arm) — that is " ++
                    "net::ERR_EMPTY_RESPONSE in a browser, and one lost asset " ++
                    "stops a production bundle from mounting\n",
                .{ bare, total, ctx.bare_close_hijack.load(.monotonic) },
            );
        }
        try std.testing.expect(bare <= budget);
    }
};

comptime {
    _ = event_loop_tests;
}

comptime {
    _ = event_loop_tests;
}
