const std = @import("std");
const posix = std.posix;
const socket = posix.system;
const c = std.c;

const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;
const is_bsd = switch (builtin.os.tag) {
    .freebsd, .openbsd, .netbsd, .dragonfly => true,
    else => false,
};

/// Windows-only Winsock 2 externs. `send()` and `setsockopt()` are the
/// functions we actually call from sse_manager.zig on Windows (see
/// `sendAll` / `setFdSendTimeout`), but the surrounding struct mirrors
/// the convention in `http_server.zig` so future Windows-specific call
/// sites can extend it (recv, etc.) without re-declaring the DLL
/// imports. `kernel32.dll` and `ws2_32.dll` import libraries are
/// shipped with Zig's MinGW toolchain, so this just-works without a
/// manual `linkSystemLibrary` call. The struct is empty on non-Windows
/// so non-Windows builds don't link ws2_32.
const winsock = if (is_windows) struct {
    extern "ws2_32" fn send(
        sockfd: c_int,
        buf: [*]const u8,
        len: c_int,
        flags: c_int,
    ) callconv(.c) c_int;
    extern "ws2_32" fn closesocket(sockfd: c_int) callconv(.c) c_int;
    extern "ws2_32" fn setsockopt(
        sockfd: c_int,
        level: c_int,
        optname: c_int,
        optval: ?*const anyopaque,
        optlen: c_int,
    ) callconv(.c) c_int;
} else struct {};

const LOOP_COUNT = 4;

/// Scoped logger for all SSE-manager diagnostics. Output goes to stderr.
/// Prefixed with `[sse]` so the stream of disconnects is greppable in
/// the nalar log without needing to filter every log line.
const log = std.log.scoped(.sse);

/// Why a client was removed. Required parameter on every remove path so
/// we can correlate the disconnects the frontend sees with the actual
/// reason nalar dropped the connection. Add new variants here whenever
/// you add a new removal path — the diagnostic goal is for the log
/// line to be self-explanatory without reading the source.
pub const RemoveReason = enum {
    /// POLL.HUP — peer closed its side of the socket (TCP FIN or RST).
    poll_hup,
    /// POLL.ERR — kernel marked the socket as errored.
    poll_err,
    /// POLL.NVAL — fd was already closed (race or leak indicator).
    poll_nval,
    /// `read()` returned 0 (EOF) on a still-poll-able socket — peer sent
    /// FIN and we caught the EOF before HUP fired.
    eof_read,
    /// `sendHeartbeat` → `writeChunkedFrame` failed — peer is gone
    /// from the server's perspective (EPIPE / ECONNRESET / EBADF).
    heartbeat_write_failed,
    /// `sendToClient` → `writeChunkedFrame` failed mid-event.
    send_to_client_failed,
    /// `broadcast` / `broadcastTyped` → `writeChunkedFrame` failed.
    broadcast_write_failed,
    /// `sweepStaleClients` removed the client because last_heartbeat
    /// exceeded 3 heartbeat cycles (15 s by default).
    sweep_stale,
    /// `gracefulShutdown` / `deinit` — explicit, server-side intent.
    explicit_shutdown,
    /// Test code path that bypassed normal removal logic.
    test_only,
};

pub const Self = @This();

pub const SseClient = struct {
    io: std.Io,
    id: [16]u8,
    fd: i32,
    arena: std.heap.ArenaAllocator,
    alive: bool,
    last_heartbeat: u64,
    message_queue: std.ArrayListUnmanaged([]const u8),
    lock: std.Io.Mutex = .init,

    pub fn init(id: [16]u8, fd: i32, parent_allocator: std.mem.Allocator, io: std.Io) SseClient {
        return .{
            .id = id,
            .fd = fd,
            .arena = std.heap.ArenaAllocator.init(parent_allocator),
            .alive = true,
            .last_heartbeat = timestamp(io),
            .message_queue = .empty,
            .lock = .init,
            .io = io,
        };
    }

    pub fn allocator(self: *SseClient) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn deinit(self: *SseClient) void {
        self.message_queue.deinit(self.allocator());
        self.arena.deinit();
        if (is_windows) {
            _ = winsock.closesocket(self.fd);
        } else _ = socket.close(self.fd);
    }

    pub fn forceDestroy(self: *SseClient) void {
        if (is_windows) {
            _ = winsock.closesocket(self.fd);
        } else _ = socket.close(self.fd);
    }

    pub fn markDisconnected(self: *SseClient) void {
        // Zig 0.16 std.Io.Mutex requires the `io` argument for
        // lock/unlock. The previous zero-arg call form compiled
        // under Zig 0.15 but is a compile error in 0.16 (member
        // function expected 1 argument(s), found 0). This function
        // is currently dead code (no callers in the codebase), but
        // fixing it now prevents the next person who wires it up
        // from hitting the same error.
        self.lock.lock(self.io) catch return;
        defer self.lock.unlock(self.io);
        self.alive = false;
    }

    pub fn sendEvent(self: *SseClient, event: []const u8) !void {
        // The lock covers all three writes of the chunked frame so a
        // concurrent sendHeartbeat / sendToClient on the same fd cannot
        // interleave its hex length between our hex length and data.
        self.lock.lock(self.io) catch return error.ClientDisconnected;
        defer self.lock.unlock(self.io);
        if (!self.alive) return error.ClientDisconnected;
        writeChunkedFrame(self.fd, event) catch {
            self.alive = false;
            return error.ClientDisconnected;
        };
    }
};

pub const SseManager = struct {
    io: std.Io,
    clients: std.AutoHashMapUnmanaged([16]u8, *SseClient),
    fd_to_id: std.AutoHashMapUnmanaged(i32, [16]u8),
    lock: std.Io.Mutex = .init,
    allocator: std.mem.Allocator,
    server_allocator: std.mem.Allocator,
    running: bool,
    on_disconnect: ?*const fn (client_id: [16]u8) void = null,
    notify_pipe: [2]i32,
    /// Set once `drainPipeNonBlocking` has flipped the notify pipe's
    /// read end to O_NONBLOCK. Idempotent (double fcntl SETFL is
    /// harmless) so no extra lock is needed.
    pipe_nonblock_set: bool = false,

    pub fn init(allocator: std.mem.Allocator, server_allocator: std.mem.Allocator, io: std.Io) !SseManager {
        var notify_pipe: [2]i32 = .{ -1, -1 };
        if (!is_windows) {
            const rc = socket.pipe(&notify_pipe);
            if (rc < 0) return error.PipeFailed;
        }
        return .{
            .clients = .empty,
            .fd_to_id = .empty,
            .lock = .init,
            .allocator = allocator,
            .server_allocator = server_allocator,
            .running = true,
            .io = io,
            .notify_pipe = notify_pipe,
        };
    }

    pub fn deinit(self: *SseManager) void {
        self.running = false;
        if (!is_windows and self.notify_pipe[1] >= 0) {
            var byte_buf: [1]u8 = .{'q'};
            _ = socket.write(self.notify_pipe[1], &byte_buf, 1);
        }
        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);

        var it = self.clients.iterator();
        while (it.next()) |entry| {
            // Use the full `deinit()` (not `forceDestroy()`) so each
            // client's per-client arena (which holds every message string
            // ever sent through `sendToClient` and any other allocations
            // made via `client.allocator()`) is freed. `forceDestroy`
            // closes the fd but leaks the arena — for a long-lived
            // server that has served many distinct connections, that
            // leak accumulates to the point of `ProcessFdQuotaExceeded`
            // (the prior commit `5df11a9a` documented a 1011-FD leak;
            // the leaked ARENA memory is the same shape of bug, just
            // measured in bytes instead of FDs).
            entry.value_ptr.*.deinit();
            self.server_allocator.destroy(entry.value_ptr);
        }
        self.clients.clearRetainingCapacity();
        self.fd_to_id.clearRetainingCapacity();

        if (!is_windows) {
            if (self.notify_pipe[0] >= 0) _ = socket.close(self.notify_pipe[0]);
            if (self.notify_pipe[1] >= 0) _ = socket.close(self.notify_pipe[1]);
        }
    }

    pub fn registerClient(self: *SseManager, fd: i32) ![16]u8 {
        _ = try self.lock.lock(self.io);
        defer self.lock.unlock(self.io);

        if (self.getClientIdByFdLocked(fd)) |id| return id;

        var id: [16]u8 = undefined;
        while (true) {
            self.io.random(&id);
            if (!self.clients.contains(id)) break;
        }

        const client = try self.server_allocator.create(SseClient);
        client.* = SseClient.init(id, fd, self.allocator, self.io);

        // Bound every subsequent write on this socket. Without this, a
        // peer that stops reading parks whichever thread emits the next
        // SSE event — while holding `self.lock` — which stalls every
        // SSE emit in the process (see `SSE_SEND_TIMEOUT_MS` for the
        // full agent-abort chain). Best-effort: failures are ignored.
        setFdSendTimeout(fd, SSE_SEND_TIMEOUT_MS);

        try self.clients.put(self.server_allocator, id, client);
        try self.fd_to_id.put(self.server_allocator, fd, id);

        log.info("register fd={d} id={x} total_clients={d}", .{ fd, id, self.clients.count() });

        // Wake up all event loops so they pick up the new client
        self.notifyLoops();

        return id;
    }

    /// Test-only helper that registers `fd` with a caller-provided id,
    /// bypassing `self.io.random` (which requires being called on the
    /// Io runtime's own thread and therefore crashes when called from
    /// a unit test's main thread). NOT for production use — production
    /// code should call `registerClient` so the id is cryptographically
    /// random and collisions are detected.
    pub fn registerClientForTest(self: *SseManager, fd: i32, id: [16]u8) ![16]u8 {
        // Skip the std.Io.Mutex here: the Io runtime's `lock` requires
        // being called from the Io thread, and we're in a unit test's
        // main thread. Tests must not call this concurrently with
        // other SseManager methods.
        if (self.fd_to_id.get(fd)) |existing| return existing;
        if (self.clients.contains(id)) return error.TestIdAlreadyUsed;

        const client = try self.server_allocator.create(SseClient);
        client.* = SseClient.init(id, fd, self.allocator, self.io);

        try self.clients.put(self.server_allocator, id, client);
        try self.fd_to_id.put(self.server_allocator, fd, id);

        return id;
    }

    pub fn removeClient(self: *SseManager, id: [16]u8, reason: RemoveReason) void {
        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);

        if (self.clients.fetchRemove(id)) |entry| {
            _ = self.fd_to_id.remove(entry.value.*.fd);
            const fd = entry.value.*.fd;
            log.info("remove fd={d} id={x} reason={s} remaining={d}", .{
                fd, id, @tagName(reason), self.clients.count(),
            });
            // Send the chunked-encoding terminator (0\r\n\r\n) BEFORE
            // closing the fd so intermediaries (Vite, browser) can
            // finalize their chunked-decoding state cleanly. The
            // write will fail silently if the peer is already gone
            // (which is the common POLL.HUP case), and that's fine.
            _ = sendAll(entry.value.*.fd, "0\r\n\r\n");
            entry.value.*.deinit();
            self.server_allocator.destroy(entry.value);
            if (self.on_disconnect) |cb| cb(id);
        }
    }

    pub fn removeClientByFd(self: *SseManager, fd: i32, reason: RemoveReason) ?[16]u8 {
        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);

        if (self.fd_to_id.fetchRemove(fd)) |entry| {
            const id = entry.value;
            if (self.clients.fetchRemove(id)) |client_entry| {
                log.info("remove fd={d} id={x} reason={s} remaining={d}", .{
                    fd, id, @tagName(reason), self.clients.count(),
                });
                // Same as removeClient: send terminator BEFORE close.
                _ = sendAll(client_entry.value.*.fd, "0\r\n\r\n");
                client_entry.value.*.deinit();
                self.server_allocator.destroy(client_entry.value);
            }
            if (self.on_disconnect) |cb| cb(id);
            return id;
        }
        return null;
    }

    fn getClientIdByFdLocked(self: *SseManager, fd: i32) ?[16]u8 {
        return self.fd_to_id.get(fd);
    }

    pub fn getClientIdByFd(self: *SseManager, fd: i32) ?[16]u8 {
        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);
        return self.getClientIdByFdLocked(fd);
    }

    fn notifyLoops(self: *SseManager) void {
        if (!is_windows and self.notify_pipe[1] >= 0) {
            var byte_buf: [1]u8 = .{'x'};
            _ = socket.write(self.notify_pipe[1], &byte_buf, 1);
        }
    }

    /// Drain the notify pipe WITHOUT blocking, consuming AT MOST ONE
    /// wakeup byte per call.
    ///
    /// Why this exists (the "3 of 4 heartbeat shards die" bug)
    /// ─────────────────────────────────────────────────────────
    /// `notifyLoops` writes ONE byte per wakeup, but ALL LOOP_COUNT
    /// event loops poll the SAME read end. The old code did a blocking
    /// `read(pipe, buf, 64)` that drained EVERY byte in the pipe —
    /// including the wakeups meant for the other loops. A loop that
    /// then finds the pipe empty at poll time blocks FOREVER in its
    /// own raw `read()` (poll only re-reports readability when NEW
    /// bytes arrive, which never come). Stranded loops stop
    /// heartbeating their shard → browser sees silence → EventSource
    /// reconnects forever.
    ///
    /// The fix is two-fold:
    ///   1. Set O_NONBLOCK on the read end ONCE so a read on an empty
    ///      pipe returns -EAGAIN instead of blocking forever.
    ///   2. Read ONE byte per call. Each wakeup byte wakes exactly one
    ///      loop; leftover bytes stay in the pipe for the other loops,
    ///      which poll reports as readable on their next iteration.
    ///
    /// EAGAIN (pipe empty — another loop already consumed our wakeup)
    /// is success-with-zero-bytes. Every other failure is swallowed:
    /// a dead notify pipe must never take down the event loop.
    fn drainPipeNonBlocking(self: *SseManager) void {
        if (is_windows) return;
        const read_fd = self.notify_pipe[0];
        if (read_fd < 0) return;

        // One-time O_NONBLOCK setup. Failures are non-fatal — worst case
        // this process keeps the old blocking behaviour.
        if (!self.pipe_nonblock_set) {
            setFdNonBlocking(read_fd);
            self.pipe_nonblock_set = true;
        }

        // Consume at most ONE wakeup byte. EAGAIN lands here as rc < 0
        // and is silently ignored — that's the normal "someone else got
        // it" case, not an error.
        var one_byte: [1]u8 = undefined;
        _ = socket.read(read_fd, &one_byte, 1);
    }

    /// Start LOOP_COUNT concurrent event loops using std.Io.Group.
    ///
    /// Spawns the loops and RETURNS immediately. startEventLoop is
    /// itself invoked via group.concurrent from main.zig; blocking on
    /// the child group inside that closure made shutdown fragile (the
    /// outer group.cancel propagated into the inner wait while child
    /// loops were blocked in raw syscalls). The loops exit cleanly on
    /// `running=false` (set by stop()/deinit()); the caller's group
    /// tracks the spawned children for the process lifetime.
    pub fn startEventLoop(self: *SseManager, heartbeat_secs: u32) !void {
        self.running = true;
        var group: std.Io.Group = .init;

        for (0..LOOP_COUNT) |loop_id| {
            try group.concurrent(
                self.io,
                struct {
                    fn run(mgr: *SseManager, secs: u32, id: usize) void {
                        mgr.runEventLoop(secs, id);
                    }
                }.run,
                .{ self, heartbeat_secs, loop_id },
            );
        }
        // No join here — see the doc comment above. The local `group`
        // only aggregates the spawned closures; std.Io.Group's child
        // handles are owned by the Io runtime and keep running after
        // this function returns.
    }

    pub fn gracefulShutdown(self: *SseManager) void {
        const close_msg = "event: close\ndata: Server shutting down\n\n";

        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);

        var it = self.clients.iterator();
        while (it.next()) |entry| {
            const fd = entry.value_ptr.*.fd;
            // Send the close event as one chunked frame, then send the
            // chunked-encoding terminator (0\r\n\r\n) so the peer can
            // finalize its chunked-decoding state cleanly. Both writes
            // are best-effort — `deinit` below closes the fd
            // regardless, and a stale peer will get EPOLLHUP on its
            // next read.
            writeChunkedFrame(fd, close_msg) catch {};
            _ = sendAll(fd, "0\r\n\r\n");
        }

        log.info("gracefulShutdown removing={d}", .{self.clients.count()});
        while (self.clients.count() > 0) {
            var it2 = self.clients.iterator();
            if (it2.next()) |entry| {
                const id = entry.key_ptr.*;
                const fd = entry.value_ptr.*.fd;
                // Full `deinit()` (not `forceDestroy()`) so the per-client
                // arena + message_queue are freed — see the comment in
                // `deinit` above for the rationale.
                entry.value_ptr.*.deinit();
                _ = self.clients.remove(id);
                _ = self.fd_to_id.remove(fd);
            }
        }
        self.clients.clearRetainingCapacity();
        self.fd_to_id.clearRetainingCapacity();
    }

    pub fn stop(self: *SseManager) void {
        self.running = false;
        self.notifyLoops();
    }

    /// Each loop handles clients at indices where client_index % LOOP_COUNT == loop_id
    fn runEventLoop(self: *SseManager, heartbeat_secs: u32, loop_id: usize) void {
        const heartbeat_ms: i32 = @intCast(heartbeat_secs * 1000);
        var last_hb: i64 = @intCast(timestamp(self.io));

        while (self.running) {
            // --- snapshot fds under lock (fast, no poll while holding lock) ---
            self.lock.lock(self.io) catch unreachable;

            var my_fds = std.ArrayListUnmanaged(i32).empty;
            defer my_fds.deinit(self.allocator);

            var it = self.clients.iterator();
            while (it.next()) |entry| {
                // deterministic ownership by client id — stable across inserts/removes
                if (entry.value_ptr.*.id[0] % LOOP_COUNT == loop_id) {
                    my_fds.append(self.allocator, entry.value_ptr.*.fd) catch break;
                }
            }
            self.lock.unlock(self.io); // release before poll — critical

            const has_pipe = self.notify_pipe[0] >= 0;
            const total_fds = if (has_pipe) my_fds.items.len + 1 else my_fds.items.len;

            if (total_fds == 0) {
                // no clients — wait for notification or heartbeat interval
                if (!is_windows) {
                    var ts: socket.timespec = .{
                        .sec = @intCast(heartbeat_secs),
                        .nsec = 0,
                    };
                    _ = socket.nanosleep(&ts, null);
                } else {
                    // Zig 0.16 removed `.{ .seconds = N }` from std.Io.Duration —
                    // only `.{ .nanoseconds = N }` is available. Convert the
                    // wall-clock heartbeat interval (heartbeat_secs, a u32) to
                    // nanoseconds via std.time.ns_per_s. The cast to i96 is
                    // safe: heartbeat_ns fits in i64 (the underlying type of
                    // `nanoseconds` minus its 32 sign bits is huge), and the
                    // @as(i96, ...) widening is always lossless for non-negative
                    // u64 values.
                    //
                    // NB: widen heartbeat_secs to u64 BEFORE the multiply —
                    // multiplying u32 by the comptime int 1_000_000_000 produces
                    // a u32 result which OVERFLOWS for any heartbeat_secs >= 5
                    // (5 * 1e9 > u32 max = 4_294_967_295). That was the source of
                    // the "thread panic: integer overflow" on Windows startup —
                    // every SSE worker thread crashed before it could service
                    // any clients, leaving the HTTP server unable to accept
                    // /health probes from nalar-desktop → AutoSpawnFailed.
                    std.Io.sleep(self.io, .{ .nanoseconds = @as(i96, @intCast(@as(u64, heartbeat_secs) * std.time.ns_per_s)) }, .real) catch {};
                }
                continue;
            }

            // === Windows path: no posix.poll/pollfd/POLL.* available.
            // The SSE manager is designed around posix.poll for socket
            // readiness, which doesn't exist on Windows (use WSAPoll from
            // std.os.windows.ws2_32 with different namespace + types). The
            // SSE server on Windows still works — clients receive data via
            // the direct `sendHeartbeat` / `broadcast` write paths below.
            // Full Windows SSE support requires porting the poll-based
            // loop to WSAPoll, which is out of scope for the fix-windows-ci
            // task. Disconnect detection on Windows therefore relies on
            // heartbeat write failures + the periodic sweep (same as the
            // Linux belt-and-suspenders path), NOT on poll HUP/ERR.
            //
            // CRITICAL: this branch MUST call sendHeartbeat + sweep on the
            // same cadence as the Linux path. The frontend SseClient has a
            // 7s stall detector (stallThresholdMs) with stallRecovery that
            // force-reconnects on silence. Skipping the heartbeat here
            // leaves Windows clients silent forever → EventSource
            // connects, gets `connected`, then stall-reconnects every 7s.
            if (is_windows) {
                std.Io.sleep(self.io, .{ .nanoseconds = @as(i96, @intCast(@as(u64, heartbeat_secs) * std.time.ns_per_s)) }, .real) catch {};
                const now_win: i64 = @intCast(timestamp(self.io));
                if (now_win - last_hb >= heartbeat_ms) {
                    self.sendHeartbeat(loop_id);
                    last_hb = now_win;
                    self.sweepStaleClients(@as(u64, @intCast(heartbeat_ms)) * 3, 64);
                }
                continue;
            }

            var poll_fds: []posix.pollfd = self.allocator.alloc(posix.pollfd, total_fds) catch {
                if (!is_windows) {
                    var ts: socket.timespec = .{
                        .sec = @intCast(heartbeat_secs),
                        .nsec = 0,
                    };
                    _ = socket.nanosleep(&ts, null);
                } else {
                    std.Io.sleep(self.io, .{ .nanoseconds = @as(i96, @intCast(@as(u64, heartbeat_secs) * std.time.ns_per_s)) }, .real) catch {};
                }
                continue;
            };
            defer self.allocator.free(poll_fds);

            var idx: usize = 0;
            if (has_pipe) {
                poll_fds[0] = .{
                    .fd = self.notify_pipe[0],
                    .events = posix.POLL.IN,
                    .revents = undefined,
                };
                idx = 1;
            }
            for (my_fds.items) |fd| {
                poll_fds[idx] = .{
                    .fd = fd,
                    .events = posix.POLL.IN | posix.POLL.HUP | posix.POLL.NVAL,
                    .revents = undefined,
                };
                idx += 1;
            }

            // poll blocks here — lock is FREE, sendToClient/registerClient can proceed
            _ = posix.poll(poll_fds, heartbeat_ms) catch continue;

            for (poll_fds[0..total_fds]) |pfd| {
                const revents = @as(u16, @bitCast(pfd.revents));
                if (revents == 0) continue;

                const poll_err = @as(u16, @intCast(posix.POLL.ERR));
                const poll_hup = @as(u16, @intCast(posix.POLL.HUP));
                // POLL.NVAL is the only event the kernel can set on a
                // "sock but not IPv4" orphan FD — the classic signature
                // of a leaked FD whose underlying kernel socket has
                // already been reaped (peer FIN + 2MSL + unlink) but
                // whose userspace FD was never close()'d. Without this
                // branch, those FDs are invisible to the reaper and
                // accumulate until `RLIMIT_NOFILE` is hit, surfacing as
                // `ProcessFdQuotaExceeded` for every FD-allocating
                // syscall (`read_file`, `bash`, sub-agent `spawn`, etc.).
                const poll_nval = @as(u16, @intCast(posix.POLL.NVAL));
                const poll_in = @as(u16, @intCast(posix.POLL.IN));

                if (revents & (poll_err | poll_hup | poll_nval) != 0) {
                    log.debug("poll revents fd={d} revents=0x{x}", .{ pfd.fd, revents });
                    if (revents & poll_hup != 0) {
                        _ = self.removeClientByFd(pfd.fd, .poll_hup);
                    } else if (revents & poll_err != 0) {
                        _ = self.removeClientByFd(pfd.fd, .poll_err);
                    } else {
                        _ = self.removeClientByFd(pfd.fd, .poll_nval);
                    }
                    continue;
                }

                if (revents & poll_in != 0) {
                    if (has_pipe and pfd.fd == self.notify_pipe[0]) {
                        if (!is_windows) {
                            // Consume exactly ONE wakeup byte, non-blocking.
                            // The old blocking drain-everything read stranded
                            // the other LOOP_COUNT-1 event loops forever —
                            // see drainPipeNonBlocking's doc comment.
                            self.drainPipeNonBlocking();
                        }
                    } else {
                        var buf: [64]u8 = undefined;
                        const n = socket.read(pfd.fd, &buf, buf.len);
                        if (n <= 0) {
                            log.debug("read() returned {d} on fd={d} (EOF or error)", .{ n, pfd.fd });
                            _ = self.removeClientByFd(pfd.fd, .eof_read);
                        }
                    }
                }
            }

            // only send heartbeat when actually due
            const now: i64 = @intCast(timestamp(self.io));
            if (now - last_hb >= heartbeat_ms) {
                self.sendHeartbeat(loop_id);
                last_hb = now;
                // Belt-and-suspenders sweep: pick up any client whose
                // `last_heartbeat` is older than 3 heartbeat cycles.
                // Defends against any future bug that lets a dead
                // client slip past the poll reaper (POLL.HUP/ERR/NVAL)
                // and the heartbeat reaper (EPIPE/ECONNRESET/EBADF).
                // Capped at 64 removals per iteration to avoid O(N²)
                // behaviour when many clients go stale at once (e.g.,
                // a server-side rollback).
                self.sweepStaleClients(@as(u64, @intCast(heartbeat_ms)) * 3, 64);
            }
        }
    }

    /// Sweep clients whose `last_heartbeat` is older than
    /// `max_stale_ms`. Removes up to `max_per_call` clients per call to
    /// bound the worst-case CPU cost when a large batch goes stale at
    /// once. Must be called under the per-loop cadence — typically
    /// once per heartbeat cycle.
    ///
    /// Exposed as `pub` so the unit test can verify the staleness
    /// sweep without standing up the full event loop. Production
    /// callers should rely on `runEventLoop`'s per-cycle call.
    pub fn sweepStaleClients(self: *SseManager, max_stale_ms: u64, max_per_call: usize) void {
        const now = timestamp(self.io);

        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);

        var stale_ids: std.ArrayListUnmanaged([16]u8) = .empty;
        defer stale_ids.deinit(self.allocator);

        var it = self.clients.iterator();
        outer: while (it.next()) |entry| {
            const client = entry.value_ptr.*;
            const age_ms = now -| client.last_heartbeat;
            if (age_ms > max_stale_ms) {
                stale_ids.append(self.allocator, client.id) catch break :outer;
                if (stale_ids.items.len >= max_per_call) break :outer;
            }
        }

        // Reap under the same lock. Mirrors the close-before-deinit
        // pattern in `removeClient` so partial-write chunked frames
        // don't produce `ERR_INCOMPLETE_CHUNKED_ENCODING` in the browser.
        for (stale_ids.items) |id| {
            if (self.clients.fetchRemove(id)) |entry| {
                const fd = entry.value.*.fd;
                _ = self.fd_to_id.remove(fd);
                log.info("sweepStale fd={d} id={x} age_ms={d} threshold_ms={d}", .{
                    fd, id, now -| entry.value.*.last_heartbeat, max_stale_ms,
                });
                _ = sendAll(fd, "0\r\n\r\n");
                entry.value.*.deinit();
                self.server_allocator.destroy(entry.value);
            }
        }
    }

    /// Only send heartbeat to clients owned by this loop
    fn sendHeartbeat(self: *SseManager, loop_id: usize) void {
        const ping = "data: ping\n\n";

        // Snapshot the client pointers under the lock. Without the lock,
        // a concurrent `registerClient` / `removeClient` could invalidate
        // the iterator or free a client we are about to dereference —
        // the resulting use-after-free corrupts the heap, and a write to
        // an already-closed fd can also produce a half-flushed chunked
        // frame (no terminating `0\r\n\r\n`), which the browser then
        // surfaces as `net::ERR_INCOMPLETE_CHUNKED_ENCODING 200 (OK)`
        // after the long-idle page finally drops the connection.
        // The probability of hitting this race grows with uptime and
        // concurrent register/remove activity, which matches the
        // "long period on page" symptom from the user report.
        self.lock.lock(self.io) catch unreachable;
        var client_ptrs: std.ArrayListUnmanaged(*SseClient) = .empty;
        defer client_ptrs.deinit(self.allocator);

        var it = self.clients.iterator();
        // Shard by `id[0] % LOOP_COUNT` to MATCH the poll loop's
        // sharding rule (`sse_manager.zig:308`). The previous
        // implementation used `global_idx % LOOP_COUNT`, which depended
        // on hashmap iteration order — two shards can disagree on which
        // loop "owns" a client. While every client was still heartbeated
        // (the modulo covered all residue classes), the sharding rule
        // had to match the poll loop's so future per-client ownership
        // invariants (e.g., the periodic sweep in
        // `sweepStaleClients`) can rely on a single source of truth.
        while (it.next()) |entry| {
            if (entry.value_ptr.*.id[0] % LOOP_COUNT == loop_id) {
                client_ptrs.append(self.allocator, entry.value_ptr.*) catch break;
            }
        }
        self.lock.unlock(self.io);

        var dead_ids: std.ArrayListUnmanaged([16]u8) = .empty;
        defer dead_ids.deinit(self.allocator);

        for (client_ptrs.items) |client| {
            // Route through `SseClient.sendEvent` so the ping takes the
            // PER-CLIENT lock. Writing the chunked frame unlocked raced
            // with concurrent `sendToClient` / broadcast writers on the
            // same fd: two threads interleaving their `<hex len>\r\n`
            // headers + payloads corrupt the chunked framing, which the
            // browser surfaces as a protocol error → EventSource
            // reconnects forever. The manager-lock snapshot above only
            // protects the client LIST, not the fd's byte stream.
            // Only update `last_heartbeat` on a SUCCESSFUL write so the
            // periodic sweep (`sweepStaleClients`) can still reap a
            // client whose pings keep failing.
            if (client.sendEvent(ping)) |_| {
                client.last_heartbeat = timestamp(self.io);
                log.info("heartbeat sent fd={d} id={x}", .{ client.fd, client.id });
            } else |_| {
                log.info("heartbeat write FAILED fd={d} id={x}", .{ client.fd, client.id });
                dead_ids.append(self.allocator, client.id) catch break;
            }
        }

        for (dead_ids.items) |id| {
            self.removeClient(id, .heartbeat_write_failed);
        }
    }

    pub fn sendToClient(self: *SseManager, id: [16]u8, data: []const u8) !void {
        // Acquire the per-manager lock BEFORE reading from `self.clients`
        // so a concurrent `registerClient` / `removeClient` cannot
        // rehash the underlying bucket array out from under us (which
        // would read freed memory and — if `client.fd` happened to be
        // recycled by a subsequent `registerClient` — write chunked
        // data to the wrong socket, causing `removeClient` on the
        // failure path to fire against a foreign client and leak the
        // real victim's fd). See the "sendToClient UAF" audit in
        // docs/superpowers/plans/2026-07-01-fix-remaining-fd-leak-risks.md.
        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);

        const client = self.clients.get(id) orelse return error.ClientNotFound;

        // Route through the chunked-encoding helper so the peer's
        // HTTP/1.1 chunked-decoder can parse the byte stream. A
        // write failure (peer gone) means the client is dead; remove
        // it and bubble up the error to the caller.
        //
        // Zig pattern: `if (error_union) { success } else |err| { ... }`
        // compiles because the else branch handles the error and
        // returns it — the body of the if-statement is reached only
        // on success. The payload capture `|_|` is required because
        // `writeChunkedFrame` returns `!void` (no payload) and the
        // pattern needs explicit binding for the success branch.
        if (writeChunkedFrame(client.fd, data)) |_| {
            // success
        } else |_| {
            log.info("sendToClient write FAILED fd={d} id={x}", .{ client.fd, id });
            // Failed write — inline the remove logic so we don't
            // try to re-acquire `self.lock` (which we already hold).
            // Mirrors the close-before-deinit pattern in `removeClient`
            // so partial chunked frames don't produce
            // `ERR_INCOMPLETE_CHUNKED_ENCODING` in the browser.
            if (self.clients.fetchRemove(id)) |entry| {
                const fd = entry.value.*.fd;
                log.info("remove fd={d} id={x} reason={s} remaining={d}", .{
                    fd, id, @tagName(RemoveReason.send_to_client_failed), self.clients.count(),
                });
                _ = self.fd_to_id.remove(fd);
                _ = sendAll(fd, "0\r\n\r\n");
                entry.value.*.deinit();
                self.server_allocator.destroy(entry.value);
            }
            if (self.on_disconnect) |cb| cb(id);
            // The only error variant in the `writeChunkedFrame` error
            // set is `WriteFailed`; map it to ClientDisconnected to
            // preserve the original public API of `sendToClient`.
            return error.ClientDisconnected;
        }
    }

    pub fn broadcast(self: *SseManager, data: []const u8) !void {
        const event = try std.fmt.allocPrint(self.allocator, "data: {s}\n\n", .{data});
        defer self.allocator.free(event);

        self.lock.lock(self.io) catch unreachable;
        var client_ptrs: std.ArrayListUnmanaged(*SseClient) = .empty;
        defer client_ptrs.deinit(self.allocator);

        var it = self.clients.iterator();
        while (it.next()) |entry| {
            client_ptrs.append(self.allocator, entry.value_ptr.*) catch break;
        }
        self.lock.unlock(self.io);

        for (client_ptrs.items) |client| {
            // Per-client lock via sendEvent — see sendHeartbeat's
            // comment. An unlocked writeChunkedFrame here can interleave
            // with a concurrent heartbeat / sendToClient on the same fd
            // and corrupt the chunked framing (browser → endless
            // reconnect).
            if (client.sendEvent(event)) |_| {
                // success
            } else |_| {
                log.info("broadcast write FAILED fd={d} id={x}", .{ client.fd, client.id });
                self.removeClient(client.id, .broadcast_write_failed);
            }
        }
    }

    pub fn broadcastTyped(self: *SseManager, event_type: []const u8, data: []const u8) !void {
        const event = try std.fmt.allocPrint(self.allocator, "event: {s}\ndata: {s}\n\n", .{ event_type, data });
        defer self.allocator.free(event);

        self.lock.lock(self.io) catch unreachable;
        var client_ptrs: std.ArrayListUnmanaged(*SseClient) = .empty;
        defer client_ptrs.deinit(self.allocator);

        var it = self.clients.iterator();
        while (it.next()) |entry| {
            client_ptrs.append(self.allocator, entry.value_ptr.*) catch break;
        }
        self.lock.unlock(self.io);

        for (client_ptrs.items) |client| {
            // Per-client lock via sendEvent — see sendHeartbeat's
            // comment. An unlocked writeChunkedFrame here can interleave
            // with a concurrent heartbeat / sendToClient on the same fd
            // and corrupt the chunked framing.
            if (client.sendEvent(event)) |_| {
                // success
            } else |_| {
                log.info("broadcastTyped write FAILED fd={d} id={x}", .{ client.fd, client.id });
                self.removeClient(client.id, .broadcast_write_failed);
            }
        }
    }

    pub fn clientCount(self: *SseManager) usize {
        self.lock.lock(self.io) catch unreachable;
        defer self.lock.unlock(self.io);
        return self.clients.count();
    }

    /// Send `data` as one HTTP/1.1 chunked-transfer-encoding frame
    /// on the wire: `<hex length>\r\n<data>\r\n`. Returns
    /// `error.ClientDisconnected` if the peer hung up (peer socket
    /// closed) or the write itself failed.
    ///
    /// Allocates a small stack-buffer for the length header (16 bytes
    /// is enough for any 64-bit length).
    pub fn sendChunked(self: *SseManager, id: [16]u8, data: []const u8) !void {
        const client = self.clients.get(id) orelse return error.ClientNotFound;
        try writeChunkedFrame(client.fd, data);
    }

    /// Send the chunked-encoding terminator: `0\r\n\r\n`. Call this
    /// once on every SSE connection just before closing the socket,
    /// so that intermediaries (Vite, browser) can finalize their
    /// chunked decoding state cleanly. Failure is non-fatal — the
    /// socket close itself signals end-of-stream.
    pub fn sendTerminatingChunk(self: *SseManager, id: [16]u8) void {
        const client = self.clients.get(id) orelse return;
        // Failure is non-fatal — caller is about to close the fd anyway.
        _ = sendAll(client.fd, "0\r\n\r\n");
    }
};

/// Write one HTTP/1.1 chunked-transfer-encoding frame to `fd`:
/// `<hex length>\r\n<data>\r\n`. Returns `error.WriteFailed` if the
/// underlying send fails for any reason.
///
/// This is a free function so both `SseManager.sendChunked` (which
/// looks up the client by id) and `SseClient.sendEvent` (which
/// already has the fd and is inside its per-client lock) can call
/// it without duplicating the 3-write loop.
pub fn writeChunkedFrame(fd: i32, data: []const u8) !void {
    var len_buf: [16]u8 = undefined;
    const len_str = std.fmt.bufPrint(&len_buf, "{x}\r\n", .{data.len}) catch
        return error.WriteFailed;
    const trailer = "\r\n";

    if (sendAll(fd, len_str) < len_str.len) return error.WriteFailed;
    if (sendAll(fd, data) < data.len) return error.WriteFailed;
    if (sendAll(fd, trailer) < trailer.len) return error.WriteFailed;
}

/// Write all of `data` to `fd`, looping on short writes. Returns
/// the number of bytes actually written, or -1 on error.
///
/// On Linux uses `sendto(fd, buf, len, MSG_NOSIGNAL, null, 0)` so a
/// peer-closed socket returns `EPIPE` instead of killing the process
/// with SIGPIPE. On non-Linux platforms falls back to
/// `posix.system.write` (macOS has SIGPIPE ignored by default in
/// many setups; Windows has no SIGPIPE at all).
fn sendAll(fd: i32, data: []const u8) isize {
    if (is_linux) {
        var sent: usize = 0;
        const flags: u32 = std.os.linux.MSG.NOSIGNAL;
        while (sent < data.len) {
            // sendto(fd, buf, len, flags, addr=null, alen=0) is
            // equivalent to send(2) on a connected socket — but
            // unlike send(2), sendto accepts flags so we can pass
            // MSG_NOSIGNAL to suppress SIGPIPE on peer close.
            const rc = std.os.linux.sendto(fd, data[sent..].ptr, data.len - sent, flags, null, 0);
            if (rc > std.math.maxInt(i32)) return -1;
            const n: isize = @intCast(rc);
            if (n < 0) return -1;
            if (n == 0) return -1;
            sent += @as(usize, @intCast(n));
        }
        return @intCast(sent);
    } else if (is_windows) {
        // On Windows, SSE fds are winsock SOCKET values (small positive
        // ints truncated from the pointer-sized handle). MSVCRT's
        // `write()` is for file/console HANDLEs (it calls `WriteFile`
        // which fails on sockets); the only correct way to send on a
        // winsock socket from a fd-shaped value is `winsock.send()`
        // (which corresponds to libc's send(2)). The winsock API takes
        // `c_int` (the same shape as the SOCKET), so we pass the i32
        // `fd` straight through after the same sign-extension that
        // `http_server.zig`'s `sendToClient` applies.
        var sent: usize = 0;
        while (sent < data.len) {
            const rc = winsock.send(
                fd,
                data[sent..].ptr,
                @intCast(data.len - sent),
                0,
            );
            if (rc < 0) return -1;
            if (rc == 0) return -1;
            sent += @as(usize, @intCast(rc));
        }
        return @intCast(sent);
    } else {
        // macOS / BSD: use posix.system.write. SIGPIPE is a no-op on
        // macOS; the default disposition varies; the SseClient-side
        // `self.alive` flag and the next `sendEvent` call will surface
        // the disconnect.
        var sent: usize = 0;
        while (sent < data.len) {
            const rc = posix.system.write(fd, data[sent..].ptr, data.len - sent);
            if (rc > std.math.maxInt(i32)) return -1;
            const n: isize = @intCast(rc);
            if (n < 0) return -1;
            if (n == 0) return -1;
            sent += @as(usize, @intCast(n));
        }
        return @intCast(sent);
    }
}

/// Upper bound on how long ONE SSE write may block on a single client's
/// socket before that peer is treated as dead and dropped.
///
/// Why this exists — the agent-stall chain:
///
///   `SseManager.sendToClient` (below) writes while holding
///   `self.lock`, and SSE emits are SYNCHRONOUS: `event_bus.emit` runs
///   the forwarding callback on the CALLER's thread, which for
///   `llm_chunk` is the agent workflow thread. With an unbounded
///   blocking `send()` on a peer that has stopped reading (closed
///   window, suspended machine, half-open TCP), ONE dead client parks
///   that thread while holding the manager lock — so every other SSE
///   emit in the process queues behind it. The agent's HTTP consumer
///   then stops draining `custom_http_client`'s 64-slot chunk queue,
///   the queue fills, and the LLM stream is aborted with
///   `WriteError` ("scanner.next failed after N chunk(s): WriteError"),
///   discarding the whole response and retrying it from scratch.
///
/// Bounding the send converts "one dead peer stalls the whole system"
/// into "one dead peer is dropped". Dropping is the intended recovery:
/// the frontend's SseClient has a stall detector plus auto-reconnect,
/// and `sendToClient` already removes any client whose write fails.
const SSE_SEND_TIMEOUT_MS: u32 = 5_000;

/// Set `SO_SNDTIMEO` on an SSE client socket (or a test fd) so a single
/// blocked write can't park the emitting thread indefinitely.
///
/// Best-effort by design: every failure is swallowed, because without
/// the socket option the behaviour is exactly what it was before this
/// helper existed — it can never make things worse.
///
/// Platform notes:
///   - **POSIX**: `SO_SNDTIMEO` takes a `struct timeval`. The kernel
///     REJECTS `tv_usec >= 1_000_000` with `EDOM` (surfaced by
///     `std.posix.setsockopt` as `error.TimeoutTooBig`), so the whole
///     seconds MUST go in `.sec` — `.sec = 0, .usec = 5_000_000` fails
///     to apply. Also note `std.posix.setsockopt` carries a comptime
///     `@compileError` on Windows, hence the explicit branch.
///   - **Windows**: Winsock's `SO_SNDTIMEO` takes a `DWORD` of
///     milliseconds (not a timeval), at optname `0x1005`,
///     `SOL_SOCKET = 0xffff`.
pub fn setFdSendTimeout(fd: i32, timeout_ms: u32) void {
    if (is_windows) {
        const ms: u32 = timeout_ms;
        _ = winsock.setsockopt(fd, 0xffff, 0x1005, @ptrCast(&ms), @sizeOf(u32));
        return;
    }
    var tv: posix.timeval = .{
        .sec = @intCast(@divTrunc(timeout_ms, 1000)),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
}

/// Set O_NONBLOCK on `fd` so reads on an empty pipe return EAGAIN
/// instead of blocking forever. Best-effort: failures are swallowed
/// (worst case the caller keeps the old blocking behaviour).
///
/// Per-platform strategy:
///   - **Linux**: raw `std.os.linux.fcntl` syscall. Zig 0.16's
///     `std.posix` has no fcntl wrapper, and this file already links
///     libc, but the syscall path avoids any libc-version variance.
///   - **macOS / BSD**: libc `fcntl` via `std.c.fcntl` (variadic
///     extern). Darwin's F_GETFL/F_SETFL/O_NONBLOCK values match
///     Linux's (3/4/0o4000), so the same constants apply.
///   - **Windows**: no-op — the SSE manager never creates a pipe on
///     Windows (`init` skips `pipe()`; the event loop is a sleep +
///     heartbeat cycle), so there is nothing to make non-blocking.
fn setFdNonBlocking(fd: i32) void {
    if (is_windows) return;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const O_NONBLOCK: i32 = 0o4000;

    if (is_linux) {
        const getfl_rc = std.os.linux.fcntl(fd, F_GETFL, 0);
        if (std.os.linux.errno(getfl_rc) == .SUCCESS) {
            const flags: usize = @intCast(getfl_rc);
            const setfl_rc = std.os.linux.fcntl(
                fd,
                F_SETFL,
                flags | @as(usize, @intCast(O_NONBLOCK)),
            );
            _ = std.os.linux.errno(setfl_rc); // best-effort; ignore result
        }
        return;
    }

    // macOS / BSD: variadic libc fcntl. Zig's std.c.fcntl is declared
    // `extern "c" fn fcntl(fd: fd_t, cmd: c_int, ...) c_int`.
    const flags = c.fcntl(fd, F_GETFL);
    if (flags >= 0) {
        _ = c.fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

fn timestamp(io: std.Io) u64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}
