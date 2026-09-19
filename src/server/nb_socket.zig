//! Non-blocking socket helpers for the event-loop migration (Phase 1).
//!
//! The threaded server (`http_server.zig:listen`) uses blocking `accept` +
//! one thread per connection. The reactor (`event_loop.zig`) needs every fd
//! non-blocking plus a small readiness vocabulary on top of `std.posix.poll`.
//!
//! POSIX-only v1: on Windows every helper returns `error.Unsupported` and the
//! caller (`GinwaServer.listenEventLoop`) falls back to the threaded path.
//! Winsock needs `ioctlsocket(FIONBIO)` + `WSAPoll`, which is Phase 6 work.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const is_windows = builtin.os.tag == .windows;

/// Readiness mask bits. Values match Linux `poll(2)` (`std.os.linux.POLL`)
/// and macOS `<sys/poll.h>` — both define IN=0x001 OUT=0x004 ERR=0x008
/// HUP=0x010 NVAL=0x020, so one constant set serves all POSIX targets.
pub const POLL = struct {
    pub const IN: i16 = 0x001;
    pub const PRI: i16 = 0x002;
    pub const OUT: i16 = 0x004;
    pub const ERR: i16 = 0x008;
    pub const HUP: i16 = 0x010;
    pub const NVAL: i16 = 0x020;
};

/// Put `fd` into non-blocking mode.
///
/// Same per-platform strategy as `sse_manager.zig:setFdNonBlocking`
/// (Zig 0.16's `std.posix` has no fcntl wrapper):
///   - Linux: raw `std.os.linux.fcntl` syscall.
///   - macOS/BSD: variadic libc `fcntl` via `std.c.fcntl`.
///     F_GETFL/F_SETFL/O_NONBLOCK are 3/4/0o4000 on both.
///   - Windows: `error.Unsupported` (needs `ioctlsocket(FIONBIO)` — Phase 6).
pub fn setNonBlocking(fd: i32) !void {
    if (comptime is_windows) return error.Unsupported;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const O_NONBLOCK: i32 = 0o4000;
    if (comptime builtin.os.tag == .linux) {
        const getfl_rc = std.os.linux.fcntl(fd, F_GETFL, 0);
        if (std.os.linux.errno(getfl_rc) != .SUCCESS) return error.FcntlFailed;
        const flags: usize = @intCast(getfl_rc);
        const setfl_rc = std.os.linux.fcntl(
            fd,
            F_SETFL,
            flags | @as(usize, @intCast(O_NONBLOCK)),
        );
        if (std.os.linux.errno(setfl_rc) != .SUCCESS) return error.FcntlFailed;
        return;
    }
    const c = std.c;
    const flags = c.fcntl(fd, F_GETFL);
    if (flags < 0) return error.FcntlFailed;
    if (c.fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return error.FcntlFailed;
}

/// True when a raw errno means "try again later" on a non-blocking fd.
pub fn isWouldBlock(err: anyerror) bool {
    return err == error.WouldBlock;
}

/// Accept one pending connection on a non-blocking listener.
///
/// Returns `error.WouldBlock` when the accept queue is drained (the normal
/// "nothing left to accept this tick" signal — NOT a failure). The returned
/// fd is left in whatever mode the listener has; callers that want
/// non-blocking clients call `setNonBlocking` on it.
pub fn acceptNonBlocking(listener_fd: i32) !i32 {
    if (comptime is_windows) return error.Unsupported;
    // Raw accept(2): same call `http_server.zig:acceptClient` uses, but the
    // listener is non-blocking so an empty queue fails with EAGAIN instead
    // of parking the thread.
    var addr: posix.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    const rc = posix.system.accept(
        listener_fd,
        @ptrCast(&addr),
        &addr_len,
    );
    if (rc < 0) {
        const e = std.posix.errno(rc);
        return switch (e) {
            .AGAIN => error.WouldBlock,
            .INTR => error.WouldBlock, // spurious wakeup — retry next tick
            else => error.AcceptFailed,
        };
    }
    return @intCast(rc);
}

/// Non-blocking recv. Returns:
///   - `null` → would block (no data right now, retry when POLLIN fires)
///   - `0`    → orderly EOF (peer sent FIN)
///   - `n>0`  → bytes placed in `buf[0..n]`
pub fn recvNonBlocking(fd: i32, buf: []u8) !?usize {
    if (comptime is_windows) return error.Unsupported;
    if (buf.len == 0) return @as(?usize, 0);
    const rc: isize = posix.system.read(fd, buf.ptr, buf.len);
    if (rc < 0) {
        const e = std.posix.errno(rc);
        return switch (e) {
            .AGAIN => null,
            .INTR => null,
            .PIPE => error.Closed,
            else => error.RecvFailed,
        };
    }
    return @as(usize, @intCast(rc));
}

/// Non-blocking send. Returns bytes accepted by the kernel (may be short —
/// caller advances its outbox offset). Returns `0` when the send buffer is
/// full (retry when POLLOUT fires); never blocks.
pub fn sendNonBlocking(fd: i32, bytes: []const u8) !usize {
    if (comptime is_windows) return error.Unsupported;
    if (bytes.len == 0) return 0;
    const rc: isize = posix.system.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) {
        const e = std.posix.errno(rc);
        return switch (e) {
            .AGAIN => 0,
            .INTR => 0,
            .PIPE => error.Closed,
            else => error.SendFailed,
        };
    }
    return @as(usize, @intCast(rc));
}

/// One `poll(2)` call over `fds`. Returns ready count.
/// `timeout_ms < 0` blocks indefinitely, `0` returns immediately.
/// (`std.posix.poll` already retries internally on EINTR.)
pub fn pollOnce(fds: []posix.pollfd, timeout_ms: i32) !usize {
    if (comptime is_windows) return error.Unsupported;
    return posix.poll(fds, timeout_ms);
}

/// Fill a `pollfd` for readability (+ errors/hangup always reported).
pub fn pollIn(fd: i32) posix.pollfd {
    return .{ .fd = fd, .events = POLL.IN, .revents = 0 };
}

/// Fill a `pollfd` for readability AND writability.
pub fn pollInOut(fd: i32) posix.pollfd {
    return .{ .fd = fd, .events = POLL.IN | POLL.OUT, .revents = 0 };
}

/// True when `revents` carries an error/hangup/invalid condition.
pub fn isErrorHungup(revents: i16) bool {
    return (revents & (POLL.ERR | POLL.HUP | POLL.NVAL)) != 0;
}

/// Bind + listen a REUSEPORT listener on `host_le:port` (Phase 6 multi-loop).
///
/// Each loop thread calls this with the SAME ip:port; the kernel
/// load-balances accepts across them (Linux `SO_REUSEPORT`, same option
/// on macOS/BSD). `host_le` is the little-endian u32 layout from
/// `http_server.Address.parseHostLe` (e.g. 127.0.0.1 → 0x0100007f).
/// The returned fd is blocking; the loop sets non-blocking on entry.
pub fn bindReusePort(host_le: u32, port: u16) !i32 {
    if (comptime is_windows) return error.Unsupported;
    const sys = posix.system;
    const raw = sys.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    if (raw < 0) return error.SocketCreationFailed;
    const fd: i32 = @intCast(raw);
    errdefer _ = sys.close(fd);

    const opt: i32 = 1;
    posix.setsockopt(
        fd,
        @intCast(posix.SOL.SOCKET),
        @intCast(posix.SO.REUSEADDR),
        std.mem.asBytes(&opt),
    ) catch return error.SetSockOptFailed;
    // SO_REUSEPORT: 15 on Linux, 0x0200 on macOS/BSD. Not exposed via
    // `posix.SO` on every target, so spell it per-OS like the fcntl
    // constants above.
    const SO_REUSEPORT: u32 = switch (builtin.os.tag) {
        .linux => 15,
        .macos, .freebsd, .openbsd, .netbsd, .dragonfly => 0x0200,
        else => return error.Unsupported,
    };
    posix.setsockopt(
        fd,
        @intCast(posix.SOL.SOCKET),
        SO_REUSEPORT,
        std.mem.asBytes(&opt),
    ) catch return error.SetSockOptFailed;

    var sockaddr: sys.sockaddr.in = .{
        .family = 2, // AF_INET
        .port = @byteSwap(port),
        .addr = @bitCast(host_le),
        .zero = undefined,
    };
    if (sys.bind(fd, @ptrCast(&sockaddr), @sizeOf(sys.sockaddr.in)) < 0)
        return error.BindFailed;
    if (sys.listen(fd, 1024) < 0) return error.ListenFailed;
    return fd;
}
