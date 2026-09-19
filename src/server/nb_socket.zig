//! Non-blocking socket helpers for the event-loop reactor.
//!
//! The threaded server (`http_server.zig:listen`) uses blocking `accept` +
//! one thread per connection. The reactor (`event_loop.zig`) needs every fd
//! non-blocking plus a small readiness vocabulary.
//!
//! Cross-platform:
//!   - POSIX: `fcntl(O_NONBLOCK)` + `poll(2)` + `socketpair(2)`.
//!   - Windows: Winsock `ioctlsocket(FIONBIO)` + `WSAPoll` + TCP-loopback
//!     pair (Winsock has no `socketpair`; same approach as
//!     `test_helpers.zig:createSocketPair`). `ws2_32` import libs ship
//!     with Zig, so no extra link step is needed.
//!
//! Out of scope (still `error.Unsupported`): `bindReusePort` on Windows —
//! Windows has no `SO_REUSEPORT` equivalent, so `loop_count > 1` stays
//! POSIX-only and `listenEventLoop` fails fast there.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const is_windows = builtin.os.tag == .windows;

/// Platform socket-readiness mask bits. Same names everywhere; values are
/// per-OS (`poll(2)` on POSIX, `WSAPoll` on Windows) so `event_loop.zig`
/// never branches.
pub const POLL = if (is_windows) struct {
    pub const IN: i16 = 0x0100; // POLLRDNORM
    pub const PRI: i16 = 0x0400; // POLLPRI
    pub const OUT: i16 = 0x0010; // POLLWRNORM
    pub const ERR: i16 = 0x0001; // POLLERR
    pub const HUP: i16 = 0x0002; // POLLHUP
    pub const NVAL: i16 = 0x0004; // POLLNVAL
} else struct {
    pub const IN: i16 = 0x001;
    pub const PRI: i16 = 0x002;
    pub const OUT: i16 = 0x004;
    pub const ERR: i16 = 0x008;
    pub const HUP: i16 = 0x010;
    pub const NVAL: i16 = 0x020;
};

/// One polled fd. Identical layout to `posix.pollfd` on POSIX
/// (`extern struct { fd: i32, events: i16, revents: i16 }`), so the POSIX
/// path reinterprets the slice directly; the Windows path translates into
/// `WSAPOLLFD` per call (Winsock's `fd` is pointer-sized).
pub const PollFd = extern struct {
    fd: i32,
    events: i16,
    revents: i16,
};

/// Winsock 2 externs. Same declaration style as `http_server.zig` and
/// `test_helpers.zig` (production fds stay `i32` SOCKET values; only the
/// `WSAPOLLFD.fd` field widens to `usize` per the Winsock ABI).
const winsock = if (is_windows) struct {
    extern "ws2_32" fn WSAStartup(wVersionRequested: c_ushort, wsaData: *WSADATA) callconv(.c) c_int;
    extern "ws2_32" fn WSAGetLastError() callconv(.c) c_int;
    extern "ws2_32" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) callconv(.c) c_int;
    extern "ws2_32" fn ioctlsocket(sockfd: c_int, cmd: c_long, argp: *c_ulong) callconv(.c) c_int;
    extern "ws2_32" fn closesocket(sockfd: c_int) callconv(.c) c_int;
    extern "ws2_32" fn bind(sockfd: c_int, addr: [*]const u8, addrlen: c_int) callconv(.c) c_int;
    extern "ws2_32" fn listen(sockfd: c_int, backlog: c_int) callconv(.c) c_int;
    extern "ws2_32" fn accept(sockfd: c_int, addr: ?*anyopaque, addrlen: ?*c_int) callconv(.c) c_int;
    extern "ws2_32" fn connect(sockfd: c_int, addr: [*]const u8, addrlen: c_int) callconv(.c) c_int;
    extern "ws2_32" fn getsockname(sockfd: c_int, addr: [*]u8, addrlen: [*]c_int) callconv(.c) c_int;
    extern "ws2_32" fn recv(sockfd: c_int, buf: ?*anyopaque, len: c_int, flags: c_int) callconv(.c) c_int;
    extern "ws2_32" fn send(sockfd: c_int, buf: ?*const anyopaque, len: c_int, flags: c_int) callconv(.c) c_int;
    extern "ws2_32" fn WSAPoll(fdarray: [*]WSAPOLLFD, nfds: c_ulong, timeout: c_int) callconv(.c) c_int;

    const WSADATA = [400]u8;
    const WSAPOLLFD = extern struct {
        fd: usize, // SOCKET
        events: i16,
        revents: i16,
    };

    // Winsock error codes (WSAGetLastError).
    const WSAEWOULDBLOCK: c_int = 10035;
    const WSAEINTR: c_int = 10004;
    const WSAECONNRESET: c_int = 10054;
    const WSAECONNABORTED: c_int = 10053;
    const WSAESHUTDOWN: c_int = 10058;
    const WSAENOTCONN: c_int = 10057;

    const FIONBIO: c_long = 0x8004667E;
    const SOCKET_ERROR: c_int = -1;
} else struct {};

/// Winsock must be started before any other winsock call. Ref-counted by
/// the DLL, so calling once per helper is safe; guarded to pay the cost
/// only on first use (same pattern as `test_helpers.zig`).
var wsa_init_lock: std.atomic.Mutex = .unlocked;
var wsa_initialized: bool = false;

fn ensureWsa() void {
    if (comptime !is_windows) return;
    if (wsa_initialized) return;
    while (!wsa_init_lock.tryLock()) std.atomic.spinLoopHint();
    defer wsa_init_lock.unlock();
    if (wsa_initialized) return;
    var wsa_data: winsock.WSADATA = undefined;
    _ = winsock.WSAStartup(0x0202, &wsa_data); // MAKEWORD(2, 2)
    wsa_initialized = true;
}

/// Widen an `i32` SOCKET value to the pointer-sized Winsock `SOCKET`
/// (`WSAPOLLFD.fd`). Bit-exact: Windows SOCKETs are small ints.
fn socketToUsize(sock: i32) usize {
    return @as(usize, @bitCast(@as(isize, sock)));
}

/// Put `fd` into non-blocking mode.
///
///   - Linux: raw `std.os.linux.fcntl` syscall (Zig 0.16's `std.posix`
///     has no fcntl wrapper; same as `sse_manager.zig:setFdNonBlocking`).
///   - macOS/BSD: variadic libc `fcntl` via `std.c.fcntl`.
///   - Windows: `ioctlsocket(FIONBIO)`.
pub fn setNonBlocking(fd: i32) !void {
    if (comptime is_windows) {
        ensureWsa();
        var mode: c_ulong = 1;
        if (winsock.ioctlsocket(fd, winsock.FIONBIO, &mode) != 0)
            return error.FcntlFailed;
        return;
    }
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

/// Close a socket fd. `closesocket` on Windows, `close(2)` elsewhere
/// (libc `close` does not release Winsock SOCKETs).
pub fn closeSocket(fd: i32) void {
    if (comptime is_windows) {
        ensureWsa();
        _ = winsock.closesocket(fd);
    } else {
        _ = posix.system.close(fd);
    }
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
    if (comptime is_windows) {
        ensureWsa();
        const rc = winsock.accept(listener_fd, null, null);
        if (rc < 0) {
            return switch (winsock.WSAGetLastError()) {
                winsock.WSAEWOULDBLOCK, winsock.WSAEINTR => error.WouldBlock,
                else => error.AcceptFailed,
            };
        }
        return rc;
    }
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
    if (buf.len == 0) return @as(?usize, 0);
    if (comptime is_windows) {
        ensureWsa();
        const rc = winsock.recv(fd, buf.ptr, @intCast(buf.len), 0);
        if (rc < 0) {
            return switch (winsock.WSAGetLastError()) {
                winsock.WSAEWOULDBLOCK, winsock.WSAEINTR => null,
                winsock.WSAECONNRESET, winsock.WSAECONNABORTED,
                winsock.WSAESHUTDOWN, winsock.WSAENOTCONN,
                => error.Closed,
                else => error.RecvFailed,
            };
        }
        return @as(usize, @intCast(rc));
    }
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
    if (bytes.len == 0) return 0;
    if (comptime is_windows) {
        ensureWsa();
        const rc = winsock.send(fd, bytes.ptr, @intCast(bytes.len), 0);
        if (rc < 0) {
            return switch (winsock.WSAGetLastError()) {
                winsock.WSAEWOULDBLOCK, winsock.WSAEINTR => 0,
                winsock.WSAECONNRESET, winsock.WSAECONNABORTED,
                winsock.WSAESHUTDOWN, winsock.WSAENOTCONN,
                => error.Closed,
                else => error.SendFailed,
            };
        }
        return @as(usize, @intCast(rc));
    }
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

/// One readiness wait over `fds`. Returns ready count.
/// `timeout_ms < 0` blocks indefinitely, `0` returns immediately.
/// (`std.posix.poll` already retries internally on EINTR.)
pub fn pollOnce(fds: []PollFd, timeout_ms: i32) !usize {
    if (comptime is_windows) {
        ensureWsa();
        // Translate into WSAPOLLFD (Winsock's fd is pointer-sized) and
        // copy revents back. Stack temp; the caller already bounds the
        // set (event_loop caps at 4098).
        var wsafds: [4098]winsock.WSAPOLLFD = undefined;
        if (fds.len > wsafds.len) return error.TooManyFds;
        for (fds, 0..) |pfd, i| {
            wsafds[i] = .{
                .fd = socketToUsize(pfd.fd),
                .events = pfd.events,
                .revents = 0,
            };
        }
        const rc = winsock.WSAPoll(
            wsafds[0..].ptr,
            @intCast(fds.len),
            timeout_ms,
        );
        if (rc == winsock.SOCKET_ERROR) return error.PollFailed;
        for (fds, 0..) |*pfd, i| pfd.revents = wsafds[i].revents;
        return @intCast(rc);
    }
    // `PollFd` is layout-identical to `posix.pollfd` — reinterpret.
    const sys_fds: []posix.pollfd = @ptrCast(fds);
    return posix.poll(sys_fds, timeout_ms);
}

/// Fill a `PollFd` for readability (+ errors/hangup always reported).
pub fn pollIn(fd: i32) PollFd {
    return .{ .fd = fd, .events = POLL.IN, .revents = 0 };
}

/// Fill a `PollFd` for readability AND writability.
pub fn pollInOut(fd: i32) PollFd {
    return .{ .fd = fd, .events = POLL.IN | POLL.OUT, .revents = 0 };
}

/// True when `revents` carries an error/hangup/invalid condition.
pub fn isErrorHungup(revents: i16) bool {
    return (revents & (POLL.ERR | POLL.HUP | POLL.NVAL)) != 0;
}

/// A connected socket pair for intra-process wakeups (the pool-mode wake
/// channel). POSIX: `socketpair(AF_UNIX)`. Windows: TCP loopback on
/// 127.0.0.1 (Winsock has no `socketpair`; same approach as
/// `test_helpers.zig:createSocketPair`, but returning raw `i32` SOCKETs).
/// Returns `{ .read, .write }` — both ends are bidirectional; by
/// convention the loop polls `read` and workers write `write`.
pub fn socketPair() !struct { read: i32, write: i32 } {
    if (comptime is_windows) {
        ensureWsa();
        const AF_INET: c_int = 2;
        const SOCK_STREAM: c_int = 1;
        const IPPROTO_TCP: c_int = 6;

        const server_raw = winsock.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_raw < 0) return error.SocketPairFailed;
        errdefer _ = winsock.closesocket(server_raw);

        // sockaddr_in for 127.0.0.1:0 (port 0 = OS picks). Layout matches
        // Winsock's sockaddr_in; 127.0.0.1 in LE-u32 form is 0x0100007f
        // (same value `Address.parseHostLe` produces).
        var addr: std.c.sockaddr.in = .{
            .family = std.c.AF.INET,
            .port = 0,
            .addr = 0x0100007f,
            .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        if (winsock.bind(server_raw, std.mem.asBytes(&addr), @sizeOf(std.c.sockaddr.in)) != 0)
            return error.SocketPairFailed;
        if (winsock.listen(server_raw, 1) != 0)
            return error.SocketPairFailed;

        var bound_addr: std.c.sockaddr.in = undefined;
        var bound_len: c_int = @sizeOf(std.c.sockaddr.in);
        if (winsock.getsockname(server_raw, std.mem.asBytes(&bound_addr), (&bound_len)[0..1].ptr) != 0)
            return error.SocketPairFailed;

        const client_raw = winsock.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client_raw < 0) return error.SocketPairFailed;
        errdefer _ = winsock.closesocket(client_raw);

        var connect_addr: std.c.sockaddr.in = .{
            .family = std.c.AF.INET,
            .port = bound_addr.port, // network byte order, as discovered
            .addr = 0x0100007f,
            .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        if (winsock.connect(client_raw, std.mem.asBytes(&connect_addr), @sizeOf(std.c.sockaddr.in)) != 0)
            return error.SocketPairFailed;

        const accepted_raw = winsock.accept(server_raw, null, null);
        if (accepted_raw < 0) return error.SocketPairFailed;
        _ = winsock.closesocket(server_raw);

        try setNonBlocking(client_raw);
        try setNonBlocking(accepted_raw);
        return .{ .read = accepted_raw, .write = client_raw };
    }
    var fds: [2]std.c.fd_t = undefined;
    if (posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds) < 0)
        return error.SocketPairFailed;
    const read: i32 = @intCast(fds[0]);
    const write: i32 = @intCast(fds[1]);
    errdefer {
        _ = posix.system.close(read);
        _ = posix.system.close(write);
    }
    try setNonBlocking(read);
    try setNonBlocking(write);
    return .{ .read = read, .write = write };
}

/// Bind + listen a REUSEPORT listener on `host_le:port` (multi-loop).
///
/// Each loop thread calls this with the SAME ip:port; the kernel
/// load-balances accepts across them (Linux `SO_REUSEPORT`, same option
/// on macOS/BSD). `host_le` is the little-endian u32 layout from
/// `http_server.Address.parseHostLe` (e.g. 127.0.0.1 → 0x0100007f).
/// The returned fd is blocking; the loop sets non-blocking on entry.
///
/// POSIX-only: Windows has no `SO_REUSEPORT` equivalent, so multi-loop
/// stays POSIX and this returns `error.Unsupported` there.
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
