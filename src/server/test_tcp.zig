//! Cross-platform TCP helpers for event-loop tests (POSIX + Windows).
//!
//! The loopback tests need real `socket/bind/listen/connect/read/write`
//! on both families. POSIX uses raw `posix.system` syscalls (same shape
//! as `http_server.zig:Address`); Windows uses Winsock directly (same
//! declaration style as `test_helpers.zig` — production fds stay `i32`
//! SOCKET values, `ws2_32` links via Zig's shipped import libs).
//!
//! Test-only: production code must use `nb_socket.zig`.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const is_windows = builtin.os.tag == .windows;

const ws = if (is_windows) struct {
    extern "ws2_32" fn WSAStartup(wVersionRequested: c_ushort, wsaData: *WSADATA) callconv(.c) c_int;
    extern "ws2_32" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) callconv(.c) c_int;
    extern "ws2_32" fn bind(sockfd: c_int, addr: [*]const u8, addrlen: c_int) callconv(.c) c_int;
    extern "ws2_32" fn listen(sockfd: c_int, backlog: c_int) callconv(.c) c_int;
    extern "ws2_32" fn connect(sockfd: c_int, addr: [*]const u8, addrlen: c_int) callconv(.c) c_int;
    extern "ws2_32" fn getsockname(sockfd: c_int, addr: [*]u8, addrlen: [*]c_int) callconv(.c) c_int;
    extern "ws2_32" fn closesocket(sockfd: c_int) callconv(.c) c_int;
    extern "ws2_32" fn recv(sockfd: c_int, buf: [*]u8, len: c_int, flags: c_int) callconv(.c) c_int;
    extern "ws2_32" fn send(sockfd: c_int, buf: ?*const anyopaque, len: c_int, flags: c_int) callconv(.c) c_int;

    const WSADATA = [400]u8;

    var init_lock: std.atomic.Mutex = .unlocked;
    var initialized: bool = false;

    fn ensure() void {
        if (initialized) return;
        while (!init_lock.tryLock()) std.atomic.spinLoopHint();
        defer init_lock.unlock();
        if (initialized) return;
        var data: WSADATA = undefined;
        _ = WSAStartup(0x0202, &data); // MAKEWORD(2, 2)
        initialized = true;
    }
} else struct {};

/// 127.0.0.1 in LE-u32 form (matches `Address.parseHostLe`).
pub const loopback_le: u32 = 0x0100007f;

/// Bind 127.0.0.1:0 + listen. Returns the listener and the OS-picked port.
pub fn listenEphemeral() !struct { fd: i32, port: u16 } {
    if (comptime is_windows) {
        ws.ensure();
        const fd = ws.socket(2, 1, 6); // AF_INET, SOCK_STREAM, IPPROTO_TCP
        if (fd < 0) return error.SocketFailed;
        errdefer _ = ws.closesocket(fd);
        var addr: std.c.sockaddr.in = .{
            .family = std.c.AF.INET,
            .port = 0,
            .addr = loopback_le,
            .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        if (ws.bind(fd, std.mem.asBytes(&addr), @sizeOf(std.c.sockaddr.in)) != 0)
            return error.BindFailed;
        if (ws.listen(fd, 16) != 0) return error.ListenFailed;
        return .{ .fd = fd, .port = try boundPort(fd) };
    }
    const sys = posix.system;
    const raw = sys.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    if (raw < 0) return error.SocketFailed;
    const fd: i32 = @intCast(raw);
    errdefer _ = sys.close(fd);
    const opt: i32 = 1;
    try posix.setsockopt(
        fd,
        @intCast(posix.SOL.SOCKET),
        @intCast(posix.SO.REUSEADDR),
        std.mem.asBytes(&opt),
    );
    var addr: sys.sockaddr.in = .{
        .family = 2,
        .port = 0,
        .addr = @bitCast(loopback_le),
        .zero = undefined,
    };
    if (sys.bind(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in)) < 0)
        return error.BindFailed;
    if (sys.listen(fd, 16) < 0) return error.ListenFailed;
    return .{ .fd = fd, .port = try boundPort(fd) };
}

/// The local port a bound socket ended up on (ephemeral discovery).
pub fn boundPort(fd: i32) !u16 {
    if (comptime is_windows) {
        ws.ensure();
        var addr: std.c.sockaddr.in = undefined;
        var len: c_int = @sizeOf(std.c.sockaddr.in);
        if (ws.getsockname(fd, std.mem.asBytes(&addr), (&len)[0..1].ptr) != 0)
            return error.GetSockNameFailed;
        if (addr.port == 0) return error.GetSockNameFailed;
        return @byteSwap(addr.port);
    }
    const sys = posix.system;
    var addr: sys.sockaddr.in = undefined;
    var len: posix.socklen_t = @sizeOf(sys.sockaddr.in);
    if (sys.getsockname(fd, @ptrCast(&addr), &len) != 0)
        return error.GetSockNameFailed;
    const port: u16 = @byteSwap(addr.port);
    if (port == 0) return error.GetSockNameFailed;
    return port;
}

/// Blocking connect to 127.0.0.1:port.
pub fn connect(port: u16) !i32 {
    if (comptime is_windows) {
        ws.ensure();
        const fd = ws.socket(2, 1, 6);
        if (fd < 0) return error.SocketFailed;
        errdefer _ = ws.closesocket(fd);
        var addr: std.c.sockaddr.in = .{
            .family = std.c.AF.INET,
            .port = @byteSwap(port),
            .addr = loopback_le,
            .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        if (ws.connect(fd, std.mem.asBytes(&addr), @sizeOf(std.c.sockaddr.in)) != 0)
            return error.ConnectFailed;
        return fd;
    }
    const sys = posix.system;
    const raw = sys.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    if (raw < 0) return error.SocketFailed;
    const fd: i32 = @intCast(raw);
    errdefer _ = sys.close(fd);
    var addr: sys.sockaddr.in = .{
        .family = 2,
        .port = @byteSwap(port),
        .addr = @bitCast(loopback_le),
        .zero = undefined,
    };
    if (sys.connect(fd, @ptrCast(&addr), @sizeOf(sys.sockaddr.in)) != 0)
        return error.ConnectFailed;
    return fd;
}

/// One blocking read. Returns bytes placed in `buf`, `0` on orderly EOF.
pub fn read(fd: i32, buf: []u8) !usize {
    if (buf.len == 0) return 0;
    if (comptime is_windows) {
        ws.ensure();
        const rc = ws.recv(fd, buf.ptr, @intCast(buf.len), 0);
        if (rc < 0) return error.ReadFailed;
        return @intCast(rc);
    }
    const n: isize = posix.system.read(fd, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    return @intCast(n);
}

/// Blocking write of the full slice (loops on short sends).
pub fn writeAll(fd: i32, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        if (comptime is_windows) {
            ws.ensure();
            const rc = ws.send(fd, data.ptr + off, @intCast(data.len - off), 0);
            if (rc <= 0) return error.WriteFailed;
            off += @intCast(rc);
        } else {
            const n: isize = posix.system.write(fd, data.ptr + off, data.len - off);
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }
}

/// Close one test socket.
pub fn close(fd: i32) void {
    if (comptime is_windows) {
        ws.ensure();
        _ = ws.closesocket(fd);
    } else {
        _ = posix.system.close(fd);
    }
}
