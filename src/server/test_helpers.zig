// src/server/test_helpers.zig
//
// Cross-platform test helpers for the kabelweb server test suite.
// Tests that need to create connected socket pairs, cast fd_t → i32
// for the production API, or call Windows-only kernel32/winsock
// functions get their primitives from here so the per-file
// duplication stays minimal.
//
// All OS branches are gated with `comptime if` so the runtime path
// for Linux/macOS is bit-identical to the prior POSIX code — no
// behavioral change on those platforms.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

/// Windows-only externs. Both `kernel32` and `ws2_32` import libraries
/// ARE shipped with Zig's MinGW toolchain, so these just-work without
/// extra `linkSystemLibrary` calls.
const win = if (builtin.os.tag == .windows) struct {
    // kernel32 — anonymous-pipe primitive (kept for backwards compat
    // even though createSocketPair() now uses TCP loopback; some
    // callers may still want a unidirectional pipe).
    extern "kernel32" fn CreatePipe(
        hReadPipe: ?*std.os.windows.HANDLE,
        hWritePipe: ?*std.os.windows.HANDLE,
        lpPipeAttributes: ?*anyopaque,
        nSize: c_uint,
    ) callconv(.winapi) c_int;

    // ws2_32 — Winsock 2.2 primitives used by the TCP-loopback
    // socketpair implementation. SOCKET (winsock) is c_int-returning;
    // the kernel32 HANDLE is pointer-sized and we get it back via
    // `@ptrFromInt(fd_raw)`. Returns `INVALID_SOCKET` (= -1 cast
    // through c_int, ~0usize when cast back to pointer) on failure.
    extern "ws2_32" fn WSAStartup(
        wVersionRequested: c_ushort,
        wsaData: *WSADATA,
    ) callconv(.c) c_int;
    extern "ws2_32" fn socket(
        domain: c_uint,
        sock_type: c_uint,
        protocol: c_uint,
    ) callconv(.c) c_int;
    extern "ws2_32" fn bind(
        sockfd: c_int,
        addr: [*]const u8,
        addrlen: c_int,
    ) callconv(.c) c_int;
    extern "ws2_32" fn listen(
        sockfd: c_int,
        backlog: c_int,
    ) callconv(.c) c_int;
    extern "ws2_32" fn accept(
        sockfd: c_int,
        addr: ?[*]u8,
        addrlen: ?[*]c_int,
    ) callconv(.c) c_int;
    extern "ws2_32" fn connect(
        sockfd: c_int,
        addr: [*]const u8,
        addrlen: c_int,
    ) callconv(.c) c_int;
    extern "ws2_32" fn getsockname(
        sockfd: c_int,
        addr: [*]u8,
        addrlen: [*]c_int,
    ) callconv(.c) c_int;
    extern "ws2_32" fn closesocket(sockfd: c_int) callconv(.c) c_int;
    extern "ws2_32" fn send(
        sockfd: c_int,
        buf: ?*const anyopaque,
        len: c_int,
        flags: c_int,
    ) callconv(.c) c_int;
    extern "ws2_32" fn recv(
        sockfd: c_int,
        buf: [*]u8,
        len: c_int,
        flags: c_int,
    ) callconv(.c) c_int;
    extern "ws2_32" fn shutdown(sockfd: c_int, how: c_int) callconv(.c) c_int;

    /// WSADATA struct passed to WSAStartup. 400 bytes is the canonical
    /// size per Winsock 2 docs; the contents are intentionally ignored
    /// (we just need the call to succeed so the winsock runtime is
    /// available for subsequent socket() calls).
    const WSADATA = [400]u8;

    /// Lazy-init guard for WSAStartup. The winsock runtime ref-counts
    /// startup calls, so calling it on every test fixture creation is
    /// safe; the underlying DLL is only loaded once. We guard with an
    /// atomic just to avoid the (cheap) syscall in the common case.
    var wsa_init_lock: std.atomic.Mutex = .unlocked;
    var wsa_initialized: bool = false;

    fn ensureWinsockInitialized() void {
        if (wsa_initialized) return;
        while (!wsa_init_lock.tryLock()) std.atomic.spinLoopHint();
        defer wsa_init_lock.unlock();
        if (wsa_initialized) return;
        var wsa_data: WSADATA = undefined;
        // MAKEWORD(2, 2) = 0x0202 — request Winsock 2.2 (highest version
        // every Windows since Windows 98 supports).
        const version: c_ushort = (2 << 8) | 2;
        _ = WSAStartup(version, &wsa_data);
        wsa_initialized = true;
    }

    /// Wrap a winsock SOCKET (c_int) as a std.c.fd_t (= *anyopaque on
    /// Windows). The SOCKET handle value is sign-extended into a
    /// pointer so the production code can treat it as the
    /// "opaque Windows HANDLE" fd_t shape; winsock.send / winsock.recv
    /// accept c_int (the original SOCKET value), so the production
    /// path @ptrFromInt → @intFromPtr round-trip recovers the exact
    /// SOCKET value with no precision loss (Windows HANDLE values are
    /// always sign-extended small ints, so c_int → pointer preserves
    /// all 32 bits).
    fn socketToFdT(sock: c_int) std.c.fd_t {
        return @ptrFromInt(@as(usize, @bitCast(@as(isize, sock))));
    }
} else struct {};

/// Create a pair of connected fds for tests. Cross-platform:
/// socketpair(AF_UNIX, SOCK_STREAM) on POSIX; TCP loopback (127.0.0.1)
/// on Windows because Winsock lacks `socketpair(2)` and CreatePipe
/// HANDLEs are NOT registered with UCRT — which means std.c.write
/// (used by the production `sse_manager.writeChunkedFrame` code path)
/// silently fails on them. The production `sendAll` Windows path uses
/// `winsock.send` (a Winsock 2 API), which works on the raw SOCKET
/// handle value without any UCRT registration.
///
/// Returns `[2]std.c.fd_t` — `i32` on POSIX, `*anyopaque` (Winsock
/// SOCKET wrapped via @ptrFromInt) on Windows. Tests that need to
/// pass these into the production SseManager API (which still takes
/// `i32` everywhere) cast via `toI32` below.
///
/// Convention: `fds[0]` is the WRITE end (write here, read from the
/// other side); `fds[1]` is the READ end. POSIX socketpair returns
/// bidirectional sockets so the convention is enforced by the caller;
/// the Windows TCP loopback returns two bidirectional sockets in the
/// order [client, accepted], so we return them in that order to match
/// the POSIX convention of "first fd = side you write to".
pub fn createSocketPair() ![2]std.c.fd_t {
    if (comptime builtin.os.tag == .windows) {
        win.ensureWinsockInitialized();

        const AF_INET: c_uint = 2;
        const SOCK_STREAM: c_uint = 1;
        const IPPROTO_TCP: c_uint = 6;

        // Create the server (listening) socket.
        const server_raw = win.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        // INVALID_SOCKET == (SOCKET)(-1) == maxInt(usize) when cast to
        // pointer. Compare via the SOCKET pointer representation (same
        // pattern as http_server.zig's createSocket()).
        if (@intFromPtr(@as(std.os.windows.HANDLE, @ptrFromInt(@as(usize, @bitCast(@as(isize, server_raw)))))) == std.math.maxInt(usize))
            return error.SocketPairFailed;
        errdefer _ = win.closesocket(server_raw);

        // sockaddr_in for 127.0.0.1:0 (port 0 = let OS pick). The
        // struct layout matches Winsock's sockaddr_in: family(u16),
        // port(u16, network byte order), addr(u32, in LE u32 layout
        // = wire bytes 127,0,0,1), zero([8]u8). 127.0.0.1 in the LE
        // u32 representation is 0x0100007f (matches the
        // parseHostLe("127.0.0.1") value used by http_server.zig).
        var addr: std.c.sockaddr.in = .{
            .family = std.c.AF.INET,
            .port = 0, // let OS pick
            .addr = 0x0100007f,
            .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        if (win.bind(server_raw, std.mem.asBytes(&addr), @sizeOf(std.c.sockaddr.in)) != 0)
            return error.SocketPairFailed;
        if (win.listen(server_raw, 1) != 0) // backlog 1 is enough for one accept
            return error.SocketPairFailed;

        // Discover the OS-assigned port via getsockname.
        var bound_addr: std.c.sockaddr.in = undefined;
        var bound_len: c_int = @sizeOf(std.c.sockaddr.in);
        if (win.getsockname(server_raw, std.mem.asBytes(&bound_addr), (&bound_len)[0..1].ptr) != 0)
            return error.SocketPairFailed;
        const port_be = bound_addr.port; // network byte order (big-endian)

        // Create the client socket and connect to the listening port.
        const client_raw = win.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (@intFromPtr(@as(std.os.windows.HANDLE, @ptrFromInt(@as(usize, @bitCast(@as(isize, client_raw)))))) == std.math.maxInt(usize))
            return error.SocketPairFailed;
        errdefer _ = win.closesocket(client_raw);

        var connect_addr: std.c.sockaddr.in = .{
            .family = std.c.AF.INET,
            .port = port_be,
            .addr = 0x0100007f,
            .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        if (win.connect(client_raw, std.mem.asBytes(&connect_addr), @sizeOf(std.c.sockaddr.in)) != 0)
            return error.SocketPairFailed;

        // Accept on the server socket — blocks until the connect above
        // completes (which it already has by this point).
        const accepted_raw = win.accept(server_raw, null, null);
        if (@intFromPtr(@as(std.os.windows.HANDLE, @ptrFromInt(@as(usize, @bitCast(@as(isize, accepted_raw)))))) == std.math.maxInt(usize))
            return error.SocketPairFailed;

        // The listening socket is no longer needed; close it so the
        // OS holds no extra fds for the test.
        _ = win.closesocket(server_raw);

        // Wrap each connected SOCKET as a std.c.fd_t. The production
        // sse_manager Windows path uses winsock.send(fd, ...) which
        // takes c_int — the test casts back via `toI32` which
        // @intFromPtr's the fd_t and recovers the original SOCKET
        // value bit-for-bit.
        const client_fd = win.socketToFdT(client_raw);
        const accepted_fd = win.socketToFdT(accepted_raw);

        return [2]std.c.fd_t{ client_fd, accepted_fd };
    } else {
        var fds: [2]std.c.fd_t = undefined;
        const rc = posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
        if (rc < 0) return error.SocketFailed;
        return fds;
    }
}

/// Close both ends of a pair created by createSocketPair. Cross-platform:
/// POSIX `close` on Linux/macOS, Winsock `closesocket` on Windows.
/// `std.c.close` does NOT work on raw winsock SOCKETs (UCRT's
/// `_close()` is for fd-table entries, not SOCKETs).
pub fn closeSocketPair(pair: [2]std.c.fd_t) void {
    if (comptime builtin.os.tag == .windows) {
        _ = win.closesocket(toI32(pair[0]));
        _ = win.closesocket(toI32(pair[1]));
    } else {
        _ = std.c.close(pair[0]);
        _ = std.c.close(pair[1]);
    }
}

/// Read from a test socketpair end (both platforms). Returns bytes read,
/// 0 on orderly shutdown, -1 on error. On Windows the pair ends are raw
/// winsock SOCKETs — CRT `read()` doesn't work on them (it returns an
/// error without touching the buffer, which surfaces downstream as
/// inexplicable content mismatches), so use winsock.recv there.
pub fn readTestFd(fd: std.c.fd_t, buf: []u8) isize {
    if (comptime builtin.os.tag == .windows) {
        return win.recv(toI32(fd), buf.ptr, @intCast(buf.len), 0);
    } else {
        return std.c.read(fd, buf.ptr, buf.len);
    }
}

/// Read exactly `buf.len` bytes from a test socketpair end, looping on
/// short reads (TCP loopback pairs return partial reads). Returns
/// error.ReadFailed on EOF-before-full or any read error.
pub fn readTestFdFull(fd: std.c.fd_t, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = readTestFd(fd, buf[off..]);
        if (n <= 0) return error.ReadFailed;
        off += @as(usize, @intCast(n));
    }
}

/// Write all of `data` to a test socketpair end, looping on short
/// writes (TCP loopback pairs on Windows return partial sends; a
/// single-shot write silently truncates). Returns error.WriteFailed
/// on any send error.
pub fn writeTestFdAll(fd: std.c.fd_t, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n: isize = if (comptime builtin.os.tag == .windows)
            win.send(toI32(fd), data.ptr + off, @intCast(data.len - off), 0)
        else
            std.c.write(fd, data.ptr + off, data.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @as(usize, @intCast(n));
    }
}

/// Close one end of a test socketpair (both platforms). Prefer this
/// over bare `std.c.close` in tests — on Windows only closesocket()
/// actually releases a SOCKET (CRT close silently succeeds without
/// closing, leaving the peer connected and the next test's assertions
/// observing a live socket).
pub fn closeTestFd(fd: std.c.fd_t) void {
    if (comptime builtin.os.tag == .windows) {
        _ = win.closesocket(toI32(fd));
    } else {
        _ = std.c.close(fd);
    }
}

/// Cast an fd_t to the i32 that the production SseManager API still
/// expects. On Linux/macOS this is a no-op (fd_t is i32). On Windows
/// the winsock SOCKET was wrapped as fd_t via @ptrFromInt, so
/// @intFromPtr reverses that and @intCast narrows to i32. The
/// round-trip is bit-exact because Windows HANDLE values are
/// sign-extended small ints (always < 2^31).
pub fn toI32(fd: std.c.fd_t) i32 {
    if (comptime builtin.os.tag == .windows) {
        return @intCast(@intFromPtr(fd));
    } else {
        return @intCast(fd);
    }
}

/// Close an fd with cross-platform handling. Use this for sock_fds
/// from `Address.init` (which is `SocketFd = i32`) instead of
/// `std.c.close(addr.sock_fd)` directly — std.c.close on Windows takes
/// fd_t (= *anyopaque) and a plain i32 wouldn't compile.
///
/// On Linux/macOS this is a no-op cast; on Windows it wraps the
/// small integer into the fd_t pointer type via @ptrFromInt + bitCast
/// AND routes to closesocket() (the winsock API for SOCKETs), since
/// std.c.close doesn't work on raw winsock SOCKETs (UCRT doesn't
/// index them).
pub fn closeI32Fd(fd: i32) void {
    if (comptime builtin.os.tag == .windows) {
        _ = win.closesocket(fd);
    } else {
        _ = std.c.close(@intCast(fd));
    }
}
