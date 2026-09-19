//! Transport abstraction for the HTTP server: a byte stream is either a plain
//! socket (`plain`) or a TLS connection (`tls`).
//!
//! Why a tagged union instead of a vtable: the HTTP/1.1 wire bytes on the plain
//! path must stay IDENTICAL to what the server wrote before this abstraction
//! existed. `plain` therefore stores exactly the `SocketFd` (an `i32`, see
//! `http_server.zig`) the server already passes around, and calls exactly the
//! primitives it called before — `std.posix.system.read` / `write` on POSIX
//! (the same `const socket = posix.system;` handle `http_server.zig`'s
//! `recvFromSock` / `sendToClient` use) and `ws2_32.recv` / `ws2_32.send` on
//! Windows (mirrored verbatim, because Winsock `SOCKET`s are not indexed by the
//! UCRT fd table so libc `read`/`write` fail on them).
//!
//! The TLS arm is deliberately an OPAQUE POINTER plus a table of function
//! pointers (`TlsOps`) registered once at startup. That keeps this file
//! compilable before/without `http2/tls.zig` — no hard module dependency, no
//! import cycle — and keeps the concrete TLS connection type (and its
//! OpenSSL/crypto dependencies) out of the transport contract.
//!
//! `SocketFd` is spelled `i32` directly here rather than importing
//! `http_server.zig`: `http_server.zig` will import THIS file (to route its
//! connections through a `Stream`), so importing back would create a module
//! cycle for no benefit (and `SocketFd` is `i32` there too).

const std = @import("std");
const builtin = @import("builtin");

/// Same handle as `http_server.zig` uses. With libc linked — which the
/// custom_http_server module always does (`server_mod.link_libc = true`,
/// `test_mod.root_module.linkSystemLibrary("c")`) — this resolves to `std.c`,
/// so `read`/`write` return `isize` exactly like the server's current
/// `recvFromSock` / `sendToClient` calls (and the `rc < 0` checks below mean
/// the same thing they mean there).
const socket = std.posix.system;

/// Winsock primitives for Windows. Declarations and parameter types are
/// copied from `http_server.zig` so the plain path issues the same calls with
/// the same ABI. Unreferenced (and unanalysed) on every other OS.
const winsock = if (builtin.os.tag == .windows) struct {
    extern "ws2_32" fn recv(sockfd: c_int, buf: ?*anyopaque, len: c_int, flags: c_int) callconv(.c) c_int;
    extern "ws2_32" fn send(sockfd: c_int, buf: ?*const anyopaque, len: c_int, flags: c_int) callconv(.c) c_int;
    extern "ws2_32" fn closesocket(sockfd: c_int) callconv(.c) c_int;
} else struct {};

/// Registered TLS implementation, `null` until `installTlsOps` runs.
///
/// Deliberately unsynchronized: the contract is "register once, at startup,
/// before any TLS connection is handed out" — so the hot path stays lock-free.
/// Installing twice simply overwrites the previous table.
var tls_ops: ?Stream.TlsOps = null;

/// A byte stream the server can read a request from and write a response to.
/// `plain` is today's path (raw accepted socket); `tls` will be an OpenSSL
/// connection once `http2/tls.zig` lands. The union keeps the HTTP/1.1 wire
/// bytes identical on the plain path — that is a hard requirement, not a
/// nicety.
pub const Stream = union(enum) {
    /// A raw accepted socket. Holds the exact `SocketFd` (`i32`) the server
    /// already carries around, so no wrapping/casting happens on this path.
    /// I/O is raw blocking syscalls — kept for tests, tools, and callers
    /// without an `std.Io`. Production serving uses `conn` below.
    plain: i32,
    /// An Io-driven accepted socket: the same raw fd, but reads/writes go
    /// through `std.Io.net.Stream` so the calling task SUSPENDS instead of
    /// parking its worker thread. This is what makes `Group.async`
    /// (fiber multiplexing over ~ncpu workers) viable: 200 connections no
    /// longer need 200 threads. The fd itself stays blocking — the Io
    /// layer issues per-call `DONTWAIT` recvmmsg-style reads and parks the
    /// fiber until readable.
    conn: Conn,
    /// An established TLS connection, owned by the TLS layer. Opaque here:
    /// this file never looks inside and never names the concrete type.
    tls: *anyopaque,

    /// An accepted socket plus the Io used to drive it. Constructed once
    /// per connection by the accept loop (`server.io`).
    pub const Conn = struct {
        fd: i32,
        io: std.Io,
    };

    /// Register the TLS read/write/close implementations once, at startup
    /// (called by the TLS integration with `tls.Conn`'s functions).
    pub const TlsOps = struct {
        read: *const fn (conn: *anyopaque, buf: []u8) anyerror!usize,
        write_all: *const fn (conn: *anyopaque, bytes: []const u8) anyerror!void,
        close: *const fn (conn: *anyopaque) void,
    };

    /// Read up to `buf.len` bytes. Returns the byte count, where 0 means EOF
    /// (the peer closed) — the same convention `http_server.zig`'s
    /// `recvFromSock` consumers rely on today.
    ///
    /// Plain: the same `read` syscall (POSIX) / `winsock.recv` (Windows) the
    /// server issues today. Conn: the same bytes via `std.Io.net.Stream`,
    /// suspending the calling fiber instead of parking its worker thread
    /// (errors collapse to `error.ReadFailed`, matching plain). TLS:
    /// `TlsOps.read`, or `error.TlsOpsNotInstalled` if no implementation
    /// was registered.
    pub fn read(self: Stream, buf: []u8) !usize {
        switch (self) {
            .plain => |fd| {
                if (comptime builtin.os.tag == .windows) {
                    const rc = winsock.recv(fd, buf.ptr, @intCast(buf.len), 0);
                    if (rc < 0) return error.ReadFailed;
                    return @intCast(rc);
                } else {
                    const rc: isize = socket.read(fd, buf.ptr, buf.len);
                    if (rc < 0) return error.ReadFailed;
                    return @as(usize, @intCast(rc));
                }
            },
            .conn => |c| {
                return readIo(c.fd, c.io, buf) catch return error.ReadFailed;
            },
            .tls => |conn| {
                const ops = tls_ops orelse return error.TlsOpsNotInstalled;
                return ops.read(conn, buf);
            },
        }
    }

    /// Io-driven short read for the `conn` variant. Wraps the raw fd in a
    /// `std.Io.net.Stream` per call (no allocation — the wrapper is two
    /// words; the address field is never inspected on the read path, so it
    /// carries the unspecified address).
    /// `readSliceShort` copies straight into `buf` (no extra copy) and
    /// returns 0 at EOF, matching the plain convention.
    fn readIo(fd: i32, io: std.Io, buf: []u8) !usize {
        const s: std.Io.net.Stream = .{
            .socket = .{
                .handle = fd,
                .address = unspecifiedAddress(),
            },
        };
        var scratch: [256]u8 = undefined;
        var r = s.reader(io, &scratch);
        return try r.interface.readSliceShort(buf);
    }

    /// Placeholder peer address for Io-wrapped accepted sockets. Only the
    /// fd `handle` is ever used by the read/write/close paths; the server
    /// never reports the peer address through this wrapper.
    fn unspecifiedAddress() std.Io.net.IpAddress {
        return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
    }

    /// Write every byte of `bytes`, looping until the whole slice is out (a
    /// single `write`/`send` may accept only part of a large payload).
    ///
    /// Plain: the same `write` (POSIX) / `winsock.send` (Windows) primitive
    /// `sendToClient` uses. A 0-byte result is treated as a failure so a
    /// stalled peer can never spin this loop forever. Conn: buffered
    /// Io-driven send (suspends instead of parking; flushed before
    /// return). TLS: `TlsOps.write_all`, or `error.TlsOpsNotInstalled`.
    pub fn writeAll(self: Stream, bytes: []const u8) !void {
        switch (self) {
            .plain => |fd| {
                var off: usize = 0;
                while (off < bytes.len) {
                    if (comptime builtin.os.tag == .windows) {
                        const rc = winsock.send(fd, bytes.ptr + off, @intCast(bytes.len - off), 0);
                        if (rc <= 0) return error.WriteFailed;
                        off += @intCast(rc);
                    } else {
                        const rc: isize = socket.write(fd, bytes.ptr + off, bytes.len - off);
                        if (rc <= 0) return error.WriteFailed;
                        off += @as(usize, @intCast(rc));
                    }
                }
            },
            .conn => |c| {
                try writeAllIo(c.fd, c.io, bytes);
            },
            .tls => |conn| {
                const ops = tls_ops orelse return error.TlsOpsNotInstalled;
                try ops.write_all(conn, bytes);
            },
        }
    }

    /// Io-driven send for the `conn` variant. Buffered through a 4 KiB
    /// stack scratch (one send syscall for typical responses) and always
    /// flushed, so bytes are on the wire at return — same guarantee as
    /// the plain loop.
    fn writeAllIo(fd: i32, io: std.Io, bytes: []const u8) !void {
        const s: std.Io.net.Stream = .{
            .socket = .{
                .handle = fd,
                .address = unspecifiedAddress(),
            },
        };
        var scratch: [4096]u8 = undefined;
        var w = s.writer(io, &scratch);
        try w.interface.writeAll(bytes);
        try w.interface.flush();
    }

    /// Close the underlying transport.
    ///
    /// Plain closes the fd (`closesocket` on Windows, `close(2)` elsewhere —
    /// the same pair `http_server.zig`'s `closeFd` uses). TLS calls the
    /// registered close hook; if no implementation is registered this is a
    /// no-op (the signature returns `void`, so it cannot report an error).
    pub fn close(self: Stream) void {
        switch (self) {
            .plain => |fd| {
                if (comptime builtin.os.tag == .windows) {
                    _ = winsock.closesocket(fd);
                } else {
                    _ = socket.close(fd);
                }
            },
            // Same fd lifetime as plain; closing never blocks, so the raw
            // primitive is correct here (no Io round-trip needed).
            .conn => |c| {
                if (comptime builtin.os.tag == .windows) {
                    _ = winsock.closesocket(c.fd);
                } else {
                    _ = socket.close(c.fd);
                }
            },
            .tls => |conn| {
                if (tls_ops) |ops| ops.close(conn);
            },
        }
    }

    /// True when this stream is TLS-backed. Cheap discriminator for callers
    /// that need to know (scheme reporting, TLS-only features).
    pub fn isTls(self: Stream) bool {
        return switch (self) {
            .plain => false,
            .conn => false,
            .tls => true,
        };
    }

    /// Register the TLS read/write/close implementations once, at startup
    /// (called by the TLS integration with `tls.Conn`'s functions).
    pub fn installTlsOps(ops: TlsOps) void {
        tls_ops = ops;
    }

    /// Clear the registered table (the inverse of `installTlsOps`).
    ///
    /// Not in the frozen interface; added so the `TlsOpsNotInstalled` behaviour
    /// is testable deterministically (and so a shutdown path can drop the
    /// table) regardless of test-runner ordering.
    pub fn uninstallTlsOps() void {
        tls_ops = null;
    }
};

test {
    _ = @import("stream_test.zig");
}
