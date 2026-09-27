//! Peekable connection reader.
//!
//! The HTTP/1.1 request reader (`RequestBuffer.readFullRequest`) stops at the
//! FIRST `\r\n\r\n` in the stream. The HTTP/2 connection preface
//! (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) contains one at byte 14, so a server that
//! parses h1 first would consume the preface plus whatever frames arrived in the
//! same TCP segment, and hand them to `parseRequest` as a bogus request body —
//! losing the first SETTINGS/HEADERS frames forever.
//!
//! This type exists to close that hole: read ONE chunk, look at it, and only then
//! decide which codec owns the socket. The buffered bytes are never discarded —
//! either the h2 driver receives them (`buffered`), or the h1 path seeds its
//! `RequestBuffer` with them (`takeBuffered`).
//!
//! The reader is transport-agnostic: it reads through a `Stream` (a plain
//! socket today, a TLS connection once the TLS layer registers its hooks), so
//! the same one-read sniff and handoff serves both the h2c and the TLS path,
//! and the server writes its response back on the very same stream
//! (`stream()`).

const std = @import("std");

/// The transport the reader buffers from (`stream.zig`). Imported privately so
/// this module's public surface stays exactly `init` / `initFd` / `stream` plus
/// the pre-existing members; consumers that need to name the type import
/// `stream.zig` directly.
const Stream = @import("stream.zig").Stream;

/// The h2 preface lives in the protocol constants module; importing it here keeps
/// the sniff and the connection driver reading the same 24 bytes.
const constants = @import("http2/constants.zig");

pub const Error = error{ RecvFailed, OutOfMemory };

pub const ConnectionReader = struct {
    alloc: std.mem.Allocator,
    conn: Stream,
    buf: std.ArrayList(u8) = .empty,
    scratch: [4096]u8 = undefined,

    /// New primary constructor: wrap any transport (`.{ .plain = fd }` for a
    /// raw socket, `.{ .tls = conn }` for a TLS connection).
    ///
    /// NB: the parameter is named `conn`, not `stream` — Zig rejects a
    /// parameter that shadows the sibling `stream()` method (declared below),
    /// and the method name is the frozen part of this API. Positionally this
    /// is `init(alloc, stream)` as documented.
    pub fn init(alloc: std.mem.Allocator, conn: Stream) ConnectionReader {
        return .{ .alloc = alloc, .conn = conn };
    }

    /// Convenience for today's call sites and tests (plain socket).
    pub fn initFd(alloc: std.mem.Allocator, fd: i32) ConnectionReader {
        return .{ .alloc = alloc, .conn = .{ .plain = fd } };
    }

    /// The stream this reader wraps — the server needs it to write the
    /// response (keeping reads and writes on the same transport, which TLS
    /// requires).
    pub fn stream(self: *const ConnectionReader) Stream {
        return self.conn;
    }

    pub fn deinit(self: *ConnectionReader) void {
        self.buf.deinit(self.alloc);
    }

    /// Bytes read so far and not yet handed off.
    pub fn buffered(self: *const ConnectionReader) []const u8 {
        return self.buf.items;
    }

    /// Read once (up to 4 KiB) and return everything buffered so far. Returns an
    /// empty slice at EOF, so callers can tell "closed" from "more to come" via
    /// `buffered().len` on the previous call.
    pub fn fillOnce(self: *ConnectionReader) Error![]const u8 {
        const n = self.conn.read(&self.scratch) catch return error.RecvFailed;
        if (n == 0) return self.buf.items;
        try self.buf.appendSlice(self.alloc, self.scratch[0..n]);
        return self.buf.items;
    }

    /// Read until at least `want` bytes are buffered, or EOF / `max_rounds` is
    /// reached. Used to complete the 24-byte preface before committing to h2.
    pub fn fillAtLeast(self: *ConnectionReader, want: usize, max_rounds: usize) Error!void {
        var rounds: usize = 0;
        while (self.buf.items.len < want and rounds < max_rounds) : (rounds += 1) {
            const before = self.buf.items.len;
            _ = try self.fillOnce();
            if (self.buf.items.len == before) return; // EOF
        }
    }

    /// Hand the buffered bytes to the caller and reset the buffer. Ownership
    /// transfers to the caller (arena-allocated memory is reclaimed wholesale).
    pub fn takeBuffered(self: *ConnectionReader) ![]u8 {
        return self.buf.toOwnedSlice(self.alloc);
    }
};

/// What the first bytes of a connection look like.
pub const Kind = enum {
    /// The complete 24-byte HTTP/2 preface is present — hand the socket to h2.
    h2,
    /// A proper prefix of the preface; more bytes are needed to decide.
    maybe_h2,
    /// Definitely not HTTP/2 — keep the HTTP/1.1 path.
    h1,
};

/// Classify the first bytes of a connection.
///
/// The caller passes whatever a single `recv` returned, which is usually MORE
/// than 24 bytes: a client that uses prior knowledge sends the preface and its
/// SETTINGS frame back-to-back, and curl does exactly that. So the "is this a
/// full preface" test must look at the first 24 bytes, not require the buffer to
/// BE 24 bytes — getting this wrong silently downgrades every real h2 client to
/// HTTP/1.1 (regression: caught by the socket-level functional probe, not by the
/// driver unit tests).
pub fn sniff(bytes: []const u8) Kind {
    if (bytes.len >= constants.preface_len) {
        return if (constants.isPreface(bytes)) .h2 else .h1;
    }
    if (bytes.len == 0) return .h1; // EOF before any byte: nothing to wait for
    return if (constants.isPrefacePrefix(bytes)) .maybe_h2 else .h1;
}

// ============================================================================
// Tests — moved here from `connection_reader_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = connection_reader_tests; }` below pulls them into the run.
// ============================================================================

const connection_reader_tests = struct {
    const builtin = @import("builtin");
    const testing = std.testing;

    const test_helpers = @import("test_helpers.zig");

    /// Write every byte to a socketpair end. Windows needs `send` (its `SOCKET`s are
    /// not indexed by the UCRT fd table, so `write()` fails there); POSIX uses
    /// `write`.
    fn writeAll(fd: i32, bytes: []const u8) !void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n: isize = if (builtin.os.tag == .windows) blk: {
                const winsock = struct {
                    extern "ws2_32" fn send(s: usize, buf: [*]const u8, len: c_int, flags: c_int) c_int;
                };
                break :blk winsock.send(@intCast(fd), bytes.ptr + off, @intCast(bytes.len - off), 0);
            } else blk: {
                const posix_socket = struct {
                    extern "c" fn write(fd: c_int, buf: [*]const u8, nbyte: usize) isize;
                };
                break :blk posix_socket.write(fd, bytes.ptr + off, bytes.len - off);
            };
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }

    // The reader is deliberately thin (a buffer + a socket), so these tests drive it
    // through a real socketpair rather than mocking the fd: the behaviour worth
    // pinning is "what happens to bytes that arrive together with the preface".
    test "sniff: preface plus frames in ONE segment is classified h2" {
        // Regression: a prior-knowledge client (curl included) sends the 24-byte
        // preface and its SETTINGS frame back-to-back, so the first read is usually
        // LONGER than 24 bytes. Requiring an exact-length match silently downgraded
        // every real h2 client to HTTP/1.1.
        const preface = constants.PREFACE;
        const settings_frame = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
        try testing.expectEqual(Kind.h2, sniff(preface ++ settings_frame));
        try testing.expectEqual(Kind.h2, sniff(preface));
        try testing.expectEqual(Kind.h2, sniff(preface ++ "more data than one frame"));
    }

    test "sniff: partial preface waits for more bytes" {
        const preface = constants.PREFACE;
        try testing.expectEqual(Kind.maybe_h2, sniff(preface[0..1]));
        try testing.expectEqual(Kind.maybe_h2, sniff(preface[0..10]));
        try testing.expectEqual(Kind.maybe_h2, sniff(preface[0..23]));
    }

    test "sniff: HTTP/1.1 and junk take the h1 path" {
        try testing.expectEqual(Kind.h1, sniff(""));
        try testing.expectEqual(Kind.h1, sniff("GET / HTTP/1.1\r\n\r\n"));
        try testing.expectEqual(Kind.h1, sniff("\x16\x03\x01\x00\xf5")); // TLS ClientHello
        // Same first byte, diverges at byte 3 → h1, never "maybe".
        try testing.expectEqual(Kind.h1, sniff("PRI * HTTP/1.1\r\n\r\n"));
    }

    test "reader: one fill keeps whole frames that arrive with the preface" {
        const pair = try test_helpers.createSocketPair();
        defer test_helpers.closeSocketPair(pair);
        const peer = test_helpers.toI32(pair[0]);

        const preface_and_settings = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" ++
            "\x00\x00\x00\x04\x00\x00\x00\x00\x00"; // one empty SETTINGS frame
        try writeAll(peer, preface_and_settings);

        // Construct through the new Stream-taking constructor (`.{ .plain = fd }`)
        // rather than `initFd`, so the primary path is exercised too.
        var reader = ConnectionReader.init(testing.allocator, .{ .plain = test_helpers.toI32(pair[1]) });
        defer reader.deinit();
        const got = try reader.fillOnce();

        // Everything the peer sent in one segment is retained — including the bytes
        // AFTER the preface's CRLFCRLF, which the h1 parser would have swallowed.
        try testing.expectEqualStrings(preface_and_settings, got);
        try testing.expect(got.len > 24);
    }

    test "reader: stream() exposes the wrapped plain transport" {
        const pair = try test_helpers.createSocketPair();
        defer test_helpers.closeSocketPair(pair);
        const fd = test_helpers.toI32(pair[1]);

        var reader = ConnectionReader.init(testing.allocator, .{ .plain = fd });
        defer reader.deinit();

        // The server writes the response back on this exact transport, so the
        // accessor must return an equivalent stream (not a copy of an fd it
        // dropped, and not a TLS stream for a plain socket).
        try testing.expect(!reader.stream().isTls());
        try testing.expectEqual(fd, reader.stream().plain);
    }

    test "reader: initFd wraps a plain socket and reads through it" {
        const pair = try test_helpers.createSocketPair();
        defer test_helpers.closeSocketPair(pair);
        try writeAll(test_helpers.toI32(pair[0]), "PING");

        var reader = ConnectionReader.initFd(testing.allocator, test_helpers.toI32(pair[1]));
        defer reader.deinit();

        try testing.expect(!reader.stream().isTls());
        const got = try reader.fillOnce();
        try testing.expectEqualStrings("PING", got);
    }

    test "reader: takeBuffered hands ownership over and empties the buffer" {
        const pair = try test_helpers.createSocketPair();
        defer test_helpers.closeSocketPair(pair);
        try writeAll(test_helpers.toI32(pair[0]), "hello");

        var reader = ConnectionReader.init(testing.allocator, .{ .plain = test_helpers.toI32(pair[1]) });
        defer reader.deinit();
        _ = try reader.fillOnce();

        const owned = try reader.takeBuffered();
        defer testing.allocator.free(owned);
        try testing.expectEqualStrings("hello", owned);
        try testing.expectEqual(@as(usize, 0), reader.buffered().len);
    }

    test "reader: fillAtLeast completes the 24-byte preface across reads" {
        const pair = try test_helpers.createSocketPair();
        defer test_helpers.closeSocketPair(pair);
        const peer = test_helpers.toI32(pair[0]);

        const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        try writeAll(peer, preface[0..10]);

        var reader = ConnectionReader.init(testing.allocator, .{ .plain = test_helpers.toI32(pair[1]) });
        defer reader.deinit();
        _ = try reader.fillOnce();
        try testing.expect(reader.buffered().len < 24);

        try writeAll(peer, preface[10..]);
        try reader.fillAtLeast(24, 4);
        try testing.expectEqual(@as(usize, 24), reader.buffered().len);
    }

    test "reader: EOF is reported as an empty buffer, not an error" {
        const pair = try test_helpers.createSocketPair();
        const peer = test_helpers.toI32(pair[0]);
        const ours = test_helpers.toI32(pair[1]);
        test_helpers.closeI32Fd(peer);

        var reader = ConnectionReader.initFd(testing.allocator, ours);
        defer reader.deinit();
        const got = try reader.fillOnce();
        try testing.expectEqual(@as(usize, 0), got.len);
        test_helpers.closeI32Fd(ours);
    }
};

comptime {
    _ = connection_reader_tests;
}
