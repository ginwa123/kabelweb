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

test {
    _ = @import("connection_reader_test.zig");
}
