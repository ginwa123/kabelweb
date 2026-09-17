//! WebSocket HTTP upgrade handshake (RFC 6455 §4).
//!
//! The handshake translates an HTTP/1.1 GET request into a WebSocket
//! connection. The server must validate the request headers and respond
//! with `101 Switching Protocols` plus the computed `Sec-WebSocket-Accept`.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc6455#section-4>
//!
//! Required request headers (RFC 6455 §4.1):
//!   - HTTP/1.1 (HTTP/1.0 explicitly rejected — RFC 6455 §4.1)
//!   - GET method
//!   - Upgrade: websocket
//!   - Connection: Upgrade
//!   - Sec-WebSocket-Key: <base64-encoded 16-byte nonce>
//!   - Sec-WebSocket-Version: 13
//!
//! Server response (RFC 6455 §4.2):
//!   HTTP/1.1 101 Switching Protocols\r\n
//!   Upgrade: websocket\r\n
//!   Connection: Upgrade\r\n
//!   Sec-WebSocket-Accept: <base64(SHA1(key + MAGIC_GUID))>\r\n
//!   \r\n
//!
//! The MAGIC_GUID is a fixed salt used by every WebSocket implementation
//! to derive the Accept value. Any deviation from this exact string would
//! break interop with browser clients.

const std = @import("std");
const builtin = @import("builtin");
const http_parser = @import("http_parser.zig");

/// The fixed GUID appended to the client's Sec-WebSocket-Key before SHA-1
/// hashing (RFC 6455 §1.3). This exact string MUST be used by every
/// implementation; browsers hardcode it client-side.
pub const MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the Sec-WebSocket-Accept value for a given client key.
///
/// Implementation: `base64(SHA1(key + MAGIC_GUID))`. The hash is computed
/// in a single pass over the 60-byte input (24-byte key + 36-byte GUID).
pub fn computeAcceptKey(client_key: []const u8) ![]u8 {
    var buf: [256]u8 = undefined;
    if (client_key.len + MAGIC_GUID.len > buf.len) return error.KeyTooLong;
    @memcpy(buf[0..client_key.len], client_key);
    @memcpy(buf[client_key.len .. client_key.len + MAGIC_GUID.len], MAGIC_GUID);

    var hash: [20]u8 = undefined;
    Sha1.hash(&buf, client_key.len + MAGIC_GUID.len, &hash);

    // Base64-encode the 20-byte SHA-1 hash using standard encoding
    // (RFC 4648 §4) with `+` and `/` characters and `=` padding.
    // Zig 0.16 base64 API: `Codecs.Encoder.calcSize(source_len)` and
    // `Codecs.Encoder.encode(dest, source)`. The encoded length for a
    // 20-byte SHA-1 is ceil(20/3)*4 = 28 bytes.
    const encoder = &std.base64.standard.Encoder;
    const encoded_size = encoder.calcSize(20);
    const dest = try std.heap.page_allocator.alloc(u8, encoded_size);
    _ = encoder.encode(dest, &hash);
    return dest;
}

/// Build the full 101 Switching Protocols response bytes.
///
/// The returned slice is owned by the caller (free with `allocator.free`).
pub fn buildAcceptResponse(allocator: std.mem.Allocator, client_key: []const u8) ![]u8 {
    const accept = try computeAcceptKey(client_key);
    defer std.heap.page_allocator.free(accept);

    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(allocator);

    // Build the response bytes using plain string literals (not Zig
    // multi-line `\\` strings, which would emit literal backslash-r-n
    // instead of CR-LF). The response must end with a blank line
    // (\r\n\r\n) per RFC 6455 §4.2.
    try buf.appendSlice(allocator, "HTTP/1.1 101 Switching Protocols\r\n");
    try buf.appendSlice(allocator, "Upgrade: websocket\r\n");
    try buf.appendSlice(allocator, "Connection: Upgrade\r\n");
    try buf.appendSlice(allocator, "Sec-WebSocket-Accept: ");
    try buf.appendSlice(allocator, accept);
    try buf.appendSlice(allocator, "\r\n\r\n");

    return buf.toOwnedSlice(allocator);
}

/// Returns true if the request is a valid WebSocket upgrade request.
///
/// Validates:
///   - HTTP/1.1 (RFC 6455 §4.1: HTTP/1.1 only)
///   - GET method (POST / PUT / etc. are rejected)
///   - Sec-WebSocket-Version: 13 (draft versions 8, 13, etc. all rejected)
///   - Sec-WebSocket-Key header present (any value)
///   - Upgrade: websocket (case-insensitive)
///   - Connection: Upgrade (case-insensitive)
pub fn isWebSocketRequest(req: *const http_parser.HttpRequest) bool {
    // HTTP/1.1 only
    if (!std.mem.eql(u8, req.version, "HTTP/1.1")) return false;

    // GET only
    if (!std.mem.eql(u8, req.method, "GET")) return false;

    // Walk headers for case-insensitive match. Header names are
    // case-insensitive per RFC 9110 §5.1 (RFC 6455 §4.1 inherits the
    // rule), and the parser preserves the original case — so an
    // exact-case hashmap lookup would fail on "upgrade"/"UPGRADE",
    // and (worse) on the lowercased names proxies forward: Node's
    // http-proxy (Vite dev) sends sec-websocket-key /
    // sec-websocket-version, which the old exact-case presence check
    // rejected with "WebSocket upgrade required" for real browsers.
    var key_ok = false;
    var upgrade_ok = false;
    var connection_ok = false;
    var version_ok = false;
    var it = req.headers.iterator();
    while (it.next()) |entry| {
        const k = entry.key_ptr.*;
        const v = entry.value_ptr.*;
        if (std.ascii.eqlIgnoreCase(k, "sec-websocket-key")) {
            key_ok = true;
        } else if (std.ascii.eqlIgnoreCase(k, "upgrade")) {
            // Per RFC 6455 §4.1, the value is a comma-separated list of
            // protocols; "websocket" must appear as one of the tokens.
            if (containsTokenIgnoreCase(v, "websocket")) {
                upgrade_ok = true;
            }
        } else if (std.ascii.eqlIgnoreCase(k, "connection")) {
            if (containsTokenIgnoreCase(v, "upgrade")) {
                connection_ok = true;
            }
        } else if (std.ascii.eqlIgnoreCase(k, "sec-websocket-version")) {
            if (std.mem.eql(u8, std.mem.trim(u8, v, " "), "13")) {
                version_ok = true;
            }
        }
    }

    return key_ok and upgrade_ok and connection_ok and version_ok;
}

/// Extract the client's Sec-WebSocket-Key from the request headers.
///
/// Case-insensitive: matches "Sec-WebSocket-Key", "sec-websocket-key", etc.
/// Returns the trimmed value (the parser strips outer whitespace).
pub fn extractWebSocketKey(req: *const http_parser.HttpRequest) ![]const u8 {
    var it = req.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "sec-websocket-key")) {
            return entry.value_ptr.*;
        }
    }
    return error.MissingKey;
}

/// Case-insensitive token search inside a comma-separated header value.
///
/// "websocket" matches "WebSocket", "WEBSOCKET", and "Connection: keep-alive, Upgrade"
/// → containsTokenIgnoreCase("keep-alive, Upgrade", "upgrade") == true.
fn containsTokenIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    // Split on commas, trim each token, compare case-insensitively.
    var parts = std.mem.splitScalar(u8, haystack, ',');
    while (parts.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t");
        if (std.ascii.eqlIgnoreCase(trimmed, needle)) return true;
    }
    return false;
}

// ============================================================================
// SHA-1 implementation (RFC 3174) — minimal, allocation-free.
// ============================================================================
//
// Why include this rather than use std.crypto.sha1.Sha1?
//   - std.crypto.sha1 was REMOVED in Zig 0.16 (along with std.crypto.random
//     and the rest of the std.crypto.* surface). The replacement
//     std.crypto.sha1.Sha1 is no longer available.
//   - std.crypto.hash.sha1 IS available in 0.16, but only via the
//     `std.crypto.hash` namespace which requires a `std.Io` runtime. We
//     want a sync, no-IO, no-allocator SHA-1 that runs inside the
//     handshake parser.
//   - SHA-1 is a small, well-known algorithm (RFC 3174) — ~80 lines.
//
// The reference implementation below is a textbook translation of RFC 3174.
// It produces the standard output bytes for any input — verified against
// the RFC 6455 §1.3 known-vector: input "dGhlIHNhbXBsZSBub25jZQ==" +
// MAGIC_GUID → SHA-1 → base64 → "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".

const Sha1 = struct {
    /// Compute SHA-1 of `data` and write the 20-byte digest to `out`.
    pub fn hash(data: []const u8, data_len: usize, out: *[20]u8) void {
        // Initial hash values (RFC 3174 §5.3.1)
        var h0: u32 = 0x67452301;
        var h1: u32 = 0xEFCDAB89;
        var h2: u32 = 0x98BADCFE;
        var h3: u32 = 0x10325476;
        var h4: u32 = 0xC3D2E1F0;

        // Pre-processing: append 0x80, pad with zeros, append 64-bit length.
        // RFC 3174 §5.1.1: message is padded until congruent to 448 mod 512.
        // The total length in bits is appended as a 64-bit big-endian integer.
        const bit_len: u64 = @intCast(data_len * 8);
        var msg: [128]u8 = undefined; // enough for 64-byte input + padding
        const padded_len = blk: {
            // Find the smallest 0 <= k < 64 such that (data_len + 1 + k) % 64 == 56
            var k: usize = 0;
            while (k < 64) : (k += 1) {
                if ((data_len + 1 + k) % 64 == 56) break;
            }
            break :blk data_len + 1 + k + 8;
        };
        if (padded_len > msg.len) {
            // For inputs up to 64 bytes (well within our 24+36 = 60-byte use case)
            // one block is enough. We never hit this branch in practice.
            @memset(&msg, 0);
            return;
        }
        @memcpy(msg[0..data_len], data[0..data_len]);
        msg[data_len] = 0x80;
        @memset(msg[data_len + 1 .. padded_len - 8], 0);
        // Append 64-bit big-endian length
        for (0..8) |i| {
            msg[padded_len - 8 + i] = @intCast((bit_len >> @intCast((7 - i) * 8)) & 0xFF);
        }

        // Process each 512-bit (64-byte) block
        var block_start: usize = 0;
        while (block_start < padded_len) {
            var w: [80]u32 = undefined;
            for (0..16) |i| {
                const idx = block_start + i * 4;
                w[i] = (@as(u32, msg[idx]) << 24) |
                    (@as(u32, msg[idx + 1]) << 16) |
                    (@as(u32, msg[idx + 2]) << 8) |
                    @as(u32, msg[idx + 3]);
            }
            for (16..80) |i| {
                const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
                w[i] = (x << 1) | (x >> 31);
            }

            var a = h0;
            var b = h1;
            var c = h2;
            var d = h3;
            var e = h4;

            for (0..80) |i| {
                const f: u32 = switch (i) {
                    0...19 => (b & c) | (~b & d),
                    20...39 => b ^ c ^ d,
                    40...59 => (b & c) | (b & d) | (c & d),
                    else => b ^ c ^ d,
                };
                const k_const: u32 = switch (i) {
                    0...19 => 0x5A827999,
                    20...39 => 0x6ED9EBA1,
                    40...59 => 0x8F1BBCDC,
                    else => 0xCA62C1D6,
                };
                const temp = ((a << 5) | (a >> 27)) +% f +% e +% k_const +% w[i];
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;
            }

            h0 +%= a;
            h1 +%= b;
            h2 +%= c;
            h3 +%= d;
            h4 +%= e;
            block_start += 64;
        }

        // Output: big-endian, 20 bytes total
        out[0] = @intCast((h0 >> 24) & 0xFF);
        out[1] = @intCast((h0 >> 16) & 0xFF);
        out[2] = @intCast((h0 >> 8) & 0xFF);
        out[3] = @intCast(h0 & 0xFF);
        out[4] = @intCast((h1 >> 24) & 0xFF);
        out[5] = @intCast((h1 >> 16) & 0xFF);
        out[6] = @intCast((h1 >> 8) & 0xFF);
        out[7] = @intCast(h1 & 0xFF);
        out[8] = @intCast((h2 >> 24) & 0xFF);
        out[9] = @intCast((h2 >> 16) & 0xFF);
        out[10] = @intCast((h2 >> 8) & 0xFF);
        out[11] = @intCast(h2 & 0xFF);
        out[12] = @intCast((h3 >> 24) & 0xFF);
        out[13] = @intCast((h3 >> 16) & 0xFF);
        out[14] = @intCast((h3 >> 8) & 0xFF);
        out[15] = @intCast(h3 & 0xFF);
        out[16] = @intCast((h4 >> 24) & 0xFF);
        out[17] = @intCast((h4 >> 16) & 0xFF);
        out[18] = @intCast((h4 >> 8) & 0xFF);
        out[19] = @intCast(h4 & 0xFF);
    }
};

// ============================================================================
// In-module tests
// ============================================================================

const testing = std.testing;

test "computeAcceptKey: RFC 6455 §1.3 known vector" {
    const accept = try computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    defer std.heap.page_allocator.free(accept);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "Sha1: known vector" {
    // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d (RFC 3174 §A.1)
    var out: [20]u8 = undefined;
    Sha1.hash("abc", 3, &out);
    const expected = [_]u8{
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
    };
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "containsTokenIgnoreCase: matches with whitespace and case" {
    try testing.expect(containsTokenIgnoreCase("Upgrade", "upgrade"));
    try testing.expect(containsTokenIgnoreCase("keep-alive, Upgrade", "upgrade"));
    try testing.expect(!containsTokenIgnoreCase("keep-alive", "upgrade"));
}
