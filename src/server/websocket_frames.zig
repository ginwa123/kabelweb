//! WebSocket frame parser and encoder (RFC 6455 §5).
//!
//! This module converts between raw WebSocket frames on the wire and the
//! `Frame` struct. It is the only part of the WebSocket implementation that
//! touches the wire format — the manager and handshake modules build on top.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc6455#section-5>
//!
//! Frame header layout (always big-endian on the wire):
//!   byte 0: FIN (1) | RSV (3) | opcode (4)
//!   byte 1: MASK (1) | payload_len (7)
//!   bytes 2..2+(0|2|8): extended payload length
//!   bytes 2..6 or 4..8: 4-byte mask key (only if MASK=1)
//!   bytes ...: payload (XOR-masked with the rotating mask key)
//!
//! Length encoding:
//!   - 0..125: literal payload length in the 7-bit field.
//!   - 126: the next 2 bytes are the 16-bit payload length (network byte order).
//!   - 127: the next 8 bytes are the 64-bit payload length.
//!
//! Opcodes (RFC 6455 §5.2):
//!   0x0 continuation, 0x1 text, 0x2 binary,
//!   0x8 close, 0x9 ping, 0xA pong
//!
//! Masking requirement (RFC 6455 §5.1):
//!   - Clients MUST mask all frames sent to the server.
//!   - Servers MUST NOT mask frames sent to the client.
//!   The parser therefore rejects unmasked frames from the client side
//!   with `error.UnmaskedFrameFromClient`.

const std = @import("std");

/// WebSocket message opcodes (RFC 6455 §5.2).
pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    // 0x3..0x7 reserved for data frames
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    // 0xB..0xF reserved for control frames
};

/// A parsed WebSocket frame.
///
/// `payload` is freshly allocated by `parseFrame` (the caller owns it and
/// must call `deinit` to free). The wire bytes are not retained.
pub const Frame = struct {
    fin: bool,
    rsv: u3,
    opcode: Opcode,
    payload: []u8,

    /// Free the payload. Safe to call multiple times (no-op after first call).
    pub fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        if (self.payload.len > 0) {
            allocator.free(self.payload);
        }
        self.payload = &[_]u8{};
    }
};

/// Input for `encodeFrame`. The mask bit is controlled by the encoder —
/// callers do not set it. The encoder always produces unmasked frames
/// (the server must not mask per RFC 6455 §5.1).
pub const EncodeInput = struct {
    opcode: Opcode,
    payload: []const u8,
};

/// Encode a WebSocket frame into a freshly-allocated byte slice.
///
/// The returned slice is owned by the caller (free with `allocator.free`).
pub fn encodeFrame(allocator: std.mem.Allocator, input: EncodeInput) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(allocator);

    // First byte: FIN=1, RSV=000, opcode
    const first_byte: u8 = 0x80 | @as(u8, @intFromEnum(input.opcode));
    try buf.append(allocator, first_byte);

    // Second byte: MASK=0 (server->client), payload_len
    const plen = input.payload.len;
    if (plen <= 125) {
        try buf.append(allocator, @intCast(plen));
    } else if (plen <= 0xFFFF) {
        try buf.append(allocator, 126);
        try buf.append(allocator, @intCast(@as(u16, @intCast(plen)) >> 8));
        try buf.append(allocator, @intCast(@as(u16, @intCast(plen)) & 0xFF));
    } else {
        try buf.append(allocator, 127);
        // 64-bit big-endian length
        var i: usize = 8;
        while (i > 0) {
            i -= 1;
            try buf.append(allocator, @intCast((plen >> @intCast(i * 8)) & 0xFF));
        }
    }

    // Payload
    try buf.appendSlice(allocator, input.payload);

    return buf.toOwnedSlice(allocator);
}

/// Parse a complete WebSocket frame from raw bytes.
///
/// The wire buffer must contain the entire frame (header + masking key + payload).
/// For streaming parsing, the caller should read more bytes until `parseFrame`
/// succeeds — see `error.IncompleteFrame` for the recoverable case.
///
/// Errors:
///   - `error.IncompleteFrame` — the wire buffer is too short for the declared
///     payload length. Caller should read more bytes and retry.
///   - `error.UnmaskedFrameFromClient` — RFC 6455 §5.1 violation (server-side only).
///   - `error.InvalidOpcode` — reserved opcode received.
pub fn parseFrame(allocator: std.mem.Allocator, wire: []const u8) !Frame {
    if (wire.len < 2) return error.IncompleteFrame;

    const b0 = wire[0];
    const b1 = wire[1];

    const fin: bool = (b0 & 0x80) != 0;
    const rsv: u3 = @truncate(@as(u8, @intCast((b0 >> 4) & 0x07)));
    const opcode_raw: u4 = @truncate(@as(u8, @intCast(b0 & 0x0F)));
    // Zig 0.16 removed std.meta.intToEnum. We validate the raw value against
    // the allowed opcodes manually — values 0x3..0x7 (data) and 0xB..0xF
    // (control) are reserved and rejected per RFC 6455 §5.2.
    const opcode: Opcode = switch (opcode_raw) {
        0x0 => .continuation,
        0x1 => .text,
        0x2 => .binary,
        0x8 => .close,
        0x9 => .ping,
        0xA => .pong,
        else => return error.InvalidOpcode,
    };

    const masked: bool = (b1 & 0x80) != 0;
    if (!masked) return error.UnmaskedFrameFromClient;

    const len7 = b1 & 0x7F;
    var payload_len: usize = 0;
    var offset: usize = 2;

    if (len7 < 126) {
        payload_len = len7;
    } else if (len7 == 126) {
        if (wire.len < offset + 2) return error.IncompleteFrame;
        const len16 = (@as(u16, wire[offset]) << 8) | @as(u16, wire[offset + 1]);
        payload_len = len16;
        offset += 2;
    } else {
        // 127 -> 64-bit length
        if (wire.len < offset + 8) return error.IncompleteFrame;
        var len64: u64 = 0;
        for (0..8) |i| {
            len64 = (len64 << 8) | @as(u64, wire[offset + i]);
        }
        payload_len = @intCast(len64);
        offset += 8;
    }

    var mask_key: [4]u8 = undefined;
    if (masked) {
        if (wire.len < offset + 4) return error.IncompleteFrame;
        @memcpy(&mask_key, wire[offset..offset + 4]);
        offset += 4;
    }

    if (wire.len < offset + payload_len) return error.IncompleteFrame;

    // Allocate and unmask the payload. We always copy (never alias the wire
    // buffer) because the wire buffer may be reused by the caller for the
    // next frame.
    const payload = try allocator.alloc(u8, payload_len);
    if (masked) {
        unmaskInPlace(payload, wire[offset..offset + payload_len], mask_key);
    } else {
        @memcpy(payload, wire[offset..offset + payload_len]);
    }

    return Frame{
        .fin = fin,
        .rsv = rsv,
        .opcode = opcode,
        .payload = payload,
    };
}

/// Information extracted from a Close frame payload (RFC 6455 §5.5.1).
///
/// The status code is a 2-byte big-endian unsigned integer. The "Normal
/// Closure" code (1000) is the default when no payload is sent.
pub const CloseInfo = struct {
    code: u16,
    reason: []const u8,
};

/// Decode the Close frame payload into a status code + reason.
///
/// An empty payload is treated as 1000 (Normal Closure) per RFC 6455 §5.5.1.
pub fn decodeClosePayload(payload: []const u8) !CloseInfo {
    if (payload.len == 0) {
        return .{ .code = 1000, .reason = "" };
    }
    if (payload.len < 2) return error.InvalidClosePayload;
    const code = (@as(u16, payload[0]) << 8) | @as(u16, payload[1]);
    return .{ .code = code, .reason = payload[2..] };
}

/// Generate a 4-byte random mask key for client→server frames.
///
/// RFC 6455 §5.3: "The masking key is a 32-bit value chosen at random by
/// the client. ... When preparing a masked frame, the client MUST pick a
/// fresh masking key from the set of allowed 32-bit values."
pub fn generateMaskKey() [4]u8 {
    var key: [4]u8 = undefined;

    // Pick the strongest random source available on this OS. `std.c`
    // exposes `getrandom` only on Linux/FreeBSD (and only on Linux with
    // glibc >= 2.25); on macOS / Windows it resolves to an empty
    // struct, so calling it is a type error on those platforms. Gate
    // by target OS and fall through to the LCG fallback otherwise.
    //
    // The mask key is a client→server direction requirement — server
    // never sees inbound frames we generate keys for — so a non-
    // cryptographic fallback is acceptable per RFC 6455 §5.3 (the
    // masking key only protects against trivial proxy tampering, not
    // attackers with the wire). The LCG fallback seeds from time-of-
    // day and is unpredictable within a single process.
    // Pick the strongest random source available on this OS. `std.c`
    // exposes `getrandom` only on Linux/FreeBSD (and only on Linux with
    // glibc >= 2.25); on macOS / Windows it resolves to the empty
    // struct `{}` (or `void`), so calling it is a type error on those
    // platforms. Gate by `@hasDecl` and by type — call only when the
    // decl is a callable function pointer.
    //
    // The mask key is a client→server direction requirement — server
    // never sees inbound frames we generate keys for — so a non-
    // cryptographic fallback is acceptable per RFC 6455 §5.3 (the
    // masking key only protects against trivial proxy tampering, not
    // attackers with the wire). The LCG fallback seeds from time-of-
    // day and is unpredictable within a single process.
    const got_random: ?isize = blk: {
        if (!@hasDecl(std.c, "getrandom")) break :blk null;
        const T = @TypeOf(std.c.getrandom);
        if (T == void or T == type) break :blk null;
        break :blk @as(?isize, std.c.getrandom(&key, key.len, 0));
    };

    if (got_random == null or got_random.? < 0) {
        // Fall back to a non-cryptographic source on platforms without
        // getrandom, or on the (vanishingly rare) getrandom failure.
        // Mix in BOTH seconds and microseconds so two consecutive
        // calls in the same second still produce different keys
        // (otherwise generateMaskKey returns the same 4 bytes twice
        // in a row — the random-bytes test catches this).
        var tv: std.c.timeval = .{ .sec = 0, .usec = 0 };
        _ = std.c.gettimeofday(&tv, null);
        // Per-process call counter — guarantees uniqueness even when
        // tv doesn't tick over between two calls.
        const Calls = struct {
            var counter: u64 = 0;
        };
        Calls.counter += 1;
        var fallback_seed: u64 = (@as(u64, @intCast(@as(i64, tv.sec))) *% 1_000_000) +% @as(u64, @intCast(tv.usec));
        fallback_seed ^= Calls.counter *% 0x9E3779B97F4A7C15;
        for (&key) |*b| {
            fallback_seed = fallback_seed *% 6364136223846793005 +% 1442695040888963407;
            b.* = @intCast((fallback_seed >> 32) & 0xFF);
        }
    }
    return key;
}

/// XOR `payload` in place with a 4-byte rotating mask key (RFC 6455 §5.3).
///
/// The mask key repeats every 4 bytes: byte i is XORed with key[i % 4].
pub fn mask(payload: []u8, key: [4]u8) void {
    for (payload, 0..) |*b, i| {
        b.* ^= key[i % 4];
    }
}

/// Inverse of `mask` — XOR is its own inverse, so this is the same call.
pub fn unmask(payload: []u8, key: [4]u8) void {
    mask(payload, key);
}

/// Decode a masked payload into a fresh buffer (helper for `parseFrame`).
/// Allocates `out` and writes the unmasked bytes into it.
fn unmaskInPlace(out: []u8, masked: []const u8, key: [4]u8) void {
    for (masked, 0..) |m, i| {
        out[i] = m ^ key[i % 4];
    }
}

// ============================================================================
// Tests
// ============================================================================

// In-module tests live at the bottom of the file. The comprehensive wire-
// format tests are in `the colocated frame-format tests below`. The tests here cover
// the in-module helpers (`mask` / `unmask` symmetric, `decodeClosePayload`
// empty payload) that the unit tests also exercise, providing a sanity
// check that the public API and the implementation line up.
const testing = std.testing;

test "mask / unmask: identity round-trip" {
    const original = "The quick brown fox jumps over the lazy dog";
    var buf: [43]u8 = undefined;
    @memcpy(&buf, original);

    const key = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    mask(&buf, key);
    unmask(&buf, key);

    try testing.expectEqualSlices(u8, original, &buf);
}

test "decodeClosePayload: empty payload returns 1000 Normal Closure" {
    const info = try decodeClosePayload("");
    try testing.expectEqual(@as(u16, 1000), info.code);
    try testing.expectEqualStrings("", info.reason);
}

test "decodeClosePayload: payload with only code returns empty reason" {
    // Two bytes only, no trailing reason.
    const info = try decodeClosePayload(&[_]u8{ 0x03, 0xE8 }); // 1000
    try testing.expectEqual(@as(u16, 1000), info.code);
    try testing.expectEqualStrings("", info.reason);
}

// ============================================================================
// Tests — moved here from `websocket_frames_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = websocket_frames_tests; }` below pulls them into the run.
// ============================================================================

const websocket_frames_tests = struct {
    // Tests for the WebSocket frame parser/encoder (RFC 6455 section 5).
    //
    // These tests are written FIRST (TDD red phase). They describe the
    // frame wire format and the behaviour we want from the parser/encoder.
    // The implementation (websocket_frames.zig) is written ONLY to make
    // these tests pass — no features without a failing test driving them.
    //
    // Frame format (RFC 6455 §5.2):
    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-------+-+-------------+-------------------------------+
    //  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    //  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
    //  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
    //  | |1|2|3|       |K|             |                               |
    //  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - +
    //  |     Extended payload length continued, if payload len == 127  |
    //  + - - - - - - - - - - - - - - - +-------------------------------+
    //  |                               |Masking-key, if MASK set to 1  |
    //  +-------------------------------+-------------------------------+
    //  | Masking-key (continued)       |          Payload Data         |
    //  +-------------------------------- - - - - - - - - - - - - - - +
    //  :                     Payload Data continued ...                :
    //  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
    //  |                     Payload Data (continued)                  |
    //  +---------------------------------------------------------------+

    const ws_frames = @import("websocket_frames.zig");

    // ============================================================================
    // encodeFrame tests
    // ============================================================================

    test "encodeFrame: small text payload (no mask, server->client)" {
        // Frame for "hi" (2 bytes) from server to client (unmasked).
        // RFC 6455 §5.1: "A client MUST mask all frames that it sends to the server."
        // §5.3: "The server MUST NOT mask any frames that it sends to the client."
        const frame = try ws_frames.encodeFrame(testing.allocator, .{
            .opcode = .text,
            .payload = "hi",
        });
        defer testing.allocator.free(frame);

        // First byte: FIN=1, RSV=000, opcode=0x1 (text) -> 0x81
        try testing.expectEqual(@as(u8, 0x81), frame[0]);
        // Second byte: MASK=0, payload_len=2 -> 0x02
        try testing.expectEqual(@as(u8, 0x02), frame[1]);
        // Payload bytes
        try testing.expectEqual(@as(u8, 'h'), frame[2]);
        try testing.expectEqual(@as(u8, 'i'), frame[3]);
        // Total frame length: 2 header bytes + 2 payload bytes
        try testing.expectEqual(@as(usize, 4), frame.len);
    }

    test "encodeFrame: empty payload (opcode-only frame)" {
        // Common pattern: pong with no payload, or close with no reason.
        const frame = try ws_frames.encodeFrame(testing.allocator, .{
            .opcode = .pong,
            .payload = "",
        });
        defer testing.allocator.free(frame);

        try testing.expectEqual(@as(u8, 0x8A), frame[0]); // FIN=1, opcode=0xA (pong)
        try testing.expectEqual(@as(u8, 0x00), frame[1]); // MASK=0, payload_len=0
        try testing.expectEqual(@as(usize, 2), frame.len);
    }

    test "encodeFrame: medium payload uses 16-bit length (126-65535 bytes)" {
        // 200-byte payload triggers the 16-bit extended length encoding.
        var payload: [200]u8 = undefined;
        for (&payload, 0..) |*b, i| b.* = @intCast(i % 256);

        const frame = try ws_frames.encodeFrame(testing.allocator, .{
            .opcode = .binary,
            .payload = &payload,
        });
        defer testing.allocator.free(frame);

        // First byte: FIN=1, opcode=0x2 (binary) -> 0x82
        try testing.expectEqual(@as(u8, 0x82), frame[0]);
        // Second byte: MASK=0, payload_len=126 (means "next 2 bytes are the length")
        try testing.expectEqual(@as(u8, 126), frame[1]);
        // Next 2 bytes: 16-bit big-endian length = 200
        try testing.expectEqual(@as(u8, 0), frame[2]);
        try testing.expectEqual(@as(u8, 200), frame[3]);
        // Total: 4 header bytes + 200 payload bytes
        try testing.expectEqual(@as(usize, 204), frame.len);
    }

    test "encodeFrame: close opcode encodes 0x88" {
        const frame = try ws_frames.encodeFrame(testing.allocator, .{
            .opcode = .close,
            .payload = "",
        });
        defer testing.allocator.free(frame);

        try testing.expectEqual(@as(u8, 0x88), frame[0]); // FIN=1, opcode=0x8
        try testing.expectEqual(@as(u8, 0x00), frame[1]);
    }

    // ============================================================================
    // parseFrame tests
    // ============================================================================

    test "parseFrame: small text frame from client (masked)" {
        // Client MUST mask. This is a frame for "hi" with a 4-byte mask key
        // 0x00 0x00 0x00 0x00 (zeros — common in test fixtures).
        // Masked bytes: 'h' XOR 0 = 'h', 'i' XOR 0 = 'i'.
        const wire = [_]u8{
            0x81, // FIN=1, opcode=0x1 (text)
            0x82, // MASK=1, payload_len=2
            0x00, 0x00, 0x00, 0x00, // mask key
            'h', 'i', // masked payload
        };

        var frame = try ws_frames.parseFrame(testing.allocator, &wire);
        defer frame.deinit(testing.allocator);

        try testing.expectEqual(ws_frames.Opcode.text, frame.opcode);
        try testing.expectEqual(@as(usize, 2), frame.payload.len);
        try testing.expectEqualSlices(u8, "hi", frame.payload);
        try testing.expect(frame.fin);
    }

    test "parseFrame: empty ping frame" {
        // A ping frame from the client MUST be masked. We use a 4-byte zero
        // mask key here so the wire matches the simple "no payload" pattern.
        // Even with payload_len=0, the parser still expects 4 mask-key bytes.
        const wire = [_]u8{
            0x89, // FIN=1, opcode=0x9 (ping)
            0x80, // MASK=1, payload_len=0
            0x00, 0x00, 0x00, 0x00, // 4-byte mask key (zeros)
        };

        var frame = try ws_frames.parseFrame(testing.allocator, &wire);
        defer frame.deinit(testing.allocator);

        try testing.expectEqual(ws_frames.Opcode.ping, frame.opcode);
        try testing.expectEqual(@as(usize, 0), frame.payload.len);
        try testing.expect(frame.fin);
    }

    test "parseFrame: 16-bit extended length encoded correctly" {
        // 200-byte payload, masked.
        const mask_key: [4]u8 = .{ 0, 0, 0, 0 };
        var payload: [200]u8 = undefined;
        for (&payload) |*b| b.* = 0; // masked payload is all zeros
        var wire_buf: [2 + 2 + 4 + 200]u8 = undefined;
        wire_buf[0] = 0x82; // FIN=1, opcode=0x2 (binary)
        wire_buf[1] = 0xFE; // MASK=1, payload_len=126 (means 16-bit length follows)
        wire_buf[2] = 0x00;
        wire_buf[3] = 200; // 16-bit big-endian length
        @memcpy(wire_buf[4..8], &mask_key);
        @memcpy(wire_buf[8..208], &payload);

        var frame = try ws_frames.parseFrame(testing.allocator, &wire_buf);
        defer frame.deinit(testing.allocator);

        try testing.expectEqual(ws_frames.Opcode.binary, frame.opcode);
        try testing.expectEqual(@as(usize, 200), frame.payload.len);
        try testing.expect(frame.fin);
    }

    test "parseFrame: unmasked frame from server is rejected (RFC 6455 §5.1)" {
        // "A client MUST mask all frames that it sends to the server."
        // The parser (running server-side) MUST reject unmasked frames.
        const wire = [_]u8{
            0x81, // FIN=1, opcode=0x1 (text)
            0x02, // MASK=0, payload_len=2 — INVALID per RFC 6455 §5.1
            'h', 'i',
        };

        const result = ws_frames.parseFrame(testing.allocator, &wire);
        try testing.expectError(error.UnmaskedFrameFromClient, result);
    }

    test "parseFrame: incomplete frame returns Incomplete error" {
        // Header says payload_len=10, but only 4 bytes are present.
        const wire = [_]u8{
            0x81, 0x8A, 0x00, 0x00, 0x00, 0x00, // fin/text, masked, len=10, mask key
            0x00, 0x00, 0x00, 0x00, // only 4 payload bytes (need 10)
        };

        const result = ws_frames.parseFrame(testing.allocator, &wire);
        try testing.expectError(error.IncompleteFrame, result);
    }

    test "parseFrame: masking key is XORed with payload bytes" {
        // A small text frame ("hi") masked with key 0x11 0x22 0x33 0x44:
        //   'h' (0x68) XOR 0x11 = 0x79
        //   'i' (0x69) XOR 0x22 = 0x4b
        // So the wire bytes are [0x79, 0x4B] after the mask key.
        const wire = [_]u8{
            0x81, 0x82, 0x11, 0x22, 0x33, 0x44, 0x79, 0x4b,
        };

        var frame = try ws_frames.parseFrame(testing.allocator, &wire);
        defer frame.deinit(testing.allocator);

        // After unmask, the payload should be exactly "hi".
        try testing.expectEqualSlices(u8, "hi", frame.payload);
    }

    // ============================================================================
    // decodeClosePayload tests
    // ============================================================================

    test "decodeClosePayload: extracts status code and optional reason" {
        // RFC 6455 §5.5.1: close frame MAY include a 2-byte status code followed
        // by a UTF-8 reason. This is OPTIONAL — a close frame with no payload is
        // equivalent to status 1000 (Normal Closure).
        const payload = "\x03\xe8" ++ "goodbye"; // 1000 = normal closure
        const info = try ws_frames.decodeClosePayload(payload);
        try testing.expectEqual(@as(u16, 1000), info.code);
        try testing.expectEqualStrings("goodbye", info.reason);
    }

    test "decodeClosePayload: empty payload defaults to 1000 (Normal Closure)" {
        const info = try ws_frames.decodeClosePayload("");
        try testing.expectEqual(@as(u16, 1000), info.code);
        try testing.expectEqualStrings("", info.reason);
    }

    // ============================================================================
    // generateMaskKey tests
    // ============================================================================

    test "generateMaskKey: returns 4 random bytes" {
        const k1 = ws_frames.generateMaskKey();
        const k2 = ws_frames.generateMaskKey();
        var all_zero = true;
        for (k1) |b| if (b != 0) {
            all_zero = false;
            break;
        };
        // Statistically near-impossible to get all zeros from random.
        try testing.expect(!all_zero);
        // Two consecutive calls should differ (with overwhelming probability).
        try testing.expect(!std.mem.eql(u8, &k1, &k2));
    }

    // ============================================================================
    // mask / unmask tests
    // ============================================================================

    test "mask: XORs payload with 4-byte rotating key" {
        const payload = "Hello, World!"; // 13 bytes
        const key = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        var buf: [13]u8 = undefined;
        @memcpy(&buf, payload);

        ws_frames.mask(&buf, key);

        // First 4 bytes XORed with 0xAA, next 4 with 0xBB, etc.
        try testing.expectEqual(@as(u8, 'H' ^ 0xAA), buf[0]);
        try testing.expectEqual(@as(u8, 'e' ^ 0xBB), buf[1]);
        try testing.expectEqual(@as(u8, 'l' ^ 0xCC), buf[2]);
        try testing.expectEqual(@as(u8, 'l' ^ 0xDD), buf[3]);
        try testing.expectEqual(@as(u8, 'o' ^ 0xAA), buf[4]); // key rotates
    }

    test "unmask: inverse of mask (XOR is its own inverse)" {
        const payload = "Hello, World!";
        const key = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        var buf: [13]u8 = undefined;
        @memcpy(&buf, payload);

        ws_frames.mask(&buf, key);
        ws_frames.unmask(&buf, key);

        try testing.expectEqualSlices(u8, payload, &buf);
    }
};

comptime {
    _ = websocket_frames_tests;
}
