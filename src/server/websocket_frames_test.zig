//! Tests for the WebSocket frame parser/encoder (RFC 6455 section 5).
//!
//! These tests are written FIRST (TDD red phase). They describe the
//! frame wire format and the behaviour we want from the parser/encoder.
//! The implementation (websocket_frames.zig) is written ONLY to make
//! these tests pass — no features without a failing test driving them.
//!
//! Frame format (RFC 6455 §5.2):
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-------+-+-------------+-------------------------------+
//!  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//!  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//!  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//!  | |1|2|3|       |K|             |                               |
//!  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - +
//!  |     Extended payload length continued, if payload len == 127  |
//!  + - - - - - - - - - - - - - - - +-------------------------------+
//!  |                               |Masking-key, if MASK set to 1  |
//!  +-------------------------------+-------------------------------+
//!  | Masking-key (continued)       |          Payload Data         |
//!  +-------------------------------- - - - - - - - - - - - - - - +
//!  :                     Payload Data continued ...                :
//!  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//!  |                     Payload Data (continued)                  |
//!  +---------------------------------------------------------------+

const std = @import("std");
const testing = std.testing;
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
