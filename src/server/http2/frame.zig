//! HTTP/2 frame codec (RFC 9113 §4.1–4.3 and §6).
//!
//! A frame is a 9-octet header plus a payload whose meaning depends on the
//! header's type. This file is pure — no I/O, no global state — and the only
//! allocation is the caller's output buffer in `writeFrame`; that keeps the
//! connection driver testable without a socket.

const std = @import("std");
const constants = @import("constants.zig");

/// Frame header. `length` counts payload octets only; the frame occupies
/// `constants.frame_header_len + length` octets on the wire.
pub const Header = struct {
    /// 24 bits on the wire. Held as u32 so length arithmetic never needs a
    /// widening cast.
    length: u32,
    type: constants.FrameType,
    flags: u8,
    /// 31 bits. The reserved high bit is never set: `decodeHeader` masks it off
    /// because RFC 9113 §4.1 tells receivers to ignore it, and `encodeHeader`
    /// refuses to produce it.
    stream_id: u32,
};

pub const Frame = struct { header: Header, payload: []const u8 };

pub const Error = error{ IncompleteFrame, FrameSizeError, InvalidFrameLength, ProtocolError };

/// High bit of the 32-bit Stream Identifier / Window Size Increment /
/// Last-Stream-ID fields. Always zero on the wire.
const reserved_bit: u32 = 0x8000_0000;

/// Decode the 9-octet frame header. Fewer than 9 octets yields
/// `error.IncompleteFrame` — the caller keeps the bytes buffered and retries
/// once more data has arrived; it is not a protocol violation.
pub fn decodeHeader(buf: []const u8) Error!Header {
    if (buf.len < constants.frame_header_len) return error.IncompleteFrame;
    return .{
        .length = std.mem.readInt(u24, buf[0..3], .big),
        .type = @enumFromInt(buf[3]),
        .flags = buf[4],
        .stream_id = std.mem.readInt(u32, buf[5..9], .big) & ~reserved_bit,
    };
}

/// Encode a frame header into `out` (9 octets, big-endian per RFC 9113 §4.1).
pub fn encodeHeader(h: Header, out: *[constants.frame_header_len]u8) Error!void {
    // The 3-octet length field cannot express anything above 2^24-1.
    if (h.length > constants.max_allowed_frame_size) return error.InvalidFrameLength;
    // Reject rather than silently mask: a stream id with the reserved bit set
    // means the caller's stream bookkeeping is wrong, and hiding that would
    // surface later as a mysterious "peer closed the connection".
    if (h.stream_id > std.math.maxInt(u31)) return error.ProtocolError;

    std.mem.writeInt(u24, out[0..3], @intCast(h.length), .big);
    out[3] = @intFromEnum(h.type);
    out[4] = h.flags;
    std.mem.writeInt(u32, out[5..9], h.stream_id, .big);
}

/// Decode one frame from the front of `buf`, enforcing the MAX_FRAME_SIZE we
/// advertised (`max_frame_size`) rather than the peer's.
pub fn decode(buf: []const u8, max_frame_size: u32) Error!struct { frame: Frame, consumed: usize } {
    const header = try decodeHeader(buf);

    // RFC 9113 §4.2: a frame larger than the receiver's advertised limit is a
    // connection error, whatever the payload's availability. Checked before
    // the availability test so an oversized announcement fails fast instead of
    // waiting for bytes we would reject anyway.
    if (header.length > max_frame_size) return error.FrameSizeError;

    const total: usize = constants.frame_header_len + @as(usize, header.length);
    if (buf.len < total) return error.IncompleteFrame;

    return .{
        .frame = .{ .header = header, .payload = buf[constants.frame_header_len..total] },
        .consumed = total,
    };
}

/// Remove the padding and the optional priority block from a frame payload,
/// returning the application data. `type` matters: the PRIORITY flag means
/// "a priority block follows" only on frame types that define a priority
/// field, so the same flag bit must be left alone (ignored) everywhere else.
pub fn stripPadding(payload: []const u8, frame_type: constants.FrameType, flags: u8) Error![]const u8 {
    var body = payload;

    if (flags & constants.flag_padded != 0) {
        // Layout: [Pad Length][data][Padding]. The Pad Length octet itself is
        // mandatory even when its value is zero (RFC 9113 §6.1).
        if (body.len == 0) return error.ProtocolError;
        const pad_len = body[0];
        const rest = body[1..];
        // RFC 9113 §6.1 rejects padding >= the whole payload length. We are one
        // step stricter: a *non-zero* pad that swallows every remaining octet
        // leaves a PADDED frame with no data at all, which no peer needs to
        // send. A zero pad length stays legal even for an empty payload — it is
        // the canonical "PADDED but unpadded" encoding.
        if (pad_len > 0 and pad_len >= rest.len) return error.ProtocolError;
        body = rest[0 .. rest.len - pad_len];
    }

    // The priority field exists only on HEADERS and PUSH_PROMISE (RFC 9113
    // §6.2, §6.6); on any other type the 0x20 bit is undefined and MUST be
    // ignored — consuming 5 octets there would eat real data.
    const has_priority_block = flags & constants.flag_priority != 0 and switch (frame_type) {
        .headers, .push_promise => true,
        else => false,
    };
    if (has_priority_block) {
        // A truncated priority block is unparseable; RFC 9113 §6.2 calls that
        // FRAME_SIZE_ERROR.
        if (body.len < 5) return error.FrameSizeError;
        body = body[5..];
    }

    return body;
}

/// Append a complete frame (header + payload) to `out`. The header is passed
/// through `encodeHeader`, so its range validation applies here too.
pub fn writeFrame(alloc: std.mem.Allocator, out: *std.ArrayList(u8), h: Header, payload: []const u8) !void {
    var header_bytes: [constants.frame_header_len]u8 = undefined;
    try encodeHeader(h, &header_bytes);
    try out.appendSlice(alloc, &header_bytes);
    try out.appendSlice(alloc, payload);
}

// ─── Control-frame payload builders ─────────────────────────────────────────
// These exist so the connection driver never hand-rolls a control frame's
// byte layout; each one is a plain big-endian encoding of its fields.

pub fn rstStreamPayload(code: constants.ErrorCode) [4]u8 {
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, @intFromEnum(code), .big);
    return out;
}

pub fn goawayPayload(last_stream_id: u32, code: constants.ErrorCode) [8]u8 {
    var out: [8]u8 = undefined;
    // Last-Stream-ID is a 31-bit field; the reserved bit must be zero
    // (RFC 9113 §6.8).
    std.mem.writeInt(u32, out[0..4], last_stream_id & ~reserved_bit, .big);
    std.mem.writeInt(u32, out[4..8], @intFromEnum(code), .big);
    return out;
}

pub fn windowUpdatePayload(increment: u32) [4]u8 {
    var out: [4]u8 = undefined;
    // Window Size Increment is 31 bits; the reserved bit must be zero
    // (RFC 9113 §6.9). There is no error channel here, so mask instead of
    // trusting the caller.
    std.mem.writeInt(u32, &out, increment & ~reserved_bit, .big);
    return out;
}

pub fn pingPayload(data: [8]u8) [8]u8 {
    // The payload is opaque; RFC 9113 §6.7 requires a PING ACK to echo the
    // exact same 8 octets, so this is a pass-through by definition.
    return data;
}

// ============================================================================
// Tests — moved here from `frame_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = frame_tests; }` below pulls them into the run.
// ============================================================================

const frame_tests = struct {
    const frame = @import("frame.zig");
    const testing = std.testing;

    test "encodeHeader -> decodeHeader round-trips length/type/flags/stream_id" {
        const cases = [_]frame.Header{
            .{ .length = 0, .type = .data, .flags = 0, .stream_id = 0 },
            .{ .length = 5, .type = .data, .flags = constants.flag_end_stream, .stream_id = 1 },
            .{ .length = 16_384, .type = .headers, .flags = constants.flag_end_headers | constants.flag_padded, .stream_id = 0x7fff_ffff },
            .{ .length = constants.max_allowed_frame_size, .type = .settings, .flags = constants.flag_ack, .stream_id = 0 },
            .{ .length = 7, .type = .rst_stream, .flags = 0, .stream_id = 99 },
            .{ .length = 8, .type = .goaway, .flags = 0, .stream_id = 0 },
            .{ .length = 4, .type = .window_update, .flags = 0, .stream_id = 3 },
            .{ .length = 8, .type = .ping, .flags = 0, .stream_id = 0 },
            .{ .length = 1, .type = .priority, .flags = 0, .stream_id = 4 },
            .{ .length = 12, .type = .continuation, .flags = constants.flag_end_headers, .stream_id = 4 },
        };

        for (cases) |h| {
            var buf: [constants.frame_header_len]u8 = undefined;
            try frame.encodeHeader(h, &buf);
            const got = try frame.decodeHeader(&buf);
            try testing.expectEqual(h.length, got.length);
            try testing.expectEqual(h.type, got.type);
            try testing.expectEqual(h.flags, got.flags);
            try testing.expectEqual(h.stream_id, got.stream_id);
        }
    }

    test "reserved bit: decode clears it, encode never emits it" {
        // The reserved bit is the high bit of the 31-bit Stream Identifier field,
        // i.e. bit 0x80 of octet 5 of the 9-octet header (octets 0..2 = length,
        // 3 = type, 4 = flags, 5..8 = R + stream id).
        const wire = [_]u8{ 0x00, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01 };
        const decoded = try frame.decodeHeader(&wire);
        try testing.expectEqual(@as(u32, 1), decoded.stream_id);
        try testing.expect(decoded.stream_id & 0x8000_0000 == 0);
        try testing.expectEqual(@as(u8, 0x00), decoded.flags);

        // Re-encoding the decoded header produces the same bytes minus the bit.
        var out: [constants.frame_header_len]u8 = undefined;
        try frame.encodeHeader(decoded, &out);
        try testing.expectEqual(@as(u8, 0x00), out[5]);
        try testing.expectEqualSlices(u8, wire[0..5], out[0..5]);
        try testing.expectEqualSlices(u8, wire[6..9], out[6..9]);

        // A caller that passes a stream id with the reserved bit set is rejected
        // instead of silently having the bit masked away.
        try testing.expectError(error.ProtocolError, frame.encodeHeader(.{
            .length = 5,
            .type = .data,
            .flags = 0,
            .stream_id = 0x8000_0001,
        }, &out));
    }

    test "a byte-4 flag bit is not mistaken for the reserved bit" {
        // Any other value in the FLAGS octet must survive the round-trip; the
        // stream id stays intact.
        const wire = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x07 };
        const decoded = try frame.decodeHeader(&wire);
        try testing.expectEqual(@as(u8, 0x80), decoded.flags);
        try testing.expectEqual(@as(u32, 7), decoded.stream_id);
    }

    test "endianness: DATA frame with stream_id 1 and length 5 has exact wire bytes" {
        var out: [constants.frame_header_len]u8 = undefined;
        try frame.encodeHeader(.{ .length = 5, .type = .data, .flags = 0, .stream_id = 1 }, &out);
        try testing.expectEqualSlices(
            u8,
            &[_]u8{ 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            &out,
        );

        // ... and the same bytes decode back to those fields.
        const wire = [_]u8{ 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        const h = try frame.decodeHeader(&wire);
        try testing.expectEqual(@as(u32, 5), h.length);
        try testing.expectEqual(constants.FrameType.data, h.type);
        try testing.expectEqual(@as(u8, 0), h.flags);
        try testing.expectEqual(@as(u32, 1), h.stream_id);
    }

    test "encodeHeader rejects a payload longer than 2^24-1" {
        var out: [constants.frame_header_len]u8 = undefined;

        try testing.expectError(error.InvalidFrameLength, frame.encodeHeader(.{
            .length = constants.max_allowed_frame_size + 1,
            .type = .data,
            .flags = 0,
            .stream_id = 1,
        }, &out));

        // The boundary itself is encodable.
        try frame.encodeHeader(.{
            .length = constants.max_allowed_frame_size,
            .type = .data,
            .flags = 0,
            .stream_id = 1,
        }, &out);
        try testing.expectEqualSlices(u8, &[_]u8{ 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, &out);
    }

    test "decodeHeader/decode need the full 9-octet header" {
        const short = [_]u8{ 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
        try testing.expectError(error.IncompleteFrame, frame.decodeHeader(&short));
        try testing.expectError(error.IncompleteFrame, frame.decode(&short, 16_384));
        try testing.expectError(error.IncompleteFrame, frame.decodeHeader(""));
        try testing.expectError(error.IncompleteFrame, frame.decode("", 16_384));
    }

    test "decode enforces the advertised max_frame_size" {
        // 41 octets total: a 32-octet payload that is fully present.
        var wire = [_]u8{0} ** (constants.frame_header_len + 32);
        wire[2] = 32;
        wire[8] = 1;

        // One octet under the announced size -> rejected even though every byte
        // has already arrived.
        try testing.expectError(error.FrameSizeError, frame.decode(&wire, 31));

        // The same bytes decode fine with a limit that admits them.
        const got = try frame.decode(&wire, 32);
        try testing.expectEqual(@as(u32, 32), got.frame.header.length);
        try testing.expectEqual(@as(usize, 32), got.frame.payload.len);
        try testing.expectEqual(@as(usize, constants.frame_header_len + 32), got.consumed);
        try testing.expectEqual(@as(u32, 1), got.frame.header.stream_id);
    }

    test "decode: announced length beyond the buffer is IncompleteFrame" {
        var wire = [_]u8{0} ** (constants.frame_header_len + 8);
        wire[2] = 8; // claims 8 payload octets

        // Only 4 of the 8 payload octets have arrived.
        try testing.expectError(error.IncompleteFrame, frame.decode(wire[0 .. constants.frame_header_len + 4], 16_384));

        // The identical prefix decodes once the rest is present.
        const got = try frame.decode(&wire, 16_384);
        try testing.expectEqual(@as(usize, constants.frame_header_len + 8), got.consumed);
        try testing.expectEqual(@as(usize, 8), got.frame.payload.len);
    }

    test "decode reports consumed for two back-to-back frames" {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(testing.allocator);

        const a = "AAAA"; // 4 octets
        const b = "BBBBBB"; // 6 octets
        try frame.writeFrame(testing.allocator, &out, .{
            .length = a.len,
            .type = .data,
            .flags = constants.flag_end_stream,
            .stream_id = 1,
        }, a);
        try frame.writeFrame(testing.allocator, &out, .{
            .length = b.len,
            .type = .continuation,
            .flags = constants.flag_end_headers,
            .stream_id = 1,
        }, b);

        const first = try frame.decode(out.items, 16_384);
        try testing.expectEqual(@as(usize, constants.frame_header_len + 4), first.consumed);
        try testing.expectEqualStrings(a, first.frame.payload);

        const second = try frame.decode(out.items[first.consumed..], 16_384);
        try testing.expectEqualStrings(b, second.frame.payload);
        try testing.expectEqual(constants.FrameType.continuation, second.frame.header.type);
        try testing.expectEqual(@as(usize, out.items.len), first.consumed + second.consumed);
    }

    test "stripPadding: without the PADDED flag the payload is untouched" {
        const payload = "hello";
        try testing.expectEqualStrings(payload, try frame.stripPadding(payload, .data, 0));
        // The PRIORITY bit is undefined on DATA and must not eat 5 octets.
        try testing.expectEqualStrings(payload, try frame.stripPadding(payload, .data, constants.flag_priority));
        try testing.expectEqualStrings(payload, try frame.stripPadding(payload, .ping, 0x07));
    }

    test "stripPadding: pad length 0 is a no-op on the data" {
        try testing.expectEqualStrings("hello", try frame.stripPadding("\x00hello", .data, constants.flag_padded));
        try testing.expectEqualStrings("", try frame.stripPadding("\x00", .data, constants.flag_padded));
    }

    test "stripPadding: pad length 3 drops the pad-length octet and 3 pad octets" {
        const payload = "\x03abc\xaa\xbb\xcc";
        try testing.expectEqualStrings("abc", try frame.stripPadding(payload, .data, constants.flag_padded));
    }

    test "stripPadding: padding that eats every remaining octet is a protocol error" {
        // 3 pad octets and nothing else after the pad-length octet.
        try testing.expectError(error.ProtocolError, frame.stripPadding("\x03\xaa\xbb\xcc", .data, constants.flag_padded));
        // Pad length far beyond the payload.
        try testing.expectError(error.ProtocolError, frame.stripPadding("\x05\x01", .data, constants.flag_padded));
        // PADDED with no octets at all: the pad-length octet is missing.
        try testing.expectError(error.ProtocolError, frame.stripPadding("", .data, constants.flag_padded));
    }

    test "stripPadding: PRIORITY on HEADERS drops the 5-octet priority block" {
        // E=1, dependency=1, weight=0x10, then "data".
        const payload = "\x80\x00\x00\x01\x10data";
        try testing.expectEqualStrings("data", try frame.stripPadding(payload, .headers, constants.flag_priority));
    }

    test "stripPadding: PADDED + PRIORITY drop 1 + 5 + pad octets" {
        // [pad_len=2][ 5-octet priority ][ "data" ][ 2 pad octets ]
        const payload = "\x02\x80\x00\x00\x01\x10dataXY";
        try testing.expectEqualStrings("data", try frame.stripPadding(
            payload,
            .headers,
            constants.flag_padded | constants.flag_priority,
        ));
    }

    test "stripPadding: a truncated priority block is a frame size error" {
        try testing.expectError(error.FrameSizeError, frame.stripPadding("\x80\x00", .headers, constants.flag_priority));
        try testing.expectError(error.FrameSizeError, frame.stripPadding("", .headers, constants.flag_priority));
    }

    test "control-frame payload builders match the RFC wire shapes" {
        const rst = frame.rstStreamPayload(.protocol_error);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x01 }, &rst);

        const goaway = frame.goawayPayload(3, .no_error);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00 }, &goaway);

        const wu = frame.windowUpdatePayload(0x7fff_ffff);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x7f, 0xff, 0xff, 0xff }, &wu);

        // The 31-bit fields never emit the reserved bit.
        const goaway_max = frame.goawayPayload(0xffff_ffff, .no_error);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x7f, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }, &goaway_max);

        const wu_reserved = frame.windowUpdatePayload(0x8000_0005);
        try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x05 }, &wu_reserved);

        const ping_bytes = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
        const ping = frame.pingPayload(ping_bytes);
        try testing.expectEqualSlices(u8, &ping_bytes, &ping);
    }

    test "writeFrame emits header + payload and can be called twice" {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(testing.allocator);

        const h1 = frame.Header{ .length = 3, .type = .data, .flags = constants.flag_end_stream, .stream_id = 1 };
        try frame.writeFrame(testing.allocator, &out, h1, "abc");
        try testing.expectEqual(@as(usize, constants.frame_header_len + 3), out.items.len);

        var expected: [constants.frame_header_len]u8 = undefined;
        try frame.encodeHeader(h1, &expected);
        try testing.expectEqualSlices(u8, &expected, out.items[0..constants.frame_header_len]);
        try testing.expectEqualStrings("abc", out.items[constants.frame_header_len..]);

        try frame.writeFrame(testing.allocator, &out, .{
            .length = 0,
            .type = .ping,
            .flags = constants.flag_ack,
            .stream_id = 0,
        }, "");
        try testing.expectEqual(@as(usize, 2 * constants.frame_header_len + 3), out.items.len);

        // The concatenation decodes as two frames in sequence.
        const f1 = try frame.decode(out.items, 16_384);
        const f2 = try frame.decode(out.items[f1.consumed..], 16_384);
        try testing.expectEqual(constants.FrameType.data, f1.frame.header.type);
        try testing.expectEqualStrings("abc", f1.frame.payload);
        try testing.expectEqual(constants.FrameType.ping, f2.frame.header.type);
        try testing.expectEqual(@as(usize, 0), f2.frame.payload.len);
        try testing.expectEqual(@as(usize, out.items.len), f1.consumed + f2.consumed);
    }

    test "writeFrame propagates header validation and writes nothing on failure" {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(testing.allocator);

        try testing.expectError(error.InvalidFrameLength, frame.writeFrame(testing.allocator, &out, .{
            .length = constants.max_allowed_frame_size + 1,
            .type = .data,
            .flags = 0,
            .stream_id = 1,
        }, ""));
        try testing.expectEqual(@as(usize, 0), out.items.len);
    }
};

comptime {
    _ = frame_tests;
}
