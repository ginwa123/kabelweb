const std = @import("std");
const constants = @import("constants.zig");
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
