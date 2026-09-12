const std = @import("std");
const constants = @import("constants.zig");
const settings = @import("settings.zig");
const testing = std.testing;

/// Read the identifier of the `n`-th 6-octet entry in a payload.
fn entryId(payload: []const u8, n: usize) u16 {
    return std.mem.readInt(u16, payload[n * 6 ..][0..2], .big);
}

/// Read the value of the `n`-th 6-octet entry in a payload.
fn entryValue(payload: []const u8, n: usize) u32 {
    return std.mem.readInt(u32, payload[n * 6 + 2 ..][0..4], .big);
}

test "encode -> decode round-trips a fully-populated Settings" {
    const original = settings.Settings{
        .header_table_size = 8192,
        .enable_push = true,
        .max_concurrent_streams = 250,
        .initial_window_size = 1 << 20,
        .max_frame_size = 32_768,
        .max_header_list_size = 1234,
    };

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);
    try settings.encode(testing.allocator, &buf, original);

    // Six present fields -> six entries, ascending identifiers, big-endian.
    try testing.expectEqual(@as(usize, 36), buf.items.len);
    try testing.expectEqual(@as(u16, 0x0001), entryId(buf.items, 0));
    try testing.expectEqual(@as(u16, 0x0002), entryId(buf.items, 1));
    try testing.expectEqual(@as(u16, 0x0003), entryId(buf.items, 2));
    try testing.expectEqual(@as(u16, 0x0004), entryId(buf.items, 3));
    try testing.expectEqual(@as(u16, 0x0005), entryId(buf.items, 4));
    try testing.expectEqual(@as(u16, 0x0006), entryId(buf.items, 5));
    try testing.expectEqual(@as(u32, 8192), entryValue(buf.items, 0));
    try testing.expectEqual(@as(u32, 1), entryValue(buf.items, 1));
    try testing.expectEqual(@as(u32, 250), entryValue(buf.items, 2));
    try testing.expectEqual(@as(u32, 1 << 20), entryValue(buf.items, 3));
    try testing.expectEqual(@as(u32, 32_768), entryValue(buf.items, 4));
    try testing.expectEqual(@as(u32, 1234), entryValue(buf.items, 5));

    const back = try settings.decode(buf.items);
    try testing.expectEqual(@as(u32, 8192), back.header_table_size.?);
    try testing.expectEqual(true, back.enable_push.?);
    try testing.expectEqual(@as(u32, 250), back.max_concurrent_streams.?);
    try testing.expectEqual(@as(u32, 1 << 20), back.initial_window_size.?);
    try testing.expectEqual(@as(u32, 32_768), back.max_frame_size.?);
    try testing.expectEqual(@as(u32, 1234), back.max_header_list_size.?);

    // The accessors agree with the decoded fields.
    try testing.expectEqual(@as(u32, 8192), back.headerTableSize());
    try testing.expectEqual(true, back.enablePush());
    try testing.expectEqual(@as(u32, 250), back.maxConcurrentStreams());
    try testing.expectEqual(@as(u32, 1 << 20), back.initialWindowSize());
    try testing.expectEqual(@as(u32, 32_768), back.maxFrameSize());
    try testing.expectEqual(@as(u32, 1234), back.maxHeaderListSize());
}

test "ours() is exactly 5 entries / 30 octets and carries the constants" {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);
    try settings.encodeOurs(testing.allocator, &buf);

    try testing.expectEqual(@as(usize, 30), buf.items.len);
    try testing.expectEqual(constants.advertised_settings_len, buf.items.len / 6);
    try testing.expectEqual(@as(usize, 5), buf.items.len / 6);

    // Non-tautological big-endian spot checks: id 2 / value 0 and
    // id 3 / value 128 (128 lands in the LAST octet, not the first).
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 }, buf.items[0..6]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x80 }, buf.items[6..12]);
    try testing.expectEqual(@as(u16, 0x0002), entryId(buf.items, 0));
    try testing.expectEqual(@as(u16, 0x0003), entryId(buf.items, 1));
    try testing.expectEqual(@as(u16, 0x0004), entryId(buf.items, 2));
    try testing.expectEqual(@as(u16, 0x0005), entryId(buf.items, 3));
    try testing.expectEqual(@as(u16, 0x0006), entryId(buf.items, 4));

    const s = try settings.decode(buf.items);
    try testing.expectEqual(constants.our_max_concurrent_streams, s.max_concurrent_streams.?);
    try testing.expectEqual(constants.our_initial_window_size, s.initial_window_size.?);
    try testing.expectEqual(constants.our_max_frame_size, s.max_frame_size.?);
    try testing.expectEqual(false, s.enable_push.?);
    try testing.expectEqual(constants.our_max_header_list_size, s.max_header_list_size.?);

    // HEADER_TABLE_SIZE is omitted on purpose: 4096 is the protocol default, so
    // omitting it and sending it are indistinguishable to the peer.
    try testing.expect(s.header_table_size == null);
    try testing.expectEqual(constants.our_header_table_size, s.headerTableSize());
    try testing.expectEqual(false, s.enablePush());

    // ours() and its encoding agree.
    const explicit = settings.ours();
    try testing.expectEqual(@as(u32, constants.our_initial_window_size), explicit.initialWindowSize());
    try testing.expectEqual(false, explicit.enablePush());
}

test "a payload that is not a whole number of entries is a frame size error" {
    try testing.expectError(error.FrameSizeError, settings.decode("abcde")); // 5 octets
    try testing.expectError(error.FrameSizeError, settings.decode(&[_]u8{ 0, 1, 0, 0, 0, 1, 0 })); // 7 octets
}

test "an empty payload is valid and decodes to all-null" {
    const s = try settings.decode("");
    try testing.expect(s.header_table_size == null);
    try testing.expect(s.enable_push == null);
    try testing.expect(s.max_concurrent_streams == null);
    try testing.expect(s.initial_window_size == null);
    try testing.expect(s.max_frame_size == null);
    try testing.expect(s.max_header_list_size == null);

    // The accessors fall back to the RFC 9113 §6.5.2 protocol defaults, not to
    // our own advertised values.
    try testing.expectEqual(constants.our_header_table_size, s.headerTableSize());
    try testing.expectEqual(true, s.enablePush());
    try testing.expectEqual(std.math.maxInt(u32), s.maxConcurrentStreams());
    try testing.expectEqual(constants.default_initial_window_size, s.initialWindowSize());
    try testing.expectEqual(constants.default_max_frame_size, s.maxFrameSize());
    try testing.expectEqual(std.math.maxInt(u32), s.maxHeaderListSize());
}

test "duplicate identifiers: the last value wins" {
    const payload = [_]u8{
        0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // max_frame_size = 16384
        0x00, 0x05, 0x00, 0x00, 0x80, 0x00, // max_frame_size = 32768
    };
    const s = try settings.decode(&payload);
    try testing.expectEqual(@as(u32, 32_768), s.max_frame_size.?);
}

test "unknown identifiers are ignored, not an error" {
    const payload = [_]u8{
        0x00, 0x99, 0xde, 0xad, 0xbe, 0xef, // unknown extension id
        0x00, 0x03, 0x00, 0x00, 0x00, 0x07, // max_concurrent_streams = 7
        0xff, 0xff, 0x00, 0x00, 0x00, 0x01, // another unknown id
    };
    const s = try settings.decode(&payload);
    try testing.expectEqual(@as(u32, 7), s.max_concurrent_streams.?);
    try testing.expect(s.max_frame_size == null);
}

test "out-of-range values are protocol errors" {
    // initial_window_size = 2^31 (one above the maximum)
    try testing.expectError(error.ProtocolError, settings.decode(&[_]u8{ 0x00, 0x04, 0x80, 0x00, 0x00, 0x00 }));
    // max_frame_size = 16383 (one below the floor)
    try testing.expectError(error.ProtocolError, settings.decode(&[_]u8{ 0x00, 0x05, 0x00, 0x00, 0x3f, 0xff }));
    // max_frame_size = 2^24 (one above the ceiling)
    try testing.expectError(error.ProtocolError, settings.decode(&[_]u8{ 0x00, 0x05, 0x01, 0x00, 0x00, 0x00 }));
    // max_frame_size = 0
    try testing.expectError(error.ProtocolError, settings.decode(&[_]u8{ 0x00, 0x05, 0x00, 0x00, 0x00, 0x00 }));
    // enable_push = 2
    try testing.expectError(error.ProtocolError, settings.decode(&[_]u8{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x02 }));

    // The boundaries themselves are legal.
    const lo = try settings.decode(&[_]u8{ 0x00, 0x05, 0x00, 0x00, 0x40, 0x00 }); // 16384
    try testing.expectEqual(@as(u32, 16_384), lo.max_frame_size.?);
    const hi = try settings.decode(&[_]u8{ 0x00, 0x05, 0x00, 0xff, 0xff, 0xff }); // 16777215
    try testing.expectEqual(constants.max_allowed_frame_size, hi.max_frame_size.?);
    const win = try settings.decode(&[_]u8{ 0x00, 0x04, 0x7f, 0xff, 0xff, 0xff }); // 2^31-1
    try testing.expectEqual(@as(u32, 2_147_483_647), win.initial_window_size.?);
    // enable_push = 0 and 1 are both legal.
    try testing.expectEqual(false, (try settings.decode(&[_]u8{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 })).enable_push.?);
    try testing.expectEqual(true, (try settings.decode(&[_]u8{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x01 })).enable_push.?);
}

test "Settings{} (nothing present) encodes to zero octets" {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);
    try settings.encode(testing.allocator, &buf, .{});
    try testing.expectEqual(@as(usize, 0), buf.items.len);
}

test "an explicit enable_push = false is encoded and survives decoding" {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);
    try settings.encode(testing.allocator, &buf, .{ .enable_push = false });

    try testing.expectEqual(@as(usize, 6), buf.items.len);
    try testing.expectEqual(@as(u16, 0x0002), entryId(buf.items, 0));
    try testing.expectEqual(@as(u32, 0), entryValue(buf.items, 0));

    const s = try settings.decode(buf.items);
    try testing.expectEqual(false, s.enable_push.?);
    try testing.expectEqual(false, s.enablePush());
}

test "encode appends to an existing buffer without disturbing it" {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, "PREFIX");

    try settings.encode(testing.allocator, &buf, .{ .max_frame_size = 16_384 });
    try testing.expectEqual(@as(usize, 6 + 6), buf.items.len);
    try testing.expectEqualStrings("PREFIX", buf.items[0..6]);
    try testing.expectEqual(@as(u16, 0x0005), entryId(buf.items[6..], 0));
    try testing.expectEqual(@as(u32, 16_384), entryValue(buf.items[6..], 0));

    // SETTINGS payloads are self-contained: decode ignores nothing but its own
    // length, so a mis-sized prefix must be rejected rather than skipped.
    try testing.expectError(error.FrameSizeError, settings.decode(buf.items[1..]));
}
