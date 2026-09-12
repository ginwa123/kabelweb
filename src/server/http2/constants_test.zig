const std = @import("std");
const constants = @import("constants.zig");
const testing = std.testing;

test "preface: exact match and prefix handling" {
    try testing.expect(constants.isPreface(constants.PREFACE));
    try testing.expect(constants.isPreface(constants.PREFACE ++ "extra bytes"));

    // One byte short is not the preface.
    try testing.expect(!constants.isPreface(constants.PREFACE[0 .. constants.PREFACE.len - 1]));
    try testing.expect(!constants.isPreface(""));
    try testing.expect(!constants.isPreface("GET / HTTP/1.1\r\n\r\n"));
    // Same length, different content.
    try testing.expect(!constants.isPreface("PRI * HTTP/2.0\r\n\r\nSM\r\n\rX"));
}

test "preface: isPrefacePrefix accepts only proper prefixes" {
    try testing.expect(constants.isPrefacePrefix("P"));
    try testing.expect(constants.isPrefacePrefix("PRI * HTTP/2.0\r\n\r\nSM\r\n\r"));
    try testing.expect(constants.isPrefacePrefix(constants.PREFACE));
    try testing.expect(!constants.isPrefacePrefix(""));
    try testing.expect(!constants.isPrefacePrefix("GET "));
    try testing.expect(!constants.isPrefacePrefix(constants.PREFACE ++ "x"));
}

test "preface: the embedded CRLFCRLF sits at byte 14 (read-ahead trap)" {
    // The h1 reader stops at the first CRLFCRLF; the preface contains one at
    // offset 14 ("PRI * HTTP/2.0" is 14 bytes). This is exactly why the server
    // must sniff BEFORE the HTTP/1.1 parser (plan task T19 / risk R1).
    const idx = std.mem.indexOf(u8, constants.PREFACE, "\r\n\r\n").?;
    try testing.expectEqual(@as(usize, 14), idx);
    try testing.expectEqual(@as(usize, 24), constants.preface_len);
}

test "frame types and flags have the RFC wire values" {
    try testing.expectEqual(@as(u8, 0x0), @intFromEnum(constants.FrameType.data));
    try testing.expectEqual(@as(u8, 0x1), @intFromEnum(constants.FrameType.headers));
    try testing.expectEqual(@as(u8, 0x2), @intFromEnum(constants.FrameType.priority));
    try testing.expectEqual(@as(u8, 0x3), @intFromEnum(constants.FrameType.rst_stream));
    try testing.expectEqual(@as(u8, 0x4), @intFromEnum(constants.FrameType.settings));
    try testing.expectEqual(@as(u8, 0x5), @intFromEnum(constants.FrameType.push_promise));
    try testing.expectEqual(@as(u8, 0x6), @intFromEnum(constants.FrameType.ping));
    try testing.expectEqual(@as(u8, 0x7), @intFromEnum(constants.FrameType.goaway));
    try testing.expectEqual(@as(u8, 0x8), @intFromEnum(constants.FrameType.window_update));
    try testing.expectEqual(@as(u8, 0x9), @intFromEnum(constants.FrameType.continuation));

    try testing.expectEqual(@as(u8, 0x1), constants.flag_end_stream);
    try testing.expectEqual(@as(u8, 0x1), constants.flag_ack);
    try testing.expectEqual(@as(u8, 0x4), constants.flag_end_headers);
    try testing.expectEqual(@as(u8, 0x8), constants.flag_padded);
    try testing.expectEqual(@as(u8, 0x20), constants.flag_priority);
}

test "error codes and setting ids have the RFC wire values" {
    try testing.expectEqual(@as(u32, 0x0), @intFromEnum(constants.ErrorCode.no_error));
    try testing.expectEqual(@as(u32, 0x1), @intFromEnum(constants.ErrorCode.protocol_error));
    try testing.expectEqual(@as(u32, 0x9), @intFromEnum(constants.ErrorCode.compression_error));
    try testing.expectEqual(@as(u32, 0xb), @intFromEnum(constants.ErrorCode.enhance_your_calm));
    try testing.expectEqual(@as(u32, 0xd), @intFromEnum(constants.ErrorCode.http_1_1_required));

    try testing.expectEqual(@as(u16, 0x1), @intFromEnum(constants.SettingId.header_table_size));
    try testing.expectEqual(@as(u16, 0x4), @intFromEnum(constants.SettingId.initial_window_size));
    try testing.expectEqual(@as(u16, 0x5), @intFromEnum(constants.SettingId.max_frame_size));
}

test "our advertised limits are internally consistent" {
    try testing.expectEqual(@as(u32, 9), constants.frame_header_len);
    try testing.expectEqual(@as(u32, 16_384), constants.our_max_frame_size);
    try testing.expect(constants.our_max_frame_size <= constants.max_allowed_frame_size);
    try testing.expect(constants.our_initial_window_size >= constants.default_initial_window_size);
    try testing.expect(@as(i64, constants.our_initial_window_size) <= constants.max_window_size);
    try testing.expect(constants.our_max_concurrent_streams > 0);
    try testing.expectEqual(@as(u32, 5), constants.advertised_settings_len);
}
