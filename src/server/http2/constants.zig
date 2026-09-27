//! HTTP/2 (RFC 9113) + HPACK (RFC 7541) constants.
//!
//! Std-only, no I/O, no allocation. Every other `http2/*.zig` file depends on
//! this one, so it is deliberately dependency-free.

const std = @import("std");

/// The HTTP/2 connection preface a client must send first (RFC 9113 §3.4).
pub const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const preface_len = PREFACE.len; // 24

/// True when `bytes` *starts with* the full preface. Shorter slices are false.
pub fn isPreface(bytes: []const u8) bool {
    if (bytes.len < PREFACE.len) return false;
    return std.mem.eql(u8, bytes[0..PREFACE.len], PREFACE);
}

/// True when `bytes` is a prefix of the preface and could still become the
/// preface with more data (used by the server's sniffer). Never true for an
/// empty slice.
pub fn isPrefacePrefix(bytes: []const u8) bool {
    if (bytes.len == 0 or bytes.len > PREFACE.len) return false;
    return std.mem.eql(u8, bytes, PREFACE[0..bytes.len]);
}

pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

/// Frame flag bits. Flags are per-frame-type, so several share a value.
pub const flag_end_stream: u8 = 0x1;
pub const flag_ack: u8 = 0x1;
pub const flag_end_headers: u8 = 0x4;
pub const flag_padded: u8 = 0x8;
pub const flag_priority: u8 = 0x20;

pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,
};

pub const SettingId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    _,
};

pub const frame_header_len = 9;

// ─── Protocol constants (RFC 9113) ──────────────────────────────────────────

pub const default_max_frame_size: u32 = 16_384;
pub const max_allowed_frame_size: u32 = 16_777_215; // 2^24 - 1
pub const default_initial_window_size: u32 = 65_535;
pub const max_window_size: i64 = 2_147_483_647; // 2^31 - 1

// ─── What *we* advertise / enforce ──────────────────────────────────────────

pub const our_max_concurrent_streams: u32 = 128;
pub const our_initial_window_size: u32 = 1_048_576; // 1 MiB, per stream
pub const our_max_frame_size: u32 = default_max_frame_size;
pub const our_max_header_list_size: u32 = 65_536;
pub const our_header_table_size: u32 = 4096;

/// SETTINGS ids we advertise, in the order they are emitted.
pub const advertised_settings_len = 5;

// ============================================================================
// Tests — moved here from `constants_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = constants_tests; }` below pulls them into the run.
// ============================================================================

const constants_tests = struct {
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
};

comptime {
    _ = constants_tests;
}
