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

test {
    _ = @import("constants_test.zig");
}
