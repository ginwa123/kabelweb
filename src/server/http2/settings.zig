//! SETTINGS frame payload codec (RFC 9113 §6.5).
//!
//! A SETTINGS payload is a list of 6-octet entries: a 2-octet identifier and a
//! 4-octet value. Identifiers are not a closed set — a peer may send settings we
//! do not implement, and those MUST be ignored rather than rejected. Everything
//! here is pure; `Settings` is the decoded, typed view of one payload.

const std = @import("std");
const constants = @import("constants.zig");

/// One 6-octet entry: u16 identifier + u32 value.
const entry_len: usize = 6;

/// One optional value per SETTINGS identifier. `null` means "the peer did not
/// send this setting", which is different from "the peer sent zero" — the
/// accessors below resolve a missing entry to its protocol default.
pub const Settings = struct {
    header_table_size: ?u32 = null,
    enable_push: ?bool = null,
    max_concurrent_streams: ?u32 = null,
    initial_window_size: ?u32 = null,
    max_frame_size: ?u32 = null,
    max_header_list_size: ?u32 = null,

    /// SETTINGS_HEADER_TABLE_SIZE defaults to 4096 (RFC 9113 §6.5.2) — the same
    /// number we advertise, so one constant serves both directions.
    pub fn headerTableSize(self: Settings) u32 {
        return self.header_table_size orelse constants.our_header_table_size;
    }

    /// ENABLE_PUSH defaults to 1 for a peer that stays silent (RFC 9113
    /// §6.5.2). Note this is the peer's default, not our advertised `false`.
    pub fn enablePush(self: Settings) bool {
        return self.enable_push orelse true;
    }

    /// MAX_CONCURRENT_STREAMS has no protocol default ("unlimited"), which we
    /// represent as the largest u32.
    pub fn maxConcurrentStreams(self: Settings) u32 {
        return self.max_concurrent_streams orelse std.math.maxInt(u32);
    }

    /// How much data the peer will let us have in flight: its advertised
    /// receive window, default 65535 (§6.5.2) — deliberately not our own larger
    /// advertised value.
    pub fn initialWindowSize(self: Settings) u32 {
        return self.initial_window_size orelse constants.default_initial_window_size;
    }

    /// Largest frame the peer is willing to receive from us; default 16384.
    pub fn maxFrameSize(self: Settings) u32 {
        return self.max_frame_size orelse constants.default_max_frame_size;
    }

    /// MAX_HEADER_LIST_SIZE has no protocol default; "unlimited" is the largest
    /// u32.
    pub fn maxHeaderListSize(self: Settings) u32 {
        return self.max_header_list_size orelse std.math.maxInt(u32);
    }
};

pub const Error = error{ FrameSizeError, ProtocolError };

/// Decode a SETTINGS payload into a `Settings`.
///
/// Duplicate identifiers are legal and the last occurrence wins. Unknown
/// identifiers are ignored. Values outside their legal range are protocol
/// errors as required by RFC 9113 §6.5.2.
pub fn decode(payload: []const u8) Error!Settings {
    // A payload that is not a whole number of entries cannot be parsed; RFC
    // 9113 §6.5 calls this FRAME_SIZE_ERROR.
    if (payload.len % entry_len != 0) return error.FrameSizeError;

    var s = Settings{};
    var i: usize = 0;
    while (i < payload.len) : (i += entry_len) {
        const id = std.mem.readInt(u16, payload[i..][0..2], .big);
        const value = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);

        // Unknown identifiers MUST be ignored (§6.5.2) — peers legitimately
        // send extensions, and a new draft must not kill the connection.
        switch (id) {
            @intFromEnum(constants.SettingId.header_table_size) => s.header_table_size = value,
            @intFromEnum(constants.SettingId.enable_push) => {
                if (value > 1) return error.ProtocolError;
                s.enable_push = value == 1;
            },
            @intFromEnum(constants.SettingId.max_concurrent_streams) => s.max_concurrent_streams = value,
            @intFromEnum(constants.SettingId.initial_window_size) => {
                // Values above 2^31-1 would make flow-control arithmetic
                // overflow; RFC 9113 §6.5.2 makes them a protocol error.
                if (@as(i64, value) > constants.max_window_size) return error.ProtocolError;
                s.initial_window_size = value;
            },
            @intFromEnum(constants.SettingId.max_frame_size) => {
                // The peer picks the frame size *we* must use, within the
                // protocol's fixed bounds.
                if (value < constants.default_max_frame_size or value > constants.max_allowed_frame_size) {
                    return error.ProtocolError;
                }
                s.max_frame_size = value;
            },
            @intFromEnum(constants.SettingId.max_header_list_size) => s.max_header_list_size = value,
            else => {},
        }
    }
    return s;
}

/// Append the 6-octet encoding of every present field, in struct-declaration
/// order (which is ascending identifier order).
pub fn encode(alloc: std.mem.Allocator, out: *std.ArrayList(u8), s: Settings) !void {
    if (s.header_table_size) |v| try encodeEntry(alloc, out, .header_table_size, v);
    if (s.enable_push) |v| try encodeEntry(alloc, out, .enable_push, @intFromBool(v));
    if (s.max_concurrent_streams) |v| try encodeEntry(alloc, out, .max_concurrent_streams, v);
    if (s.initial_window_size) |v| try encodeEntry(alloc, out, .initial_window_size, v);
    if (s.max_frame_size) |v| try encodeEntry(alloc, out, .max_frame_size, v);
    if (s.max_header_list_size) |v| try encodeEntry(alloc, out, .max_header_list_size, v);
}

/// The SETTINGS this server advertises. `constants.zig` is the only source of
/// the values; `constants.advertised_settings_len` counts the entries.
pub fn ours() Settings {
    return .{
        // ENABLE_PUSH=false: this server never pushes. HEADER_TABLE_SIZE is
        // deliberately left unset — the protocol default (4096) already equals
        // the value we want, so sending it would only waste 6 octets.
        .enable_push = false,
        .max_concurrent_streams = constants.our_max_concurrent_streams,
        .initial_window_size = constants.our_initial_window_size,
        .max_frame_size = constants.our_max_frame_size,
        .max_header_list_size = constants.our_max_header_list_size,
    };
}

pub fn encodeOurs(alloc: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    return encode(alloc, out, ours());
}

fn encodeEntry(alloc: std.mem.Allocator, out: *std.ArrayList(u8), id: constants.SettingId, value: u32) !void {
    var entry: [entry_len]u8 = undefined;
    std.mem.writeInt(u16, entry[0..2], @intFromEnum(id), .big);
    std.mem.writeInt(u32, entry[2..6], value, .big);
    try out.appendSlice(alloc, &entry);
}

test {
    _ = @import("settings_test.zig");
}
