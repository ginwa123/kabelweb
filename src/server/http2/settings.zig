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

// ============================================================================
// Tests — moved here from `settings_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = settings_tests; }` below pulls them into the run.
// ============================================================================

const settings_tests = struct {
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
};

comptime {
    _ = settings_tests;
}
