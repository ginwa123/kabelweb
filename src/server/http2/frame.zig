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

test {
    _ = @import("frame_test.zig");
}
