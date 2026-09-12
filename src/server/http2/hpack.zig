//! HPACK header compression (RFC 7541).
//!
//! This file implements the four primitive codecs (§5.1 integers, §5.2 strings,
//! §6.1/6.2 indexed + literal representations, §6.3 dynamic table size update)
//! plus a stateful Decoder that owns the dynamic table, and a deliberately
//! simple Encoder.
//!
//! The Encoder never writes to a dynamic table. WHY: an encoder that never adds
//! entries can never desynchronise with the decoder, and it still produces
//! spec-legal blocks (static-table indexing + literal-without-indexing). That
//! keeps the first cut obviously correct; richer encoders can layer on later
//! without changing this interface.
//!
//! Decoding is where correctness actually matters, so the Decoder is strict:
//! malformed representations, out-of-range indices, undersized table updates
//! and oversized header lists are all rejected rather than papered over.

const std = @import("std");
const huffman = @import("huffman.zig");
const tables = @import("generated_tables.zig");

pub const Pair = struct { name: []const u8, value: []const u8 };

pub const Error = error{
    CompressionError,
    HeaderListTooLarge,
    IntegerOverflow,
    InvalidHuffmanCode,
    OutOfMemory,
};

/// Per-entry overhead mandated by RFC 7541 §4.1 (counts the 32-byte
/// bookkeeping the spec assumes).
const entry_overhead: usize = 32;

// ─── §5.1 Integer representation ────────────────────────────────────────────

/// Decode a prefixed integer. `prefix_bits` is N (1..8); the first octet's low
/// N bits are the value's low bits, and any higher bits are the caller's
/// representation flags (masked off here). Returns the value and how many
/// octets were consumed.
pub fn decodeInteger(data: []const u8, prefix_bits: u5) Error!struct { value: usize, consumed: usize } {
    if (data.len == 0) return error.CompressionError;

    const max_prefix: usize = (@as(usize, 1) << prefix_bits) - 1;
    var value: usize = @as(usize, data[0]) & max_prefix;
    var pos: usize = 1;
    // Fast path: the whole value fit in the prefix.
    if (value < max_prefix) return .{ .value = value, .consumed = pos };

    var shift: u6 = 0;
    while (true) {
        if (pos >= data.len) return error.CompressionError; // truncated continuation
        const b = data[pos];
        pos += 1;
        const m: usize = b & 0x7f;

        // RFC 7541 §5.1 caps integers at 2^32-1. The first octet already
        // supplies up to 8 bits, so a continuation at shift 28 may only carry
        // the 4 remaining bits, and anything at shift >= 32 is out of range.
        if (shift >= 32) return error.IntegerOverflow;
        if (shift == 28 and m > 0x0f) return error.IntegerOverflow;

        value += m << shift;
        if (b & 0x80 == 0) break; // high bit clear: last octet
        shift += 7;
    }
    return .{ .value = value, .consumed = pos };
}

/// Encode `value` with an N-bit prefix. `prefix` carries the representation
/// bits to OR into the first octet (e.g. 0x40 for literal-with-incremental-
/// indexing); pass 0 when there are none. Its low `prefix_bits` must be zero.
pub fn encodeInteger(alloc: std.mem.Allocator, out: *std.ArrayList(u8), value: usize, prefix_bits: u5, prefix: u8) !void {
    const max_prefix: usize = (@as(usize, 1) << prefix_bits) - 1;
    if (value < max_prefix) {
        try out.append(alloc, prefix | @as(u8, @intCast(value)));
        return;
    }
    try out.append(alloc, prefix | @as(u8, @intCast(max_prefix)));
    var rem = value - max_prefix;
    while (rem >= 128) {
        try out.append(alloc, @as(u8, @intCast(rem & 0x7f)) | 0x80);
        rem >>= 7;
    }
    try out.append(alloc, @as(u8, @intCast(rem)));
}

// ─── §5.2 String literal representation ─────────────────────────────────────

/// Decode a length-prefixed string. The returned slice is allocated with
/// `alloc`; Huffman payloads are decoded first. High bit of the first octet is
/// the Huffman flag, the low 7 bits are the length prefix.
pub fn decodeString(alloc: std.mem.Allocator, data: []const u8) Error!struct { value: []const u8, consumed: usize } {
    if (data.len == 0) return error.CompressionError;
    const is_huffman = data[0] & 0x80 != 0;

    const len = try decodeInteger(data, 7);
    if (len.consumed > data.len) return error.CompressionError;
    if (len.value > data.len - len.consumed) return error.CompressionError; // truncated payload
    const consumed = len.consumed + len.value;
    const raw = data[len.consumed..consumed];

    if (is_huffman) {
        const decoded = try huffman.decode(alloc, raw);
        return .{ .value = decoded, .consumed = consumed };
    }
    return .{ .value = try alloc.dupe(u8, raw), .consumed = consumed };
}

/// Encode a string literal without Huffman. Always legal, and simpler to
/// reason about than the Huffman path.
pub fn encodeString(alloc: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    try encodeInteger(alloc, out, value.len, 7, 0x00);
    try out.appendSlice(alloc, value);
}

// ─── Appendix A static table helpers ────────────────────────────────────────

/// 1-based index of the exact (name, value) static entry, or null.
pub fn findStaticIndex(name: []const u8, value: []const u8) ?usize {
    for (tables.static_table, 0..) |e, i| {
        if (std.mem.eql(u8, e.name, name) and std.mem.eql(u8, e.value, value)) return i + 1;
    }
    return null;
}

/// 1-based index of the first static entry whose name matches, or null.
pub fn findStaticName(name: []const u8) ?usize {
    for (tables.static_table, 0..) |e, i| {
        if (std.mem.eql(u8, e.name, name)) return i + 1;
    }
    return null;
}

/// Static entry at 1-based `index` (1..61). Returned slices are borrowed.
pub fn staticEntry(index: usize) Pair {
    std.debug.assert(index >= 1 and index <= tables.static_table.len);
    const e = tables.static_table[index - 1];
    return .{ .name = e.name, .value = e.value };
}

// ─── Decoder ────────────────────────────────────────────────────────────────

/// Stateful HPACK decoder. Owns the dynamic table; header-list entries handed
/// to the caller are separately allocated so they never alias table state (a
/// later eviction inside the same block can't pull a name out from under you).
pub const Decoder = struct {
    alloc: std.mem.Allocator,
    /// Hard ceiling from SETTINGS_HEADER_TABLE_SIZE; a size update may never
    /// exceed it.
    max_table_size: u32,
    /// Maximum decoded header list size (sum of name+value+32), 0 = no limit
    /// is not assumed here — callers pass a real cap.
    max_header_list_size: u32,
    /// Current table limit, mutable via §6.3 dynamic table size updates.
    table_size: u32,
    /// Bytes currently occupied by `entries`.
    used_size: u32,
    /// Newest entry first (dynamic index 1 == items[0]).
    entries: std.ArrayList(Pair),

    pub fn init(alloc: std.mem.Allocator, max_table_size: u32, max_header_list_size: u32) Decoder {
        return .{
            .alloc = alloc,
            .max_table_size = max_table_size,
            .max_header_list_size = max_header_list_size,
            .table_size = max_table_size,
            .used_size = 0,
            .entries = std.ArrayList(Pair).empty,
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.freeEntries();
        self.entries.deinit(self.alloc);
    }

    pub fn dynamicTableSize(self: *Decoder) u32 {
        return self.used_size;
    }

    pub fn dynamicTableCount(self: *Decoder) usize {
        return self.entries.items.len;
    }

    fn freeEntries(self: *Decoder) void {
        for (self.entries.items) |e| {
            self.alloc.free(e.name);
            self.alloc.free(e.value);
        }
        self.entries.clearRetainingCapacity();
    }

    fn clear(self: *Decoder) void {
        self.freeEntries();
        self.used_size = 0;
    }

    fn evictOldest(self: *Decoder) void {
        const last = self.entries.pop() orelse return;
        const sz: u32 = @intCast(last.name.len + last.value.len + entry_overhead);
        self.used_size -= @min(self.used_size, sz);
        self.alloc.free(last.name);
        self.alloc.free(last.value);
    }

    /// Drop oldest entries until the table fits its current limit.
    fn evictToFit(self: *Decoder) void {
        while (self.used_size > self.table_size and self.entries.items.len > 0) {
            self.evictOldest();
        }
    }

    /// §6.3: lower (or re-raise, within the ceiling) the table size.
    fn setTableSize(self: *Decoder, new_size: u32) Error!void {
        if (new_size > self.max_table_size) return error.CompressionError;
        self.table_size = new_size;
        self.evictToFit();
    }

    /// §4.4: insert at the newest position, evicting oldest entries as needed.
    /// An entry larger than the whole table empties it instead of being stored.
    fn addEntry(self: *Decoder, name: []const u8, value: []const u8) Error!void {
        const raw_size = name.len + value.len + entry_overhead;
        if (raw_size > std.math.maxInt(u32)) return error.CompressionError;
        const entry_size: u32 = @intCast(raw_size);

        if (entry_size > self.table_size) {
            self.clear();
            return;
        }
        while (self.used_size + entry_size > self.table_size) {
            if (self.entries.items.len == 0) {
                self.used_size = 0;
                break;
            }
            self.evictOldest();
        }

        const n = try self.alloc.dupe(u8, name);
        errdefer self.alloc.free(n);
        const v = try self.alloc.dupe(u8, value);
        errdefer self.alloc.free(v);
        try self.entries.insert(self.alloc, 0, .{ .name = n, .value = v });
        self.used_size += entry_size;
    }

    /// Resolve a 1-based index against the static table (1..61) then the
    /// dynamic table (62..). Returned slices are borrowed from the tables.
    fn lookup(self: *Decoder, index: usize) Error!Pair {
        if (index == 0) return error.CompressionError;
        if (index <= tables.static_table.len) {
            const e = tables.static_table[index - 1];
            return .{ .name = e.name, .value = e.value };
        }
        const d = index - (tables.static_table.len + 1); // 0 == newest
        if (d >= self.entries.items.len) return error.CompressionError;
        return self.entries.items[d];
    }

    /// Append a header-list entry with its own copies of name and value.
    fn appendHeader(self: *Decoder, out: *std.ArrayList(Pair), name: []const u8, value: []const u8) Error!void {
        const n = try self.alloc.dupe(u8, name);
        errdefer self.alloc.free(n);
        const v = try self.alloc.dupe(u8, value);
        errdefer self.alloc.free(v);
        try out.append(self.alloc, .{ .name = n, .value = v });
    }

    const ResolvedName = struct { name: []const u8, owned: bool, consumed: usize };

    /// Resolve the name portion of a literal representation: index 0 means the
    /// name follows as a string literal (owned by us), otherwise it is an index
    /// into the static or dynamic table (borrowed).
    fn readName(self: *Decoder, data: []const u8, index: usize) Error!ResolvedName {
        if (index == 0) {
            const s = try decodeString(self.alloc, data);
            return .{ .name = s.value, .owned = true, .consumed = s.consumed };
        }
        const e = try self.lookup(index);
        return .{ .name = e.name, .owned = false, .consumed = 0 };
    }

    /// Decode one header block. Appends to `out`; every appended pair is owned
    /// by the caller (free with the same allocator).
    pub fn decode(self: *Decoder, block: []const u8, out: *std.ArrayList(Pair)) Error!void {
        var pos: usize = 0;
        var list_size: usize = 0;

        while (pos < block.len) {
            const b = block[pos];

            if (b & 0x80 != 0) {
                // §6.1 Indexed Header Field (1xxxxxxx)
                const iv = try decodeInteger(block[pos..], 7);
                pos += iv.consumed;
                const e = try self.lookup(iv.value);
                try self.appendHeader(out, e.name, e.value);
                list_size += e.name.len + e.value.len + entry_overhead;
                if (list_size > self.max_header_list_size) return error.HeaderListTooLarge;
            } else if (b & 0x40 != 0) {
                // §6.2.1 Literal Header Field with Incremental Indexing (01xxxxxx)
                const iv = try decodeInteger(block[pos..], 6);
                pos += iv.consumed;
                const named = try self.readName(block[pos..], iv.value);
                defer {
                    if (named.owned) self.alloc.free(named.name);
                }
                pos += named.consumed;

                const vs = try decodeString(self.alloc, block[pos..]);
                defer self.alloc.free(vs.value);
                pos += vs.consumed;

                try self.appendHeader(out, named.name, vs.value);
                list_size += named.name.len + vs.value.len + entry_overhead;
                try self.addEntry(named.name, vs.value);
                if (list_size > self.max_header_list_size) return error.HeaderListTooLarge;
            } else if (b & 0x20 != 0) {
                // §6.3 Dynamic Table Size Update (001xxxxx)
                const iv = try decodeInteger(block[pos..], 5);
                pos += iv.consumed;
                if (iv.value > std.math.maxInt(u32)) return error.CompressionError;
                try self.setTableSize(@intCast(iv.value));
            } else {
                // §6.2.2 Literal without Indexing (0000xxxx) and
                // §6.2.3 Literal Never Indexed (0001xxxx): same wire shape,
                // and neither touches the dynamic table.
                const iv = try decodeInteger(block[pos..], 4);
                pos += iv.consumed;
                const named = try self.readName(block[pos..], iv.value);
                defer {
                    if (named.owned) self.alloc.free(named.name);
                }
                pos += named.consumed;

                const vs = try decodeString(self.alloc, block[pos..]);
                defer self.alloc.free(vs.value);
                pos += vs.consumed;

                try self.appendHeader(out, named.name, vs.value);
                list_size += named.name.len + vs.value.len + entry_overhead;
                if (list_size > self.max_header_list_size) return error.HeaderListTooLarge;
            }
        }
    }
};

// ─── Encoder ────────────────────────────────────────────────────────────────

/// Minimal-correct HPACK encoder. Static-table exact matches use the indexed
/// form; everything else uses literal-without-indexing (0x00) with a static
/// name index when available, else an inline name. It never adds to a dynamic
/// table, so both sides stay trivially in sync.
pub const Encoder = struct {
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) Encoder {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Encoder) void {
        _ = self;
    }

    pub fn encode(self: *Encoder, headers: []const Pair, out: *std.ArrayList(u8)) !void {
        for (headers) |h| {
            if (findStaticIndex(h.name, h.value)) |idx| {
                try encodeInteger(self.alloc, out, idx, 7, 0x80);
                continue;
            }

            // Literal without indexing: represent the name by static index if
            // we can, otherwise inline it (index 0).
            if (findStaticName(h.name)) |name_idx| {
                try encodeInteger(self.alloc, out, name_idx, 4, 0x00);
            } else {
                try encodeInteger(self.alloc, out, 0, 4, 0x00);
                try encodeString(self.alloc, out, h.name);
            }
            try encodeString(self.alloc, out, h.value);
        }
    }
};

test {
    _ = @import("hpack_test.zig");
}
