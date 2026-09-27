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

// ============================================================================
// Tests — moved here from `hpack_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = hpack_tests; }` below pulls them into the run.
// ============================================================================

const hpack_tests = struct {
    const hpack = @import("hpack.zig");
    const vectors = @import("rfc7541_vectors.zig");
    const testing = std.testing;

    fn freePairs(alloc: std.mem.Allocator, list: *std.ArrayList(hpack.Pair)) void {
        for (list.items) |p| {
            alloc.free(p.name);
            alloc.free(p.value);
        }
        list.deinit(alloc);
    }

    fn expectPairsEqual(expected: anytype, actual: []const hpack.Pair) !void {
        try testing.expectEqual(expected.len, actual.len);
        for (expected, actual) |e, a| {
            try testing.expectEqualSlices(u8, e.name, a.name);
            try testing.expectEqualSlices(u8, e.value, a.value);
        }
    }

    fn expectDecodeError(expected: anyerror, dec: *hpack.Decoder, block: []const u8) !void {
        var out = std.ArrayList(hpack.Pair).empty;
        defer freePairs(testing.allocator, &out);
        try testing.expectError(expected, dec.decode(block, &out));
    }

    // ─── 1. Integer vectors (RFC 7541 C.1) ──────────────────────────────────────

    test "RFC 7541 C.1 integer vectors round-trip" {
        for (vectors.integer_vectors) |v| {
            var out = std.ArrayList(u8).empty;
            defer out.deinit(testing.allocator);
            try hpack.encodeInteger(testing.allocator, &out, v.value, v.prefix_bits, v.initial_byte);
            try testing.expectEqualSlices(u8, v.expected, out.items);

            const dec = try hpack.decodeInteger(v.expected, v.prefix_bits);
            try testing.expectEqual(v.value, dec.value);
            try testing.expectEqual(v.expected.len, dec.consumed);
        }
    }

    // ─── 2. Integer edge cases ──────────────────────────────────────────────────

    test "integer boundary: prefix maximum vs one past it vs 1337" {
        // 30 is the largest value that fits a 5-bit prefix in one octet.
        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(testing.allocator);

        try hpack.encodeInteger(testing.allocator, &buf, 30, 5, 0x00);
        try testing.expectEqualSlices(u8, "\x1e", buf.items);
        const v30 = try hpack.decodeInteger("\x1e", 5);
        try testing.expectEqual(@as(usize, 30), v30.value);
        try testing.expectEqual(@as(usize, 1), v30.consumed);

        // Exactly the prefix maximum must still take a (zero) continuation octet.
        buf.clearRetainingCapacity();
        try hpack.encodeInteger(testing.allocator, &buf, 31, 5, 0x00);
        try testing.expectEqualSlices(u8, "\x1f\x00", buf.items);
        const v31 = try hpack.decodeInteger("\x1f\x00", 5);
        try testing.expectEqual(@as(usize, 31), v31.value);
        try testing.expectEqual(@as(usize, 2), v31.consumed);

        // One more than the maximum.
        buf.clearRetainingCapacity();
        try hpack.encodeInteger(testing.allocator, &buf, 32, 5, 0x00);
        try testing.expectEqualSlices(u8, "\x1f\x01", buf.items);
        const v32 = try hpack.decodeInteger("\x1f\x01", 5);
        try testing.expectEqual(@as(usize, 32), v32.value);
        try testing.expectEqual(@as(usize, 2), v32.consumed);

        // RFC C.1.2.
        const v1337 = try hpack.decodeInteger("\x1f\x9a\x0a", 5);
        try testing.expectEqual(@as(usize, 1337), v1337.value);
        try testing.expectEqual(@as(usize, 3), v1337.consumed);
    }

    test "integer: four-octet multi-octet value, truncation and overflow" {
        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(testing.allocator);

        const big: usize = 0x0fff_ffff; // 28 bits -> multi-octet
        try hpack.encodeInteger(testing.allocator, &buf, big, 8, 0x00);
        try testing.expect(buf.items.len >= 4);
        const round = try hpack.decodeInteger(buf.items, 8);
        try testing.expectEqual(big, round.value);
        try testing.expectEqual(buf.items.len, round.consumed);

        // An incomplete multi-octet sequence (continuation bit set, no next octet).
        try testing.expectError(error.CompressionError, hpack.decodeInteger("\x1f\x80", 5));
        // Empty input has no integer at all.
        try testing.expectError(error.CompressionError, hpack.decodeInteger("", 5));

        // Continuations that would need more than 32 bits.
        try testing.expectError(error.IntegerOverflow, hpack.decodeInteger("\xff\xff\xff\xff\xff\xff", 8));
    }

    // ─── 3. Block vectors (RFC 7541 C.2) ────────────────────────────────────────

    test "RFC 7541 C.2 block vectors decode to the exact header lists" {
        for (vectors.block_vectors) |v| {
            var dec = hpack.Decoder.init(testing.allocator, v.table_size, 4096);
            defer dec.deinit();
            var out = std.ArrayList(hpack.Pair).empty;
            defer freePairs(testing.allocator, &out);
            try dec.decode(v.block, &out);
            try expectPairsEqual(v.expected, out.items);
        }
    }

    // ─── 4. Full request/response cases (RFC 7541 C.3-C.6) ──────────────────────

    test "RFC 7541 C.3-C.6 cases decode step-by-step on a persistent decoder" {
        for (vectors.cases) |c| {
            var dec = hpack.Decoder.init(testing.allocator, c.table_size, 65536);
            defer dec.deinit();
            for (c.steps) |step| {
                var out = std.ArrayList(hpack.Pair).empty;
                defer freePairs(testing.allocator, &out);
                // The SAME decoder spans the steps: the dynamic table (and its
                // eviction behaviour) must carry over, which is what makes C.5/C.6
                // a real test of dynamic indexing.
                try dec.decode(step.block, &out);
                try expectPairsEqual(step.expected, out.items);
            }
        }
    }

    test "decoder dynamic table accounting" {
        var dec = hpack.Decoder.init(testing.allocator, 4096, 4096);
        defer dec.deinit();
        try testing.expectEqual(@as(usize, 0), dec.dynamicTableCount());
        try testing.expectEqual(@as(u32, 0), dec.dynamicTableSize());

        var out = std.ArrayList(hpack.Pair).empty;
        defer freePairs(testing.allocator, &out);
        // C.2.1 inserts "custom-key" (10) + "custom-header" (13) + 32 = 55 bytes.
        try dec.decode("\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0d\x63\x75\x73\x74\x6f\x6d\x2d\x68\x65\x61\x64\x65\x72", &out);
        try testing.expectEqual(@as(usize, 1), dec.dynamicTableCount());
        try testing.expectEqual(@as(u32, 55), dec.dynamicTableSize());
    }

    // ─── 5. Malformed input is rejected ─────────────────────────────────────────

    test "malformed: dynamic table size update above the decoder ceiling" {
        var block = std.ArrayList(u8).empty;
        defer block.deinit(testing.allocator);
        try hpack.encodeInteger(testing.allocator, &block, 8192, 5, 0x20);

        var dec = hpack.Decoder.init(testing.allocator, 4096, 4096);
        defer dec.deinit();
        try expectDecodeError(error.CompressionError, &dec, block.items);
    }

    test "malformed: header list exceeds max_header_list_size" {
        const headers = [_]hpack.Pair{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":method", .value = "GET" },
        };
        var block = std.ArrayList(u8).empty;
        defer block.deinit(testing.allocator);
        var enc = hpack.Encoder.init(testing.allocator);
        defer enc.deinit();
        try enc.encode(&headers, &block);

        // Each pair costs name+value+32 = 42 bytes; two already exceed a 64 cap.
        var dec = hpack.Decoder.init(testing.allocator, 4096, 64);
        defer dec.deinit();
        try expectDecodeError(error.HeaderListTooLarge, &dec, block.items);
    }

    test "malformed: bad indices and truncated strings" {
        var d0 = hpack.Decoder.init(testing.allocator, 4096, 4096);
        defer d0.deinit();
        // Indexed field with index 0.
        try expectDecodeError(error.CompressionError, &d0, "\x80");

        var d1 = hpack.Decoder.init(testing.allocator, 4096, 4096);
        defer d1.deinit();
        // Indexed field 62 with an empty dynamic table -> past the end.
        try expectDecodeError(error.CompressionError, &d1, "\xbe");

        var d2 = hpack.Decoder.init(testing.allocator, 4096, 4096);
        defer d2.deinit();
        // Literal with a name length of 5 but only 3 octets present.
        try expectDecodeError(error.CompressionError, &d2, "\x40\x05abc");
    }

    // ─── 6. Encoder round-trip property ─────────────────────────────────────────

    test "encoder round-trip: 200 random header lists, no dynamic growth" {
        var prng = std.Random.DefaultPrng.init(0x5eed_1234_abcd_0001);
        const rand = prng.random();

        const names = [_][]const u8{
            ":method",
            ":status",
            ":path",
            "accept-encoding",
            "content-type",
            "x-custom-Header",
            "Ünïcödé-Key",
            "a",
        };
        const values = [_][]const u8{
            "GET",
            "POST",
            "200",
            "gzip, deflate",
            "text/html; charset=utf-8",
            "val-00",
            "",
            "x",
        };

        var iter: usize = 0;
        while (iter < 200) : (iter += 1) {
            var headers = std.ArrayList(hpack.Pair).empty;
            defer headers.deinit(testing.allocator);
            const n = 1 + rand.uintLessThan(usize, 12);
            var j: usize = 0;
            while (j < n) : (j += 1) {
                try headers.append(testing.allocator, .{
                    .name = names[rand.uintLessThan(usize, names.len)],
                    .value = values[rand.uintLessThan(usize, values.len)],
                });
            }

            var enc = hpack.Encoder.init(testing.allocator);
            defer enc.deinit();
            var block = std.ArrayList(u8).empty;
            defer block.deinit(testing.allocator);
            try enc.encode(headers.items, &block);

            var dec = hpack.Decoder.init(testing.allocator, 4096, 1 << 20);
            defer dec.deinit();
            var got = std.ArrayList(hpack.Pair).empty;
            defer freePairs(testing.allocator, &got);
            try dec.decode(block.items, &got);

            try expectPairsEqual(headers.items, got.items);
            // Literal-without-indexing must never touch the dynamic table.
            try testing.expectEqual(@as(usize, 0), dec.dynamicTableCount());
        }
    }

    // ─── 7. Static-table helpers ────────────────────────────────────────────────

    test "static table helpers" {
        try testing.expectEqual(@as(?usize, 2), hpack.findStaticIndex(":method", "GET"));
        try testing.expectEqual(@as(?usize, 8), hpack.findStaticIndex(":status", "200"));
        try testing.expectEqual(@as(?usize, null), hpack.findStaticIndex(":method", "NOT A METHOD"));
        try testing.expect(hpack.findStaticName("accept-encoding") != null);
        try testing.expectEqual(@as(?usize, null), hpack.findStaticName("x-not-in-static"));

        try testing.expectEqualSlices(u8, ":authority", hpack.staticEntry(1).name);
        try testing.expectEqualSlices(u8, "www-authenticate", hpack.staticEntry(61).name);
    }

    // ─── 8. Encoder shape assertions ────────────────────────────────────────────

    test "encoder shapes: indexed match, literal name, static name index" {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(testing.allocator);
        var enc = hpack.Encoder.init(testing.allocator);
        defer enc.deinit();

        // Exact static match -> single indexed octet.
        try enc.encode(&[_]hpack.Pair{.{ .name = ":status", .value = "200" }}, &out);
        try testing.expectEqualSlices(u8, "\x88", out.items);

        // Unknown name -> literal-without-indexing with an inline name (0x00).
        out.clearRetainingCapacity();
        try enc.encode(&[_]hpack.Pair{.{ .name = "x-not-static", .value = "v" }}, &out);
        try testing.expect(out.items.len > 0);
        try testing.expectEqual(@as(u8, 0x00), out.items[0]);

        // Known name (static index 8 = :status), non-static value -> the literal
        // form reuses the name index (8 fits a 4-bit prefix in one octet).
        out.clearRetainingCapacity();
        try enc.encode(&[_]hpack.Pair{.{ .name = ":status", .value = "418" }}, &out);
        try testing.expect(out.items.len > 0);
        try testing.expectEqual(@as(u8, 0x00 | 8), out.items[0]);
    }

    // ─── Encoder -> Decoder whole-block equivalence ─────────────────────────────

    test "encoder output decodes back to the same list (representative block)" {
        const headers = [_]hpack.Pair{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/index.html" },
            .{ .name = "custom-key", .value = "custom-value" },
            .{ .name = "accept-encoding", .value = "br" },
        };
        var block = std.ArrayList(u8).empty;
        defer block.deinit(testing.allocator);
        var enc = hpack.Encoder.init(testing.allocator);
        defer enc.deinit();
        try enc.encode(&headers, &block);

        var dec = hpack.Decoder.init(testing.allocator, 4096, 4096);
        defer dec.deinit();
        var out = std.ArrayList(hpack.Pair).empty;
        defer freePairs(testing.allocator, &out);
        try dec.decode(block.items, &out);
        try expectPairsEqual(&headers, out.items);
    }
};

comptime {
    _ = hpack_tests;
}
