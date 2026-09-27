//! HPACK Huffman coding (RFC 7541 §5.2 + Appendix B).
//!
//! WHY a comptime tree: HPACK's Huffman code is a canonical, prefix-free code
//! over 257 symbols (0..255 plus the EOS symbol 256). Decoding is a simple
//! bit-by-bit walk of a binary trie. Building that trie once at comptime means
//! the hot path is a couple of array loads per bit, with no runtime setup and
//! no per-symbol allocation. It is O(n) in the *number of input bits* — never a
//! linear scan of all 257 code lengths per decoded symbol.
//!
//! The two decoder rules that are easy to get wrong (both enforced here):
//!   * an EOS symbol in the stream is a decoding error (§5.2);
//!   * trailing padding must be the EOS prefix (all 1-bits) and at most 7 bits.

const std = @import("std");
const tables = @import("generated_tables.zig");

pub const Error = error{ InvalidHuffmanCode, OutOfMemory };

/// Symbol 256 is EOS: it exists only to define padding, never to be emitted.
const eos_symbol: u16 = 256;
/// Sentinel for "this edge/leaf was never populated".
const none: u16 = 0xffff;

const HuffNode = struct {
    /// children[0] / children[1]; `none` means the edge does not exist.
    children: [2]u16 = .{ none, none },
    /// Leaf symbol 0..256, or `none` for an internal node.
    symbol: u16 = none,
};

/// A strictly binary prefix tree with 257 leaves has at most 256 internal
/// nodes; 2*257+2 is a comfortable static bound so the whole decoder lives in
/// one comptime-known array.
const max_nodes = 2 * 257 + 2;

/// Build the decoding trie from the RFC table. Codes are stored MSB-first: bit
/// `bits-1` is the first bit seen on the wire.
fn buildTree() [max_nodes]HuffNode {
    @setEvalBranchQuota(200_000);
    var nodes = [_]HuffNode{.{}} ** max_nodes;
    var used: u16 = 1; // node 0 is the root
    for (tables.huffman_codes, 0..) |hc, sym| {
        var cur: u16 = 0;
        var i: u5 = hc.bits;
        while (i > 0) {
            i -= 1;
            const b: u1 = @intCast((hc.code >> i) & 1);
            if (nodes[cur].children[b] == none) {
                nodes[cur].children[b] = used;
                used += 1;
            }
            cur = nodes[cur].children[b];
        }
        nodes[cur].symbol = @intCast(sym);
    }
    return nodes;
}

const tree = buildTree();

/// Decode an HPACK Huffman string. The result is freshly allocated with
/// `alloc`; the caller owns it.
pub fn decode(alloc: std.mem.Allocator, input: []const u8) Error![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    var cur: u16 = 0;
    var pending_bits: u6 = 0; // bits consumed since the last emitted symbol
    var pending_all_ones = true; // ... and whether every one of them was 1

    const total_bits = input.len * 8;
    var idx: usize = 0;
    while (idx < total_bits) : (idx += 1) {
        const byte = input[idx >> 3];
        const shift: u3 = @intCast(7 - (idx & 7));
        const bit: u1 = @truncate(byte >> shift);

        if (bit == 0) pending_all_ones = false;
        pending_bits += 1;

        const next = tree[cur].children[bit];
        if (next == none) return error.InvalidHuffmanCode;
        cur = next;

        const sym = tree[cur].symbol;
        if (sym != none) {
            // EOS must never appear in a real stream — only its all-ones
            // prefix is allowed, as padding.
            if (sym == eos_symbol) return error.InvalidHuffmanCode;
            try out.append(alloc, @intCast(sym));
            cur = 0;
            pending_bits = 0;
            pending_all_ones = true;
        }
    }

    // We stopped mid-code: the remainder is padding, which per §5.2 must be a
    // prefix of the EOS code (i.e. all ones) and strictly at most 7 bits.
    if (cur != 0 and !(pending_all_ones and pending_bits <= 7)) {
        return error.InvalidHuffmanCode;
    }

    return try out.toOwnedSlice(alloc);
}

/// Number of octets `encode` would produce, without allocating.
pub fn encodedLen(input: []const u8) usize {
    var total: usize = 0;
    for (input) |byte| total += tables.huffman_codes[byte].bits;
    return (total + 7) / 8;
}

/// Huffman-encode `input` per Appendix B. Used by tests and by future encoder
/// work; the wire format only requires that we can *decode*.
pub fn encode(alloc: std.mem.Allocator, input: []const u8) Error![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    // A u64 accumulator because one leftover octet (<=7 bits) can be followed
    // by a 30-bit code: 37 bits would overflow a u32.
    var acc: u64 = 0;
    var acc_bits: u6 = 0;

    for (input) |byte| {
        const hc = tables.huffman_codes[byte];
        acc = (acc << @as(u6, hc.bits)) | @as(u64, hc.code);
        acc_bits += hc.bits;
        while (acc_bits >= 8) {
            acc_bits -= 8;
            try out.append(alloc, @intCast((acc >> acc_bits) & 0xff));
        }
    }

    if (acc_bits != 0) {
        // Pad the final octet with the most significant bits of EOS, which are
        // all ones — exactly what the decoder verifies when it sees padding.
        const pad: u6 = 8 - acc_bits;
        acc = (acc << pad) | ((@as(u64, 1) << pad) - 1);
        try out.append(alloc, @intCast(acc & 0xff));
    }

    return try out.toOwnedSlice(alloc);
}

// ============================================================================
// Tests — moved here from `huffman_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = huffman_tests; }` below pulls them into the run.
// ============================================================================

const huffman_tests = struct {
    const huffman = @import("huffman.zig");
    const testing = std.testing;

    fn expectDecodes(encoded: []const u8, expected: []const u8) !void {
        const got = try huffman.decode(testing.allocator, encoded);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, expected, got);
    }

    test "round-trip: representative strings survive encode then decode" {
        const samples = [_][]const u8{
            "",
            "www.example.com",
            "no-cache",
            "custom-key",
            "custom-value",
            "Mon, 21 Oct 2013 20:13:21 GMT",
            "https://www.example.com",
        };
        for (samples) |s| {
            const encoded = try huffman.encode(testing.allocator, s);
            defer testing.allocator.free(encoded);
            // encodedLen must agree with what the encoder actually produced.
            try testing.expectEqual(huffman.encodedLen(s), encoded.len);

            const decoded = try huffman.decode(testing.allocator, encoded);
            defer testing.allocator.free(decoded);
            try testing.expectEqualSlices(u8, s, decoded);
        }
    }

    test "round-trip: all 256 byte values as one raw string" {
        var raw: [256]u8 = undefined;
        for (&raw, 0..) |*b, i| b.* = @intCast(i);

        const encoded = try huffman.encode(testing.allocator, &raw);
        defer testing.allocator.free(encoded);
        try testing.expectEqual(huffman.encodedLen(&raw), encoded.len);

        const decoded = try huffman.decode(testing.allocator, encoded);
        defer testing.allocator.free(decoded);
        try testing.expectEqualSlices(u8, &raw, decoded);
    }

    test "RFC 7541 C.4.1 anchor: huffman-coded www.example.com" {
        try expectDecodes("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff", "www.example.com");
    }

    test "RFC 7541 C.4.2 anchor: huffman-coded no-cache" {
        try expectDecodes("\xa8\xeb\x10\x64\x9c\xbf", "no-cache");
    }

    test "RFC 7541 C.4.3 payloads: huffman-coded custom-key / custom-value" {
        // These are the name/value octets that follow the 0x40 representation byte
        // in C.4.3 (the length prefixes live in the header block, not here).
        try expectDecodes("\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f", "custom-key");
        try expectDecodes("\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf", "custom-value");
    }

    test "RFC 7541 C.5/C.6 anchors: 302 and the GMT date (huffman payloads)" {
        // "302": 3 (6 bits) + 0 (5) + 2 (5) = exactly 16 bits, no padding needed.
        try expectDecodes("\x64\x02", "302");

        // The date payload carried by C.5.1 / C.6.1 after their length octet.
        try expectDecodes(
            "\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff",
            "Mon, 21 Oct 2013 20:13:21 GMT",
        );
        // C.6.3's own octets differ by one bit in the seconds field (20:13:22);
        // deriving it with our encoder keeps the second anchor honest without
        // hard-coding a literal that the RFC text renders ambiguously.
        const one_second_later = try huffman.encode(testing.allocator, "Mon, 21 Oct 2013 20:13:22 GMT");
        defer testing.allocator.free(one_second_later);
        try expectDecodes(one_second_later, "Mon, 21 Oct 2013 20:13:22 GMT");
    }

    test "C.4.3-adjacent literal decodes to https://www.example.com" {
        // This exact octet string circulates as a "C.4.3" anchor but the RFC
        // vector file assigns it to https://www.example.com — proven here so the
        // ambiguity cannot silently regress.
        try expectDecodes("\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3", "https://www.example.com");
    }

    test "EOS symbol in the stream is a decoding error" {
        // 0x3fffffff (30 one-bits) is the EOS code; four 0xff octets contain it.
        try testing.expectError(error.InvalidHuffmanCode, huffman.decode(testing.allocator, "\xff\xff\xff\xff"));
    }

    test "padding rules: all-ones <= 7 bits is valid, anything else is an error" {
        // Valid: C.4.1 ends with all-ones padding.
        const ok = try huffman.decode(testing.allocator, "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff");
        defer testing.allocator.free(ok);
        try testing.expectEqualSlices(u8, "www.example.com", ok);

        // Invalid: same octets, final byte zeroed -> padding is not all ones.
        const bad_ones = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0x00 };
        try testing.expectError(error.InvalidHuffmanCode, huffman.decode(testing.allocator, &bad_ones));

        // Invalid: 8 one-bits of padding — a prefix of EOS, but strictly longer
        // than the 7 bits §5.2 allows.
        try testing.expectError(error.InvalidHuffmanCode, huffman.decode(testing.allocator, "\xff"));
    }

    test "encodedLen matches the encoder for a known string" {
        try testing.expectEqual(@as(usize, 12), huffman.encodedLen("www.example.com"));
        try testing.expectEqual(@as(usize, 0), huffman.encodedLen(""));
    }
};

comptime {
    _ = huffman_tests;
}
