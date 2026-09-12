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

test {
    _ = @import("huffman_test.zig");
}
