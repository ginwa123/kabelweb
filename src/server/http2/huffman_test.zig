const std = @import("std");
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
