const std = @import("std");
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
