//! GENERATED FILE — DO NOT EDIT BY HAND.
//!
//! RFC 7541 Appendix C conformance vectors. The encoded blocks are transcribed
//! byte-for-byte from the RFC text; the expected header lists are the RFC's own
//! "Decoded header list" tables, cross-checked against the reference `hpack`
//! implementation by `tools/gen_hpack_tables.py`.

pub const Pair = struct { name: []const u8, value: []const u8 };

/// A single HPACK block plus the exact header list it must decode to.
pub const BlockVector = struct {
    name: []const u8,
    table_size: u32 = 4096,
    block: []const u8,
    expected: []const Pair,
};

/// A sequence of blocks decoded with ONE decoder (dynamic table carries over).
pub const Step = struct {
    name: []const u8,
    block: []const u8,
    expected: []const Pair,
};

pub const Case = struct {
    name: []const u8,
    table_size: u32,
    steps: []const Step,
};

pub const IntegerVector = struct {
    name: []const u8,
    /// Value to encode plus the prefix/start octet the RFC uses.
    value: usize,
    prefix_bits: u5,
    initial_byte: u8,
    expected: []const u8,
};

/// RFC 7541 Appendix C.1 (each vector is a single octet sequence).
pub const integer_vectors = [_]IntegerVector{
    .{ .name = "C.1.1 value 10, 5-bit prefix", .value = 10, .prefix_bits = 5, .initial_byte = 0x00, .expected = "\x0a" },
    .{ .name = "C.1.2 value 1337, 5-bit prefix", .value = 1337, .prefix_bits = 5, .initial_byte = 0x00, .expected = "\x1f\x9a\x0a" },
    .{ .name = "C.1.3 value 42, 8-bit prefix", .value = 42, .prefix_bits = 8, .initial_byte = 0x00, .expected = "\x2a" },
};

const bv_0_0 = Pair{ .name = "custom-key", .value = "custom-header" };
const bv_0_expected = [_]Pair{ bv_0_0 };
const bv_1_0 = Pair{ .name = ":path", .value = "/sample/path" };
const bv_1_expected = [_]Pair{ bv_1_0 };
const bv_2_0 = Pair{ .name = "password", .value = "secret" };
const bv_2_expected = [_]Pair{ bv_2_0 };
const bv_3_0 = Pair{ .name = ":method", .value = "GET" };
const bv_3_expected = [_]Pair{ bv_3_0 };

pub const block_vectors = [_]BlockVector{
    .{ .name = "C.2.1 (4096 octet table)", .table_size = 4096, .block = "\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0d\x63\x75\x73\x74\x6f\x6d\x2d\x68\x65\x61\x64\x65\x72", .expected = &bv_0_expected },
    .{ .name = "C.2.2 (4096 octet table)", .table_size = 4096, .block = "\x04\x0c\x2f\x73\x61\x6d\x70\x6c\x65\x2f\x70\x61\x74\x68", .expected = &bv_1_expected },
    .{ .name = "C.2.3 (4096 octet table)", .table_size = 4096, .block = "\x10\x08\x70\x61\x73\x73\x77\x6f\x72\x64\x06\x73\x65\x63\x72\x65\x74", .expected = &bv_2_expected },
    .{ .name = "C.2.4 (4096 octet table)", .table_size = 4096, .block = "\x82", .expected = &bv_3_expected },
};

const cs_0_0_0 = Pair{ .name = ":method", .value = "GET" };
const cs_0_0_1 = Pair{ .name = ":scheme", .value = "http" };
const cs_0_0_2 = Pair{ .name = ":path", .value = "/" };
const cs_0_0_3 = Pair{ .name = ":authority", .value = "www.example.com" };
const cs_0_0_expected = [_]Pair{ cs_0_0_0, cs_0_0_1, cs_0_0_2, cs_0_0_3 };
const cs_0_0 = Step{ .name = "C.3.1", .block = "\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d", .expected = &cs_0_0_expected };
const cs_0_1_0 = Pair{ .name = ":method", .value = "GET" };
const cs_0_1_1 = Pair{ .name = ":scheme", .value = "http" };
const cs_0_1_2 = Pair{ .name = ":path", .value = "/" };
const cs_0_1_3 = Pair{ .name = ":authority", .value = "www.example.com" };
const cs_0_1_4 = Pair{ .name = "cache-control", .value = "no-cache" };
const cs_0_1_expected = [_]Pair{ cs_0_1_0, cs_0_1_1, cs_0_1_2, cs_0_1_3, cs_0_1_4 };
const cs_0_1 = Step{ .name = "C.3.2", .block = "\x82\x86\x84\xbe\x58\x08\x6e\x6f\x2d\x63\x61\x63\x68\x65", .expected = &cs_0_1_expected };
const cs_0_2_0 = Pair{ .name = ":method", .value = "GET" };
const cs_0_2_1 = Pair{ .name = ":scheme", .value = "https" };
const cs_0_2_2 = Pair{ .name = ":path", .value = "/index.html" };
const cs_0_2_3 = Pair{ .name = ":authority", .value = "www.example.com" };
const cs_0_2_4 = Pair{ .name = "custom-key", .value = "custom-value" };
const cs_0_2_expected = [_]Pair{ cs_0_2_0, cs_0_2_1, cs_0_2_2, cs_0_2_3, cs_0_2_4 };
const cs_0_2 = Step{ .name = "C.3.3", .block = "\x82\x87\x85\xbf\x40\x0a\x63\x75\x73\x74\x6f\x6d\x2d\x6b\x65\x79\x0c\x63\x75\x73\x74\x6f\x6d\x2d\x76\x61\x6c\x75\x65", .expected = &cs_0_2_expected };
const case_0 = Case{ .name = "C.3", .table_size = 4096, .steps = &[_]Step{ cs_0_0, cs_0_1, cs_0_2 } };
const cs_1_0_0 = Pair{ .name = ":method", .value = "GET" };
const cs_1_0_1 = Pair{ .name = ":scheme", .value = "http" };
const cs_1_0_2 = Pair{ .name = ":path", .value = "/" };
const cs_1_0_3 = Pair{ .name = ":authority", .value = "www.example.com" };
const cs_1_0_expected = [_]Pair{ cs_1_0_0, cs_1_0_1, cs_1_0_2, cs_1_0_3 };
const cs_1_0 = Step{ .name = "C.4.1", .block = "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff", .expected = &cs_1_0_expected };
const cs_1_1_0 = Pair{ .name = ":method", .value = "GET" };
const cs_1_1_1 = Pair{ .name = ":scheme", .value = "http" };
const cs_1_1_2 = Pair{ .name = ":path", .value = "/" };
const cs_1_1_3 = Pair{ .name = ":authority", .value = "www.example.com" };
const cs_1_1_4 = Pair{ .name = "cache-control", .value = "no-cache" };
const cs_1_1_expected = [_]Pair{ cs_1_1_0, cs_1_1_1, cs_1_1_2, cs_1_1_3, cs_1_1_4 };
const cs_1_1 = Step{ .name = "C.4.2", .block = "\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf", .expected = &cs_1_1_expected };
const cs_1_2_0 = Pair{ .name = ":method", .value = "GET" };
const cs_1_2_1 = Pair{ .name = ":scheme", .value = "https" };
const cs_1_2_2 = Pair{ .name = ":path", .value = "/index.html" };
const cs_1_2_3 = Pair{ .name = ":authority", .value = "www.example.com" };
const cs_1_2_4 = Pair{ .name = "custom-key", .value = "custom-value" };
const cs_1_2_expected = [_]Pair{ cs_1_2_0, cs_1_2_1, cs_1_2_2, cs_1_2_3, cs_1_2_4 };
const cs_1_2 = Step{ .name = "C.4.3", .block = "\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf", .expected = &cs_1_2_expected };
const case_1 = Case{ .name = "C.4", .table_size = 4096, .steps = &[_]Step{ cs_1_0, cs_1_1, cs_1_2 } };
const cs_2_0_0 = Pair{ .name = ":status", .value = "302" };
const cs_2_0_1 = Pair{ .name = "cache-control", .value = "private" };
const cs_2_0_2 = Pair{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" };
const cs_2_0_3 = Pair{ .name = "location", .value = "https://www.example.com" };
const cs_2_0_expected = [_]Pair{ cs_2_0_0, cs_2_0_1, cs_2_0_2, cs_2_0_3 };
const cs_2_0 = Step{ .name = "C.5.1", .block = "\x48\x03\x33\x30\x32\x58\x07\x70\x72\x69\x76\x61\x74\x65\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x31\x20\x47\x4d\x54\x6e\x17\x68\x74\x74\x70\x73\x3a\x2f\x2f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d", .expected = &cs_2_0_expected };
const cs_2_1_0 = Pair{ .name = ":status", .value = "307" };
const cs_2_1_1 = Pair{ .name = "cache-control", .value = "private" };
const cs_2_1_2 = Pair{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" };
const cs_2_1_3 = Pair{ .name = "location", .value = "https://www.example.com" };
const cs_2_1_expected = [_]Pair{ cs_2_1_0, cs_2_1_1, cs_2_1_2, cs_2_1_3 };
const cs_2_1 = Step{ .name = "C.5.2", .block = "\x48\x03\x33\x30\x37\xc1\xc0\xbf", .expected = &cs_2_1_expected };
const cs_2_2_0 = Pair{ .name = ":status", .value = "200" };
const cs_2_2_1 = Pair{ .name = "cache-control", .value = "private" };
const cs_2_2_2 = Pair{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" };
const cs_2_2_3 = Pair{ .name = "location", .value = "https://www.example.com" };
const cs_2_2_4 = Pair{ .name = "content-encoding", .value = "gzip" };
const cs_2_2_5 = Pair{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" };
const cs_2_2_expected = [_]Pair{ cs_2_2_0, cs_2_2_1, cs_2_2_2, cs_2_2_3, cs_2_2_4, cs_2_2_5 };
const cs_2_2 = Step{ .name = "C.5.3", .block = "\x88\xc1\x61\x1d\x4d\x6f\x6e\x2c\x20\x32\x31\x20\x4f\x63\x74\x20\x32\x30\x31\x33\x20\x32\x30\x3a\x31\x33\x3a\x32\x32\x20\x47\x4d\x54\xc0\x5a\x04\x67\x7a\x69\x70\x77\x38\x66\x6f\x6f\x3d\x41\x53\x44\x4a\x4b\x48\x51\x4b\x42\x5a\x58\x4f\x51\x57\x45\x4f\x50\x49\x55\x41\x58\x51\x57\x45\x4f\x49\x55\x3b\x20\x6d\x61\x78\x2d\x61\x67\x65\x3d\x33\x36\x30\x30\x3b\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x31", .expected = &cs_2_2_expected };
const case_2 = Case{ .name = "C.5", .table_size = 256, .steps = &[_]Step{ cs_2_0, cs_2_1, cs_2_2 } };
const cs_3_0_0 = Pair{ .name = ":status", .value = "302" };
const cs_3_0_1 = Pair{ .name = "cache-control", .value = "private" };
const cs_3_0_2 = Pair{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" };
const cs_3_0_3 = Pair{ .name = "location", .value = "https://www.example.com" };
const cs_3_0_expected = [_]Pair{ cs_3_0_0, cs_3_0_1, cs_3_0_2, cs_3_0_3 };
const cs_3_0 = Step{ .name = "C.6.1", .block = "\x48\x82\x64\x02\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3", .expected = &cs_3_0_expected };
const cs_3_1_0 = Pair{ .name = ":status", .value = "307" };
const cs_3_1_1 = Pair{ .name = "cache-control", .value = "private" };
const cs_3_1_2 = Pair{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" };
const cs_3_1_3 = Pair{ .name = "location", .value = "https://www.example.com" };
const cs_3_1_expected = [_]Pair{ cs_3_1_0, cs_3_1_1, cs_3_1_2, cs_3_1_3 };
const cs_3_1 = Step{ .name = "C.6.2", .block = "\x48\x83\x64\x0e\xff\xc1\xc0\xbf", .expected = &cs_3_1_expected };
const cs_3_2_0 = Pair{ .name = ":status", .value = "200" };
const cs_3_2_1 = Pair{ .name = "cache-control", .value = "private" };
const cs_3_2_2 = Pair{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" };
const cs_3_2_3 = Pair{ .name = "location", .value = "https://www.example.com" };
const cs_3_2_4 = Pair{ .name = "content-encoding", .value = "gzip" };
const cs_3_2_5 = Pair{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" };
const cs_3_2_expected = [_]Pair{ cs_3_2_0, cs_3_2_1, cs_3_2_2, cs_3_2_3, cs_3_2_4, cs_3_2_5 };
const cs_3_2 = Step{ .name = "C.6.3", .block = "\x88\xc1\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x84\xa6\x2d\x1b\xff\xc0\x5a\x83\x9b\xd9\xab\x77\xad\x94\xe7\x82\x1d\xd7\xf2\xe6\xc7\xb3\x35\xdf\xdf\xcd\x5b\x39\x60\xd5\xaf\x27\x08\x7f\x36\x72\xc1\xab\x27\x0f\xb5\x29\x1f\x95\x87\x31\x60\x65\xc0\x03\xed\x4e\xe5\xb1\x06\x3d\x50\x07", .expected = &cs_3_2_expected };
const case_3 = Case{ .name = "C.6", .table_size = 256, .steps = &[_]Step{ cs_3_0, cs_3_1, cs_3_2 } };

pub const cases = [_]Case{ case_0, case_1, case_2, case_3 };
