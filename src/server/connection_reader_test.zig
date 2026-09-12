const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const ConnectionReader = @import("connection_reader.zig").ConnectionReader;
const constants = @import("http2/constants.zig");
const sniff = @import("connection_reader.zig").sniff;
const Kind = @import("connection_reader.zig").Kind;
const test_helpers = @import("test_helpers.zig");

/// Write every byte to a socketpair end. Windows needs `send` (its `SOCKET`s are
/// not indexed by the UCRT fd table, so `write()` fails there); POSIX uses
/// `write`.
fn writeAll(fd: i32, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n: isize = if (builtin.os.tag == .windows) blk: {
            const winsock = struct {
                extern "ws2_32" fn send(s: usize, buf: [*]const u8, len: c_int, flags: c_int) c_int;
            };
            break :blk winsock.send(@intCast(fd), bytes.ptr + off, @intCast(bytes.len - off), 0);
        } else blk: {
            const posix_socket = struct {
                extern "c" fn write(fd: c_int, buf: [*]const u8, nbyte: usize) isize;
            };
            break :blk posix_socket.write(fd, bytes.ptr + off, bytes.len - off);
        };
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
}

// The reader is deliberately thin (a buffer + a socket), so these tests drive it
// through a real socketpair rather than mocking the fd: the behaviour worth
// pinning is "what happens to bytes that arrive together with the preface".
test "sniff: preface plus frames in ONE segment is classified h2" {
    // Regression: a prior-knowledge client (curl included) sends the 24-byte
    // preface and its SETTINGS frame back-to-back, so the first read is usually
    // LONGER than 24 bytes. Requiring an exact-length match silently downgraded
    // every real h2 client to HTTP/1.1.
    const preface = constants.PREFACE;
    const settings_frame = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
    try testing.expectEqual(Kind.h2, sniff(preface ++ settings_frame));
    try testing.expectEqual(Kind.h2, sniff(preface));
    try testing.expectEqual(Kind.h2, sniff(preface ++ "more data than one frame"));
}

test "sniff: partial preface waits for more bytes" {
    const preface = constants.PREFACE;
    try testing.expectEqual(Kind.maybe_h2, sniff(preface[0..1]));
    try testing.expectEqual(Kind.maybe_h2, sniff(preface[0..10]));
    try testing.expectEqual(Kind.maybe_h2, sniff(preface[0..23]));
}

test "sniff: HTTP/1.1 and junk take the h1 path" {
    try testing.expectEqual(Kind.h1, sniff(""));
    try testing.expectEqual(Kind.h1, sniff("GET / HTTP/1.1\r\n\r\n"));
    try testing.expectEqual(Kind.h1, sniff("\x16\x03\x01\x00\xf5")); // TLS ClientHello
    // Same first byte, diverges at byte 3 → h1, never "maybe".
    try testing.expectEqual(Kind.h1, sniff("PRI * HTTP/1.1\r\n\r\n"));
}

test "reader: one fill keeps whole frames that arrive with the preface" {
    const pair = try test_helpers.createSocketPair();
    defer test_helpers.closeSocketPair(pair);
    const peer = test_helpers.toI32(pair[0]);

    const preface_and_settings = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" ++
        "\x00\x00\x00\x04\x00\x00\x00\x00\x00"; // one empty SETTINGS frame
    try writeAll(peer, preface_and_settings);

    // Construct through the new Stream-taking constructor (`.{ .plain = fd }`)
    // rather than `initFd`, so the primary path is exercised too.
    var reader = ConnectionReader.init(testing.allocator, .{ .plain = test_helpers.toI32(pair[1]) });
    defer reader.deinit();
    const got = try reader.fillOnce();

    // Everything the peer sent in one segment is retained — including the bytes
    // AFTER the preface's CRLFCRLF, which the h1 parser would have swallowed.
    try testing.expectEqualStrings(preface_and_settings, got);
    try testing.expect(got.len > 24);
}

test "reader: stream() exposes the wrapped plain transport" {
    const pair = try test_helpers.createSocketPair();
    defer test_helpers.closeSocketPair(pair);
    const fd = test_helpers.toI32(pair[1]);

    var reader = ConnectionReader.init(testing.allocator, .{ .plain = fd });
    defer reader.deinit();

    // The server writes the response back on this exact transport, so the
    // accessor must return an equivalent stream (not a copy of an fd it
    // dropped, and not a TLS stream for a plain socket).
    try testing.expect(!reader.stream().isTls());
    try testing.expectEqual(fd, reader.stream().plain);
}

test "reader: initFd wraps a plain socket and reads through it" {
    const pair = try test_helpers.createSocketPair();
    defer test_helpers.closeSocketPair(pair);
    try writeAll(test_helpers.toI32(pair[0]), "PING");

    var reader = ConnectionReader.initFd(testing.allocator, test_helpers.toI32(pair[1]));
    defer reader.deinit();

    try testing.expect(!reader.stream().isTls());
    const got = try reader.fillOnce();
    try testing.expectEqualStrings("PING", got);
}

test "reader: takeBuffered hands ownership over and empties the buffer" {
    const pair = try test_helpers.createSocketPair();
    defer test_helpers.closeSocketPair(pair);
    try writeAll(test_helpers.toI32(pair[0]), "hello");

    var reader = ConnectionReader.init(testing.allocator, .{ .plain = test_helpers.toI32(pair[1]) });
    defer reader.deinit();
    _ = try reader.fillOnce();

    const owned = try reader.takeBuffered();
    defer testing.allocator.free(owned);
    try testing.expectEqualStrings("hello", owned);
    try testing.expectEqual(@as(usize, 0), reader.buffered().len);
}

test "reader: fillAtLeast completes the 24-byte preface across reads" {
    const pair = try test_helpers.createSocketPair();
    defer test_helpers.closeSocketPair(pair);
    const peer = test_helpers.toI32(pair[0]);

    const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    try writeAll(peer, preface[0..10]);

    var reader = ConnectionReader.init(testing.allocator, .{ .plain = test_helpers.toI32(pair[1]) });
    defer reader.deinit();
    _ = try reader.fillOnce();
    try testing.expect(reader.buffered().len < 24);

    try writeAll(peer, preface[10..]);
    try reader.fillAtLeast(24, 4);
    try testing.expectEqual(@as(usize, 24), reader.buffered().len);
}

test "reader: EOF is reported as an empty buffer, not an error" {
    const pair = try test_helpers.createSocketPair();
    const peer = test_helpers.toI32(pair[0]);
    const ours = test_helpers.toI32(pair[1]);
    test_helpers.closeI32Fd(peer);

    var reader = ConnectionReader.initFd(testing.allocator, ours);
    defer reader.deinit();
    const got = try reader.fillOnce();
    try testing.expectEqual(@as(usize, 0), got.len);
    test_helpers.closeI32Fd(ours);
}
