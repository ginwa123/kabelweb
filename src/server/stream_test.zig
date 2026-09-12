// Tests for the transport abstraction in `stream.zig`.
//
// The plain path is driven through a REAL socketpair (`test_helpers`), not a
// mock: the property worth pinning is the syscall-level behaviour the HTTP/1.1
// server depends on (short writes, EOF == 0, a closed fd failing fast).

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const Stream = @import("stream.zig").Stream;
const test_helpers = @import("test_helpers.zig");

/// Read until `dst` is completely filled OR the stream reports EOF. The caller
/// must size `dst` to the payload it expects: with a larger buffer this blocks
/// on a live peer that has nothing more to send (there is no "how much is
/// left" signal on a stream). Returns the byte count actually read.
fn readExact(s: Stream, dst: []u8) !usize {
    var got: usize = 0;
    while (got < dst.len) {
        const n = try s.read(dst[got..]);
        if (n == 0) break; // EOF
        got += n;
    }
    return got;
}

/// `shutdown(SHUT_RDWR)` — only used to unblock a reader thread if the writer
/// side of a test fails, so a broken test can never hang the suite.
fn shutdownBoth(fd: i32) void {
    const SHUT_RDWR: c_int = 2;
    if (comptime builtin.os.tag == .windows) {
        const winsock = struct {
            extern "ws2_32" fn shutdown(sockfd: c_int, how: c_int) callconv(.c) c_int;
        };
        _ = winsock.shutdown(fd, SHUT_RDWR);
    } else {
        _ = std.posix.system.shutdown(fd, SHUT_RDWR);
    }
}

// ───────────────────────────── plain path ─────────────────────────────

test "plain: writeAll then read round-trips the same bytes" {
    const pair = try test_helpers.createSocketPair();
    defer test_helpers.closeSocketPair(pair);

    const writer: Stream = .{ .plain = test_helpers.toI32(pair[0]) };
    const reader: Stream = .{ .plain = test_helpers.toI32(pair[1]) };

    try testing.expect(!writer.isTls());
    try testing.expect(!reader.isTls());

    const msg = "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n";
    try writer.writeAll(msg);

    var buf: [msg.len]u8 = undefined;
    const n = try readExact(reader, &buf);
    try testing.expectEqual(msg.len, n);
    try testing.expectEqualStrings(msg, buf[0..n]);
}

test "plain: writeAll accepts an empty payload (no syscall, no error)" {
    const pair = try test_helpers.createSocketPair();
    defer test_helpers.closeSocketPair(pair);

    const writer: Stream = .{ .plain = test_helpers.toI32(pair[0]) };
    try writer.writeAll("");
}

test "plain: writeAll delivers a 256 KiB payload larger than one syscall" {
    const pair = try test_helpers.createSocketPair();
    defer test_helpers.closeSocketPair(pair);

    const writer_fd = test_helpers.toI32(pair[0]);
    const writer: Stream = .{ .plain = writer_fd };
    const reader: Stream = .{ .plain = test_helpers.toI32(pair[1]) };

    // A payload bigger than the socketpair's send/receive buffers, so the
    // write side MUST loop over short writes. A concurrent reader drains it —
    // without one, a single-threaded write would legitimately block forever.
    const payload = try testing.allocator.alloc(u8, 256 * 1024);
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);

    const received = try testing.allocator.alloc(u8, payload.len);
    defer testing.allocator.free(received);

    const Ctx = struct {
        stream: Stream,
        dst: []u8,
        got: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.got = readExact(self.stream, self.dst) catch |e| {
                self.err = e;
                return;
            };
        }
    };

    var ctx = Ctx{ .stream = reader, .dst = received };
    const t = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});

    writer.writeAll(payload) catch |err| {
        // Unblock the reader (FIN) so `join` can't hang, then surface the error.
        shutdownBoth(writer_fd);
        t.join();
        return err;
    };
    t.join();
    if (ctx.err) |e| return e;

    try testing.expectEqual(payload.len, ctx.got);
    try testing.expectEqualSlices(u8, payload, received);
}

test "plain: read returns 0 at EOF when the peer closes" {
    const pair = try test_helpers.createSocketPair();
    const peer = test_helpers.toI32(pair[0]);
    const ours = test_helpers.toI32(pair[1]);
    // Peer sends nothing, so close means plain EOF: the next read must return 0
    // (not an error and not a block).
    test_helpers.closeI32Fd(peer);

    const s: Stream = .{ .plain = ours };
    var buf: [8]u8 = undefined;
    const n = try s.read(&buf);
    try testing.expectEqual(@as(usize, 0), n);

    s.close();
}

test "plain: close closes the fd, so a later read fails instead of blocking" {
    const pair = try test_helpers.createSocketPair();
    const peer = test_helpers.toI32(pair[0]);
    const ours = test_helpers.toI32(pair[1]);
    // NOTE: no `closeSocketPair(pair)` defer here — `ours` is closed below, and
    // closing it twice would be a second close of a possibly-reused fd.
    defer test_helpers.closeI32Fd(peer);

    const s: Stream = .{ .plain = ours };
    s.close();

    var buf: [8]u8 = undefined;
    try testing.expectError(error.ReadFailed, s.read(&buf));
}

// ────────────────────────────── tls path ──────────────────────────────

/// Fake TLS implementation. The ops must be plain (non-capturing) functions,
/// so the call log lives in container-level vars.
const FakeTls = struct {
    var read_calls: usize = 0;
    var write_calls: usize = 0;
    var close_calls: usize = 0;
    var last_write: []const u8 = "";
    var last_conn: ?*anyopaque = null;

    const payload = "tls-payload";

    fn reset() void {
        read_calls = 0;
        write_calls = 0;
        close_calls = 0;
        last_write = "";
        last_conn = null;
    }

    fn read(conn: *anyopaque, buf: []u8) anyerror!usize {
        read_calls += 1;
        last_conn = conn;
        const n = @min(payload.len, buf.len);
        @memcpy(buf[0..n], payload[0..n]);
        return n;
    }

    fn writeAll(conn: *anyopaque, bytes: []const u8) anyerror!void {
        write_calls += 1;
        last_conn = conn;
        last_write = bytes;
    }

    fn close(conn: *anyopaque) void {
        close_calls += 1;
        last_conn = conn;
    }
};

test "tls: using a tls stream before installTlsOps errors instead of crashing" {
    // Deterministic regardless of test-runner ordering.
    Stream.uninstallTlsOps();
    FakeTls.reset();

    var marker: u8 = 0;
    const s: Stream = .{ .tls = @ptrCast(&marker) };

    try testing.expect(s.isTls());

    var buf: [16]u8 = undefined;
    try testing.expectError(error.TlsOpsNotInstalled, s.read(&buf));
    try testing.expectError(error.TlsOpsNotInstalled, s.writeAll("hello"));

    // `close` returns void, so it cannot report "not installed": it must be a
    // safe no-op rather than a crash.
    s.close();
    try testing.expectEqual(@as(usize, 0), FakeTls.close_calls);
}

test "tls: installed ops receive read/writeAll/close and the connection pointer" {
    FakeTls.reset();
    var marker: u8 = 0;
    const conn: *anyopaque = @ptrCast(&marker);
    Stream.installTlsOps(.{
        .read = FakeTls.read,
        .write_all = FakeTls.writeAll,
        .close = FakeTls.close,
    });
    defer Stream.uninstallTlsOps();

    const s: Stream = .{ .tls = conn };
    try testing.expect(s.isTls());
    try testing.expect(!(Stream{ .plain = 7 }).isTls());

    var buf: [32]u8 = undefined;
    const n = try s.read(&buf);
    try testing.expectEqualStrings(FakeTls.payload, buf[0..n]);
    try testing.expectEqual(@as(usize, 1), FakeTls.read_calls);
    try testing.expect(FakeTls.last_conn.? == conn);

    try s.writeAll("bytes-on-the-wire");
    try testing.expectEqual(@as(usize, 1), FakeTls.write_calls);
    try testing.expectEqualStrings("bytes-on-the-wire", FakeTls.last_write);
    try testing.expect(FakeTls.last_conn.? == conn);

    s.close();
    try testing.expectEqual(@as(usize, 1), FakeTls.close_calls);
    try testing.expect(FakeTls.last_conn.? == conn);
}
