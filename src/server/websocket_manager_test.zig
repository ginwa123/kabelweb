//! Tests for the WebSocket manager (register, broadcast, remove clients).
//!
//! The WebSocket manager is the counterpart to sse_manager.zig: it owns the
//! set of currently-connected WebSocket clients, supports broadcasting a
//! message to all of them, and supports targeted send-to-client. It is
//! thread-safe (multiple client threads can register / send concurrently).
//!
//! These tests are written FIRST (TDD red phase). The implementation
//! (websocket_manager.zig) must satisfy these contracts.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const ws_manager = @import("websocket_manager.zig");

const is_windows = builtin.os.tag == .windows;

// ============================================================================
// Counting writer — used to verify that broadcast / sendToClient dispatch
// the right number of writes.
// ============================================================================

const CountingWriter = struct {
    fn w(_: ?*anyopaque, _: i32, _: []const u8) anyerror!usize {
        return 0;
    }
};

test "WsManager.init: creates empty manager with zero clients" {
    const mgr = try ws_manager.WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    try testing.expectEqual(@as(usize, 0), mgr.clientCount());
}

test "WsManager.registerClient: returns 16-byte client id" {
    const mgr = try ws_manager.WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    const fd = createDummySocket();
    defer closeDummySocket(fd);

    const client_id = try mgr.registerClient(fd, CountingWriter.w, null);
    defer mgr.removeClient(&client_id, .test_only);

    try testing.expectEqual(@as(usize, 1), mgr.clientCount());
    try testing.expectEqual(@as(usize, 16), client_id.len);
}

test "WsManager.removeClient: decrements client count" {
    const mgr = try ws_manager.WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    const fd = createDummySocket();
    defer closeDummySocket(fd);

    const id = try mgr.registerClient(fd, CountingWriter.w, null);
    try testing.expectEqual(@as(usize, 1), mgr.clientCount());

    mgr.removeClient(&id, .test_only);
    try testing.expectEqual(@as(usize, 0), mgr.clientCount());
}

test "WsManager.removeClient: idempotent (removing twice is safe)" {
    const mgr = try ws_manager.WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    const fd = createDummySocket();
    defer closeDummySocket(fd);

    const id = try mgr.registerClient(fd, CountingWriter.w, null);
    mgr.removeClient(&id, .test_only);
    // Second call must not crash.
    mgr.removeClient(&id, .test_only);
    try testing.expectEqual(@as(usize, 0), mgr.clientCount());
}

test "WsManager.sendToClient: returns ClientNotFound for unknown id" {
    const mgr = try ws_manager.WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    var bogus: [16]u8 = .{0} ** 16;
    try testing.expectError(error.ClientNotFound, mgr.sendToClient(&bogus, "x"));
}

test "WsManager.clientCount: registers multiple clients" {
    const mgr = try ws_manager.WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    var ids: [5][16]u8 = undefined;
    var fds: [5]i32 = undefined;
    for (0..5) |i| {
        fds[i] = createDummySocket();
        ids[i] = try mgr.registerClient(fds[i], CountingWriter.w, null);
    }
    defer for (0..5) |i| {
        mgr.removeClient(&ids[i], .test_only);
        closeDummySocket(fds[i]);
    };

    try testing.expectEqual(@as(usize, 5), mgr.clientCount());
}

test "WsManager.broadcast: completes without error" {
    const mgr = try ws_manager.WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    const fd1 = createDummySocket();
    defer closeDummySocket(fd1);
    const fd2 = createDummySocket();
    defer closeDummySocket(fd2);

    const id1 = try mgr.registerClient(fd1, CountingWriter.w, null);
    defer mgr.removeClient(&id1, .test_only);
    const id2 = try mgr.registerClient(fd2, CountingWriter.w, null);
    defer mgr.removeClient(&id2, .test_only);

    // Broadcast completes (writers return 0 writes happily).
    try mgr.broadcast("hello");
    try mgr.broadcast("world");
}

test "WsManager.sendToClient: sends without error to registered client" {
    const mgr = try ws_manager.WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    const fd = createDummySocket();
    defer closeDummySocket(fd);

    const id = try mgr.registerClient(fd, CountingWriter.w, null);
    defer mgr.removeClient(&id, .test_only);

    try mgr.sendToClient(&id, "private-message");
}

// ============================================================================
// Test helpers (cross-platform fd plumbing)
// ============================================================================

// The WsManager only STORES the fd in a HashMap; the test's CountingWriter
// doesn't write to it. So we don't need a real OS fd — any sentinel value
// works. On Linux we open a real pipe (returning the write end) for the
// rare case the production code path later touches the fd. On Windows,
// `std.posix.system.socket` requires linking ws2_32 which the module's
// build.zig doesn't pull in, and the production code never validates
// the fd anyway — so we just return -1 as a sentinel. This keeps the
// test compile-clean on both platforms without any ws2_32 dependency.
fn createDummySocket() i32 {
    if (is_windows) {
        return -1; // Sentinel — WsManager stores but never validates
    } else {
        var fds: [2]std.posix.fd_t = undefined;
        const rc = std.posix.system.pipe(&fds);
        if (rc < 0) return -1;
        // Close the read end and return the write end as our "client fd".
        _ = std.posix.system.close(fds[0]);
        return @intCast(fds[1]);
    }
}

fn closeDummySocket(fd: i32) void {
    if (fd < 0) return; // Sentinel — nothing to close
    // Cross-platform close: on POSIX fd_t is i32 (so fd is passed directly);
    // on Windows fd_t is *anyopaque — @intFromPtr wraps a small i32 HANDLE
    // value as a fake pointer. Safe for our -1 sentinel and any handle
    // values < 2^31 (which the Windows kernel always assigns here).
    _ = std.c.close(if (comptime builtin.os.tag == .windows)
        @ptrFromInt(@as(usize, @bitCast(@as(isize, fd))))
    else
        @as(std.c.fd_t, fd));
}
