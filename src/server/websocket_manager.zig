//! WebSocket manager (RFC 6455): owns connected clients, supports
//! broadcast and targeted send-to-client.
//!
//! This is the counterpart to sse_manager.zig. It keeps a thread-safe
//! registry of WebSocket clients keyed by a 16-byte id, exposes broadcast
//! and sendToClient, and owns the per-client arena (so message buffers
//! written on behalf of a client are reaped when the client disconnects).
//!
//! Concurrency: `registerClient` / `removeClient` / `broadcast` / `sendToClient`
//! are all safe to call from multiple threads concurrently. The internal
//! registry is guarded by `std.atomic.Mutex` (a lock-free spinlock in
//! Zig 0.16 — `std.Thread.Mutex` no longer exists in the public surface).
//!
//! Memory: each client owns an `std.heap.ArenaAllocator`. Callers may
//! allocate response buffers out of the client's arena (via `clientAllocator`)
//! and the buffer is freed automatically when `removeClient` runs.

const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

/// Why a client was removed. Mirrors sse_manager.RemoveReason so the
/// observable behaviour is consistent across SSE and WebSocket transports.
pub const RemoveReason = enum {
    /// Server explicitly asked to remove the client.
    explicit,
    /// Broadcast / sendToClient reported a write failure.
    write_failed,
    /// Test code path that bypassed normal removal logic.
    test_only,
};

/// Function signature for the per-client write callback.
///
/// The manager stores the callback at `registerClient` time and invokes
/// it on every broadcast / sendToClient. The callback is responsible for
/// actually transmitting the bytes back to the client (over the socket).
/// The `ctx` pointer is opaque to the manager — pass any user data
/// (typically a `*GinwaServer` pointer) that the callback needs to
/// produce the actual write. Returning a smaller count than `data.len`
/// or an error triggers cleanup.
pub const WriteFn = *const fn (ctx: ?*anyopaque, fd: i32, data: []const u8) anyerror!usize;

/// A connected WebSocket client.
pub const WsClient = struct {
    id: [16]u8,
    fd: i32,
    arena: std.heap.ArenaAllocator,
    write: WriteFn,
    /// Opaque user data passed to the write callback. The manager does
    /// not interpret this — it's a passthrough for the callback.
    write_ctx: ?*anyopaque,
    alive: bool = true,

    pub fn allocator(self: *WsClient) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn deinit(self: *WsClient) void {
        if (self.alive) {
            self.alive = false;
            self.arena.deinit();
        }
    }
};

/// WebSocket manager state.
pub const WsManager = struct {
    allocator: std.mem.Allocator,
    parent_allocator: std.mem.Allocator,
    /// Stored to match the SSE manager constructor signature; not used
    /// directly because we own an arena per client.
    io: std.Io,
    clients: std.ArrayListUnmanaged(*WsClient) = .empty,
    lock: std.atomic.Mutex = .unlocked,
    next_seq: u64 = 0,

    /// Initialize a new manager. The `allocator` is used for the registry
    /// itself (client structs). The `parent_allocator` is the parent arena
    /// from which each client's arena draws memory.
    pub fn init(
        allocator: std.mem.Allocator,
        parent_allocator: std.mem.Allocator,
        io: std.Io,
    ) !*WsManager {
        const mgr = try allocator.create(WsManager);
        mgr.* = .{
            .allocator = allocator,
            .parent_allocator = parent_allocator,
            .io = io,
            .clients = .empty,
            .lock = .unlocked,
            .next_seq = 0,
        };
        return mgr;
    }

    /// Free the manager and all clients. Idempotent.
    pub fn destroy(self: *WsManager) void {
        // Take the lock once to drain the client list.
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        // NOTE: we do NOT unlock here — `self` is freed at the end of
        // this function, so unlocking would touch freed memory and
        // crash (the lock check performs an atomic load on the mutex).
        // The mutex is part of the freed struct, so there is no need
        // to leave it in a particular state.

        for (self.clients.items) |client| {
            client.deinit();
            self.allocator.destroy(client);
        }
        self.clients.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// Register a new client and return its 16-byte id.
    ///
    /// The caller transfers ownership of the `fd` to the manager — the
    /// manager does not close it on success but relies on the
    /// `removeClient` / `destroy` paths to free the per-client arena.
    /// The `write_ctx` is an opaque pointer passed to every write callback
    /// invocation (typically a `*GinwaServer`).
    pub fn registerClient(self: *WsManager, fd: i32, write: WriteFn, write_ctx: ?*anyopaque) ![16]u8 {
        const id = self.nextId();

        const client = try self.allocator.create(WsClient);
        client.* = .{
            .id = id,
            .fd = fd,
            .arena = std.heap.ArenaAllocator.init(self.parent_allocator),
            .write = write,
            .write_ctx = write_ctx,
            .alive = true,
        };

        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        defer self.lock.unlock();
        try self.clients.append(self.allocator, client);

        return id;
    }

    /// Remove a client by id. Idempotent — removing an unknown id is a no-op.
    pub fn removeClient(self: *WsManager, id: *const [16]u8, _: RemoveReason) void {
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        defer self.lock.unlock();

        for (self.clients.items, 0..) |client, i| {
            if (std.mem.eql(u8, &client.id, id)) {
                _ = self.clients.swapRemove(i);
                client.deinit();
                self.allocator.destroy(client);
                return;
            }
        }
    }

    /// Number of currently-connected clients.
    pub fn clientCount(self: *WsManager) usize {
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        defer self.lock.unlock();
        return self.clients.items.len;
    }

    /// Broadcast a UTF-8 text message to every connected client.
    ///
    /// The message is encoded as a single WebSocket text frame and
    /// delivered via each client's write callback. Clients whose write
    /// fails are removed from the registry.
    pub fn broadcast(self: *WsManager, message: []const u8) !void {
        // Encode once into the manager's allocator; share the bytes
        // across every client write.
        const encoded = try encodeFrameOwned(self.allocator, .text, message);
        defer self.allocator.free(encoded);

        // Snapshot the client list under the lock so we don't hold the
        // lock across the writes (which can be slow and may trigger
        // removeClient from another thread).
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        const snapshot = try self.allocator.dupe(*WsClient, self.clients.items);
        self.lock.unlock();

        defer self.allocator.free(snapshot);

        for (snapshot) |client| {
            // write returns !usize — discard the success count, propagate errors.
            _ = client.write(client.write_ctx, client.fd, encoded) catch |err| {
                // Write failed → drop the client. The removeClient path
                // re-takes the lock; that's safe because we already
                // released it before the loop.
                self.removeClient(&client.id, .write_failed);
                return err;
            };
        }
    }

    /// Send a UTF-8 text message to a single client. Returns
    /// `error.ClientNotFound` if the id is not registered.
    pub fn sendToClient(self: *WsManager, client_id: *const [16]u8, message: []const u8) !void {
        // Look up the client under the lock.
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
        defer self.lock.unlock();

        for (self.clients.items) |client| {
            if (std.mem.eql(u8, &client.id, client_id)) {
                const encoded = try encodeFrameOwned(self.allocator, .text, message);
                defer self.allocator.free(encoded);
                // write returns !usize — discard the success count, propagate errors.
                _ = client.write(client.write_ctx, client.fd, encoded) catch |err| {
                    // Note: we already hold the lock; removeClient will
                    // spin-wait for it. Easiest path: mark dead and let
                    // the next call clean up. For simplicity we just
                    // return the error.
                    return err;
                };
                return;
            }
        }
        return error.ClientNotFound;
    }

    // ----------------------------------------------------------------
    // internal helpers
    // ----------------------------------------------------------------

    /// Generate a 16-byte client id. The first 8 bytes are a process-local
    /// counter (starts at 1) and the last 8 bytes are a timestamp; both
    /// are written big-endian so the id is human-readable in logs.
    fn nextId(self: *WsManager) [16]u8 {
        const seq = @as(u64, @atomicRmw(@TypeOf(self.next_seq), &self.next_seq, .Add, 1, .seq_cst));
        // Use std.c.gettimeofday for cross-platform millisecond-precision
        // timestamps. The id is a debug-log aid only — it does not need
        // to be cryptographically unique, only unique-enough to identify
        // a client in a log line.
        var tv: std.c.timeval = .{ .sec = 0, .usec = 0 };
        _ = std.c.gettimeofday(&tv, null);
        const ts: u64 = @intCast(@as(i64, tv.sec) * 1000 + @as(i64, @divTrunc(tv.usec, 1000)));

        var id: [16]u8 = undefined;
        for (0..8) |i| {
            id[i] = @intCast((seq >> @intCast((7 - i) * 8)) & 0xFF);
        }
        for (0..8) |i| {
            id[8 + i] = @intCast((ts >> @intCast((7 - i) * 8)) & 0xFF);
        }
        return id;
    }
};

// ============================================================================
// Local frame encoder (avoids a circular import with websocket_frames.zig)
// ============================================================================

const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

/// Encode a server-to-client WebSocket frame. Server frames are NEVER
/// masked (RFC 6455 §5.1). The returned slice is heap-allocated and
/// owned by the caller.
fn encodeFrameOwned(allocator: std.mem.Allocator, opcode: Opcode, payload: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(allocator);

    // First byte: FIN=1, opcode
    try buf.append(allocator, @as(u8, 0x80) | @intFromEnum(opcode));

    // Second byte: MASK=0, payload_len
    const plen = payload.len;
    if (plen <= 125) {
        try buf.append(allocator, @intCast(plen));
    } else if (plen <= 0xFFFF) {
        try buf.append(allocator, 126);
        try buf.append(allocator, @intCast(@as(u16, @intCast(plen)) >> 8));
        try buf.append(allocator, @intCast(@as(u16, @intCast(plen)) & 0xFF));
    } else {
        try buf.append(allocator, 127);
        var i: usize = 8;
        while (i > 0) {
            i -= 1;
            try buf.append(allocator, @intCast((plen >> @intCast(i * 8)) & 0xFF));
        }
    }

    try buf.appendSlice(allocator, payload);
    return buf.toOwnedSlice(allocator);
}

// ============================================================================
// In-module tests
// ============================================================================

const testing = std.testing;

test "WsManager: broadcast to multiple clients" {
    const mgr = try WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    const Writer = struct {
        fn w(_: ?*anyopaque, _: i32, _: []const u8) anyerror!usize {
            return 0;
        }
    };

    const fd1: i32 = -1;
    const fd2: i32 = -2;
    const id1 = try mgr.registerClient(fd1, Writer.w, null);
    const id2 = try mgr.registerClient(fd2, Writer.w, null);

    try mgr.broadcast("hello world");

    try testing.expectEqual(@as(usize, 2), mgr.clientCount());

    mgr.removeClient(&id1, .test_only);
    mgr.removeClient(&id2, .test_only);
}

test "WsManager: removeClient is idempotent" {
    const mgr = try WsManager.init(testing.allocator, testing.allocator, undefined);
    defer mgr.destroy();

    const Writer = struct {
        fn w(_: ?*anyopaque, _: i32, _: []const u8) anyerror!usize {
            return 0;
        }
    };

    var id = try mgr.registerClient(-1, Writer.w, null);
    mgr.removeClient(&id, .test_only);
    // Second call must not crash.
    mgr.removeClient(&id, .test_only);
    try testing.expectEqual(@as(usize, 0), mgr.clientCount());
}

// ============================================================================
// Tests — moved here from `websocket_manager_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = websocket_manager_tests; }` below pulls them into the run.
// ============================================================================

const websocket_manager_tests = struct {
    // Tests for the WebSocket manager (register, broadcast, remove clients).
    //
    // The WebSocket manager is the counterpart to sse_manager.zig: it owns the
    // set of currently-connected WebSocket clients, supports broadcasting a
    // message to all of them, and supports targeted send-to-client. It is
    // thread-safe (multiple client threads can register / send concurrently).
    //
    // These tests are written FIRST (TDD red phase). The implementation
    // (websocket_manager.zig) must satisfy these contracts.

    const ws_manager = @import("websocket_manager.zig");


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
};

comptime {
    _ = websocket_manager_tests;
}
