const std = @import("std");
const posix = std.posix;
const sse_manager = @import("sse_manager.zig");
const SseManager = sse_manager.SseManager;
const SseClient = sse_manager.SseClient;
const builtin = @import("builtin");
const helpers = @import("test_helpers.zig");

// Cross-platform fd plumbing — shared with the rest of the suite via
// test_helpers.zig. See that file for the comptime if dispatch and the
// kernel32 CreatePipe shim details.
const createSocketPair = helpers.createSocketPair;
const closeSocketPair = helpers.closeSocketPair;
const toI32 = helpers.toI32;

// ============================================================================
// SSE Manager Tests - Client Registration and Removal
// ============================================================================

// ============================================================================
// SSE Manager Tests - Client Registration and Removal
// ============================================================================

test "SseManager: register and remove single client" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);
    defer mgr.deinit();

    // Create a socket pair for testing
    const pair = try createSocketPair();
    defer {
        _ = std.c.close(pair[0]);
        _ = std.c.close(pair[1]);
    }

    // Register a client
    _ = try mgr.registerClient(toI32(pair[0]));
    try std.testing.expect(mgr.clientCount() == 1);

    // Remove client by fd
    const removed_id = mgr.removeClientByFd(toI32(pair[0]), .test_only);
    try std.testing.expect(removed_id != null);
    try std.testing.expect(mgr.clientCount() == 0);
}

test "SseManager: register and remove multiple clients" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);
    defer mgr.deinit();

    // Create multiple socket pairs
    const pair1 = try createSocketPair();
    const pair2 = try createSocketPair();
    const pair3 = try createSocketPair();
    defer {
        _ = std.c.close(pair1[0]);
        _ = std.c.close(pair1[1]);
        _ = std.c.close(pair2[0]);
        _ = std.c.close(pair2[1]);
        _ = std.c.close(pair3[0]);
        _ = std.c.close(pair3[1]);
    }

    // Register multiple clients
    _ = try mgr.registerClient(toI32(pair1[0]));
    _ = try mgr.registerClient(toI32(pair2[0]));
    _ = try mgr.registerClient(toI32(pair3[0]));
    try std.testing.expect(mgr.clientCount() == 3);

    // Remove each client one by one
    _ = mgr.removeClientByFd(toI32(pair2[0]), .test_only);
    try std.testing.expect(mgr.clientCount() == 2);

    _ = mgr.removeClientByFd(toI32(pair1[0]), .test_only);
    try std.testing.expect(mgr.clientCount() == 1);

    _ = mgr.removeClientByFd(toI32(pair3[0]), .test_only);
    try std.testing.expect(mgr.clientCount() == 0);
}

test "SseManager: remove by ID works correctly" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);
    defer mgr.deinit();

    const pair = try createSocketPair();
    defer {
        _ = std.c.close(pair[0]);
        _ = std.c.close(pair[1]);
    }

    const id = try mgr.registerClient(toI32(pair[0]));
    try std.testing.expect(mgr.clientCount() == 1);

    // Remove by ID
    mgr.removeClient(id, .test_only);
    try std.testing.expect(mgr.clientCount() == 0);
}

test "SseManager: remove non-existent client returns null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);
    defer mgr.deinit();

    // Try to remove a client that doesn't exist
    const result = mgr.removeClientByFd(9999, .test_only);
    try std.testing.expect(result == null);
}

test "SseManager: deinit cleans up all clients" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);

    // Create and register multiple clients
    var socket_pairs = std.ArrayListUnmanaged([2]std.c.fd_t){ .items = &.{}, .capacity = 0 };
    defer {
        // Note: manager already closed read ends, only close write ends
        for (socket_pairs.items) |fds| {
            _ = std.c.close(fds[1]);
        }
        socket_pairs.deinit(allocator);
    }

    for (0..5) |_| {
        const fds = try createSocketPair();
        try socket_pairs.append(allocator, fds);
        _ = try mgr.registerClient(toI32(fds[0]));
    }

    try std.testing.expect(mgr.clientCount() == 5);

    // deinit should clean up without crashing
    mgr.deinit();

    // Close the other ends of socket pairs
    for (socket_pairs.items) |fds| {
        _ = std.c.close(fds[1]);
    }
}

test "SseManager: removeClientByFd then removeClient (race condition test)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);
    defer mgr.deinit();

    const pair = try createSocketPair();
    defer {
        _ = std.c.close(pair[0]);
        _ = std.c.close(pair[1]);
    }

    _ = try mgr.registerClient(toI32(pair[0]));

    // First removal by fd
    const removed = mgr.removeClientByFd(toI32(pair[0]), .test_only);
    try std.testing.expect(removed != null);
    try std.testing.expect(mgr.clientCount() == 0);

    // Second removal by id should be a no-op
    mgr.removeClient(removed.?, .test_only);
    try std.testing.expect(mgr.clientCount() == 0);
}

test "SseManager: removeClient then removeClientByFd (race condition test)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);
    defer mgr.deinit();

    const pair = try createSocketPair();
    defer {
        _ = std.c.close(pair[0]);
        _ = std.c.close(pair[1]);
    }

    const id = try mgr.registerClient(toI32(pair[0]));

    // First removal by id
    mgr.removeClient(id, .test_only);
    try std.testing.expect(mgr.clientCount() == 0);

    // Second removal by fd should be a no-op
    const removed = mgr.removeClientByFd(toI32(pair[0]), .test_only);
    try std.testing.expect(removed == null);
    try std.testing.expect(mgr.clientCount() == 0);
}

test "SseManager: register same fd twice returns same id" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);
    defer mgr.deinit();

    const pair = try createSocketPair();
    defer {
        _ = std.c.close(pair[0]);
        _ = std.c.close(pair[1]);
    }

    const id1 = try mgr.registerClient(toI32(pair[0]));
    const id2 = try mgr.registerClient(toI32(pair[0]));

    // Should return the same id (no duplicate registration)
    try std.testing.expectEqualSlices(u8, &id1, &id2);
    try std.testing.expect(mgr.clientCount() == 1);
}

test "SseClient: deinit doesn't crash on closed fd" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    // Create an invalid socket fd by closing immediately
    const pair = try createSocketPair();
    // Close the first socket
    _ = std.c.close(pair[0]);

    var id: [16]u8 = undefined;
    @memset(&id, 0);

    // Create client with already-closed fd
    var client = SseClient.init(id, toI32(pair[0]), allocator, io);

    // deinit should not crash even though fd is invalid
    client.deinit();
    _ = std.c.close(pair[1]);
}

test "SseManager: stress test - rapid add/remove" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);
    defer mgr.deinit();

    // Rapidly add and remove clients
    var socket_pairs = std.ArrayListUnmanaged([2]std.c.fd_t){ .items = &.{}, .capacity = 0 };
    defer {
        // Close write ends (read ends were closed by mgr.deinit)
        for (socket_pairs.items) |fds| {
            _ = std.c.close(fds[1]);
        }
        socket_pairs.deinit(allocator);
    }

    for (0..10) |_| {
        const fds = try createSocketPair();
        try socket_pairs.append(allocator, fds);
        _ = try mgr.registerClient(toI32(fds[0]));
    }

    try std.testing.expect(mgr.clientCount() == 10);

    // Remove all in reverse order
    for (0..10) |i| {
        const idx = 10 - 1 - i;
        _ = mgr.removeClientByFd(toI32(socket_pairs.items[idx][0]), .test_only);
    }

    try std.testing.expect(mgr.clientCount() == 0);

    // Clean up other ends
    for (socket_pairs.items) |fds| {
        _ = std.c.close(fds[1]);
    }
}

test "SseManager: gracefulShutdown with ArenaAllocator - no crash" {
    // This test verifies that gracefulShutdown doesn't crash with an ArenaAllocator.
    // The bug was that deinit() calls arena.deinit() which was corrupting the
    // canary tracking when used with DebugAllocator.
    // Using ArenaAllocator as a simpler allocator that doesn't track canaries.

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});

    defer threaded.deinit();

    const io = threaded.io();
    var mgr = try SseManager.init(allocator, server_allocator, io);

    // Create and register multiple clients
    var socket_pairs = std.ArrayListUnmanaged([2]std.c.fd_t){ .items = &.{}, .capacity = 0 };
    defer {
        for (socket_pairs.items) |fds| {
            _ = std.c.close(fds[1]);
        }
        socket_pairs.deinit(allocator);
    }

    for (0..5) |_| {
        const fds = try createSocketPair();
        try socket_pairs.append(allocator, fds);
        _ = try mgr.registerClient(toI32(fds[0]));
    }

    try std.testing.expect(mgr.clientCount() == 5);

    // gracefulShutdown should NOT crash with ArenaAllocator
    mgr.gracefulShutdown();

    // After gracefulShutdown, client count should be 0
    try std.testing.expect(mgr.clientCount() == 0);

    // Clean up other ends after gracefulShutdown closed them
    for (socket_pairs.items) |fds| {
        _ = std.c.close(fds[1]);
    }

    // Final deinit should be clean
    mgr.deinit();
}

/// Worker for the send-timeout regression test. File scope (not a
/// local) because a regression means the thread is STILL BLOCKED when
/// the test finishes — a stack-local context would dangle.
const SendTimeoutWorker = struct {
    fd: i32 = -1,
    payload: []const u8 = &.{},
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    err: ?anyerror = null,

    fn run(self: *SendTimeoutWorker) void {
        self.err = if (sse_manager.writeChunkedFrame(self.fd, self.payload)) |_| null else |e| e;
        self.done.store(true, .release);
    }
};
var send_timeout_worker: SendTimeoutWorker = .{};

test "sse: setFdSendTimeout bounds a write to a peer that never reads" {
    // POSIX-only: exercises the `struct timeval` SO_SNDTIMEO path.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const pair = try createSocketPair();
    defer closeSocketPair(pair);

    // 500 ms so the test stays fast; production uses 5 s.
    sse_manager.setFdSendTimeout(toI32(pair[0]), 500);

    // Nobody ever reads pair[1]. Without the send timeout this call
    // parks the emitting thread forever — the exact production hazard
    // documented on SSE_SEND_TIMEOUT_MS (one dead SSE peer holding
    // `SseManager.lock` and stalling the agent workflow thread, whose
    // chunk queue then overflows and aborts the LLM stream with
    // WriteError).
    const payload = try std.testing.allocator.alloc(u8, 8 * 1024 * 1024);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'x');

    send_timeout_worker = .{ .fd = toI32(pair[0]), .payload = payload };
    const worker = std.Thread.spawn(.{}, SendTimeoutWorker.run, .{&send_timeout_worker}) catch
        return error.SkipZigTest;
    // Deliberately detached: on a regression the thread is wedged in a
    // blocking send, and joining would hang the test suite. Detaching is
    // safe because the context is file-scope, and closing the socketpair
    // (the `defer` above) unblocks the send so the thread exits.
    worker.detach();

    // Watchdog: fail cleanly instead of hanging the runner.
    const deadline_ns = std.Io.Timestamp.now(std.testing.io, .awake).nanoseconds + 10 * std.time.ns_per_s;
    while (!send_timeout_worker.done.load(.acquire) and
        std.Io.Timestamp.now(std.testing.io, .awake).nanoseconds < deadline_ns)
    {
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake) catch {};
    }
    if (!send_timeout_worker.done.load(.acquire)) {
        std.debug.print(
            \\
            \\!! writeChunkedFrame is STILL BLOCKED after 10s on a peer that never reads !!
            \\   setFdSendTimeout did not apply SO_SNDTIMEO. One dead SSE client can
            \\   then park the emitting thread (and SseManager.lock) forever, which
            \\   stalls the agent workflow thread mid-stream.
            \\
        , .{});
        return error.SendNotBoundedByTimeout;
    }

    try std.testing.expectEqual(@as(?anyerror, error.WriteFailed), send_timeout_worker.err);
}

/// Resolve `sse_manager.zig` from whichever cwd the suite is running
/// under. Two callers exist:
///   - the parent suite (`zig build test` at the repo root, which is
///     what CI runs) → repo-root-relative path first;
///   - the package's own `zig build test` (`cd src/modules/kabelweb`)
///     → package-local path.
/// `sse_chunked_test.zig` hardcodes the repo-root form; we tolerate both
/// so the standalone package suite keeps working too.
fn readSseManagerSource(allocator: std.mem.Allocator) ![]u8 {
    const candidates = [_][]const u8{
        "src/modules/kabelweb/src/server/sse_manager.zig",
        "src/server/sse_manager.zig",
    };
    var last_err: anyerror = error.FileNotFound;
    for (candidates) |path| {
        const result = std.Io.Dir.cwd().readFileAlloc(
            std.testing.io,
            path,
            allocator,
            .limited(256 * 1024),
        );
        if (result) |source| {
            return source;
        } else |err| {
            last_err = err;
        }
    }
    return last_err;
}

test "sse: registerClient applies the send timeout to every SSE socket" {
    // Static contract: the socket bound is only useful if it is actually
    // applied when a client connects. `registerClient` is the single
    // production registration path (registerClientForTest is test-only),
    // so the call must live there.
    const source = try readSseManagerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    const fn_start = std.mem.indexOf(u8, source, "pub fn registerClient(") orelse
        return error.RegisterClientMissing;
    const fn_end = std.mem.indexOfPos(u8, source, fn_start, "\n    }\n") orelse
        return error.RegisterClientBodyMissing;
    const body = source[fn_start..fn_end];

    if (std.mem.indexOf(u8, body, "setFdSendTimeout(") == null) {
        std.debug.print(
            \\
            \\!! sse_manager.zig: registerClient does not call setFdSendTimeout !!
            \\   A stuck SSE peer would park the emitting thread forever while
            \\   holding SseManager.lock, stalling every SSE emit in the process
            \\   (including the agent's llm_chunk stream). See SSE_SEND_TIMEOUT_MS.
            \\
        , .{});
        return error.RegisterClientMissingSendTimeout;
    }
}