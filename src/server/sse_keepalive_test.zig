// ============================================================================
// SSE keepalive stress test — repros the "client is removed ~15s after
// open" symptom seen in the frontend on a real Pro/Vite setup, but in
// a 100%-controlled Zig unit test (no Vite, no browser, no proxy).
//
// The user-visible bug is: an SSE connection drops at irregular intervals
// (8s, 15s, 90s, 132s in the user-reported DevTools screenshot) and the
// frontend re-enters its reconnect loop. The exact 15s pattern matches
// the SSE manager's `sweepStaleClients` threshold (`heartbeat_secs * 3`).
//
// This test stands up a real `SseManager` with a real registered client
// (via socketpair), runs the event loop for ~20s on a worker thread, and
// asserts the client is STILL alive at the end. If sweepStaleClients
// is firing spuriously, the assertion fails — and the `[sse]` log lines
// tell us exactly which path removed the client.
//
// Setup:
//   - Server side fd (pair[0]) is registered with SseManager.
//   - Client side fd (pair[1]) is drained on a separate thread, so the
//     kernel buffer never fills up and `write` never blocks.
//   - 5s heartbeat (matches production binary).
//   - 20s runtime: long enough for 3 heartbeat cycles AND 1 sweep cycle
//     at the 15s threshold, so any spurious sweep would have fired.
// ============================================================================

const std = @import("std");
const posix = std.posix;
const sse_manager = @import("sse_manager.zig");
const SseManager = sse_manager.SseManager;
const builtin = @import("builtin");

fn createSocketPair() ![2]std.c.fd_t {
    var fds: [2]std.c.fd_t = undefined;
    const rc = posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc < 0) return error.SocketPairFailed;
    return fds;
}

/// Drains `fd` into the void so the kernel send buffer never fills up.
/// This mimics a healthy peer that reads everything the server sends
/// (so write() never sees EAGAIN / never returns a partial write).
fn drainThread(fd: i32) void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.system.read(fd, &buf, buf.len);
        if (n <= 0) break;
    }
}

test "sse keepalive: server does NOT mis-remove a healthy client under 60s" {
    if (builtin.os.tag == .windows) {
        // The SseManager uses posix-only primitives (socketpair, poll,
        // sendto). The test infra runs on POSIX; skip on Windows.
        return;
    }

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

    // socketpair: [0] = server side, [1] = client side
    const pair = try createSocketPair();
    defer {
        _ = std.c.close(pair[0]);
        _ = std.c.close(pair[1]);
    }

    // Register the server-side fd with the SSE manager
    _ = try mgr.registerClient(pair[0]);

    // Spawn the client-side drain thread. Without this, the kernel
    // send buffer would fill up after ~64 KB of heartbeats and
    // write() would block — that's a confounding variable we want
    // to avoid here.
    const drainT = try std.Thread.spawn(.{}, drainThread, .{pair[1]});
    defer drainT.join();

    // Spawn the SSE event loop with a 5s heartbeat (matches production).
    const loopT = try std.Thread.spawn(.{}, struct {
        fn run(sm: *SseManager, secs: u32) void {
            sm.startEventLoop(secs) catch |err| {
                std.debug.print("SSE event loop error: {s}\n", .{@errorName(err)});
            };
        }
    }.run, .{ &mgr, @as(u32, 5) });
    _ = loopT;
    defer {
        mgr.stop();
        // No join — the event loop threads were spawned via Io.Group
        // which doesn't expose them as joinable handles. They'll exit
        // naturally when running=false and the Io runtime is torn down
        // by `threaded.deinit()` below. We're done with the mgr after
        // the assertion, so a late background crash is acceptable.
    }

    // Spin for 60s — long enough to catch the bug the user
    // reproduced in the browser (heartbeat #7 is the last one
    // delivered at ~t=30s, then onerror at ~t=46s). The earlier 20s
    // version of this test wasn't long enough; we know better now.
    std.debug.print("\n--- 60s soak test starting ---\n", .{});
    std.debug.print("    heartbeat = 5s, sweep threshold = 15s\n", .{});
    std.debug.print("    if client is removed at or before t=60s: BUG REPRODUCED\n", .{});
    std.debug.print("    if client is removed by sweep_stale: maybe the bug\n", .{});
    std.debug.print("    if client is removed by eof_read: peer-side close\n", .{});
    std.debug.print("    if client is removed by heartbeat_write_failed: kernel write failed\n", .{});
    const period_ns: u64 = 500 * std.time.ns_per_ms;
    const total_periods: usize = 120; // 120 * 500ms = 60s
    var iter: usize = 0;
    while (iter < total_periods) : (iter += 1) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = period_ns };
        _ = std.c.nanosleep(&ts, null);
        const count = mgr.clientCount();
        const elapsed_s = iter / 2;
        std.debug.print("    t={d}s clientCount={d}\n", .{ elapsed_s, count });
    }
    std.debug.print("--- 60s soak complete ---\n\n", .{});

    // The core assertion. If the client is gone, the SSE manager
    // mis-removed a healthy client. The [sse] stderr from the event
    // loop will tell us which path (heartbeat_write_failed /
    // sweep_stale / eof_read) was the cause.
    try std.testing.expect(mgr.clientCount() == 1);
    try std.testing.expect(mgr.getClientIdByFd(pair[0]) != null);

    mgr.deinit();
}

// 2-client variant — same setup as the 1-client soak, but with TWO
// healthy peers. Exercises both shards of `id[0] % LOOP_COUNT`
// simultaneously (LOOP_COUNT = 4, so two random ids may land in
// different shards). If the SSE manager's per-shard heartbeat logic
// has a per-instance bug (e.g., the second shard's poll loop is
// racing the first), it would surface here but not in the 1-client
// test.
test "sse keepalive: server does NOT mis-remove 2 healthy clients under 60s" {
    if (builtin.os.tag == .windows) {
        return;
    }

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

    // Two socketpairs. Each pair[0] goes to the SSE manager, pair[1]
    // goes to its own drain thread.
    const pair_a = try createSocketPair();
    const pair_b = try createSocketPair();
    defer {
        _ = std.c.close(pair_a[0]);
        _ = std.c.close(pair_a[1]);
        _ = std.c.close(pair_b[0]);
        _ = std.c.close(pair_b[1]);
    }

    const id_a = try mgr.registerClient(pair_a[0]);
    const id_b = try mgr.registerClient(pair_b[0]);
    std.debug.print("client A id[0]={x} id_b id[0]={x} (same shard? {any})\n", .{
        id_a[0],
        id_b[0],
        id_a[0] % 4 == id_b[0] % 4,
    });

    // Drain both sockets on separate threads.
    const drainA = try std.Thread.spawn(.{}, drainThread, .{pair_a[1]});
    const drainB = try std.Thread.spawn(.{}, drainThread, .{pair_b[1]});
    defer drainA.join();
    defer drainB.join();

    // Spawn the SSE event loop.
    const loopT = try std.Thread.spawn(.{}, struct {
        fn run(sm: *SseManager, secs: u32) void {
            sm.startEventLoop(secs) catch |err| {
                std.debug.print("SSE event loop error: {s}\n", .{@errorName(err)});
            };
        }
    }.run, .{ &mgr, @as(u32, 5) });
    _ = loopT;
    defer mgr.stop();

    std.debug.print("\n--- 60s 2-client soak starting ---\n", .{});
    std.debug.print("    heartbeat = 5s, sweep threshold = 15s\n", .{});
    std.debug.print("    if EITHER client is removed: BUG REPRODUCED\n", .{});
    const period_ns: u64 = 500 * std.time.ns_per_ms;
    const total_periods: usize = 120;
    var iter: usize = 0;
    while (iter < total_periods) : (iter += 1) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = period_ns };
        _ = std.c.nanosleep(&ts, null);
        const count = mgr.clientCount();
        const elapsed_s = iter / 2;
        std.debug.print("    t={d}s clientCount={d}\n", .{ elapsed_s, count });
    }
    std.debug.print("--- 60s 2-client soak complete ---\n\n", .{});

    try std.testing.expect(mgr.clientCount() == 2);
    try std.testing.expect(mgr.getClientIdByFd(pair_a[0]) != null);
    try std.testing.expect(mgr.getClientIdByFd(pair_b[0]) != null);

    mgr.deinit();
}