//! Regression tests for HTTP/1.1 chunked-transfer-encoding in
//! `sse_manager.zig` (Tasks 1 & 2 of
//! `docs/superpowers/plans/2026-06-19-fix-sse-incomplete-chunked-encoding.md`).
//!
//! NOTE: this file lives next to `sse_manager_test.zig` but is a
//! separate file because `sse_manager_test.zig` is currently dead in
//! this branch — it uses `std.Io.init()` which doesn't compile on
//! Zig 0.16, and the project's root test runner only imports
//! `test_session_lifecycle.zig` from this module, not
//! `sse_manager_test.zig`. This file is registered in
//! `src/root.zig` (line 401) so it runs as part of the project-wide
//! `zig build test` step.

const std = @import("std");
const posix = std.posix;
const sse_manager = @import("sse_manager.zig");
const SseManager = sse_manager.SseManager;
const builtin = @import("builtin");
const helpers = @import("test_helpers.zig");
const toI32 = helpers.toI32;
const is_windows = builtin.os.tag == .windows;

/// Windows-only Winsock extern for recv + closesocket. The test
/// fixture creates raw winsock SOCKETS (not registered with UCRT via
/// `_open_osfhandle`), so MSVCRT's `read()` / `close()` don't work on
/// them (they call `ReadFile` / `_close()` which fail on sockets).
/// Winsock APIs (`recv`, `closesocket`) take the SOCKET value as c_int
/// — recovered via `toI32(fd)` — and bypass UCRT entirely. Empty
/// struct on non-Windows so non-Windows builds don't link ws2_32.
const winsock = if (is_windows) struct {
    extern "ws2_32" fn recv(
        sockfd: c_int,
        buf: [*]u8,
        len: c_int,
        flags: c_int,
    ) callconv(.c) c_int;
    extern "ws2_32" fn closesocket(sockfd: c_int) callconv(.c) c_int;
} else struct {};

fn closeFd(fd: std.c.fd_t) void {
    // Windows: std.c.close on a raw winsock SOCKET fails (UCRT's
    // _close looks up the fd in its table — raw SOCKETs aren't there).
    // Use closesocket directly. On POSIX, std.c.close works fine on
    // socketpair fds.
    if (is_windows) {
        _ = winsock.closesocket(toI32(fd));
    } else {
        _ = std.c.close(fd);
    }
}

fn readFd(fd: std.c.fd_t, buf: []u8, len: usize) isize {
    // Same reasoning as closeFd above: std.c.read on a raw winsock
    // SOCKET fails on Windows (UCRT's _read uses ReadFile, which
    // doesn't work on sockets). Use winsock.recv directly — same
    // ABI as libc's recv(2) on POSIX, so the POSIX path is a no-op.
    if (is_windows) {
        return winsock.recv(toI32(fd), buf.ptr, @intCast(len), 0);
    } else {
        return posix.system.read(fd, buf.ptr, len);
    }
}

fn createSocketPair() ![2]std.c.fd_t {
    return helpers.createSocketPair();
}

// ============================================================================
// Task 1: writeChunkedFrame / sendChunked / sendTerminatingChunk
// ============================================================================

test "writeChunkedFrame: writes <hex len>\\r\\n<data>\\r\\n" {
    const pair = try createSocketPair();
    defer _ = closeFd(pair[0]);
    defer _ = closeFd(pair[1]);

    try sse_manager.writeChunkedFrame(toI32(pair[0]), "event: ping\ndata: 1\n\n");

    // Read on the OTHER end of the socketpair and assert the chunked frame.
    // Data is 21 bytes → hex len "15" → "15\r\n" (4) + data (21) + "\r\n" (2) = 27.
    var buf: [64]u8 = undefined;
    const n = readFd(pair[1], &buf, buf.len);
    try std.testing.expect(n == 27);
    try std.testing.expectEqualSlices(u8, "15\r\nevent: ping\ndata: 1\n\n\r\n", buf[0..@intCast(n)]);
}

test "writeChunkedFrame: empty data writes 0\\r\\n\\r\\n (chunked terminator)" {
    const pair = try createSocketPair();
    defer _ = closeFd(pair[0]);
    defer _ = closeFd(pair[1]);

    try sse_manager.writeChunkedFrame(toI32(pair[0]), "");

    var buf: [16]u8 = undefined;
    const n = readFd(pair[1], &buf, buf.len);
    try std.testing.expect(n == 5);
    try std.testing.expectEqualSlices(u8, "0\r\n\r\n", buf[0..@intCast(n)]);
}

test "SseClient: sendEvent writes <hex len>\\r\\n<data>\\r\\n" {
    const pair = try createSocketPair();
    defer _ = closeFd(pair[0]);
    defer _ = closeFd(pair[1]);

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const id: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    var client: sse_manager.SseClient = .init(id, toI32(pair[0]), std.testing.allocator, threaded.io());
    // Suppress the per-client arena cleanup on scope-exit (it would
    // double-free the fd that `closeFd(pair[0])` above
    // also closes). The test only needs `client.sendEvent` to write
    // the chunked frame; we explicitly call `forceDestroy` to close
    // the fd without deinitialising the arena.
    defer client.forceDestroy();
    try client.sendEvent("event: ping\ndata: 1\n\n");

    var buf: [64]u8 = undefined;
    const n = readFd(pair[1], &buf, buf.len);
    try std.testing.expect(n == 27);
    try std.testing.expectEqualSlices(u8, "15\r\nevent: ping\ndata: 1\n\n\r\n", buf[0..@intCast(n)]);
}

test "SseManager: sendChunked on missing client returns ClientNotFound" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var mgr = try SseManager.init(std.testing.allocator, std.testing.allocator, threaded.io());
    defer mgr.deinit();

    var bogus: [16]u8 = undefined;
    @memset(&bogus, 0xAB);
    const err = mgr.sendChunked(bogus, "data: x\n\n") catch |e| e;
    try std.testing.expectEqual(error.ClientNotFound, err);
}

// ============================================================================
// Task 2: removeClient sends the chunked-encoding terminator before closing
// ============================================================================

test "SseManager: removeClient sends the terminating chunk (0\\r\\n\\r\\n) before close" {
    // Regression test for the
    // `net::ERR_INCOMPLETE_CHUNKED_ENCODING 200 (OK)` browser error: every
    // SSE connection must end with `0\r\n\r\n` so the peer's chunked-
    // decoder can finalize cleanly. `removeClient` is responsible for
    // flushing the terminator before closing the fd.
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    // Wrap the server_allocator in an ArenaAllocator so the hash map's
    // backing memory is freed when the arena is deinit'd (SseManager.deinit
    // calls clearRetainingCapacity which keeps the storage around, and
    // DebugAllocator flags the residual as a leak otherwise).
    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var mgr = try SseManager.init(std.testing.allocator, server_allocator, threaded.io());
    defer mgr.deinit();

    const pair = try createSocketPair();
    // We do NOT close pair[0] here — removeClient's sendTerminatingChunk
    // will write to it, and then deinit() will close it. We only own
    // the read end.
    defer _ = closeFd(pair[1]);

    // Use registerClientForTest so the random-id path (which requires
    // being on the Io thread) is bypassed.
    const id = try mgr.registerClientForTest(toI32(pair[0]), .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });

    // Send one event so the peer has a chunked frame on the wire.
    try mgr.sendChunked(id, "event: ping\ndata: 1\n\n");

    // removeClient must (a) flush the terminator, then (b) close the fd.
    mgr.removeClient(id, .test_only);

    // Read everything available on the peer end. Expected sequence:
    //   "15\r\nevent: ping\ndata: 1\n\n\r\n0\r\n\r\n"
    //  =  4 + 21 + 2 + 5 = 32 bytes.
    //  (the hex length "15" is 2 chars, then \r\n, then the 21-byte
    //  data, then \r\n trailer, then the 5-byte terminator "0\r\n\r\n")
    var buf: [64]u8 = undefined;
    // posix.system.read takes ([*]u8, usize), so we pass `&buf` (which
    // coerces from *[64]u8 to [*]u8) and `buf.len`. We do best-effort:
    // the close from removeClient causes the remaining bytes to be
    // available; we may need one or two reads to drain the kernel
    // buffer.
    var total: usize = 0;
    while (total < 32) {
        const n = readFd(pair[1], &buf, buf.len - total);
        if (n <= 0) break;
        total += @intCast(n);
    }

    try std.testing.expect(total == 32);
    try std.testing.expectEqualSlices(
        u8,
        "15\r\nevent: ping\ndata: 1\n\n\r\n0\r\n\r\n",
        buf[0..total],
    );
}

// ============================================================================
// Task 3: HTTP response headers declare Transfer-Encoding: chunked
// ============================================================================
//
// Regression guard for
// `net::ERR_INCOMPLETE_CHUNKED_ENCODING 200 (OK)` in the browser.
//
// Per RFC 9112 §6, an HTTP/1.1 response with neither `Content-Length` nor
// `Transfer-Encoding` is implicitly framed by connection-close. For an
// SSE stream we never close the connection voluntarily, so we MUST declare
// chunked encoding in the response headers. Without this declaration,
// intermediaries (Vite, nginx, Cloudflare, ALB) misinterpret the response
// and surface `ERR_INCOMPLETE_CHUNKED_ENCODING` on disconnect.
//
// We test this via static source-check (the pattern used by 12+ other
// tests in this codebase, e.g.
// `src/http_handlers/git_pr_create_test.zig`). A
// behavioural GinwaServer-level test would require spinning up a real
// Io runtime + concurrent group + accepting socket, which is brittle for
// a unit test and out of scope for this task. The source-check is the
// canonical regression guard for "header X is present on response Y".

const HTTP_SERVER_CANDIDATES = &.{
    // cwd = repo root (repo-root `zig build test` gate)
    "src/modules/kabelweb/src/server/http_server.zig",
    // cwd = kabelweb package dir (package's own `zig build test`)
    "src/server/http_server.zig",
};

fn readHttpServerSource(allocator: std.mem.Allocator) ![]u8 {
    // `.unlimited` so the static source-check tests don't break when
    // http_server.zig grows past the previous 64 KiB cap (currently
    // ~65.8 KiB on `worktree/fix-ci-windows-webview2`). The previous
    // `.limited(64 * 1024)` surfaced as `error.StreamTooLong` on Windows
    // and caused 4 of the source-check tests to fail there while passing
    // on Linux/macOS (the failure was OS-independent — purely a file-
    // size limit). `.unlimited` matches the contract of every other
    // test that does source-grep; the read still goes through the
    // arena-allocator and the file is freed by the caller.
    // Try each candidate cwd-relative path in order — the suite runs
    // both from the repo root (root gate) and from the kabelweb package
    // dir (package's own build), which have different cwds.
    var last_err: anyerror = error.FileNotFound;
    inline for (HTTP_SERVER_CANDIDATES) |path| {
        if (std.Io.Dir.cwd().readFileAlloc(
            std.testing.io,
            path,
            allocator,
            .unlimited,
        )) |source| {
            return source;
        } else |err| {
            last_err = err;
        }
    }
    return last_err;
}

test "HTTP server: SSE response declares Transfer-Encoding: chunked" {
    // Regression for `net::ERR_INCOMPLETE_CHUNKED_ENCODING`. The SSE
    // response headers in the `.sse =>` arm of `GinwaServer.handle` must
    // include `Transfer-Encoding: chunked` so HTTP/1.1 intermediaries
    // forward the body using chunked-decoding semantics.
    const source = try readHttpServerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    if (std.mem.indexOf(u8, source, "Transfer-Encoding: chunked") == null) {
        std.debug.print("\n!! http_server.zig missing Transfer-Encoding: chunked !!\n", .{});
        return error.TransferEncodingChunkedMissing;
    }
}

test "HTTP server: SSE response sets X-Accel-Buffering: no" {
    // Regression for `net::ERR_INCOMPLETE_CHUNKED_ENCODING` under Vite /
    // nginx / Cloudflare / ALB. `X-Accel-Buffering: no` is the de-facto
    // standard signal to disable response buffering so SSE chunks reach
    // the client as soon as the server writes them.
    const source = try readHttpServerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    if (std.mem.indexOf(u8, source, "X-Accel-Buffering: no") == null) {
        std.debug.print("\n!! http_server.zig missing X-Accel-Buffering: no !!\n", .{});
        return error.XAccelBufferingMissing;
    }
}

test "HTTP server: SSE response says Connection: close (NOT keep-alive)" {
    // Regression for the "SSE drops every 30s" bug under Vite / WebKitGTK /
    // WKWebView. Sending `Connection: keep-alive` on an SSE response is a
    // lie — the connection is never reused for a follow-up request — and
    // Node.js's HTTP server stamps `Keep-Alive: timeout=5` on keep-alive
    // responses, which some browsers enforce aggressively (closing the
    // upstream socket ~5s after the last heartbeat). Empirically this
    // matches the user's reported pattern of heartbeats stopping after
    // ~30s in the browser DevTools. The correct header is `Connection:
    // close` — telling intermediaries this stream ends when the socket
    // closes — combined with `Transfer-Encoding: chunked` (so HTTP/1.1
    // knows the body is chunk-bounded rather than connection-bounded).
    //
    // NOTE: We search for the literal header NAME without the trailing
    // `\r\n` because in the Zig source the `\r\n` is an escape sequence
    // (4 source bytes: `\`, `r`, `\`, `n`) rather than 2 real CR+LF
    // bytes. That's enough to disambiguate from comments / docstrings.
    const source = try readHttpServerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    // The SSE arm must declare `Connection: close`.
    if (std.mem.indexOf(u8, source, "\"Connection: close\\r\\n\"") == null) {
        std.debug.print("\n!! http_server.zig SSE arm missing '\"Connection: close\\\\r\\\\n\"' string literal !!\n", .{});
        return error.SseConnectionCloseMissing;
    }
    // The SSE arm must NOT declare `Connection: keep-alive`.
    if (std.mem.indexOf(u8, source, "\"Connection: keep-alive\\r\\n\"") != null) {
        std.debug.print("\n!! http_server.zig SSE arm still sends 'Connection: keep-alive' (causes ~30s drop under Vite) !!\n", .{});
        return error.SseConnectionKeepAliveStillPresent;
    }
}

// ============================================================================
// Task 4 (long-period fix #1): sendHeartbeat must take the SseManager lock
// when snapshotting client pointers.
//
// Bug history: the lock was COMMENTED OUT in sendHeartbeat, while
// broadcast/broadcastTyped correctly take it. Under concurrent
// registerClient/removeClient activity, the unlocked iterator could
// be invalidated mid-iteration and the captured `entry.value_ptr.*`
// could read freed memory (use-after-free). On a long-idle page with
// many connections, the corruption surfaces as a half-flushed chunked
// terminator, which the browser reports as
// `net::ERR_INCOMPLETE_CHUNKED_ENCODING 200 (OK)` once the connection
// finally drops.
//
// This is a static source-check (matching the project's established
// pattern for "guard against revert" tests, see the 12+ tests in
// `src/http_handlers/`). We assert the function body
// contains BOTH the lock acquisition AND the matching unlock — guards
// against someone re-commenting the lock again.
// ============================================================================

const SSE_MANAGER_CANDIDATES = &.{
    // cwd = repo root (repo-root `zig build test` gate)
    "src/modules/kabelweb/src/server/sse_manager.zig",
    // cwd = kabelweb package dir (package's own `zig build test`)
    "src/server/sse_manager.zig",
};

fn readSseManagerSource(allocator: std.mem.Allocator) ![]u8 {
    // See `readHttpServerSource` for the rationale on `.unlimited`.
    // sse_manager.zig is currently ~43 KiB (under the old 64 KiB cap)
    // but we use `.unlimited` here too so future growth doesn't break
    // these tests asymmetrically.
    var last_err: anyerror = error.FileNotFound;
    inline for (SSE_MANAGER_CANDIDATES) |path| {
        if (std.Io.Dir.cwd().readFileAlloc(
            std.testing.io,
            path,
            allocator,
            .unlimited,
        )) |source| {
            return source;
        } else |err| {
            last_err = err;
        }
    }
    return last_err;
}

test "SseManager: sendHeartbeat takes the manager lock during the client snapshot" {
    const source = try readSseManagerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    // Find the `fn sendHeartbeat` declaration and look at the next ~8 KiB
    // of body. Anything outside that window is irrelevant — we only care
    // that the lock is held while iterating `self.clients`, not the
    // IO loop after the snapshot. The 8 KiB window comfortably covers any
    // function body in this codebase (the longest observed is ~2.4 KiB).
    const decl = std.mem.indexOf(u8, source, "fn sendHeartbeat(") orelse {
        std.debug.print("\n!! sse_manager.zig missing `fn sendHeartbeat` !!\n", .{});
        return error.SendHeartbeatMissing;
    };
    const window_end = @min(decl + 8192, source.len);
    const body = source[decl..window_end];

    if (std.mem.indexOf(u8, body, "self.lock.lock(self.io)") == null) {
        std.debug.print(
            "\n!! sse_manager.zig: sendHeartbeat does not take `self.lock.lock(self.io)` !!\n" ++
                "   The lock MUST be held while iterating `self.clients`; an unlocked iteration\n" ++
                "   is a use-after-free race with concurrent registerClient/removeClient.\n",
            .{},
        );
        return error.SendHeartbeatLockMissing;
    }
    if (std.mem.indexOf(u8, body, "self.lock.unlock(self.io)") == null) {
        std.debug.print(
            "\n!! sse_manager.zig: sendHeartbeat does not release `self.lock` !!\n" ++
                "   The lock acquired during the client snapshot must be released before the\n" ++
                "   IO loop, otherwise the manager deadlocks on the next registerClient.\n",
            .{},
        );
        return error.SendHeartbeatUnlockMissing;
    }
    // Also guard against the lock being COMMENTED OUT — the regression
    // that motivated this fix was exactly `// self.lock.lock(...)` with
    // a leading `//`. A grep for the bare call is not enough; we check
    // the prefix lines too.
    if (std.mem.indexOf(u8, body, "// self.lock.lock(self.io)") != null or
        std.mem.indexOf(u8, body, "// self.lock.unlock(self.io)") != null)
    {
        std.debug.print(
            "\n!! sse_manager.zig: sendHeartbeat lock is commented out !!\n" ++
                "   Uncomment the `self.lock.lock(self.io)` / `self.lock.unlock(self.io)` lines.\n",
            .{},
        );
        return error.SendHeartbeatLockCommentedOut;
    }
}

// ============================================================================
// Task 5 (long-period fix #2): acceptClient must set SO_KEEPALIVE on every
// accepted SSE socket.
//
// Bug history: the previous acceptClient returned the fd without
// enabling TCP keepalive. On Linux, the default `tcp_keepalive_time`
// is 7200s (2 hours), so a silently-dropped connection (Wi-Fi loss,
// NAT table expiry, half-open TCP after a peer crash) was not detected
// at the kernel level. The server kept heartbeating into a dead socket
// for up to 2 hours; when the connection finally closed, the
// application-level heartbeat races (see Task 4 test above) could
// produce a half-flushed chunked terminator, which the browser reports
// as `net::ERR_INCOMPLETE_CHUNKED_ENCODING 200 (OK)`.
//
// Settings mirror `Agent.apply_tcp_keepalive`
// (`src/modules/agent/Agent.zig:793`) so outbound LLM conns and
// inbound browser conns fail at the same rate:
//   keepidle  = 10s, keepintvl = 5s, keepcnt = 3
//   → dead-conn detection in ~25s.
// ============================================================================

test "HTTP server: acceptClient sets SO_KEEPALIVE on accepted sockets" {
    const source = try readHttpServerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    // Find the `fn acceptClient` declaration and check the next ~8 KiB
    // of body — anything outside that window is irrelevant. The 8 KiB
    // window comfortably covers any function body in this codebase (the
    // longest observed is ~2.4 KiB for `acceptClient` itself, with
    // verbose keepalive comment). We assert that the function body
    // contains both the SO_KEEPALIVE setup AND the TCP keepalive timer
    // configuration (KEEPIDLE / KEEPINTVL / KEEPCNT), so a future
    // refactor that drops any of these is caught.
    const decl = std.mem.indexOf(u8, source, "fn acceptClient(") orelse {
        std.debug.print("\n!! http_server.zig missing `fn acceptClient` !!\n", .{});
        return error.AcceptClientMissing;
    };
    const window_end = @min(decl + 8192, source.len);
    const body = source[decl..window_end];

    if (std.mem.indexOf(u8, body, "posix.SO.KEEPALIVE") == null and
        std.mem.indexOf(u8, body, "SO.KEEPALIVE") == null)
    {
        std.debug.print(
            "\n!! http_server.zig: acceptClient does not set SO_KEEPALIVE !!\n" ++
                "   Without TCP keepalive, silent network drops (Wi-Fi loss, NAT timeout)\n" ++
                "   are not detected at the kernel level for up to 2 hours (Linux default).\n" ++
                "   Add `posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, ...)`\n" ++
                "   right after `socket.accept(...)` returns.\n",
            .{},
        );
        return error.SoKeepaliveMissing;
    }
    if (std.mem.indexOf(u8, body, "posix.TCP.KEEPIDLE") == null and
        std.mem.indexOf(u8, body, "TCP.KEEPIDLE") == null)
    {
        std.debug.print(
            "\n!! http_server.zig: acceptClient missing TCP_KEEPIDLE !!\n" ++
                "   SO_KEEPALIVE alone uses the system default (7200s on Linux). For an SSE\n" ++
                "   server that must detect dead clients within ~25s, override TCP_KEEPIDLE.\n",
            .{},
        );
        return error.TcpKeepidleMissing;
    }
    if (std.mem.indexOf(u8, body, "posix.TCP.KEEPINTVL") == null and
        std.mem.indexOf(u8, body, "TCP.KEEPINTVL") == null)
    {
        std.debug.print(
            "\n!! http_server.zig: acceptClient missing TCP_KEEPINTVL !!\n" ++
                "   Without an explicit probe interval, the OS uses the system default.\n",
            .{},
        );
        return error.TcpKeepintvlMissing;
    }
    if (std.mem.indexOf(u8, body, "posix.TCP.KEEPCNT") == null and
        std.mem.indexOf(u8, body, "TCP.KEEPCNT") == null)
    {
        std.debug.print(
            "\n!! http_server.zig: acceptClient missing TCP_KEEPCNT !!\n" ++
                "   Without an explicit probe count, the OS uses the system default.\n",
            .{},
        );
        return error.TcpKeepcntMissing;
    }
}

// ============================================================================
// Task 3: SSE Manager FD-leak regression tests
// (`docs/superpowers/plans/2026-06-30-fix-sse-fd-leak.md`)
// ============================================================================

test "SseManager: sweepStaleClients removes clients whose last_heartbeat is stale" {
    // Regression test for the periodic-stale sweep in
    // `docs/superpowers/plans/2026-06-30-fix-sse-fd-leak.md` Change 3.
    // A client whose `last_heartbeat` is older than `max_stale_ms` must
    // be reaped, closing its FD and freeing the SseClient.
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var mgr = try SseManager.init(std.testing.allocator, server_allocator, io);
    defer mgr.deinit();

    // Register a client backed by a real socket pair so the FD is valid
    // (we only want to test the staleness sweep, not POLL.NVAL).
    const pair = try createSocketPair();
    // The sweep closes pair[0] for us; we close the other end.
    defer _ = closeFd(pair[1]);
    const id: [16]u8 = .{ 0x42 } ** 16;
    _ = try mgr.registerClientForTest(toI32(pair[0]), id);
    try std.testing.expect(mgr.clientCount() == 1);

    // The client's `last_heartbeat` was set to `timestamp()` at register
    // time. Wait long enough that 200ms have elapsed (so a 100ms
    // staleness threshold catches it).
    try std.Io.sleep(io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .real);

    // Sweep with max_stale_ms=100 (anything older than 100ms is stale).
    mgr.sweepStaleClients(100, 64);
    try std.testing.expect(mgr.clientCount() == 0);
}

test "SseManager: sweepStaleClients respects max_per_call cap" {
    // The sweep helper is bounded per-call to avoid O(N²) behaviour when
    // a large batch goes stale at once (e.g., on a server-side rollback).
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var mgr = try SseManager.init(std.testing.allocator, server_allocator, io);
    defer mgr.deinit();

    const pair1 = try createSocketPair();
    const pair2 = try createSocketPair();
    const pair3 = try createSocketPair();
    const pair4 = try createSocketPair();
    defer _ = closeFd(pair1[1]);
    defer _ = closeFd(pair2[1]);
    defer _ = closeFd(pair3[1]);
    defer _ = closeFd(pair4[1]);

    _ = try mgr.registerClientForTest(toI32(pair1[0]), .{ 0x11 } ** 16);
    _ = try mgr.registerClientForTest(toI32(pair2[0]), .{ 0x22 } ** 16);
    _ = try mgr.registerClientForTest(toI32(pair3[0]), .{ 0x33 } ** 16);
    _ = try mgr.registerClientForTest(toI32(pair4[0]), .{ 0x44 } ** 16);
    try std.testing.expect(mgr.clientCount() == 4);

    // Make all 4 stale.
    try std.Io.sleep(io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .real);

    // Sweep with max_per_call=2 — at most 2 per call.
    mgr.sweepStaleClients(100, 2);
    try std.testing.expect(mgr.clientCount() == 2);

    // Second sweep picks up the remaining 2.
    mgr.sweepStaleClients(100, 2);
    try std.testing.expect(mgr.clientCount() == 0);
}

// ============================================================================
// Task 4 (2026-07-01): additional FD-leak / memory-leak regression tests
// (`docs/superpowers/plans/2026-07-01-fix-remaining-fd-leak-risks.md`).
//
// Three fixes audited on 2026-07-01 that were NOT addressed by the prior
// `5df11a9a` (POLL.NVAL) fix:
//   1. `sendToClient` reads `self.clients` and `client.fd` without holding
//      the lock — UAF + potential FD leak if a concurrent `removeClient`
//      frees the client while the writeChunkedFrame is in flight.
//   2. `deinit` and `gracefulShutdown` call `client.forceDestroy()` which
//      closes the fd but leaks the per-client arena + message_queue —
//      memory leak in long-lived servers that have served many distinct
//      connections.
//   3. `handleClientDisconnect` (in root.zig) only unregisters the FIRST
//      routing_key containing the client_id, leaving N-1 orphans in
//      `session_to_client_ids` for clients connected via the unified
//      SSE endpoint (which registers under N channels).
// ============================================================================

test "SseManager: sendToClient removes the client on a failed write (behavioural)" {
    // Verify the failed-write path correctly cleans up: after
    // sendToClient returns ClientDisconnected, the client must no
    // longer be in the manager (so the FD is properly closed and the
    // SseClient struct is freed).
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var mgr = try SseManager.init(std.testing.allocator, server_allocator, io);
    defer mgr.deinit();

    const pair = try createSocketPair();
    // We close pair[0] BEFORE calling sendToClient so the write
    // fails with EPIPE — this simulates the "peer crashed" scenario
    // that the failed-write branch must clean up. Use the closeFd
    // helper (which short-circuits on Windows, where sockets are HANDLE
    // not i32) instead of posix.system.close directly — calling the
    // latter on Windows fails to compile because posix.system.close
    // expects `*anyopaque` (fd_t on Windows) and we're passing i32.
    closeFd(pair[0]);
    defer closeFd(pair[1]);

    const id: [16]u8 = .{ 0xAA, 0xBB, 0xCC, 0xDD } ++ .{0} ** 12;
    _ = try mgr.registerClientForTest(toI32(pair[0]), id);
    try std.testing.expect(mgr.clientCount() == 1);

    // sendToClient should observe the failed write, remove the client,
    // and return error.ClientDisconnected.
    const result = mgr.sendToClient(id, "data: ping\n\n");
    try std.testing.expectError(error.ClientDisconnected, result);
    try std.testing.expect(mgr.clientCount() == 0);
}

test "SseManager: sendToClient returns ClientNotFound for an unknown id (behavioural)" {
    // Sanity check: the lock-protected path still returns ClientNotFound
    // when the id is not registered.
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer server_arena.deinit();
    const server_allocator = server_arena.allocator();

    var mgr = try SseManager.init(std.testing.allocator, server_allocator, io);
    defer mgr.deinit();

    const bogus: [16]u8 = .{0xFE} ** 16;
    const result = mgr.sendToClient(bogus, "data: hello\n\n");
    try std.testing.expectError(error.ClientNotFound, result);
}

// ============================================================================
// Task 6 (2026-08-24, "SSE always reconnecting" fix #1): the notify-pipe
// read in `runEventLoop` must be NON-BLOCKING and consume AT MOST ONE
// byte per wakeup.
//
// Bug history (verified live on the dev nalar, 2026-08-24): all
// LOOP_COUNT event loops poll the SAME pipe read-end. The old code did a
// BLOCKING `read(pipe, buf, 64)` that drained EVERY byte in the pipe.
// With one wakeup byte per registerClient, loop A consumed loops B/C/D's
// wakeups; those loops then called read() again and blocked FOREVER on
// an empty pipe (poll only re-reports readability when NEW bytes arrive,
// which never come because nobody writes more wakeups). Stranded loops
// stop heartbeating their shard → browser sees silence → EventSource
// reconnects forever. Live proof: 3 of 4 poll threads of the running
// nalar were GONE (`/proc/<pid>/task` had exactly one thread sitting in
// poll_schedule_timeout).
//
// This is a static source-check (house pattern — see the Task 4 test
// above) asserting:
//   1. The pipe-POLL.IN branch calls `drainPipeNonBlocking` (the new
//      helper) instead of a raw blocking `socket.read`.
//   2. `drainPipeNonBlocking` sets O_NONBLOCK via fcntl before reading.
// ============================================================================

test "SseManager: notify pipe drained non-blocking, one byte per wakeup" {
    const source = try readSseManagerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    // Locate runEventLoop's body window.
    const decl = std.mem.indexOf(u8, source, "fn runEventLoop(") orelse {
        std.debug.print("\n!! sse_manager.zig missing `fn runEventLoop` !!\n", .{});
        return error.RunEventLoopMissing;
    };
    const window_end = @min(decl + 16384, source.len);
    const body = source[decl..window_end];

    // 1. The pipe branch must route through the non-blocking drainer.
    if (std.mem.indexOf(u8, body, "self.drainPipeNonBlocking()") == null) {
        std.debug.print(
            "\n!! sse_manager.zig: runEventLoop does not call self.drainPipeNonBlocking() !!\n" ++
                "   A blocking drain-everything read strands the other LOOP_COUNT-1 event\n" ++
                "   loops forever (they block in read() on an empty pipe with no future\n" ++
                "   wakeup) — their shards stop heartbeating and browsers reconnect forever.\n",
            .{},
        );
        return error.PipeDrainNonBlockingMissing;
    }

    // 2. The drainer must exist and delegate the O_NONBLOCK setup to
    //    setFdNonBlocking (which itself must do fcntl SETFL).
    const drain_decl = std.mem.indexOf(u8, source, "fn drainPipeNonBlocking(") orelse {
        std.debug.print("\n!! sse_manager.zig missing `fn drainPipeNonBlocking` !!\n", .{});
        return error.DrainPipeHelperMissing;
    };
    const drain_end = @min(drain_decl + 4096, source.len);
    const drain_body = source[drain_decl..drain_end];
    if (std.mem.indexOf(u8, drain_body, "setFdNonBlocking(") == null) {
        std.debug.print(
            "\n!! sse_manager.zig: drainPipeNonBlocking does not call setFdNonBlocking !!\n" ++
                "   Without O_NONBLOCK a read on the empty pipe blocks forever once another\n" ++
                "   loop consumed this loop's wakeup byte.\n",
            .{},
        );
        return error.PipeO_NONBLOCKMissing;
    }

    // 2b. The helper itself must perform the fcntl SETFL dance — and it
    //     must cover BOTH POSIX platforms (Linux raw syscall + macOS/BSD
    //     libc fcntl). Windows is a documented no-op (no pipe there).
    const helper_decl = std.mem.indexOf(u8, source, "fn setFdNonBlocking(") orelse {
        std.debug.print("\n!! sse_manager.zig missing `fn setFdNonBlocking` !!\n", .{});
        return error.SetFdNonBlockingMissing;
    };
    const helper_end = @min(helper_decl + 4096, source.len);
    const helper_body = source[helper_decl..helper_end];
    if (std.mem.indexOf(u8, helper_body, "F_SETFL") == null or
        std.mem.indexOf(u8, helper_body, "O_NONBLOCK") == null)
    {
        std.debug.print(
            "\n!! sse_manager.zig: setFdNonBlocking does not set O_NONBLOCK via F_SETFL !!\n",
            .{},
        );
        return error.PipeO_NONBLOCKMissing;
    }
    // Cross-platform guard: the Linux branch AND the macOS/BSD libc
    // branch must both be present. A future edit that drops either one
    // silently breaks SSE heartbeats on that platform.
    if (std.mem.indexOf(u8, helper_body, "is_linux") == null or
        std.mem.indexOf(u8, helper_body, "c.fcntl") == null)
    {
        std.debug.print(
            "\n!! sse_manager.zig: setFdNonBlocking lost a platform branch !!\n" ++
                "   Must handle BOTH `is_linux` (raw syscall) and macOS/BSD (`c.fcntl`).\n" ++
                "   Windows is allowed to no-op (no notify pipe exists there).\n",
            .{},
        );
        return error.SetFdNonBlockingPlatformBranchMissing;
    }
}

// ============================================================================
// Task 7 (2026-08-24, "SSE always reconnecting" fix #2): heartbeat /
// broadcast / broadcastTyped writes MUST take the PER-CLIENT lock by
// routing through `SseClient.sendEvent`.
//
// Bug history (observed live 2026-08-24): `data: ping` arrived BEFORE
// the `event: connected` handshake on a brand-new connection. Root
// cause: sendHeartbeat wrote its chunked frame WITHOUT the per-client
// lock while unified_events_sse's handshake `sendToClient` held it (or
// vice versa). Two threads interleaving `<hex len>\r\n` + payload +
// `\r\n` on the same fd corrupt the chunked framing; the browser's
// EventSource treats the mangled stream as a protocol failure and
// reconnects forever. The manager-lock snapshot protects the client
// LIST, not the fd's BYTE STREAM — only the per-client lock serializes
// writers to one socket.
// ============================================================================

test "SseManager: sendHeartbeat routes through SseClient.sendEvent (per-client lock)" {
    const source = try readSseManagerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    const decl = std.mem.indexOf(u8, source, "fn sendHeartbeat(") orelse {
        std.debug.print("\n!! sse_manager.zig missing `fn sendHeartbeat` !!\n", .{});
        return error.SendHeartbeatMissing;
    };
    const window_end = @min(decl + 8192, source.len);
    const body = source[decl..window_end];

    if (std.mem.indexOf(u8, body, "client.sendEvent(ping)") == null) {
        std.debug.print(
            "\n!! sse_manager.zig: sendHeartbeat writes pings without the per-client lock !!\n" ++
                "   Route through `client.sendEvent(ping)` so the ping cannot interleave with\n" ++
                "   a concurrent sendToClient/broadcast on the same fd (corrupts chunked\n" ++
                "   framing → browser reconnects forever).\n",
            .{},
        );
        return error.SendHeartbeatPerClientLockMissing;
    }
}

test "SseManager: broadcast + broadcastTyped route through SseClient.sendEvent (per-client lock)" {
    const source = try readSseManagerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    inline for (.{ "pub fn broadcast(", "pub fn broadcastTyped(" }) |decl_marker| {
        const decl = std.mem.indexOf(u8, source, decl_marker) orelse {
            std.debug.print("\n!! sse_manager.zig missing `{s}` !!\n", .{decl_marker});
            return error.BroadcastMissing;
        };
        const window_end = @min(decl + 4096, source.len);
        const body = source[decl..window_end];

        if (std.mem.indexOf(u8, body, "client.sendEvent(event)") == null) {
            std.debug.print(
                "\n!! sse_manager.zig: {s} writes without the per-client lock !!\n" ++
                    "   Route through `client.sendEvent(event)` — see sendHeartbeat.\n",
                .{decl_marker},
            );
            return error.BroadcastPerClientLockMissing;
        }
    }
}

// ============================================================================
// Task 8 (2026-08-24, "SSE always reconnecting" fix #3): startEventLoop
// must NOT call group.await inside its own spawned closure chain.
//
// Bug history: startEventLoop is itself invoked via group.concurrent
// from main.zig. Calling `group.await` inside that nested context made
// shutdown fragile: when main's outer group.cancel fired, the cancel
// propagated into the inner await while child loops were blocked in
// raw syscalls (the stranded pipe reads above), tearing down threads
// mid-syscall. After Fix 1 the loops exit cleanly on `running=false`,
// so startEventLoop can simply spawn and RETURN — the caller's group
// already tracks the children.
// ============================================================================

test "SseManager: startEventLoop spawns loops and returns (no nested group.await)" {
    const source = try readSseManagerSource(std.testing.allocator);
    defer std.testing.allocator.free(source);

    const decl = std.mem.indexOf(u8, source, "pub fn startEventLoop(") orelse {
        std.debug.print("\n!! sse_manager.zig missing `pub fn startEventLoop` !!\n", .{});
        return error.StartEventLoopMissing;
    };
    const window_end = @min(decl + 4096, source.len);
    const body = source[decl..window_end];

    if (std.mem.indexOf(u8, body, "group.await") != null) {
        std.debug.print(
            "\n!! sse_manager.zig: startEventLoop still calls group.await !!\n" ++
                "   startEventLoop is itself spawned via group.concurrent from main.zig;\n" ++
                "   nesting group.await inside that closure makes shutdown fragile. Spawn\n" ++
                "   the LOOP_COUNT loops and return — the caller's group tracks them.\n",
            .{},
        );
        return error.StartEventLoopNestedAwait;
    }
}
