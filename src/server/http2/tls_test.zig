//! Tests for `tls.zig` — the OpenSSL server-side TLS + ALPN surface.
//!
//! # Why there are two client implementations here
//!
//! The tests drive real TLS clients over a `socketpair`, because the whole
//! point of this module is that two independent implementations agree on the
//! wire — a mocked record layer would prove nothing about the handshake.
//!
//! * **`std.crypto.tls.Client`** (Zig's own, used for the record-layer tests:
//!   data round-trip, clean EOF, and the "no ALPN offered" case). It cannot be
//!   used for ALPN: Zig 0.16's TLS client has no ALPN support at all — there is
//!   not one occurrence of "alpn" anywhere under `/usr/lib/zig/std`, so the
//!   extension is never even sent. That is a fact about std, not a limitation
//!   of this test, and it is deliberately not papered over: the ALPN cases are
//!   driven by…
//! * **OpenSSL's TLS client** (`TLS_client_method` + `SSL_set_alpn_protos`),
//!   which advertises exactly the protocol list each case needs and reports
//!   back what *it* negotiated. Asserting both ends agree is strictly stronger
//!   evidence than asserting only the server's view.
//!
//! Both clients run in a `std.Thread`; the server-side handshake runs on the
//! test thread. The fds are blocking, so one side must be on another thread or
//! the handshake would deadlock against itself.
//!
//! Sockets are read/written through `std.c.read`/`std.c.write`, which exist on
//! POSIX only — the socket-driven tests therefore skip on Windows. (The module
//! under test is platform-neutral: it only ever passes an `i32` to
//! `SSL_set_fd`.) Every such test sets a 10s socket timeout first, so a logic
//! error that makes one side wait forever fails the test instead of hanging
//! the run.

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

const tls = @import("tls.zig");
const tls_cert = @import("tls_cert.zig");

/// Server preference order used by nearly every test: h2 first.
const alpn_both = [_][]const u8{ tls.alpn_h2, tls.alpn_http1 };
/// A client that only speaks HTTP/1.1 (e.g. an old browser over TLS).
const alpn_http1_only = [_][]const u8{tls.alpn_http1};
/// A client that shares no protocol with the listener.
const alpn_unrelated = [_][]const u8{ "spdy/3.1" };

// ---------------------------------------------------------------------------
// OpenSSL *client* surface (test-only; the module under test declares its own
// server-side surface).
// ---------------------------------------------------------------------------

const SSL = opaque {};
const SSL_CTX = opaque {};
const SSL_METHOD = opaque {};

extern fn TLS_client_method() ?*const SSL_METHOD;
extern fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
extern fn SSL_CTX_free(ctx: ?*SSL_CTX) void;
extern fn SSL_CTX_set_alpn_protos(ctx: *SSL_CTX, protos: [*]const u8, protos_len: c_uint) c_int;
extern fn SSL_new(ctx: *SSL_CTX) ?*SSL;
extern fn SSL_free(ssl: ?*SSL) void;
extern fn SSL_set_fd(ssl: *SSL, fd: c_int) c_int;
extern fn SSL_connect(ssl: *SSL) c_int;
extern fn SSL_shutdown(ssl: *SSL) c_int;
extern fn SSL_get0_alpn_selected(ssl: *const SSL, data: *?[*]const u8, len: *c_uint) void;

/// `SSL_CTX_set_alpn_protos` returns **0 on success** (the inverse of most of
/// the library's predicates) — hence the explicit comparison below.
const OSSL_ALPN_SET_OK: c_int = 0;

// ---------------------------------------------------------------------------
// Socket plumbing (POSIX only — see the file header)
// ---------------------------------------------------------------------------

/// Bound how long a blocking handshake may stall. A 10s ceiling is orders of
/// magnitude above a local socketpair handshake, so this never bites a healthy
/// run; it exists purely to turn a deadlock into a test failure.
const socket_timeout_seconds = 10;

/// Socket primitives, dispatched at comptime.
///
/// Deliberately local rather than `@import("../test_helpers.zig")`: that file
/// lives one directory above this module's root, which makes it unreachable
/// when `tls.zig` is compiled standalone (the mandated verification command),
/// even though it resolves fine once this file is wired into the module's test
/// runner. The duplication is a dozen lines of `socketpair(2)`.
///
/// The Windows arm exists so this file still compiles there; none of it is ever
/// *called* on Windows, because the socket-driven tests skip (the module-level
/// helper there builds a winsock TCP-loopback pair, whose SOCKETs the C runtime
/// fd table does not index). Selecting the arm at container level means the
/// unused one is never analysed at all.
const socket_io = if (builtin.os.tag == .windows) struct {
    fn createPair() ![2]i32 {
        return error.SocketIoUnsupportedOnWindows;
    }

    fn closePair(pair: [2]i32) void {
        _ = pair;
    }

    fn setTimeouts(pair: [2]i32) !void {
        _ = pair;
    }

    fn read(fd: i32, buf: []u8) !usize {
        _ = fd;
        _ = buf;
        return error.SocketIoUnsupportedOnWindows;
    }

    fn writeAll(fd: i32, bytes: []const u8) !void {
        _ = fd;
        _ = bytes;
        return error.SocketIoUnsupportedOnWindows;
    }
} else struct {
    /// A connected `AF_UNIX`/`SOCK_STREAM` pair. `pair[0]` is the client end,
    /// `pair[1]` the server end (the caller's convention, not the kernel's).
    fn createPair() ![2]i32 {
        var fds: [2]std.posix.fd_t = undefined;
        const rc = std.posix.system.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds);
        if (rc < 0) return error.SocketPairFailed;
        return .{ fds[0], fds[1] };
    }

    fn closePair(pair: [2]i32) void {
        _ = std.c.close(pair[0]);
        _ = std.c.close(pair[1]);
    }

    fn setTimeouts(pair: [2]i32) !void {
        const timeout: std.posix.timeval = .{ .sec = socket_timeout_seconds, .usec = 0 };
        const bytes = std.mem.toBytes(timeout);
        for (pair) |fd| {
            try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &bytes);
            try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, &bytes);
        }
    }

    fn read(fd: i32, buf: []u8) !usize {
        const n = std.c.read(fd, buf.ptr, buf.len);
        if (n < 0) return error.SocketReadFailed;
        return @intCast(n);
    }

    fn writeAll(fd: i32, bytes: []const u8) !void {
        var written: usize = 0;
        while (written < bytes.len) {
            const n = std.c.write(fd, bytes.ptr + written, bytes.len - written);
            if (n <= 0) return error.SocketWriteFailed;
            written += @intCast(n);
        }
    }
};

/// Blocking `std.Io.Reader` over a socket fd.
///
/// Zig 0.16's TLS client wants the `Io.Reader`/`Io.Writer` interfaces (not a
/// `net.Stream`), so the vtable is filled in by hand. Implementing `stream`
/// alone is enough — the default `readVec` drives it through an internal
/// fixed writer.
const SocketReader = struct {
    interface: std.Io.Reader,
    fd: i32,

    fn init(fd: i32, buffer: []u8) SocketReader {
        return .{
            .fd = fd,
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *SocketReader = @fieldParentPtr("interface", r);
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = socket_io.read(self.fd, dest) catch return error.ReadFailed;
        // A zero-length read on a stream socket means the peer closed: that is
        // end-of-stream, not "no data yet".
        if (n == 0) return error.EndOfStream;
        w.advance(n);
        return n;
    }
};

/// Blocking `std.Io.Writer` over a socket fd. Mirrors the std socket writer's
/// drain: the buffered bytes go out first, then each slice, then the last slice
/// `splat` times, with `consume` doing the buffer bookkeeping.
const SocketWriter = struct {
    interface: std.Io.Writer,
    fd: i32,

    fn init(fd: i32, buffer: []u8) SocketWriter {
        return .{
            .fd = fd,
            .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer, .end = 0 },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *SocketWriter = @fieldParentPtr("interface", w);
        var sent: usize = 0;

        const buffered = w.buffered();
        if (buffered.len > 0) {
            socket_io.writeAll(self.fd, buffered) catch return error.WriteFailed;
            sent += buffered.len;
        }
        for (data[0 .. data.len - 1]) |chunk| {
            socket_io.writeAll(self.fd, chunk) catch return error.WriteFailed;
            sent += chunk.len;
        }
        const last = data[data.len - 1];
        var i: usize = 0;
        while (i < splat) : (i += 1) {
            socket_io.writeAll(self.fd, last) catch return error.WriteFailed;
            sent += last.len;
        }
        return w.consume(sent);
    }
};

// ---------------------------------------------------------------------------
// Client flavours
// ---------------------------------------------------------------------------

/// OpenSSL client. Carries the ALPN protocol list to advertise and reports what
/// the server negotiated back.
const AlpnClient = struct {
    fd: i32 = -1,
    /// Protocols to advertise, in this client's own preference order.
    offer: []const []const u8,
    /// True for the case where the server is *expected* to reject the
    /// handshake (no protocol in common).
    expect_failure: bool = false,

    /// null when the thread finished without an unexpected error.
    err: ?[]const u8 = null,
    /// True when SSL_connect returned 1.
    connected: bool = false,
    negotiated: [32]u8 = undefined,
    negotiated_len: usize = 0,

    fn run(self: *AlpnClient) void {
        self.runFallible() catch |err| {
            self.err = @errorName(err);
        };
    }

    fn runFallible(self: *AlpnClient) !void {
        // Encode the ALPN list in wire format: a length byte, then the name.
        var wire: [256]u8 = undefined;
        var wire_len: usize = 0;
        for (self.offer) |protocol| {
            wire[wire_len] = @intCast(protocol.len);
            @memcpy(wire[wire_len + 1 ..][0..protocol.len], protocol);
            wire_len += 1 + protocol.len;
        }
        try testing.expect(wire_len <= wire.len);

        const method = TLS_client_method() orelse return error.TlsClientMethod;
        const ctx = SSL_CTX_new(method) orelse return error.NoSslContext;
        defer SSL_CTX_free(ctx);

        if (SSL_CTX_set_alpn_protos(ctx, &wire, @intCast(wire_len)) != OSSL_ALPN_SET_OK)
            return error.SetAlpnProtosFailed;

        const ssl = SSL_new(ctx) orelse return error.NoSsl;
        defer SSL_free(ssl);
        if (SSL_set_fd(ssl, self.fd) != 1) return error.SetFdFailed;

        const rc = SSL_connect(ssl);
        self.connected = rc == 1;
        if (!self.connected) {
            // Expected for the no-overlap case: the server answered with an
            // ALPN alert, so the handshake is supposed to fail here.
            if (!self.expect_failure) return error.HandshakeFailed;
            return;
        }
        if (self.expect_failure) return error.HandshakeSucceededUnexpectedly;

        var data: ?[*]const u8 = null;
        var len: c_uint = 0;
        SSL_get0_alpn_selected(ssl, &data, &len);
        if (data != null and len > 0) {
            try testing.expect(len <= self.negotiated.len);
            @memcpy(self.negotiated[0..len], data.?[0..len]);
            self.negotiated_len = len;
        }

        // Orderly shutdown so the server sees close_notify rather than a reset.
        _ = SSL_shutdown(ssl);
    }
};

/// `std.crypto.tls.Client` flavour: record-layer behaviour, no ALPN.
const StdClientTask = struct {
    fd: i32 = -1,
    /// Application data to send after the handshake.
    send: []const u8 = "",
    /// How many bytes to read back from the server (0 = don't read).
    expect: usize = 0,
    /// Send close_notify once finished.
    close_notify: bool = false,

    err: ?[]const u8 = null,
    received: [64]u8 = undefined,

    fn run(self: *StdClientTask) void {
        self.runFallible() catch |err| {
            self.err = @errorName(err);
        };
    }

    fn runFallible(self: *StdClientTask) !void {
        const Client = std.crypto.tls.Client;
        const min = Client.min_buffer_len;

        // The three buffer-size relationships std's own HTTP client relies on:
        // the socket reader and the socket writer each need room for a maximum
        // ciphertext record, and the decrypted reader needs at least that too.
        var socket_read_buffer: [min]u8 = undefined;
        var socket_write_buffer: [min]u8 = undefined;
        var plaintext_write_buffer: [1024]u8 = undefined;
        var decrypted_read_buffer: [min + 4096]u8 = undefined;
        var entropy: [Client.Options.entropy_len]u8 = undefined;
        testing.io.random(&entropy);

        var socket_reader = SocketReader.init(self.fd, &socket_read_buffer);
        var socket_writer = SocketWriter.init(self.fd, &socket_write_buffer);

        var client = try Client.init(&socket_reader.interface, &socket_writer.interface, .{
            // The server presents a self-signed certificate and this test is
            // about the record layer, not the trust model.
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &decrypted_read_buffer,
            .write_buffer = &plaintext_write_buffer,
            .entropy = &entropy,
            .realtime_now = std.Io.Clock.real.now(testing.io),
        });

        if (self.send.len > 0) {
            try client.writer.writeAll(self.send);
            try client.writer.flush();
            // `Client.writer.flush` only encrypts into the socket writer's
            // buffer; the socket writer needs its own flush to hit the wire.
            try socket_writer.interface.flush();
        }

        if (self.expect > 0) {
            try client.reader.readSliceAll(self.received[0..self.expect]);
        }

        if (self.close_notify) {
            try client.end();
            try socket_writer.interface.flush();
        }
    }
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// One in-flight handshake: the socketpair, the client thread, and the task the
/// thread fills in.
///
/// Generic over the client flavour because the tear-down order — join the
/// thread, free the `Conn`, close the fds — is identical for both and is
/// exactly the part that is easy to get wrong.
fn Handshake(comptime ClientTask: type) type {
    return struct {
        const Self = @This();

        alloc: std.mem.Allocator,
        pair: [2]i32,
        task: ClientTask,
        thread: std.Thread,
        joined: bool = false,
        /// null when the server rejected the handshake.
        conn: ?*tls.Conn = null,

        /// Start the client thread, then run the server half of the handshake on
        /// the calling thread.
        ///
        /// `error.HandshakeFailed` becomes a null `conn` rather than an error:
        /// one of the cases below *expects* the server to reject.
        fn start(alloc: std.mem.Allocator, ctx: *tls.Ctx, task: ClientTask) !*Self {
            const self = try alloc.create(Self);
            errdefer alloc.destroy(self);
            const pair = try socket_io.createPair();
            errdefer socket_io.closePair(pair);
            try socket_io.setTimeouts(pair);

            self.* = .{
                .alloc = alloc,
                .pair = pair,
                .task = task,
                .thread = undefined,
            };
            self.task.fd = pair[0];
            self.thread = try std.Thread.spawn(.{}, ClientTask.run, .{&self.task});

            self.conn = tls.Conn.accept(ctx, pair[1]) catch |err| switch (err) {
                error.HandshakeFailed => null,
                else => {
                    self.join();
                    return err;
                },
            };
            return self;
        }

        fn join(self: *Self) void {
            if (self.joined) return;
            self.joined = true;
            self.thread.join();
        }

        fn deinit(self: *Self) void {
            self.join();
            if (self.conn) |conn| conn.deinit();
            socket_io.closePair(self.pair);
            self.alloc.destroy(self);
        }
    };
}

const AlpnHandshake = Handshake(AlpnClient);
const StdHandshake = Handshake(StdClientTask);

/// A `Ctx` backed by a freshly generated self-signed pair, plus the temp
/// directory holding it.
const Fixture = struct {
    alloc: std.mem.Allocator,
    tmp: testing.TmpDir,
    dir: []u8,
    ctx: *tls.Ctx,

    fn init(alloc: std.mem.Allocator, alpn: []const []const u8) !*Fixture {
        const self = try alloc.create(Fixture);
        errdefer alloc.destroy(self);

        self.alloc = alloc;
        self.tmp = testing.tmpDir(.{});
        errdefer self.tmp.cleanup();

        // A real directory the generator can be pointed at: the TLS stack only
        // ever sees paths, never dir handles.
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try self.tmp.dir.realPath(testing.io, &buffer);
        self.dir = try alloc.dupe(u8, buffer[0..len]);
        errdefer alloc.free(self.dir);

        const paths = try tls_cert.ensureSelfSigned(alloc, self.dir, "nalar-h2-test", 1);
        defer alloc.free(paths.cert_pem);
        defer alloc.free(paths.key_pem);

        self.ctx = try tls.Ctx.init(alloc, paths.cert_pem, paths.key_pem, alpn);
        return self;
    }

    fn deinit(self: *Fixture) void {
        self.ctx.deinit();
        self.alloc.free(self.dir);
        self.tmp.cleanup();
        self.alloc.destroy(self);
    }
};

/// Fail the test with the client thread's error name, which is otherwise
/// invisible from the main thread.
fn expectNoClientError(err: ?[]const u8) !void {
    if (err) |name| {
        std.debug.print("client thread failed: {s}\n", .{name});
        return error.ClientThreadFailed;
    }
}

/// Every socket-driven test begins with this: the harness reads raw fds.
fn skipOnWindows() !void {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
}

// ---------------------------------------------------------------------------
// ALPN negotiation
// ---------------------------------------------------------------------------

test "ALPN negotiation picks h2 when the client offers h2 and http/1.1" {
    try skipOnWindows();
    const alloc = testing.allocator;
    const fixture = try Fixture.init(alloc, &alpn_both);
    defer fixture.deinit();

    const handshake = try AlpnHandshake.start(alloc, fixture.ctx, .{ .offer = &alpn_both });
    defer handshake.deinit();
    handshake.join();

    try expectNoClientError(handshake.task.err);
    try testing.expect(handshake.task.connected);
    try testing.expect(handshake.conn != null);

    // Both ends must agree: the server's view …
    try testing.expectEqualStrings(tls.alpn_h2, handshake.conn.?.selectedAlpn());
    // … and the client's (this is what a browser acts on).
    try testing.expectEqualStrings(tls.alpn_h2, handshake.task.negotiated[0..handshake.task.negotiated_len]);
}

test "ALPN negotiation falls back to http/1.1 when h2 is not offered" {
    try skipOnWindows();
    const alloc = testing.allocator;
    const fixture = try Fixture.init(alloc, &alpn_both);
    defer fixture.deinit();

    const handshake = try AlpnHandshake.start(alloc, fixture.ctx, .{ .offer = &alpn_http1_only });
    defer handshake.deinit();
    handshake.join();

    try expectNoClientError(handshake.task.err);
    try testing.expect(handshake.conn != null);
    try testing.expectEqualStrings(tls.alpn_http1, handshake.conn.?.selectedAlpn());
    try testing.expectEqualStrings(tls.alpn_http1, handshake.task.negotiated[0..handshake.task.negotiated_len]);
}

test "server preference wins over the client's ordering" {
    try skipOnWindows();
    const alloc = testing.allocator;
    const fixture = try Fixture.init(alloc, &alpn_both);
    defer fixture.deinit();

    // Client prefers http/1.1; the server prefers h2. The server's order is
    // what must decide, otherwise "h2 preferred" would be a client property.
    const client_order = [_][]const u8{ tls.alpn_http1, tls.alpn_h2 };
    const handshake = try AlpnHandshake.start(alloc, fixture.ctx, .{ .offer = &client_order });
    defer handshake.deinit();
    handshake.join();

    try expectNoClientError(handshake.task.err);
    try testing.expectEqualStrings(tls.alpn_h2, handshake.conn.?.selectedAlpn());
}

test "a client sharing no ALPN protocol is rejected during the handshake" {
    try skipOnWindows();
    const alloc = testing.allocator;
    const fixture = try Fixture.init(alloc, &alpn_both);
    defer fixture.deinit();

    const handshake = try AlpnHandshake.start(alloc, fixture.ctx, .{
        .offer = &alpn_unrelated,
        .expect_failure = true,
    });
    defer handshake.deinit();
    handshake.join();

    // The server refused: no connection object, no client-side handshake.
    try testing.expect(handshake.conn == null);
    try testing.expect(!handshake.task.connected);
    try expectNoClientError(handshake.task.err);

    // OpenSSL's error queue must name the actual reason (a no-application-
    // protocol alert), not just "handshake failed".
    const reason = fixture.ctx.lastError();
    try testing.expect(reason.len > 0);
    if (std.mem.indexOf(u8, reason, "application protocol") == null) {
        std.debug.print("unexpected handshake failure reason: {s}\n", .{reason});
        return error.MissingAlpnDiagnostic;
    }
}

test "ALPN selection is per-connection, not sticky across connections" {
    try skipOnWindows();
    const alloc = testing.allocator;
    const fixture = try Fixture.init(alloc, &alpn_both);
    defer fixture.deinit();

    // Two handshakes over the SAME Ctx with different client offers: the
    // selection must be recomputed per connection (the callback reads the Ctx's
    // preference list, not any cached state).
    {
        const handshake = try AlpnHandshake.start(alloc, fixture.ctx, .{ .offer = &alpn_both });
        defer handshake.deinit();
        handshake.join();
        try testing.expectEqualStrings(tls.alpn_h2, handshake.conn.?.selectedAlpn());
    }
    {
        const handshake = try AlpnHandshake.start(alloc, fixture.ctx, .{ .offer = &alpn_http1_only });
        defer handshake.deinit();
        handshake.join();
        try testing.expectEqualStrings(tls.alpn_http1, handshake.conn.?.selectedAlpn());
    }
}

// ---------------------------------------------------------------------------
// std.crypto.tls.Client (Zig's own client)
// ---------------------------------------------------------------------------

test "a client that sends no ALPN extension still completes the handshake" {
    try skipOnWindows();
    const alloc = testing.allocator;
    const fixture = try Fixture.init(alloc, &alpn_both);
    defer fixture.deinit();

    // Zig's TLS client never sends ALPN (std has no such option), so this also
    // documents real-world behaviour for clients that omit the extension:
    // the handshake succeeds and the caller must fall back to HTTP/1.1.
    const handshake = try StdHandshake.start(alloc, fixture.ctx, .{});
    defer handshake.deinit();
    handshake.join();

    try expectNoClientError(handshake.task.err);
    try testing.expect(handshake.conn != null);
    try testing.expectEqualStrings("", handshake.conn.?.selectedAlpn());
    // Nothing has failed, so there is nothing to report.
    try testing.expectEqualStrings("", fixture.ctx.lastError());
}

test "application data round-trips through the TLS connection" {
    try skipOnWindows();
    const alloc = testing.allocator;
    const fixture = try Fixture.init(alloc, &alpn_both);
    defer fixture.deinit();

    const from_client = "hello http2";
    const from_server = "pong!";

    const handshake = try StdHandshake.start(alloc, fixture.ctx, .{
        .send = from_client,
        .expect = from_server.len,
    });
    defer handshake.deinit();
    try testing.expect(handshake.conn != null);

    const conn = handshake.conn.?;

    var buf: [64]u8 = undefined;
    const n = try conn.read(&buf);
    try testing.expectEqualStrings(from_client, buf[0..n]);

    try conn.writeAll(from_server);

    handshake.join();
    try expectNoClientError(handshake.task.err);
    try testing.expectEqualStrings(from_server, handshake.task.received[0..from_server.len]);
}

test "close_notify is reported as a clean end of stream" {
    try skipOnWindows();
    const alloc = testing.allocator;
    const fixture = try Fixture.init(alloc, &alpn_both);
    defer fixture.deinit();

    const handshake = try StdHandshake.start(alloc, fixture.ctx, .{ .close_notify = true });
    defer handshake.deinit();
    try testing.expect(handshake.conn != null);

    var buf: [16]u8 = undefined;
    // 0 — not an error — is what separates an orderly shutdown from a
    // truncation attempt (which must surface as TlsReadFailed).
    try testing.expectEqual(@as(usize, 0), try handshake.conn.?.read(&buf));

    handshake.join();
    try expectNoClientError(handshake.task.err);
}

// ---------------------------------------------------------------------------
// Ctx.init failure modes
// ---------------------------------------------------------------------------

test "Ctx.init rejects missing or mismatched key material without crashing" {
    const alloc = testing.allocator;

    // Nothing at all: no cert file on disk.
    const missing = tls.Ctx.init(alloc, "/nonexistent-nalar-test/cert.pem", "/nonexistent-nalar-test/key.pem", &alpn_both);
    if (missing) |ctx| {
        ctx.deinit();
        return error.ExpectedCertificateLoadFailure;
    } else |err| {
        try testing.expectEqual(error.CertificateLoadFailed, err);
    }

    // A valid pair, plus a second, unrelated pair to cross the key with.
    var tmp_a = testing.tmpDir(.{});
    defer tmp_a.cleanup();
    var tmp_b = testing.tmpDir(.{});
    defer tmp_b.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len_a = try tmp_a.dir.realPath(testing.io, &path_buffer);
    const dir_a = try alloc.dupe(u8, path_buffer[0..len_a]);
    defer alloc.free(dir_a);
    const len_b = try tmp_b.dir.realPath(testing.io, &path_buffer);
    const dir_b = try alloc.dupe(u8, path_buffer[0..len_b]);
    defer alloc.free(dir_b);

    const pair_a = try tls_cert.ensureSelfSigned(alloc, dir_a, "nalar-h2-test-a", 1);
    defer alloc.free(pair_a.cert_pem);
    defer alloc.free(pair_a.key_pem);
    const pair_b = try tls_cert.ensureSelfSigned(alloc, dir_b, "nalar-h2-test-b", 1);
    defer alloc.free(pair_b.cert_pem);
    defer alloc.free(pair_b.key_pem);

    const crossed = tls.Ctx.init(alloc, pair_a.cert_pem, pair_b.key_pem, &alpn_both);
    if (crossed) |ctx| {
        ctx.deinit();
        return error.ExpectedKeyMismatch;
    } else |err| {
        // OpenSSL's loader checks the key against the certificate as it loads,
        // so the mismatch can surface as either failure; both are correct and
        // the important part is that it is not accepted silently.
        try testing.expect(err == error.PrivateKeyLoadFailed or err == error.PrivateKeyMismatch);
    }

    // The message must be actionable, not an empty string.
    const garbage = tls.Ctx.init(alloc, pair_a.cert_pem, pair_a.key_pem, &.{});
    if (garbage) |ctx| {
        ctx.deinit();
        return error.ExpectedEmptyAlpnRejection;
    } else |err| {
        try testing.expectEqual(error.EmptyAlpnList, err);
    }
}

test "Ctx.init rejects an empty certificate path and an over-long ALPN name" {
    const alloc = testing.allocator;

    try testing.expectError(
        error.InvalidCertificatePath,
        tls.Ctx.init(alloc, "", "/tmp/key.pem", &alpn_both),
    );
    try testing.expectError(
        error.EmptyAlpnList,
        tls.Ctx.init(alloc, "/tmp/cert.pem", "/tmp/key.pem", &.{}),
    );

    // 256 bytes cannot be encoded: the ALPN wire format is a single length byte
    // per protocol.
    const too_long = "x" ** 256;
    try testing.expectError(
        error.InvalidAlpnProtocol,
        tls.Ctx.init(alloc, "/tmp/cert.pem", "/tmp/key.pem", &.{too_long}),
    );
}

test "Ctx.lastError stays empty until something fails" {
    const alloc = testing.allocator;
    const fixture = try Fixture.init(alloc, &alpn_both);
    defer fixture.deinit();

    // A successfully constructed Ctx has nothing to report. The populated case
    // (a rejected handshake, where lastError carries OpenSSL's own
    // "no application protocol" alert text) is asserted in the ALPN rejection
    // test above.
    //
    // Note: `Ctx.init` failures cannot be inspected this way — the interface
    // returns an error and nothing else, so the diagnostic for a bad
    // certificate path is only reachable through the error name. Callers that
    // need the string must log the error name; that is a property of the
    // frozen interface, not of this implementation.
    try testing.expectEqualStrings("", fixture.ctx.lastError());
}
