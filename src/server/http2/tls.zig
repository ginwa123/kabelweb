//! Server-side TLS for the HTTP/2 listener, backed by OpenSSL.
//!
//! Why OpenSSL: Zig 0.16's `std.crypto.tls` contains a TLS *client* only — there
//! is no server state machine and no ALPN support anywhere in std (a grep for
//! "alpn" across `/usr/lib/zig/std` returns zero hits). Since HTTP/2 over TLS is
//! selected *by* ALPN (`h2`), the server half has to come from somewhere, and
//! the system OpenSSL is the dependency the rest of this module already links.
//!
//! Shape of the surface:
//!   * `Ctx` owns one `SSL_CTX` — the certificate, the key and the ALPN
//!     preference list. Build it once per listener, share it across all
//!     connections (OpenSSL's `SSL_CTX` is the thread-safe, immutable-after-setup
//!     part of the library).
//!   * `Conn` owns one `SSL` — one live connection. `accept` performs the
//!     blocking handshake; `read`/`writeAll` are the record-layer equivalents of
//!     `recv`/`send`.
//!
//! The fd is owned by the caller: `SSL_set_fd` wraps it in a `BIO_NOCLOSE` BIO,
//! so neither `SSL_free` nor `shutdown` closes it. That keeps the "who closes the
//! socket" question in exactly one place (the accept loop that created it).
//!
//! # Integration requirement: SIGPIPE
//!
//! OpenSSL writes to the socket through the plain `write(2)` syscall (the
//! built-in socket BIO does not set `MSG_NOSIGNAL`), so a peer that vanished
//! between two application writes can raise `SIGPIPE` — whose default
//! disposition terminates the process. This module cannot suppress that from
//! inside a `SSL_write` call: the accept loop must either ignore `SIGPIPE`
//! process-wide (`signal(SIGPIPE, SIG_IGN)` at startup, as most servers do) or
//! set `SO_NOSIGPIPE` on each accepted socket on the platforms that support it.
//! Windows has no `SIGPIPE` and needs nothing.

const std = @import("std");

// ===========================================================================
// OpenSSL C surface — only the symbols this file calls.
//
// Hand-declared rather than `@cImport`'d: the ABI this module depends on is then
// explicit and reviewable, and `zig test -lc -lssl -lcrypto` stays the entire
// build recipe. Every numeric constant below cites the header it came from.
// ===========================================================================

const SSL = opaque {};
const SSL_CTX = opaque {};
const SSL_METHOD = opaque {};

/// `SSL_get_error` results (openssl/ssl.h).
const SSL_ERROR_SSL: c_int = 1;
const SSL_ERROR_WANT_READ: c_int = 2;
const SSL_ERROR_WANT_WRITE: c_int = 3;
const SSL_ERROR_SYSCALL: c_int = 5;
const SSL_ERROR_ZERO_RETURN: c_int = 6;

/// `SSL_CTX_set_alpn_select_cb` callback results (openssl/tls1.h).
/// `OK` = accepted, `ALERT_FATAL` = abort the handshake with an ALPN alert.
const SSL_TLSEXT_ERR_OK: c_int = 0;
const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;

/// `SSL_FILETYPE_PEM` (openssl/x509.h).
const X509_FILETYPE_PEM: c_int = 1;

/// `SSL_OP_NO_COMPRESSION` == `SSL_OP_BIT(17)`, `SSL_OP_CIPHER_SERVER_PREFERENCE`
/// == `SSL_OP_BIT(22)`, `SSL_OP_NO_RENEGOTIATION` == `SSL_OP_BIT(30)`, where
/// `SSL_OP_BIT(n)` is `1 << n` (openssl/ssl.h).
const SSL_OP_NO_COMPRESSION: u64 = 1 << 17;
const SSL_OP_CIPHER_SERVER_PREFERENCE: u64 = 1 << 22;
const SSL_OP_NO_RENEGOTIATION: u64 = 1 << 30;

/// `SSL_CTRL_SET_MIN_PROTO_VERSION` (openssl/ssl.h) — the command code that the
/// `SSL_CTX_set_min_proto_version` *macro* expands to. The macro has no symbol
/// to link against, so the ctrl call is written out.
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
/// `TLS1_2_VERSION` (openssl/prov_ssl.h).
const TLS1_2_VERSION: c_long = 0x0303;

extern fn TLS_server_method() ?*const SSL_METHOD;
extern fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
extern fn SSL_CTX_free(ctx: ?*SSL_CTX) void;
extern fn SSL_CTX_ctrl(ctx: *SSL_CTX, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
extern fn SSL_CTX_set_options(ctx: *SSL_CTX, op: u64) u64;
extern fn SSL_CTX_use_certificate_chain_file(ctx: *SSL_CTX, file: [*:0]const u8) c_int;
extern fn SSL_CTX_use_PrivateKey_file(ctx: *SSL_CTX, file: [*:0]const u8, file_type: c_int) c_int;
extern fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) c_int;
extern fn SSL_CTX_set_alpn_select_cb(
    ctx: *SSL_CTX,
    cb: *const fn (?*SSL, *[*]const u8, *u8, [*]const u8, c_uint, ?*anyopaque) callconv(.c) c_int,
    arg: ?*anyopaque,
) void;

extern fn SSL_new(ctx: *SSL_CTX) ?*SSL;
extern fn SSL_free(ssl: ?*SSL) void;
extern fn SSL_set_fd(ssl: *SSL, fd: c_int) c_int;
extern fn SSL_accept(ssl: *SSL) c_int;
extern fn SSL_read(ssl: *SSL, buf: [*]u8, num: c_int) c_int;
extern fn SSL_write(ssl: *SSL, buf: [*]const u8, num: c_int) c_int;
extern fn SSL_shutdown(ssl: *SSL) c_int;
extern fn SSL_get_error(ssl: *const SSL, ret: c_int) c_int;
extern fn SSL_get0_alpn_selected(ssl: *const SSL, data: *?[*]const u8, len: *c_uint) void;

extern fn ERR_get_error() c_ulong;
extern fn ERR_error_string_n(e: c_ulong, buf: [*]u8, len: usize) void;

// ===========================================================================
// Public surface
// ===========================================================================

/// ALPN protocol identifier for HTTP/2 (RFC 9113 §3.1).
pub const alpn_h2 = "h2";
/// ALPN protocol identifier for HTTP/1.1 over TLS — RFC 7301 (ALPN) plus the
/// registered `http/1.1` entry in the "TLS ALPN Protocol IDs" registry.
pub const alpn_http1 = "http/1.1";

/// Every failure this module can produce. The individual functions return
/// inferred subsets, but they are all drawn from this set so the domain is
/// greppable from one place.
pub const Error = error{
    /// Certificate or key path was empty.
    InvalidCertificatePath,
    /// `Ctx.init` was given no ALPN protocols, which would make every
    /// handshake fail — rejected up front instead of at the first connection.
    EmptyAlpnList,
    /// An ALPN protocol name was empty or longer than 255 bytes (the wire
    /// format prefixes each name with a single length byte).
    InvalidAlpnProtocol,
    NoServerMethod,
    ContextInitFailed,
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    /// The certificate and key on disk do not belong together.
    PrivateKeyMismatch,
    SetFdFailed,
    /// `SSL_new` failed (per-connection state; allocation failure).
    ConnectionInitFailed,
    HandshakeFailed,
    /// `read`/`writeAll`/`selectedAlpn` called after `shutdown`/`deinit`.
    ConnectionClosed,
    TlsReadFailed,
    TlsWriteFailed,
};

/// A TLS listener configuration: certificate, key and ALPN preference order.
///
/// Build one and share it across every connection: `SSL_CTX` holds no
/// per-connection state, which is what lets the accept loop keep it in a single
/// server field.
pub const Ctx = struct {
    alloc: std.mem.Allocator,
    ctx: *SSL_CTX,
    /// Server preference order, owned (deep-copied) by this `Ctx`.
    ///
    /// Copied rather than borrowed because the ALPN callback reads this list
    /// during every handshake — long after `init` returned — so a caller that
    /// built the list on its stack must not be able to dangle it.
    alpn: []const []const u8,
    /// Static message describing the most recent failure. Superseded by
    /// `error_buffer` when OpenSSL had something more specific to say.
    last_error: []const u8 = "",
    /// `ERR_error_string_n` output for the most recent failure. OpenSSL error
    /// strings are only ever produced into a caller-supplied buffer — there is
    /// no "give me a static string" API — so the storage lives here.
    error_buffer: [256]u8 = undefined,
    error_buffer_used: bool = false,

    /// Load `cert_pem_path`/`key_pem_path` and configure ALPN.
    ///
    /// `alpn` is the server's preference order, e.g. `&.{ "h2", "http/1.1" }`;
    /// the first entry the client also offers is the one negotiated (see
    /// `alpnSelectCallback`).
    pub fn init(
        alloc: std.mem.Allocator,
        cert_pem_path: []const u8,
        key_pem_path: []const u8,
        alpn: []const []const u8,
    ) !*Ctx {
        if (cert_pem_path.len == 0 or key_pem_path.len == 0) return error.InvalidCertificatePath;
        if (alpn.len == 0) return error.EmptyAlpnList;
        for (alpn) |protocol| {
            // A single length byte precedes each protocol name on the wire, so
            // 255 is a hard ceiling, not a convention. Rejecting it here beats
            // a handshake that mysteriously never negotiates.
            if (protocol.len == 0 or protocol.len > 255) return error.InvalidAlpnProtocol;
        }

        const self = try alloc.create(Ctx);
        errdefer alloc.destroy(self);
        self.* = .{ .alloc = alloc, .ctx = undefined, .alpn = &.{} };

        self.alpn = try dupeAlpnList(alloc, alpn);
        errdefer freeAlpnList(alloc, self.alpn);

        const method = TLS_server_method() orelse {
            self.recordError("TLS_server_method() returned null");
            return error.NoServerMethod;
        };
        self.ctx = SSL_CTX_new(method) orelse {
            self.recordError("SSL_CTX_new() failed (out of memory?)");
            return error.ContextInitFailed;
        };
        errdefer SSL_CTX_free(self.ctx);

        // OpenSSL takes C strings for paths; the temporary NUL-terminated
        // copies live only for this call.
        const cert_z = try alloc.dupeZ(u8, cert_pem_path);
        defer alloc.free(cert_z);
        const key_z = try alloc.dupeZ(u8, key_pem_path);
        defer alloc.free(key_z);

        // A malformed PEM or a missing file both land here; `lastError` carries
        // OpenSSL's own diagnosis (e.g. "no start line", "No such file").
        if (SSL_CTX_use_certificate_chain_file(self.ctx, cert_z.ptr) != 1) {
            self.recordError("SSL_CTX_use_certificate_chain_file() failed");
            self.captureOpenSslError();
            return error.CertificateLoadFailed;
        }
        if (SSL_CTX_use_PrivateKey_file(self.ctx, key_z.ptr, X509_FILETYPE_PEM) != 1) {
            self.recordError("SSL_CTX_use_PrivateKey_file() failed");
            self.captureOpenSslError();
            return error.PrivateKeyLoadFailed;
        }
        // Catches a cert/key pair that was assembled from two different
        // generations — a real possibility when the pair lives in a directory
        // the user can edit, and otherwise only discovered per-handshake.
        if (SSL_CTX_check_private_key(self.ctx) != 1) {
            self.recordError("certificate and private key do not match");
            self.captureOpenSslError();
            return error.PrivateKeyMismatch;
        }

        // ALPN is the whole reason this file exists: without it a browser
        // cannot know the listener speaks h2, and would stay on HTTP/1.1.
        SSL_CTX_set_alpn_select_cb(self.ctx, &alpnSelectCallback, @ptrCast(self));

        // RFC 9113 §9.2: HTTP/2 over TLS requires TLS 1.2 or newer. OpenSSL 3.x
        // already defaults to that floor, but an `openssl.cnf` with a relaxed
        // `MinProtocol`/security level can lower it, and a protocol downgrade on
        // an h2 listener is not something to leave to a system default.
        _ = SSL_CTX_ctrl(self.ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, null);

        // Hardening that only makes sense for a long-lived HTTP/2 listener:
        //   * NO_COMPRESSION — TLS compression is a CRIME-style attack surface
        //     and HTTP/2 does its own (HPACK) compression anyway.
        //   * CIPHER_SERVER_PREFERENCE — the server's cipher order wins, so the
        //     listener's ordering decision is not overridable by a client.
        //   * NO_RENEGOTIATION — RFC 9113 §9.2.1 requires renegotiation to be
        //     disabled for HTTP/2; mid-stream renegotiation is also how HTTP/2
        //     request smuggling via downgrade attacks got its start.
        _ = SSL_CTX_set_options(
            self.ctx,
            SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_RENEGOTIATION,
        );

        return self;
    }

    /// Release the `SSL_CTX`. Every `Conn` created from this `Ctx` must be
    /// deinited first — live `SSL` objects reference their `SSL_CTX`.
    pub fn deinit(self: *Ctx) void {
        SSL_CTX_free(self.ctx);
        freeAlpnList(self.alloc, self.alpn);
        self.alloc.destroy(self);
    }

    /// Last error as a string. Points either at a static message or at this
    /// `Ctx`'s own error buffer, so it stays valid until the next failure (or
    /// until the `Ctx` is deinited) and never allocates.
    pub fn lastError(self: *Ctx) []const u8 {
        if (self.error_buffer_used) return std.mem.sliceTo(&self.error_buffer, 0);
        return self.last_error;
    }

    fn recordError(self: *Ctx, message: []const u8) void {
        self.last_error = message;
        self.error_buffer_used = false;
    }

    /// Move OpenSSL's most recent error-queue entry into `error_buffer`.
    ///
    /// The queue is per-thread and accumulates; taking the first entry (the
    /// most recent) and clearing nothing means a stale entry from an earlier
    /// call can be reported. That trade is deliberate: this is diagnostics for
    /// a human reading a log, and draining the whole queue would need an
    /// allocation to do it faithfully.
    fn captureOpenSslError(self: *Ctx) void {
        const code = ERR_get_error();
        if (code == 0) return;
        @memset(&self.error_buffer, 0);
        ERR_error_string_n(code, &self.error_buffer, self.error_buffer.len);
        self.error_buffer_used = true;
    }
};

/// One live TLS connection.
pub const Conn = struct {
    alloc: std.mem.Allocator,
    /// Null after `shutdown` — a connection torn down twice must not
    /// double-free, and using one afterwards must fail loudly rather than
    /// dereference freed memory.
    ssl: ?*SSL,

    /// Blocking handshake on an accepted socket.
    ///
    /// Ownership: the fd stays the caller's. `SSL_set_fd` wraps it in a
    /// `BIO_NOCLOSE` BIO, so on failure (and on any later `shutdown`/`deinit`)
    /// the caller closes the fd. Being blocking, this call inherits whatever
    /// timeout the caller set on the socket.
    pub fn accept(ctx: *Ctx, fd: i32) !*Conn {
        const ssl = SSL_new(ctx.ctx) orelse {
            ctx.recordError("SSL_new() failed");
            return error.ConnectionInitFailed;
        };
        // `fd` is an i32 in this repo (`SocketFd`); `SSL_set_fd` takes an int,
        // and on Windows that int is the winsock SOCKET value.
        if (SSL_set_fd(ssl, fd) != 1) {
            ctx.recordError("SSL_set_fd() failed");
            ctx.captureOpenSslError();
            SSL_free(ssl);
            return error.SetFdFailed;
        }

        const rc = SSL_accept(ssl);
        if (rc != 1) {
            recordHandshakeFailure(ctx, SSL_get_error(ssl, rc));
            SSL_free(ssl);
            return error.HandshakeFailed;
        }

        const self = ctx.alloc.create(Conn) catch |err| {
            SSL_free(ssl);
            return err;
        };
        self.* = .{ .alloc = ctx.alloc, .ssl = ssl };
        return self;
    }

    /// Read up to `buf.len` bytes of application data.
    ///
    /// Returns >0 for data, 0 for a *clean* end of stream (a `close_notify`
    /// alert), and `error.TlsReadFailed` for anything else — including a bare
    /// TCP close with no `close_notify`, which is indistinguishable from a
    /// truncation attack and must not be reported as an orderly shutdown. A
    /// socket-level timeout (`SO_RCVTIMEO`) also lands in that error: from the
    /// record layer's point of view an abandoned connection is a failure.
    ///
    /// A zero-length `buf` returns 0 without touching the connection — callers
    /// that distinguish "nothing to read" from "peer closed" must do so before
    /// calling.
    pub fn read(self: *Conn, buf: []u8) !usize {
        const ssl = self.ssl orelse return error.ConnectionClosed;
        if (buf.len == 0) return 0;

        var retries: usize = 0;
        while (true) {
            const rc = SSL_read(ssl, buf.ptr, @intCast(@min(buf.len, max_io_chunk)));
            if (rc > 0) return @intCast(rc);
            switch (SSL_get_error(ssl, rc)) {
                // Peer sent close_notify: an orderly shutdown, not an error.
                SSL_ERROR_ZERO_RETURN => return 0,
                // A blocking fd should not need these, but TLS 1.3
                // post-handshake messages (session tickets, KeyUpdate) can ask
                // for another round trip. Allow a bounded handful so they are
                // not mistaken for failure, and cap it so a pathological peer
                // cannot spin this loop forever.
                SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE => {
                    retries += 1;
                    if (retries > max_spurious_want) return error.TlsReadFailed;
                    continue;
                },
                else => return error.TlsReadFailed,
            }
        }
    }

    /// Write all of `bytes`, in record-sized chunks.
    pub fn writeAll(self: *Conn, bytes: []const u8) !void {
        const ssl = self.ssl orelse return error.ConnectionClosed;

        var written: usize = 0;
        var retries: usize = 0;
        while (written < bytes.len) {
            const chunk: c_int = @intCast(@min(bytes.len - written, max_io_chunk));
            const rc = SSL_write(ssl, bytes.ptr + written, chunk);
            if (rc > 0) {
                written += @intCast(rc);
                retries = 0;
                continue;
            }
            switch (SSL_get_error(ssl, rc)) {
                SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE => {
                    retries += 1;
                    if (retries > max_spurious_want) return error.TlsWriteFailed;
                    continue;
                },
                else => return error.TlsWriteFailed,
            }
        }
    }

    /// The ALPN protocol the client and server agreed on, or `""` when none
    /// was negotiated.
    ///
    /// `""` happens for a client that sends no ALPN extension at all (curl and
    /// Zig's own TLS client do this) — the handshake still succeeds and the
    /// caller should fall back to HTTP/1.1. A client that offers ALPN but
    /// shares no protocol with this listener never gets this far: the handshake
    /// already failed (see `alpnSelectCallback`).
    ///
    /// The returned slice points into OpenSSL's per-`SSL` storage; it is valid
    /// until `shutdown`/`deinit` and must not be freed.
    pub fn selectedAlpn(self: *Conn) []const u8 {
        const ssl = self.ssl orelse return "";
        var data: ?[*]const u8 = null;
        var len: c_uint = 0;
        SSL_get0_alpn_selected(ssl, &data, &len);
        if (data == null or len == 0) return "";
        return data.?[0..len];
    }

    /// Best-effort `SSL_shutdown` (a `close_notify` alert) followed by
    /// `SSL_free`. The fd is not closed (see `accept`). Idempotent.
    pub fn shutdown(self: *Conn) void {
        const ssl = self.ssl orelse return;
        // The return value is deliberately ignored: 0 means "close_notify sent,
        // waiting for the peer's", 1 means "both sent", negative means the peer
        // is already gone. None of those change what we do next, and a
        // half-closed peer must not turn teardown into an error path.
        _ = SSL_shutdown(ssl);
        SSL_free(ssl);
        self.ssl = null;
    }

    /// `shutdown` + free the `Conn` itself.
    ///
    /// The `shutdown` half is idempotent, so calling this after a `shutdown` is
    /// safe; as with any `alloc.destroy`, the `Conn` must not be touched again
    /// afterwards.
    pub fn deinit(self: *Conn) void {
        self.shutdown();
        self.alloc.destroy(self);
    }
};

/// Maximum bytes handed to a single `SSL_read`/`SSL_write` call — those take an
/// `int`, so a larger slice would silently truncate (or trap) in the cast.
const max_io_chunk: usize = std.math.maxInt(c_int);

/// How many consecutive `WANT_READ`/`WANT_WRITE` results a blocking fd may
/// produce before we give up.
const max_spurious_want: usize = 16;

// ===========================================================================
// Internals
// ===========================================================================

/// Deep-copy the caller's ALPN preference list (see `Ctx.alpn` for why).
fn dupeAlpnList(alloc: std.mem.Allocator, alpn: []const []const u8) ![][]const u8 {
    const owned = try alloc.alloc([]const u8, alpn.len);
    errdefer alloc.free(owned);
    var filled: usize = 0;
    // `filled` is read when the error fires, so the partially-filled prefix (and
    // only that prefix) is released.
    errdefer for (owned[0..filled]) |protocol| alloc.free(protocol);
    for (alpn) |protocol| {
        owned[filled] = try alloc.dupe(u8, protocol);
        filled += 1;
    }
    return owned;
}

fn freeAlpnList(alloc: std.mem.Allocator, alpn: []const []const u8) void {
    for (alpn) |protocol| alloc.free(protocol);
    alloc.free(alpn);
}

/// OpenSSL ALPN selection callback (see `SSL_CTX_set_alpn_select_cb`).
///
/// `in`/`in_len` is the client's protocol list in wire format: one length byte
/// followed by that many bytes, repeated. The chosen protocol is reported by
/// pointing `out` at the matching entry *inside `in`* — legal because OpenSSL
/// keeps the ClientHello alive for the handshake, and it means no allocation
/// and no static buffer that a second connection could race.
///
/// Selection follows the SERVER's order (the list handed to `Ctx.init`), not
/// the client's: that is what "h2 preferred" means, and it is why a client
/// offering `http/1.1` first still gets `h2`.
///
/// No overlap => `SSL_TLSEXT_ERR_ALERT_FATAL`. The alternative (`NOACK`, i.e.
/// "continue without ALPN") would complete a TLS handshake for a client that
/// believes it is talking to an h2 server while the listener is about to speak
/// HTTP/1.1. Failing the handshake is the loud, safe outcome; and it is the
/// behaviour the interface is specified to have.
fn alpnSelectCallback(
    ssl: ?*SSL,
    out: *[*]const u8,
    out_len: *u8,
    in: [*]const u8,
    in_len: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = ssl;
    // A null `arg` means the callback was registered without its `Ctx`, which
    // this file never does. Fail the handshake rather than pretend ALPN was
    // negotiated and let the caller speak the wrong protocol.
    const ctx: *Ctx = @ptrCast(@alignCast(arg orelse return SSL_TLSEXT_ERR_ALERT_FATAL));
    const offered = in[0..in_len];

    for (ctx.alpn) |server_protocol| {
        var i: usize = 0;
        while (i < offered.len) {
            const name_len = offered[i];
            // A zero-length name or a length that runs past the end is a
            // malformed list; there is nothing further to match against.
            if (name_len == 0 or i + 1 + name_len > offered.len) break;
            const client_protocol = offered[i + 1 ..][0..name_len];
            if (std.mem.eql(u8, server_protocol, client_protocol)) {
                out.* = in + i + 1;
                out_len.* = name_len;
                return SSL_TLSEXT_ERR_OK;
            }
            i += 1 + name_len;
        }
    }

    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/// Turn an `SSL_get_error` code into a sentence a human can act on, and let
/// OpenSSL append its own detail when it has one.
fn recordHandshakeFailure(self: *Ctx, ssl_error: c_int) void {
    self.last_error = switch (ssl_error) {
        SSL_ERROR_ZERO_RETURN => "peer closed the connection during the TLS handshake",
        SSL_ERROR_WANT_READ => "TLS handshake needs more data (socket is non-blocking?)",
        SSL_ERROR_WANT_WRITE => "TLS handshake needs the socket to drain (socket is non-blocking?)",
        SSL_ERROR_SYSCALL => "TLS handshake failed at the socket level (peer closed or reset)",
        SSL_ERROR_SSL => "TLS handshake rejected by OpenSSL (no shared cipher, ALPN mismatch, or a rejected certificate?)",
        else => "TLS handshake failed",
    };
    self.captureOpenSslError();
}

// ============================================================================
// Tests — moved here from `tls_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = tls_tests; }` below pulls them into the run.
// ============================================================================

const tls_tests = struct {
    // Tests for `tls.zig` — the OpenSSL server-side TLS + ALPN surface.
    //
    // # Why there are two client implementations here
    //
    // The tests drive real TLS clients over a `socketpair`, because the whole
    // point of this module is that two independent implementations agree on the
    // wire — a mocked record layer would prove nothing about the handshake.
    //
    // * **`std.crypto.tls.Client`** (Zig's own, used for the record-layer tests:
    //   data round-trip, clean EOF, and the "no ALPN offered" case). It cannot be
    //   used for ALPN: Zig 0.16's TLS client has no ALPN support at all — there is
    //   not one occurrence of "alpn" anywhere under `/usr/lib/zig/std`, so the
    //   extension is never even sent. That is a fact about std, not a limitation
    //   of this test, and it is deliberately not papered over: the ALPN cases are
    //   driven by…
    // * **OpenSSL's TLS client** (`TLS_client_method` + `SSL_set_alpn_protos`),
    //   which advertises exactly the protocol list each case needs and reports
    //   back what *it* negotiated. Asserting both ends agree is strictly stronger
    //   evidence than asserting only the server's view.
    //
    // Both clients run in a `std.Thread`; the server-side handshake runs on the
    // test thread. The fds are blocking, so one side must be on another thread or
    // the handshake would deadlock against itself.
    //
    // Sockets are read/written through `std.c.read`/`std.c.write`, which exist on
    // POSIX only — the socket-driven tests therefore skip on Windows. (The module
    // under test is platform-neutral: it only ever passes an `i32` to
    // `SSL_set_fd`.) Every such test sets a 10s socket timeout first, so a logic
    // error that makes one side wait forever fails the test instead of hanging
    // the run.

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


    extern fn TLS_client_method() ?*const SSL_METHOD;
    extern fn SSL_CTX_set_alpn_protos(ctx: *SSL_CTX, protos: [*]const u8, protos_len: c_uint) c_int;
    extern fn SSL_connect(ssl: *SSL) c_int;

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
};

comptime {
    _ = tls_tests;
}
