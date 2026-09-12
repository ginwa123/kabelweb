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

test {
    _ = @import("tls_test.zig");
}
