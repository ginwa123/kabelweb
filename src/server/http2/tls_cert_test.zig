//! Tests for `tls_cert.zig`.
//!
//! The point of these tests is to prove the *bytes written to disk* are a real,
//! usable certificate — not that some OpenSSL call returned 1. Three
//! independent readings of the same file therefore have to agree:
//!
//!   1. Zig's own X.509 parser (`std.crypto.Certificate`) — proves real DER.
//!   2. Zig's own host-name matcher (`Parsed.verifyHostName`) — proves the SANs
//!      a webview actually checks are present and spelled correctly.
//!   3. OpenSSL's server-side loader (`SSL_CTX_use_certificate_chain_file` +
//!      `SSL_CTX_use_PrivateKey_file` + `SSL_CTX_check_private_key`) — proves the
//!      pair is acceptable to the library that will do the handshaking, and that
//!      the key matches the certificate.
//!
//! If the generator wrote a malformed DER, a mismatched key, or a certificate
//! that only OpenSSL tolerates, at least one of those three fails.

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

const tls_cert = @import("tls_cert.zig");

// ---------------------------------------------------------------------------
// OpenSSL surface for the acceptance test (server-side key loading only).
// ---------------------------------------------------------------------------

const SSL_CTX = opaque {};
const SSL_METHOD = opaque {};

extern fn TLS_server_method() ?*const SSL_METHOD;
extern fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
extern fn SSL_CTX_free(ctx: ?*SSL_CTX) void;
extern fn SSL_CTX_use_certificate_chain_file(ctx: *SSL_CTX, file: [*:0]const u8) c_int;
extern fn SSL_CTX_use_PrivateKey_file(ctx: *SSL_CTX, file: [*:0]const u8, file_type: c_int) c_int;
extern fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) c_int;
extern fn ERR_get_error() c_ulong;
extern fn ERR_error_string_n(e: c_ulong, buf: [*]u8, len: usize) void;

const X509_FILETYPE_PEM: c_int = 1;

/// Print OpenSSL's pending error queue. Called only on failure, so the success
/// path stays silent; a bare `assert(rc == 1)` would leave the actual reason
/// ("key values mismatch", "no start line", …) invisible.
fn dumpOpenSslErrors(what: []const u8) void {
    var printed = false;
    while (true) {
        // `ERR_get_error` pops one entry off the thread's error queue and
        // returns 0 when the queue is empty.
        const code = ERR_get_error();
        if (code == 0) break;
        var buf: [256]u8 = undefined;
        ERR_error_string_n(code, &buf, buf.len);
        std.debug.print("{s}: {s}\n", .{ what, std.mem.sliceTo(&buf, 0) });
        printed = true;
    }
    if (!printed) std.debug.print("{s}: (OpenSSL error queue empty)\n", .{what});
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Absolute path of a `testing.tmpDir` directory.
///
/// The generator is given a plain path (never a dir handle), so the test must
/// hand it one that works regardless of the process cwd — asking the opened
/// directory for its own real path is the only spelling that cannot drift when
/// std changes where `tmpDir` puts things.
fn tmpDirAbsolutePath(alloc: std.mem.Allocator, tmp: *testing.TmpDir) ![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return alloc.dupe(u8, buffer[0..len]);
}

fn readFile(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(testing.io, path, alloc, .limited(1 << 20));
}

fn fileMtimeNanos(path: []const u8) !i96 {
    const stat = try std.Io.Dir.cwd().statFile(testing.io, path, .{});
    return stat.mtime.nanoseconds;
}

/// Decode the base64 body of the `CERTIFICATE` PEM block into DER.
///
/// Deliberately decoded with Zig's own std (not OpenSSL): the parse test below
/// claims "the bytes on disk are valid X.509", so the decode step must not be
/// able to paper over an encoding mistake made by the generator.
fn pemToDer(alloc: std.mem.Allocator, pem: []const u8) ![]u8 {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const begin = std.mem.indexOf(u8, pem, begin_marker) orelse return error.MissingPemHeader;
    const body_start = std.mem.indexOfScalarPos(u8, pem, begin + begin_marker.len, '\n') orelse
        return error.MissingPemHeader;
    const end = std.mem.indexOfPos(u8, pem, body_start, end_marker) orelse return error.MissingPemFooter;

    // PEM wraps the base64 into 64-column lines — strip the line breaks so the
    // decoded length can be computed exactly (3 bytes per 4 chars, minus pad).
    var compact: std.ArrayList(u8) = .empty;
    defer compact.deinit(alloc);
    for (pem[body_start + 1 .. end]) |c| {
        switch (c) {
            ' ', '\t', '\r', '\n' => {},
            else => try compact.append(alloc, c),
        }
    }
    try testing.expect(compact.items.len % 4 == 0);

    const padding: usize = if (std.mem.endsWith(u8, compact.items, "=="))
        2
    else if (std.mem.endsWith(u8, compact.items, "="))
        1
    else
        0;

    const der = try alloc.alloc(u8, compact.items.len / 4 * 3 - padding);
    errdefer alloc.free(der);
    try std.base64.standard.Decoder.decode(der, compact.items);
    return der;
}

// ---------------------------------------------------------------------------
// Generation + reuse
// ---------------------------------------------------------------------------

test "ensureSelfSigned writes a PEM pair into a fresh directory and reuses it" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirAbsolutePath(alloc, &tmp);
    defer alloc.free(dir);

    const first = try tls_cert.ensureSelfSigned(alloc, dir, "nalar-h2-test", 30);
    defer alloc.free(first.cert_pem);
    defer alloc.free(first.key_pem);

    // The returned paths are inside the requested directory and use the names
    // the TLS listener expects.
    try testing.expect(std.mem.startsWith(u8, first.cert_pem, dir));
    try testing.expect(std.mem.startsWith(u8, first.key_pem, dir));
    try testing.expect(std.mem.endsWith(u8, first.cert_pem, tls_cert.cert_file_name));
    try testing.expect(std.mem.endsWith(u8, first.key_pem, tls_cert.key_file_name));

    const cert_before = try readFile(alloc, first.cert_pem);
    defer alloc.free(cert_before);
    const key_before = try readFile(alloc, first.key_pem);
    defer alloc.free(key_before);

    try testing.expect(std.mem.startsWith(u8, cert_before, "-----BEGIN CERTIFICATE-----"));
    try testing.expect(std.mem.endsWith(u8, cert_before, "-----END CERTIFICATE-----\n"));
    // An unencrypted PKCS#8 EC key ("BEGIN PRIVATE KEY", not the legacy
    // "BEGIN EC PRIVATE KEY") is what PEM_write_bio_PrivateKey emits.
    try testing.expect(std.mem.startsWith(u8, key_before, "-----BEGIN PRIVATE KEY-----"));
    try testing.expect(std.mem.endsWith(u8, key_before, "-----END PRIVATE KEY-----\n"));

    const cert_mtime = try fileMtimeNanos(first.cert_pem);
    const key_mtime = try fileMtimeNanos(first.key_pem);

    // Second call: identical paths, byte-identical contents, untouched mtimes.
    // Any of the three failing means the material was regenerated, which would
    // invalidate a webview's already-granted trust in the certificate.
    const second = try tls_cert.ensureSelfSigned(alloc, dir, "nalar-h2-test", 30);
    defer alloc.free(second.cert_pem);
    defer alloc.free(second.key_pem);

    try testing.expectEqualStrings(first.cert_pem, second.cert_pem);
    try testing.expectEqualStrings(first.key_pem, second.key_pem);

    const cert_after = try readFile(alloc, second.cert_pem);
    defer alloc.free(cert_after);
    const key_after = try readFile(alloc, second.key_pem);
    defer alloc.free(key_after);
    try testing.expectEqualSlices(u8, cert_before, cert_after);
    try testing.expectEqualSlices(u8, key_before, key_after);

    try testing.expectEqual(cert_mtime, try fileMtimeNanos(second.cert_pem));
    try testing.expectEqual(key_mtime, try fileMtimeNanos(second.key_pem));
}

test "returned paths are absolute even for a relative input directory" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // `testing.tmpDir` hands back a directory that is *relative* to the test's
    // cwd, which exercises the relative-input branch without touching the real
    // cwd or any user-visible location.
    const relative = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer alloc.free(relative);

    const paths = try tls_cert.ensureSelfSigned(alloc, relative, "nalar-h2-test", 1);
    defer alloc.free(paths.cert_pem);
    defer alloc.free(paths.key_pem);

    // The interface promises absolute paths; a relative one would silently
    // break a listener whose cwd is not the process's starting directory.
    try testing.expect(std.fs.path.isAbsolute(paths.cert_pem));
    try testing.expect(std.fs.path.isAbsolute(paths.key_pem));
}

test "a deleted half is regenerated instead of being reused" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirAbsolutePath(alloc, &tmp);
    defer alloc.free(dir);

    const first = try tls_cert.ensureSelfSigned(alloc, dir, "nalar-h2-test", 30);
    defer alloc.free(first.cert_pem);
    defer alloc.free(first.key_pem);
    const cert_before = try readFile(alloc, first.cert_pem);
    defer alloc.free(cert_before);

    // Simulate a crash between the two writes (or a hand-deleted key).
    try std.Io.Dir.cwd().deleteFile(testing.io, first.key_pem);

    const second = try tls_cert.ensureSelfSigned(alloc, dir, "nalar-h2-test", 30);
    defer alloc.free(second.cert_pem);
    defer alloc.free(second.key_pem);

    // Both halves exist again, and they are a fresh pair: a regenerated
    // certificate carries a new serial, a new key and a new signature, so the
    // bytes cannot coincide with the previous one.
    const cert_after = try readFile(alloc, second.cert_pem);
    defer alloc.free(cert_after);
    const key_after = try readFile(alloc, second.key_pem);
    defer alloc.free(key_after);

    try testing.expect(cert_after.len > 0);
    try testing.expect(key_after.len > 0);
    try testing.expect(!std.mem.eql(u8, cert_before, cert_after));
}

test "invalid inputs are rejected before touching the filesystem" {
    const alloc = testing.allocator;

    try testing.expectError(
        error.InvalidDirectoryPath,
        tls_cert.ensureSelfSigned(alloc, "", "nalar-h2-test", 30),
    );
    try testing.expectError(
        error.InvalidCommonName,
        tls_cert.ensureSelfSigned(alloc, "/nonexistent-nalar-test-dir", "", 30),
    );
    try testing.expectError(
        error.InvalidValidityDays,
        tls_cert.ensureSelfSigned(alloc, "/nonexistent-nalar-test-dir", "nalar-h2-test", 0),
    );
}

// ---------------------------------------------------------------------------
// File modes (POSIX)
// ---------------------------------------------------------------------------

test "private key is owner-only and the directory is 0700" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // A *nested* directory that does not exist yet, so the 0700 creation path
    // (rather than the pre-existing-directory path) is what gets exercised.
    const parent = try tmpDirAbsolutePath(alloc, &tmp);
    defer alloc.free(parent);
    const dir = try std.fs.path.join(alloc, &.{ parent, "certs" });
    defer alloc.free(dir);

    const paths = try tls_cert.ensureSelfSigned(alloc, dir, "nalar-h2-test", 30);
    defer alloc.free(paths.cert_pem);
    defer alloc.free(paths.key_pem);

    const key_mode = (try std.Io.Dir.cwd().statFile(testing.io, paths.key_pem, .{})).permissions.toMode();
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), key_mode & 0o777);

    const cert_mode = (try std.Io.Dir.cwd().statFile(testing.io, paths.cert_pem, .{})).permissions.toMode();
    try testing.expectEqual(@as(std.posix.mode_t, 0o644), cert_mode & 0o777);

    const dir_mode = (try std.Io.Dir.cwd().statFile(testing.io, dir, .{})).permissions.toMode();
    try testing.expectEqual(@as(std.posix.mode_t, 0o700), dir_mode & 0o777);
}

// ---------------------------------------------------------------------------
// The certificate is real X.509 with the required SANs
// ---------------------------------------------------------------------------

test "certificate parses with Zig's X.509 parser and carries the localhost SANs" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirAbsolutePath(alloc, &tmp);
    defer alloc.free(dir);

    const paths = try tls_cert.ensureSelfSigned(alloc, dir, "nalar-h2-test", 30);
    defer alloc.free(paths.cert_pem);
    defer alloc.free(paths.key_pem);

    const pem = try readFile(alloc, paths.cert_pem);
    defer alloc.free(pem);
    const der = try pemToDer(alloc, pem);
    defer alloc.free(der);

    const parsed = try std.crypto.Certificate.parse(.{ .buffer = der, .index = 0 });

    // Self-signed: subject == issuer == CN=<common_name>.
    try testing.expectEqualStrings("nalar-h2-test", parsed.commonName());
    try testing.expectEqualStrings(parsed.issuer(), parsed.subject());

    // Validity window is `days` long. The two ASN.1 timestamps are read from
    // the clock by two separate `X509_gmtime_adj` calls, so a tick between
    // them can add one second — accept exactly that and nothing more.
    const expected_seconds: u64 = 30 * std.time.s_per_day;
    const actual_seconds = parsed.validity.not_after - parsed.validity.not_before;
    try testing.expect(actual_seconds == expected_seconds or actual_seconds == expected_seconds + 1);

    // Zig's own matcher — the same code path `std.http.Client` uses — must
    // accept the host name a webview will dial.
    try parsed.verifyHostName("localhost");

    // Structural SAN assertions: context tag 2 (dNSName) + length 9 +
    // "localhost", and context tag 7 (iPAddress) + length 4 + 127.0.0.1. The
    // tag/length prefix is what makes this a DER claim rather than a
    // "the string appears somewhere in the file" claim.
    const dns_name_san = [_]u8{ 0x82, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't' };
    const ip_address_san = [_]u8{ 0x87, 0x04, 127, 0, 0, 1 };
    try testing.expect(std.mem.indexOf(u8, der, &dns_name_san) != null);
    try testing.expect(std.mem.indexOf(u8, der, &ip_address_san) != null);

    // The key is an EC P-256 key, not RSA/Ed25519.
    try testing.expect(std.meta.eql(
        parsed.pub_key_algo,
        std.crypto.Certificate.Parsed.PubKeyAlgo{ .X9_62_id_ecPublicKey = .X9_62_prime256v1 },
    ));
}

// ---------------------------------------------------------------------------
// OpenSSL acceptance (the real gate for the TLS listener)
// ---------------------------------------------------------------------------

test "OpenSSL loads the generated pair as a server certificate" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpDirAbsolutePath(alloc, &tmp);
    defer alloc.free(dir);

    const paths = try tls_cert.ensureSelfSigned(alloc, dir, "nalar-h2-test", 30);
    defer alloc.free(paths.cert_pem);
    defer alloc.free(paths.key_pem);

    const method = TLS_server_method() orelse {
        dumpOpenSslErrors("TLS_server_method");
        return error.NoServerMethod;
    };
    const ctx = SSL_CTX_new(method) orelse {
        dumpOpenSslErrors("SSL_CTX_new");
        return error.NoSslContext;
    };
    defer SSL_CTX_free(ctx);

    const cert_z = try alloc.dupeZ(u8, paths.cert_pem);
    defer alloc.free(cert_z);
    const key_z = try alloc.dupeZ(u8, paths.key_pem);
    defer alloc.free(key_z);

    // A malformed DER fails here: OpenSSL parses the certificate fully.
    const cert_rc = SSL_CTX_use_certificate_chain_file(ctx, cert_z.ptr);
    if (cert_rc != 1) dumpOpenSslErrors("SSL_CTX_use_certificate_chain_file");
    try testing.expectEqual(@as(c_int, 1), cert_rc);

    const key_rc = SSL_CTX_use_PrivateKey_file(ctx, key_z.ptr, X509_FILETYPE_PEM);
    if (key_rc != 1) dumpOpenSslErrors("SSL_CTX_use_PrivateKey_file");
    try testing.expectEqual(@as(c_int, 1), key_rc);

    // Fails with "key values mismatch" if the certificate on disk does not
    // actually belong to the private key next to it.
    const pair_rc = SSL_CTX_check_private_key(ctx);
    if (pair_rc != 1) dumpOpenSslErrors("SSL_CTX_check_private_key");
    try testing.expectEqual(@as(c_int, 1), pair_rc);
}
