//! Self-signed server certificate generation + on-disk reuse for the
//! HTTP/2-over-TLS listener.
//!
//! Why OpenSSL: Zig 0.16's `std.crypto` ships certificate *verification* (the
//! client half) but neither X.509 *generation* nor a TLS server. The h2
//! listener therefore talks to OpenSSL through the C API, and this file owns
//! the "get me a usable keypair" end of that. (`tls.zig` owns the handshake.)
//!
//! Design constraints:
//!   * **Reuse, never churn.** A browser or desktop webview that accepted the
//!     certificate once must keep working across restarts, so an existing pair
//!     is returned untouched — regeneration would invalidate the trust the
//!     user already granted.
//!   * **Never hand OpenSSL a half-written pair.** A crash between the two
//!     writes (or a hand-deleted file) must not leave a directory that looks
//!     provisioned but fails every handshake with a confusing OpenSSL error;
//!     the pair is therefore only reused when BOTH files exist and are
//!     non-empty, and is otherwise regenerated wholesale.
//!   * **Private key is owner-only.** Written 0600 with an explicit re-apply
//!     after creation, so a permissive umask cannot widen it.
//!   * **All OpenSSL objects are released before returning.** The caller only
//!     ever sees PEM bytes, so no failure path can leak a half-built `X509`
//!     or key.

const std = @import("std");
const builtin = @import("builtin");

// ===========================================================================
// OpenSSL C surface — only the symbols this file calls.
//
// Declared by hand rather than via `@cImport`: the dependency is then explicit
// and reviewable (six libcrypto entry points, not the whole 9000-line X509
// header surface), the ABI cannot silently shift under a system OpenSSL
// upgrade, and `zig test -lc -lssl -lcrypto` stays the entire build recipe.
// ===========================================================================

const ASN1_INTEGER = opaque {};
const ASN1_TIME = opaque {};
const BIO = opaque {};
const BIO_METHOD = opaque {};
const EVP_MD = opaque {};
const EVP_PKEY = opaque {};
const X509 = opaque {};
const X509_EXTENSION = opaque {};
const X509_NAME = opaque {};

/// `BIO_get_mem_data(b, pp)` is a macro for `BIO_ctrl(b, BIO_CTRL_INFO, 0, pp)`
/// (openssl/bio.h), i.e. "hand me the memory BIO's internal buffer".
const BIO_CTRL_INFO: c_int = 3;
/// `MBSTRING_UTF8` (openssl/asn1.h) — tells `X509_NAME_add_entry_by_txt` that
/// the bytes are UTF-8, so a non-ASCII common name is encoded correctly
/// instead of being reinterpreted as printable-ASCII.
const MBSTRING_UTF8: c_int = 0x1000;
/// `X509_FILETYPE_PEM` (openssl/x509.h).
const X509_FILETYPE_PEM: c_int = 1;
/// `X509_add_ext(x, ex, loc)` with loc == -1 appends the extension.
const X509_ADD_EXT_APPEND: c_int = -1;
/// `X509_NAME_add_entry_by_txt(..., loc == -1)` appends the RDN.
const X509_NAME_ADD_APPEND: c_int = -1;

extern fn EVP_PKEY_Q_keygen(libctx: ?*anyopaque, propq: ?[*:0]const u8, key_type: [*:0]const u8, ...) ?*EVP_PKEY;
extern fn EVP_PKEY_free(pkey: ?*EVP_PKEY) void;
extern fn EVP_sha256() *const EVP_MD;
extern fn X509_new() ?*X509;
extern fn X509_free(x: ?*X509) void;
extern fn X509_set_version(x: *X509, version: c_long) c_int;
extern fn X509_get_serialNumber(x: *X509) ?*ASN1_INTEGER;
extern fn ASN1_INTEGER_set(a: *ASN1_INTEGER, v: c_long) c_int;
extern fn X509_getm_notBefore(x: *const X509) ?*ASN1_TIME;
extern fn X509_getm_notAfter(x: *const X509) ?*ASN1_TIME;
extern fn X509_gmtime_adj(s: ?*ASN1_TIME, adj: c_long) ?*ASN1_TIME;
extern fn X509_get_subject_name(x: *const X509) ?*X509_NAME;
extern fn X509_set_subject_name(x: *X509, name: *const X509_NAME) c_int;
extern fn X509_set_issuer_name(x: *X509, name: *const X509_NAME) c_int;
extern fn X509_NAME_add_entry_by_txt(name: *X509_NAME, field: [*:0]const u8, entry_type: c_int, bytes: [*]const u8, len: c_int, loc: c_int, set: c_int) c_int;
extern fn X509_set_pubkey(x: *X509, pkey: *EVP_PKEY) c_int;
extern fn X509_add_ext(x: *X509, ex: *X509_EXTENSION, loc: c_int) c_int;
extern fn X509_EXTENSION_free(ex: ?*X509_EXTENSION) void;
extern fn X509_sign(x: *X509, pkey: *EVP_PKEY, md: *const EVP_MD) c_int;
extern fn OBJ_txt2nid(s: [*:0]const u8) c_int;
extern fn X509V3_EXT_conf_nid(conf: ?*anyopaque, ctx: ?*anyopaque, ext_nid: c_int, value: [*:0]const u8) ?*X509_EXTENSION;
extern fn BIO_new(method: ?*const BIO_METHOD) ?*BIO;
extern fn BIO_s_mem() ?*const BIO_METHOD;
extern fn BIO_free(bio: ?*BIO) c_int;
extern fn BIO_ctrl(bio: *BIO, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
extern fn PEM_write_bio_X509(bio: *BIO, x: *const X509) c_int;
extern fn PEM_write_bio_PrivateKey(bio: *BIO, pkey: *const EVP_PKEY, cipher: ?*const anyopaque, kstr: ?[*]const u8, klen: c_int, cb: ?*anyopaque, u: ?*anyopaque) c_int;

// ===========================================================================
// Public surface
// ===========================================================================

/// Names of the pair inside the target directory. Fixed rather than
/// caller-supplied so the generator and the TLS listener can never disagree
/// about where the material lives.
pub const cert_file_name = "cert.pem";
pub const key_file_name = "key.pem";

/// SAN entries baked into every generated certificate.
///
/// Browsers and webviews ignore the common name entirely and reject a
/// certificate whose SAN does not match the host being dialed, so these two
/// entries — the two spellings of "this machine" a local webview can use — are
/// the difference between a click-through-once certificate and a hard failure.
/// The `common_name` parameter is therefore informational (it shows up in
/// certificate dialogs); it is deliberately NOT used as a SAN, so a caller
/// cannot accidentally produce a certificate that matches nothing.
const san_list = "DNS:localhost,IP:127.0.0.1";

/// Additional v3 extensions every mainstream TLS stack expects on a server
/// certificate. OpenSSL itself does not require them, but Windows' Schannel
/// and the WebKit/Chromium network stacks inspect `extendedKeyUsage` before
/// accepting a certificate for `serverAuth`, and `keyUsage` is cheap insurance.
const extra_extensions = [_]struct { name: [*:0]const u8, value: [*:0]const u8 }{
    .{ .name = "basicConstraints", .value = "critical,CA:FALSE" },
    .{ .name = "keyUsage", .value = "critical,digitalSignature" },
    .{ .name = "extendedKeyUsage", .value = "serverAuth" },
};

pub const Paths = struct {
    /// Absolute path of the PEM certificate (allocated with `alloc`).
    cert_pem: []const u8,
    /// Absolute path of the PEM private key (allocated with `alloc`).
    key_pem: []const u8,
};

/// Every failure this module can produce on its own. Filesystem failures are
/// reported as-is by the public function's inferred error set; this set covers
/// the OpenSSL/caller-input half so the domain is greppable. `OutOfMemory`
/// rides along because the PEM buffers are allocator-owned.
pub const Error = error{
    /// `dir_path` was empty — there is nowhere to write the pair.
    InvalidDirectoryPath,
    /// Empty common name, or one containing a NUL (OpenSSL's X509 helpers use
    /// `char *` internally in places, so a NUL would truncate the name).
    InvalidCommonName,
    /// `days == 0` would produce a certificate that is already expired.
    InvalidValidityDays,
    KeyGenerationFailed,
    CertificateCreationFailed,
    InvalidExtensionName,
    ExtensionConfigFailed,
    SubjectAltNameExtensionFailed,
    CertificateSignFailed,
    CertificateEncodeFailed,
    PrivateKeyEncodeFailed,
} || std.mem.Allocator.Error;

/// Ensure a self-signed certificate exists in `dir_path`, generating it on
/// first use and REUSING it afterwards (a browser/webview that trusts it once
/// must keep working across restarts).
///
/// Requirements:
///  * EC P-256 key, signed with SHA-256, valid for `days` days from now,
///    subject/issuer commonName = `common_name`.
///  * SANs include `DNS:localhost` and `IP:127.0.0.1` (browsers/webviews
///    reject a cert whose SAN does not match the host — see `san_list`).
///  * key file written with mode 0600 on POSIX (never world-readable); the
///    directory created 0700 if missing.
///  * Returns the two paths as owned slices (free both with `alloc`).
pub fn ensureSelfSigned(
    alloc: std.mem.Allocator,
    dir_path: []const u8,
    common_name: []const u8,
    days: u32,
) !Paths {
    if (dir_path.len == 0) return error.InvalidDirectoryPath;
    if (common_name.len == 0) return error.InvalidCommonName;
    if (std.mem.indexOfScalar(u8, common_name, 0) != null) return error.InvalidCommonName;
    if (days == 0) return error.InvalidValidityDays;

    // `std.Io.Dir` needs an `Io` runtime and this signature writes the frozen
    // interface, which has no `io` parameter. Own a private one for the call;
    // provisioning happens once per process start, so the cost is irrelevant
    // and a global would be one more thing to initialise in the wrong order.
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // `resolve` alone does NOT prepend the cwd (see its doc comment), so the
    // directory is made absolute explicitly — the interface promises absolute
    // paths for the returned files. Everything below derives from that single
    // resolved directory so the created directory and the written files can
    // never disagree.
    const abs_dir = try absoluteDirPath(alloc, io, dir_path);
    defer alloc.free(abs_dir);

    const cert_path = try std.fs.path.resolve(alloc, &.{ abs_dir, cert_file_name });
    errdefer alloc.free(cert_path);
    const key_path = try std.fs.path.resolve(alloc, &.{ abs_dir, key_file_name });
    errdefer alloc.free(key_path);

    if (try reuseExistingPair(io, cert_path, key_path)) {
        return .{ .cert_pem = cert_path, .key_pem = key_path };
    }

    // Create the directory (if needed) *before* generating: a key generation
    // failure should not leave a directory behind, and a directory failure
    // should not burn key-generation entropy.
    _ = try std.Io.Dir.cwd().createDirPathStatus(io, abs_dir, permissionsFromMode(dir_mode));

    const pems = try buildPems(alloc, io, common_name, days);
    defer alloc.free(pems.cert);
    defer alloc.free(pems.key);

    try writeFileWithMode(io, cert_path, pems.cert, cert_mode);
    try writeFileWithMode(io, key_path, pems.key, key_mode);

    return .{ .cert_pem = cert_path, .key_pem = key_path };
}

/// 0700 — the directory holds a private key, so nothing outside the owner has
/// any business listing it.
const dir_mode: u32 = 0o700;
/// 0600 — owner read/write only.
const key_mode: u32 = 0o600;
/// 0644 — the certificate is public by definition; keep it world-readable so
/// a webview process running as another user can still load it.
const cert_mode: u32 = 0o644;

// ===========================================================================
// Reuse
// ===========================================================================

/// Absolute form of `dir_path`, consulted against the process cwd only when the
/// caller actually gave a relative path.
///
/// `std.fs.path.resolve` normalises `.`/`..` but deliberately does not prepend
/// the cwd, so the cwd is fetched explicitly — and only when needed, so an
/// absolute `dir_path` still works in a process whose cwd is unusable.
///
/// `std.process.currentPath` rather than `std.Io.Dir.cwd().realPath`: on Linux
/// the cwd handle *is* the `AT_FDCWD` sentinel (-100), and the POSIX `realPath`
/// implementation resolves it via `readlink("/proc/self/fd/-100")`, which does
/// not exist — so the "obvious" call returns FileNotFound for every relative
/// input.
fn absoluteDirPath(alloc: std.mem.Allocator, io: std.Io, dir_path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(dir_path)) return std.fs.path.resolve(alloc, &.{dir_path});

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_len = try std.process.currentPath(io, &buffer);
    return std.fs.path.resolve(alloc, &.{ buffer[0..cwd_len], dir_path });
}

/// A pair is reusable only when BOTH halves exist as non-empty regular files.
/// Anything else (first run, crash between the two writes, a half-deleted
/// directory) regenerates both, which is cheap and always self-consistent.
fn reuseExistingPair(io: std.Io, cert_path: []const u8, key_path: []const u8) !bool {
    if (!try fileIsNonEmpty(io, cert_path)) return false;
    return fileIsNonEmpty(io, key_path);
}

fn fileIsNonEmpty(io: std.Io, path: []const u8) !bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        // Expected on the first run: "not there yet" is not an error here.
        error.FileNotFound => return false,
        else => |e| return e,
    };
    return stat.kind == .file and stat.size > 0;
}

// ===========================================================================
// Generation
// ===========================================================================

/// The freshly minted pair, both slices owned by `alloc`.
const Pems = struct {
    cert: []u8,
    key: []u8,
};

/// Build a self-signed EC P-256 / SHA-256 certificate and encode both halves
/// as PEM into `alloc`-owned buffers.
///
/// Every OpenSSL object is released by a `defer` before this function returns,
/// so a failure halfway through cannot leak a partially-built `X509`.
fn buildPems(alloc: std.mem.Allocator, io: std.Io, common_name: []const u8, days: u32) Error!Pems {
    // `EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")`: property query NULL, type
    // "EC", one variadic curve name. The variadic call is intentional — this is
    // the OpenSSL 3.x one-shot keygen entry point and the only signature the
    // EC curve argument is accepted by (there is no non-variadic twin).
    const pkey = EVP_PKEY_Q_keygen(null, null, "EC", "P-256") orelse return error.KeyGenerationFailed;
    defer EVP_PKEY_free(pkey);

    const x509 = X509_new() orelse return error.CertificateCreationFailed;
    defer X509_free(x509);

    // Version 2 == X.509 v3. SANs and the other v3 extensions below are only
    // legal in v3; leaving the version at the default v1 makes them silently
    // unencodable.
    if (X509_set_version(x509, 2) != 1) return error.CertificateCreationFailed;

    const serial = X509_get_serialNumber(x509) orelse return error.CertificateCreationFailed;
    // Random 31-bit serial. RFC 5280 §4.1.2.2 asks for entropy; a sequential
    // serial is a footgun the moment this certificate is fed to code that
    // assumes CA-like numbering. Bounded by i31 so it is unambiguously
    // positive in ASN.1 terms (a negative INTEGER would be malformed here).
    //
    // `io.random` (not `randomSecure`) is deliberate: a serial number is not
    // key material — it only needs to be non-sequential — so the infallible
    // path is preferable to plumbing an `EntropyUnavailable` error out of a
    // function whose job is "write me a certificate".
    var serial_bytes: [4]u8 = undefined;
    io.random(&serial_bytes);
    const serial_value = (@as(u32, @bitCast(serial_bytes)) & 0x7fff_ffff) | 1;
    if (ASN1_INTEGER_set(serial, @intCast(serial_value)) != 1) return error.CertificateCreationFailed;

    // notBefore = now, notAfter = now + days. Widen before multiplying so a
    // large `days` cannot wrap into a *shorter* validity than requested.
    const not_before = X509_getm_notBefore(x509) orelse return error.CertificateCreationFailed;
    if (X509_gmtime_adj(not_before, 0) == null) return error.CertificateCreationFailed;
    const not_after = X509_getm_notAfter(x509) orelse return error.CertificateCreationFailed;
    const validity_seconds: c_long = @intCast(@as(u64, days) * std.time.s_per_day);
    if (X509_gmtime_adj(not_after, validity_seconds) == null) return error.CertificateCreationFailed;

    // Subject == issuer == "CN=<common_name>": that identity is what makes the
    // certificate self-signed and what the client sees in a trust prompt.
    const name = X509_get_subject_name(x509) orelse return error.CertificateCreationFailed;
    if (X509_NAME_add_entry_by_txt(
        name,
        "CN",
        MBSTRING_UTF8,
        common_name.ptr,
        @intCast(common_name.len),
        X509_NAME_ADD_APPEND,
        0,
    ) != 1) return error.CertificateCreationFailed;
    if (X509_set_subject_name(x509, name) != 1) return error.CertificateCreationFailed;
    if (X509_set_issuer_name(x509, name) != 1) return error.CertificateCreationFailed;

    if (X509_set_pubkey(x509, pkey) != 1) return error.CertificateCreationFailed;

    // SANs come from the extension config string DSL — `NID_subject_alt_name`
    // is looked up by name rather than hardcoded, so an OpenSSL that renumbers
    // its NIDs cannot silently attach the SANs to the wrong extension.
    const san_nid = OBJ_txt2nid("subjectAltName");
    if (san_nid <= 0) return error.InvalidExtensionName;
    if (!try addExtension(x509, san_nid, san_list)) return error.SubjectAltNameExtensionFailed;

    for (extra_extensions) |ext| {
        const nid = OBJ_txt2nid(ext.name);
        if (nid <= 0) return error.InvalidExtensionName;
        if (!try addExtension(x509, nid, ext.value)) return error.ExtensionConfigFailed;
    }

    // SHA-256 over the tbsCertificate, signed with the EC key.
    if (X509_sign(x509, pkey, EVP_sha256()) == 0) return error.CertificateSignFailed;

    const cert_bio = BIO_new(BIO_s_mem()) orelse return error.CertificateEncodeFailed;
    defer _ = BIO_free(cert_bio);
    if (PEM_write_bio_X509(cert_bio, x509) != 1) return error.CertificateEncodeFailed;
    const cert_pem = readMemBio(alloc, cert_bio) catch |err| switch (err) {
        error.MemBioEmpty => return error.CertificateEncodeFailed,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer alloc.free(cert_pem);

    const key_bio = BIO_new(BIO_s_mem()) orelse return error.PrivateKeyEncodeFailed;
    defer _ = BIO_free(key_bio);
    // NULL cipher: the key is protected by the file mode, not a passphrase —
    // the server has to be able to read it unattended at startup.
    if (PEM_write_bio_PrivateKey(key_bio, pkey, null, null, 0, null, null) != 1)
        return error.PrivateKeyEncodeFailed;
    const key_pem = readMemBio(alloc, key_bio) catch |err| switch (err) {
        error.MemBioEmpty => return error.PrivateKeyEncodeFailed,
        error.OutOfMemory => return error.OutOfMemory,
    };

    return .{ .cert = cert_pem, .key = key_pem };
}

/// Attach one v3 extension described by OpenSSL's config-string DSL
/// (e.g. `"DNS:localhost,IP:127.0.0.1"`).
///
/// `X509_add_ext` takes a deep copy of the extension, so the temporary
/// `X509_EXTENSION` must be freed here — forgetting that leaks per extension.
fn addExtension(x509: *X509, nid: c_int, value: [*:0]const u8) Error!bool {
    const ext = X509V3_EXT_conf_nid(null, null, nid, value) orelse return false;
    defer X509_EXTENSION_free(ext);
    return X509_add_ext(x509, ext, X509_ADD_EXT_APPEND) == 1;
}

/// Copy the contents of a memory BIO into an `alloc`-owned buffer.
///
/// `BIO_get_mem_data` hands back a pointer into the BIO's *own* buffer, so the
/// bytes MUST be copied out before the BIO is freed.
fn readMemBio(alloc: std.mem.Allocator, bio: *BIO) (error{ MemBioEmpty, OutOfMemory })![]u8 {
    var data: [*]const u8 = undefined;
    const len = BIO_ctrl(bio, BIO_CTRL_INFO, 0, @ptrCast(&data));
    if (len <= 0) return error.MemBioEmpty;
    return alloc.dupe(u8, data[0..@intCast(len)]);
}

// ===========================================================================
// Filesystem plumbing
// ===========================================================================

fn writeFileWithMode(io: std.Io, path: []const u8, bytes: []const u8, mode: u32) !void {
    const permissions = permissionsFromMode(mode);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes,
        .flags = .{ .permissions = permissions },
    });

    // POSIX `open(2)` masks the requested mode with the process umask. The
    // umask can only *clear* bits, so 0600 cannot become group/other-readable
    // — but re-applying the mode explicitly makes the guarantee independent of
    // that reasoning, and documents the intent at the call site.
    if (comptime builtin.os.tag != .windows) {
        try std.Io.Dir.cwd().setFilePermissions(io, path, permissions, .{});
    }
}

/// POSIX mode → `std.Io.File.Permissions`.
///
/// The POSIX `Permissions` is an `enum(mode_t)` that is only constructible
/// through `fromMode`, and it does not exist on Windows at all, hence the
/// comptime split (the untaken branch is never analysed).
fn permissionsFromMode(mode: u32) std.Io.File.Permissions {
    if (comptime builtin.os.tag == .windows) return .default_file;
    return .fromMode(@intCast(mode));
}

// ============================================================================
// Tests — moved here from `tls_cert_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = tls_cert_tests; }` below pulls them into the run.
// ============================================================================

const tls_cert_tests = struct {
    // Tests for `tls_cert.zig`.
    //
    // The point of these tests is to prove the *bytes written to disk* are a real,
    // usable certificate — not that some OpenSSL call returned 1. Three
    // independent readings of the same file therefore have to agree:
    //
    //   1. Zig's own X.509 parser (`std.crypto.Certificate`) — proves real DER.
    //   2. Zig's own host-name matcher (`Parsed.verifyHostName`) — proves the SANs
    //      a webview actually checks are present and spelled correctly.
    //   3. OpenSSL's server-side loader (`SSL_CTX_use_certificate_chain_file` +
    //      `SSL_CTX_use_PrivateKey_file` + `SSL_CTX_check_private_key`) — proves the
    //      pair is acceptable to the library that will do the handshaking, and that
    //      the key matches the certificate.
    //
    // If the generator wrote a malformed DER, a mismatched key, or a certificate
    // that only OpenSSL tolerates, at least one of those three fails.

    const testing = std.testing;

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

        const key_mode_actual = (try std.Io.Dir.cwd().statFile(testing.io, paths.key_pem, .{})).permissions.toMode();
        try testing.expectEqual(@as(std.posix.mode_t, 0o600), key_mode_actual & 0o777);

        const cert_mode_actual = (try std.Io.Dir.cwd().statFile(testing.io, paths.cert_pem, .{})).permissions.toMode();
        try testing.expectEqual(@as(std.posix.mode_t, 0o644), cert_mode_actual & 0o777);

        const dir_mode_actual = (try std.Io.Dir.cwd().statFile(testing.io, dir, .{})).permissions.toMode();
        try testing.expectEqual(@as(std.posix.mode_t, 0o700), dir_mode_actual & 0o777);
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
};

comptime {
    _ = tls_cert_tests;
}
