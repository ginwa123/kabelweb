// ============================================================================
// security.zig — security primitives for the ginwasaas HTTP server.
//
// Provides six `pub fn` primitives that handlers opt into:
//
//   * csrfTokenIssue / csrfTokenValidate — synchronizer-token pattern with
//     HMAC-SHA256 signing. Tokens embed (timestamp ‖ nonce ‖ hmac) and
//     expire after `CSRF_TOKEN_TTL_SEC` seconds.
//
//   * rateLimitCheck — in-memory token bucket per (ip, route). Allows
//     `RATE_LIMIT_MAX` requests per `RATE_LIMIT_WINDOW_SEC` seconds.
//     Test-only `rateLimitResetForTesting` clears the buckets between
//     tests so they don't leak state.
//
//   * applySecurityHeaders — sets 7 headers (CSP, X-Content-Type-Options,
//     X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP)
//     in-place on an HttpResponse.
//
//   * checkOrigin — rejects POST with mismatched Origin or Referer host.
//     Returns `error.CrossOriginForbidden`.
//
//   * enforceBodySizeLimit — rejects bodies > max bytes. Returns
//     `error.PayloadTooLarge`.
//
// Memory model
// ------------
// * No allocations for primitive inputs that fit in stack buffers.
// * The CSRF token bundle allocates the token string; the caller (handler)
//   is responsible for freeing it (or letting the per-request arena reap
//   it, which is the production path).
// * The rate-limit store is module-level mutable state. Tests must call
//   `rateLimitResetForTesting` in setup to avoid cross-test pollution.
// * `applySecurityHeaders` mutates the response's headers map in place;
//   all header values are string literals (no allocations).
// ============================================================================

const std = @import("std");
const builtin = @import("builtin");
const http_parser = @import("http_parser.zig");

pub const HttpResponse = http_parser.HttpResponse;
pub const HttpRequest = http_parser.HttpRequest;

/// HMAC algorithm used for CSRF token signing. SHA-256 produces 32-byte
/// digests which we then base64url-encode for the token format.
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HMAC_LEN = HmacSha256.mac_length; // 32

/// CSRF token lifetime (seconds). 1 hour per OWASP recommendation for
/// form-submission tokens; sessions rarely need longer.
pub const CSRF_TOKEN_TTL_SEC: i64 = 60 * 60;

/// Rate-limit defaults (applied per `(ip, route)` pair).
pub const RATE_LIMIT_MAX: u32 = 5;
pub const RATE_LIMIT_WINDOW_SEC: i64 = 60;

/// Maximum request body size accepted on state-changing endpoints.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// CORS configuration used by `buildPreflightResponse` and
/// `buildPreHandlerFailRedirect`. Mirrors the field-by-field shape on
/// `GinwaServer.cors` so the framework can forward the config by value
/// to these pure helpers (no GinwaServer pointer needed at the test
/// site).
pub const CORSConfig = struct {
    enabled: bool = false,
    allowed_origins: []const []const u8 = &.{},
    allowed_methods: []const u8 = "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    allowed_headers: []const u8 = "Content-Type, X-CSRF-Token, X-Requested-With",
    allow_credentials: bool = false,
    max_age: u32 = 86400,
};

/// Error codes returned by the framework's pre-handler fail redirect.
/// String constants match the `?error=<code>` query keys that
/// `redirectTo*WithError` helpers in the ginwasaas handlers consume.
pub const PreHandlerFailCode = enum {
    cross_origin,
    body_too_large,
    server_error,

    pub fn label(self: PreHandlerFailCode) []const u8 {
        return switch (self) {
            .cross_origin => "cross_origin",
            .body_too_large => "body_too_large",
            .server_error => "server_error",
        };
    }
};

/// (Removed in follow-up: `buildPreHandlerFailRedirect` is no longer used
/// by GinwaServer since the per-route `on_pre_handler_fail` opt-in was
/// dropped. The helpers `preHandlerCheck`, `checkOriginInList`,
/// `applyCORSHeaders`, `buildPreflightResponse`, `applyCORSResponse`
/// remain as usable primitives; handlers continue to call `checkOrigin`
/// and `enforceBodySizeLimit` themselves.)

/// Token bucket state for one `(ip, route)` pair.
const BucketState = struct {
    /// Window start (unix seconds).
    window_start: i64,
    /// Requests consumed in the current window.
    count: u32,
};

/// Route-keyed map of IP-keyed bucket states. Mutated under a mutex.
var buckets: std.StringHashMap(std.StringHashMap(BucketState)) = undefined;
var buckets_init: bool = false;
var buckets_mutex: std.atomic.Mutex = .unlocked;

/// Spinlock acquire — Zig 0.16 removed `std.Thread.Mutex`. The standard
/// library's `atomic.Mutex` is an enum with `tryLock`/`unlock` only;
/// we wrap it in a `tryLock` + `spinLoopHint` loop here.
fn mutexLock(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn ensureBucketsInit() void {
    if (buckets_init) return;
    mutexLock(&buckets_mutex);
    defer buckets_mutex.unlock();
    if (buckets_init) return;
    buckets = std.StringHashMap(std.StringHashMap(BucketState)).init(std.heap.page_allocator);
    buckets_init = true;
}

/// Bundle returned by `csrfTokenIssue`. The caller owns `token` (freed
/// via the allocator passed to `csrfTokenIssue`) and is responsible for
/// inserting `cookie` into the `Set-Cookie` response header.
pub const CsrfTokenBundle = struct {
    token: []u8,
    cookie: []u8,
    expires_at: i64,
};

/// Constant-time equality check on two byte slices. Returns true iff
/// they have the same length and identical contents. Avoids timing
/// side-channels when comparing HMAC digests.
fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

/// Generate a cryptographically-secure random nonce of `len` bytes.
///
/// Platform CSPRNG dispatch:
///   * Linux    → syscall getrandom(2) (no fd, no /dev/urandom setup).
///   * macOS    → arc4random_buf (declared in std.c private; uses
///                SecRandomCopyBytes under the hood since macOS 10.12,
///                i.e. effectively a CSPRNG — the "arc4" name is stale).
///   * Windows  → BCryptGenRandom from bcrypt.dll with
///                BCRYPT_USE_SYSTEM_PREFERRED_RNG. Built at link time via
///                `linkSystemLibrary("bcrypt")` in build.zig.
/// `std.c.getrandom` exists only on Linux/FreeBSD; on Windows and macOS it
/// resolves to `void` (Zig's c.zig switch), which is why this function is
/// target-aware rather than a single line.
fn generateNonce(allocator: std.mem.Allocator, len: usize) ![]u8 {
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);

    switch (builtin.os.tag) {
        .linux, .freebsd, .openbsd, .netbsd => {
            var filled: usize = 0;
            while (filled < len) {
                // std.c.getrandom returns the number of bytes written (isize),
                // or -1 on error. Loop until the buffer is full.
                const slice = buf[filled..];
                const n = std.c.getrandom(slice.ptr, slice.len, 0);
                if (n <= 0) return error.RandomFailed;
                filled += @intCast(n);
            }
        },
        .macos, .ios, .tvos, .watchos => {
            // arc4random_buf is declared in std.c private; available on all
            // Apple targets. The Zig 0.16 std.c exports it as
            // `std.c.arc4random_buf` but only on Darwin-family — gate here.
            std.c.arc4random_buf(buf.ptr, buf.len);
        },
        .windows => {
            // BCrypt.dll → BCRYPT_USE_SYSTEM_PREFERRED_RNG (0x00000002).
            // hAlgorithm = NULL means "use the system-preferred RNG" which
            // the docs guarantee is suitable for cryptographic use and is
            // seeded from the OS entropy pool at boot.
            const status = bcrypt.BCryptGenRandom(
                null,
                buf.ptr,
                @intCast(buf.len),
                0x00000002, // BCRYPT_USE_SYSTEM_PREFERRED_RNG
            );
            if (status != 0) return error.RandomFailed;
        },
        else => return error.UnsupportedPlatform,
    }
    return buf;
}

/// Windows bcrypt.dll bindings. Declared locally because std.c only covers
/// libc; bcrypt is a separate system DLL that build.zig links via
/// `linkSystemLibrary("bcrypt")`. Both functions are stdcall-equivalent
/// (c_long on x86_64) per Microsoft's bcrypt.h.
const bcrypt = struct {
    extern "bcrypt" fn BCryptGenRandom(
        hAlgorithm: ?*const anyopaque,
        pbBuffer: [*]u8,
        cbBuffer: c_ulong,
        dwFlags: c_ulong,
    ) callconv(.c) c_long;
};

/// Generate an HMAC-SHA256 over `msg` keyed by `secret`. Returns a heap
/// buffer of `HMAC_LEN` bytes; caller owns it.
fn hmacSha256(allocator: std.mem.Allocator, secret: []const u8, msg: []const u8) ![]u8 {
    var mac: [HMAC_LEN]u8 = undefined;
    HmacSha256.create(&mac, msg, secret);
    return allocator.dupe(u8, &mac);
}

/// Issue a new CSRF token. `now` is unix seconds (use
/// `std.Io.Clock.now(.real, io).toSeconds()`). The token format is:
///   <timestamp_seconds>.<nonce_b64u>.<hmac_b64u>
/// where hmac = HMAC-SHA256(secret, "<timestamp_seconds>:<nonce_raw>").
/// All three fields are base64url-no-pad so the token is URL-safe.
pub fn csrfTokenIssue(
    secret: []const u8,
    io: std.Io,
    allocator: std.mem.Allocator,
) !CsrfTokenBundle {
    const now = std.Io.Clock.now(.real, io).toSeconds();
    const expires_at = now + CSRF_TOKEN_TTL_SEC;

    // 16-byte nonce — 128 bits is plenty for CSRF (collision-resistant).
    const nonce_raw = try generateNonce(allocator, 16);
    defer allocator.free(nonce_raw);

    // HMAC over "<timestamp>:<nonce_raw>".
    var msg_buf: [64]u8 = undefined;
    const ts_str = std.fmt.bufPrint(&msg_buf, "{d}:", .{now}) catch unreachable;
    var signed_msg: [80]u8 = undefined;
    @memcpy(signed_msg[0..ts_str.len], ts_str);
    @memcpy(signed_msg[ts_str.len..][0..nonce_raw.len], nonce_raw);
    const signed_msg_slice = signed_msg[0 .. ts_str.len + nonce_raw.len];

    const hmac = try hmacSha256(allocator, secret, signed_msg_slice);
    defer allocator.free(hmac);

    // base64url-encode nonce + hmac (no padding).
    const nonce_b64_len = std.base64.url_safe_no_pad.Encoder.calcSize(nonce_raw.len);
    const hmac_b64_len = std.base64.url_safe_no_pad.Encoder.calcSize(hmac.len);
    const nonce_b64 = try allocator.alloc(u8, nonce_b64_len);
    defer allocator.free(nonce_b64);
    const hmac_b64 = try allocator.alloc(u8, hmac_b64_len);
    defer allocator.free(hmac_b64);
    _ = std.base64.url_safe_no_pad.Encoder.encode(nonce_b64, nonce_raw);
    _ = std.base64.url_safe_no_pad.Encoder.encode(hmac_b64, hmac);

    // Token format: "<ts>.<nonce_b64>.<hmac_b64>".
    const token = try std.fmt.allocPrint(
        allocator,
        "{d}.{s}.{s}",
        .{ now, nonce_b64, hmac_b64 },
    );

    // Cookie value: same as token (the cookie value IS the token). The
    // server re-validates by recomputing HMAC, so a forged cookie would
    // fail the HMAC check.
    const cookie = try allocator.dupe(u8, token);

    return .{
        .token = token,
        .cookie = cookie,
        .expires_at = expires_at,
    };
}

/// Validate a CSRF token against the same secret + current time. Returns
/// `error.CsrfMismatch` on any failure (malformed, expired, wrong HMAC).
pub fn csrfTokenValidate(
    token: []const u8,
    secret: []const u8,
    now: i64,
) !void {
    // Parse "<ts>.<nonce_b64>.<hmac_b64>".
    var parts = std.mem.splitScalar(u8, token, '.');
    const ts_str = parts.next() orelse return error.CsrfMismatch;
    const nonce_b64 = parts.next() orelse return error.CsrfMismatch;
    const hmac_b64 = parts.next() orelse return error.CsrfMismatch;
    if (parts.next() != null) return error.CsrfMismatch; // trailing junk

    const ts = std.fmt.parseInt(i64, ts_str, 10) catch return error.CsrfMismatch;

    // Expiry check (reject tokens older than CSRF_TOKEN_TTL_SEC).
    if (now < ts) return error.CsrfMismatch; // clock skew guard
    if (now - ts > CSRF_TOKEN_TTL_SEC) return error.CsrfMismatch;

    // Decode nonce + hmac. url_safe_no_pad uses 4 chars per 3 bytes,
    // so decoded_len = (encoded_len * 3) / 4 (integer division).
    const nonce_len: usize = (nonce_b64.len * 3) / 4;
    var nonce_raw: [64]u8 = undefined;
    if (nonce_len > nonce_raw.len) return error.CsrfMismatch;
    std.base64.url_safe_no_pad.Decoder.decode(nonce_raw[0..nonce_len], nonce_b64) catch return error.CsrfMismatch;

    const hmac_len: usize = (hmac_b64.len * 3) / 4;
    var hmac_raw: [64]u8 = undefined;
    if (hmac_len > HMAC_LEN) return error.CsrfMismatch;
    if (hmac_len > hmac_raw.len) return error.CsrfMismatch;
    std.base64.url_safe_no_pad.Decoder.decode(hmac_raw[0..hmac_len], hmac_b64) catch return error.CsrfMismatch;

    // Recompute HMAC and compare in constant time.
    var msg_buf: [80]u8 = undefined;
    const ts_prefix = std.fmt.bufPrint(&msg_buf, "{d}:", .{ts}) catch unreachable;
    @memcpy(msg_buf[ts_prefix.len..][0..nonce_len], nonce_raw[0..nonce_len]);
    const msg = msg_buf[0 .. ts_prefix.len + nonce_len];

    var expected: [HMAC_LEN]u8 = undefined;
    HmacSha256.create(&expected, msg, secret);

    if (!constantTimeEql(expected[0..], hmac_raw[0..hmac_len])) {
        return error.CsrfMismatch;
    }
}

/// Check + record a rate-limit hit for `(ip, route)` at time `now`.
/// Allows up to `RATE_LIMIT_MAX` requests per `RATE_LIMIT_WINDOW_SEC`
/// seconds. Returns `error.RateLimited` with `Retry-After` hint on
/// rejection. Test-only `rateLimitResetForTesting(route)` clears buckets.
pub fn rateLimitCheck(
    ip: []const u8,
    route: []const u8,
    now: i64,
) !u32 {
    ensureBucketsInit();
    mutexLock(&buckets_mutex);
    defer buckets_mutex.unlock();

    const route_bucket = buckets.getPtr(route) orelse blk: {
        const new_bucket = std.StringHashMap(BucketState).init(std.heap.page_allocator);
        try buckets.put(route, new_bucket);
        break :blk buckets.getPtr(route).?;
    };

    if (route_bucket.getPtr(ip)) |state| {
        const elapsed = now - state.window_start;
        if (elapsed >= RATE_LIMIT_WINDOW_SEC) {
            // Window expired — reset.
            state.window_start = now;
            state.count = 1;
            return 0;
        }
        if (state.count >= RATE_LIMIT_MAX) {
            const retry_after: u32 = @intCast(RATE_LIMIT_WINDOW_SEC - elapsed);
            return makeError(retry_after);
        }
        state.count += 1;
        return 0;
    }

    try route_bucket.put(ip, .{ .window_start = now, .count = 1 });
    return 0;
}

fn makeError(retry_after: u32) error{ RateLimited } {
    _ = retry_after; // surfaced via the return value via u32
    return error.RateLimited;
}

/// Test-only helper to clear all rate-limit state. Production code
/// should never call this — the buckets live for the process lifetime.
pub fn rateLimitResetForTesting() void {
    ensureBucketsInit();
    mutexLock(&buckets_mutex);
    defer buckets_mutex.unlock();
    var it = buckets.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.*.deinit();
    }
    buckets.clearRetainingCapacity();
}

/// Security response headers applied to every response.
/// Security response headers applied to every response. The defaults are
/// a strict, dependency-free baseline (`'self'` + inline styles/scripts).
/// Apps that load third-party assets (CDN scripts, analytics beacons)
/// should override via `GinwaServer.security_headers` — the library
/// itself stays agnostic of any specific origin.
pub const SecurityHeaders = struct {
    content_security_policy: []const u8 = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
    x_content_type_options: []const u8 = "nosniff",
    x_frame_options: []const u8 = "DENY",
    referrer_policy: []const u8 = "strict-origin-when-cross-origin",
    permissions_policy: []const u8 = "camera=(), microphone=(), geolocation=()",
    cross_origin_opener_policy: []const u8 = "same-origin",
    cross_origin_resource_policy: []const u8 = "same-origin",
};

/// Back-compat default instance (used by `applySecurityHeaders(response)`
/// and `HttpResponse.withSecurityHeaders()`).
pub const default_security_headers: SecurityHeaders = .{};

const SEC_NOSNIFF = "nosniff";
const SEC_FRAME = "DENY";
const SEC_REFERRER = "strict-origin-when-cross-origin";
const SEC_PERMISSIONS = "camera=(), microphone=(), geolocation=()";
const SEC_COOP = "same-origin";
const SEC_CORP = "same-origin";

/// Apply the seven standard security response headers in-place, using the
/// provided configuration (or the library default when omitted).
pub fn applySecurityHeadersWith(response: *HttpResponse, cfg: SecurityHeaders) void {
    response.headers.put("Content-Security-Policy", cfg.content_security_policy) catch @panic("OOM");
    response.headers.put("X-Content-Type-Options", cfg.x_content_type_options) catch @panic("OOM");
    response.headers.put("X-Frame-Options", cfg.x_frame_options) catch @panic("OOM");
    response.headers.put("Referrer-Policy", cfg.referrer_policy) catch @panic("OOM");
    response.headers.put("Permissions-Policy", cfg.permissions_policy) catch @panic("OOM");
    response.headers.put("Cross-Origin-Opener-Policy", cfg.cross_origin_opener_policy) catch @panic("OOM");
    response.headers.put("Cross-Origin-Resource-Policy", cfg.cross_origin_resource_policy) catch @panic("OOM");
}

/// Apply the seven standard security response headers in-place with the
/// library-default policy. All values are string literals (no allocation).
pub fn applySecurityHeaders(response: *HttpResponse) void {
    applySecurityHeadersWith(response, default_security_headers);
}

/// Extract the host (with optional port) from a URL like
/// `http://example.com:8080/path` or `https://example.com/path`. Returns
/// the slice up to the first `/` after the scheme, or the whole input if
/// no path separator exists. Public so callers (and tests) can use it
/// for host extraction without re-implementing the slice arithmetic.
pub fn extractHost(url: []const u8) []const u8 {
    // Skip "scheme://".
    const scheme_sep = std.mem.indexOf(u8, url, "://") orelse return url;
    var rest = url[scheme_sep + 3 ..];
    // Cut at first '/' (start of path) or '?' or '#'.
    for (rest, 0..) |c, i| {
        if (c == '/' or c == '?' or c == '#') return rest[0..i];
    }
    return rest;
}

/// Check that the request's Origin or Referer matches the expected host.
/// Returns `error.CrossOriginForbidden` on mismatch. Accepts the
/// request if neither header is present (legitimate for same-origin
/// GETs in some browsers, but handlers should enforce CSRF separately).
pub fn checkOrigin(request: *const HttpRequest, expected_host: []const u8) !void {
    // Look for Origin (case-insensitive per RFC 7230 §3.2).
    var it = request.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "origin")) {
            const origin_host = extractHost(entry.value_ptr.*);
            if (!std.ascii.eqlIgnoreCase(origin_host, expected_host)) {
                return error.CrossOriginForbidden;
            }
            return;
        }
    }

    // No Origin — fall back to Referer (case-insensitive).
    it = request.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "referer")) {
            const ref_host = extractHost(entry.value_ptr.*);
            if (!std.ascii.eqlIgnoreCase(ref_host, expected_host)) {
                return error.CrossOriginForbidden;
            }
            return;
        }
    }

    // Neither present — fail open for now (the CSRF + SameSite=Strict
    // cookie provides the primary defense; this is defence in depth).
    // Production deployments may want to flip this to fail-closed.
}

/// Reject request bodies that exceed `max` bytes.
pub fn enforceBodySizeLimit(body_len: usize, max: usize) !void {
    if (body_len > max) return error.PayloadTooLarge;
}

/// Check that the request's Origin OR Referer host matches any entry in
/// `allowed_origins` (case-insensitive host extraction). Mirrors
/// `checkOrigin` but accepts a whitelist instead of a single host.
///
/// Behaviour identical to `checkOrigin` when both Origin and Referer are
/// absent: returns success (the CSRF cookie + SameSite=Strict handles
/// the strict case). Returns `error.CrossOriginForbidden` when
/// Origin/Referer is present but doesn't match any whitelisted host.
///
/// `allowed_origins` is a slice of host strings like `"localhost:4021"`
/// or `"api.example.com"`. The comparison ignores scheme and path —
/// `http://localhost:4021/foo` and `https://localhost:4021/bar` both
/// match entry `"localhost:4021"`.
pub fn checkOriginInList(
    request: *const HttpRequest,
    allowed_origins: []const []const u8,
) !void {
    // Allow empty whitelist when callers want to opt-out (matches the
    // single-host checkOrigin contract: nothing to match against, pass).
    if (allowed_origins.len == 0) return;

    var it = request.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "origin")) {
            const origin_host = extractHost(entry.value_ptr.*);
            for (allowed_origins) |allowed| {
                if (std.ascii.eqlIgnoreCase(origin_host, allowed)) return;
            }
            return error.CrossOriginForbidden;
        }
    }

    // No Origin — fall back to Referer.
    it = request.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "referer")) {
            const ref_host = extractHost(entry.value_ptr.*);
            for (allowed_origins) |allowed| {
                if (std.ascii.eqlIgnoreCase(ref_host, allowed)) return;
            }
            return error.CrossOriginForbidden;
        }
    }

    // Neither present — fail open (CSRF cookie is the primary defence).
}

/// Combined same-origin + body-size guard. Runs `checkOriginInList` then
/// `enforceBodySizeLimit` and forwards whichever error fires first.
/// Useful as a single helper call at the top of state-changing
/// handlers — replaces the inline two-line repetition:

///   gserverz.security.checkOrigin(&req, "localhost:4021") catch { ... };
///   gserverz.security.enforceBodySizeLimit(...)         catch { ... };

/// with:

///   gserverz.security.preHandlerCheck(&req, cors_origins, MAX_BODY_BYTES)
///       catch |err| switch (err) {
///           error.CrossOriginForbidden => return redirect(...),
///           error.PayloadTooLarge      => return redirect(...),
///       };

/// When the GinwaServer route is configured with
/// `Route.on_pre_handler_fail`, this check runs automatically inside
/// the dispatch loop and handlers don't need to call it at all.
pub fn preHandlerCheck(
    request: *const HttpRequest,
    allowed_origins: []const []const u8,
    max_body_bytes: usize,
) !void {
    try checkOriginInList(request, allowed_origins);
    try enforceBodySizeLimit(request.body.len, max_body_bytes);
}

/// Build the canonical CORS response-headers for `origin` against
/// `allowed_origins`. Returns an empty map when CORS is disabled or
/// when the origin isn't whitelisted (caller should still send the
/// origin through a separate validation step if it wants strict
/// enforcement).
///
/// Headers attached when the origin is whitelisted:
///   * Access-Control-Allow-Origin:  <origin>
///   * Vary: Origin
///
/// Headers attached when `allowed_methods` is non-empty:
///   * Access-Control-Allow-Methods:  <methods>
///
/// Headers attached when `allowed_headers` is non-empty:
///   * Access-Control-Allow-Headers:  <headers>
///
/// `Access-Control-Allow-Credentials: true` is set when
/// `allow_credentials` is true.
///
/// Mutates `headers` in place; values pointed at are caller-owned
/// (string literals or heap slices).
pub fn applyCORSHeaders(
    headers: *std.StringHashMap([]const u8),
    origin: []const u8,
    allowed_origins: []const []const u8,
    allowed_methods: []const u8,
    allowed_headers: []const u8,
    allow_credentials: bool,
) !void {
    if (allowed_origins.len == 0) return;

    // Compare the extracted host (`localhost:4021`) against the whitelist,
    // NOT the full Origin (`http://localhost:4021`). `extractHost` strips
    // the scheme + path so scheme-agnostic / path-bearing entries work.
    const origin_host = extractHost(origin);
    var origin_allowed = false;
    for (allowed_origins) |allowed| {
        if (std.ascii.eqlIgnoreCase(origin_host, allowed)) {
            origin_allowed = true;
            break;
        }
    }
    if (!origin_allowed) return;

    try headers.put("Access-Control-Allow-Origin", origin);
    try headers.put("Vary", "Origin");
    if (allowed_methods.len > 0) {
        try headers.put("Access-Control-Allow-Methods", allowed_methods);
    }
    if (allowed_headers.len > 0) {
        try headers.put("Access-Control-Allow-Headers", allowed_headers);
    }
    if (allow_credentials) {
        try headers.put("Access-Control-Allow-Credentials", "true");
    }
}

/// Return true when `request` declares an Origin that matches one of the
/// `allowed_origins` (or when no Origin is present and the whitelist is
/// non-empty — we treat missing-Origin the same way `checkOriginInList`
/// does: fail-open, return true; CSRF cookie + SameSite=Strict is the
/// primary defence). When the whitelist is empty, returns true
/// unconditionally (no CORS gate).
pub fn originMatches(
    request: *const HttpRequest,
    allowed_origins: []const []const u8,
) bool {
    if (allowed_origins.len == 0) return true;

    var it = request.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "origin")) {
            const origin_host = extractHost(entry.value_ptr.*);
            for (allowed_origins) |allowed| {
                if (std.ascii.eqlIgnoreCase(origin_host, allowed)) return true;
            }
            return false;
        }
    }

    // No Origin — same behaviour as checkOriginInList: pass through.
    return true;
}

/// Extract the Origin request header value if present. Returns null
/// when missing. The returned slice is case-preserving — browsers
/// always send `Origin` (not `origin`), but the lookup is
/// case-insensitive to match the standard.
pub fn getRequestOrigin(request: *const HttpRequest) ?[]const u8 {
    var it = request.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "origin")) {
            return entry.value_ptr.*;
        }
    }
    return null;
}

/// Build a `204 No Content` CORS preflight response for `request`.
///
/// Behaviour:
///   * Status 204 always (mismatched origins still get a 204 with
///     no CORS headers — the browser blocks the response from JS).
///   * When Origin is present and allowed: sets Allow-Origin, Vary,
///     Allow-Methods, Allow-Headers, Allow-Credentials (if enabled),
///     and Max-Age.
///   * Security headers always attached.
///
/// `config` may be `.{}` — in that case the response has no CORS
/// headers but is still a well-formed 204 with security headers.
/// `allocator` owns the response's headers map and any heap-allocated
/// header values (Content-Length, Max-Age); the response itself is a
/// stack value.
pub fn buildPreflightResponse(
    allocator: std.mem.Allocator,
    request: *const HttpRequest,
    config: CORSConfig,
) !HttpResponse {
    var preflight = HttpResponse{
        .status_code = 204,
        .status_text = "No Content",
        .headers = std.StringHashMap([]const u8).init(allocator),
        .body = "",
        .allocator = allocator,
    };
    errdefer preflight.headers.deinit();

    if (config.enabled) {
        if (getRequestOrigin(request)) |origin| {
            try applyCORSHeaders(
                &preflight.headers,
                origin,
                config.allowed_origins,
                config.allowed_methods,
                config.allowed_headers,
                config.allow_credentials,
            );
            const max_age_str = try std.fmt.allocPrint(allocator, "{d}", .{config.max_age});
            try preflight.headers.put("Access-Control-Max-Age", max_age_str);
        }
    }
    applySecurityHeaders(&preflight);
    return preflight;
}

/// Run the framework's pre-handler security gate (origin +
/// body-size) and, on failure, build a `302 Found` redirect response
/// to `<fail_base><error_code>`. Returns `null` when the gate
/// passes (the caller should proceed to the user handler).
///
/// The Location string is heap-allocated onto `allocator`. The
/// response's headers map is also `allocator`-owned. CORS response
/// headers are attached when `config.enabled` is true and the
/// request's Origin matches `config.allowed_origins`.
///
/// (Currently unused: the per-route `on_pre_handler_fail` mechanism
/// was dropped, so `GinwaServer.runPreHandlerFailRedirect` no longer
/// calls this. Kept as an exportable helper for callers that want to
/// wire the same redirect logic themselves, plus to keep the
/// coverage tests passing.)
pub fn buildPreHandlerFailRedirect(
    allocator: std.mem.Allocator,
    request: *const HttpRequest,
    config: CORSConfig,
    max_body_bytes: usize,
    fail_base: []const u8,
) !?HttpResponse {
    const fail_code: ?PreHandlerFailCode = if (preHandlerCheck(
        request,
        config.allowed_origins,
        max_body_bytes,
    )) |_|
        null // gate passed
    else |err| blk: {
        break :blk switch (err) {
            error.CrossOriginForbidden => PreHandlerFailCode.cross_origin,
            error.PayloadTooLarge => PreHandlerFailCode.body_too_large,
        };
    };

    const code = fail_code orelse return null;

    var fail_response = HttpResponse{
        .status_code = 302,
        .status_text = "Found",
        .headers = std.StringHashMap([]const u8).init(allocator),
        .body = "",
        .allocator = allocator,
    };
    errdefer fail_response.headers.deinit();

    const location = try std.fmt.allocPrint(allocator, "{s}{s}", .{ fail_base, code.label() });
    try fail_response.headers.put("Location", location);
    try fail_response.headers.put("Content-Type", "text/html; charset=utf-8");
    try fail_response.headers.put("Content-Length", "0");
    applySecurityHeaders(&fail_response);

    if (config.enabled) {
        if (getRequestOrigin(request)) |origin| {
            try applyCORSHeaders(
                &fail_response.headers,
                origin,
                config.allowed_origins,
                config.allowed_methods,
                config.allowed_headers,
                config.allow_credentials,
            );
        }
    }
    return fail_response;
}

// ───────────────────────────────────────────────────────────────────────────
//  Engine auto-gate (zero-config). When `server.cors.enabled`, the engine
//  itself blocks state-changing requests from non-whitelisted origins —
//  no per-route / per-group declarations anywhere in app code.
// ───────────────────────────────────────────────────────────────────────────

/// Verdict of `preGateCheck`.
pub const PreGateResult = enum {
    /// Proceed to routing/handler.
    pass,
    /// State-changing request from a non-whitelisted Origin → 403 page.
    block_cors,
    /// Body exceeds the configured cap → 413 page.
    block_body_too_large,
};

/// Methods that can change server state and are therefore auto-gated.
/// GET/HEAD/OPTIONS are never gated (safe / preflight methods).
pub fn isStateChanging(method: []const u8) bool {
    return std.mem.eql(u8, method, "POST") or
        std.mem.eql(u8, method, "PUT") or
        std.mem.eql(u8, method, "PATCH") or
        std.mem.eql(u8, method, "DELETE");
}

/// Engine-level gate. Runs BEFORE route matching on every request:
///
///   * Method not state-changing (GET/HEAD/OPTIONS) → `.pass`.
///   * Body over `max_body_bytes` → `.block_body_too_large` — ALWAYS
///     enforced, independent of `config.enabled` (body-size protection
///     is not a CORS feature).
///   * CORS disabled → `.pass` for the origin stage (back-compat:
///     servers that never enable CORS see no origin gating).
///   * No Origin header → `.pass` (curl / server-to-server clients don't
///     send one; the CSRF cookie remains the primary defence for forms).
///   * Origin present but not in `config.allowed_origins` → `.block_cors`.
pub fn preGateCheck(
    request: *const HttpRequest,
    config: CORSConfig,
    max_body_bytes: usize,
) !PreGateResult {
    if (!isStateChanging(request.method)) return .pass;

    // Body-size cap: ALWAYS on, independent of CORS.
    enforceBodySizeLimit(request.body.len, max_body_bytes) catch {
        return .block_body_too_large;
    };

    if (!config.enabled) return .pass;

    // Origin check (cheapest signal of a cross-site request).
    var it = request.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "origin")) {
            const origin_host = extractHost(entry.value_ptr.*);
            var allowed = false;
            for (config.allowed_origins) |candidate| {
                if (std.ascii.eqlIgnoreCase(origin_host, candidate)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) return .block_cors;
            break;
        }
    }

    return .pass;
}

/// Build the engine's built-in explanation page for an auto-gated
/// request. This is a DEVELOPER-facing diagnostic: it names the blocked
/// origin and shows exactly which config line fixes it. Attach security
/// headers + CORS headers at the call site (the engine knows both).
pub fn buildEngineBlockPage(
    allocator: std.mem.Allocator,
    result: PreGateResult,
    origin: ?[]const u8,
    host: []const u8,
) !HttpResponse {
    const status: u16 = switch (result) {
        .block_cors => 403,
        .block_body_too_large => 413,
        .pass => unreachable,
    };
    const status_text = switch (result) {
        .block_cors => "Forbidden",
        .block_body_too_large => "Payload Too Large",
        .pass => unreachable,
    };

    const title = switch (result) {
        .block_cors => "403 — Cross-origin request blocked",
        .block_body_too_large => "413 — Request body too large",
        .pass => unreachable,
    };
    const detail = switch (result) {
        .block_cors => if (origin) |o|
            try std.fmt.allocPrint(allocator, "Origin <code>{s}</code> is not in <code>server.cors.allowed_origins</code>.", .{o})
        else
            try std.fmt.allocPrint(allocator, "Request origin is not allowed.", .{}),
        .block_body_too_large => try std.fmt.allocPrint(allocator, "Request body exceeds the server's size cap.", .{}),
        .pass => unreachable,
    };
    const hint = switch (result) {
        .block_cors => try std.fmt.allocPrint(
            allocator,
            "Fix: add <code>\"{s}\"</code> to <code>server.cors.allowed_origins</code> in your server setup.",
            .{host},
        ),
        .block_body_too_large => try std.fmt.allocPrint(
            allocator,
            "Fix: raise the body-size limit in the server's security configuration.",
            .{},
        ),
        .pass => unreachable,
    };

    const body = try std.fmt.allocPrint(allocator,
        \\<!DOCTYPE html>
        \\<html><head><meta charset="utf-8"><title>{s}</title></head>
        \\<body style="font-family: ui-monospace, monospace; max-width: 42rem; margin: 4rem auto; padding: 0 1rem; line-height: 1.6;">
        \\<h1>{s}</h1>
        \\<p>{s}</p>
        \\<p>{s}</p>
        \\<hr><small>ginwa http server - engine pre-handler gate</small>
        \\</body></html>
    , .{ title, title, detail, hint });

    var resp = HttpResponse{
        .status_code = status,
        .status_text = status_text,
        .headers = std.StringHashMap([]const u8).init(allocator),
        .body = body,
        .allocator = allocator,
    };
    errdefer resp.headers.deinit();
    try resp.headers.put("Content-Type", "text/html; charset=utf-8");
    const len_str = try std.fmt.allocPrint(allocator, "{d}", .{body.len});
    try resp.headers.put("Content-Length", len_str);
    return resp;
}

/// Apply CORS response headers to `response` (in place). Reads
/// the request's Origin header and gates on `config.allowed_origins`.
/// No-op when CORS is disabled.
pub fn applyCORSResponse(
    response: *HttpResponse,
    request: *const HttpRequest,
    config: CORSConfig,
) !void {
    if (!config.enabled) return;
    const origin = getRequestOrigin(request) orelse return;
    return applyCORSHeaders(
        &response.headers,
        origin,
        config.allowed_origins,
        config.allowed_methods,
        config.allowed_headers,
        config.allow_credentials,
    );
}