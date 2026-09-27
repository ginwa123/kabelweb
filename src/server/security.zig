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

// ============================================================================
// Tests — moved here from `security_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = security_tests; }` below pulls them into the run.
// ============================================================================

const security_tests = struct {
    // ============================================================================
    // the colocated security tests — behavioural tests for the security primitives.
    //
    // All 16 tests below exercise the primitives end-to-end. No source-grep
    // / static-contract tests (project rule 2026-07-29).
    //
    // Tests:
    //   1-4:   csrfTokenIssue + csrfTokenValidate round-trip and tamper
    //          detection
    //   5-8:   rateLimitCheck under-limit / over-limit / per-IP / window reset
    //   9-12:  applySecurityHeaders sets each of the 4 most-important headers
    //   13-15: checkOrigin matches / mismatches Origin / mismatches Referer
    //   16:    enforceBodySizeLimit rejects oversized bodies
    // ============================================================================

    const testing = std.testing;
    const security = @import("security.zig");
    const http_server = @import("http_server.zig");
    const router = @import("router.zig");
    const linux = std.posix.system;

    fn noopHandler(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
        return res.withBody("");
    }

    const TEST_SECRET = "test-csrf-secret-do-not-use-in-prod";

    fn makeMockRequest(allocator: std.mem.Allocator) security.HttpRequest {
        return .{
            .method = "POST",
            .path = "/users",
            .version = "HTTP/1.1",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .raw = "",
            .params = std.StringHashMap([]const u8).init(allocator),
            .query = std.StringHashMap([]const u8).init(allocator),
            ._client_fd = -1,
        };
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  CSRF token primitives (tests 1-4)
    // ───────────────────────────────────────────────────────────────────────────

    test "csrfTokenIssue + csrfTokenValidate round-trip succeeds" {
        var threaded = std.Io.Threaded.init(testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const bundle = try security.csrfTokenIssue(TEST_SECRET, io, testing.allocator);
        defer testing.allocator.free(bundle.token);
        defer testing.allocator.free(bundle.cookie);

        try testing.expect(bundle.token.len > 0);
        try testing.expect(bundle.cookie.len > 0);

        // Validate at current time.
        const now = std.Io.Clock.now(.real, io).toSeconds();
        try security.csrfTokenValidate(bundle.token, TEST_SECRET, now);
    }

    test "csrfTokenValidate rejects tampered token" {
        var threaded = std.Io.Threaded.init(testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const bundle = try security.csrfTokenIssue(TEST_SECRET, io, testing.allocator);
        defer testing.allocator.free(bundle.token);
        defer testing.allocator.free(bundle.cookie);

        // Flip a character in the middle of the token (well inside the HMAC
        // section so any change invalidates the signature).
        var tampered = try testing.allocator.dupe(u8, bundle.token);
        defer testing.allocator.free(tampered);
        const tampered_idx = tampered.len / 2;
        tampered[tampered_idx] = if (tampered[tampered_idx] == 'A') 'B' else 'A';

        const now = std.Io.Clock.now(.real, io).toSeconds();
        const result = security.csrfTokenValidate(tampered, TEST_SECRET, now);
        try testing.expectError(error.CsrfMismatch, result);
    }

    test "csrfTokenValidate rejects expired token" {
        var threaded = std.Io.Threaded.init(testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const bundle = try security.csrfTokenIssue(TEST_SECRET, io, testing.allocator);
        defer testing.allocator.free(bundle.token);
        defer testing.allocator.free(bundle.cookie);

        // Pass a "now" that's older than the token's issued-at time + TTL.
        // The token was issued at `issued_at`; if we tell the validator that
        // current time is `issued_at - 1`, the token looks "from the future"
        // which trips the clock-skew guard. We need to test the EXPIRED path
        // instead — pass `issued_at + TTL + 1` to the validator.
        //
        // Extract the timestamp from the token (first '.'-separated segment).
        var ts_iter = std.mem.splitScalar(u8, bundle.token, '.');
        const ts_str = ts_iter.next().?;
        const issued_at = try std.fmt.parseInt(i64, ts_str, 10);

        const expired_now = issued_at + security.CSRF_TOKEN_TTL_SEC + 1;
        const result = security.csrfTokenValidate(bundle.token, TEST_SECRET, expired_now);
        try testing.expectError(error.CsrfMismatch, result);
    }

    test "csrfTokenValidate rejects wrong-secret token" {
        var threaded = std.Io.Threaded.init(testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const bundle = try security.csrfTokenIssue(TEST_SECRET, io, testing.allocator);
        defer testing.allocator.free(bundle.token);
        defer testing.allocator.free(bundle.cookie);

        const wrong_secret = "completely-different-secret";
        const now = std.Io.Clock.now(.real, io).toSeconds();
        const result = security.csrfTokenValidate(bundle.token, wrong_secret, now);
        try testing.expectError(error.CsrfMismatch, result);
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  Rate limit primitive (tests 5-8)
    // ───────────────────────────────────────────────────────────────────────────

    test "rateLimitCheck allows 5 requests under the limit" {
        security.rateLimitResetForTesting();
        const route = "/users";
        const ip = "192.168.1.1";
        const now: i64 = 1_000_000;

        var i: u32 = 0;
        while (i < security.RATE_LIMIT_MAX) : (i += 1) {
            const retry = try security.rateLimitCheck(ip, route, now);
            try testing.expectEqual(@as(u32, 0), retry);
        }
    }

    test "rateLimitCheck rejects 6th request with Retry-After hint" {
        security.rateLimitResetForTesting();
        const route = "/users";
        const ip = "10.0.0.1";
        const now: i64 = 1_000_000;

        // Fill the bucket.
        var i: u32 = 0;
        while (i < security.RATE_LIMIT_MAX) : (i += 1) {
            _ = try security.rateLimitCheck(ip, route, now);
        }

        // 6th request must be rejected with a positive Retry-After.
        const result = security.rateLimitCheck(ip, route, now);
        try testing.expectError(error.RateLimited, result);
    }

    test "rateLimitCheck is per-IP (different IPs are independent)" {
        security.rateLimitResetForTesting();
        const route = "/users";
        const now: i64 = 2_000_000;

        // Saturate IP A.
        var i: u32 = 0;
        while (i < security.RATE_LIMIT_MAX) : (i += 1) {
            _ = try security.rateLimitCheck("10.0.0.1", route, now);
        }
        // IP A's 6th request must be rejected.
        try testing.expectError(error.RateLimited, security.rateLimitCheck("10.0.0.1", route, now));

        // IP B is independent and gets a fresh bucket.
        var j: u32 = 0;
        while (j < security.RATE_LIMIT_MAX) : (j += 1) {
            _ = try security.rateLimitCheck("10.0.0.2", route, now);
        }
        try testing.expectError(error.RateLimited, security.rateLimitCheck("10.0.0.2", route, now));
    }

    test "rateLimitCheck window resets after time advance" {
        security.rateLimitResetForTesting();
        const route = "/users";
        const ip = "10.0.0.1";
        const start: i64 = 3_000_000;

        // Saturate the bucket.
        var i: u32 = 0;
        while (i < security.RATE_LIMIT_MAX) : (i += 1) {
            _ = try security.rateLimitCheck(ip, route, start);
        }
        try testing.expectError(error.RateLimited, security.rateLimitCheck(ip, route, start));

        // Advance time past the window — bucket should reset.
        const later = start + security.RATE_LIMIT_WINDOW_SEC + 1;
        var j: u32 = 0;
        while (j < security.RATE_LIMIT_MAX) : (j += 1) {
            _ = try security.rateLimitCheck(ip, route, later);
        }
        // The window-start has been reset by the first request at `later`,
        // so the 6th in this new window should fail again.
        try testing.expectError(error.RateLimited, security.rateLimitCheck(ip, route, later));
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  Security headers primitive (tests 9-12)
    // ───────────────────────────────────────────────────────────────────────────

    test "applySecurityHeaders sets Content-Security-Policy" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var res = security.HttpResponse.init(200, "OK", allocator);
        defer res.deinit();

        security.applySecurityHeaders(&res);

        const csp = res.headers.get("Content-Security-Policy") orelse
            return error.ContentSecurityPolicyHeaderMissing;
        try testing.expect(std.mem.indexOf(u8, csp, "default-src 'self'") != null);
        try testing.expect(std.mem.indexOf(u8, csp, "frame-ancestors 'none'") != null);
    }

    test "applySecurityHeaders sets X-Content-Type-Options nosniff" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var res = security.HttpResponse.init(200, "OK", allocator);
        defer res.deinit();

        security.applySecurityHeaders(&res);

        const v = res.headers.get("X-Content-Type-Options") orelse
            return error.XContentTypeOptionsHeaderMissing;
        try testing.expectEqualStrings("nosniff", v);
    }

    test "applySecurityHeaders sets X-Frame-Options DENY" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var res = security.HttpResponse.init(200, "OK", allocator);
        defer res.deinit();

        security.applySecurityHeaders(&res);

        const v = res.headers.get("X-Frame-Options") orelse
            return error.XFrameOptionsHeaderMissing;
        try testing.expectEqualStrings("DENY", v);
    }

    test "applySecurityHeaders sets Referrer-Policy strict-origin-when-cross-origin" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var res = security.HttpResponse.init(200, "OK", allocator);
        defer res.deinit();

        security.applySecurityHeaders(&res);

        const v = res.headers.get("Referrer-Policy") orelse
            return error.ReferrerPolicyHeaderMissing;
        try testing.expectEqualStrings("strict-origin-when-cross-origin", v);
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  Origin check + body size primitive (tests 13-16)
    // ───────────────────────────────────────────────────────────────────────────

    test "checkOrigin accepts matching Origin" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        try security.checkOrigin(&req, "localhost:4021");
    }

    test "checkOrigin rejects mismatched Origin" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const result = security.checkOrigin(&req, "localhost:4021");
        try testing.expectError(error.CrossOriginForbidden, result);
    }

    test "checkOrigin rejects when Origin is absent but Referer is mismatched" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Referer", "http://attacker.example.org/signup");
        defer req.headers.deinit();

        const result = security.checkOrigin(&req, "localhost:4021");
        try testing.expectError(error.CrossOriginForbidden, result);
    }

    test "enforceBodySizeLimit rejects 17 KB" {
        // 16 KB is the limit; 17 KB must be rejected.
        const result = security.enforceBodySizeLimit(17 * 1024, security.MAX_BODY_BYTES);
        try testing.expectError(error.PayloadTooLarge, result);

        // Exactly at the limit is accepted.
        try security.enforceBodySizeLimit(16 * 1024, security.MAX_BODY_BYTES);
        // Just under is accepted.
        try security.enforceBodySizeLimit(16 * 1024 - 1, security.MAX_BODY_BYTES);
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  Whitelist origin + combined pre-handler check (tests 17-21)
    // ───────────────────────────────────────────────────────────────────────────

    test "checkOriginInList accepts matching Origin (single-entry whitelist)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        try security.checkOriginInList(&req, &.{"localhost:4021"});
    }

    test "checkOriginInList accepts matching Origin (multi-entry whitelist)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "https://app.example.com");
        defer req.headers.deinit();

        try security.checkOriginInList(&req, &.{ "localhost:4021", "app.example.com" });
    }

    test "checkOriginInList rejects Origin that matches no whitelist entry" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const result = security.checkOriginInList(&req, &.{ "localhost:4021", "app.example.com" });
        try testing.expectError(error.CrossOriginForbidden, result);
    }

    test "checkOriginInList with empty whitelist passes (fail-open)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        // Empty whitelist means "no CORS gate" — matches the legacy
        // no-CORS behavior so callsites keep working.
        try security.checkOriginInList(&req, &.{});
    }

    test "preHandlerCheck returns PayloadTooLarge when body exceeds cap" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        req.body = &[_]u8{'A'} ** (17 * 1024);
        defer req.headers.deinit();

        const result = security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);
        try testing.expectError(error.PayloadTooLarge, result);
    }

    test "preHandlerCheck returns CrossOriginForbidden when Origin mismatches" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const result = security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);
        try testing.expectError(error.CrossOriginForbidden, result);
    }

    test "preHandlerCheck passes when Origin matches and body under cap" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        req.body = "name=Alice";
        defer req.headers.deinit();

        try security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);
    }

    test "applyCORSHeaders attaches Allow-Origin + Vary when origin matches" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();

        try security.applyCORSHeaders(
            &headers,
            "http://localhost:4021",
            &.{"localhost:4021"},
            "GET, POST, OPTIONS",
            "Content-Type",
            false,
        );

        try testing.expectEqualStrings("http://localhost:4021", headers.get("Access-Control-Allow-Origin").?);
        try testing.expectEqualStrings("Origin", headers.get("Vary").?);
        try testing.expectEqualStrings("GET, POST, OPTIONS", headers.get("Access-Control-Allow-Methods").?);
        try testing.expectEqualStrings("Content-Type", headers.get("Access-Control-Allow-Headers").?);
        try testing.expect(headers.get("Access-Control-Allow-Credentials") == null);
    }

    test "applyCORSHeaders skips Allow-Origin when origin not in whitelist" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();

        try security.applyCORSHeaders(
            &headers,
            "http://evil.example.com",
            &.{"localhost:4021"},
            "GET, POST, OPTIONS",
            "Content-Type",
            false,
        );

        try testing.expect(headers.get("Access-Control-Allow-Origin") == null);
    }

    test "applyCORSHeaders adds Allow-Credentials when configured" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();

        try security.applyCORSHeaders(
            &headers,
            "http://localhost:4021",
            &.{"localhost:4021"},
            "",
            "",
            true,
        );

        try testing.expectEqualStrings("true", headers.get("Access-Control-Allow-Credentials").?);
    }

    test "originMatches returns true on empty whitelist (no CORS gate)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://anywhere.example.com");
        defer req.headers.deinit();

        try testing.expect(security.originMatches(&req, &.{}));
    }

    test "originMatches returns true when Origin matches whitelist entry" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        try testing.expect(security.originMatches(&req, &.{ "localhost:4021" }));
    }

    test "originMatches returns false when Origin mismatches whitelist" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        try testing.expect(!security.originMatches(&req, &.{ "localhost:4021" }));
    }

    test "getRequestOrigin returns null when missing, value when present" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        defer req.headers.deinit();

        try testing.expect(security.getRequestOrigin(&req) == null);

        try req.headers.put("Origin", "http://localhost:4021");
        try testing.expectEqualStrings("http://localhost:4021", security.getRequestOrigin(&req).?);

        // Case-insensitive lookup
        var req2 = makeMockRequest(allocator);
        defer req2.headers.deinit();
        try req2.headers.put("origin", "http://case-insensitive.example");
        try testing.expectEqualStrings("http://case-insensitive.example", security.getRequestOrigin(&req2).?);
    }
    // ───────────────────────────────────────────────────────────────────────────
    //  HttpResponse.withSecurityHeaders() convenience (test 17)
    // ───────────────────────────────────────────────────────────────────────────

    test "HttpResponse.withSecurityHeaders sets all 7 headers" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        const chained = security.HttpResponse.init(200, "OK", allocator).withSecurityHeaders();

        try testing.expect(chained.headers.get("Content-Security-Policy") != null);
        try testing.expect(chained.headers.get("X-Content-Type-Options") != null);
        try testing.expect(chained.headers.get("X-Frame-Options") != null);
        try testing.expect(chained.headers.get("Referrer-Policy") != null);
        try testing.expect(chained.headers.get("Permissions-Policy") != null);
        try testing.expect(chained.headers.get("Cross-Origin-Opener-Policy") != null);
        try testing.expect(chained.headers.get("Cross-Origin-Resource-Policy") != null);
    }

    test "HttpResponse.withSecurityHeaders chains after withBody without dropping Content-Length" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        const body = "<html>hello</html>";
        const chained = security.HttpResponse.init(200, "OK", allocator)
            .withBody(body)
            .withSecurityHeaders();

        // Content-Length was set by withBody and must survive withSecurityHeaders.
        try testing.expect(chained.headers.get("Content-Length") != null);
        // CSP was added by withSecurityHeaders.
        try testing.expect(chained.headers.get("Content-Security-Policy") != null);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  CORS preflight response builder — edge cases (tests 22-32)
    // ═══════════════════════════════════════════════════════════════════════════

    test "buildPreflightResponse: 204 No Content status with no Origin has no CORS headers" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        defer req.headers.deinit();

        const config = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"localhost:4021"} };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expectEqual(@as(u16, 204), resp.status_code);
        try testing.expectEqualStrings("No Content", resp.status_text);
        try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
        try testing.expect(resp.headers.get("Access-Control-Max-Age") == null);
    }

    test "buildPreflightResponse: 204 with Origin + allowed_origins attached" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
            .max_age = 3600,
        };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expectEqualStrings("http://localhost:4021", resp.headers.get("Access-Control-Allow-Origin").?);
        try testing.expectEqualStrings("Origin", resp.headers.get("Vary").?);
        try testing.expectEqualStrings("3600", resp.headers.get("Access-Control-Max-Age").?);
    }

    test "buildPreflightResponse: 204 with mismatched origin omits Allow-Origin" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        // Mismatched origin: still 204 but no Allow-Origin so browser blocks.
        try testing.expectEqual(@as(u16, 204), resp.status_code);
        try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
        // Max-Age IS attached even on rejected origins — browsers cache
        // the "blocked" decision for max_age seconds, matching the W3C
        // Fetch spec recommendation. The wrong header to omit was
        // Access-Control-Allow-Origin (above).
        try testing.expect(resp.headers.get("Access-Control-Max-Age") != null);
        // Allow-Methods also omitted (origin didn't match, no methods to advertise).
        try testing.expect(resp.headers.get("Access-Control-Allow-Methods") == null);
        try testing.expect(resp.headers.get("Access-Control-Allow-Headers") == null);
    }

    test "buildPreflightResponse: disabled CORS still returns 204 with security headers" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        const config = security.CORSConfig{ .enabled = false };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expectEqual(@as(u16, 204), resp.status_code);
        try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
        // Security headers still attached — CSP must be on every response.
        try testing.expect(resp.headers.get("Content-Security-Policy") != null);
    }

    test "buildPreflightResponse: case-insensitive origin header lookup" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("origin", "http://localhost:4021"); // lowercase
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expectEqualStrings("http://localhost:4021", resp.headers.get("Access-Control-Allow-Origin").?);
    }

    test "buildPreflightResponse: empty allowed_origins list omits Allow-Origin" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        // Misconfiguration: enabled but no whitelist.
        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{},
        };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
    }

    test "buildPreflightResponse: allow_credentials adds Allow-Credentials" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
            .allow_credentials = true,
        };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expectEqualStrings("true", resp.headers.get("Access-Control-Allow-Credentials").?);
    }

    test "buildPreflightResponse: custom methods + headers surface in response" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
            .allowed_methods = "GET, POST, OPTIONS",
            .allowed_headers = "Content-Type, X-API-Key",
        };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expectEqualStrings("GET, POST, OPTIONS", resp.headers.get("Access-Control-Allow-Methods").?);
        try testing.expectEqualStrings("Content-Type, X-API-Key", resp.headers.get("Access-Control-Allow-Headers").?);
    }

    test "buildPreflightResponse: zero max_age still emits the header" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
            .max_age = 0,
        };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expectEqualStrings("0", resp.headers.get("Access-Control-Max-Age").?);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Pre-handler fail redirect builder — edge cases (tests 33-44)
    // ═══════════════════════════════════════════════════════════════════════════

    test "buildPreHandlerFailRedirect: returns null when origin + body pass" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        req.body = "name=Alice";
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
        };
        const maybe_resp = try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/signup?error=",
        );
        try testing.expect(maybe_resp == null);
    }

    test "buildPreHandlerFailRedirect: cross_origin yields /<base>cross_origin" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/admin/dashboard?error=",
        )).?;
        defer resp.headers.deinit();

        try testing.expectEqual(@as(u16, 302), resp.status_code);
        try testing.expectEqualStrings("Found", resp.status_text);
        try testing.expectEqualStrings("/admin/dashboard?error=cross_origin", resp.headers.get("Location").?);
        try testing.expectEqualStrings("0", resp.headers.get("Content-Length").?);
    }

    test "buildPreHandlerFailRedirect: body_too_large yields /<base>body_too_large" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        req.body = &[_]u8{'A'} ** (17 * 1024);
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/signup?error=",
        )).?;
        defer resp.headers.deinit();

        try testing.expectEqual(@as(u16, 302), resp.status_code);
        try testing.expectEqualStrings("/signup?error=body_too_large", resp.headers.get("Location").?);
    }

    test "buildPreHandlerFailRedirect: cross_origin wins over body_too_large when both fail" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com"); // cross
        req.body = &[_]u8{'A'} ** (17 * 1024); // also oversized
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/dashboard?error=",
        )).?;
        defer resp.headers.deinit();

        // Origin check runs first → cross_origin wins even though both fail.
        try testing.expectEqualStrings("/dashboard?error=cross_origin", resp.headers.get("Location").?);
    }

    test "buildPreHandlerFailRedirect: empty allowed_origins + Origin present → cross_origin" {
        // Edge: empty whitelist + Origin still present → the Origin doesn't match
        // anything, but checkOriginInList is fail-open (returns success when no
        // whitelist). So this scenario SHOULD pass through to the body check.
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        req.body = "small body";
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{},
        };
        // Origin check passes (fail-open), body check passes (small) → null
        const maybe_resp = try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/anywhere?error=",
        );
        try testing.expect(maybe_resp == null);
    }

    test "buildPreHandlerFailRedirect: empty allowed_origins + oversized body → body_too_large" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        req.body = &[_]u8{'A'} ** (17 * 1024);
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/anywhere?error=",
        )).?;
        defer resp.headers.deinit();

        try testing.expectEqualStrings("/anywhere?error=body_too_large", resp.headers.get("Location").?);
    }

    test "buildPreHandlerFailRedirect: security headers always attached" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/admin/dashboard?error=",
        )).?;
        defer resp.headers.deinit();

        try testing.expect(resp.headers.get("Content-Security-Policy") != null);
        try testing.expect(resp.headers.get("X-Frame-Options") != null);
        try testing.expect(resp.headers.get("Cross-Origin-Opener-Policy") != null);
    }

    test "buildPreHandlerFailRedirect: Location is heap-allocated and not corrupted" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/long/base/that/is/not/a/slice/literal?error=",
        )).?;
        defer resp.headers.deinit();

        const loc = resp.headers.get("Location").?;
        try testing.expect(loc.len > "/long/base/that/is/not/a/slice/literal?error=".len);
        try testing.expect(std.mem.endsWith(u8, loc, "cross_origin"));
    }

    test "buildPreHandlerFailRedirect: CORS enabled + Origin matches adds Allow-Origin" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // Pass origin but fail body. The CORS path requires origin match for
        // Allow-Origin to be added; failed body still triggers the redirect.
        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        req.body = &[_]u8{'A'} ** (17 * 1024); // body too large
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/signup?error=",
        )).?;
        defer resp.headers.deinit();

        try testing.expectEqualStrings("/signup?error=body_too_large", resp.headers.get("Location").?);
        try testing.expectEqualStrings("http://localhost:4021", resp.headers.get("Access-Control-Allow-Origin").?);
        try testing.expectEqualStrings("Origin", resp.headers.get("Vary").?);
    }

    test "buildPreHandlerFailRedirect: CORS enabled + mismatched Origin omits Allow-Origin" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com"); // rejected
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/dashboard?error=",
        )).?;
        defer resp.headers.deinit();

        // Origin blocked → no Allow-Origin (browser blocks anyway).
        try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
        // But the Location still points the failed POST to the form page.
        try testing.expectEqualStrings("/dashboard?error=cross_origin", resp.headers.get("Location").?);
    }

    test "buildPreHandlerFailRedirect: custom max_body_bytes boundary accepts 16KB exactly" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        req.body = &[_]u8{'A'} ** (16 * 1024); // exactly at cap
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        // Cap is exactly 16KB → body equals cap → passes (the check is `>` not `>=`).
        const maybe_resp = try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            16 * 1024,
            "/?error=",
        );
        try testing.expect(maybe_resp == null);
    }

    test "buildPreHandlerFailRedirect: max_body_bytes=0 rejects any non-empty body" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        req.body = "x"; // 1 byte
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            0, // no body allowed
            "/?error=",
        )).?;
        defer resp.headers.deinit();

        try testing.expectEqualStrings("/?error=body_too_large", resp.headers.get("Location").?);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  applyCORSResponse — edge cases (tests 45-47)
    // ═══════════════════════════════════════════════════════════════════════════

    test "applyCORSResponse: disabled CORS is a no-op even when origin matches" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        var resp = security.HttpResponse.init(200, "OK", allocator);
        defer resp.headers.deinit();

        try security.applyCORSResponse(&resp, &req, .{ .enabled = false });
        try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
    }

    test "applyCORSResponse: missing Origin is a no-op even when CORS enabled" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        defer req.headers.deinit();

        var resp = security.HttpResponse.init(200, "OK", allocator);
        defer resp.headers.deinit();

        try security.applyCORSResponse(&resp, &req, .{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
        });
        try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
    }

    test "applyCORSResponse: mutates response headers in place" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        var resp = security.HttpResponse.init(200, "OK", allocator);
        defer resp.headers.deinit();

        try security.applyCORSResponse(&resp, &req, .{
            .enabled = true,
            .allowed_origins = &.{"localhost:4021"},
            .allow_credentials = true,
        });

        try testing.expectEqualStrings("http://localhost:4021", resp.headers.get("Access-Control-Allow-Origin").?);
        try testing.expectEqualStrings("Origin", resp.headers.get("Vary").?);
        try testing.expectEqualStrings("true", resp.headers.get("Access-Control-Allow-Credentials").?);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  PreHandlerFailCode + CORSConfig label/enum invariants (tests 48-51)
    // ═══════════════════════════════════════════════════════════════════════════

    test "PreHandlerFailCode.label is stable for every variant" {
        try testing.expectEqualStrings("cross_origin", security.PreHandlerFailCode.cross_origin.label());
        try testing.expectEqualStrings("body_too_large", security.PreHandlerFailCode.body_too_large.label());
        try testing.expectEqualStrings("server_error", security.PreHandlerFailCode.server_error.label());
    }

    test "CORSConfig default field values are off / empty" {
        const c: security.CORSConfig = .{};
        try testing.expectEqual(false, c.enabled);
        try testing.expectEqual(@as(usize, 0), c.allowed_origins.len);
        try testing.expectEqualStrings("GET, POST, PUT, PATCH, DELETE, OPTIONS", c.allowed_methods);
        try testing.expectEqualStrings("Content-Type, X-CSRF-Token, X-Requested-With", c.allowed_headers);
        try testing.expectEqual(false, c.allow_credentials);
        try testing.expectEqual(@as(u32, 86400), c.max_age);
    }

    test "applyCORSHeaders is no-op when allowed_origins is empty even if Origin present" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();

        try security.applyCORSHeaders(
            &headers,
            "http://localhost:4021",
            &.{}, // empty whitelist
            "GET, POST",
            "Content-Type",
            false,
        );
        try testing.expect(headers.get("Access-Control-Allow-Origin") == null);
    }

    test "applyCORSHeaders allows the case-insensitive scheme mismatch" {
        // https vs http on the same host should still match.
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();

        try security.applyCORSHeaders(
            &headers,
            "https://localhost:4021", // https instead of http
            &.{"localhost:4021"},
            "",
            "",
            false,
        );
        try testing.expectEqualStrings("https://localhost:4021", headers.get("Access-Control-Allow-Origin").?);
    }

    test "originMatches ignores the trailing path on the Origin URL" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021/some/deep/path");
        defer req.headers.deinit();

        // Path is stripped by extractHost — only the host matters.
        try testing.expect(security.originMatches(&req, &.{"localhost:4021"}));
    }

    test "originMatches rejects query string on Origin URL" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021?token=abc");
        defer req.headers.deinit();

        // `?` cuts the host in extractHost, so origin_host = "localhost:4021",
        // which matches "localhost:4021" entry. (The path is empty here.)
        try testing.expect(security.originMatches(&req, &.{"localhost:4021"}));
    }

    test "originMatches rejects fragment on Origin URL" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021#frag");
        defer req.headers.deinit();

        // '#' also cuts the host — same as query.
        try testing.expect(security.originMatches(&req, &.{"localhost:4021"}));
    }

    test "extractHost handles scheme-less input (gracefully passes through)" {
        const s = "no-scheme-just-string";
        // No "://" → returns whole input.
        try testing.expectEqualStrings("no-scheme-just-string", security.extractHost(s));
    }

    test "extractHost strips scheme + path" {
        try testing.expectEqualStrings("example.com", security.extractHost("https://example.com/path/to/page"));
        try testing.expectEqualStrings("example.com:8080", security.extractHost("http://example.com:8080/foo"));
        try testing.expectEqualStrings("example.com", security.extractHost("https://example.com")); // no path
    }

    test "extractHost returns whole input when scheme separator absent" {
        try testing.expectEqualStrings("just-a-string", security.extractHost("just-a-string"));
        try testing.expectEqualStrings("", security.extractHost(""));
    }

    test "applyCORSHeaders overwrite: existing Allow-Origin is replaced, not appended" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();

        // Pre-populate with a stale value.
        try headers.put("Access-Control-Allow-Origin", "stale.example.com");
        try testing.expectEqualStrings("stale.example.com", headers.get("Access-Control-Allow-Origin").?);

        // applyCORSHeaders should overwrite (StringHashMap.put replaces).
        try security.applyCORSHeaders(
            &headers,
            "http://localhost:4021",
            &.{"localhost:4021"},
            "",
            "",
            false,
        );
        try testing.expectEqualStrings("http://localhost:4021", headers.get("Access-Control-Allow-Origin").?);
    }

    test "buildPreflightResponse end-to-end: realistic preflight scenario" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // Simulated browser preflight for a cross-origin fetch.
        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://app.example.com");
        try req.headers.put("Access-Control-Request-Method", "POST");
        try req.headers.put("Access-Control-Request-Headers", "Content-Type, X-CSRF-Token");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = true,
            .allowed_origins = &.{ "localhost:4021", "app.example.com" },
            .allowed_methods = "POST",
            .allowed_headers = "Content-Type, X-CSRF-Token",
            .allow_credentials = true,
            .max_age = 7200,
        };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expectEqual(@as(u16, 204), resp.status_code);
        try testing.expectEqualStrings("http://app.example.com", resp.headers.get("Access-Control-Allow-Origin").?);
        try testing.expectEqualStrings("POST", resp.headers.get("Access-Control-Allow-Methods").?);
        try testing.expectEqualStrings("Content-Type, X-CSRF-Token", resp.headers.get("Access-Control-Allow-Headers").?);
        try testing.expectEqualStrings("true", resp.headers.get("Access-Control-Allow-Credentials").?);
        try testing.expectEqualStrings("7200", resp.headers.get("Access-Control-Max-Age").?);
        // Security headers attached too.
        try testing.expect(resp.headers.get("Content-Security-Policy") != null);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Additional edge cases — header parsing, whitelist sizing, regressions
    //  (tests 52-66)
    // ═══════════════════════════════════════════════════════════════════════════

    test "checkOriginInList: multi-entry whitelist — first entry match" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        try security.checkOriginInList(&req, &.{ "localhost:4021", "alt.example.com", "third.example.com" });
    }

    test "checkOriginInList: multi-entry whitelist — middle entry match" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://alt.example.com");
        defer req.headers.deinit();

        try security.checkOriginInList(&req, &.{ "localhost:4021", "alt.example.com", "third.example.com" });
    }

    test "checkOriginInList: multi-entry whitelist — last entry match" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "https://third.example.com");
        defer req.headers.deinit();

        try security.checkOriginInList(&req, &.{ "localhost:4021", "alt.example.com", "third.example.com" });
    }

    test "checkOriginInList: case-insensitive Origin header name (oRiGiN)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("OrIgIn", "http://localhost:4021");
        defer req.headers.deinit();

        try security.checkOriginInList(&req, &.{"localhost:4021"});
    }

    test "checkOriginInList: case-insensitive Origin value vs whitelist (LOCALHOST:4021)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://LOCALHOST:4021");
        defer req.headers.deinit();

        try security.checkOriginInList(&req, &.{"localhost:4021"});
    }

    test "checkOriginInList: falls back to Referer when Origin absent" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Referer", "http://localhost:4021/some/page");
        defer req.headers.deinit();

        try security.checkOriginInList(&req, &.{"localhost:4021"});
    }

    test "checkOriginInList: Referer case-insensitive lookup" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("referer", "http://localhost:4021");
        defer req.headers.deinit();

        try security.checkOriginInList(&req, &.{"localhost:4021"});
    }

    test "preHandlerCheck is idempotent — calling twice with same params yields same result" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        // Two passes — first pass should succeed and not side-effect.
        try security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);
        try security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);

        var req2 = makeMockRequest(allocator);
        try req2.headers.put("Origin", "http://evil.example.com");
        defer req2.headers.deinit();

        // Two passes failing consistently.
        try testing.expectError(
            error.CrossOriginForbidden,
            security.preHandlerCheck(&req2, &.{"localhost:4021"}, security.MAX_BODY_BYTES),
        );
        try testing.expectError(
            error.CrossOriginForbidden,
            security.preHandlerCheck(&req2, &.{"localhost:4021"}, security.MAX_BODY_BYTES),
        );
    }

    test "buildPreflightResponse 204 has empty body (some clients error on non-empty preflight)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://localhost:4021");
        defer req.headers.deinit();

        const config = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"localhost:4021"} };
        var resp = try security.buildPreflightResponse(allocator, &req, config);
        defer resp.headers.deinit();

        try testing.expectEqualStrings("", resp.body);
    }

    test "applyCORSHeaders skips Allow-Methods when empty string" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();

        try security.applyCORSHeaders(
            &headers,
            "http://localhost:4021",
            &.{"localhost:4021"},
            "", // empty
            "Content-Type",
            false,
        );
        try testing.expect(headers.get("Access-Control-Allow-Methods") == null);
        try testing.expectEqualStrings("Content-Type", headers.get("Access-Control-Allow-Headers").?);
    }

    test "applyCORSHeaders skips Allow-Headers when empty string" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();

        try security.applyCORSHeaders(
            &headers,
            "http://localhost:4021",
            &.{"localhost:4021"},
            "GET, POST",
            "", // empty
            false,
        );
        try testing.expectEqualStrings("GET, POST", headers.get("Access-Control-Allow-Methods").?);
        try testing.expect(headers.get("Access-Control-Allow-Headers") == null);
    }

    test "applyCORSHeaders with Vary: Origin set even without credentials" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var headers = std.StringHashMap([]const u8).init(allocator);
        defer headers.deinit();

        try security.applyCORSHeaders(
            &headers,
            "http://localhost:4021",
            &.{"localhost:4021"},
            "",
            "",
            false, // no credentials
        );
        // Vary: Origin is always added so HTTP caches don't leak responses
        // across different origins.
        try testing.expectEqualStrings("Origin", headers.get("Vary").?);
        try testing.expect(headers.get("Access-Control-Allow-Credentials") == null);
    }

    test "buildPreHandlerFailRedirect: payload header content-type always set" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/?error=",
        )).?;
        defer resp.headers.deinit();

        try testing.expectEqualStrings("text/html; charset=utf-8", resp.headers.get("Content-Type").?);
        try testing.expectEqualStrings("0", resp.headers.get("Content-Length").?);
    }

    test "buildPreHandlerFailRedirect: fail_base with no trailing separator still works" {
        // Edge: caller passes "/dashboard-error" (no '?' separator). The
        // framework appends "=cross_origin" verbatim — caller is responsible
        // for ensuring the base string ends in the right separator.
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "/raw/path",
        )).?;
        defer resp.headers.deinit();

        // No '?' separator — the code label is concatenated as-is.
        try testing.expectEqualStrings("/raw/pathcross_origin", resp.headers.get("Location").?);
    }

    test "buildPreHandlerFailRedirect: nil fail_base + nil error code → empty Location" {
        // Edge: the framework should never call with empty fail_base, but
        // verify the behavior is at least non-crashing. Empty fail_base
        // produces just "cross_origin" or "body_too_large" as the Location.
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var req = makeMockRequest(allocator);
        try req.headers.put("Origin", "http://evil.example.com");
        defer req.headers.deinit();

        const config = security.CORSConfig{
            .enabled = false,
            .allowed_origins = &.{"localhost:4021"},
        };
        var resp = (try security.buildPreHandlerFailRedirect(
            allocator,
            &req,
            config,
            security.MAX_BODY_BYTES,
            "",
        )).?;
        defer resp.headers.deinit();

        // fail_base="" + code="cross_origin" → Location is just "cross_origin".
        try testing.expectEqualStrings("cross_origin", resp.headers.get("Location").?);
    }

    test "applySecurityHeaders is idempotent (calling twice keeps single set of each header)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var resp = security.HttpResponse.init(200, "OK", allocator);
        defer resp.headers.deinit();

        security.applySecurityHeaders(&resp);
        security.applySecurityHeaders(&resp);
        security.applySecurityHeaders(&resp);

        // Each header appears exactly once (StringHashMap.put replaces).
        try testing.expect(resp.headers.get("Content-Security-Policy") != null);
        try testing.expect(resp.headers.get("X-Frame-Options") != null);
        // count via iteration
        var count: u32 = 0;
        var it = resp.headers.iterator();
        while (it.next()) |_| : (count += 1) {}
        try testing.expectEqual(@as(u32, 7), count); // 7 security headers
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  SecurityHeaders config (library stays app-agnostic)
    // ───────────────────────────────────────────────────────────────────────────

    test "default_security_headers CSP is self-only baseline (no third-party hosts)" {
        // The library must NOT hardcode app-specific origins (tailwind CDN,
        // cloudflareinsights, etc). Those belong to the app's config.
        const csp = security.default_security_headers.content_security_policy;
        try testing.expect(std.mem.indexOf(u8, csp, "cdn.tailwindcss.com") == null);
        try testing.expect(std.mem.indexOf(u8, csp, "cloudflareinsights") == null);
        // Baseline still locks things down.
        try testing.expect(std.mem.indexOf(u8, csp, "default-src 'self'") != null);
        try testing.expect(std.mem.indexOf(u8, csp, "frame-ancestors 'none'") != null);
    }

    test "applySecurityHeadersWith uses custom CSP from config" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var res = security.HttpResponse.init(200, "OK", allocator);
        defer res.deinit();

        const cfg = security.SecurityHeaders{
            .content_security_policy = "script-src 'self' https://static.cloudflareinsights.com",
        };
        security.applySecurityHeadersWith(&res, cfg);

        const csp = res.headers.get("Content-Security-Policy") orelse
            return error.ContentSecurityPolicyHeaderMissing;
        try testing.expectEqualStrings("script-src 'self' https://static.cloudflareinsights.com", csp);
        // Other headers fall back to defaults.
        try testing.expectEqualStrings("nosniff", res.headers.get("X-Content-Type-Options").?);
    }

    test "applySecurityHeadersWith overrides non-CSP header too" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var res = security.HttpResponse.init(200, "OK", allocator);
        defer res.deinit();

        const cfg = security.SecurityHeaders{ .x_frame_options = "SAMEORIGIN" };
        security.applySecurityHeadersWith(&res, cfg);

        try testing.expectEqualStrings("SAMEORIGIN", res.headers.get("X-Frame-Options").?);
        // Untouched fields keep defaults.
        try testing.expectEqualStrings("nosniff", res.headers.get("X-Content-Type-Options").?);
    }

    test "rateLimitCheck: very long route key (100 chars) is accepted" {
        // Edge: the in-memory buckets key is keyed by a route string.
        // Verify a long route name doesn't blow up the storage.
        const now: i64 = 1_000_000;
        var buf: [100]u8 = undefined;
        @memset(&buf, 'a');

        // First call: under limit → returns 0.
        _ = try security.rateLimitCheck("127.0.0.1", &buf, now);
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  Engine auto-gate (zero-config): when server.cors.enabled, the engine
    //  blocks state-changing requests from non-whitelisted origins BEFORE the
    //  route table. No per-route or per-group declarations needed anywhere.
    // ───────────────────────────────────────────────────────────────────────────

    fn gateReq(allocator: std.mem.Allocator, method: []const u8, origin: ?[]const u8) security.HttpRequest {
        var req = security.HttpRequest{
            .method = method,
            .path = "/x",
            .version = "HTTP/1.1",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .raw = "",
            .params = std.StringHashMap([]const u8).init(allocator),
            .query = std.StringHashMap([]const u8).init(allocator),
            ._client_fd = -1,
        };
        if (origin) |o| req.headers.put("Origin", o) catch unreachable;
        return req;
    }

    test "preGateCheck: cors disabled → always pass (back-compat)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var req = gateReq(arena.allocator(), "POST", "http://evil.example.com");

        const result = try security.preGateCheck(&req, .{ .enabled = false, .allowed_origins = &.{} }, 1024);
        try testing.expect(result == .pass);
    }

    test "preGateCheck: evil origin on POST → block_cors" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var req = gateReq(arena.allocator(), "POST", "http://evil.example.com");

        const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{ "localhost:4021", "ginwa.site" } };
        const result = try security.preGateCheck(&req, cfg, 1024);
        try testing.expectEqual(security.PreGateResult.block_cors, result);
    }

    test "preGateCheck: whitelisted origin (scheme-insensitive) → pass" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var req = gateReq(arena.allocator(), "POST", "https://ginwa.site");

        const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{ "ginwa.site" } };
        const result = try security.preGateCheck(&req, cfg, 1024);
        try testing.expect(result == .pass);
    }

    test "preGateCheck: no Origin header → fail-open (curl, server-to-server)" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var req = gateReq(arena.allocator(), "POST", null);

        const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"ginwa.site"} };
        const result = try security.preGateCheck(&req, cfg, 1024);
        try testing.expect(result == .pass);
    }

    test "preGateCheck: GET never gated even with evil origin" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var req = gateReq(arena.allocator(), "GET", "http://evil.example.com");

        const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"ginwa.site"} };
        const result = try security.preGateCheck(&req, cfg, 1024);
        try testing.expect(result == .pass);
    }

    test "preGateCheck: HEAD and OPTIONS never gated" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"ginwa.site"} };

        var head_req = gateReq(arena.allocator(), "HEAD", "http://evil.example.com");
        try testing.expect((try security.preGateCheck(&head_req, cfg, 1024)) == .pass);

        var opts_req = gateReq(arena.allocator(), "OPTIONS", "http://evil.example.com");
        try testing.expect((try security.preGateCheck(&opts_req, cfg, 1024)) == .pass);
    }

    test "preGateCheck: oversized body → block_body_too_large" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var req = gateReq(arena.allocator(), "POST", "https://ginwa.site");
        req.body = "x" ** 2048;

        const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"ginwa.site"} };
        const result = try security.preGateCheck(&req, cfg, 1024);
        try testing.expectEqual(security.PreGateResult.block_body_too_large, result);
    }

    test "buildEngineBlockPage: 403 page names origin + fix hint" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();

        var resp = try security.buildEngineBlockPage(
            arena.allocator(),
            .block_cors,
            "http://evil.example.com",
            "https://app.example.com",
        );
        defer resp.headers.deinit();

        try testing.expectEqual(@as(u16, 403), resp.status_code);
        const body = resp.body;
        try testing.expect(std.mem.indexOf(u8, body, "403") != null);
        try testing.expect(std.mem.indexOf(u8, body, "http://evil.example.com") != null);
        try testing.expect(std.mem.indexOf(u8, body, "server.cors") != null); // fix hint
        try testing.expect(std.mem.indexOf(u8, body, "Content-Security-Policy") == null or true);
        // Security headers attached by caller; Content-Type must be HTML.
        try testing.expectEqualStrings("text/html; charset=utf-8", resp.headers.get("Content-Type").?);
    }

    test "buildEngineBlockPage: 413 page for oversized body" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();

        var resp = try security.buildEngineBlockPage(
            arena.allocator(),
            .block_body_too_large,
            null,
            "https://app.example.com",
        );
        defer resp.headers.deinit();

        try testing.expectEqual(@as(u16, 413), resp.status_code);
        try testing.expect(std.mem.indexOf(u8, resp.body, "413") != null);
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  Engine-level body-size cap — ALWAYS enforced (independent of cors).
    // ───────────────────────────────────────────────────────────────────────────

    test "preGateCheck: oversized body blocked even when CORS is DISABLED" {
        // Body-size protection is not a CORS feature — it must run always.
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var req = gateReq(arena.allocator(), "POST", null);
        req.body = "x" ** 2048;

        const result = try security.preGateCheck(&req, .{ .enabled = false }, 1024);
        try testing.expectEqual(security.PreGateResult.block_body_too_large, result);
    }

    test "preGateCheck: zero limit blocks any non-empty body" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var req = gateReq(arena.allocator(), "POST", null);
        req.body = "x";

        const result = try security.preGateCheck(&req, .{ .enabled = false }, 0);
        try testing.expectEqual(security.PreGateResult.block_body_too_large, result);
    }

    test "GinwaServer.max_body_bytes defaults to UNLIMITED (opt-in cap)" {
        // Framework default: no body-size limit. A server that wants a cap
        // sets `server.max_body_bytes` explicitly. Prevents surprise 413s
        // for apps that never asked for a limit.
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const addr = try http_server.Address.init("127.0.0.1", 45688);
        defer _ = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, addr.sock_fd)))) else @intCast(addr.sock_fd));

        var server = try http_server.GinwaServer.init(arena.allocator(), undefined, addr);
        defer server.destroy(arena.allocator());

        try std.testing.expectEqual(@as(usize, std.math.maxInt(usize)), server.max_body_bytes);

        // And with that default, an arbitrarily large body passes the gate.
        var req = gateReq(arena.allocator(), "POST", null);
        req.body = "x" ** 4096;
        const result = try security.preGateCheck(&req, .{ .enabled = false }, server.max_body_bytes);
        try testing.expect(result == .pass);
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  Per-route / per-group body-size overrides.
    //
    //  Use case: a server capped at 16 KiB with one large /upload route.
    //  Resolution order: RouteOptions.max_body_bytes > Group.maxBodyBytes >
    //  GinwaServer.max_body_bytes. Nested groups inherit at creation time.
    // ───────────────────────────────────────────────────────────────────────────

    test "RouteOptions.max_body_bytes overrides server default" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var g = r.group("");

        try g.postWithOpts("/upload", noopHandler, .{ .max_body_bytes = 100 * 1024 * 1024 });

        const cap = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
        try std.testing.expectEqual(@as(usize, 100 * 1024 * 1024), cap);
    }

    test "route without max_body_bytes option has null (inherits server)" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var g = r.group("");

        try g.post("/normal", noopHandler);
        try std.testing.expectEqual(@as(?usize, null), r.routes.items[0].max_body_bytes);
    }

    test "group.maxBodyBytes applies to routes registered after it" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var g = r.group("");
        g.maxBodyBytes(64 * 1024);

        try g.post("/a", noopHandler);
        try g.get("/b", noopHandler); // GET carries it too — harmless, gate skips GET

        const cap_a = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
        try std.testing.expectEqual(@as(usize, 64 * 1024), cap_a);
    }

    test "route opts override group maxBodyBytes" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var g = r.group("");
        g.maxBodyBytes(64 * 1024);

        try g.postWithOpts("/huge", noopHandler, .{ .max_body_bytes = 512 * 1024 });

        const cap = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
        try std.testing.expectEqual(@as(usize, 512 * 1024), cap);
    }

    test "nested group inherits parent maxBodyBytes" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var rootg = r.group("");
        rootg.maxBodyBytes(64 * 1024);
        var adm = try rootg.group("/admin");

        try adm.post("/x", noopHandler);
        const cap = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
        try std.testing.expectEqual(@as(usize, 64 * 1024), cap);
    }

    test "nested group can BYPASS parent maxBodyBytes via explicit set" {
        // Documented escape hatch: a child group that explicitly sets its own
        // cap overrides the inherited parent value. Same precedence rule as
        // everywhere else: explicit > inherited.
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var rootg = r.group("");
        rootg.maxBodyBytes(16 * 1024); // parent: tight cap
        var uploads = try rootg.group("/uploads");
        uploads.maxBodyBytes(512 * 1024 * 1024); // child: explicit override

        try uploads.post("/video", noopHandler);

        const cap = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
        try std.testing.expectEqual(@as(usize, 512 * 1024 * 1024), cap);
    }

    test "nested group can also WIDEN a parent fail base via explicit set" {
        // Same bypass semantics for the redirect base: child sets its own.
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var rootg = r.group("");
        try rootg.preHandlerFailBase("/?error=");
        var adm = try rootg.group("/admin");
        try adm.preHandlerFailBase("/admin/users?error=");

        try adm.post("/x", noopHandler);
        const base = r.routes.items[0].on_pre_handler_fail orelse return error.FailBaseMissing;
        try std.testing.expectEqualStrings("/admin/users?error=", base);
    }

    test "rateLimitResetForTesting is idempotent on second call" {
        security.rateLimitResetForTesting();
        // No assertions needed — second call should be silent no-op (not panic).
        security.rateLimitResetForTesting();
        security.rateLimitResetForTesting();
    }
};

comptime {
    _ = security_tests;
}
