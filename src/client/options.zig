//! Per-request tunables. All fields optional — `null` means "use
//! libcurl's default". Default `Options{}` therefore == "do exactly
//! what `curl -s URL` would".
//!
//! Field naming mirrors libcurl's `CURLOPT_*` so call sites read
//! 1:1 against the manual page.

const curl = @import("curl.zig");

pub const Options = struct {
    /// Total time for the transfer, in milliseconds.
    /// Maps to `CURLOPT_TIMEOUT_MS`.
    timeout_ms: ?u32 = null,

    /// Connect-only timeout (ms). Maps to `CURLOPT_CONNECTTIMEOUT_MS`.
    connect_timeout_ms: ?u32 = null,

    /// Follow `3xx` Location responses. Default: false (matches
    /// the old `HttpClient.zig` "no redirect" shell-curl behaviour).
    follow_redirects: bool = false,

    /// Caps the redirect count when `follow_redirects = true`.
    /// Maps to `CURLOPT_MAXREDIRS`. Default: 5 (libcurl's unbounded
    /// when not set; we cap to a sensible value here).
    max_redirects: u16 = 5,

    /// Override the User-Agent header. Empty → "custom_http_client/0.1.0".
    user_agent: []const u8 = "",

    /// Verify the server's TLS certificate (default `true`).
    verify_ssl: bool = true,

    /// Continue the handshake when the certificate revocation check
    /// cannot be *made* — an unreachable CRL / OCSP endpoint — instead
    /// of failing the whole connection. Maps to libcurl's
    /// `CURLSSLOPT_REVOKE_BEST_EFFORT` in `CURLOPT_SSL_OPTIONS`
    /// (schannel-only; other backends ignore the bit).
    ///
    /// Default `true`, because the alternative is a hard failure the
    /// caller cannot tell apart from "the server is down". The case that
    /// matters in practice is Windows: libcurl's schannel backend does
    /// the revocation check inline in the handshake, so a box that
    /// cannot reach the CA's revocation servers — corporate network,
    /// blocked `crl.*`/OCSP, no proxy for the chain engine — fails with
    /// `CRYPT_E_REVOCATION_OFFLINE` (CURLE 35) on *every* HTTPS request.
    /// Linux/macOS builds link an OpenSSL-backed curl, which never
    /// fetches a CRL, so they never see it.
    ///
    /// This does not weaken trust: the chain and the revocation check
    /// both still run — only "the answer is unknown" stops being fatal.
    /// Set `false` for a strict caller that wants an unreachable
    /// revocation server to abort the connection.
    revoke_best_effort: bool = true,

    /// Max buffered response body in `Client.perform` (bytes).
    /// Prevents OOM on large downloads — use `openStream` for those.
    /// Default 10 MiB. `null` = unbounded (legacy).
    max_body_bytes: ?usize = 10 * 1024 * 1024,

    /// Max response headers in `Client.perform`. Default 100.
    max_headers: usize = 100,

    /// Max total header bytes (name+value) in `Client.perform`.
    /// Default 32 KiB.
    max_header_bytes: usize = 32 * 1024,

    /// Max URL length (bytes). Default 8 KiB.
    max_url_bytes: usize = 8 * 1024,

    /// The value this request hands to libcurl's `CURLOPT_SSL_OPTIONS`.
    ///
    /// One function called by both `CURLOPT_SSL_OPTIONS` sites —
    /// `client.zig`'s buffered `perform` and `stream.zig`'s `openStream`
    /// — so the two paths cannot drift. (The streaming path is what an
    /// agent's LLM calls use; a fix applied to only one of them is how
    /// this class of bug ships half-applied.)
    ///
    /// Zero means "relax nothing": `verify_ssl = false` already turns
    /// verification — and with it revocation — off outright, and
    /// `revoke_best_effort = false` asks for libcurl's strict default.
    pub fn sslOptions(self: Options) c_long {
        if (!self.verify_ssl) return 0;
        return if (self.revoke_best_effort) curl.SSLOPT.REVOKE_BEST_EFFORT else 0;
    }
};

// ============================================================================
// Tests — moved here from `options_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = options_tests; }` below pulls them into the run.
// ============================================================================

const options_tests = struct {
    const std = @import("std");
    const testing = std.testing;
    const custom_http_client = @import("root.zig");

    test "Options defaults match libcurl's 'do nothing special' baseline" {
        const opts: custom_http_client.Options = .{};
        try testing.expectEqual(@as(?u32, null), opts.timeout_ms);
        try testing.expectEqual(@as(?u32, null), opts.connect_timeout_ms);
        try testing.expectEqual(false, opts.follow_redirects);
        try testing.expectEqual(@as(u16, 5), opts.max_redirects);
        try testing.expectEqualStrings("", opts.user_agent);
        try testing.expectEqual(true, opts.verify_ssl);
    }

    test "Options can be constructed with one-of-each field set" {
        const opts: custom_http_client.Options = .{
            .timeout_ms = 1500,
            .connect_timeout_ms = 500,
            .follow_redirects = true,
            .max_redirects = 10,
            .user_agent = "test/1.0",
            .verify_ssl = false,
            .revoke_best_effort = false,
        };
        try testing.expectEqual(@as(u32, 1500), opts.timeout_ms.?);
        try testing.expectEqual(@as(u32, 500), opts.connect_timeout_ms.?);
        try testing.expectEqual(true, opts.follow_redirects);
        try testing.expectEqual(@as(u16, 10), opts.max_redirects);
        try testing.expectEqualStrings("test/1.0", opts.user_agent);
        try testing.expectEqual(false, opts.verify_ssl);
        try testing.expectEqual(false, opts.revoke_best_effort);
    }

    test "sslOptions: best-effort revocation is the default, and is not NO_REVOKE" {
        // The Windows regression this guards: a default `Options{}` must
        // ask libcurl to tolerate an unreachable CRL/OCSP endpoint.
        // Without the bit, schannel hard-fails the handshake
        // (CRYPT_E_REVOCATION_OFFLINE -> CURLE 35) on every HTTPS call.
        try testing.expectEqual(curl.SSLOPT.REVOKE_BEST_EFFORT, (custom_http_client.Options{}).sslOptions());
        // Best-effort keeps the revocation check; NO_REVOKE drops it.
        // Shipping the wrong bit would silently disable revocation.
        try testing.expect(curl.SSLOPT.REVOKE_BEST_EFFORT != curl.SSLOPT.NO_REVOKE);
    }

    test "sslOptions: strict revocation is the opt-out; verify_ssl=false relaxes nothing" {
        try testing.expectEqual(@as(c_long, 0), (custom_http_client.Options{ .revoke_best_effort = false }).sslOptions());
        // verify_ssl=false already turns verification — and revocation
        // with it — off entirely, so the option carries no bits either way.
        try testing.expectEqual(@as(c_long, 0), (custom_http_client.Options{ .verify_ssl = false }).sslOptions());
        try testing.expectEqual(@as(c_long, 0), (custom_http_client.Options{ .verify_ssl = false, .revoke_best_effort = false }).sslOptions());
    }
};

comptime {
    _ = options_tests;
}
