//! Per-request tunables. All fields optional — `null` means "use
//! libcurl's default". Default `Options{}` therefore == "do exactly
//! what `curl -s URL` would".
//!
//! Field naming mirrors libcurl's `CURLOPT_*` so call sites read
//! 1:1 against the manual page.

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
        };
        try testing.expectEqual(@as(u32, 1500), opts.timeout_ms.?);
        try testing.expectEqual(@as(u32, 500), opts.connect_timeout_ms.?);
        try testing.expectEqual(true, opts.follow_redirects);
        try testing.expectEqual(@as(u16, 10), opts.max_redirects);
        try testing.expectEqualStrings("test/1.0", opts.user_agent);
        try testing.expectEqual(false, opts.verify_ssl);
    }
};

comptime {
    _ = options_tests;
}
