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
