

// Test runner for kabelweb's server half.
//
// Runs every server test EXCEPT two files:
//   - `sse_chunked_test.zig` — registered by kabelweb's lib root
//     (src/root.zig) instead, so both the package's own build and the
//     repo-root gate cover it.
//   - `read_html_test.zig` — parent-only (imports nalarcore's
//     src/root.zig, which would be a package cycle from here). The
//     repo root re-imports it directly.
//   - `sse_keepalive_test.zig` (2×60 s soaks) — registered by
//     src/full_test.zig, which is the root of this package's own
//     `zig build test`. The repo-root gate (via kabelweb's lib root)
//     skips the soaks so `zig build test` stays fast.
//
// To exercise everything (including soaks), run:
//
//   cd src/modules/kabelweb && zig build test --summary all
const std = @import("std");
const builtin = @import("builtin");

test {
    _ = @import("test_helpers.zig"); // Compile-only — ensures the cross-platform helpers stay in sync.
    _ = @import("http_server_test.zig");
    _ = @import("sse_manager_test.zig");
    _ = @import("router_test.zig");
    _ = @import("http_parser_test.zig");
    // sse_chunked_test.zig lives in kabelweb's lib root (src/root.zig)
    // so both this package's build and the repo-root gate cover it.
    _ = @import("test_session_lifecycle.zig");
    _ = @import("complex_cases_test.zig");
    _ = @import("complex_cases_extra_test.zig");
    _ = @import("main_static_html_test.zig");
    // NOTE: sse_keepalive_test.zig (2×60 s soaks) is intentionally NOT
    // here — it runs via src/full_test.zig (this package's own
    // `zig build test`) so the repo-root gate stays fast.
    // WebSocket support (RFC 6455) — frames, handshake, manager
    _ = @import("websocket_frames_test.zig");
    _ = @import("websocket_handshake_test.zig");
    _ = @import("websocket_manager_test.zig");
    // Jinja-style template engine — tokenizer, parser, renderer, inheritance
    _ = @import("template_test.zig");
    // Security primitives — CSRF, rate limit, security headers, origin, body size
    _ = @import("security_test.zig");
    // Jinja-style template engine — tokenizer, parser, renderer, inheritance
    _ = @import("template_test.zig");
    // readHtml helper — read template file with embedded-source fallback.
    // Parent-only: read_html_test.zig imports nalarcore's src/root.zig
    // (a package cycle from here). The repo root re-imports it directly.
    // _ = @import("read_html_test.zig");
    // Per-request Context value bag + HttpResponse.redirectWithContext
    _ = @import("context_test.zig");
    // Cronjob manager — pure-function parser + scheduler unit tests (no thread)
    _ = @import("cron_expression_test.zig");
    // Cronjob manager — registry + thread start/stop tests
    _ = @import("cronjob_manager_test.zig");
    // Group + middleware worked example — registers a sample API on a
    // Router (groups, nested groups, two middlewares) and runs a
    // series of tests that exercise prefix joining, middleware chain
    // ordering, header augmentation, and short-circuiting. Doubles
    // as living documentation for the Router.group / Group.use API.
    _ = @import("example_group.zig");

    // HTTP/2 (h2c) subsystem — frame/settings/HPACK/stream/flow-control unit
    // tests. The aggregator imports each implementation file, which in turn
    // pulls its own sibling `*_test.zig`. This MUST also be registered in
    // `src/root.zig`'s test block, otherwise the CI gate skips these tests.
    _ = @import("http2/test_runner.zig");
    // Peekable connection buffer — the piece that lets the server sniff the h2
    // preface BEFORE the HTTP/1.1 request reader consumes it.
    _ = @import("connection_reader.zig");
    // Transport abstraction (plain socket | TLS). Its own tests cover short
    // writes, EOF and the TLS op-table dispatch.
    _ = @import("stream.zig");
    // TLS + ALPN (OpenSSL) and the self-signed certificate generator. Importing
    // `tls.zig` pulls `tls_cert.zig`'s tests through `tls_test.zig`.
    _ = @import("http2/tls.zig");
}
