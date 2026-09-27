//! kabelweb — unified Zig web-framework library.
//!
//! One package, two halves:
//!   - `server` — pure-Zig HTTP server (GinwaServer, Router, SSE/WS,
//!     Template, Cron, HTTP/2). No third-party deps; links c + ssl +
//!     crypto for the OpenSSL server-side TLS.
//!   - `client` — libcurl-backed HTTP client (Client, Request/Response,
//!     streaming SSE scanner). Links system libcurl when the host has
//!     it, else the vendored fat `libcurl.a`.
//!
//! Consumers import this file as `@import("kabelweb")`:
//!
//! ```zig
//! const kabelweb = @import("kabelweb");
//! const server = kabelweb.server; // GinwaServer, Router, HttpRequest, …
//! const client = kabelweb.client; // Client, Request, Response, get/post, …
//! ```

pub const server = @import("server/http_server.zig");
pub const client = @import("client/root.zig");

// Flat aliases for the 90% case — the names most call sites reach for.
pub const GinwaServer = server.GinwaServer;
pub const Router = server.Router;
pub const Group = server.Group;
pub const HandlerFn = server.HandlerFn;
pub const MiddlewareFn = server.MiddlewareFn;
pub const MiddlewareChain = server.MiddlewareChain;
pub const HttpRequest = server.HttpRequest;
pub const HttpResponse = server.HttpResponse;
pub const HttpContext = server.HttpContext;
pub const Session = server.Session;
pub const Context = server.Context;
pub const ContextStore = server.ContextStore;
pub const SseManager = server.SseManager;
pub const WsManager = server.WsManager;
pub const CronjobManager = server.CronjobManager;
pub const Template = server.Template;

pub const Client = client.Client;
pub const Request = client.Request;
pub const Response = client.Response;
pub const Method = client.Method;
pub const Header = client.Header;
pub const Options = client.Options;
pub const ClientError = client.Error;
pub const ResponseStream = client.ResponseStream;
pub const StreamScanner = client.StreamScanner;
pub const openStream = client.openStream;
pub const get = client.get;
pub const post = client.post;
pub const put = client.put;
pub const patch = client.patch;
pub const delete = client.delete;

// ----- Tests (fast set — the root `zig build test` gate runs these) -----
//
// Tests are CO-LOCATED with the code they cover: every implementation file
// under `src/` carries its own `test { ... }` blocks (the separate
// `*_test.zig` files that used to hold them were merged into those files and
// deleted). Zig only runs tests it can reach, so this block imports every
// implementation file that owns tests.
//
// Every build step compiles this same root; they differ only in the test-name
// filter and environment:
//   - `zig build test`        → everything, including the 2×60 s SSE soaks
//                               (sets KABELWEB_SOAK=1 for the run)
//   - `zig build test-fast`   → everything except the soaks (they self-skip
//                               via `error.SkipZigTest` while KABELWEB_SOAK
//                               is unset)
//   - `zig build test-server` → server suites only   (filter `server.`)
//   - `zig build test-client` → client suites only   (filter `client.`)
test {
    // --- server: HTTP core ---
    _ = @import("server/http_server.zig");
    _ = @import("server/http_parser.zig");
    _ = @import("server/router.zig");
    _ = @import("server/context.zig");
    _ = @import("server/security.zig");
    _ = @import("server/stream.zig");
    _ = @import("server/read_html.zig");
    _ = @import("server/template.zig");
    _ = @import("server/connection_reader.zig");
    _ = @import("server/event_loop.zig");
    _ = @import("server/worker_pool.zig");
    // Group + middleware worked example (also living documentation).
    _ = @import("server/example_group.zig");
    // --- server: SSE (the soak tests in here need KABELWEB_SOAK=1) ---
    _ = @import("server/sse_manager.zig");
    // --- server: cron ---
    _ = @import("server/cron_expression.zig");
    _ = @import("server/cronjob_manager.zig");
    // --- server: WebSocket (RFC 6455) ---
    _ = @import("server/websocket_frames.zig");
    _ = @import("server/websocket_handshake.zig");
    _ = @import("server/websocket_manager.zig");
    // --- server: HTTP/2 (h2c) ---
    _ = @import("server/http2/constants.zig");
    _ = @import("server/http2/frame.zig");
    _ = @import("server/http2/huffman.zig");
    _ = @import("server/http2/hpack.zig");
    _ = @import("server/http2/settings.zig");
    _ = @import("server/http2/stream.zig");
    _ = @import("server/http2/flow_control.zig");
    _ = @import("server/http2/connection.zig");
    _ = @import("server/http2/server.zig");
    // TLS + ALPN (OpenSSL) and the self-signed certificate generator.
    _ = @import("server/http2/tls.zig");
    _ = @import("server/http2/tls_cert.zig");
    // --- client (libcurl-backed; the suites spin up an in-process server) ---
    _ = @import("client/client.zig");
    _ = @import("client/methods.zig");
    _ = @import("client/request.zig");
    _ = @import("client/response.zig");
    _ = @import("client/stream.zig");
    _ = @import("client/curl.zig");
    _ = @import("client/options.zig");
}
