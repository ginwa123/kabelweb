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
// server/test_runner.zig covers every server suite EXCEPT the 60 s SSE
// soaks (see full_test.zig) and sse_chunked_test.zig (parent-only
// history — now same-package, so registered here). The client suites
// spin an in-process server via a relative ../server import — no
// cross-package dep needed.
test {
    _ = @import("server/test_runner.zig");
    _ = @import("server/sse_chunked_test.zig");
    _ = @import("client/root.zig");
}
