# kabelweb

> ⚠️ **WARNING: This repo is AI slop and experimental, DO NOT USE IN PRODUCTION!!!!!!** ⚠️

Unified Zig web-framework library: a pure-Zig HTTP **server** plus a
libcurl-backed HTTP **client** in one package. Zero Zig dependencies,
Zig `0.16.0` minimum.

```zig
const kabelweb = @import("kabelweb");
const server = kabelweb.server; // GinwaServer, Router, HttpRequest/Response, SSE/WS, Template, Cron, HTTP/2
const client = kabelweb.client; // Client, Request/Response, get/post/put/patch/delete, ResponseStream
```

What you get:

- **REST API** — `Router` + `Group`, `:params`, `?query`, JSON helpers, middleware
- **SSE** — `SseManager` (broadcast / typed events / per-client), chunked + keepalive
- **WebSocket** — RFC6455 handshake + frames (`ws_manager`, `sendToClient`, broadcast)
- **Templates** — Jinja-style engine (`{{ var }}`, `{% if/for/block/extends/include/macro/set/raw %}`, auto-escape)
- **Static HTML** — comptime-embedded pages + `read_html` file helper
- **Security** — CSRF HMAC, rate-limit, CORS, origin + body-size gates
- **Cron** — cron-expression scheduler + background jobs
- **HTTP/2** — h2c + TLS (OpenSSL) + HPACK
- **Client** — buffered `Client.perform()` + streaming `openStream` / `StreamScanner`

Demo server runs on `http://127.0.0.1:29590` (`zig build run`).

---

## Table of contents

- [Architecture](#architecture)
- [Layout](#layout)
- [Requirements / Install](#requirements--install)
- [Build & test](#build--test)
- [Add as dependency](#add-as-dependency)
- [Quickstart (server)](#quickstart-server)
- [REST API usage](#rest-api-usage)
- [SSE usage](#sse-usage)
- [WebSocket usage](#websocket-usage)
- [Templates usage](#templates-usage)
- [Static HTML usage](#static-html-usage)
- [Security / middleware / cron / HTTP-2](#security--middleware--cron--http-2)
- [Client usage](#client-usage)
- [Demo routes](#demo-routes)
- [Config reference](#config-reference)
- [Troubleshooting](#troubleshooting)
- [History](#history)

---

## Architecture

One package, two halves (`src/root.zig` re-exports both):

- `server` — pure Zig, no third-party deps (links system `ssl` + `crypto` only for TLS).
- `client` — libcurl-backed (`curl.zig`), links system `libcurl` or vendored fat `libcurl.a`.

```
                 ┌─ kabelweb (@import) ─────────────┐
                 │  src/root.zig                    │
                 │  server ────────┐  client ─────┐ │
                 └─────────────────┼──────────────┼─┘
                                   │              │ libcurl (system|vendor)
  ┌─ SERVER (pure Zig) ────────────┘              └─ CLIENT (curl.zig) ─┐
  │ GinwaServer (http_server.zig)                   Client.perform()    │
  │  Address:bind+listen (POSIX/ws2_32)             buffered Response   │
  │  Router/Group → MiddlewareChain → HandlerFn     openStream→worker   │
  │  Context/ContextStore (ctx cookie)              Request/Response/   │
  │  SseManager / WsManager / Cron / Template       Options/Method      │
  │  Stream (plain|TLS-OpenSSL) + CORS/CSRF/caps    mapCurlCode→Error   │
  │                                                                     │
  │  ┌─ Path A: listen() threaded ─┐  ┌─ Path B: listenEventLoop() ─┐   │
  │  │ accept → thread-per-conn    │  │ poll reactor (1 thread/loop)│   │
  │  │  ├─ H1 blocking serve       │  │  framing: headers+CL        │   │
  │  │  ├─ H2c preface→h2 driver   │  │  dispatch: direct ──────────┤   │
  │  │  └─ TLS+ALPN→h2|h1          │  │           │ worker_pool     │   │
  │  └─────────────────────────────┘  │           ▼                 │   │
  │                                   │   WorkerPool (ring+threads) │   │
  │                                   │  hijack: static-pool│SSE/WS │   │
  │                                   │   │dedicated thread │H2/TLS │   │
  │                                   └─────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────────┘
  Request flow: socket → [TLS?] → [h2c sniff?] → H1 frame → Router.match
    → preHandlerCheck → MiddlewareChain → Handler → respond|hijack → keep-alive/close
```

Key files and roles:

| Area | File | Role |
|---|---|---|
| Facade | `src/root.zig` | `@import("kabelweb")` → `server.*` + `client.*` + flat aliases (`GinwaServer`, `Router`, `Client`, `get/post/...`, `openStream`) |
| Server core | `src/server/http_server.zig` | `Address` (IPv4 bind, `SO_REUSEADDR`, Win `ws2_32`), `GinwaServer` (router/sse/ws/cron/context/csrf/cors/max_body/tls/h2c), `listen()` + `listenEventLoop()` |
| Reactor | `src/server/event_loop.zig` | Single-threaded `poll`/`WSAPoll` reactor, `DispatchResult{respond\|hijack_static\|hijack_sse\|hijack_ws}`, `Stats`, wake-fd |
| Pool | `src/server/worker_pool.zig` | Generic bounded pool (`thread_count 0=ncpu`, ring queue, `QueueFull`/`PoolStopped`) |
| Router | `src/server/router.zig` | `Router`/`Group`, `HandlerFn(ctx,req,res)`, `SseHandlerFn`, `WsHandlerFn(ctx,req,server,fd,id)`, `MiddlewareChain` (outer→inner, short-circuit). Registration order = match order. SSE/WS are always `GET`, no middleware |
| State | `src/server/context.zig` | `Context` map (`string\|int\|bool`) + `ContextStore` (`ctx=<id>` cookie) |
| SSE | `src/server/sse_manager.zig` | `broadcast(msg)`, `broadcastTyped(event,data)`, `sendToClient(id, frame)` |
| WS | `src/server/websocket_{handshake,frames,manager}.zig` | Upgrade (`101`), `parseFrame`/`encodeFrame` (`text/ping/pong/close`), `sendToClient`/`broadcast` |
| HTTP | `src/server/http_parser.zig` | `HttpRequest` (params/query/body/form), `HttpResponse` (`withBody/withJson/jsonResponse/withHeader/redirect`), `S.response.*` helpers |
| Templates | `src/server/template.zig` | Tokenize → parse → render, auto-escape on `{{ }}`, `{% raw %}` for verbatim |
| Static | `src/server/read_html.zig` | File → HTML string helper (demo uses comptime `@embedFile` instead) |
| Cron | `src/server/cron_expression.zig`, `cronjob_manager.zig` | Cron parsing + background scheduler |
| H2 | `src/server/http2/` | h2c + TLS (OpenSSL externs, no headers) + HPACK/huffman |
| Client | `src/client/client.zig`, `stream.zig`, `methods.zig`, `request.zig`, `response.zig`, `options.zig` | Buffered `perform()` + streaming `ResponseStream`/`StreamScanner`/`openStream`, verb helpers |
| Examples | `src/examples/server_demo.zig`, `client_smoke.zig` | Demo server (`/`, `/health`, `/hello`, `/users`, `/stream`, `/ws`, `/template`) + smoke CLI |

Threading model:

- `listenEventLoop()` — the only serve path (the old thread-per-connection `listen()` was deleted): 1 loop = 1 thread, non-blocking I/O only.
  - `.worker_pool` (default) — complete requests → `WorkerPool` threads; queue-full → inline fallback (counted). A slow handler stalls only its connection (loop allocator must be thread-safe).
  - `.direct` — dispatch on loop thread (low overhead, but a slow handler stalls every conn on the loop).
  - Long-lived/upgrades never block the loop: `hijack_static` → small static pool, `hijack_sse/ws` → dedicated thread/conn, H2-preface/TLS → hijack to H2/TLS worker. Reactor v1 returns `501` for SSE/WS/H2/TLS if unsupported.
  - Multi-loop ready: `loop_id/loop_count + SO_REUSEPORT`, `Stats.combine`.

---

## Layout

```text
src/
  root.zig        # facade — `server` + `client` namespaces + flat aliases
  server/         # HTTP server
    http_server.zig   # GinwaServer facade + re-exports
    router.zig        # Router/Group, matchRoute (registration order = match order)
    http_parser.zig   # HttpRequest/Response/Context/Session
    event_loop.zig    # poll reactor
    worker_pool.zig   # bounded thread pool
    security.zig      # CSRF HMAC, rate-limit, CORS, origin/body gates
    sse_manager.zig / websocket_*.zig / stream.zig / connection_reader.zig
    template.zig / read_html.zig / cron_*.zig / example_group.zig
    http2/            # h2c + TLS (OpenSSL) + HPACK
    templates/        # demo jinja layouts (base.jinja, example.jinja)
  client/         # HTTP client
    client.zig        # buffered Client.perform()
    stream.zig        # streaming ResponseStream/StreamScanner/openStream
    curl.zig / request.zig / response.zig / methods.zig / options.zig
    *_test.zig        # suites spin an in-process server (relative import, no network)
  examples/
    server_demo.zig   # demo server: landing page, /health, SSE /stream, WS /ws, /template
    client_smoke.zig  # `kabelweb-client-smoke <METHOD> <URL>` manual smoke CLI
    templates/        # embedded demo templates
scripts/
  build-vendor-curl.sh  # cross-compiles fat libcurl.a per target (curl 8.10.1 + OpenSSL 3.4.0)
  stub_libcurl.h/.c     # Windows dev-box no-op fallback
```

---

## Requirements / Install

Minimum **Zig 0.16.0** (`build.zig.zon`, zero Zig deps). No other Zig packages needed.

System libs are probed first (pure-Zig `fileExists`, no shell). When the host has
**all three** (`libcurl` + `libssl` + `libcrypto`) and target == host, system libs are
linked and the vendored archive is skipped. Partial installs fall back to vendor.

```sh
# Debian/Ubuntu
sudo apt install libcurl4-openssl-dev libssl-dev
# Arch / Fedora: curl-devel + openssl-devel equivalent
# macOS
brew install curl openssl@3
# Windows
vcpkg install curl:x64-windows openssl:x64-windows
```

Vendored fallback (hermetic, static):

- Built by `bash scripts/build-vendor-curl.sh` (~30 min first run).
- Layout: `vendor/curl/<target>/lib/libcurl.a` + `vendor/curl/<target>/include/curl/curl.h`
  where `<target>` = `linux-x86_64 | linux-aarch64 | macos-arm64 | macos-x86_64 | windows-amd64`.
- Fat archive = curl + ssl + crypto merged, wired via `addObjectFile` (not `-lcurl`).
- Force it: `zig build -Dforce-vendor=true ...`; custom dir: `-Dvendor-dir=...`.
- Windows with neither vcpkg nor vendor archive auto-generates a no-op stub from
  `scripts/stub_libcurl.*` (`curl_easy_init → NULL`, `perform → CURLE_FAILED_INIT`).

---

## Build & test

Run from the package root (`/home/ginwa/kabelweb`):

```sh
cd /home/ginwa/kabelweb
zig build test            # full: fast suites + 60s SSE soaks
zig build test-fast       # fast only, no soaks — what CI runs per-platform
zig build test-server     # server half only
zig build test-client     # client half only
zig build test -Dtest-filter=<substr>   # filter (Zig 0.16: no `-- --test-filter`)
zig build                 # build both example exes only
zig build run             # server demo → zig-out/bin/kabelweb-server-demo (port 29590)

# smoke client
zig-out/bin/kabelweb-client-smoke GET https://example.com
zig-out/bin/kabelweb-client-smoke GET http://127.0.0.1:29590/health

# server demo checks
curl -i http://127.0.0.1:29590/
curl http://127.0.0.1:29590/health       # -> OK
curl "http://127.0.0.1:29590/hello?name=World"
curl -N http://127.0.0.1:29590/stream    # SSE
```

Link model (`build.zig`): system probe first — when the host has
libcurl + libssl + libcrypto, link system libs; else embed the
vendored fat `vendor/curl/<target>/lib/libcurl.a`. The server half adds no new deps:
pure Zig + system ssl/crypto (hand-declared OpenSSL externs, no headers).

---

## Add as dependency

`build.zig.zon`:

```zig
.dependencies = .{
    .kabelweb = .{
        .url = "https://github.com/<org>/kabelweb/archive/<sha>.tar.gz",
        .hash = "<zig-fetch-hash>",
        // or local path during dev:
        // .path = "../kabelweb",
    },
},
```

`build.zig` consumer:

```zig
const kabelweb_dep = b.dependency("kabelweb", .{
    .target = target,
    .optimize = optimize,
    // .@"force-vendor" = true,      // optional hermetic
    // .@"vendor-dir" = "vendor/curl", // optional override
});
const kabelweb_mod = kabelweb_dep.module("kabelweb");
exe.root_module.addImport("kabelweb", kabelweb_mod);
// libc + curl/ssl/crypto include+link flags propagate via module graph.
```

---

## Quickstart (server)

```zig
const std = @import("std");
const S = @import("kabelweb").server;

pub fn main(init: std.process.Init) void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const addr = try S.Address.init("127.0.0.1", 29590);
    const gs = try S.GinwaServer.init(allocator, init.io, addr);
    defer gs.deinit();

    try gs.router.get("/health", healthH);
    try gs.router.get("/hello/:name", helloH);
    try gs.router.post("/users", createUserH);
    try gs.router.sse("/stream", sseH); // always GET
    try gs.router.ws("/ws", wsEchoH);   // always GET
    try gs.router.get("/template", templateH);

    // groups: prefix + inherited middleware
    var root = gs.router.group("");
    try root.use(requestIdMw);
    var api = try root.group("/api");
    var v1 = try api.group("/v1");
    try v1.get("/ping", pingH);
    try v1.post("/echo", echoH);

    try gs.listenEventLoop(.{}); // single reactor; .{ .loop_count = N } for REUSEPORT
}

fn healthH(_: S.HttpContext, req: S.HttpRequest, res: S.HttpResponse) !S.HttpResponse {
    _ = req;
    return res.withBody("OK");
}
```

Handler shape (all server handlers share it):

```zig
fn H(ctx: S.HttpContext, req: S.HttpRequest, res: S.HttpResponse) !S.HttpResponse
fn WsH(ctx: S.HttpContext, req: S.HttpRequest, server: *anyopaque, fd: i32, id: *[16]u8) !void // after 101
```

`ctx.allocator` is a per-request arena (no `free` needed). `req` is by-value, read-only.

---

## REST API usage

GET with query + path params:

```zig
fn helloH(ctx: S.HttpContext, req: S.HttpRequest, res: S.HttpResponse) !S.HttpResponse {
    const name = req.query.get("name") orelse req.params.get("name") orelse "HTTP";
    const text = try std.fmt.allocPrint(ctx.allocator, "Hello, {s}!", .{name});
    return res.withBody(text); // sets Content-Length
}
```

```sh
curl "http://127.0.0.1:29590/hello?name=World"
curl http://127.0.0.1:29590/hello/Alice   # :name via router
```

POST JSON body:

```zig
const User = struct { username: []const u8 = "", email: []const u8 = "" };

fn createUserH(ctx: S.HttpContext, req: S.HttpRequest, res: S.HttpResponse) !S.HttpResponse {
    const a = ctx.allocator;
    const u = std.json.parseFromSliceLeaky(User, a, req.body, .{}) catch
        return S.response.badRequest("Invalid user JSON", a);
    const out = try std.fmt.allocPrint(a,
        "{{\"username\":\"{s}\",\"email\":\"{s}\"}}", .{ u.username, u.email });
    return res.jsonResponse(.{ .status_code = 201, .data = out });
    // alt: res.withJson(out) (200) | res.withBody("OK")
}
```

```sh
curl -X POST http://127.0.0.1:29590/users \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com"}'
```

Response helpers (`http_parser.zig`): `withBody`, `withJson`,
`jsonResponse(.{ .status_code, .data })`, `withHeader(k,v)`, `setContentType(ct)`,
`redirect("/path").withSecurityHeaders()`, `S.response.ok/created/badRequest/notFound/internalError`.
Form bodies: `const f = try req.form(LoginForm, a);` (all-`[]const u8` struct + `deinit`).

Middleware (outer → inner, short-circuit on error):

```zig
fn requestIdMw(ctx: S.HttpContext, req: S.HttpRequest, res: S.HttpResponse, next: *S.MiddlewareChain) !S.HttpResponse {
    _ = req;
    const id = try std.fmt.allocPrint(ctx.allocator, "{d}", .{std.time.milliTimestamp()});
    try ctx.put("request_id", .{ .string = id });
    var out = try next.next(ctx, req, res);
    out = out.withHeader("X-Request-Id", id);
    return out;
}
// try group.use(requestIdMw);
// try router.getWithOpts("/secure", h, .{ .middlewares = &.{authMw}, .max_body_bytes = 1 << 20 });
```

---

## SSE usage

Register (always `GET`, no middleware):

```zig
try gs.router.sse("/stream", sseH);

fn sseH(ctx: S.HttpContext, req: S.HttpRequest, res: S.HttpResponse) !S.HttpResponse {
    _ = ctx; _ = req; _ = res;
    return error.WouldBlock; // hijack: SseManager owns fd after handshake
}
```

Push from anywhere (handler / cron / thread):

```zig
try gs.sse_manager.broadcast("hello all");                        // -> data: hello all\n\n
try gs.sse_manager.broadcastTyped("connected", "{\"ok\":true}");  // -> event: connected\ndata: ...
try gs.sse_manager.sendToClient(client_id, "data: hi\n\n");       // raw chunked frame
```

Browser (`EventSource`):

```js
const src = new EventSource('/stream');
src.addEventListener('connected', e => console.log(e.data));
src.addEventListener('message', e => console.log(e.data));
src.onerror = () => console.log('sse error');
```

```sh
curl -N http://127.0.0.1:29590/stream
```

Streaming client (buffered client can't hold SSE open):

```zig
var c = S.Client.init(allocator);
var stream = try c.openStream(io, .{ .method = .GET, .url = "http://127.0.0.1:29590/stream" }, .{});
defer stream.deinit();
var sc = S.StreamScanner.init(&stream, true); // skip_empty=true skips heartbeats
defer sc.deinit();
while (try sc.next()) |line| { /* "data: ..." / "event: ..." per line */ }
```

---

## WebSocket usage

Register (always `GET`):

```zig
try gs.router.ws("/ws", wsEchoH);
```

Echo + ping/pong + broadcast (RFC6455 §5.5.3: pong must echo ping payload):

```zig
const ws_frames = S.ws_frames;

fn wsEchoH(ctx: S.HttpContext, req: S.HttpRequest, srv_p: *anyopaque, fd: i32, id: *[16]u8) !void {
    _ = req; _ = id;
    const srv: *S.GinwaServer = @ptrCast(@alignCast(srv_p));
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = srv.recvFromClient(fd, &buf) catch return;
        if (n == 0) return;
        var f = try ws_frames.parseFrame(ctx.allocator, buf[0..n]);
        defer f.deinit(ctx.allocator);
        switch (f.opcode) {
            .text => {
                const echo = try ws_frames.encodeFrame(ctx.allocator, .{ .opcode = .text, .payload = f.payload });
                defer ctx.allocator.free(echo);
                _ = srv.sendToClient(fd, echo) catch return;
                if (std.mem.startsWith(u8, f.payload, "/broadcast "))
                    try srv.ws_manager.broadcast(f.payload["/broadcast ".len..]);
            },
            .ping => {
                const pong = try ws_frames.encodeFrame(ctx.allocator, .{ .opcode = .pong, .payload = f.payload });
                defer ctx.allocator.free(pong);
                _ = srv.sendToClient(fd, pong) catch return;
            },
            .close => return, // server sends close frame on return
            else => {},
        }
    }
}
// targeted: try gs.ws_manager.sendToClient(&client_id, "hi one");
```

Browser:

```js
const ws = new WebSocket('ws://127.0.0.1:29590/ws');
ws.onmessage = e => console.log(e.data);
ws.onopen = () => ws.send('hello');
ws.send('/broadcast hello all');
```

Test with `websocat` / `wscat`:

```sh
websocat ws://127.0.0.1:29590/ws
```

---

## Templates usage

Engine: tokenize → parse → render. Compiled once, rendered many times.
Auto-escape is **ON** for `{{ var }}`; use `{% raw %}...{% endraw %}` for verbatim HTML.

Supported:

- `{{ var }}` — substitution, HTML-escaped
- `{{ a.b.c }}` / `{{ x[0] }}` — dotted + bracket paths
- `{{ name(arg1, arg2) }}` — macro call
- `{% if cond %}...{% elif %}...{% else %}...{% endif %}`
- `{% for x in items %}...{% empty %}...{% endfor %}` (+ `{% for x in items if cond %}` filter, `loop.index`)
- `{% raw %}...{% endraw %}`, `{# comment #}` (dropped)
- `{% extends "parent.jinja" %}` + `{% block name %}...{% endblock %}`
- `{% include "partial.html" %}` (`with context` / `without context`, `ignore missing`)
- `{% set var = expr %}`, `{% macro name(p1, p2=default) %}...{% endmacro %}`

No filters, no whitespace control, no `set` beyond the above.

`base.jinja` (layout):

```jinja
<title>{% block title %}GinwaServer Demo{% endblock %}</title>
<div class="container">
  {% block content %}{% endblock %}
</div>
```

`example.jinja` (child):

```jinja
{% extends "base.jinja" %}
{% block content %}
<h1>Jinja-Style Templating Demo</h1>
<ul>
{% for f in features %}
  <li><h2>{{ f.name }}</h2><p>{{ f.description }}</p></li>
{% endfor %}
</ul>
{% if show_extra %}
  <p>Bonus section — show_extra is true.</p>
  <p>Raw: {% raw %}{{ not a variable }}{% endraw %}</p>
{% else %}
  <p>Bonus hidden. Set show_extra=true to reveal it.</p>
{% endif %}
<div>Build: {{ build_sha }} | Started: {{ started_at }}</div>
{% endblock %}
```

Render in a handler (production: pre-compile once at startup, fresh context per request):

```zig
const EXAMPLE_TEMPLATE = @embedFile("templates/example.jinja");
const BASE_TEMPLATE = @embedFile("templates/base.jinja");

const Loader = struct {
    fn load(_: *anyopaque, a: std.mem.Allocator, path: []const u8) anyerror![]u8 {
        if (std.mem.eql(u8, path, "example.jinja")) return a.dupe(u8, EXAMPLE_TEMPLATE);
        if (std.mem.eql(u8, path, "base.jinja")) return a.dupe(u8, BASE_TEMPLATE);
        return error.TemplateNotFound;
    }
};

fn templateH(ctx: S.HttpContext, req: S.HttpRequest, res: S.HttpResponse) !S.HttpResponse {
    _ = req;
    var loader = Loader{};
    const nodes = S.Template.compileWithParent(ctx.allocator, EXAMPLE_TEMPLATE, @ptrCast(&loader), &Loader.load)
        catch |err| return S.response.internalError(@errorName(err), ctx.allocator);
    defer S.Template.freeNodes(ctx.allocator, nodes);

    var tctx = S.Template.Context.init(ctx.allocator);
    defer tctx.deinit();
    try tctx.put("build_sha", .{ .string = "146df72d" });
    try tctx.put("started_at", .{ .string = "2026-08-06" });
    try tctx.put("show_extra", .{ .bool = true });
    // array of maps for {% for f in features %}:
    // try tctx.put("features", .{ .array = &arr }); // arr: []Template.Value{.map = ...}

    return res.withRender(nodes, &tctx); // body + Content-Length + text/html
}
```

```sh
curl http://127.0.0.1:29590/template
```

---

## Static HTML usage

Canonical pattern (demo `GET /`): comptime string → per-request arena dup → `text/html`:

```zig
const LANDING_PAGE_HTML = @embedFile("index.html"); // or inline \\ string

fn landingH(ctx: S.HttpContext, req: S.HttpRequest, res: S.HttpResponse) !S.HttpResponse {
    _ = req;
    const body = ctx.allocator.dupe(u8, LANDING_PAGE_HTML) catch
        return S.response.internalError("Failed to allocate HTML body", ctx.allocator);
    var out = res.withBody(body);
    out.headers.put("Content-Type", "text/html; charset=utf-8") catch
        return S.response.internalError("Failed to set Content-Type", ctx.allocator);
    return out;
}
```

File helper alternative: `read_html.zig` (`readHtml(allocator, path)`).

---

## Security / middleware / cron / HTTP-2

Security (`security.zig`):

```zig
// CORS + body cap per route
try gs.router.getWithOpts("/api/data", h, .{
    .cors = .{ .allowed_origins = &.{ "https://example.com" } },
    .max_body_bytes = 1 << 20, // 413 when exceeded
});
// CSRF HMAC, rate-limit, origin gate — see security.zig + example_group.zig
```

Cron (`cron_expression.zig` + `cronjob_manager.zig`):

```zig
// "*/30 * * * * *" — every 30s; push into SSE/WS from the job
try gs.cron.add("*/30 * * * * *", cronTick, null);
fn cronTick(_: ?*anyopaque) void {
    gs.sse_manager.broadcast("tick") catch {};
}
```

HTTP/2 + TLS:

```zig
// h2c (cleartext, opt-in) + TLS via OpenSSL
// try gs.enable_h2c();
// try gs.enableTls(cert_path, key_path); // ALPN `h2` → http2/server.zig, else H1
```

---

## Client usage

Buffered (one `Client` per worker — thread-unsafe):

```zig
const C = @import("kabelweb").client;
var cli = C.Client.init(allocator);
const resp = try C.get(&cli, "http://127.0.0.1:29590/health", .{});
defer resp.deinit(allocator); // MUST call once
// POST: try C.post(&cli, url, body, &.{.{ .name = "Content-Type", .value = "application/json" }}, .{});
// put/patch/delete + C.Request{ .method, .url, .headers, .body } + C.Options{ .timeout_ms, .follow_redirects, .max_body }
```

Streaming (SSE / large bodies):

```zig
var stream = try cli.openStream(io, .{ .method = .GET, .url = "http://127.0.0.1:29590/stream" }, .{});
defer stream.deinit();
var sc = C.StreamScanner.init(&stream, true);
defer sc.deinit();
while (try sc.next()) |line| { std.debug.print("{s}\n", .{line}); }
```

Smoke CLI:

```sh
zig-out/bin/kabelweb-client-smoke GET https://example.com
```

---

## Demo routes

`zig build run` → `http://127.0.0.1:29590`:

| Method | Path | Handler | Try it |
|---|---|---|---|
| GET | `/` | Static landing page (comptime HTML + live SSE demo) | `curl -i http://127.0.0.1:29590/` |
| GET | `/health` | `OK` | `curl http://127.0.0.1:29590/health` |
| GET | `/hello?name=X` | Query greeting | `curl "http://127.0.0.1:29590/hello?name=World"` |
| GET | `/hello/:name` | Path-param greeting | `curl http://127.0.0.1:29590/hello/Alice` |
| POST | `/users` | JSON create → `201` | `curl -X POST .../users -H "Content-Type: application/json" -d '{"username":"alice"}'` |
| SSE | `/stream` | `SseManager` + heartbeats | `curl -N http://127.0.0.1:29590/stream` |
| WS | `/ws` | Echo + `/broadcast` | `websocat ws://127.0.0.1:29590/ws` |
| GET | `/template` | Jinja render (`example.jinja` → `base.jinja`) | `curl http://127.0.0.1:29590/template` |

Flags: `zig build run -- --pool N --loops N` (worker pool size / REUSEPORT loop count).

---

## Config reference

Event loop (`event_loop.zig` `Config`): `max_conns`, `idle_timeout`, `header_timeout`,
`max_request_bytes` (default 8 MB), `max_requests_per_conn` (default 1000),
`loop_id/loop_count`, `tls/h2c`, `dispatch_mode (.worker_pool default / .direct)`.

Worker pool (`worker_pool.zig` `Config`): `thread_count` (`0` = ncpu, min 2),
`queue_depth`, `stack 8MB`. `submit` is non-blocking (`QueueFull` → inline fallback).

Router: registration order = match order. `Group{prefix, middlewares, max_body_bytes}`.
Snapshot semantics; `*WithOpts` for CORS/body gate.

---

## Troubleshooting

- `zig build test` fails on curl link → install system libs above, or `zig build -Dforce-vendor=true`.
- Windows without vcpkg/vendor → stub libcurl compiles but every client call returns `CURLE_FAILED_INIT` (expected).
- `413` → `max_body_bytes` exceeded; raise via `getWithOpts` / group.
- `501` in reactor → SSE/WS/H2/TLS not enabled on that loop; use `listen()` or enable hijack path.
- Template `500` → check stderr: every `ParseError` prints `template:<line>:<column>` + source line + caret.
- SSE stalls behind proxy → ensure chunked + no buffering (`curl -N`, `X-Accel-Buffering: no`).

---

## History

Merges `src/modules/custom_http_server/` + `src/modules/custom_http_client/`
(hard `git mv` — `git log --follow` tracks origins). The pre-merge
docs are kept as `docs-server-README.md`, `docs-client-README.md`,
`docs-client-NALAR.md`, `docs-client-CLAUDE.md`.
