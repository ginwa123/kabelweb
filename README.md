# kabelweb

Unified Zig web-framework library: a pure-Zig HTTP **server** plus a
libcurl-backed HTTP **client** in one package.

```zig
const kabelweb = @import("kabelweb");
const server = kabelweb.server; // GinwaServer, Router, HttpRequest/Response, SSE/WS, Template, Cron, HTTP/2
const client = kabelweb.client; // Client, Request/Response, get/post/put/patch/delete, ResponseStream
```

## Layout

```text
src/
  root.zig        # facade — `server` + `client` namespaces + flat aliases
  server/         # HTTP server (moved from custom_http_server/src/)
    http_server.zig   # GinwaServer facade + re-exports
    router.zig        # Router/Group, matchRoute (registration order = match order)
    http_parser.zig   # HttpRequest/Response/Context/Session
    security.zig      # CSRF HMAC, rate-limit, CORS, origin/body gates
    sse_manager.zig / websocket_*.zig / stream.zig / connection_reader.zig
    template.zig / read_html.zig / cron_*.zig / example_group.zig
    http2/            # h2c + TLS (OpenSSL) + HPACK
    templates/        # demo jinja layouts
  client/         # HTTP client (moved from custom_http_client/src/)
    client.zig        # buffered Client.perform()
    stream.zig        # streaming ResponseStream/StreamScanner/openStream
    curl.zig / request.zig / response.zig / methods.zig / options.zig
    *_test.zig        # suites spin an in-process server (relative import, no network)
  examples/
    server_demo.zig   # demo server: landing page, /health, SSE /stream, WS /ws, /template
    client_smoke.zig  # `kabelweb-client-smoke <METHOD> <URL>` manual smoke CLI
scripts/build-vendor-curl.sh  # cross-compiles fat libcurl.a per target
scripts/stub_libcurl.*        # Windows dev-box no-op fallback
```

## Build

```sh
cd src/modules/kabelweb
zig build test            # server + client suites
zig build run             # server demo
zig-out/bin/kabelweb-client-smoke GET https://example.com
```

Link model (see `build.zig`): system probe first — when the host has
libcurl + libssl + libcrypto, link system libs; else embed the
vendored fat `vendor/curl/<target>/lib/libcurl.a` (curl + ssl +
crypto merged, hermetic). The server half adds no new deps: pure Zig
+ system ssl/crypto (hand-declared OpenSSL externs, no headers).

## History

Merges `src/modules/custom_http_server/` + `src/modules/custom_http_client/`
(hard `git mv` — `git log --follow` tracks origins). The pre-merge
docs are kept as `docs-server-README.md`, `docs-client-README.md`,
`docs-client-NALAR.md`, `docs-client-CLAUDE.md`.
