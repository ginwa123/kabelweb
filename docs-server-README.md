# Custom HTTP Server

A lightweight, pure Zig HTTP server implementation with routing, SSE support, WebSocket support, and JSON handling.

## Features

- **HTTP Server**: Pure Zig implementation using low-level POSIX sockets
- **HTTP/2 (h2c, opt-in)**: cleartext HTTP/2 on the same port, negotiated per
  connection by sniffing the 24-byte preface. Off by default (`--http2 h2c`).
  Frames, HPACK, multiplexing and flow control are implemented natively in Zig —
  no new dependencies. Browsers are unaffected (they need TLS + ALPN, which this
  server does not provide). See `docs/http2.md`.
- **Routing**: RESTful routing with path parameters (e.g., `/hello/:name`)
- **SSE (Server-Sent Events)**: Built-in SSE manager with heartbeat and broadcasting
- **WebSocket**: RFC 6455 WebSocket transport with frame parsing/encoding, handshake, and a client manager (broadcast + targeted send)
- **JSON Handling**: JSON request/response parsing and generation
- **Concurrent**: Per-connection request handling with arena allocators
- **Cross-Platform**: Linux, macOS, BSD, and Windows support

## Quick Start

### Build and Run

```bash
zig build run
```

### Test Endpoints

```bash
# Static HTML landing page (open in a browser for the demo)
curl -i http://127.0.0.1:29590/
# → Returns: HTTP/1.1 200 OK
#            Content-Type: text/html; charset=utf-8
#            <html lang="en"><head>... (a styled, self-contained page
#            documenting every other endpoint below)

# Health check (plain text — suitable for load balancers)
curl http://127.0.0.1:29590/health
# → Returns: OK

# Query parameters
curl "http://127.0.0.1:29590/hello?name=World&greeting=Hello&mood=happy"
# → Returns: Hello, World! (greeting: Hello, mood: happy)

# Path parameters
curl http://127.0.0.1:29590/hello/Alice
# → Returns: Hello, Alice! (greeting: hello, mood: neutral)

# Create user (POST JSON)
curl -X POST http://127.0.0.1:29590/users \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com"}'
# → Returns: {"username":"alice","email":"alice@example.com"}

# SSE streaming
curl http://127.0.0.1:29590/stream
# → Receives server-sent events with heartbeat pings

# WebSocket echo + broadcast (use any WS client)
# wscat -c ws://127.0.0.1:29590/ws
# > hello                           # → echoed back
# > /broadcast ping from one client  # → broadcast to every connected client
```

### Static HTML in `main.zig`

`GET /` serves a real HTML page (`text/html; charset=utf-8`) compiled
into the binary as a comptime string constant (`LANDING_PAGE_HTML`).
The page is self-contained — inline CSS, inline JavaScript, no external
assets — and demonstrates every server feature:

* A styled "Endpoints" table with curl examples for each route.
* A live SSE demo using the browser's `EventSource` API to subscribe
  to `/stream` and render the last 5 events received.

To add the same pattern to your own server, copy the
`landingPageHandler` function from `src/main.zig`. It:

1. Calls `ctx.allocator.dupe(u8, LANDING_PAGE_HTML)` to copy the
   comptime constant into the per-request arena.
2. Calls `res.withBody(body)` to set the body and `Content-Length`.
3. Sets `Content-Type: text/html; charset=utf-8` explicitly so
   browsers render it as HTML (without this header some browsers
   sniff and fall back to plain text).

Static-contract regression tests in
`src/main_static_html_test.zig` assert the constant, function, route
registration, doctype, charset, endpoint table, and EventSource demo
all stay present across edits — see "Running Tests" below.

## Architecture

```
src/
├── main.zig                  # Server entry point, route setup, and static HTML page (LANDING_PAGE_HTML)
├── http_server.zig           # Core server: Address, GinwaServer, RequestBuffer
├── http_parser.zig           # HTTP request/response parsing
├── router.zig                # Route matching with parameter extraction
├── sse_manager.zig           # SSE client management and event loop
├── websocket_frames.zig      # RFC 6455 frame parser/encoder (text, binary, ping, pong, close)
├── websocket_handshake.zig   # RFC 6455 §4 HTTP upgrade handshake + SHA-1 + base64
├── websocket_manager.zig     # WebSocket client registry: register, broadcast, remove
├── main_static_html_test.zig # Static-contract tests for LANDING_PAGE_HTML
└── build.zig                 # Build configuration
```

### Core Components

**http_server.zig**
- `Address`: Socket binding and port configuration
- `GinwaServer`: Main server struct handling connections
- `RequestBuffer`: Auto-growing buffer for reading HTTP requests

**router.zig**
- `Router`: Route registry supporting GET, POST, PUT, DELETE, PATCH
- `Route`: Individual route definition with handler
- Path parameter extraction via `:param` syntax

**sse_manager.zig**
- `SseManager`: Manages SSE connections and broadcasting
- `SseClient`: Individual SSE client state
- Heartbeat mechanism with configurable interval
- Thread-safe client management with lock

**websocket_frames.zig**
- `parseFrame(allocator, wire)` — parse a complete WebSocket frame (RFC 6455 §5)
- `encodeFrame(allocator, input)` — encode an unmasked server-to-client frame
- `decodeClosePayload` — extract close status code + reason
- `generateMaskKey` — 4 random bytes for client-side masking
- `mask` / `unmask` — XOR with 4-byte rotating key

**websocket_handshake.zig**
- `computeAcceptKey(client_key)` — `base64(SHA1(key + MAGIC_GUID))`
- `buildAcceptResponse(allocator, key)` — full 101 response bytes
- `isWebSocketRequest(req)` — case-insensitive header validation
- `extractWebSocketKey(req)` — case-insensitive key lookup

**websocket_manager.zig**
- `WsManager`: thread-safe client registry (register, remove, broadcast, sendToClient)
- `WsClient`: per-client state (id, fd, arena, write callback)

**cronjob_manager.zig**
- `CronExpression`: 5-field cron parser (minute, hour, dom, month, dow) with `*`, `N`, `N-M`, `*/N`, `N,M,K` syntax
- `CronjobManager`: thread-safe registry of cron-scheduled callbacks; background thread ticks every 1s
- `nextFireAfter`: minute-by-minute calculator used by tests and the tick loop

**http_parser.zig**
- `HttpRequest`: Parsed request with method, path, headers, body
- `HttpResponse`: Response builder with body and JSON support

## API Reference

### Router

```zig
try gs.router.get("/path", handler);
try gs.router.post("/path", handler);
try gs.router.put("/path", handler);
try gs.router.delete("/path", handler);
try gs.router.patch("/path", handler);
try gs.router.sse("/stream", sseHandler);
try gs.router.ws("/ws", wsHandler);
```

### WebSocket Handler

```zig
const ws_frames = @import("websocket_frames.zig");

fn wsEchoHandler(
    ctx: gserverz.HttpContext,
    req: gserverz.HttpRequest,
    server_ptr: *anyopaque,
    client_fd: i32,
) !void {
    const server: *gserverz.GinwaServer = @ptrCast(@alignCast(server_ptr));
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try server.recvFromClient(client_fd, &buf);
        if (n == 0) return; // peer closed
        var frame = try ws_frames.parseFrame(ctx.allocator, buf[0..n]);
        defer frame.deinit(ctx.allocator);
        switch (frame.opcode) {
            .text => {
                const echo = try ws_frames.encodeFrame(ctx.allocator, .{ .opcode = .text, .payload = frame.payload });
                defer ctx.allocator.free(echo);
                try server.sendToClient(client_fd, echo);
            },
            .ping => { /* reply with pong */ },
            .close => return,
            else => {},
        }
    }
}
```

### Handler Signature

```zig
fn handler(ctx: HttpContext, req: HttpRequest, res: HttpResponse) !HttpResponse {
    // Access query params: req.query.get("name")
    // Access path params: req.params.get("name")
    // Access body: req.body
    return res.withBody("Response text");
}
```

### SSE Manager

```zig
// Broadcast to all clients
try gs.sse_manager.broadcast("message");

// Send to specific client
try gs.sse_manager.sendToClient(client_id, "message");

// Get connected client count
const count = gs.sse_manager.clientCount();
```

### Cronjob Manager

Register a callback against a standard 5-field cron expression. The
background thread ticks every 1 second and fires any job whose next
scheduled time has arrived.

```zig
fn housekeeping(_: ?*anyopaque, now_unix: i64) void {
    std.log.info("housekeeping fired at {d}", .{now_unix});
}

// Register — the cron expression is validated at register time and
// returns CronError if malformed.
const now_unix = std.Io.Clock.now(.real, gs.io).toSeconds();
const id = try gs.cronjob_manager.register(
    "*/5 * * * *",     // every 5 minutes
    "housekeeping",
    housekeeping,
    null,
    now_unix,           // initial anchor — first fire is strictly after this
);

// Unregister by id (idempotent).
gs.cronjob_manager.unregister(id);

// Inspect registered jobs.
for (gs.cronjob_manager.list()) |job| {
    std.debug.print("job {d}: {s}\n", .{job.id, job.name});
}
```

Supported expression syntax:

| Token | Meaning |
|---|---|
| `*` | every value in range |
| `N` | exactly N |
| `N-M` | range (inclusive) |
| `*/N` | step (every N units, starting at min) |
| `N,M,K` | list (any of N, M, K) |

Standard 5 fields: `minute hour dom month dow`. UTC only. Minute
precision. No persistence — jobs are dropped on server restart.

The manager is automatically started by `GinwaServer.listen()` and
stopped by `GinwaServer.deinit()`. Callers do not need to (and should
not) call `start` / `stop` themselves.

## Running Tests

```bash
zig build test
```

## Dependencies

- Zig 0.15+
- Standard library only (no external dependencies)
- Links against libc for socket operations

## Configuration

### Port
Default port is `29590`. To change, modify `main.zig`:
```zig
const address = try gserverz.Address.init(29590);
```

### SSE Heartbeat
Default heartbeat interval is 15 seconds. To change:
```zig
try gs.sse_manager.startEventLoop(15); // seconds
```