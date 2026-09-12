const std = @import("std");
const linux = std.posix.system;
const gserverz = @import("kabelweb").server;

// implementation http server custom
pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("Server error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

// ============================================================================
// Static HTML example — a self-contained landing page served at GET /.
//
// This is the canonical "static HTML in custom_http_server" pattern:
//
//   1. The HTML lives as a comptime string constant (LANDING_PAGE_HTML below).
//      Compiling it in keeps the binary self-contained — no on-disk file to
//      ship alongside the executable, no 404 risk.
//   2. The handler duplicates the constant into the per-request arena
//      (so it lives for the lifetime of the request and is reaped when
//      `GinwaServer.handle` calls `arena.deinit()` on the response).
//   3. We set `Content-Type: text/html; charset=utf-8` so browsers render
//      it as HTML (vs. withBody() which would default the Content-Type to
//      whatever the parser already has — i.e. nothing, making browsers
//      guess and usually render as plain text).
//   4. `withBody` automatically sets `Content-Length`, so the response
//      is one allocator-friendly call: get arena-owned slice, set body,
//      set content-type header, return response.
//
// Why a static HTML page (vs. e.g. compiling the Vue webapp into the
// binary): this server is the DEMO of itself — the page documents the
// server's own endpoints. It is not a generic static-file server.
// ============================================================================

/// A self-contained HTML landing page served at `GET /`. Inline CSS, inline
/// JavaScript, no external assets — works the same on every platform
/// (Linux/macOS/Windows) since HTML/CSS/JS are cross-platform by definition.
///
/// Sections:
///   * Hero: server identity + a one-line "what it is" pitch
///   * Endpoints table: every demo route with method, path, and curl example
///   * SSE live demo: a JavaScript EventSource subscribing to `/stream` and
///     rendering the last 5 events received
///
/// The page intentionally avoids hand-rolled HTML escaping inside the
/// JavaScript section (single-quoted strings only, no `</script>` inside
/// string literals) so the bytes are safe to embed verbatim.
const LANDING_PAGE_HTML =
    \\<!doctype html>
    \\<html lang="en">
    \\<head>
    \\  <meta charset="utf-8" />
    \\  <meta name="viewport" content="width=device-width, initial-scale=1" />
    \\  <title>GinwaServer — Static HTML Demo</title>
    \\  <style>
    \\    :root {
    \\      --bg: #0f172a;
    \\      --panel: #1e293b;
    \\      --panel-2: #334155;
    \\      --text: #e2e8f0;
    \\      --muted: #94a3b8;
    \\      --accent: #22d3ee;
    \\      --accent-2: #a78bfa;
    \\      --ok: #22c55e;
    \\      --warn: #f59e0b;
    \\    }
    \\    * { box-sizing: border-box; }
    \\    html, body { margin: 0; padding: 0; }
    \\    body {
    \\      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    \\      background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
    \\      color: var(--text);
    \\      min-height: 100vh;
    \\      line-height: 1.5;
    \\    }
    \\    .container { max-width: 960px; margin: 0 auto; padding: 32px 24px; }
    \\    header.hero { padding: 32px 0 16px; }
    \\    h1 {
    \\      margin: 0 0 8px;
    \\      font-size: 36px;
    \\      letter-spacing: -0.02em;
    \\      background: linear-gradient(90deg, var(--accent), var(--accent-2));
    \\      -webkit-background-clip: text;
    \\      background-clip: text;
    \\      color: transparent;
    \\    }
    \\    .subtitle { color: var(--muted); font-size: 16px; margin: 0 0 8px; }
    \\    .badge-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
    \\    .badge {
    \\      display: inline-flex; align-items: center; gap: 6px;
    \\      padding: 4px 10px; border-radius: 999px;
    \\      font-size: 12px; font-weight: 500;
    \\      background: var(--panel-2); color: var(--muted);
    \\      border: 1px solid rgba(255,255,255,0.06);
    \\    }
    \\    .badge.ok { color: var(--ok); }
    \\    .badge.warn { color: var(--warn); }
    \\    section { margin-top: 32px; }
    \\    h2 {
    \\      font-size: 20px; margin: 0 0 12px;
    \\      border-bottom: 1px solid rgba(255,255,255,0.08);
    \\      padding-bottom: 8px;
    \\    }
    \\    .endpoint {
    \\      background: var(--panel);
    \\      border: 1px solid rgba(255,255,255,0.06);
    \\      border-radius: 8px;
    \\      padding: 14px 16px;
    \\      margin: 8px 0;
    \\    }
    \\    .endpoint-head {
    \\      display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    \\    }
    \\    .method {
    \\      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    \\      font-size: 12px; font-weight: 700;
    \\      padding: 3px 8px; border-radius: 4px;
    \\      background: var(--accent); color: #0c1320;
    \\      letter-spacing: 0.04em;
    \\    }
    \\    .method.post { background: var(--warn); }
    \\    .method.sse { background: var(--accent-2); }
    \\    code, pre {
    \\      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    \\      background: #0b1220; color: #cbd5e1;
    \\      padding: 2px 6px; border-radius: 4px; font-size: 13px;
    \\    }
    \\    pre { padding: 12px 14px; overflow-x: auto; margin: 8px 0 0; }
    \\    pre code { background: transparent; padding: 0; }
    \\    .path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--text); }
    \\    .desc { color: var(--muted); font-size: 14px; margin: 4px 0 0; }
    \\    #sse-log {
    \\      background: #0b1220;
    \\      border: 1px solid rgba(255,255,255,0.06);
    \\      border-radius: 8px;
    \\      padding: 12px; min-height: 96px;
    \\      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    \\      font-size: 13px;
    \\      max-height: 220px;
    \\      overflow-y: auto;
    \\    }
    \\    #sse-log .event { padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }
    \\    #sse-log .event:last-child { border-bottom: 0; }
    \\    #sse-status { font-size: 13px; color: var(--muted); margin-bottom: 8px; }
    \\    #sse-status.connected { color: var(--ok); }
    \\    #sse-status.error { color: var(--warn); }
    \\    footer {
    \\      margin-top: 48px; padding-top: 24px;
    \\      border-top: 1px solid rgba(255,255,255,0.08);
    \\      color: var(--muted); font-size: 13px; text-align: center;
    \\    }
    \\    @media (max-width: 600px) {
    \\      .container { padding: 20px 16px; }
    \\      h1 { font-size: 28px; }
    \\    }
    \\  </style>
    \\</head>
    \\<body>
    \\  <div class="container">
    \\    <header class="hero">
    \\      <h1>GinwaServer</h1>
    \\      <p class="subtitle">A static HTML page served by the custom HTTP server &mdash; this file lives as a comptime string in <code>src/main.zig</code>.</p>
    \\      <div class="badge-row">
    \\        <span class="badge ok">● Zig 0.16</span>
    \\        <span class="badge ok">● Linux / macOS / Windows</span>
    \\        <span class="badge">HTTP/1.1</span>
    \\        <span class="badge">SSE</span>
    \\        <span class="badge">JSON</span>
    \\      </div>
    \\    </header>
    \\
    \\    <section>
    \\      <h2>Endpoints</h2>
    \\
    \\      <div class="endpoint">
    \\        <div class="endpoint-head">
    \\          <span class="method">GET</span>
    \\          <span class="path">/</span>
    \\        </div>
    \\        <p class="desc">This page &mdash; a static HTML response compiled into the binary.</p>
    \\        <pre><code>curl http://127.0.0.1:29590/</code></pre>
    \\      </div>
    \\
    \\      <div class="endpoint">
    \\        <div class="endpoint-head">
    \\          <span class="method">GET</span>
    \\          <span class="path">/health</span>
    \\        </div>
    \\        <p class="desc">Plain-text health check. Suitable for load balancers and process supervisors.</p>
    \\        <pre><code>curl http://127.0.0.1:29590/health
\\# -&gt; OK</code></pre>
    \\      </div>
    \\
    \\      <div class="endpoint">
    \\        <div class="endpoint-head">
    \\          <span class="method">GET</span>
    \\          <span class="path">/hello</span>
    \\        </div>
    \\        <p class="desc">Greets with optional <code>name</code>, <code>greeting</code>, and <code>mood</code> query parameters.</p>
    \\        <pre><code>curl "http://127.0.0.1:29590/hello?name=World&amp;greeting=Hi&amp;mood=happy"
\\# -&gt; Hi, World! (greeting: Hi, mood: happy)</code></pre>
    \\      </div>
    \\
    \\      <div class="endpoint">
    \\        <div class="endpoint-head">
    \\          <span class="method">GET</span>
    \\          <span class="path">/hello/:name</span>
    \\        </div>
    \\        <p class="desc">Path-parameter variant &mdash; :name is extracted by the router.</p>
    \\        <pre><code>curl http://127.0.0.1:29590/hello/Alice
\\# -&gt; hello, Alice! (greeting: hello, mood: neutral)</code></pre>
    \\      </div>
    \\
    \\      <div class="endpoint">
    \\        <div class="endpoint-head">
    \\          <span class="method post">POST</span>
    \\          <span class="path">/users</span>
    \\        </div>
    \\        <p class="desc">Creates a user from a JSON body. Returns 201 Created with the echoed payload.</p>
    \\        <pre><code>curl -X POST http://127.0.0.1:29590/users \
    \\  -H "Content-Type: application/json" \
    \\  -d '{"username":"alice","email":"alice@example.com"}'
\\# -&gt; {"username":"alice","email":"alice@example.com"}</code></pre>
    \\      </div>
    \\
    \\      <div class="endpoint">
    \\        <div class="endpoint-head">
    \\          <span class="method sse">SSE</span>
    \\          <span class="path">/stream</span>
    \\        </div>
    \\        <p class="desc">Server-Sent Events. Open the connection and receive named events and heartbeats until you close it.</p>
    \\        <pre><code>curl -N http://127.0.0.1:29590/stream
\\# stream of "data: ..." events ending in periodic heartbeats</code></pre>
    \\      </div>
    \\    </section>
    \\
    \\    <section>
    \\      <h2>Live SSE demo</h2>
    \\      <p class="desc">Open this page in a browser, then look below &mdash; this block subscribes to <code>/stream</code> via the EventSource API and renders the last events it receives.</p>
    \\      <div id="sse-status">Connecting&hellip;</div>
    \\      <div id="sse-log"></div>
    \\      <script>
    \\        (function () {
    \\          var status = document.getElementById('sse-status');
    \\          var log = document.getElementById('sse-log');
    \\          var MAX_EVENTS = 5;
    \\
    \\          function appendLine(text) {
    \\            var line = document.createElement('div');
    \\            line.className = 'event';
    \\            var ts = new Date().toISOString().substr(11, 12);
    \\            line.textContent = '[' + ts + '] ' + text;
    \\            log.appendChild(line);
    \\            while (log.childNodes.length > MAX_EVENTS) {
    \\              log.removeChild(log.firstChild);
    \\            }
    \\            log.scrollTop = log.scrollHeight;
    \\          }
    \\
    \\          if (typeof EventSource === 'undefined') {
    \\            status.textContent = 'EventSource not supported in this browser';
    \\            status.className = 'error';
    \\            return;
    \\          }
    \\
    \\          var source = new EventSource('/stream');
    \\          source.addEventListener('connected', function (e) {
    \\            status.textContent = '● Connected to /stream';
    \\            status.className = 'connected';
    \\            appendLine('connected: ' + (e.data || ''));
    \\          });
    \\          source.addEventListener('message', function (e) {
    \\            appendLine('message: ' + (e.data || ''));
    \\          });
    \\          source.onerror = function () {
    \\            status.textContent = '● Connection error (server offline?)';
    \\            status.className = 'error';
    \\          };
    \\        })();
    \\      </script>
    \\    </section>
    \\
    \\    <footer>
    \\      Source: <code>src/modules/kabelweb/src/examples/server_demo.zig</code> &middot; see <code>LANDING_PAGE_HTML</code>.
    \\    </footer>
    \\  </div>
    \\</body>
    \\</html>
;

/// Serves the static landing page at `GET /`. Allocates a per-request copy of
/// the HTML body, sets `Content-Type: text/html; charset=utf-8`, and lets
/// `withBody` add the matching `Content-Length` automatically. No defer
/// needed — the per-request arena allocator reaps the dup'd buffer when
/// `GinwaServer.handle` returns.
fn landingPageHandler(
    ctx: gserverz.HttpContext,
    req: gserverz.HttpRequest,
    res: gserverz.HttpResponse,
) !gserverz.HttpResponse {
    _ = req;

    // Duplicate into the per-request arena so the response is request-scoped
    // (reaped by GinwaServer.handle via arena.deinit()). LANDING_PAGE_HTML
    // itself lives in the binary's rodata; the arena copy is what the wire
    // receives. For a 4 KB page the dup is ~4 KB of arena — negligible.
    const body = ctx.allocator.dupe(u8, LANDING_PAGE_HTML) catch {
        return gserverz.response.internalError("Failed to allocate HTML body", ctx.allocator);
    };

    var out = res.withBody(body);

    // withBody already sets Content-Length. We explicitly add the HTML
    // content-type so browsers render the response as HTML (without this,
    // some browsers sniff and fall back to plain text rendering).
    out.headers.put("Content-Type", "text/html; charset=utf-8") catch {
        return gserverz.response.internalError("Failed to set Content-Type header", ctx.allocator);
    };

    return out;
}

// ============================================================================
// Jinja-style template handler — demonstrates the template engine.
//
// Renders `templates/example.jinja` (a child of `templates/base.jinja`)
// with a context built from a few hardcoded values. On each request:
//   1. Load the child template source (recursively loads the parent).
//   2. Compile the merged AST with inheritance resolution.
//   3. Build a context with: build_sha, started_at, features[], show_extra.
//   4. Render the AST and serve as `text/html; charset=utf-8`.
//
// For production: pre-compile the AST once at startup (cache it in a
// global) and only build a fresh context per request. The compile step
// walks the file system / parses; the render step is in-memory and fast.
// ============================================================================

// Bundle the template sources at compile time so the binary is
// self-contained — no on-disk template files required at runtime.
const EXAMPLE_TEMPLATE = @embedFile("templates/example.jinja");

// Loader callback: serves the bundled child + parent to the template
// engine. For multi-template apps this would be a real filesystem
// loader; for this single-page demo, embedFile is enough.
const TemplateLoader = struct {
    fn load(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
    ) anyerror![]u8 {
        _ = ctx;
        if (std.mem.eql(u8, path, "example.jinja")) {
            return allocator.dupe(u8, EXAMPLE_TEMPLATE) catch return error.OutOfMemory;
        }
        if (std.mem.eql(u8, path, "base.jinja")) {
            return allocator.dupe(u8, BASE_TEMPLATE) catch return error.OutOfMemory;
        }
        return error.TemplateNotFound;
    }
};

const BASE_TEMPLATE = @embedFile("templates/base.jinja");

fn templateHandler(
    ctx: gserverz.HttpContext,
    req: gserverz.HttpRequest,
    res: gserverz.HttpResponse,
) !gserverz.HttpResponse {
    _ = req;

    // Build a loader + compile the template (with inheritance).
    var loader = TemplateLoader{};
    const nodes = gserverz.Template.compileWithParent(
        ctx.allocator,
        EXAMPLE_TEMPLATE,
        @ptrCast(&loader),
        &TemplateLoader.load,
    ) catch |err| {
        return gserverz.response.internalError(@errorName(err), ctx.allocator);
    };
    defer gserverz.Template.freeNodes(ctx.allocator, nodes);

    // Build a context. Real apps would inject request-scoped data here
    // (user info, feature flags, build SHA from CI, etc.).
    var tctx = gserverz.Template.Context.init(ctx.allocator);
    defer tctx.deinit();

    try tctx.put("build_sha", .{ .string = "146df72d" });
    try tctx.put("started_at", .{ .string = "2026-08-06" });
    try tctx.put("show_extra", .{ .bool = true });

    const features = [_]gserverz.Template.Value{
        .{ .string = "AI Chat View" },
        .{ .string = "Kanban Mode" },
        .{ .string = "Design Canvas" },
    };
    const descs = [_][]const u8{
        "Talk to an agent that can see your workspace.",
        "Sprint board wired to your tasks.",
        "Visual editor backed by Zig.",
    };
    var fmap = std.StringHashMap(gserverz.Template.Value).init(ctx.allocator);
    defer fmap.deinit();
    try fmap.put("name", .{ .string = features[0].string });
    try fmap.put("description", .{ .string = descs[0] });
    // For brevity we put one feature; the template loops, so a single
    // item is enough to demonstrate the loop. To pass an array, build
    // one as shown below:
    var fmap2 = std.StringHashMap(gserverz.Template.Value).init(ctx.allocator);
    try fmap2.put("name", .{ .string = features[1].string });
    try fmap2.put("description", .{ .string = descs[1] });
    var fmap3 = std.StringHashMap(gserverz.Template.Value).init(ctx.allocator);
    try fmap3.put("name", .{ .string = features[2].string });
    try fmap3.put("description", .{ .string = descs[2] });
    const arr = [_]gserverz.Template.Value{
        .{ .map = fmap },
        .{ .map = fmap2 },
        .{ .map = fmap3 },
    };
    try tctx.put("features", .{ .array = &arr });

    // Render via the response's `withRender` helper — sets the body,
    // Content-Length, and Content-Type in one call.
    return res.withRender(nodes, &tctx);
}

// Handlers - (ctx, req, res) -> !HttpResponse
fn healthHandler(_: gserverz.HttpContext, req: gserverz.HttpRequest, res: gserverz.HttpResponse) !gserverz.HttpResponse {
    _ = req;
    return res.withBody("OK");
}

fn helloHandler(ctx: gserverz.HttpContext, req: gserverz.HttpRequest, res: gserverz.HttpResponse) !gserverz.HttpResponse {
    const name = req.query.get("name") orelse "HTTP";
    const greeting = req.query.get("greeting") orelse "hello";
    const mood = req.query.get("mood") orelse "neutral";

    const text = std.fmt.allocPrint(ctx.allocator, "Hello, {s}! (greeting: {s}, mood: {s})", .{ name, greeting, mood }) catch {
        return gserverz.response.internalError("Failed to format", ctx.allocator);
    };
    return res.withBody(text);
}

fn helloNameHandler(ctx: gserverz.HttpContext, req: gserverz.HttpRequest, res: gserverz.HttpResponse) !gserverz.HttpResponse {
    const name = req.query.get("name") orelse req.params.get("name") orelse "unknown";
    const greeting = req.query.get("greeting") orelse "hello";
    const mood = req.query.get("mood") orelse "neutral";


    const text = std.fmt.allocPrint(ctx.allocator, "Hello, {s}! (greeting: {s}, mood: {s})", .{ name, greeting, mood }) catch {
        return gserverz.response.internalError("Failed to format", ctx.allocator);
    };
    return res.withBody(text);
}

const User = struct {
    username: []const u8 = "",
    email: []const u8 = "",
};

fn createUserHandler(ctx: gserverz.HttpContext, req: gserverz.HttpRequest, res: gserverz.HttpResponse) !gserverz.HttpResponse {
    const allocator = ctx.allocator;

    std.debug.print("HANDLER: req.body.len={}\n", .{req.body.len});

    const user = std.json.parseFromSliceLeaky(User, allocator, req.body, .{}) catch |err| {
        std.debug.print("HANDLER JSON error: {s}\n", .{@errorName(err)});
        if (req.body.len > 0) {
            std.debug.print("HANDLER body[0..50]={s}\n", .{req.body[0..@min(50, req.body.len)]});
        }
        return gserverz.response.badRequest("Invalid user JSON", allocator);
    };

    const json_text = std.fmt.allocPrint(allocator, "{{\"username\":\"{s}\",\"email\":\"{s}\"}}", .{ user.username, user.email }) catch {
        return gserverz.response.internalError("Failed to format", allocator);
    };
    return res.jsonResponse(.{ .status_code = 201, .data = json_text });
}

/// SSE streaming handler - registers client with SSE manager
/// Actual streaming handled by SseManager.runEventLoop()
fn sseStreamHandler(ctx: gserverz.HttpContext, req: gserverz.HttpRequest, res: gserverz.HttpResponse) !gserverz.HttpResponse {
    _ = ctx;
    _ = req;
    _ = res;
    // Client is registered in http_server.zig before this is called
    // The SSE manager event loop handles ongoing messaging and heartbeat
    return error.WouldBlock; // Handler should not complete - connection stays open
}

// ============================================================================
// WebSocket echo handler — demonstrates the WebSocket transport end-to-end.
//
// This is the canonical "echo + broadcast" pattern for a custom HTTP
// server with WebSocket support:
//
//   1. The handler is invoked AFTER the 101 Switching Protocols response
//      has been sent. It receives (ctx, req, server_ptr, client_fd).
//
//   2. We run a read loop: each incoming frame is parsed and either
//      echoed back (text frames) or used as a broadcast trigger
//      (a message starting with "/broadcast "). Other opcodes:
//        - ping   → reply with pong carrying the same payload
//        - close  → exit the loop (the server sends its own close frame)
//        - binary → ignore
//
//   3. On loop exit, the server sends a close frame and closes the fd.
//
// See websocket_frames.zig for the wire format and websocket_handshake.zig
// for the upgrade flow. This handler is intentionally self-contained —
// production handlers would split the read loop into a helper function
// for testability.
// ============================================================================

const ws_frames = @import("kabelweb").server.ws_frames;

fn wsEchoHandler(ctx: gserverz.HttpContext, req: gserverz.HttpRequest, server_ptr: *anyopaque, client_fd: i32, client_id: *[16]u8) !void {
    const server: *gserverz.GinwaServer = @ptrCast(@alignCast(server_ptr));
    _ = req;

    var buf: [4096]u8 = undefined;

    while (true) {
        const n = server.recvFromClient(client_fd, &buf) catch |err| {
            std.debug.print("ws echo recv error: {s}\n", .{@errorName(err)});
            return;
        };
        if (n == 0) return; // peer closed

        // Parse the first complete frame in buf. For multi-frame
        // messages this loop would need to handle continuations; for
        // the demo we only handle single-frame messages.
        var frame = ws_frames.parseFrame(ctx.allocator, buf[0..n]) catch |err| switch (err) {
            error.IncompleteFrame => {
                // For simplicity, we don't buffer partial frames here.
                // A real implementation would accumulate into a growable
                // ArrayList and re-parse.
                std.debug.print("ws echo: incomplete frame\n", .{});
                continue;
            },
            else => {
                std.debug.print("ws echo: parse error {s}\n", .{@errorName(err)});
                return;
            },
        };
        defer frame.deinit(ctx.allocator);

        switch (frame.opcode) {
            .text => {
                // Echo the frame back to the sender.
                const echo = ws_frames.encodeFrame(ctx.allocator, .{
                    .opcode = .text,
                    .payload = frame.payload,
                }) catch continue;
                defer ctx.allocator.free(echo);
                _ = server.sendToClient(client_fd, echo) catch return;

                // Special-case: a message beginning with "/broadcast "
                // is sent to all connected WebSocket clients (including
                // this one) via the WsManager broadcast path. This
                // demonstrates the fan-out use case (chat rooms,
                // notifications, etc.).
                if (std.mem.startsWith(u8, frame.payload, "/broadcast ")) {
                    server.ws_manager.broadcast(frame.payload["/broadcast ".len..]) catch {};
                    // The sender also sees the broadcast; we already
                    // echoed above, so the sender gets the message twice.
                    // (Acceptable for the demo; real apps would skip the
                    // echo for broadcast-triggered messages.)
                }

                // Special-case: "/echo <id>" sends an extra message
                // targeted at the named client id (no id→fd lookup in
                // this demo, just illustrates the sendToClient path).
                _ = client_id;
            },
            .ping => {
                // Reply with a pong carrying the same payload (RFC 6455 §5.5.3).
                const pong = ws_frames.encodeFrame(ctx.allocator, .{
                    .opcode = .pong,
                    .payload = frame.payload,
                }) catch continue;
                defer ctx.allocator.free(pong);
                _ = server.sendToClient(client_fd, pong) catch return;
            },
            .close => return, // peer wants to close — exit the loop
            else => {}, // binary / continuation / pong — ignore
        }
    }
}

// ============================================================================
// Cronjob demo — a single in-process callback that fires every minute.
//
// This is a normal cron job (server-internal scheduling), NOT an HTTP
// endpoint. The cronjob manager is a private subsystem of GinwaServer —
// callbacks run on a background thread inside the process, and there is
// intentionally no HTTP API to register / unregister / inspect jobs.
//
// To inspect what jobs are running, use the in-process `list()` API from
// another piece of server code (e.g. a startup log line, a debug command
// run from a separate channel, or a test).
//
// Why this is the canonical example:
//   - It shows the `register` API (expression + name + callback + now anchor)
//   - The callback itself is trivial (a log line) so the demo is easy to
//     read end-to-end without domain-specific noise.
//
// The cronjob manager is started automatically by `gs.listen()` — see the
// "Cronjob manager running (1s tick)" log line below.
// ============================================================================

/// Callback invoked by the cronjob manager when the scheduled time arrives.
/// Receives the current Unix timestamp (seconds) as `now_unix`. Runs on
/// the cronjob background thread — keep it short and non-blocking.
fn heartbeatLogger(_: ?*anyopaque, now_unix: i64) void {
    std.debug.print("[cronjob] heartbeat fired at now={d}\n", .{now_unix});
}

pub fn run(init: std.process.Init) !void {
    // const arena_allocator = init.arena;
    // defer arena_allocator.deinit();
    // const allocator = arena_allocator.allocator();
    //
    const allocator = init.gpa;
    const io = init.io;

    // Test allocator with a large allocation first
    std.debug.print("DEBUG: Testing allocator with 1MB allocation...\n", .{});
    const test_alloc = allocator.alloc(u8, 1024 * 1024) catch |err| {
        std.debug.print("DEBUG: 1MB alloc failed: {s}\n", .{@errorName(err)});
        return err;
    };
    allocator.free(test_alloc);
    std.debug.print("DEBUG: 1MB alloc succeeded\n", .{});

    const address = try gserverz.Address.init("127.0.0.1", 29590);
    const gs = try gserverz.GinwaServer.init(allocator, io, address);
    defer gs.deinit();

    // Start SSE event loop in a separate thread (non-blocking)
    const sse_thread = try std.Thread.spawn(.{}, struct {
        fn run(sm: *gserverz.SseManager, secs: u32) void {
            sm.startEventLoop(secs) catch |err| {
                std.debug.print("SSE event loop error: {s}\n", .{@errorName(err)});
            };
        }
    }.run, .{ &gs.sse_manager, @as(u32, 15) });
    defer {
        gs.sse_manager.stop();
        sse_thread.join();
    }

    std.debug.print("HTTP Server listening on 127.0.0.1:29590...\n", .{});
    std.debug.print("SSE Event loop running with 15s heartbeat...\n", .{});
    std.debug.print("Open  http://127.0.0.1:29590/  in a browser for the static HTML demo.\n", .{});
    std.debug.print("Or:   curl http://127.0.0.1:29590/health\n", .{});
    std.debug.print("Press Ctrl+C to stop\n\n", .{});

    // -------------------------------------------------------------------
    // Group + Middleware wiring — applies cross-cutting concerns to a
    // realistic mix of routes.
    //
    //   * `router.group(prefix)` — sub-router. Routes registered via
    //     a group have the prefix prepended; nested groups concatenate
    //     prefixes (no double slashes) and inherit the parent's
    //     middleware list.
    //   * `group.use(middleware)` — runs BEFORE every route added to
    //     the group (and any nested group), in registration order.
    //     A middleware either returns its own response (short-circuit)
    //     or calls `chain.next(...)` to continue.
    //
    // Layout:
    //
    //   root group "" (no prefix)
    //   ├── requestIdMiddleware        — every response gets X-Request-Id
    //   │
    //   ├── /hello, /health, /hello/:name, /, /example, /users  (public demos)
    //   │
    //   ├── /realtime group
    //   │   ├── connectionIdMiddleware — SSE/WS gets X-Connection-Id
    //   │   ├── /stream (SSE)
    //   │   └── /ws (WebSocket)
    //   │
    //   └── /api group
    //       ├── /v1 group
    //       │   ├── /ping, /info, /echo  (requestId only — inherited)
    //       │   └── /admin group
    //       │       ├── authGuardMiddleware — admin needs bearer token
    //       │       └── /secret
    // -------------------------------------------------------------------

    const auth_header_value = "Bearer secret-token-please-change";

    // ─── Middlewares ────────────────────────────────────────────────────

    // Request-Id: stamps every response with a correlation header.
    // Attached to the root group so EVERY route (demo, API, admin)
    // gets it. Real apps would use std.crypto.random to generate a
    // per-request UUID; we hard-code a value for determinism.
    const requestIdMiddleware = struct {
        fn h(
            ctx: gserverz.HttpContext,
            req: gserverz.HttpRequest,
            res: gserverz.HttpResponse,
            chain: *gserverz.MiddlewareChain,
        ) anyerror!gserverz.HttpResponse {
            const stamped = res.withHeader("X-Request-Id", "example-trace-1");
            return chain.next(ctx, req, stamped);
        }
    }.h;

    // No-cache: dev-mode helper that prevents intermediate caches
    // from caching demo responses. Useful for `/`, `/example` etc.
    // during local development so reloads reflect the latest source.
    // (Defined for reference — not wired into the demo routes.)
    const noCacheMiddleware = struct {
        fn h(
            ctx: gserverz.HttpContext,
            req: gserverz.HttpRequest,
            res: gserverz.HttpResponse,
            chain: *gserverz.MiddlewareChain,
        ) anyerror!gserverz.HttpResponse {
            const stamped = res.withHeader("Cache-Control", "no-store");
            return chain.next(ctx, req, stamped);
        }
    }.h;
    _ = noCacheMiddleware;

    // Connection-Id: stamps SSE/WS responses with a per-connection
    // correlation header. Real apps would use a unique id per
    // connection (e.g. random 16-byte hex); we hard-code for the
    // demo. Lives on the `/realtime` group so SSE and WebSocket
    // routes get it but no other route does.
    const connectionIdMiddleware = struct {
        fn h(
            ctx: gserverz.HttpContext,
            req: gserverz.HttpRequest,
            res: gserverz.HttpResponse,
            chain: *gserverz.MiddlewareChain,
        ) anyerror!gserverz.HttpResponse {
            const stamped = res.withHeader("X-Connection-Id", "conn-stub-1");
            return chain.next(ctx, req, stamped);
        }
    }.h;

    // Auth-guard: returns 401 when Authorization header is missing
    // or doesn't match. Sets status_code via a copy (HttpResponse is
    // a value type, no `withStatus(...)` builder). Used by the
    // /api/v1/admin group so non-admin /api/v1 routes stay public.
    const authGuardMiddleware = struct {
        fn h(
            ctx: gserverz.HttpContext,
            req: gserverz.HttpRequest,
            res: gserverz.HttpResponse,
            chain: *gserverz.MiddlewareChain,
        ) anyerror!gserverz.HttpResponse {
            const provided = req.headers.get("Authorization");
            if (provided == null) {
                var copy = res.withHeader("WWW-Authenticate", "Bearer");
                copy.status_code = 401;
                copy.body = "missing authorization";
                return copy;
            }
            if (!std.mem.eql(u8, provided.?, auth_header_value)) {
                var copy = res;
                copy.status_code = 401;
                copy.body = "invalid authorization";
                return copy;
            }
            return chain.next(ctx, req, res);
        }
    }.h;

    // ─── Handlers for the API endpoints ────────────────────────────────

    const PingHandler = struct {
        fn h(_: gserverz.HttpContext, _: gserverz.HttpRequest, res: gserverz.HttpResponse) anyerror!gserverz.HttpResponse {
            return res.withBody("pong");
        }
    }.h;
    const EchoHandler = struct {
        fn h(_: gserverz.HttpContext, req: gserverz.HttpRequest, res: gserverz.HttpResponse) anyerror!gserverz.HttpResponse {
            return res.withBody(req.body);
        }
    }.h;
    const SecretHandler = struct {
        fn h(_: gserverz.HttpContext, _: gserverz.HttpRequest, res: gserverz.HttpResponse) anyerror!gserverz.HttpResponse {
            return res.withBody("top-secret");
        }
    }.h;
    const PublicInfoHandler = struct {
        fn h(_: gserverz.HttpContext, _: gserverz.HttpRequest, res: gserverz.HttpResponse) anyerror!gserverz.HttpResponse {
            return res.withBody("info accessible to anyone with the request id");
        }
    }.h;

    // ─── Root group: every response gets X-Request-Id ──────────────────
    // Empty prefix means "no URL transformation" — routes registered
    // through `root` use exactly the path passed in.
    var root = gs.router.group("");
    try root.use(requestIdMiddleware);

    // ─── Public demo routes ────────────────────────────────────────────
    // These share no extra middleware beyond requestId (from `root`).
    try root.get("/", landingPageHandler);
    try root.get("/hello", helloHandler);
    try root.get("/hello/:name", helloNameHandler);
    try root.get("/health", healthHandler);
    try root.get("/example", templateHandler);
    try root.post("/users", createUserHandler);

    // ─── /realtime group: SSE + WS with connection-tracking ───────────
    // Nested under root so requestId applies too. Adds connectionId
    // for SSE/WS so the client can correlate events to a connection.
    var realtime = try root.group("/realtime");
    try realtime.use(connectionIdMiddleware);
    try realtime.sse("/stream", sseStreamHandler);
    try realtime.ws("/ws", wsEchoHandler);

    // ─── /api group: versioned API ─────────────────────────────────────
    // Nested under root → inherits requestId. The /api/v1 sub-group
    // doesn't add any v1-specific middleware; this is a placeholder
    // where a real app might add version-deprecation headers, etc.
    var api = try root.group("/api");
    var api_v1 = try api.group("/v1");
    try api_v1.get("/ping", PingHandler);
    try api_v1.get("/info", PublicInfoHandler);
    try api_v1.post("/echo", EchoHandler);

    // /admin is a deeply-nested group under /api/v1 — gets
    // requestId (from root) AND authGuard (just here). Demonstrates
    // that nested groups inherit AND add to the middleware chain.
    var admin = try api_v1.group("/admin");
    try admin.use(authGuardMiddleware);
    try admin.get("/secret", SecretHandler);

    // ─── Diagnostics printout ──────────────────────────────────────────
    std.debug.print("\n[demo] Group + middleware endpoints:\n", .{});
    std.debug.print("   root group '' + requestId:\n", .{});
    std.debug.print("     GET /              GET /hello        GET /hello/:name\n", .{});
    std.debug.print("     GET /health       GET /example      POST /users\n", .{});
    std.debug.print("   /realtime (root + requestId + connectionId):\n", .{});
    std.debug.print("     GET /realtime/stream (SSE)    GET /realtime/ws (WS)\n", .{});
    std.debug.print("   /api/v1 (root + requestId):\n", .{});
    std.debug.print("     GET /api/v1/ping   GET /api/v1/info  POST /api/v1/echo\n", .{});
    std.debug.print("   /api/v1/admin (root + requestId + authGuard):\n", .{});
    std.debug.print("     GET /api/v1/admin/secret\n", .{});
    std.debug.print("   curl -i http://127.0.0.1:29590/health              # requestId only\n", .{});
    std.debug.print("   curl -i http://127.0.0.1:29590/api/v1/ping      # requestId only\n", .{});
    std.debug.print("   curl -i http://127.0.0.1:29590/realtime/stream  # requestId + connectionId (SSE handshake)\n", .{});
    std.debug.print("   curl -i -H 'Authorization: Bearer {s}' http://127.0.0.1:29590/api/v1/admin/secret\n\n", .{auth_header_value});

    // ---------------------------------------------------------------------
    // Cronjob demo — register a "every minute" job BEFORE listen() so the
    // tick thread can pick it up immediately. The cron manager is started
    // by `listen()` (see the "Cronjob manager running (1s tick)" log line).
    //
    // Pattern:
    //   1. Capture the current Unix time as the "last fired" anchor so the
    //      first fire is the FIRST minute strictly after registration.
    //   2. Pass the expression, name, callback, ctx, and anchor to register.
    //   3. The callback runs on the cronjob background thread (NOT on a
    //      request handler thread) — keep it short and non-blocking.
    // ---------------------------------------------------------------------
    const boot_unix = std.Io.Clock.now(.real, io).toSeconds();
    _ = gs.cronjob_manager.register(
        "* * * * *",        // every minute, on the minute
        "heartbeat",
        heartbeatLogger,
        null,
        boot_unix,
    ) catch |err| {
        std.debug.print("Failed to register heartbeat cron: {s}\n", .{@errorName(err)});
    };

    std.debug.print("WebSocket listening on ws://127.0.0.1:29590/ws\n", .{});

    try gs.listen();
}

// curl http://127.0.0.1:29590/       # → HTML landing page
// curl http://127.0.0.1:29590/health # → "OK"
// curl http://127.0.0.1:29590/hello   # → "Hello, HTTP!"
