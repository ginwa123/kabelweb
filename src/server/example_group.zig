//! Generic worked-example showing how to use `Router.group(...)` and
//! `Group.use(...)` (middleware). Lives inside the module so it
//! doubles as living documentation AND as a runnable test fixture.
//!
//! What's here:
//!   - `registerExampleRoutes(router)` — pure Zig, registers a small
//!     sample API on the caller-provided router. No external
//!     dependencies (no DB, no template engine, no auth). Safe to
//!     call from tests or from a project's bootstrap.
//!   - dummy handlers (helloHandler, echoBodyHandler, etc.) — minimal
//!     responses suitable for inspection.
//!   - dummy middlewares (requestLogger, authGuard) — one passes
//!     through with header augmentation, one short-circuits.
//!   - `test "..."` blocks cover each scenario:
//!       * group + simple middleware runs the chain
//!       * nested group inherits parent prefix + middlewares
//!       * middleware that short-circuits returns its own response
//!       * middleware that augments `res` via `res.withHeader(...)`
//!       * routes outside the group do NOT inherit the middleware
//!       * paths get the prefix joined with no double slash
//!
//! How to read this file:
//!   1. Look at `requestLogger` and `authGuard` to see the
//!      `MiddlewareFn` signature and the "call chain.next(...) to
//!      continue, return your own response to short-circuit" rule.
//!   2. Look at `registerExampleRoutes` for the canonical usage of
//!      `router.group(prefix)`, `group.use(mw)`, `group.get(path, h)`,
//!      `group.group(prefix)`, etc.
//!   3. The `test` blocks at the bottom show expected outcomes —
//!      `zig build test` runs them all.

const std = @import("std");
const http_parser = @import("http_parser.zig");
const router = @import("router.zig");
const Router = router.Router;

// ────────────────────────────────────────────────────────────────────
// Public surface
// ────────────────────────────────────────────────────────────────────

/// Register the example routes on `router`. Use this as a template
/// for your own API — copy the function and substitute real handlers.
///
/// Returns a small `ExampleShape` so tests can check what got
/// registered (route count, prefix).
pub fn registerExampleRoutes(arena: std.mem.Allocator, router_inst: *Router) ExampleShape {
    _ = arena; // Reserved for future use (e.g., a precomputed routes table).
    const r = router_inst;

    // ── Public routes (no group, no middleware) ──────────────────────
    // These are reachable without going through any middleware —
    // good for things like /health and the landing page.
    r.get("/health", healthHandler) catch unreachable;
    r.get("/", helloHandler) catch unreachable;

    // ── Protected /api/v1 group with a request-Id middleware ─────────
    // Every route registered on this group:
    //   * has the prefix /api/v1 prepended
    //   * runs through `requestLogger` BEFORE its handler
    //
    // Note: `requestLogger` always calls `chain.next(...)` so it
    // doesn't change behavior — it just augments responses with an
    // `X-Request-Id` header. To make it stricter, change it to
    // verify something about `req` and short-circuit on failure.
    var api = r.group("/api");
    api.use(requestLogger) catch unreachable;

    api.get("/v1/ping", jsonHandler(.{ .body = "{\"pong\":true}" })) catch unreachable;
    api.post("/v1/echo", echoBodyHandler) catch unreachable;

    // ── Nested group: /api/v1/admin gated by an authGuard ──────────
    // The inner group inherits:
    //   * prefix chain: /api + /v1/admin → /api/v1/admin
    //   * middlewares:  [requestLogger, authGuard]   (authGuard is added last → runs last)
    //
    // So a request to /api/v1/admin/secret runs:
    //     requestLogger → authGuard → secretHandler
    // And a request to /api/v1/ping runs:
    //     requestLogger → pingHandler   (authGuard does NOT run)
    var admin = api.group("/v1/admin") catch unreachable;
    admin.use(authGuard) catch unreachable;

    admin.get("/secret", jsonHandler(.{ .body = "{\"secret\":\"top-level\"}" })) catch unreachable;
    admin.post("/secret", echoBodyHandler) catch unreachable;

    return .{
        .public_route_count = 2,
        .api_prefix = "/api",
        .admin_prefix = "/api/v1/admin",
    };
}

/// Shape returned by `registerExampleRoutes` so tests can assert
/// what got wired up. (Zig doesn't have a built-in way to introspect
/// a Router's registered routes.)
pub const ExampleShape = struct {
    public_route_count: usize,
    api_prefix: []const u8,
    admin_prefix: []const u8,
};

// ────────────────────────────────────────────────────────────────────
// Handlers — dumb stubs that return JSON/plain text. Replace these
// with real handlers in your application.
// ────────────────────────────────────────────────────────────────────

fn healthHandler(
    _: http_parser.HttpContext,
    _: http_parser.HttpRequest,
    res: http_parser.HttpResponse,
) anyerror!http_parser.HttpResponse {
    return res.withBody("OK");
}

fn helloHandler(
    _: http_parser.HttpContext,
    _: http_parser.HttpRequest,
    res: http_parser.HttpResponse,
) anyerror!http_parser.HttpResponse {
    return res.withBody("hello from the example router");
}

fn echoBodyHandler(
    _: http_parser.HttpContext,
    req: http_parser.HttpRequest,
    res: http_parser.HttpResponse,
) anyerror!http_parser.HttpResponse {
    return res.withBody(req.body);
}

/// Builds a handler that always returns the same JSON body. Useful
/// for `api.get("/path", jsonHandler(.{...}))` inline declarations.
fn jsonHandler(comptime config: struct { body: []const u8 }) fn (
    http_parser.HttpContext,
    http_parser.HttpRequest,
    http_parser.HttpResponse,
) anyerror!http_parser.HttpResponse {
    return struct {
        fn h(
            _: http_parser.HttpContext,
            _: http_parser.HttpRequest,
            res: http_parser.HttpResponse,
        ) anyerror!http_parser.HttpResponse {
            return res.withJson(config.body);
        }
    }.h;
}

// ────────────────────────────────────────────────────────────────────
// Middlewares
//
// Two flavors demonstrated:
//
//   1. `requestLogger` — augments the response on the way IN, always
//      calls `chain.next(...)`. Use this pattern for non-blocking
//      observability (logging, request IDs, response timing).
//
//   2. `authGuard`     — gates on a header. When missing or wrong,
//      returns its own 401 response WITHOUT calling `chain.next(...)`,
//      short-circuiting the chain (the final handler never runs).
// ────────────────────────────────────────────────────────────────────

const AUTH_HEADER_VALUE = "Bearer secret-token-please-change";

/// Request-logger middleware. Reads no state from the request; just
/// stamps every response with `X-Request-Id` so callers can correlate
/// requests across hops. Always passes through.
pub fn requestLogger(
    ctx: http_parser.HttpContext,
    req: http_parser.HttpRequest,
    res: http_parser.HttpResponse,
    chain: *router.MiddlewareChain,
) anyerror!http_parser.HttpResponse {
    // Generate a fake request id (in real code: std.crypto.random or
    // a uuid-from-time). Hard-coded for the example so tests stay
    // deterministic.
    const stamped = res.withHeader("X-Request-Id", "example-trace-1");
    return chain.next(ctx, req, stamped);
}

/// Auth-guard middleware. Reads the `Authorization` header. On
/// success calls `chain.next(...)`; on failure returns 401 short-
/// circuiting the chain.
pub fn authGuard(
    ctx: http_parser.HttpContext,
    req: http_parser.HttpRequest,
    res: http_parser.HttpResponse,
    chain: *router.MiddlewareChain,
) anyerror!http_parser.HttpResponse {
    // For the example we hard-code the expected token. In real code
    // compare against a JWT signature or a session record.
    const provided = req.headers.get("Authorization") orelse
        return res.withHeader("WWW-Authenticate", "Bearer").withBody("missing authorization header");

    if (!std.mem.eql(u8, provided, AUTH_HEADER_VALUE)) {
        return res.withBody("invalid authorization token");
    }

    return chain.next(ctx, req, res);
}

// ────────────────────────────────────────────────────────────────────
// Tests — each exercises a specific feature of group + middleware.
// Run via `zig build test` from `src/modules/custom_http_server`.
// ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn makeRequest(method: []const u8, path: []const u8, hdrs: ?std.StringHashMap([]const u8)) http_parser.HttpRequest {
    return .{
        .method = method,
        .path = path,
        .version = "HTTP/1.1",
        .headers = hdrs orelse std.StringHashMap([]const u8).init(testing.allocator),
        .body = "",
        .raw = "",
        .params = std.StringHashMap([]const u8).init(testing.allocator),
        .query = std.StringHashMap([]const u8).init(testing.allocator),
        ._client_fd = -1,
        .session = undefined,
    };
}

/// Bootstrap a Router living on a heap-allocated ArenaAllocator.
///
/// The arena is heap-allocated (via `testing.allocator`) so the
/// Router's `arena: Allocator` field — which captures the arena's
/// `*ArenaAllocator` pointer — stays valid for the lifetime of the
/// arena. (Earlier versions returned the arena by value, which made
/// Router.arena a dangling pointer into the bootstrap function's
/// stack frame after return — segfault at the first allocation
/// through Router.arena.)
fn bootstrap() struct { arena: *std.heap.ArenaAllocator, r: *Router } {
    const arena = testing.allocator.create(std.heap.ArenaAllocator) catch unreachable;
    arena.* = std.heap.ArenaAllocator.init(testing.allocator);
    const r = arena.allocator().create(Router) catch unreachable;
    r.* = Router.init(arena.allocator());
    return .{ .arena = arena, .r = r };
}

test "example: public /health resolves (no middleware)" {
    var bs = bootstrap();
    // Arena lives on the heap; the defer runs `arena.deinit()` (frees
    // every allocation it made) then `testing.allocator.destroy(arena)`
    // (frees the arena struct itself).
    defer {
        bs.arena.deinit();
        testing.allocator.destroy(bs.arena);
    }

    _ = registerExampleRoutes(bs.arena.allocator(), bs.r);

    var req = makeRequest("GET", "/health", null);
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();

    const ctx = http_parser.HttpContext{ .allocator = bs.arena.allocator(), .io = undefined };
    const result = bs.r.matchRoute("GET", "/health", &req, ctx);
    try testing.expect(result != null);

    // Public route has no middleware — chain.run dispatches straight to final_handler.
    switch (result.?) {
        .handler => |h| {
            const resp = try h.chain.run(h.ctx, h.req, h.res);
            try testing.expectEqual(@as(u16, 200), resp.status_code);
            try testing.expectEqualStrings("OK", resp.body);
        },
        else => return error.UnexpectedMatchVariant,
    }
}

test "example: /api/v1/ping resolves under prefix + runs requestLogger" {
    var bs = bootstrap();
    defer {
        bs.arena.deinit();
        testing.allocator.destroy(bs.arena);
    }

    _ = registerExampleRoutes(bs.arena.allocator(), bs.r);

    var req = makeRequest("GET", "/api/v1/ping", null);
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();

    const ctx = http_parser.HttpContext{ .allocator = bs.arena.allocator(), .io = undefined };
    const result = bs.r.matchRoute("GET", "/api/v1/ping", &req, ctx);
    try testing.expect(result != null);

    switch (result.?) {
        .handler => |h| {
            const resp = try h.chain.run(h.ctx, h.req, h.res);
            try testing.expectEqual(@as(u16, 200), resp.status_code);
            // requestLogger stamped X-Request-Id on the way down — it must be on the final response.
            try testing.expect(resp.headers.get("X-Request-Id") != null);
            try testing.expectEqualStrings("example-trace-1", resp.headers.get("X-Request-Id").?);
            // JSON body set by the handler itself.
            try testing.expectEqualStrings("application/json", resp.headers.get("Content-Type").?);
        },
        else => return error.UnexpectedMatchVariant,
    }
}

test "example: nested group inherits prefix AND parent middlewares" {
    var bs = bootstrap();
    defer {
        bs.arena.deinit();
        testing.allocator.destroy(bs.arena);
    }

    _ = registerExampleRoutes(bs.arena.allocator(), bs.r);

    // /api/v1/admin/secret should:
    //   1. Match the nested group's prefix /api/v1/admin + /secret = /api/v1/admin/secret
    //   2. Run requestLogger (inherited from outer /api group)
    //   3. Run authGuard (added by inner /api/v1/admin group)
    //   4. Then run the handler.
    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();
    try headers.put("Authorization", AUTH_HEADER_VALUE);

    var req = makeRequest("GET", "/api/v1/admin/secret", headers);
    defer req.params.deinit();
    defer req.query.deinit();

    const ctx = http_parser.HttpContext{ .allocator = bs.arena.allocator(), .io = undefined };
    const result = bs.r.matchRoute("GET", "/api/v1/admin/secret", &req, ctx);
    try testing.expect(result != null);

    switch (result.?) {
        .handler => |h| {
            const resp = try h.chain.run(h.ctx, h.req, h.res);
            try testing.expectEqual(@as(u16, 200), resp.status_code);
            // Inherited middleware ran — X-Request-Id is present.
            try testing.expect(resp.headers.get("X-Request-Id") != null);
        },
        else => return error.UnexpectedMatchVariant,
    }
}

test "example: authGuard short-circuits when Authorization header missing" {
    var bs = bootstrap();
    defer {
        bs.arena.deinit();
        testing.allocator.destroy(bs.arena);
    }

    _ = registerExampleRoutes(bs.arena.allocator(), bs.r);

    var req = makeRequest("GET", "/api/v1/admin/secret", null);
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();

    const ctx = http_parser.HttpContext{ .allocator = bs.arena.allocator(), .io = undefined };
    const result = bs.r.matchRoute("GET", "/api/v1/admin/secret", &req, ctx);
    try testing.expect(result != null);

    switch (result.?) {
        .handler => |h| {
            const resp = try h.chain.run(h.ctx, h.req, h.res);
            // Chain short-circuited at authGuard — body is the guard's
            // "missing authorization header" message, NOT the handler's
            // json body.
            try testing.expectEqualStrings("missing authorization header", resp.body);
            try testing.expectEqualStrings("Bearer", resp.headers.get("WWW-Authenticate").?);
            // Note: requestLogger ran FIRST (it's earlier in the chain),
            // so its X-Request-Id header IS still on the response —
            // requestLogger called chain.next(...) to invoke authGuard,
            // and the header it stamped traveled along. This is the
            // desired middleware semantic: earlier middlewares' effects
            // persist through a later short-circuit.
            try testing.expectEqualStrings("example-trace-1", resp.headers.get("X-Request-Id").?);
        },
        else => return error.UnexpectedMatchVariant,
    }
}

test "example: authGuard rejects bad token" {
    var bs = bootstrap();
    defer {
        bs.arena.deinit();
        testing.allocator.destroy(bs.arena);
    }

    _ = registerExampleRoutes(bs.arena.allocator(), bs.r);

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();
    try headers.put("Authorization", "Bearer wrong-token");

    var req = makeRequest("GET", "/api/v1/admin/secret", headers);
    defer req.params.deinit();
    defer req.query.deinit();

    const ctx = http_parser.HttpContext{ .allocator = bs.arena.allocator(), .io = undefined };
    const result = bs.r.matchRoute("GET", "/api/v1/admin/secret", &req, ctx);
    try testing.expect(result != null);

    switch (result.?) {
        .handler => |h| {
            const resp = try h.chain.run(h.ctx, h.req, h.res);
            try testing.expectEqualStrings("invalid authorization token", resp.body);
        },
        else => return error.UnexpectedMatchVariant,
    }
}

test "example: routes outside the group don't run the middleware" {
    var bs = bootstrap();
    defer {
        bs.arena.deinit();
        testing.allocator.destroy(bs.arena);
    }

    _ = registerExampleRoutes(bs.arena.allocator(), bs.r);

    // /health is registered with r.get(...) — NOT through api. So no
    // middleware runs, and no X-Request-Id is stamped.
    var req = makeRequest("GET", "/health", null);
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();

    const ctx = http_parser.HttpContext{ .allocator = bs.arena.allocator(), .io = undefined };
    const result = bs.r.matchRoute("GET", "/health", &req, ctx);
    try testing.expect(result != null);

    switch (result.?) {
        .handler => |h| {
            const resp = try h.chain.run(h.ctx, h.req, h.res);
            try testing.expectEqual(@as(u16, 200), resp.status_code);
            try testing.expect(resp.headers.get("X-Request-Id") == null);
        },
        else => return error.UnexpectedMatchVariant,
    }
}

test "example: HTTP method matters — POST /api/v1/admin/secret works" {
    var bs = bootstrap();
    defer {
        bs.arena.deinit();
        testing.allocator.destroy(bs.arena);
    }

    _ = registerExampleRoutes(bs.arena.allocator(), bs.r);

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();
    try headers.put("Authorization", AUTH_HEADER_VALUE);

    var req = makeRequest("POST", "/api/v1/admin/secret", headers);
    req.body = "echoed!";
    defer req.params.deinit();
    defer req.query.deinit();

    const ctx = http_parser.HttpContext{ .allocator = bs.arena.allocator(), .io = undefined };
    const result = bs.r.matchRoute("POST", "/api/v1/admin/secret", &req, ctx);
    try testing.expect(result != null);

    switch (result.?) {
        .handler => |h| {
            const resp = try h.chain.run(h.ctx, h.req, h.res);
            try testing.expectEqualStrings("echoed!", resp.body);
        },
        else => return error.UnexpectedMatchVariant,
    }
}

test "example: HTTP method mismatch returns no route" {
    var bs = bootstrap();
    defer {
        bs.arena.deinit();
        testing.allocator.destroy(bs.arena);
    }

    _ = registerExampleRoutes(bs.arena.allocator(), bs.r);

    var req = makeRequest("GET", "/api/v1/echo", null); // echo is POST-only
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();

    const ctx = http_parser.HttpContext{ .allocator = bs.arena.allocator(), .io = undefined };
    const result = bs.r.matchRoute("GET", "/api/v1/echo", &req, ctx);
    try testing.expect(result == null);
}
