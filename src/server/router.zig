const std = @import("std");
const http_parser = @import("http_parser.zig");

pub const Self = @This();

/// Handler fn: (ctx, request, response) -> anyerror!HttpResponse
/// `ctx` is `HttpContext` BY VALUE (the per-request execution context:
/// allocator + io + optional SSE client_id). HttpContext is a small
/// value (3 fields) — passing by value avoids a pointer indirection on
/// every handler call and matches the WebSocket handler convention.
/// `req` is `HttpRequest` **BY VALUE** — a shallow snapshot from the
/// post-route-match request. The cross-redirect session lives on
/// `req.session` (set by the listen loop) — handlers call
/// `req.session.set / getString / flushPending`, and the redirect
/// helper `res.redirectWith(req, loc)` reads `req.session.outgoing`
/// after the handler returns.
pub const HandlerFn = *const fn (
    ctx: http_parser.HttpContext,
    req: http_parser.HttpRequest,
    res: http_parser.HttpResponse,
) anyerror!http_parser.HttpResponse;

/// SSE streaming handler — same shape as `HandlerFn` plus the SSE-specific
/// `client_id` lives on `ctx.client_id` (set by the listen loop after
/// `sse_manager.registerClient`).
pub const SseHandlerFn = *const fn (
    ctx: http_parser.HttpContext,
    req: http_parser.HttpRequest,
    res: http_parser.HttpResponse,
) anyerror!http_parser.HttpResponse;

/// WebSocket handler.
///
/// Unlike SSE handlers, the WebSocket handler is invoked AFTER the
/// transport handshake has completed (the 101 response has already been
/// sent). The handler receives the parsed `HttpRequest` (so it can read
/// headers / query / params / session), the GinwaServer pointer (so
/// it can read frames and broadcast via the WsManager), the client fd,
/// and the client's 16-byte id (so it can send targeted messages or
/// remove the client early).
///
/// The handler runs in the same per-connection thread as the read loop
/// (the listen loop spawns the handler on the worker thread). When the
/// handler returns, the WebSocket close handshake is initiated and the
/// client is removed from the WsManager.
pub const WsHandlerFn = *const fn (
    ctx: http_parser.HttpContext,
    req: http_parser.HttpRequest,
    server: *anyopaque,
    client_fd: i32,
    client_id: *[16]u8,
) anyerror!void;

/// Middleware function. Runs BEFORE the route's handler if the route's
/// group (or any enclosing group) registered the middleware via `use`.
///
/// Middlewares are composed into a per-request `MiddlewareChain`:
/// `chain.run` walks the slice in registration order (outermost group
/// first, innermost last, route's own last). A middleware that wants to
/// continue the chain MUST return whatever `chain.next(ctx, req, res)`
/// returns. A middleware that wants to SHORT-CIRCUIT the chain (e.g.
/// returning a 401 on auth failure) returns its own `HttpResponse`
/// WITHOUT calling `chain.next(...)`.
///
/// `req` and `res` are passed by value (matching `HandlerFn`); to add a
/// header or mutate state, derive a new value via `res.setHeader(...)`
/// (or similar builder methods) and pass THAT to `chain.next(...)`.
pub const MiddlewareFn = *const fn (
    ctx: http_parser.HttpContext,
    req: http_parser.HttpRequest,
    res: http_parser.HttpResponse,
    chain: *MiddlewareChain,
) anyerror!http_parser.HttpResponse;

/// Per-request middleware chain state. Allocated on the per-request arena
/// inside `matchRoute` and torn down when the request's arena is freed.
///
/// The chain walks `middlewares[0]`, `middlewares[1]`, ..., then
/// `final_handler` — in that exact order. Each middleware bumps
/// `index` on entry; if a middleware never calls `chain.next(...)`,
/// nothing further runs and the middleware's returned response is the
/// final response.
///
/// Lifetime: per-request. The `middlewares` slice is borrowed from the
/// route's storage (allocated once at route registration on the Router
/// arena), so re-using the Router across requests is safe. Only the
/// `MiddlewareChain` struct itself is per-request (one small arena
/// alloc per matched route).
pub const MiddlewareChain = struct {
    middlewares: []const MiddlewareFn,
    final_handler: HandlerFn,
    /// Fail-redirect base for the framework pre-handler security gate
    /// (origin vs server.cors + body-size). Null = gate disabled for
    /// this route. Copied from the matched Route by `matchRoute`.
    on_pre_handler_fail: ?[]const u8 = null,
    /// Index of the next middleware to invoke. Invariant:
    /// 0 <= index <= middlewares.len.
    index: usize = 0,

    /// Entry point — called exactly ONCE by the listen loop after
    /// `matchRoute` returns a `.handler` `RouteResult`. If the route
    /// has no middlewares (slice is empty), this dispatches straight
    /// to `final_handler`.
    pub fn run(
        self: *MiddlewareChain,
        ctx: http_parser.HttpContext,
        req: http_parser.HttpRequest,
        res: http_parser.HttpResponse,
    ) anyerror!http_parser.HttpResponse {
        if (self.index >= self.middlewares.len) {
            return self.final_handler(ctx, req, res);
        }
        const mw = self.middlewares[self.index];
        self.index += 1;
        return mw(ctx, req, res, self);
    }

    /// Advance to the next middleware (or, when all middlewares have
    /// run, the final handler). Middlewares that want to continue the
    /// chain must call this and return its result. Calling `next`
    /// twice from the same middleware is undefined behavior — the
    /// signature is single-call only, matching Express / Gin / Chi.
    pub fn next(
        self: *MiddlewareChain,
        ctx: http_parser.HttpContext,
        req: http_parser.HttpRequest,
        res: http_parser.HttpResponse,
    ) anyerror!http_parser.HttpResponse {
        return self.run(ctx, req, res);
    }
};

/// Route type to distinguish SSE from regular handlers
pub const RouteType = enum {
    regular,
    sse,
    websocket,
};

pub const Router = Self;

routes: std.ArrayListUnmanaged(Route) = .empty,
arena: std.mem.Allocator,

pub const Route = struct {
    method: []const u8 = "",
    path: []const u8 = "",
    handler: HandlerFn = defaultHandler,
    sse_handler: ?SseHandlerFn = null,
    ws_handler: ?WsHandlerFn = null,
    route_type: RouteType = .regular,
    /// Snapshot of middleware slice inherited from enclosing group(s)
    /// plus middlewares added directly on the route. Empty slice if
    /// the route has no middleware. Lives on the Router arena; the
    /// per-request `MiddlewareChain` borrows this slice.
    middlewares: []const MiddlewareFn = &.{},
    /// Framework-level pre-handler security gate. When non-null, the
    /// dispatch loop runs `security.preHandlerCheck` (origin vs
    /// `server.cors.allowed_origins` + body-size cap) BEFORE the handler
    /// and, on failure, returns `302 → <on_pre_handler_fail><code>`
    /// without invoking the handler. Null = no gate (safe for GETs and
    /// non-browser endpoints). See `RouteOptions`.
    on_pre_handler_fail: ?[]const u8 = null,
    /// Per-route body-size override (bytes). Null = inherit the group's
    /// `maxBodyBytes`, or the server's `max_body_bytes` when the group
    /// has none. See `RouteOptions.max_body_bytes`.
    max_body_bytes: ?usize = null,
};

/// Options for the `*WithOpts` route-registration variants. Mirrors the
/// optional Route fields an app may want to set at registration time.
pub const RouteOptions = struct {
    /// Fail-redirect base for the framework pre-handler gate (origin +
    /// body size). The error code label is appended, e.g.
    /// `.on_pre_handler_fail = "/signup?error="` produces
    /// `/signup?error=cross_origin`. Null disables the gate for this
    /// route (the default — GETs don't need it).
    on_pre_handler_fail: ?[]const u8 = null,
    /// Per-route body-size cap override (bytes). Takes precedence over
    /// the group's `maxBodyBytes` and the server's `max_body_bytes`.
    /// Null = inherit. Example: a 100 MB upload route on an otherwise-
    /// capped server: `.max_body_bytes = 100 * 1024 * 1024`.
    max_body_bytes: ?usize = null,
};

pub fn defaultHandler(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
    return res.withBody("");
}

pub fn init(arena: std.mem.Allocator) Self {
    return .{
        .arena = arena,
        .routes = .empty,
    };
}

pub fn deinit(self: *Self) void {
    self.routes.deinit(self.arena);
}

// ────────────────────────────────────────────────────────────────────
// Group — sub-router with shared prefix + middleware chain.
//
// router.group("/api") returns a Group; routes registered via group.get /
// group.post / etc. are stamped with "/api" prepended to their path,
// and middlewares added via group.use(mw) are attached to each route.
// Nested groups (group.group(...)) inherit the parent's prefix and
// middlewares — inner group's middlewares run AFTER the outer group's
// in the chain.
//
// Snapshot semantics: middlewares added to a group after a route has
// already been registered do NOT retroactively apply. Each route's
// `middlewares` slice is captured at registration time. This matches
// Express and avoids the bug where adding middleware later
// accidentally re-applies it to already-registered routes.
// ────────────────────────────────────────────────────────────────────

pub const Group = struct {
    router: *Self,
    /// Effective prefix (concatenation of all enclosing prefixes + this
    /// group's prefix). Empty string means "no prefix" — routes are
    /// registered at their raw path.
    prefix: []const u8,
    /// Middleware list — cloned from parent group at creation time, then
    /// mutated by `use`. Stored on the Router arena.
    middlewares: std.ArrayListUnmanaged(MiddlewareFn),
    /// Group-level fail-redirect base for the framework pre-handler
    /// security gate. Set ONCE via `preHandlerFailBase`; every state-
    /// changing route (POST/PUT/PATCH/DELETE) registered on this group
    /// AFTER the call inherits it. GET/SSE/WS routes are never gated.
    /// A route's `RouteOptions.on_pre_handler_fail` overrides this.
    /// Null = routes get no gate unless they opt in individually.
    pre_handler_fail_base: ?[]const u8 = null,
    /// Group-level body-size cap override (bytes). Routes registered
    /// after `maxBodyBytes` inherit it; route opts win over the group;
    /// null = inherit the server's `max_body_bytes`. Nested groups
    /// created after the call inherit it.
    max_body_bytes: ?usize = null,

    /// Set the group-wide fail-redirect base (e.g. `"/admin/users?error="`).
    /// Applies to state-changing routes registered after this call;
    /// nested groups created after this call inherit it.
    pub fn preHandlerFailBase(self: *Group, base: []const u8) !void {
        self.pre_handler_fail_base = try self.router.arena.dupe(u8, base);
    }

    /// Set a group-wide body-size cap override (bytes). Applies to all
    /// routes registered after this call; nested groups created after
    /// this call inherit it. Route-level `.max_body_bytes` wins.
    pub fn maxBodyBytes(self: *Group, cap: usize) void {
        self.max_body_bytes = cap;
    }

    /// Add a middleware to this group. Runs for every route registered
    /// on this group AFTER this call. Multiple middlewares run in
    /// registration order.
    pub fn use(self: *Group, mw: MiddlewareFn) !void {
        try self.middlewares.append(self.router.arena, mw);
    }

    /// Add a GET route. Path is concatenated with the group's prefix.
    pub fn get(self: *Group, path: []const u8, handler: anytype) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRoute("GET", combined, handler, .regular, null, null);
    }

    pub fn post(self: *Group, path: []const u8, handler: anytype) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRoute("POST", combined, handler, .regular, null, null);
    }

    pub fn put(self: *Group, path: []const u8, handler: anytype) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRoute("PUT", combined, handler, .regular, null, null);
    }

    pub fn delete(self: *Group, path: []const u8, handler: anytype) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRoute("DELETE", combined, handler, .regular, null, null);
    }

    pub fn patch(self: *Group, path: []const u8, handler: anytype) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRoute("PATCH", combined, handler, .regular, null, null);
    }

    // ─── *WithOpts variants — enable the framework pre-handler gate ────

    pub fn getWithOpts(self: *Group, path: []const u8, handler: anytype, opts: RouteOptions) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRouteWithOpts("GET", combined, handler, .regular, null, null, opts);
    }

    pub fn postWithOpts(self: *Group, path: []const u8, handler: anytype, opts: RouteOptions) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRouteWithOpts("POST", combined, handler, .regular, null, null, opts);
    }

    pub fn putWithOpts(self: *Group, path: []const u8, handler: anytype, opts: RouteOptions) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRouteWithOpts("PUT", combined, handler, .regular, null, null, opts);
    }

    pub fn deleteWithOpts(self: *Group, path: []const u8, handler: anytype, opts: RouteOptions) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRouteWithOpts("DELETE", combined, handler, .regular, null, null, opts);
    }

    pub fn patchWithOpts(self: *Group, path: []const u8, handler: anytype, opts: RouteOptions) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRouteWithOpts("PATCH", combined, handler, .regular, null, null, opts);
    }

    /// SSE route on the group. Always GET (per SSE spec).
    /// Note: SSE routes do NOT currently run middleware; only `.regular`
    /// routes do. If a middleware needs to gate an SSE endpoint, register
    /// the SSE under a regular path prefix and have an upstream
    /// auth-protected `.regular` route dispatch to it. (SSE-on-group
    /// middleware is a candidate for a future iteration; SSE handshake
    /// lifecycle complicates chain teardown.)
    pub fn sse(self: *Group, path: []const u8, handler: anytype) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRoute("GET", combined, handler, .sse, handler, null);
    }

    /// WebSocket route on the group. Always GET (per RFC 6455 §4.1).
    /// Same caveat as `sse` — middleware doesn't currently run on WS.
    /// Takes ONLY the WS handler (mirrors `Router.ws`): `.handler` is
    /// parked on `defaultHandler` because dispatch never reads it for
    /// websocket routes (see `RouteResult.websocket`).
    pub fn ws(self: *Group, path: []const u8, handler: WsHandlerFn) !void {
        const combined = try combinePrefix(self.router.arena, self.prefix, path);
        try self.appendRoute("GET", combined, defaultHandler, .websocket, null, handler);
    }

    /// Nested group. Inherits parent's prefix (concatenates with this
    /// new prefix, separated by '/' only when neither side has one) AND
    /// inherits parent's middlewares. After this call, both groups are
    /// independent — adding more middleware to the parent does NOT
    /// affect routes registered through the inner group.
    pub fn group(self: *Group, prefix: []const u8) !Group {
        const combined = try combinePrefix(self.router.arena, self.prefix, prefix);
        var mws: std.ArrayListUnmanaged(MiddlewareFn) = .empty;
        try mws.appendSlice(self.router.arena, self.middlewares.items);
        return .{
            .router = self.router,
            .prefix = combined,
            .middlewares = mws,
            // Nested groups inherit the parent's fail base + body cap at
            // creation time (same snapshot semantics as middlewares).
            .pre_handler_fail_base = self.pre_handler_fail_base,
            .max_body_bytes = self.max_body_bytes,
        };
    }

    /// Internal — append a route snapshot to the parent router. Snapshots
    /// the middleware slice onto the Router arena so it's stable.
    fn appendRoute(
        self: *Group,
        method: []const u8,
        path: []const u8,
        handler: anytype,
        route_type: RouteType,
        sse_handler: ?SseHandlerFn,
        ws_handler: ?WsHandlerFn,
    ) !void {
        return self.appendRouteWithOpts(method, path, handler, route_type, sse_handler, ws_handler, .{});
    }

    /// Internal — `appendRoute` with options (fail-redirect base etc.).
    fn appendRouteWithOpts(
        self: *Group,
        method: []const u8,
        path: []const u8,
        handler: anytype,
        route_type: RouteType,
        sse_handler: ?SseHandlerFn,
        ws_handler: ?WsHandlerFn,
        opts: RouteOptions,
    ) !void {
        const mws = try self.router.arena.dupe(MiddlewareFn, self.middlewares.items);
        // Fail-base resolution: explicit route opts win; otherwise state-
        // changing methods inherit the group's preHandlerFailBase. GET /
        // SSE / WS are never gated.
        const is_state_changing = std.mem.eql(u8, method, "POST") or
            std.mem.eql(u8, method, "PATCH") or
            std.mem.eql(u8, method, "PUT") or
            std.mem.eql(u8, method, "DELETE");
        const fail_base: ?[]const u8 = if (opts.on_pre_handler_fail) |b|
            try self.router.arena.dupe(u8, b)
        else if (is_state_changing) self.pre_handler_fail_base else null;
        // Body-cap resolution: route opts > group maxBodyBytes > null
        // (null = inherit the server's max_body_bytes at dispatch time).
        try self.router.routes.append(self.router.arena, Route{
            .method = method,
            .path = path,
            .handler = handler,
            .route_type = route_type,
            .sse_handler = sse_handler,
            .ws_handler = ws_handler,
            .middlewares = mws,
            .on_pre_handler_fail = fail_base,
            .max_body_bytes = opts.max_body_bytes orelse self.max_body_bytes,
        });
    }
};

/// Combine two path segments with proper slash handling. Always
/// produces exactly ONE '/' between non-empty segments (or zero
/// if one side is empty after trimming). Cases:
///   combine("","/foo")       -> "/foo"
///   combine("/admin","")     -> "/admin"
///   combine("/admin","x")    -> "/admin/x"
///   combine("/admin","/x")   -> "/admin/x"     (no double slash)
///   combine("/admin/","x")   -> "/admin/x"     (no double slash)
///   combine("/admin/","/x")  -> "/admin/x"     (no double slash)
///   combine("/","/foo")      -> "/foo"         (root absorbs leading slash)
///   combine("/","/")         -> "/"
///   combine("/","")          -> "/"
///   combine("/","x")         -> "/x"
///   combine("","")           -> ""
///
/// The returned slice lives on `arena` (Router's arena when called
/// from group methods, or any arena when called directly).
pub fn combinePrefix(arena: std.mem.Allocator, prefix: []const u8, path: []const u8) ![]const u8 {
    // Root prefix special-case: "/" + any path returns the path
    // re-anchored at the root with exactly one leading '/'. Treating
    // "/" as a normal prefix would produce "//foo" when joining
    // with "/foo".
    if (std.mem.eql(u8, prefix, "/")) {
        // path already starts with '/' → return as-is.
        if (path.len > 0 and path[0] == '/') return path;
        // path is empty or has no leading slash → restore the root.
        if (path.len == 0) return "/";
        return try std.fmt.allocPrint(arena, "/{s}", .{path});
    }

    if (prefix.len == 0) return path;
    if (path.len == 0) return prefix;

    // Strip trailing '/' from prefix until we hit a non-slash.
    var prefix_end: usize = prefix.len;
    while (prefix_end > 0 and prefix[prefix_end - 1] == '/') : (prefix_end -= 1) {}
    const prefix_trim = prefix[0..prefix_end];

    // Strip leading '/' from path.
    var path_start: usize = 0;
    while (path_start < path.len and path[path_start] == '/') : (path_start += 1) {}
    const path_trim = path[path_start..];

    // After trimming slashes, an empty prefix stays empty — restore
    // a single leading '/' so the joined path stays anchored.
    if (prefix_trim.len == 0) {
        return try std.fmt.allocPrint(arena, "/{s}", .{path_trim});
    }
    if (path_trim.len == 0) return prefix_trim;
    return try std.fmt.allocPrint(arena, "{s}/{s}", .{ prefix_trim, path_trim });
}

// ────────────────────────────────────────────────────────────────────
// Router — top-level registration methods (no group, no middleware).
// ────────────────────────────────────────────────────────────────────

/// Create a sub-router. Routes and middleware registered on the group
/// are stamped with `prefix` and inherit the group's middleware list.
/// Multiple groups can be active at once; they're orthogonal — each
/// keeps its own prefix and middleware chain.
pub fn group(self: *Self, prefix: []const u8) Group {
    return .{
        .router = self,
        .prefix = prefix,
        .middlewares = .empty,
    };
}

/// Add a GET route with generic context support
pub fn get(self: *Self, path: []const u8, handler: anytype) !void {
    return self.addRouteInternal("GET", path, handler);
}

/// Add a POST route with generic context support
pub fn post(self: *Self, path: []const u8, handler: anytype) !void {
    return self.addRouteInternal("POST", path, handler);
}

/// Add a PUT route with generic context support
pub fn put(self: *Self, path: []const u8, handler: anytype) !void {
    return self.addRouteInternal("PUT", path, handler);
}

/// Add a DELETE route with generic context support
pub fn delete(self: *Self, path: []const u8, handler: anytype) !void {
    return self.addRouteInternal("DELETE", path, handler);
}

/// Add a PATCH route with generic context support
pub fn patch(self: *Self, path: []const u8, handler: anytype) !void {
    return self.addRouteInternal("PATCH", path, handler);
}

// ─── *WithOpts variants — enable the framework pre-handler gate ────────

pub fn getWithOpts(self: *Self, path: []const u8, handler: anytype, opts: RouteOptions) !void {
    return self.addRouteInternalWithOpts("GET", path, handler, opts);
}

pub fn postWithOpts(self: *Self, path: []const u8, handler: anytype, opts: RouteOptions) !void {
    return self.addRouteInternalWithOpts("POST", path, handler, opts);
}

pub fn putWithOpts(self: *Self, path: []const u8, handler: anytype, opts: RouteOptions) !void {
    return self.addRouteInternalWithOpts("PUT", path, handler, opts);
}

pub fn deleteWithOpts(self: *Self, path: []const u8, handler: anytype, opts: RouteOptions) !void {
    return self.addRouteInternalWithOpts("DELETE", path, handler, opts);
}

pub fn patchWithOpts(self: *Self, path: []const u8, handler: anytype, opts: RouteOptions) !void {
    return self.addRouteInternalWithOpts("PATCH", path, handler, opts);
}

/// Add an SSE streaming route
pub fn sse(self: *Self, path: []const u8, handler: anytype) !void {
    try self.routes.append(self.arena, Route{
        .method = "GET",
        .path = path,
        .handler = undefined,
        .sse_handler = handler,
        .route_type = .sse,
    });
}

/// Add a WebSocket route. WebSocket routes are always GET (per RFC 6455 §4.1).
pub fn ws(self: *Self, path: []const u8, handler: anytype) !void {
    try self.routes.append(self.arena, Route{
        .method = "GET",
        .path = path,
        .handler = undefined,
        .ws_handler = handler,
        .route_type = .websocket,
    });
}

/// Generic internal route adder — no middleware (use group for that).
fn addRouteInternal(self: *Self, method: []const u8, path: []const u8, handler: anytype) !void {
    return self.addRouteInternalWithOpts(method, path, handler, .{});
}

/// Generic internal route adder with options (fail-redirect base etc.).
fn addRouteInternalWithOpts(self: *Self, method: []const u8, path: []const u8, handler: anytype, opts: RouteOptions) !void {
    try self.routes.append(self.arena, Route{
        .method = method,
        .path = path,
        .handler = handler,
        .route_type = .regular,
        .on_pre_handler_fail = if (opts.on_pre_handler_fail) |b|
            try self.arena.dupe(u8, b)
        else
            null,
    });
}

/// Route matching result - chain + contexts needed to execute it.
///
/// `RouteResult.handler` carries a `*MiddlewareChain` that the listen
/// loop runs via `chain.run(ctx, req, res)`. With no middleware the
/// chain's `run` dispatches straight to the final handler — same shape
/// as before this feature was added.
pub const RouteResult = union(enum) {
    handler: struct {
        chain: *MiddlewareChain,
        ctx: http_parser.HttpContext,
        req: http_parser.HttpRequest,
        res: http_parser.HttpResponse,
        /// Effective body cap for THIS route: route/group override when
        /// set, otherwise the server's `max_body_bytes`. The dispatch
        /// loop passes it to the engine gate.
        max_body_bytes: usize,
    },
    sse: struct {
        handler: SseHandlerFn,
        ctx: http_parser.HttpContext,
        req: http_parser.HttpRequest,
    },
    websocket: struct {
        handler: WsHandlerFn,
        ctx: http_parser.HttpContext,
        req: http_parser.HttpRequest,
    },
};

/// Route matching and execution - returns the chain to execute.
///
/// `req` is `*HttpRequest` (mutated to populate `req.params` from
/// `:name` patterns); the returned `RouteResult` carries a snapshot
/// value-copy of req with the populated params. The session pointer
/// is already inside the request (`req.session`), so no separate
/// session arg is needed. `ctx` is the per-request allocator + io
/// (passed BY VALUE; HttpContext is a small 3-field struct).
///
/// Per-request allocation: when a route has middlewares, this
/// allocates a small `MiddlewareChain` struct on `ctx.allocator` (the
/// per-request arena). When no middleware, we still allocate the
/// chain (one pointer-sized struct per request); the overhead is
/// negligible and keeps the listen loop branch-free.
pub fn matchRoute(
    self: *Self,
    req_method: []const u8,
    req_path: []const u8,
    req: *http_parser.HttpRequest,
    ctx: http_parser.HttpContext,
) ?RouteResult {
    for (self.routes.items) |route| {
        // Try exact match first
        if (std.mem.eql(u8, req_method, route.method) and std.mem.eql(u8, req_path, route.path)) {
            if (route.ws_handler) |wsHandler| {
                return .{ .websocket = .{ .handler = wsHandler, .ctx = ctx, .req = req.* } };
            }
            if (route.sse_handler) |sseHandler| {
                return .{ .sse = .{ .handler = sseHandler, .ctx = ctx, .req = req.* } };
            }
            const chain = ctx.allocator.create(MiddlewareChain) catch return null;
            chain.* = .{
                .middlewares = route.middlewares,
                .final_handler = route.handler,
                .on_pre_handler_fail = route.on_pre_handler_fail,
            };
            const res = http_parser.HttpResponse.init(200, "OK", ctx.allocator);
            return .{ .handler = .{ .chain = chain, .ctx = ctx, .req = req.*, .res = res, .max_body_bytes = route.max_body_bytes orelse 0 } };
        }

        // Try pattern matching with params (e.g., /hello/:name)
        if (std.mem.eql(u8, req_method, route.method) and matchPathWithParams(route.path, req_path, &req.params)) {
            if (route.ws_handler) |wsHandler| {
                return .{ .websocket = .{ .handler = wsHandler, .ctx = ctx, .req = req.* } };
            }
            if (route.sse_handler) |sseHandler| {
                return .{ .sse = .{ .handler = sseHandler, .ctx = ctx, .req = req.* } };
            }
            const chain = ctx.allocator.create(MiddlewareChain) catch return null;
            chain.* = .{
                .middlewares = route.middlewares,
                .final_handler = route.handler,
                .on_pre_handler_fail = route.on_pre_handler_fail,
            };
            const res = http_parser.HttpResponse.init(200, "OK", ctx.allocator);
            return .{ .handler = .{ .chain = chain, .ctx = ctx, .req = req.*, .res = res, .max_body_bytes = route.max_body_bytes orelse 0 } };
        }
    }
    return null;
}

/// Legacy route handler for backward compatibility. Bypasses
/// middleware — runs only the raw final handler (or returns 404 for
/// SSE/WS that matchRoute found). Kept for callers that pre-date the
/// group/middleware feature.
pub fn handleRoute(
    self: *Self,
    req_method: []const u8,
    req_path: []const u8,
    req: *http_parser.HttpRequest,
    ctx: http_parser.HttpContext,
) http_parser.HttpResponse {
    if (matchRoute(self, req_method, req_path, req, ctx)) |result| {
        switch (result) {
            .handler => |h| {
                // Legacy handleRoute skips middleware — just calls the
                // final handler directly. Useful for synthetic tests
                // that don't care about middleware semantics.
                return h.chain.final_handler(h.ctx, h.req, h.res) catch
                    http_parser.internalError("Handler error", std.heap.page_allocator);
            },
            .sse => return http_parser.notFound(std.heap.page_allocator),
            .websocket => return http_parser.notFound(std.heap.page_allocator),
        }
    }
    return http_parser.notFound(std.heap.page_allocator);
}

/// Match a route pattern against a request path and extract params
fn matchPathWithParams(pattern: []const u8, path: []const u8, params: *std.StringHashMap([]const u8)) bool {
    var pattern_parts = std.mem.splitScalar(u8, pattern, '/');
    var path_parts = std.mem.splitScalar(u8, path, '/');

    while (pattern_parts.next()) |pattern_part| {
        const path_part = path_parts.next() orelse return false;

        // If pattern part starts with ':', it's a param
        if (pattern_part.len > 0 and pattern_part[0] == ':') {
            const param_name = pattern_part[1..];
            params.put(param_name, path_part) catch return false;
        } else if (!std.mem.eql(u8, pattern_part, path_part)) {
            return false;
        }
    }

    return path_parts.next() == null;
}

// ────────────────────────────────────────────────────────────────────
// Tests — colocated test block exercising the corner cases of
// prefix combination (the Group implementation reuses combinePrefix,
// so this also documents the prefix-joining contract).
//
// Each test uses a fresh ArenaAllocator rooted at `std.testing.allocator`
// and frees the arena at scope exit. `combinePrefix` allocates a fresh
// `[]const u8` slice via `std.fmt.allocPrint` for most non-empty
// combinations — using a per-test arena keeps those allocations scoped
// to the test and avoids leaking them through the test allocator.
// (Earlier versions of these tests used `std.testing.allocator`
// directly, which made `combinePrefix`'s allocations show up as leaks
// in Zig's DebugAllocator — `zig build test` would fail with
// "leaked N allocations" at the end of the run.)
// ────────────────────────────────────────────────────────────────────

test "combinePrefix - empty/empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "", "");
    try std.testing.expectEqualStrings("", out);
}

test "combinePrefix - empty + path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "", "/foo");
    try std.testing.expectEqualStrings("/foo", out);
}

test "combinePrefix - prefix + empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "/admin", "");
    try std.testing.expectEqualStrings("/admin", out);
}

test "combinePrefix - no slash on either side joins with slash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "/admin", "x");
    try std.testing.expectEqualStrings("/admin/x", out);
}

test "combinePrefix - prefix has trailing slash, no double slash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "/admin/", "x");
    try std.testing.expectEqualStrings("/admin/x", out);
}

test "combinePrefix - path has leading slash, no double slash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "/admin", "/x");
    try std.testing.expectEqualStrings("/admin/x", out);
}

test "combinePrefix - both have slashes, no double slash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "/admin/", "/x");
    try std.testing.expectEqualStrings("/admin/x", out);
}

test "combinePrefix - root prefix + root path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "/", "/");
    try std.testing.expectEqualStrings("/", out);
}

test "combinePrefix - root prefix + child path produces single slash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "/", "/foo");
    try std.testing.expectEqualStrings("/foo", out);
}

test "combinePrefix - prefix with trailing slash + path with leading slash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "/admin/", "/v1/foo");
    try std.testing.expectEqualStrings("/admin/v1/foo", out);
}

test "combinePrefix - empty prefix + empty path returns empty slice" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try combinePrefix(arena.allocator(), "", "");
    try std.testing.expectEqual(@as(usize, 0), out.len);
}

// ============================================================================
// Tests — moved here from `router_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = router_tests; }` below pulls them into the run.
// ============================================================================

const router_tests = struct {
    const router = @import("router.zig");

    // Helper to create a mock HttpRequest for testing
    fn createMockRequest(method: []const u8, path: []const u8, allocator: std.mem.Allocator) http_parser.HttpRequest {
        return http_parser.HttpRequest{
            .method = method,
            .path = path,
            .version = "HTTP/1.1",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .raw = "",
            .params = std.StringHashMap([]const u8).init(allocator),
            .query = std.StringHashMap([]const u8).init(allocator),
            ._client_fd = -1,
        };
    }

    // ============================================================================
    // Router Initialization Tests
    // ============================================================================

    test "Router.init creates empty router" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        const r = router.Router.init(arena.allocator());
        try std.testing.expectEqual(@as(usize, 0), r.routes.items.len);
    }

    test "Router.deinit cleans up routes" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        r.deinit();
        // If we get here without memory leaks, the test passes
    }

    // ============================================================================
    // Basic Route Registration Tests
    // ============================================================================

    test "Router.get registers GET route" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/test", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("OK", std.heap.page_allocator);
            }
        }.handle);

        try std.testing.expectEqual(@as(usize, 1), r.routes.items.len);
        try std.testing.expectEqualStrings("GET", r.routes.items[0].method);
        try std.testing.expectEqualStrings("/test", r.routes.items[0].path);
    }

    test "Router.post registers POST route" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.post("/api/data", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("Created", std.heap.page_allocator);
            }
        }.handle);

        try std.testing.expectEqual(@as(usize, 1), r.routes.items.len);
        try std.testing.expectEqualStrings("POST", r.routes.items[0].method);
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  RouteOptions + on_pre_handler_fail — framework-level origin gate.
    //  server.cors is the single source of truth for WHICH origins are allowed;
    //  each state-changing route declares only WHERE to redirect on failure.
    // ───────────────────────────────────────────────────────────────────────────

    fn noopHandler(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
        return res.withBody("");
    }

    test "Route.on_pre_handler_fail defaults to null" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.post("/x", noopHandler);
        try std.testing.expectEqual(@as(?[]const u8, null), r.routes.items[0].on_pre_handler_fail);
    }

    test "postWithOpts stores on_pre_handler_fail base" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.postWithOpts("/admin/signin", noopHandler, .{
            .on_pre_handler_fail = "/admin/signin?error=",
        });

        try std.testing.expectEqual(@as(usize, 1), r.routes.items.len);
        try std.testing.expectEqualStrings("POST", r.routes.items[0].method);
        const base = r.routes.items[0].on_pre_handler_fail orelse return error.FailBaseMissing;
        try std.testing.expectEqualStrings("/admin/signin?error=", base);
    }

    test "getWithOpts stores on_pre_handler_fail base (GET routes can opt in too)" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.getWithOpts("/page", noopHandler, .{
            .on_pre_handler_fail = "/?error=",
        });

        const base = r.routes.items[0].on_pre_handler_fail orelse return error.FailBaseMissing;
        try std.testing.expectEqualStrings("/?error=", base);
    }

    test "group.postWithOpts combines prefix and stores fail base" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var g = r.group("");

        try g.postWithOpts("/users", noopHandler, .{ .on_pre_handler_fail = "/signup?error=" });

        try std.testing.expectEqualStrings("/users", r.routes.items[0].path);
        const base = r.routes.items[0].on_pre_handler_fail orelse return error.FailBaseMissing;
        try std.testing.expectEqualStrings("/signup?error=", base);
    }

    // ───────────────────────────────────────────────────────────────────────────
    //  Group-level fail base — set ONCE per group, inherited by its routes
    //  (state-changing methods only). Kills per-route boilerplate.
    // ───────────────────────────────────────────────────────────────────────────

    test "group.preHandlerFailBase applies to POST routes registered after it" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var g = r.group("");
        try g.preHandlerFailBase("/?error=");

        try g.post("/x", noopHandler);
        const base = r.routes.items[0].on_pre_handler_fail orelse return error.FailBaseMissing;
        try std.testing.expectEqualStrings("/?error=", base);
    }

    test "group.preHandlerFailBase does NOT gate GET routes" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var g = r.group("");
        try g.preHandlerFailBase("/?error=");

        try g.get("/x", noopHandler);
        try std.testing.expectEqual(@as(?[]const u8, null), r.routes.items[0].on_pre_handler_fail);
    }

    test "route opts override group base" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var g = r.group("");
        try g.preHandlerFailBase("/?error=");

        try g.postWithOpts("/special", noopHandler, .{ .on_pre_handler_fail = "/special-fail?error=" });
        const base = r.routes.items[0].on_pre_handler_fail orelse return error.FailBaseMissing;
        try std.testing.expectEqualStrings("/special-fail?error=", base);
    }

    test "nested group inherits parent fail base" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var rootg = r.group("");
        try rootg.preHandlerFailBase("/?error=");
        var adm = try rootg.group("/admin");

        try adm.post("/x", noopHandler);
        const base = r.routes.items[0].on_pre_handler_fail orelse return error.FailBaseMissing;
        try std.testing.expectEqualStrings("/?error=", base);
    }

    test "no group base + no route opts = gate disabled (back-compat)" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();
        var g = r.group("");

        try g.post("/x", noopHandler);
        try std.testing.expectEqual(@as(?[]const u8, null), r.routes.items[0].on_pre_handler_fail);
    }

    test "Router.put registers PUT route" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.put("/api/data/1", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("Updated", std.heap.page_allocator);
            }
        }.handle);

        try std.testing.expectEqual(@as(usize, 1), r.routes.items.len);
        try std.testing.expectEqualStrings("PUT", r.routes.items[0].method);
        try std.testing.expectEqualStrings("/api/data/1", r.routes.items[0].path);
    }

    test "Router.delete registers DELETE route" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.delete("/api/data/1", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("Deleted", std.heap.page_allocator);
            }
        }.handle);

        try std.testing.expectEqual(@as(usize, 1), r.routes.items.len);
        try std.testing.expectEqualStrings("DELETE", r.routes.items[0].method);
    }

    test "Router.patch registers PATCH route" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.patch("/api/data/1", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("Patched", std.heap.page_allocator);
            }
        }.handle);

        try std.testing.expectEqual(@as(usize, 1), r.routes.items.len);
        try std.testing.expectEqualStrings("PATCH", r.routes.items[0].method);
    }

    // ============================================================================
    // Route Matching Tests
    // ============================================================================

    test "Router.matchRoute exact match returns handler result" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/hello", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("hello");
            }
        }.handle);

        var req = createMockRequest("GET", "/hello", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("GET", "/hello", &req, ctx);
        try std.testing.expect(result != null);

        switch (result.?) {
            .handler => |res_data| {
                try std.testing.expectEqual(@as(u16, 200), res_data.res.status_code);
            },
            .sse => {
                try std.testing.expect(false); // Should not be SSE
            },
            .websocket => {
                try std.testing.expect(false); // Should not be WebSocket
            },
        }
    }

    test "Router.matchRoute no match returns null" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/existing", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("OK", std.heap.page_allocator);
            }
        }.handle);

        var req = createMockRequest("GET", "/nonexistent", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("GET", "/nonexistent", &req, ctx);
        try std.testing.expect(result == null);
    }

    test "Router.matchRoute method mismatch returns null" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/api", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("OK", std.heap.page_allocator);
            }
        }.handle);

        var req = createMockRequest("POST", "/api", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("POST", "/api", &req, ctx);
        try std.testing.expect(result == null);
    }

    test "Router.matchRoute case sensitive path matching" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/API", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("OK", std.heap.page_allocator);
            }
        }.handle);

        var req_lower = createMockRequest("GET", "/api", arena.allocator());
        defer req_lower.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result_lower = r.matchRoute("GET", "/api", &req_lower, ctx);
        try std.testing.expect(result_lower == null); // Case sensitive

        var req_exact = createMockRequest("GET", "/API", arena.allocator());
        defer req_exact.params.deinit();

        const result_exact = r.matchRoute("GET", "/API", &req_exact, ctx);
        try std.testing.expect(result_exact != null);
    }

    // ============================================================================
    // Path Parameter Extraction Tests
    // ============================================================================

    test "Router.matchRoute extracts path params" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/users/:id", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("OK", std.heap.page_allocator);
            }
        }.handle);

        var req = createMockRequest("GET", "/users/123", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("GET", "/users/123", &req, ctx);
        try std.testing.expect(result != null);

        const id_value = req.params.get("id");
        try std.testing.expect(id_value != null);
        try std.testing.expectEqualStrings("123", id_value.?);
    }

    test "Router.matchRoute extracts multiple path params" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/users/:userId/posts/:postId", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("OK", std.heap.page_allocator);
            }
        }.handle);

        var req = createMockRequest("GET", "/users/abc/posts/xyz", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("GET", "/users/abc/posts/xyz", &req, ctx);
        try std.testing.expect(result != null);

        try std.testing.expectEqualStrings("abc", req.params.get("userId").?);
        try std.testing.expectEqualStrings("xyz", req.params.get("postId").?);
    }

    test "Router.matchRoute params mismatch returns null" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        // Route expects two segments: /users/:id
        try r.get("/users/:id", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("OK", std.heap.page_allocator);
            }
        }.handle);

        // Request has extra segment: /users/123/extra
        var req = createMockRequest("GET", "/users/123/extra", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("GET", "/users/123/extra", &req, ctx);
        try std.testing.expect(result == null);
    }

    test "Router.matchRoute partial param match" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        // Route: /users/:id
        try r.get("/users/:id", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("OK", std.heap.page_allocator);
            }
        }.handle);

        // Request is just /users (missing param)
        var req = createMockRequest("GET", "/users", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("GET", "/users", &req, ctx);
        try std.testing.expect(result == null);
    }

    // ============================================================================
    // SSE Route Tests
    // ============================================================================

    test "Router.sse registers SSE route" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.sse("/stream", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.heap.page_allocator);
            }
        }.handle);

        try std.testing.expectEqual(@as(usize, 1), r.routes.items.len);
        try std.testing.expectEqualStrings("GET", r.routes.items[0].method);
        try std.testing.expectEqualStrings("/stream", r.routes.items[0].path);
        try std.testing.expectEqual(router.RouteType.sse, r.routes.items[0].route_type);
    }

    test "Router.sse route returns sse result" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.sse("/stream", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.heap.page_allocator);
            }
        }.handle);

        var req = createMockRequest("GET", "/stream", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("GET", "/stream", &req, ctx);
        try std.testing.expect(result != null);

        switch (result.?) {
            .handler => {
                try std.testing.expect(false); // Should not be handler
            },
            .sse => |sse_arm| {
                _ = sse_arm;
            },
            .websocket => {
                try std.testing.expect(false); // Should not be WebSocket
            },
        }
    }

    // ============================================================================
    // HandleRoute Tests
    // ============================================================================

    test "Router.handleRoute returns 404 when no route matches" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        var req = createMockRequest("GET", "/nonexistent", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const res = r.handleRoute("GET", "/nonexistent", &req, ctx);
        try std.testing.expectEqual(@as(u16, 404), res.status_code);
    }

    test "Router.handleRoute returns SSE as 404 (backward compat)" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.sse("/stream", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.heap.page_allocator);
            }
        }.handle);

        var req = createMockRequest("GET", "/stream", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        // handleRoute is legacy and doesn't handle SSE properly
        const res = r.handleRoute("GET", "/stream", &req, ctx);
        try std.testing.expectEqual(@as(u16, 404), res.status_code);
    }

    // ============================================================================
    // Multiple Routes Tests
    // ============================================================================

    test "Router handles multiple routes" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/a", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("A", std.heap.page_allocator);
            }
        }.handle);

        try r.post("/b", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("B", std.heap.page_allocator);
            }
        }.handle);

        try r.get("/c", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("C", std.heap.page_allocator);
            }
        }.handle);

        try std.testing.expectEqual(@as(usize, 3), r.routes.items.len);
    }

    test "Router matches correct route among multiple" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/first", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("First");
            }
        }.handle);

        try r.get("/second", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("Second");
            }
        }.handle);

        var req_second = createMockRequest("GET", "/second", arena.allocator());
        defer req_second.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("GET", "/second", &req_second, ctx);
        try std.testing.expect(result != null);

        switch (result.?) {
            .handler => |res_data| {
                try std.testing.expectEqual(@as(u16, 200), res_data.res.status_code);
            },
            .sse => {
                try std.testing.expect(false);
            },
            .websocket => {
                try std.testing.expect(false);
            },
        }
    }

    // ============================================================================
    // Context Preservation Tests
    // ============================================================================

    test "Router.preserves context data" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        try r.get("/test", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("OK");
            }
        }.handle);

        var req = createMockRequest("GET", "/test", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
        };

        const result = r.matchRoute("GET", "/test", &req, ctx);
        try std.testing.expect(result != null);
        try std.testing.expectEqual(@as(u16, 200), result.?.handler.res.status_code);
    }

    // ============================================================================
    // Group + Middleware Edge-Case Tests
    //
    // Each test below exercises one specific corner of the group / middleware
    // API. Cases are deliberately narrow — they verify one behaviour each so
    // failures point at the right invariant.
    // ============================================================================

    test "Group.get: prefix is prepended to the route path" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Handler = struct {
            fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("ok");
            }
        };

        var api = r.group("/api");
        try api.get("/v1/health", Handler.h);

        try std.testing.expectEqual(@as(usize, 1), r.routes.items.len);
        try std.testing.expectEqualStrings("/api/v1/health", r.routes.items[0].path);
        try std.testing.expectEqualStrings("GET", r.routes.items[0].method);
    }

    test "Group.post registers with method POST and prefix combined" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Handler = struct {
            fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.testing.allocator);
            }
        };

        var g = r.group("/api/v1");
        try g.post("/users", Handler.h);

        try std.testing.expectEqualStrings("/api/v1/users", r.routes.items[0].path);
        try std.testing.expectEqualStrings("POST", r.routes.items[0].method);
    }

    test "Group.put / delete / patch each register correctly" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Handler = struct {
            fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.testing.allocator);
            }
        };

        var g = r.group("/api");
        try g.put("/r", Handler.h);
        try g.delete("/r", Handler.h);
        try g.patch("/r", Handler.h);

        try std.testing.expectEqual(@as(usize, 3), r.routes.items.len);
        try std.testing.expectEqualStrings("PUT", r.routes.items[0].method);
        try std.testing.expectEqualStrings("DELETE", r.routes.items[1].method);
        try std.testing.expectEqualStrings("PATCH", r.routes.items[2].method);
        for (r.routes.items) |route| {
            try std.testing.expectEqualStrings("/api/r", route.path);
        }
    }

    test "Empty group prefix registers routes at their raw path" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Handler = struct {
            fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.testing.allocator);
            }
        };

        var g = r.group("");
        try g.get("/raw", Handler.h);

        try std.testing.expectEqualStrings("/raw", r.routes.items[0].path);
    }

    test "Group with prefix that ends in / does not double-slash" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Handler = struct {
            fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.testing.allocator);
            }
        };

        var g = r.group("/api/");
        try g.get("/v1/foo", Handler.h);
        try g.get("v1/bar", Handler.h); // missing leading slash → still joins correctly

        try std.testing.expectEqualStrings("/api/v1/foo", r.routes.items[0].path);
        try std.testing.expectEqualStrings("/api/v1/bar", r.routes.items[1].path);
    }

    test "Nested group concatenates prefixes correctly" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Handler = struct {
            fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.testing.allocator);
            }
        };

        var api = r.group("/api");
        var v1 = try api.group("/v1");
        try v1.get("/users", Handler.h);

        try std.testing.expectEqualStrings("/api/v1/users", r.routes.items[0].path);
    }

    test "Nested group inherits parent middlewares" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        // Each middleware stamps a unique HEADER (different keys so they
        // coexist on the final response). The handler sets the body.
        // Inspecting the headers proves which middleware ran.

        const OuterMw = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-Outer", "yes"));
            }
        }.h;

        const InnerMw = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-Inner", "yes"));
            }
        }.h;

        const Handler = struct {
            fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("HANDLER-RAN");
            }
        }.h;

        var api = r.group("/api");
        try api.use(OuterMw);
        var v1 = try api.group("/v1");
        try v1.use(InnerMw);
        try v1.get("/users", Handler);

        var req = createMockRequest("GET", "/api/v1/users", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };
        const result = r.matchRoute("GET", "/api/v1/users", &req, ctx);
        try std.testing.expect(result != null);

        switch (result.?) {
            .handler => |h| {
                try std.testing.expectEqual(@as(usize, 2), h.chain.middlewares.len);
                const final_res = try h.chain.run(h.ctx, h.req, h.res);
                // Both middlewares ran (each left its header) AND the
                // chain reached the handler (body is "HANDLER-RAN").
                try std.testing.expectEqualStrings("yes", final_res.headers.get("X-Mw-Outer").?);
                try std.testing.expectEqualStrings("yes", final_res.headers.get("X-Mw-Inner").?);
                try std.testing.expectEqualStrings("HANDLER-RAN", final_res.body);
            },
            else => return error.UnexpectedMatchVariant,
        }
    }

    test "Middleware order: multiple group.use() calls run in registration order" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        // Each middleware stamps a DIFFERENT-KEYED header so they all
        // accumulate on the final response. We then assert each one is
        // present, proving the chain visited all three.

        const First = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-1", "ran"));
            }
        }.h;
        const Second = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-2", "ran"));
            }
        }.h;
        const Third = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-3", "ran"));
            }
        }.h;

        const Final = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("HANDLER-RAN");
            }
        }.h;

        var g = r.group("");
        try g.use(First);
        try g.use(Second);
        try g.use(Third);
        try g.get("/m", Final);

        var req = createMockRequest("GET", "/m", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };
        const result = r.matchRoute("GET", "/m", &req, ctx);
        try std.testing.expect(result != null);

        switch (result.?) {
            .handler => |h| {
                try std.testing.expectEqual(@as(usize, 3), h.chain.middlewares.len);
                const final_res = try h.chain.run(h.ctx, h.req, h.res);
                // All three middlewares visited — each left its own header.
                try std.testing.expectEqualStrings("ran", final_res.headers.get("X-Mw-1").?);
                try std.testing.expectEqualStrings("ran", final_res.headers.get("X-Mw-2").?);
                try std.testing.expectEqualStrings("ran", final_res.headers.get("X-Mw-3").?);
                // Chain reached the handler.
                try std.testing.expectEqualStrings("HANDLER-RAN", final_res.body);
            },
            else => return error.UnexpectedMatchVariant,
        }
    }

    test "Middleware that short-circuits skips later middlewares and the handler" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const First = struct {
            pub fn h(
                _: http_parser.HttpContext,
                _: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                _: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                // Short-circuit — return without calling next. Body is
                // unique ("BLOCKED") so we can tell it never made it to
                // the handler (which would have set body to "REACHED").
                return res.withBody("BLOCKED");
            }
        }.h;
        // If this runs, it would stamp "LATER_RAN" on the body — the
        // first middleware's BLOCKED proves it never did.
        const Second = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withBody("LATER_RAN,"));
            }
        }.h;

        const Handler = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("REACHED");
            }
        }.h;

        var g = r.group("");
        try g.use(First);
        try g.use(Second);
        try g.get("/blocked", Handler);

        var req = createMockRequest("GET", "/blocked", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };
        const result = r.matchRoute("GET", "/blocked", &req, ctx);

        switch (result.?) {
            .handler => |h| {
                const final_res = try h.chain.run(h.ctx, h.req, h.res);
                // First middleware short-circuited — body is its message,
                // not the handler's "REACHED" and not the second
                // middleware's "LATER_RAN," prefix.
                try std.testing.expectEqualStrings("BLOCKED", final_res.body);
                try std.testing.expect(std.mem.indexOf(u8, final_res.body, "LATER_RAN") == null);
                try std.testing.expect(std.mem.indexOf(u8, final_res.body, "REACHED") == null);
            },
            else => return error.UnexpectedMatchVariant,
        }
    }

    test "Route with zero middleware runs the handler directly through chain.run" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Handler = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("DIRECT");
            }
        }.h;

        try r.get("/direct", Handler);

        var req = createMockRequest("GET", "/direct", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };
        const result = r.matchRoute("GET", "/direct", &req, ctx);

        switch (result.?) {
            .handler => |h| {
                try std.testing.expectEqual(@as(usize, 0), h.chain.middlewares.len);
                const final_res = try h.chain.run(h.ctx, h.req, h.res);
                try std.testing.expectEqualStrings("DIRECT", final_res.body);
            },
            else => return error.UnexpectedMatchVariant,
        }
    }

    test "Middleware error propagates up to chain.run" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Boom = struct {
            pub fn h(
                _: http_parser.HttpContext,
                _: http_parser.HttpRequest,
                _: http_parser.HttpResponse,
                _: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return error.MiddlewareBoom;
            }
        }.h;

        const Handler = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("should not run");
            }
        }.h;

        var g = r.group("");
        try g.use(Boom);
        try g.get("/explode", Handler);

        var req = createMockRequest("GET", "/explode", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };
        const result = r.matchRoute("GET", "/explode", &req, ctx);

        switch (result.?) {
            .handler => |h| {
                // Error from middleware propagates — matchRoute itself
                // succeeds (the error happens at run time).
                const final_res = h.chain.run(h.ctx, h.req, h.res);
                try std.testing.expectError(error.MiddlewareBoom, final_res);
            },
            else => return error.UnexpectedMatchVariant,
        }
    }

    test "Group.use after route registration does NOT retroactively apply" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        // The middleware stamps a header on the way IN. If it runs, that
        // header appears on the final response (the handler doesn't touch
        // headers). If middleware DIDN'T run, the header is absent.
        const LateMw = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Late-Mw", "ran"));
            }
        }.h;

        const Handler = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("handler ran");
            }
        }.h;

        var g = r.group("");
        try g.get("/route", Handler); // snapshot at this point: 0 middleware
        try g.use(LateMw); // middleware registered AFTER the route
        try g.get("/late", Handler); // snapshot at this point: 1 middleware

        // Hit /route — late middleware must NOT run. /route was registered
        // before LateMw was added, so its middlewares slice was duped
        // before the change.
        var req1 = createMockRequest("GET", "/route", arena.allocator());
        defer req1.params.deinit();
        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };
        const result1 = r.matchRoute("GET", "/route", &req1, ctx);

        switch (result1.?) {
            .handler => |h| {
                try std.testing.expectEqual(@as(usize, 0), h.chain.middlewares.len);
                const final_res = try h.chain.run(h.ctx, h.req, h.res);
                try std.testing.expectEqualStrings("handler ran", final_res.body);
                try std.testing.expect(final_res.headers.get("X-Late-Mw") == null);
            },
            else => return error.UnexpectedMatchVariant,
        }

        // Hit /late — middleware DOES run because /late was registered
        // AFTER LateMw was added.
        var req2 = createMockRequest("GET", "/late", arena.allocator());
        defer req2.params.deinit();
        const result2 = r.matchRoute("GET", "/late", &req2, ctx);

        switch (result2.?) {
            .handler => |h| {
                try std.testing.expectEqual(@as(usize, 1), h.chain.middlewares.len);
                const final_res = try h.chain.run(h.ctx, h.req, h.res);
                try std.testing.expectEqualStrings("handler ran", final_res.body);
                try std.testing.expectEqualStrings("ran", final_res.headers.get("X-Late-Mw").?);
            },
            else => return error.UnexpectedMatchVariant,
        }
    }

    test "Group.route conflict: same full path registered twice via two groups, first wins" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const First = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("first");
            }
        }.h;
        const Second = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("second");
            }
        }.h;

        var g1 = r.group("/api/v1");
        try g1.get("/users", First);

        var g2 = r.group("/api/v1");
        try g2.get("/users", Second);

        var req = createMockRequest("GET", "/api/v1/users", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };
        const result = r.matchRoute("GET", "/api/v1/users", &req, ctx);

        switch (result.?) {
            .handler => |h| {
                const final_res = try h.chain.run(h.ctx, h.req, h.res);
                // First-wins semantics: the body is "first", not "second".
                try std.testing.expectEqualStrings("first", final_res.body);
            },
            else => return error.UnexpectedMatchVariant,
        }
    }

    test "Path params work inside a group" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Handler = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("ok");
            }
        }.h;

        var api = r.group("/api");
        try api.get("/users/:id/posts/:postId", Handler);

        var req = createMockRequest("GET", "/api/users/42/posts/abc", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };
        const result = r.matchRoute("GET", "/api/users/42/posts/abc", &req, ctx);
        try std.testing.expect(result != null);
        try std.testing.expectEqualStrings("42", req.params.get("id").?);
        try std.testing.expectEqualStrings("abc", req.params.get("postId").?);
    }

    test "Empty prefix group + path with leading slash joins cleanly" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        const Handler = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.testing.allocator);
            }
        }.h;

        var g = r.group("");
        try g.get("/health", Handler); // path starts with /
        try g.get("health2", Handler); // path doesn't start with /

        // Empty prefix + path-with-slash → path as-is (already "/health").
        // Empty prefix + path-without-slash → path as-is (no leading / added).
        try std.testing.expectEqualStrings("/health", r.routes.items[0].path);
        try std.testing.expectEqualStrings("health2", r.routes.items[1].path);
    }

    test "Three-level nested groups: prefix and middleware chain both stack" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        // Each middleware stamps a header. All three headers must
        // survive on the final response — proving the chain visited all
        // three middlewares.
        const A = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-A", "yes"));
            }
        }.h;
        const B = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-B", "yes"));
            }
        }.h;
        const C = struct {
            pub fn h(
                ctx: http_parser.HttpContext,
                req: http_parser.HttpRequest,
                res: http_parser.HttpResponse,
                chain: *router.MiddlewareChain,
            ) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-C", "yes"));
            }
        }.h;

        const Handler = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("LEAF-RAN");
            }
        }.h;

        var g1 = r.group("/a");
        try g1.use(A);
        var g2 = try g1.group("/b");
        try g2.use(B);
        var g3 = try g2.group("/c");
        try g3.use(C);
        try g3.get("/leaf", Handler);

        var req = createMockRequest("GET", "/a/b/c/leaf", arena.allocator());
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };
        const result = r.matchRoute("GET", "/a/b/c/leaf", &req, ctx);

        switch (result.?) {
            .handler => |h| {
                try std.testing.expectEqual(@as(usize, 3), h.chain.middlewares.len);
                const final_res = try h.chain.run(h.ctx, h.req, h.res);
                // All three middlewares visited.
                try std.testing.expectEqualStrings("yes", final_res.headers.get("X-Mw-A").?);
                try std.testing.expectEqualStrings("yes", final_res.headers.get("X-Mw-B").?);
                try std.testing.expectEqualStrings("yes", final_res.headers.get("X-Mw-C").?);
                // Chain reached the handler.
                try std.testing.expectEqualStrings("LEAF-RAN", final_res.body);
            },
            else => return error.UnexpectedMatchVariant,
        }
    }

    test "Sibling groups are independent (one group's middleware doesn't bleed)" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        // Each middleware stamps a unique HEADER. After running, we
        // inspect the final response to see which middleware stamped.
        const ApiMw = struct {
            pub fn h(ctx: http_parser.HttpContext, req: http_parser.HttpRequest, res: http_parser.HttpResponse, chain: *router.MiddlewareChain) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-Ran", "api"));
            }
        }.h;
        const AdminMw = struct {
            pub fn h(ctx: http_parser.HttpContext, req: http_parser.HttpRequest, res: http_parser.HttpResponse, chain: *router.MiddlewareChain) anyerror!http_parser.HttpResponse {
                return chain.next(ctx, req, res.withHeader("X-Mw-Ran", "admin"));
            }
        }.h;

        const Handler = struct {
            pub fn h(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("ok");
            }
        }.h;

        var api = r.group("/api");
        try api.use(ApiMw);
        try api.get("/health", Handler);

        var admin = r.group("/admin");
        try admin.use(AdminMw);
        try admin.get("/secret", Handler);

        var req1 = createMockRequest("GET", "/api/health", arena.allocator());
        defer req1.params.deinit();
        var req2 = createMockRequest("GET", "/admin/secret", arena.allocator());
        defer req2.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = arena.allocator(), .io = undefined };

        // Hit /api/health — only ApiMw runs.
        switch (r.matchRoute("GET", "/api/health", &req1, ctx).?) {
            .handler => |h| {
                const resp = try h.chain.run(h.ctx, h.req, h.res);
                try std.testing.expectEqualStrings("api", resp.headers.get("X-Mw-Ran").?);
            },
            else => return error.UnexpectedMatchVariant,
        }

        // Hit /admin/secret — only AdminMw runs.
        switch (r.matchRoute("GET", "/admin/secret", &req2, ctx).?) {
            .handler => |h| {
                const resp = try h.chain.run(h.ctx, h.req, h.res);
                try std.testing.expectEqualStrings("admin", resp.headers.get("X-Mw-Ran").?);
            },
            else => return error.UnexpectedMatchVariant,
        }
    }

    test "Group with no routes does not crash and does not pollute routes list" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        var r = router.Router.init(arena.allocator());
        defer r.deinit();

        _ = r.group("/empty");
        try std.testing.expectEqual(@as(usize, 0), r.routes.items.len);
    }
};

comptime {
    _ = router_tests;
}
