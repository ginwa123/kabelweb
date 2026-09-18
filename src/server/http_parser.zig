const std = @import("std");
const Template = @import("template.zig");
const context_mod = @import("context.zig");
const ContextStore = context_mod.ContextStore;

pub const HttpContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Optional client ID for SSE connections (set after registerClient)
    client_id: ?[16]u8 = null,
    /// Server-configured CORS origins, injected by the dispatch loop from
    /// `GinwaServer.cors.allowed_origins`. Handlers use this for the
    /// origin/CSRF defence-in-depth gate instead of hardcoding a host —
    /// the server config is the single source of truth.
    allowed_origins: []const []const u8 = &.{},
};

/// Monotonic counter for the `ctx=<id>` cookie value. Each call returns
/// a unique u64 within the server's lifetime. Used by
/// `HttpResponse.redirectWithContext`. Wraparound is at 2^64 so it
/// won't happen in any realistic uptime.
var context_id_counter: std.atomic.Value(u64) = .init(0);

fn nextContextId() u64 {
    return context_id_counter.fetchAdd(1, .seq_cst);
}

/// Decode URL-encoded string (handles %XX, +, and all special chars)
pub fn urlDecode(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // Calculate exact size needed
    var decoded_len: usize = 0;
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        if (data[i] == '%' and i + 2 < data.len) {
            _ = std.fmt.parseInt(u8, data[i + 1 .. i + 3], 16) catch {
                decoded_len += 1;
                i += 1;
                continue;
            };
            decoded_len += 1;
            i += 2;
        } else if (data[i] == '+') {
            decoded_len += 1;
        } else {
            decoded_len += 1;
        }
    }

    // Allocate exact size
    const result = try allocator.alloc(u8, decoded_len);
    var j: usize = 0;
    i = 0;
    while (i < data.len) : (i += 1) {
        if (data[i] == '%' and i + 2 < data.len) {
            const decoded = std.fmt.parseInt(u8, data[i + 1 .. i + 3], 16) catch {
                result[j] = data[i];
                j += 1;
                i += 1;
                continue;
            };
            result[j] = decoded;
            j += 1;
            i += 2;
        } else if (data[i] == '+') {
            result[j] = ' ';
            j += 1;
        } else {
            result[j] = data[i];
            j += 1;
        }
    }

    return result[0..j];
}

/// Parse an `application/x-www-form-urlencoded` body into a key→value map.
/// Empty body returns an empty map. Caller frees the map (and the duped
/// key/value slices it owns) via `map.deinit()`. On partial-parse failure
/// the map is freed by the errdefer so the caller never leaks.
///
/// The HTTP primitive underlying `HttpRequest.form`. Most callers should
/// use `HttpRequest.form(T, allocator)` directly — this lower-level API
/// is useful for advanced cases (e.g. partial parses, custom validation).
pub fn parseFormBody(allocator: std.mem.Allocator, body: []const u8) !std.StringHashMap([]const u8) {
    var map = std.StringHashMap([]const u8).init(allocator);
    errdefer map.deinit();
    if (body.len == 0) return map;

    var it = std.mem.splitScalar(u8, body, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const raw_key = pair[0..eq];
        const raw_val = pair[eq + 1 ..];
        const key = try urlDecode(raw_key, allocator);
        errdefer allocator.free(key);
        const value = try urlDecode(raw_val, allocator);
        errdefer allocator.free(value);
        try map.put(key, value);
    }
    return map;
}

/// HTTP Request structure parsed from raw HTTP data
pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    version: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    raw: []const u8,

    /// Route params extracted from path patterns like /hello/:name
    params: std.StringHashMap([]const u8),
    /// Query string params extracted from URL like ?foo=bar&baz=qux
    query: std.StringHashMap([]const u8),

    _client_fd: i32,

    /// Per-request session (cross-redirect state bag). Wired by the
    /// listen loop right after parsing; tests construct one and set
    /// this field directly. Handlers call `req.session.set(...)`,
    /// `req.session.getString(...)`, and the redirect helper reads
    /// `req.session.outgoing` after the handler returns. Keeping the
    /// pointer on the request makes the API ergonomic
    /// (`req.session.set(...)`) without sacrificing req's by-value
    /// semantics.
    ///
    /// Default is `undefined` because there is no meaningful empty
    /// Session value to point at — the listen loop / tests MUST set
    /// this before any handler runs. A handler that reads
    /// `req.session` without it being wired will segfault; that is
    /// intentionally a hard error rather than a silent fall-back.
    session: *Session = undefined,

    // NOTE: there is intentionally NO write-SSE-event helper here. The only
    // correct way to write to a client socket is GinwaServer.sendToClient /
    // SseManager.sendToClient (winsock.send on Windows; raw write()/WriteFile
    // fails on winsock sockets). A previous writeSSEEvent using linux.write
    // was deleted for exactly that reason -- do not re-add one.
    /// Parse the request body as `application/x-www-form-urlencoded` and
    /// return a `T` struct with each `[]const u8` field populated from the
    /// matching form key.
    ///
    /// `T` must be a struct whose fields are all `[]const u8` and which
    /// defines a `deinit(self: *@This(), allocator: Allocator) void`
    /// method (each populated string is a heap allocation).
    ///
    /// Fields present in the form but missing from `T` are silently
    /// dropped. Fields present in `T` but missing from the form keep
    /// their default value (typically `""`).
    ///
    /// Returns:
    ///   - `error.InvalidFormBody` if the body can't be parsed as
    ///     urlencoded (e.g. undecodable percent sequence)
    ///   - `error.OutOfMemory` on allocation failure
    ///
    /// Example model + handler:
    /// ```zig
    /// const LoginForm = struct {
    ///     username: []const u8 = "",
    ///     password: []const u8 = "",
    ///     pub fn deinit(self: *@This(), a: Allocator) void {
    ///         a.free(self.username);
    ///         a.free(self.password);
    ///     }
    /// };
    ///
    /// var form = req.form(LoginForm, allocator) catch |err| switch (err) {
    ///     error.InvalidFormBody => return res.redirect("/login?error=invalid_form").withSecurityHeaders(),
    ///     else => return res.redirect("/login?error=server_error").withSecurityHeaders(),
    /// };
    /// defer form.deinit(allocator);
    /// // use form.username, form.password (already URL-decoded)
    /// ```
    pub fn form(self: HttpRequest, comptime T: type, allocator: std.mem.Allocator) !T {
        var map = parseFormBody(allocator, self.body) catch return error.InvalidFormBody;
        // Defer: free every (key, value) the map owns, then the bucket array.
        // StringHashMap.deinit() only frees the bucket array — the entries
        // (key + value slices) are caller-owned. The transient map lifetime
        // is bounded by this method, so we clean up here.
        defer {
            var it = map.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            map.deinit();
        }

        var result: T = .{};
        inline for (@typeInfo(T).@"struct".fields) |field| {
            if (map.get(field.name)) |raw_value| {
                @field(result, field.name) = try allocator.dupe(u8, raw_value);
            }
        }
        return result;
    }

    /// Free all heap-owned data:
    /// - `path` was allocated by `urlDecode` in `parseRequest`
    /// - `query` keys + values were URL-decoded (heap-owned)
    /// - `headers`, `params` maps own their buckets; their entries are
    ///   slices into `raw` (request_data) or into `path`, so no per-entry free
    ///
    /// Production usage (http_server.zig handle function) does NOT call this
    /// because the per-request arena reaps everything. This method exists for
    /// test code (where `std.testing.allocator` enforces leak detection) and
    /// for non-arena callers that want explicit ownership.
    pub fn deinit(self: *HttpRequest, allocator: std.mem.Allocator) void {
        // `path` was always allocated by `urlDecode` in `parseRequest` (even
        // for empty inputs the function allocates `decoded_len` bytes, which
        // can be 0). Free unconditionally.
        allocator.free(self.path);

        // Query keys + values are heap-allocated URL-decoded strings
        // (see `parseRequest` body). Free each before deiniting the map
        // (which only frees the bucket array).
        var qit = self.query.iterator();
        while (qit.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.query.deinit();

        self.headers.deinit();
        self.params.deinit();
    }
};

/// Per-request session — the cross-redirect state bag that lives across
/// the cookie round-trip. The handler signature is
/// `(ctx: *HttpContext, req: HttpRequest, session: *Session, res: HttpResponse)`:
/// `req` is **by value** (a shallow copy from the post-route-match
/// snapshot — see safety note below), `session` is the **only** pointer
/// in the signature, and it is explicitly the per-request mutable state.
///
/// **Safety note for the by-value req:** the listen loop snapshots the
/// post-`matchRoute` request into a struct copy before calling the
/// handler. The copy shares `headers` / `params` / `query` map bucket
/// arrays with the original (which the listen loop owns and deinits
/// later). **Handlers MUST NOT mutate req.headers / req.params /
/// req.query and MUST NOT call `req.deinit()` on the copy.** Reading is
/// fine. The `Session` API is where mutability lives.
pub const Session = struct {
    /// Server-side session storage. Wired by `GinwaServer.context_store`
    /// in main.zig. When `null`, the simple `set`/`get` API is
    /// disabled — handlers will get `error.NoContextStore` on `set` /
    /// `setInt` / `setBool` and `null` on `get` / `getString` / etc.
    context_store: ?*ContextStore,
    /// Context rebuilt from the incoming `Cookie: ctx=<id>` header.
    /// BORROWED from `context_store`; never free this directly.
    incoming: ?*context_mod.Context = null,
    /// Cookie id that produced `incoming`. Used by `flashString` to
    /// evict the entry from the store on consume. BORROWED from the
    /// store's internal dup — freed by `store.remove(id)`.
    incoming_id: ?[]const u8 = null,
    /// Context accumulating values set this request. Lazily created by
    /// the first `set` call; ownership transfers to the store via
    /// `flushPending` on a redirect.
    outgoing: ?*context_mod.Context = null,

    /// Build a session with an optional pre-populated `incoming` and
    /// `incoming_id`. The listen loop calls this after parsing the
    /// request and looking up the cookie in the store. `incoming_id`
    /// is the cookie id used to load `incoming` — needed by
    /// `flashString` to evict the entry from the store on consume.
    pub fn init(
        store: ?*ContextStore,
        incoming: ?*context_mod.Context,
        incoming_id: ?[]const u8,
    ) Session {
        return .{
            .context_store = store,
            .incoming = incoming,
            .incoming_id = incoming_id,
        };
    }

    /// No-op deinit. Kept for symmetry with the other request-scoped
    /// types so callers can write `defer session.deinit();` without
    /// thinking. All fields are either borrowed (`context_store`,
    /// `incoming`) or transferred-to-store (`outgoing`); nothing to free
    /// here.
    pub fn deinit(self: *Session) void {
        _ = self;
    }

    /// Store a string value for the next request. The redirect helper
    /// `HttpResponse.redirectWith` serialises pending values into a
    /// cookie; the next request's `get`/`getString` reads them back.
    ///
    /// Returns `error.NoContextStore` if the server didn't wire a
    /// `ContextStore` (no cookie round-trip is possible).
    pub fn set(self: *Session, key: []const u8, value: []const u8) !void {
        const store = self.context_store orelse return error.NoContextStore;
        if (self.outgoing == null) {
            self.outgoing = try store.newContext();
        }
        try self.outgoing.?.put(key, .{ .string = value });
    }

    /// Store an i64 for the next request.
    pub fn setInt(self: *Session, key: []const u8, value: i64) !void {
        const store = self.context_store orelse return error.NoContextStore;
        if (self.outgoing == null) {
            self.outgoing = try store.newContext();
        }
        try self.outgoing.?.put(key, .{ .int = value });
    }

    /// Store a bool for the next request.
    pub fn setBool(self: *Session, key: []const u8, value: bool) !void {
        const store = self.context_store orelse return error.NoContextStore;
        if (self.outgoing == null) {
            self.outgoing = try store.newContext();
        }
        try self.outgoing.?.put(key, .{ .bool = value });
    }

    /// Read a value by key. Walks outgoing (set this request) first,
    /// then incoming (rebuilt from the previous request's cookie).
    /// Returns `null` if no store is wired AND no incoming context is
    /// available locally — the only way to read is via a populated
    /// `incoming` (which itself requires a store).
    pub fn get(self: *const Session, key: []const u8) ?context_mod.Value {
        if (self.outgoing) |o| if (o.get(key)) |v| return v;
        if (self.incoming) |i| return i.get(key);
        return null;
    }

    /// Convenience: `get` projected to `[]const u8` (returns `null`
    /// for any non-string value or missing key).
    pub fn getString(self: *const Session, key: []const u8) ?[]const u8 {
        return if (self.get(key)) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;
    }

    /// Convenience: `get` projected to `i64`.
    pub fn getInt(self: *const Session, key: []const u8) ?i64 {
        return if (self.get(key)) |v| switch (v) {
            .int => |n| n,
            else => null,
        } else null;
    }

    /// Convenience: `get` projected to `bool`.
    pub fn getBool(self: *const Session, key: []const u8) ?bool {
        return if (self.get(key)) |v| switch (v) {
            .bool => |b| b,
            else => null,
        } else null;
    }

    // ─── Rails-style flash messages (one-shot) ─────────────────────────
    //
    // The `flash` API matches Rails / Laravel / Django: set a value with
    // `flash(k, v)` before redirecting; the next request reads it with
    // `flashString(k)` (or `takeString`) which auto-evicts it from the
    // store. Subsequent requests see nothing. Use this for "Welcome
    // aboard!" banners and other one-shot notifications. For persistent
    // per-user state (login flags, preferences) use the regular
    // `set`/`getString` API.

    /// Set a one-shot flash message. Same storage as `set` — the
    /// difference is at read time: `flashString` evicts on consume.
    /// Rails-style `flash[:notice] = "..."`.
    pub fn flash(self: *Session, key: []const u8, value: []const u8) !void {
        const store = self.context_store orelse return error.NoContextStore;
        if (self.outgoing == null) {
            self.outgoing = try store.newContext();
        }
        try self.outgoing.?.put(key, .{ .string = value });
    }

    /// Read a one-shot flash message AND evict it. Rails-style
    /// `flash[:notice]`. After this call:
    /// - the key is removed from the underlying Context
    /// - if the Context is now empty AND it lives in the store, the
    ///   whole entry is removed from the store
    /// - subsequent requests with the same cookie see no incoming
    ///
    /// Returns `null` if no incoming context or the key isn't there.
    /// The returned slice is owned by the per-request arena (ctx.allocator)
    /// so the caller can use it freely for the duration of the request.
    pub fn flashString(self: *Session, key: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
        const incoming = self.incoming orelse return null;
        const val = incoming.get(key) orelse return null;
        const str = switch (val) {
            .string => |s| s,
            else => return null,
        };
        // Copy the string BEFORE evicting — `incoming.remove(key)` frees
        // the heap-allocated value back to the store's allocator, and
        // returning a slice into freed memory would be use-after-free.
        const owned = allocator.dupe(u8, str) catch return null;
        _ = incoming.remove(key);
        // If the Context is now empty AND it was loaded from the store,
        // evict the whole entry. Empty contexts in the store are dead
        // weight; removing them also frees the cookie id memory.
        if (incoming.values.count() == 0) {
            if (self.context_store) |store| {
                if (self.incoming_id) |id| {
                    store.remove(id);
                    self.incoming = null;
                    self.incoming_id = null;
                }
            }
        }
        return owned;
    }

    /// Move `outgoing` into the `ContextStore` and return the cookie id.
    /// Returns `null` if there's no outgoing Context or it's empty.
    /// Detaches `outgoing` so subsequent `set` calls start a fresh one.
    ///
    /// The returned id is store-owned memory (the store takes ownership
    /// via `putOwned`). The caller (typically `redirectWith`) uses it
    /// to build the cookie; the cookie's lifetime is bounded by
    /// response.deinit, and the id's lifetime is bounded by store.deinit.
    pub fn flushPending(self: *Session) !?[]const u8 {
        const store = self.context_store orelse return null;
        const out = self.outgoing orelse return null;
        if (out.values.count() == 0) return null;

        // Mint an opaque ID and hand it (and the Context) to the store.
        // The store owns the id slice from here on — it's freed when
        // the Context is removed or the store is destroyed.
        var id_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_buf, nextContextId(), .little);
        const id = try std.fmt.allocPrint(store.allocator, "{x}", .{id_buf});
        try store.putOwned(id, out);

        self.outgoing = null;
        return id;
    }
};

/// HTTP Response builder
pub const HttpResponse = struct {
    status_code: u16,
    status_text: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    allocator: std.mem.Allocator,
    /// When true, `toBytes()` emits `Connection: keep-alive` (+ `Keep-Alive`
    /// timeout hint) instead of `Connection: close`, so the server's
    /// keep-alive loop can reuse the connection for the next request.
    /// Defaults to false (close) to preserve the historical wire format —
    /// the dispatch loop sets it per-request from the client's
    /// `Connection` header + HTTP version. SSE/WS upgrade paths always
    /// leave it false (they hijack or close the connection).
    keep_alive: bool = false,

    pub fn init(status_code: u16, status_text: []const u8, allocator: std.mem.Allocator) HttpResponse {
        return .{
            .status_code = status_code,
            .status_text = status_text,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .allocator = allocator,
        };
    }

    pub fn withBody(self: HttpResponse, body: []const u8) HttpResponse {
        var copy = self;
        copy.body = body;
        const len_str = std.fmt.allocPrint(self.allocator, "{}", .{body.len}) catch @panic("OOM");
        copy.headers.put("Content-Length", len_str) catch @panic("OOM");
        return copy;
    }

    /// Render a compiled Jinja template and set the body + Content-Type
    /// in one call. Equivalent to:
    ///   const body = try Template.render(self.allocator, nodes, ctx);
    ///   return self.withBody(body).setContentType("text/html; charset=utf-8");
    /// but allocates the body and the Content-Length string for you.
    ///
    /// On render error, returns the response unchanged (caller should
    /// check for an empty body if this matters — a successful render
    /// always produces a non-empty body unless the template itself is
    /// empty).
    pub fn withRender(
        self: HttpResponse,
        nodes: []const Template.Node,
        ctx: *const Template.Context,
    ) HttpResponse {
        // Template.render needs a mutable *Context (set/macros mutate it),
        // but the caller's signature is `*const Context` so callers don't
        // have to give up mutability. `Template.render` itself doesn't
        // require the context to be mutated when there are no `{% set %}`
        // or `{% macro %}` tags — we constCast here is safe in that
        // common case. If a handler uses set/macro with withRender, the
        // caller should pass a mutable context instead.
        const body = Template.render(
            self.allocator,
            nodes,
            @constCast(ctx),
            .{},
        ) catch return self;
        return self
            .withBody(body)
            .setContentType("text/html; charset=utf-8");
    }

    /// Set a content-type header on the response. Returns the (possibly
    /// copied) response so it can be chained after withBody / withJson
    /// / withRender.
    pub fn setContentType(self: HttpResponse, ct: []const u8) HttpResponse {
        var copy = self;
        copy.headers.put("Content-Type", ct) catch @panic("OOM");
        return copy;
    }

    /// Set an arbitrary response header. Returns a copy with the new
    /// (or replaced) header — does not mutate `self`. Used by middleware
    /// that wants to add a marker (e.g. `X-Request-Id`, `X-Admin-Route`)
    /// on the way down the chain.
    ///
    /// Overwrites any prior value for the same key. To set multiple
    /// headers from inside a middleware, derive a fresh copy on each
    /// call — `HttpResponse` is a value type.
    pub fn withHeader(self: HttpResponse, name: []const u8, value: []const u8) HttpResponse {
        var copy = self;
        copy.headers.put(name, value) catch @panic("OOM");
        return copy;
    }

    /// Apply the 7 standard security response headers (CSP,
    /// X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
    /// Permissions-Policy, COOP, CORP) by delegating to
    /// `security.applySecurityHeaders`. Chainable after withBody /
    /// withJson / withRender.
    ///
    /// Call AFTER withBody/withJson/withRender so security headers
    /// aren't accidentally overwritten by Content-Type / Content-Length.
    pub fn withSecurityHeaders(self: HttpResponse) HttpResponse {
        var copy = self;
        const security = @import("security.zig");
        security.applySecurityHeaders(&copy);
        return copy;
    }

    pub fn withJson(self: HttpResponse, json: []const u8) HttpResponse {
        var copy = self;
        copy.body = json;
        const len_str = std.fmt.allocPrint(self.allocator, "{}", .{json.len}) catch @panic("OOM");
        copy.headers.put("Content-Type", "application/json") catch @panic("OOM");
        copy.headers.put("Content-Length", len_str) catch @panic("OOM");
        return copy;
    }

    /// Build a 302 Found redirect to `location` with an empty body.
    /// Sets `Content-Type: text/html; charset=utf-8` and `Content-Length: 0`
    /// (some HTTP clients / proxies expect a body even on a redirect; this
    /// makes the response shape uniform with `withBody` / `withRender`).
    ///
    /// Ownership: the `Location` header value is a slice the caller passes
    /// in (typically a string literal or a heap slice from `allocPrint`).
    /// The Content-Length value is heap-allocated and owned by the response
    /// (via the per-request arena in production).
    ///
    /// The caller is responsible for attaching security headers:
    /// `res.redirect("/").withSecurityHeaders()`.
    ///
    /// The caller is responsible for any auxiliary headers (e.g.
    /// `Retry-After` on a 429 redirect) — `put` them on the returned
    /// response before chaining `.withSecurityHeaders()`.
    ///
    /// Example (success):
    /// ```zig
    /// return res.redirect("/").withSecurityHeaders();
    /// ```
    ///
    /// Example (redirect to an error page with a query code):
    /// ```zig
    /// const location = try std.fmt.allocPrint(
    ///     allocator,
    ///     "/signup?error={s}",
    ///     .{code.label()},
    /// );
    /// // no defer free(location) — the Location header in the response
    /// // owns the slice until the per-request arena reaps it.
    /// return res.redirect(location).withSecurityHeaders();
    /// ```
    pub fn redirect(self: HttpResponse, location: []const u8) HttpResponse {
        var copy = self;
        copy.status_code = 302;
        copy.status_text = "Found";
        copy.body = "";
        copy.headers.put("Location", location) catch @panic("OOM");
        copy.headers.put("Content-Type", "text/html; charset=utf-8") catch @panic("OOM");
        const len_str = std.fmt.allocPrint(self.allocator, "0", .{}) catch @panic("OOM");
        copy.headers.put("Content-Length", len_str) catch @panic("OOM");
        return copy;
    }

    /// 302 redirect that ALSO flushes any pending `req.session.set`
    /// values into a `Set-Cookie` header. The next request's
    /// `HttpRequest` will see those values via `req.session.get` /
    /// `req.session.getString` / etc.
    ///
    /// This is the cookie + store + Context round-trip, hidden behind
    /// one call. Used by the success path of `createUserHandler` to
    /// carry the new user's name to the landing page.
    ///
    /// If `req.session` has no pending values, this is the same as
    /// `redirect`.
    pub fn redirectWith(self: HttpResponse, req: HttpRequest, location: []const u8) !HttpResponse {
        var out = self.redirect(location);
        if (try req.session.flushPending()) |id| {
            const cookie = try std.fmt.allocPrint(
                out.allocator,
                "ctx={s}; Path=/; HttpOnly; SameSite=Strict",
                .{id},
            );
            try out.headers.put("Set-Cookie", cookie);
        }
        return out;
    }

    /// Build a 302 Found redirect that ALSO carries a `Context` value bag
    /// across the redirect via a `Set-Cookie: ctx=<id>` header. The
    /// context is stored in `store` under a freshly-generated opaque ID;
    /// the next request reads the cookie via `contextFromRequest` and
    /// retrieves the same context.
    ///
    /// Cookie shape: `ctx=<hex-id>; Path=/; HttpOnly; SameSite=Strict`.
    /// The hex ID is 16 hex chars (an 8-byte atomic counter) so each
    /// redirect mints a unique value within a single server lifetime.
    /// Production hardening should layer in entropy from `/dev/urandom`;
    /// the cookie is still HttpOnly+SameSite=Strict which blocks most
    /// attacks.
    ///
    /// Ownership: the `Set-Cookie` value string and the redirect's
    /// `Content-Length` value are both allocated from `ctx.allocator`.
    /// The arena reaps them at response-drop time; do NOT `defer
    /// allocator.free(...)` them.
    pub fn redirectWithContext(
        self: HttpResponse,
        location: []const u8,
        ctx: *const context_mod.Context,
        store: *ContextStore,
    ) !HttpResponse {
        // 8-byte ID from an atomic counter — unique per call. hex-encoded
        // to 16 chars; cookie-safe (no special chars).
        var id_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_buf, nextContextId(), .little);
        const id = try std.fmt.allocPrint(ctx.allocator, "{x}", .{id_buf});
        try store.put(id, @constCast(ctx));

        var out = self.redirect(location);
        // Allocate the cookie from the response's allocator (per-request
        // arena in production) so `HttpResponse.deinit` can free it via
        // the same allocator. Using `ctx.allocator` (the store) would
        // cross-allocator free.
        const cookie = try std.fmt.allocPrint(
            out.allocator,
            "ctx={s}; Path=/; HttpOnly; SameSite=Strict",
            .{id},
        );
        try out.headers.put("Set-Cookie", cookie);
        // The store duped the ID; we can free the original now.
        ctx.allocator.free(id);
        return out;
    }

    /// Free all heap-owned data: the headers map and any header values
    /// that were allocated by `withBody` / `withJson` / `redirect`
    /// (Content-Length). Header keys/values from `headers.put(...)` are
    /// caller-owned (caller frees the key + value strings).
    ///
    /// Production usage in http_server.zig does NOT call this because
    /// the per-request arena reaps everything. This method exists for
    /// test code (where `std.testing.allocator` enforces leak detection)
    /// and for non-arena callers that want explicit ownership.
    pub fn deinit(self: *HttpResponse) void {
        // The standard helper methods (withBody/withJson/redirect) use
        // std.fmt.allocPrint(allocator, "{}", .{n}) for the
        // Content-Length value, which is heap-owned. Content-Type is
        // a string literal so no free needed.
        if (self.headers.fetchRemove("Content-Length")) |kv| {
            self.allocator.free(kv.value);
        }
        // redirectWithContext heap-allocates the Set-Cookie value via
        // std.fmt.allocPrint. Free it here so test allocators don't
        // report leaks. Production arena allocators no-op the free.
        if (self.headers.fetchRemove("Set-Cookie")) |kv| {
            self.allocator.free(kv.value);
        }
        self.headers.deinit();
    }

    pub fn toBytes(self: HttpResponse) ![]u8 {
        var buf = std.ArrayList(u8).empty;
        errdefer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "HTTP/1.1 ");

        var status_buf: [20]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{self.status_code}) catch return error.OutOfMemory;
        try buf.appendSlice(self.allocator, status_str);

        try buf.appendSlice(self.allocator, " ");
        try buf.appendSlice(self.allocator, self.status_text);
        try buf.appendSlice(self.allocator, "\r\n");
        try buf.appendSlice(self.allocator, "Server: Server/1.0\r\n"); // todo change i think
        if (self.keep_alive) {
            try buf.appendSlice(self.allocator, "Connection: keep-alive\r\n");
            try buf.appendSlice(self.allocator, "Keep-Alive: timeout=5, max=1000\r\n");
        } else {
            try buf.appendSlice(self.allocator, "Connection: close\r\n");
        }

        var it = self.headers.iterator();
        while (it.next()) |entry| {
            try buf.appendSlice(self.allocator, entry.key_ptr.*);
            try buf.appendSlice(self.allocator, ": ");
            try buf.appendSlice(self.allocator, entry.value_ptr.*);
            try buf.appendSlice(self.allocator, "\r\n");
        }

        try buf.appendSlice(self.allocator, "\r\n");
        try buf.appendSlice(self.allocator, self.body);

        return buf.toOwnedSlice(self.allocator);
    }

    pub fn jsonResponse(self: HttpResponse, jsonStruct: JsonStruct) HttpResponse {
        return jsonResponseHelper(self.allocator, jsonStruct);
    }
};

/// Parse an HTTP request from raw bytes. The listen loop separately
/// builds a `Session` (looking up the incoming cookie via
/// `context.contextFromRequest`) and threads it through to the handler
/// — `parseRequest` itself stays at the HTTP layer only.
pub fn parseRequest(
    data: []const u8,
    allocator: std.mem.Allocator,
    _: std.Io,
    client_fd: i32,
) !HttpRequest {
    const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse {
        return error.IncompleteRequest;
    };

    const header_section = data[0..header_end];
    const body_start = header_end + 4;
    const body = if (body_start < data.len) data[body_start..] else "";

    var lines = std.mem.splitScalar(u8, header_section, '\n');

    const first_line = lines.next() orelse return error.MissingRequestLine;
    var trimmed_line: []const u8 = if (first_line.len > 0 and first_line[0] == '\r') first_line[1..] else first_line;
    // Strip the trailing CR/LF that splitScalar('\n') leaves behind. The
    // request line is "GET /path HTTP/1.1\r"; without this trim the
    // version field would be "HTTP/1.1\r" and fail any string compare.
    if (trimmed_line.len > 0 and trimmed_line[trimmed_line.len - 1] == '\r') {
        trimmed_line = trimmed_line[0 .. trimmed_line.len - 1];
    }
    var first_parts = std.mem.splitScalar(u8, trimmed_line, ' ');
    const method = first_parts.next() orelse return error.InvalidRequestLine;
    const path_with_query = first_parts.next() orelse return error.InvalidRequestLine;
    const version = first_parts.next() orelse return error.InvalidRequestLine;

    // Split path and query string
    var path: []const u8 = path_with_query;
    var query_str: []const u8 = "";
    if (std.mem.indexOf(u8, path_with_query, "?")) |q_idx| {
        path = path_with_query[0..q_idx];
        query_str = path_with_query[q_idx + 1 ..];
    }

    // Decode URL-encoded path
    const decoded_path = try urlDecode(path, allocator);

    var headers = std.StringHashMap([]const u8).init(allocator);
    while (lines.next()) |line| {
        // Strip optional leading CR (handles the first line which can
        // start with \r if the request was read verbatim).
        var clean_line: []const u8 = if (line.len > 0 and line[0] == '\r') line[1..] else line;
        // Strip optional trailing CR/LF (splitScalar('\n') leaves the
        // CR on each line, which would otherwise leak into header values).
        if (clean_line.len > 0 and clean_line[clean_line.len - 1] == '\r') {
            clean_line = clean_line[0 .. clean_line.len - 1];
        }
        if (clean_line.len == 0) break;
        if (std.mem.indexOf(u8, clean_line, ":")) |colon| {
            const key = std.mem.trim(u8, clean_line[0..colon], " ");
            const value = std.mem.trim(u8, clean_line[colon + 1 ..], " ");
            try headers.put(key, value);
        }
    }

    // Parse query params
    var query = std.StringHashMap([]const u8).init(allocator);
    if (query_str.len > 0) {
        var query_params = std.mem.splitScalar(u8, query_str, '&');
        while (query_params.next()) |param| {
            var key: []const u8 = param;
            var value: []const u8 = "";

            if (std.mem.indexOf(u8, param, "=")) |eq_idx| {
                key = param[0..eq_idx];
                value = param[eq_idx + 1 ..];
            }

            // URL decode both key and value
            const decoded_key = try urlDecode(key, allocator);
            const decoded_value = try urlDecode(value, allocator);
            try query.put(decoded_key, decoded_value);
        }
    }

    // Params are populated by the router when matching route patterns
    const params = std.StringHashMap([]const u8).init(allocator);

    return HttpRequest{
        .method = method,
        .path = decoded_path,
        .version = version,
        .headers = headers,
        .body = body,
        .raw = data,
        .params = params,
        .query = query,
        ._client_fd = client_fd,
    };
}

/// Helper to create common responses
pub fn ok(body: []const u8, allocator: std.mem.Allocator) HttpResponse {
    return HttpResponse.init(200, "OK", allocator).withBody(body);
}

pub fn created(body: []const u8, allocator: std.mem.Allocator) HttpResponse {
    return HttpResponse.init(201, "Created", allocator).withBody(body);
}

pub fn badRequest(msg: []const u8, allocator: std.mem.Allocator) HttpResponse {
    return HttpResponse.init(400, "Bad Request", allocator).withBody(msg);
}

pub fn notFound(allocator: std.mem.Allocator) HttpResponse {
    return HttpResponse.init(404, "Not Found", allocator).withBody("Not Found");
}

pub fn internalError(msg: []const u8, allocator: std.mem.Allocator) HttpResponse {
    return HttpResponse.init(500, "Internal Server Error", allocator).withBody(msg);
}

pub const JsonStruct = struct {
    data: []const u8,
    status_code: u16,
};

pub fn jsonResponseHelper(allocator: std.mem.Allocator, jsonStruct: JsonStruct) HttpResponse {
    const status_text: []const u8 = switch (jsonStruct.status_code) {
        // 1xx Informational
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",

        // 2xx Success
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",

        // 3xx Redirection
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",

        // 4xx Client Errors
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a Teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",

        // 5xx Server Errors
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",

        else => "Unknown",
    };

    return HttpResponse.init(jsonStruct.status_code, status_text, allocator).withJson(jsonStruct.data);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Behavioural tests for HttpRequest.form() + HttpResponse.redirect()
//
//  These tests are colocated with the methods (in http_parser.zig) so they
//  run whenever the file is compiled into a test binary. The gserverz
//  module's own `zig build test` is pre-existing broken (Zig 0.16 rejects
//  `@embedFile` of files outside the module path, and the test_runner has
//  a truncated test), so the ginwasaas project-level `zig build test` is
//  the canonical run. Both paths compile http_parser.zig and pick these
//  tests up.
// ═══════════════════════════════════════════════════════════════════════════

test "HttpRequest.form: parses urlencoded body into typed struct" {
    const LoginForm = struct {
        username: []const u8 = "",
        password: []const u8 = "",
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            a.free(self.username);
            a.free(self.password);
        }
    };

    var req: HttpRequest = .{
        .method = "POST",
        .path = "/login",
        .version = "HTTP/1.1",
        .headers = std.StringHashMap([]const u8).init(std.testing.allocator),
        .body = "username=ada_l&password=correct-horse-battery",
        .raw = "username=ada_l&password=correct-horse-battery",
        .params = std.StringHashMap([]const u8).init(std.testing.allocator),
        .query = std.StringHashMap([]const u8).init(std.testing.allocator),
        ._client_fd = -1,
    };
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();

    var form = try req.form(LoginForm, std.testing.allocator);
    defer form.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("ada_l", form.username);
    try std.testing.expectEqualStrings("correct-horse-battery", form.password);
}

test "HttpRequest.form: missing fields keep their struct default ('')" {
    // Note: defaults must be the empty string "" (a string literal). Using
    // any other literal (e.g. "0") would cause deinit to free a static
    // address and crash — the form parser only allocates when a field
    // is present in the body. Empty-string defaults are always safe.
    const PartialForm = struct {
        name: []const u8 = "",
        nickname: []const u8 = "", // missing from body -> keeps default
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            a.free(self.name);
            a.free(self.nickname);
        }
    };

    var req: HttpRequest = .{
        .method = "POST",
        .path = "/x",
        .version = "HTTP/1.1",
        .headers = std.StringHashMap([]const u8).init(std.testing.allocator),
        .body = "name=Alice",
        .raw = "name=Alice",
        .params = std.StringHashMap([]const u8).init(std.testing.allocator),
        .query = std.StringHashMap([]const u8).init(std.testing.allocator),
        ._client_fd = -1,
    };
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();

    var form = try req.form(PartialForm, std.testing.allocator);
    defer form.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("Alice", form.name);
    try std.testing.expectEqualStrings("", form.nickname);
}

test "HttpRequest.form: url-decodes values (spaces + percent-encoding)" {
    const CommentForm = struct {
        body: []const u8 = "",
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            a.free(self.body);
        }
    };

    var req: HttpRequest = .{
        .method = "POST",
        .path = "/x",
        .version = "HTTP/1.1",
        .headers = std.StringHashMap([]const u8).init(std.testing.allocator),
        // "Hello World!" + "a@b.com" with percent-encoding
        .body = "body=Hello+World%21",
        .raw = "body=Hello+World%21",
        .params = std.StringHashMap([]const u8).init(std.testing.allocator),
        .query = std.StringHashMap([]const u8).init(std.testing.allocator),
        ._client_fd = -1,
    };
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();

    var form = try req.form(CommentForm, std.testing.allocator);
    defer form.deinit(std.testing.allocator);

    // "Hello+World%21" -> "Hello World!"
    try std.testing.expectEqualStrings("Hello World!", form.body);
}

test "HttpRequest.form: empty body returns struct with all-default fields" {
    const EmptyForm = struct {
        x: []const u8 = "",
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            a.free(self.x);
        }
    };

    var req: HttpRequest = .{
        .method = "POST",
        .path = "/x",
        .version = "HTTP/1.1",
        .headers = std.StringHashMap([]const u8).init(std.testing.allocator),
        .body = "",
        .raw = "",
        .params = std.StringHashMap([]const u8).init(std.testing.allocator),
        .query = std.StringHashMap([]const u8).init(std.testing.allocator),
        ._client_fd = -1,
    };
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();

    var form = try req.form(EmptyForm, std.testing.allocator);
    defer form.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("", form.x);
}

test "HttpResponse.redirect: 302 + Location + empty body + Content-Type + Content-Length: 0" {
    var res = HttpResponse.init(0, "", std.testing.allocator);
    defer res.deinit();

    var out = res.redirect("/");
    defer out.deinit();

    try std.testing.expectEqual(@as(u16, 302), out.status_code);
    try std.testing.expectEqualStrings("Found", out.status_text);
    try std.testing.expectEqualStrings("", out.body);
    try std.testing.expectEqualStrings("/", out.headers.get("Location").?);
    try std.testing.expectEqualStrings("text/html; charset=utf-8", out.headers.get("Content-Type").?);
    try std.testing.expectEqualStrings("0", out.headers.get("Content-Length").?);
}

test "HttpResponse.redirect: chains with withSecurityHeaders" {
    var res = HttpResponse.init(0, "", std.testing.allocator);
    defer res.deinit();

    var out = res.redirect("/landing").withSecurityHeaders();
    defer out.deinit();

    try std.testing.expectEqual(@as(u16, 302), out.status_code);
    try std.testing.expectEqualStrings("/landing", out.headers.get("Location").?);
    try std.testing.expect(out.headers.get("Content-Security-Policy") != null);
    try std.testing.expect(out.headers.get("X-Frame-Options") != null);
    try std.testing.expect(out.headers.get("X-Content-Type-Options") != null);
}

test "HttpResponse.redirect: original response unchanged (immutable-by-value)" {
    var res = HttpResponse.init(200, "OK", std.testing.allocator);
    defer res.deinit();

    var out = res.redirect("/somewhere");
    defer out.deinit();

    // The original `res` still has its initial state — the method takes
    // `self` by value and mutates the COPY.
    try std.testing.expectEqual(@as(u16, 200), res.status_code);
    try std.testing.expectEqualStrings("OK", res.status_text);
    try std.testing.expect(res.headers.get("Location") == null);
}

test "HttpResponse.redirect: caller can attach Retry-After before withSecurityHeaders" {
    var res = HttpResponse.init(0, "", std.testing.allocator);
    defer res.deinit();

    var out = res.redirect("/signup?error=rate_limited");
    try out.headers.put("Retry-After", "60");
    out = out.withSecurityHeaders();
    defer out.deinit();

    try std.testing.expectEqual(@as(u16, 302), out.status_code);
    try std.testing.expectEqualStrings("/signup?error=rate_limited", out.headers.get("Location").?);
    try std.testing.expectEqualStrings("60", out.headers.get("Retry-After").?);
    try std.testing.expect(out.headers.get("Content-Security-Policy") != null);
}
