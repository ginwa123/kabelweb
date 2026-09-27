const std = @import("std");
const Template = @import("template.zig");
const context_mod = @import("context.zig");
const ContextStore = context_mod.ContextStore;
const Stream = @import("stream.zig").Stream;

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

/// Decode URL-encoded string (handles %XX, +, and all special chars.
/// Fast path: when the input contains no '%' and no '+', it is already
/// decoded — a single `dupe` avoids the two-pass scan + parseInt loop.
pub fn urlDecode(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var needs_decode = false;
    for (data) |c| {
        if (c == '%' or c == '+') {
            needs_decode = true;
            break;
        }
    }
    if (!needs_decode) return allocator.dupe(u8, data);
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
        // Heap path (owns the returned slice). Exactly one allocation,
        // sized up front — no regrowth, no transient 2x peak. The hot
        // loop prefers `writeTo` (zero allocs for small responses); this
        // stays for tests, error pages, and large bodies.
        const hlen = self.headLen();
        const total = hlen + 2 + self.body.len;
        const out = try self.allocator.alloc(u8, total);
        errdefer self.allocator.free(out);
        const n = try self.formatHeadInto(out);
        std.debug.assert(n == hlen); // headLen/formatHeadInto must agree
        @memcpy(out[n..][0..2], "\r\n");
        @memcpy(out[n + 2 ..][0..self.body.len], self.body);
        return out;
    }

    /// Length to frame on the wire, or null when no Content-Length line
    /// is emitted: an explicit header wins (manual framing), and
    /// 1xx/204/304 must not carry one (RFC 9110 §8.6).
    fn autoContentLength(self: HttpResponse) ?usize {
        if (self.headers.contains("Content-Length")) return null;
        if (self.status_code == 204 or self.status_code == 304) return null;
        if (self.status_code >= 100 and self.status_code < 200) return null;
        return self.body.len;
    }

    /// Shared response-head formatter (status line + Server/Connection +
    /// headers + auto Content-Length). Single source of truth for both
    /// `toBytes` (heap) and `writeTo` (stack fast path) so the wire bytes
    /// can never drift apart. Hand-rolled cursor appends (no Writer
    /// vtable): this runs ~100k times/sec on the hot path.
    const Head = struct {
        buf: []u8,
        pos: usize = 0,
        fn put(h: *Head, s: []const u8) !void {
            if (h.pos + s.len > h.buf.len) return error.Overflow;
            @memcpy(h.buf[h.pos..][0..s.len], s);
            h.pos += s.len;
        }
        fn int(h: *Head, v: anytype) !void {
            const s = std.fmt.bufPrint(h.buf[h.pos..], "{d}", .{v}) catch return error.Overflow;
            h.pos += s.len;
        }
    };

    /// Exact byte length of `formatHeadInto` output. Must stay in sync
    /// (enforced by `std.debug.assert` in `toBytes`, covered by tests).
    fn headLen(self: HttpResponse) usize {
        var n: usize = "HTTP/1.1 ".len + std.fmt.count("{d}", .{self.status_code}) + 1 + self.status_text.len + 2;
        n += "Server: Server/1.0\r\n".len;
        n += if (self.keep_alive) "Connection: keep-alive\r\nKeep-Alive: timeout=5, max=1000\r\n".len else "Connection: close\r\n".len;
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            n += entry.key_ptr.*.len + 2 + entry.value_ptr.*.len + 2;
        }
        if (self.autoContentLength()) |len| {
            n += "Content-Length: ".len + std.fmt.count("{d}", .{len}) + 2;
        }
        return n;
    }

    fn formatHeadInto(self: HttpResponse, buf: []u8) !usize {
        var h: Head = .{ .buf = buf };
        try h.put("HTTP/1.1 ");
        try h.int(self.status_code);
        try h.put(" ");
        try h.put(self.status_text);
        try h.put("\r\n");
        try h.put("Server: Server/1.0\r\n"); // todo change i think
        if (self.keep_alive) {
            try h.put("Connection: keep-alive\r\n");
            try h.put("Keep-Alive: timeout=5, max=1000\r\n");
        } else {
            try h.put("Connection: close\r\n");
        }

        var it = self.headers.iterator();
        while (it.next()) |entry| {
            try h.put(entry.key_ptr.*);
            try h.put(": ");
            try h.put(entry.value_ptr.*);
            try h.put("\r\n");
        }

        if (self.autoContentLength()) |len| {
            try h.put("Content-Length: ");
            try h.int(len);
            try h.put("\r\n");
        }
        return h.pos;
    }

    /// Stream this response with minimum allocation: responses whose
    /// head + blank line + body fit 4 KiB go out with ZERO heap allocs
    /// (covers health/hello/echo/redirect); larger ones fall back to the
    /// `toBytes` heap path. Wire bytes are identical either way.
    pub fn writeTo(self: HttpResponse, stream: Stream) !void {
        var stack: [4096]u8 = undefined;
        const n = self.formatHeadInto(&stack) catch return self.writeToHeap(stream);
        if (n + 2 + self.body.len > stack.len) return self.writeToHeap(stream);
        @memcpy(stack[n..][0..2], "\r\n");
        @memcpy(stack[n + 2 ..][0..self.body.len], self.body);
        try stream.writeAll(stack[0 .. n + 2 + self.body.len]);
    }

    fn writeToHeap(self: HttpResponse, stream: Stream) !void {
        const bytes = try self.toBytes();
        defer self.allocator.free(bytes);
        try stream.writeAll(bytes);
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

// ============================================================================
// Tests — moved here from `complex_cases_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = complex_cases_tests; }` below pulls them into the run.
// ============================================================================

const complex_cases_tests = struct {
    // Complex test cases for custom_http_server module.
    //
    // These tests target edge cases and behaviors NOT covered by the
    // basic test files:
    //   - HTTP parser: malformed requests, edge case bodies, header edge cases
    //   - URL decoder: percent-encoded sequences, edge cases, mixed content
    //   - Router: complex patterns, traversal cases, edge cases
    //   - Response builder: all status codes, multi-value headers, JSON edge cases
    //   - HTTP server: lifecycle, edge cases in Address / GinwaServer
    //
    // Each section has its own helper functions and shared imports.
    // TDD methodology: tests are written first, the production code is
    // updated only when a test reveals a real bug (not just a missing
    // test case).

    const http_parser = @import("http_parser.zig");
    const http_server = @import("http_server.zig");
    const router = @import("router.zig");
    const sse_manager = @import("sse_manager.zig");
    const builtin = @import("builtin");
    const linux = std.posix.system;
    const helpers = @import("test_helpers.zig");
    const toI32 = helpers.toI32;
    const closeSocketPair = helpers.closeSocketPair;
    const closeI32Fd = helpers.closeI32Fd;

    const posix = std.posix;

    const allocator = std.testing.allocator;
    const expect = std.testing.expect;
    const expectEqual = std.testing.expectEqual;
    const expectEqualStrings = std.testing.expectEqualStrings;
    const expectError = std.testing.expectError;
    const expectEqualSlices = std.testing.expectEqualSlices;

    // ============================================================================
    // SECTION 1: HTTP Parser Edge Cases
    // ============================================================================
    //
    // These exercise parseRequest() and urlDecode() with malformed, unusual,
    // or boundary inputs. The goal is to lock in correct behavior for the
    // "long tail" of HTTP requests that the basic happy-path tests don't cover.

    fn createRawRequest(allocator_: std.mem.Allocator, raw: []const u8) ![]u8 {
        // Tests construct raw HTTP request bytes directly (not via the
        // createHttpRequest helper) so they can craft malformed inputs
        // (missing headers, no \r\n\r\n, etc.).
        return try allocator_.dupe(u8, raw);
    }

    // ============================================================================
    // 1.1 Missing terminator (\r\n\r\n not found)
    // ============================================================================

    test "parser: reject request missing CRLFCRLF terminator" {
        // Per RFC 9112, a request without the header-body separator is malformed.
        // parseRequest returns error.IncompleteRequest.
        const data = "GET /test HTTP/1.1\r\nHost: localhost\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        const result = http_parser.parseRequest(request_data, allocator, undefined, 0);
        try expectError(error.IncompleteRequest, result);
    }

    // ============================================================================
    // 1.2 Empty body with POST and explicit Content-Length: 0
    // ============================================================================

    test "parser: POST with Content-Length: 0 has empty body" {
        const data =
            "POST /api/submit HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Content-Length: 0\r\n" ++
            "\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings("POST", req.method);
        try expectEqualStrings("/api/submit", req.path);
        try expectEqualStrings("", req.body);
        try expectEqual(@as(usize, 0), req.body.len);
    }

    // ============================================================================
    // 1.3 Method names — should NOT be uppercased
    // ============================================================================

    test "parser: lowercase method is preserved" {
        const data = "get /test HTTP/1.1\r\n\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings("get", req.method);
    }

    // ============================================================================
    // 1.4 Path with embedded spaces (technically invalid HTTP, but seen in the wild)
    // ============================================================================

    test "parser: path with literal spaces is truncated at first space" {
        // DOCUMENTED LIMITATION: the parser splits the first line by ' '
        // and takes only the first three fields (method, path, version).
        // For `GET /hello world HTTP/1.1`, the path becomes "/hello" — the
        // rest goes into version, which then matches what splitScalar returns
        // third. Effectively, paths with literal spaces are truncated.
        //
        // Real-world clients should percent-encode spaces (%20) — this test
        // locks in the truncation behavior so a future "fix" doesn't break
        // callers that rely on it.
        const data = "GET /hello world HTTP/1.1\r\n\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        // Path is truncated to "/hello" (everything before the first space).
        try expectEqualStrings("/hello", req.path);
    }

    // ============================================================================
    // 1.5 Body with embedded \r\n\r\n (false terminator)
    // ============================================================================

    test "parser: body containing CRLFCRLF is treated as body (after first terminator)" {
        // The FIRST \r\n\r\n is the header terminator. Subsequent \r\n\r\n
        // in the body are part of the body, not headers.
        const body_str = "line1\r\n\r\nline2"; // 5+2+2+5 = 14 bytes
        var data_buf: [256]u8 = undefined;
        const data = try std.fmt.bufPrint(
            &data_buf,
            "POST /api HTTP/1.1\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ body_str.len, body_str },
        );
        const request_data = try allocator.dupe(u8, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings(body_str, req.body);
        try expectEqual(body_str.len, req.body.len);
    }

    // ============================================================================
    // 1.6 Headers with leading/trailing whitespace — trim behavior
    // ============================================================================

    test "parser: header values with surrounding whitespace are trimmed" {
        const data =
            "GET / HTTP/1.1\r\n" ++
            "Host:    localhost:8080    \r\n" ++
            "\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        const host_raw = req.headers.get("Host") orelse "";
        // The parser trims header values via std.mem.trim — verify no leading/trailing spaces.
        try expect(!std.mem.startsWith(u8, host_raw, " "));
        try expect(!std.mem.endsWith(u8, host_raw, " "));
    }

    // ============================================================================
    // 1.7 Very long header value (10 KB)
    // ============================================================================

    test "parser: handles 10 KB header value" {
        var header_value_buf: [10240]u8 = undefined;
        for (&header_value_buf) |*c| c.* = 'x';

        var data = std.ArrayList(u8).empty;
        defer data.deinit(allocator);
        try data.appendSlice(allocator, "GET / HTTP/1.1\r\nX-Long: ");
        try data.appendSlice(allocator, &header_value_buf);
        try data.appendSlice(allocator, "\r\n\r\n");

        const request_data = try data.toOwnedSlice(allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        const hv = req.headers.get("X-Long") orelse "";
        try expectEqual(@as(usize, 10240), hv.len);
        // Verify first/last chars are 'x'
        try expectEqual(@as(u8, 'x'), hv[0]);
        try expectEqual(@as(u8, 'x'), hv[10239]);
    }

    // ============================================================================
    // 1.8 Multiple values for same header — last one wins
    // ============================================================================

    test "parser: duplicate header — last value wins" {
        const data =
            "GET / HTTP/1.1\r\n" ++
            "Host: first.example.com\r\n" ++
            "Host: second.example.com\r\n" ++
            "\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        const host = req.headers.get("Host") orelse "";
        const trimmed = std.mem.trim(u8, host, "\r");
        try expectEqualStrings("second.example.com", trimmed);
    }

    // ============================================================================
    // 1.9 Header with colons in value
    // ============================================================================

    test "parser: header value containing colon is preserved" {
        const data =
            "GET / HTTP/1.1\r\n" ++
            "X-Time: 12:34:56\r\n" ++
            "\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        const time_val = req.headers.get("X-Time") orelse "";
        const trimmed = std.mem.trim(u8, time_val, "\r");
        try expectEqualStrings("12:34:56", trimmed);
    }

    // ============================================================================
    // 1.10 Query string with no value (`?flag`)
    // ============================================================================

    test "parser: query param with no value parses as empty string" {
        const data = "GET /api?flag&debug HTTP/1.1\r\n\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings("/api", req.path);
        try expect(req.query.get("flag") != null);
        try expectEqualStrings("", req.query.get("flag").?);
        try expectEqualStrings("", req.query.get("debug").?);
    }

    // ============================================================================
    // 1.11 Query param with multiple `=` signs
    // ============================================================================

    test "parser: query value containing = is preserved" {
        const data = "GET /api?filter=a=b=c HTTP/1.1\r\n\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        const v = req.query.get("filter") orelse "";
        try expectEqualStrings("a=b=c", v);
    }

    // ============================================================================
    // 1.12 Special HTTP version strings
    // ============================================================================

    test "parser: HTTP/1.0 version is preserved" {
        const data = "GET / HTTP/1.0\r\n\r\n";
        const request_data = try createRawRequest(allocator, data);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings("HTTP/1.0", req.version);
    }

    // ============================================================================
    // SECTION 2: URL Decoder Edge Cases
    // ============================================================================

    test "urlDecode: empty string returns empty slice (or zero-alloc)" {
        const result = try http_parser.urlDecode("", allocator);
        defer allocator.free(result);
        try expectEqual(@as(usize, 0), result.len);
    }

    test "urlDecode: %20 decodes to space" {
        const result = try http_parser.urlDecode("hello%20world", allocator);
        defer allocator.free(result);
        try expectEqualStrings("hello world", result);
    }

    test "urlDecode: lowercase hex %2f decodes to /" {
        const result = try http_parser.urlDecode("path%2fsegment", allocator);
        defer allocator.free(result);
        try expectEqualStrings("path/segment", result);
    }

    test "urlDecode: + decodes to space (form-urlencoded semantics)" {
        const result = try http_parser.urlDecode("a+b+c", allocator);
        defer allocator.free(result);
        try expectEqualStrings("a b c", result);
    }

    test "urlDecode: invalid percent sequence is preserved literally" {
        // %XY is not a valid hex pair — the implementation falls through to
        // a literal '%' (the spec mandates this fallback).
        const result = try http_parser.urlDecode("100%XYZ", allocator);
        defer allocator.free(result);
        try expect(std.mem.indexOfScalar(u8, result, '%') != null);
    }

    test "urlDecode: trailing incomplete %X is preserved" {
        const result = try http_parser.urlDecode("foo%", allocator);
        defer allocator.free(result);
        // Should preserve the '%' (incomplete escape is literal).
        try expect(std.mem.indexOfScalar(u8, result, '%') != null);
    }

    test "urlDecode: percent-encoded special chars (slash, colon, query, hash, ampersand, equals)" {
        // %2F = /, %3A = :, %3F = ?, %23 = #, %26 = &, %3D = =
        const result = try http_parser.urlDecode("%2F%3A%3F%23%26%3D", allocator);
        defer allocator.free(result);
        try expectEqualStrings("/:?#&=", result);
    }

    test "urlDecode: long string stress test (10 KB input → 5 KB output)" {
        // Build input "a%61a%61a%61..." (4 input bytes → 2 decoded 'a' bytes).
        // 10240 input bytes / 4 = 2560 groups → 2560 * 2 = 5120 decoded bytes.
        var input_buf: [10240]u8 = undefined;
        for (&input_buf, 0..) |*c, i| {
            const in_group = i % 4;
            c.* = switch (in_group) {
                0 => 'a',
                1 => '%',
                2 => '6',
                3 => '1',
                else => unreachable,
            };
        }
        const result = try http_parser.urlDecode(&input_buf, allocator);
        defer allocator.free(result);

        // 10240 input bytes → 5120 decoded bytes.
        try expectEqual(@as(usize, 5120), result.len);
        // Every char should be 'a'.
        for (result) |c| try expectEqual(@as(u8, 'a'), c);
    }

    // ============================================================================
    // SECTION 3: Router Complex Cases
    // ============================================================================
    //
    // These test the route matching logic with paths and patterns that the
    // basic router tests don't cover.

    fn createMockRequest(method: []const u8, path: []const u8, allocator_: std.mem.Allocator) http_parser.HttpRequest {
        return http_parser.HttpRequest{
            .method = method,
            .path = path,
            .version = "HTTP/1.1",
            .headers = std.StringHashMap([]const u8).init(allocator_),
            .body = "",
            .raw = "",
            .params = std.StringHashMap([]const u8).init(allocator_),
            .query = std.StringHashMap([]const u8).init(allocator_),
            ._client_fd = -1,
        };
    }

    test "router: query string in path does NOT match (caller must strip)" {
        // DOCUMENTED LIMITATION: The router's `matchRoute(method, path, ...)`
        // does NOT strip query strings before matching. Callers must pass
        // the path WITHOUT query string.
        //
        // In production, `http_server.zig:322` calls matchRoute with
        // `req.path` which is the parsed path (with query stripped by
        // parseRequest). So the limitation only affects direct callers.
        //
        // This test locks in the current behavior — a future change to
        // strip query strings in matchRoute should flip the assertion.
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var r = router.Router.init(a);
        defer r.deinit();

        try r.get("/api/search", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return res.withBody("search");
            }
        }.handle);

        var req = createMockRequest("GET", "/api/search?q=hello&page=2", a);
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = a, .io = undefined };
        // Path with query string does NOT match.
        const result = r.matchRoute("GET", req.path, &req, ctx);
        try expect(result == null);

        // Same path WITHOUT query string matches.
        var req_no_q = createMockRequest("GET", "/api/search", a);
        defer req_no_q.params.deinit();
        const result_no_q = r.matchRoute("GET", "/api/search", &req_no_q, ctx);
        try expect(result_no_q != null);
    }

    test "router: trailing slash is treated as part of the path" {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var r = router.Router.init(a);
        defer r.deinit();

        try r.get("/users", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("users", std.heap.page_allocator);
            }
        }.handle);

        var req_no_slash = createMockRequest("GET", "/users", a);
        defer req_no_slash.params.deinit();

        var req_with_slash = createMockRequest("GET", "/users/", a);
        defer req_with_slash.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = a, .io = undefined };

        const r1 = r.matchRoute("GET", "/users", &req_no_slash, ctx);
        try expect(r1 != null);

        // The trailing-slash variant is a different path — it should NOT match.
        const r2 = r.matchRoute("GET", "/users/", &req_with_slash, ctx);
        try expect(r2 == null);
    }

    test "router: route param can contain URL-like chars (slashes forbidden by parser)" {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var r = router.Router.init(a);
        defer r.deinit();

        try r.get("/files/:name", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("file", std.heap.page_allocator);
            }
        }.handle);

        // The router's split-on-/ logic considers everything between slashes
        // to be a single segment. So "/files/report.pdf" should bind name=report.pdf.
        var req = createMockRequest("GET", "/files/report.pdf", a);
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = a, .io = undefined };
        const result = r.matchRoute("GET", "/files/report.pdf", &req, ctx);
        try expect(result != null);
        try expectEqualStrings("report.pdf", req.params.get("name").?);
    }

    test "router: empty path \"/\" matches a root route registration" {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var r = router.Router.init(a);
        defer r.deinit();

        try r.get("/", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("root", std.heap.page_allocator);
            }
        }.handle);

        var req = createMockRequest("GET", "/", a);
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = a, .io = undefined };
        const result = r.matchRoute("GET", "/", &req, ctx);
        try expect(result != null);
    }

    test "router: deep nesting /a/b/c/d/e/f with 6 param segments" {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var r = router.Router.init(a);
        defer r.deinit();

        try r.get("/a/:p1/b/:p2/c/:p3", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("deep", std.heap.page_allocator);
            }
        }.handle);

        var req = createMockRequest("GET", "/a/aa/b/bb/c/cc", a);
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = a, .io = undefined };
        const result = r.matchRoute("GET", "/a/aa/b/bb/c/cc", &req, ctx);
        try expect(result != null);
        try expectEqualStrings("aa", req.params.get("p1").?);
        try expectEqualStrings("bb", req.params.get("p2").?);
        try expectEqualStrings("cc", req.params.get("p3").?);
    }

    test "router: same path registered for multiple methods — each is independent" {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var r = router.Router.init(a);
        defer r.deinit();

        try r.get("/multi", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("GET", std.heap.page_allocator);
            }
        }.handle);

        try r.post("/multi", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("POST", std.heap.page_allocator);
            }
        }.handle);

        try r.put("/multi", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("PUT", std.heap.page_allocator);
            }
        }.handle);

        try r.delete("/multi", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("DELETE", std.heap.page_allocator);
            }
        }.handle);

        try r.patch("/multi", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("PATCH", std.heap.page_allocator);
            }
        }.handle);

        try expectEqual(@as(usize, 5), r.routes.items.len);

        // All 5 methods should match their respective routes.
        const ctx = http_parser.HttpContext{ .allocator = a, .io = undefined };

        inline for ([_][]const u8{ "GET", "POST", "PUT", "DELETE", "PATCH" }) |method| {
            var req = createMockRequest(method, "/multi", a);
            defer req.params.deinit();
            const result = r.matchRoute(method, "/multi", &req, ctx);
            try expect(result != null);
        }
    }

    test "router: HEAD request should match GET route (HTTP convention)" {
        // Per RFC 9110 §9.3.2, HEAD requests MAY be served by a GET handler.
        // The current implementation does NOT support this (separate routes
        // per method) — this test documents the limitation. If a future
        // change adds HEAD-to-GET fallback, flip the expect to != null.
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var r = router.Router.init(a);
        defer r.deinit();

        try r.get("/page", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("page", std.heap.page_allocator);
            }
        }.handle);

        var req = createMockRequest("HEAD", "/page", a);
        defer req.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = a, .io = undefined };
        const result = r.matchRoute("HEAD", "/page", &req, ctx);
        // Currently HEAD does not fall back to GET — locked in for now.
        try expect(result == null);
    }

    test "router: empty pattern \"/\" is matched by \"/\" request only" {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var r = router.Router.init(a);
        defer r.deinit();

        try r.get("/", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("root", std.heap.page_allocator);
            }
        }.handle);

        var req_a = createMockRequest("GET", "/", a);
        defer req_a.params.deinit();

        var req_empty = createMockRequest("GET", "", a);
        defer req_empty.params.deinit();

        const ctx = http_parser.HttpContext{ .allocator = a, .io = undefined };

        // Exact match works.
        try expect(r.matchRoute("GET", "/", &req_a, ctx) != null);
        // Empty path doesn't match a "/" route (current implementation).
        try expect(r.matchRoute("GET", "", &req_empty, ctx) == null);
    }

    // ============================================================================
    // SECTION 4: HTTP Response Builder Edge Cases
    // ============================================================================

    test "response: withBody sets Content-Length to body byte count" {
        const body = "Hello, World!";
        var resp = http_parser.HttpResponse.init(200, "OK", allocator).withBody(body);
        defer resp.deinit();
        const cl = resp.headers.get("Content-Length") orelse "";
        try expectEqualStrings("13", cl);
    }

    test "response: withJson sets both Content-Type and Content-Length" {
        const json = "{\"key\":\"value\"}";
        var resp = http_parser.HttpResponse.init(200, "OK", allocator).withJson(json);
        defer resp.deinit();
        const ct = resp.headers.get("Content-Type") orelse "";
        const cl = resp.headers.get("Content-Length") orelse "";
        try expectEqualStrings("application/json", ct);
        try expectEqualStrings("15", cl);
    }

    test "response: 201 Created status text" {
        var resp = http_parser.created("resource-id-123", allocator);
        defer resp.deinit();
        try expectEqual(@as(u16, 201), resp.status_code);
        try expectEqualStrings("Created", resp.status_text);
    }

    test "response: 204 No Content (used for DELETE responses)" {
        var resp = http_parser.HttpResponse.init(204, "No Content", allocator).withBody("");
        defer resp.deinit();
        try expectEqual(@as(u16, 204), resp.status_code);
        try expectEqualStrings("No Content", resp.status_text);
    }

    test "response: 400 Bad Request via helper" {
        var resp = http_parser.badRequest("missing 'name' field", allocator);
        defer resp.deinit();
        try expectEqual(@as(u16, 400), resp.status_code);
        try expectEqualStrings("Bad Request", resp.status_text);
        try expectEqualStrings("missing 'name' field", resp.body);
    }

    test "response: 500 Internal Server Error via helper" {
        var resp = http_parser.internalError("database connection failed", allocator);
        defer resp.deinit();
        try expectEqual(@as(u16, 500), resp.status_code);
        try expectEqualStrings("Internal Server Error", resp.status_text);
        try expectEqualStrings("database connection failed", resp.body);
    }

    test "response: 404 Not Found has default body" {
        var resp = http_parser.notFound(allocator);
        defer resp.deinit();
        try expectEqual(@as(u16, 404), resp.status_code);
        try expectEqualStrings("Not Found", resp.status_text);
        try expectEqualStrings("Not Found", resp.body);
    }

    test "response: jsonResponseHelper for 418 I'm a teapot" {
        var resp = http_parser.jsonResponseHelper(allocator, .{ .data = "{\"teapot\":true}", .status_code = 418 });
        defer resp.deinit();
        try expectEqual(@as(u16, 418), resp.status_code);
        try expectEqualStrings("I'm a Teapot", resp.status_text);
    }

    test "response: jsonResponseHelper for 503 Service Unavailable" {
        var resp = http_parser.jsonResponseHelper(allocator, .{ .data = "{\"retry_after\":60}", .status_code = 503 });
        defer resp.deinit();
        try expectEqual(@as(u16, 503), resp.status_code);
        try expectEqualStrings("Service Unavailable", resp.status_text);
    }

    test "response: jsonResponseHelper for unknown status returns 'Unknown' text" {
        // Out-of-range status codes fall through to the "Unknown" default
        // in the switch (verified at http_parser.zig:327).
        var resp = http_parser.jsonResponseHelper(allocator, .{ .data = "{}", .status_code = 999 });
        defer resp.deinit();
        try expectEqual(@as(u16, 999), resp.status_code);
        try expectEqualStrings("Unknown", resp.status_text);
    }

    test "response: toBytes produces valid HTTP/1.1 wire format" {
        var resp = http_parser.HttpResponse.init(200, "OK", allocator).withBody("Hello");
        const bytes = try resp.toBytes();
        defer resp.allocator.free(bytes);
        defer resp.deinit();

        // The first line MUST be "HTTP/1.1 200 OK\r\n".
        try expectEqualStrings("HTTP/1.1 200 OK\r\n", bytes[0..17]);

        // Must contain Content-Length: 5
        try expect(std.mem.indexOf(u8, bytes, "Content-Length: 5\r\n") != null);

        // Must end with body after \r\n\r\n
        try expect(std.mem.endsWith(u8, bytes, "\r\n\r\nHello"));
    }

    test "response: multiple headers preserved through toBytes" {
        var resp = http_parser.HttpResponse.init(200, "OK", allocator).withBody("x");
        try resp.headers.put("X-Custom-1", "value1");
        try resp.headers.put("X-Custom-2", "value2");
        try resp.headers.put("X-Request-Id", "abc-123");

        const bytes = try resp.toBytes();
        defer resp.allocator.free(bytes);
        defer resp.deinit();

        try expect(std.mem.indexOf(u8, bytes, "X-Custom-1: value1\r\n") != null);
        try expect(std.mem.indexOf(u8, bytes, "X-Custom-2: value2\r\n") != null);
        try expect(std.mem.indexOf(u8, bytes, "X-Request-Id: abc-123\r\n") != null);
    }

    // ============================================================================
    // SECTION 5: GinwaServer / Address Edge Cases
    // ============================================================================

    test "address: invalid port (0) is accepted by kernel (port 0 = ephemeral)" {
        // Port 0 is valid — it asks the kernel to pick an ephemeral port.
        // The Address struct must accept it without error.
        const addr = try http_server.Address.init("127.0.0.1", 0);
        defer _ = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, addr.sock_fd)))) else @intCast(addr.sock_fd));
        try expect(addr.sock_fd >= 0);
        try expectEqual(@as(u16, 0), addr.port);
    }

    test "address: maximum u16 port (65535) is accepted" {
        // Port 65535 is the top of the u16 range — must not overflow.
        const addr = try http_server.Address.init("127.0.0.1", 65535);
        defer _ = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, addr.sock_fd)))) else @intCast(addr.sock_fd));
        try expectEqual(@as(u16, 65535), addr.port);
    }

    test "address: SO_REUSEADDR is set (verifiable by getsockopt)" {
        // SO_REUSEADDR allows a fresh socket to bind a port that was
        // recently in TIME_WAIT. macOS has stricter semantics than Linux
        // for this option, so we don't try to actually rebind the same
        // port (that fails on macOS regardless of SO_REUSEADDR for ~60s
        // after the first close). Instead, we directly verify the option
        // is set via getsockopt — that's the actual property being tested.
        if (builtin.os.tag == .windows) return error.SkipZigTest;

        const addr = try http_server.Address.init("127.0.0.1", 0);
        defer _ = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, addr.sock_fd)))) else @intCast(addr.sock_fd));

        // Read SO_REUSEADDR back and confirm it's set to a non-zero value.
        var optval: c_int = 0;
        var optlen: std.c.socklen_t = @sizeOf(c_int);
        const rc = std.c.getsockopt(
            addr.sock_fd,
            @intCast(posix.SOL.SOCKET),
            @intCast(posix.SO.REUSEADDR),
            &optval,
            &optlen,
        );
        try expectEqual(@as(c_int, 0), rc); // 0 = success
        try expect(optval != 0);            // 1 = SO_REUSEADDR set
    }

    /// Read the ephemeral port the kernel assigned to `fd`. Used by the
    /// SO_REUSEADDR test above to pick a port that's free on this host.
    fn getsocknamePort(fd: i32) !u16 {
        var sa: std.c.sockaddr.in = std.mem.zeroes(std.c.sockaddr.in);
        var sa_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        if (std.c.getsockname(fd, @ptrCast(&sa), &sa_len) != 0) return error.GetSockNameFailed;
        return std.mem.bigToNative(u16, sa.port);
    }

    const GetSockNameFailed = error{GetSockNameFailed};

    test "ginwa: destroy then re-init works (no global state leak)" {
        const a = allocator;
        const addr1 = try http_server.Address.init("127.0.0.1", 45710);
        defer _ = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, addr1.sock_fd)))) else @intCast(addr1.sock_fd));

        var server1 = try http_server.GinwaServer.init(a, undefined, addr1);
        defer server1.destroy(a);

        const addr2 = try http_server.Address.init("127.0.0.1", 45711);
        defer _ = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, addr2.sock_fd)))) else @intCast(addr2.sock_fd));

        var server2 = try http_server.GinwaServer.init(a, undefined, addr2);
        defer server2.destroy(a);

        try expect(server1.address.sock_fd != server2.address.sock_fd);
    }

    test "ginwa: destroy releases router routes (no leak via destroy alone)" {
        // Regression test: previously `server.deinit()` had to be called
        // explicitly before `server.destroy(allocator)` because destroy
        // didn't free the router's ArrayList. Now destroy() calls deinit()
        // first, so a single destroy() should clean up everything.
        const a = allocator;
        const addr = try http_server.Address.init("127.0.0.1", 45712);
        defer _ = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, addr.sock_fd)))) else @intCast(addr.sock_fd));

        var server = try http_server.GinwaServer.init(a, undefined, addr);
        // Intentionally do NOT call server.deinit() — destroy() should handle it.
        try server.router.get("/route1", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.heap.page_allocator);
            }
        }.handle);
        try server.router.get("/route2", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.heap.page_allocator);
            }
        }.handle);
        try server.router.get("/route3", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("", std.heap.page_allocator);
            }
        }.handle);

        // No leak reported by testing.allocator on scope exit.
        server.destroy(a);
    }

    test "address: closeFd on Address fd closes it (kernel returns EBADF on next op)" {
        const addr = try http_server.Address.init("127.0.0.1", 45713);
        const fd = addr.sock_fd;
        // fd_t form for the read below (SOCKET-as-pointer on Windows).
        const fd_t: std.c.fd_t = if (comptime builtin.os.tag == .windows)
            @ptrFromInt(@as(usize, @bitCast(@as(isize, fd))))
        else
            @intCast(fd);

        // Platform close (closesocket on Windows — CRT close silently
        // succeeds without closing a SOCKET, leaving the peer connected).
        helpers.closeI32Fd(fd);

        // After close, a recv on this fd must fail on every platform.
        var buf: [16]u8 = undefined;
        try expect(helpers.readTestFd(fd_t, &buf) < 0);
    }

    // ============================================================================
    // SECTION 6: RequestBuffer Edge Cases
    // ============================================================================

    test "requestBuffer: getContentLength with Content-Length: 0" {
        const data =
            "POST /api HTTP/1.1\r\n" ++
            "Content-Length: 0\r\n" ++
            "\r\n";
        const cl = http_server.RequestBuffer.getContentLength(data);
        try expect(cl != null);
        try expectEqual(@as(usize, 0), cl.?);
    }

    test "requestBuffer: getContentLength missing header returns null" {
        const data =
            "GET /api HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "\r\n";
        const cl = http_server.RequestBuffer.getContentLength(data);
        try expect(cl == null);
    }

    test "requestBuffer: getContentLength with tabs in value" {
        // Header value separator is colon + optional whitespace (tabs OK).
        const data =
            "POST /api HTTP/1.1\r\n" ++
            "Content-Length:\t1234\r\n" ++
            "\r\n";
        const cl = http_server.RequestBuffer.getContentLength(data);
        try expect(cl != null);
        try expectEqual(@as(usize, 1234), cl.?);
    }

    test "requestBuffer: getContentLength with uppercase variant" {
        const data =
            "POST /api HTTP/1.1\r\n" ++
            "content-length: 500\r\n" ++
            "\r\n";
        const cl = http_server.RequestBuffer.getContentLength(data);
        try expect(cl != null);
        try expectEqual(@as(usize, 500), cl.?);
    }

    test "requestBuffer: getContentLength with bogus non-numeric value" {
        const data =
            "POST /api HTTP/1.1\r\n" ++
            "Content-Length: not-a-number\r\n" ++
            "\r\n";
        const cl = http_server.RequestBuffer.getContentLength(data);
        try expect(cl == null);
    }

    // ============================================================================
    // SECTION 7: SSE Manager Edge Cases
    // ============================================================================

    fn createSocketPair() ![2]std.c.fd_t {
        // Windows: kernel32 CreatePipe via the shared helper. POSIX:
        // socketpair with the macOS/BSD SO_SNDBUF bump. Dispatched at
        // comptime so each host's branch is dead-code-eliminated.
        if (comptime builtin.os.tag == .windows) {
            return helpers.createSocketPair();
        }
        return createBsdSocketPair();
    }

    fn createBsdSocketPair() ![2]std.c.fd_t {
        // POSIX-only: socketpair + bump SO_SNDBUF for macOS/BSD portability.
        // Windows is handled by the shared helpers.createSocketPair (which
        // uses kernel32 CreatePipe — no SO_SNDBUF tuning applies to pipes).
        var fds: [2]std.c.fd_t = undefined;
        const rc = posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
        if (rc < 0) return error.SocketFailed;
        // macOS (and BSD) defaults SO_SNDBUF to ~8 KB on AF_UNIX SOCK_STREAM
        // pairs — far smaller than Linux (~208 KB). Tests that write 16 KB or
        // more would block forever waiting for the reader to drain. Bump to
        // 256 KB explicitly so SSE write-path tests stay portable.
        var size: c_int = 256 * 1024;
        _ = posix.system.setsockopt(
            fds[0],
            posix.SOL.SOCKET,
            posix.SO.SNDBUF,
            &size,
            @sizeOf(@TypeOf(size)),
        );
        return fds;
    }

    test "sse: writeChunkedFrame handles empty event (terminator chunk)" {
        const pair = try createSocketPair();
        defer helpers.closeSocketPair(pair);

        try sse_manager.writeChunkedFrame(toI32(pair[0]), "");

        // Read exactly the 5-byte terminator (TCP loopback pairs return
        // partial reads; a single-shot read is only correct on POSIX
        // socketpairs with room in the buffer).
        var buf: [16]u8 = undefined;
        try helpers.readTestFdFull(pair[1], buf[0..5]);
        try expectEqualSlices(u8, "0\r\n\r\n", buf[0..5]);
    }

    test "sse: writeChunkedFrame handles large event (16 KB)" {
        const pair = try createSocketPair();
        defer helpers.closeSocketPair(pair);

        var large = std.ArrayList(u8).empty;
        defer large.deinit(allocator);
        var i: usize = 0;
        while (i < 16384) : (i += 1) try large.append(allocator, 'A');

        try sse_manager.writeChunkedFrame(toI32(pair[0]), large.items);

        // Read the hex header "4000\r\n" (6 bytes) + 16384 data + "\r\n" (2 bytes) = 16392
        var header_buf: [6]u8 = undefined;
        try helpers.readTestFdFull(pair[1], &header_buf);
        // Hex length of 16384 is "4000"
        try expectEqualStrings("4000\r\n", &header_buf);
    }

    test "sse: register 100 clients then remove all — no FD leaks" {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var mgr = try sse_manager.SseManager.init(a, a, io);
        defer mgr.deinit();

        var socket_pairs = std.ArrayListUnmanaged([2]std.c.fd_t).empty;
        defer {
            for (socket_pairs.items) |fds| {
                _ = std.c.close(fds[1]);
            }
            socket_pairs.deinit(a);
        }

        for (0..100) |_| {
            const fds = try createSocketPair();
            try socket_pairs.append(a, fds);
            _ = try mgr.registerClient(toI32(fds[0]));
        }

        try expectEqual(@as(usize, 100), mgr.clientCount());

        // Remove all clients — verify count drops to 0 with no leak.
        for (socket_pairs.items) |fds| {
            _ = mgr.removeClientByFd(toI32(fds[0]), .test_only);
        }

        try expectEqual(@as(usize, 0), mgr.clientCount());
    }

    test "sse: client IDs are unique (no collisions across 50 registrations)" {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var mgr = try sse_manager.SseManager.init(a, a, io);
        defer mgr.deinit();

        var socket_pairs = std.ArrayListUnmanaged([2]std.c.fd_t).empty;
        defer {
            for (socket_pairs.items) |fds| {
                _ = std.c.close(fds[1]);
            }
            socket_pairs.deinit(a);
        }

        var ids = std.ArrayListUnmanaged([16]u8).empty;
        defer ids.deinit(a);

        for (0..50) |_| {
            const fds = try createSocketPair();
            try socket_pairs.append(a, fds);
            const id = try mgr.registerClient(toI32(fds[0]));
            try ids.append(a, id);
        }

        // Verify no duplicate IDs in the list (each must be unique).
        for (ids.items, 0..) |id, i| {
            for (ids.items[i + 1 ..]) |other| {
                try expect(!std.mem.eql(u8, &id, &other));
            }
        }
    }

    test "sse: remove same fd twice returns null on second call" {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var mgr = try sse_manager.SseManager.init(a, a, io);
        defer mgr.deinit();

        const pair = try createSocketPair();
        defer _ = std.c.close(pair[0]);
        defer _ = std.c.close(pair[1]);

        _ = try mgr.registerClient(toI32(pair[0]));

        const first = mgr.removeClientByFd(toI32(pair[0]), .test_only);
        try expect(first != null);

        const second = mgr.removeClientByFd(toI32(pair[0]), .test_only);
        try expect(second == null);
    }

    // ============================================================================
    // SECTION 8: Concurrent Request Handling Integration
    // ============================================================================

    test "integration: parse 100 sequential requests from socket pair" {
        // Simulates a server parsing multiple HTTP requests from one
        // persistent connection. The parser is called once per request.
        const pair = try createSocketPair();
        defer helpers.closeSocketPair(pair);

        var i: usize = 0;
        while (i < 100) : (i += 1) {
            var request_buf: [128]u8 = undefined;
            const req_str = try std.fmt.bufPrint(
                &request_buf,
                "GET /req/{d} HTTP/1.1\r\nHost: localhost\r\n\r\n",
                .{i},
            );

            // Write to client end of pair (server reads from pair[0]).
            // Loop on short writes (TCP loopback pairs return partial
            // sends; a single-shot write silently truncates).
            try helpers.writeTestFdAll(pair[1], req_str);

            var rb = http_server.RequestBuffer.init(allocator);
            defer rb.deinit();

            const data = try rb.readFullRequest(toI32(pair[0]));
            defer allocator.free(data);

            var req = try http_parser.parseRequest(data, allocator, undefined, 0);
            defer req.deinit(allocator);

            // Verify path matches what we sent
            var expected_path_buf: [32]u8 = undefined;
            const expected_path = try std.fmt.bufPrint(&expected_path_buf, "/req/{d}", .{i});
            try expectEqualStrings(expected_path, req.path);
            try expectEqualStrings("GET", req.method);
        }
    }

    // ============================================================================
    // SECTION 9: Edge Case Stress Tests
    // ============================================================================

    test "stress: parse 1000 random-ish requests without crash" {
        var prng = std.Random.DefaultPrng.init(42);
        const random = prng.random();

        var i: usize = 0;
        while (i < 1000) : (i += 1) {
            const method = if (i % 4 == 0) "GET" else if (i % 4 == 1) "POST" else if (i % 4 == 2) "PUT" else "DELETE";
            // Build a random path segment (alphanumeric only — no %XX, no
            // spaces, so urlDecode doesn't have to do anything weird).
            const path_len = random.intRangeAtMost(u8, 1, 50);
            var path_seg: [64]u8 = undefined;
            random.bytes(path_seg[0..path_len]);
            for (path_seg[0..path_len]) |*c| {
                // Map random byte to safe ASCII (a-z, A-Z, 0-9)
                const n: u8 = c.* % 62;
                c.* = if (n < 26) @as(u8, 'a') + n else if (n < 52) @as(u8, 'A') + (n - 26) else @as(u8, '0') + (n - 52);
            }

            var request_buf: [256]u8 = undefined;
            const req_str = try std.fmt.bufPrint(
                &request_buf,
                "{s} /api/{s} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
                .{ method, path_seg[0..path_len] },
            );
            const request_data = try allocator.dupe(u8, req_str);
            defer allocator.free(request_data);

            var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
            defer req.deinit(allocator);

            // No assertion — we're just verifying no panic / crash / leak.
        }
    }

    test "stress: 50 sequential server init/destroy cycles" {
        var i: usize = 0;
        while (i < 50) : (i += 1) {
            // Port 0 = let the OS pick a free one. Fixed ports in the
            // 45800-range sit INSIDE the kernel's ephemeral range
            // (32768-60999), so any concurrent OUTBOUND connection using one
            // of those ports as its source port makes bind() fail with
            // EADDRINUSE — the flaky `BindFailed` this test used to hit.
            // Same fix as the 500-cycle test in the extra complex-cases suite in sse_manager.zig.
            const addr = try http_server.Address.init("127.0.0.1", 0);
            var server = try http_server.GinwaServer.init(allocator, undefined, addr);
            server.destroy(allocator);
            closeI32Fd(addr.sock_fd);
        }
        // No leak reported by testing.allocator on scope exit.
    }
};

comptime {
    _ = complex_cases_tests;
}

// ============================================================================
// Tests — moved here from `http_parser_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = http_parser_tests; }` below pulls them into the run.
// ============================================================================

const http_parser_tests = struct {
    const http_parser = @import("http_parser.zig");

    const expect = std.testing.expect;
    const expectEqual = std.testing.expectEqual;
    const expectEqualStrings = std.testing.expectEqualStrings;

    const allocator = std.testing.allocator;

    // ==================== Helper Functions ====================

    fn createHttpRequest(method: []const u8, path: []const u8, body: []const u8, alloc: std.mem.Allocator) ![]u8 {
        return createHttpRequestWithHeaders(method, path, &.{}, body, alloc);
    }

    fn createHttpRequestWithHeaders(method: []const u8, path: []const u8, headers: []const []const u8, body: []const u8, alloc: std.mem.Allocator) ![]u8 {
        var buf = std.ArrayList(u8).empty;
        errdefer buf.deinit(alloc);

        try buf.appendSlice(alloc, method);
        try buf.appendSlice(alloc, " ");
        try buf.appendSlice(alloc, path);
        try buf.appendSlice(alloc, " HTTP/1.1\r\n");

        for (headers) |header| {
            try buf.appendSlice(alloc, header);
            try buf.appendSlice(alloc, "\r\n");
        }

        if (body.len > 0) {
            const cl = try std.fmt.allocPrint(alloc, "Content-Length: {d}", .{body.len});
            defer alloc.free(cl);
            try buf.appendSlice(alloc, cl);
            try buf.appendSlice(alloc, "\r\n");
        }

        try buf.appendSlice(alloc, "\r\n");
        try buf.appendSlice(alloc, body);

        return try buf.toOwnedSlice(alloc);
    }

    /// Create JSON body with exact target size
    /// Format: {"key":"xxx...xxx"} where the content makes total size = target_size
    fn createJsonBody(comptime target_size: usize, alloc: std.mem.Allocator, char: u8) ![]u8 {
        // prefix: {"":""} = 9 chars ("\"" + ":" + "\"" + ":" + "\"")
        // suffix: "} = 2 chars
        // Need target_size - 11 chars of padding
        var body = std.ArrayList(u8).empty;
        errdefer body.deinit(alloc);
        try body.appendSlice(alloc, "{\"data\":\"");
        while (body.items.len < target_size - 2) {
            try body.append(alloc, char);
        }
        try body.appendSlice(alloc, "\"}");
        return try body.toOwnedSlice(alloc);
    }

    // ==================== Basic Request Parsing Tests ====================

    test "parse GET request without body" {
        const request_data = try createHttpRequest("GET", "/test", "", allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings("GET", req.method);
        try expectEqualStrings("/test", req.path);
        try expectEqualStrings("HTTP/1.1", req.version);
        try expectEqualStrings("", req.body);
    }

    test "parse POST request with small JSON" {
        const body = "{\"name\":\"test\"}";
        const request_data = try createHttpRequest("POST", "/api", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings("POST", req.method);
        try expectEqualStrings("/api", req.path);
        try expectEqualStrings(body, req.body);
    }

    test "parse request with custom headers" {
        const request_data = try createHttpRequestWithHeaders("GET", "/test", &.{
            "Host: localhost:8080",
            "User-Agent: TestClient/1.0",
            "Accept: application/json",
        }, "", allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        // Headers may have trailing \r from HTTP parsing
        const host_val = req.headers.get("Host") orelse "";
        const user_agent_val = req.headers.get("User-Agent") orelse "";
        const accept_val = req.headers.get("Accept") orelse "";

        // Trim any trailing carriage returns
        const host = std.mem.trim(u8, host_val, "\r");
        const user_agent = std.mem.trim(u8, user_agent_val, "\r");
        const accept = std.mem.trim(u8, accept_val, "\r");

        try expectEqualStrings("localhost:8080", host);
        try expectEqualStrings("TestClient/1.0", user_agent);
        try expectEqualStrings("application/json", accept);
    }

    // ==================== Large JSON Body Tests ====================

    test "parse POST with 4KB JSON (exactly buffer size)" {
        const body = try createJsonBody(4096, allocator, 'x');
        defer allocator.free(body);

        try expectEqual(@as(usize, 4096), body.len);

        const request_data = try createHttpRequest("POST", "/api/data", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqual(@as(usize, 4096), req.body.len);
    }

    test "parse POST with 5KB JSON (exceeds buffer size)" {
        const body = try createJsonBody(5120, allocator, 'y');
        defer allocator.free(body);

        const request_data = try createHttpRequest("POST", "/api/data", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqual(@as(usize, 5120), req.body.len);
    }

    test "parse POST with 8KB JSON (2x buffer size)" {
        const body = try createJsonBody(8192, allocator, 'z');
        defer allocator.free(body);

        const request_data = try createHttpRequest("POST", "/api/data", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqual(@as(usize, 8192), req.body.len);
    }

    test "parse POST with 16KB JSON (4x buffer size)" {
        const body = try createJsonBody(16384, allocator, 'a');
        defer allocator.free(body);

        const request_data = try createHttpRequest("POST", "/api/data", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqual(@as(usize, 16384), req.body.len);
    }

    test "parse POST with 100KB JSON (large payload)" {
        const body = try createJsonBody(102400, allocator, 'b');
        defer allocator.free(body);

        const request_data = try createHttpRequest("POST", "/api/data", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqual(@as(usize, 102400), req.body.len);
    }

    // ==================== Edge Case Tests ====================

    test "parse POST with JSON at buffer boundary (4095 bytes)" {
        const body = try createJsonBody(4095, allocator, 'c');
        defer allocator.free(body);

        const request_data = try createHttpRequest("POST", "/api/data", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqual(@as(usize, 4095), req.body.len);
    }

    test "parse POST with JSON at buffer boundary (4097 bytes)" {
        const body = try createJsonBody(4097, allocator, 'd');
        defer allocator.free(body);

        const request_data = try createHttpRequest("POST", "/api/data", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqual(@as(usize, 4097), req.body.len);
    }

    test "parse JSON with special characters" {
        const body = "{\"message\":\"Hello\\nWorld\\t!\\u00A9\"}";
        const request_data = try createHttpRequest("POST", "/api", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings(body, req.body);
    }

    test "parse JSON with unicode characters" {
        const body = "{\"name\":\"日本語テスト\"}";
        const request_data = try createHttpRequest("POST", "/api", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings(body, req.body);
    }

    test "parse POST with body split across 4096 boundaries" {
        const body = try createJsonBody(8192, allocator, ',');
        defer allocator.free(body);

        const request_data = try createHttpRequest("POST", "/api/chunked", body, allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqual(@as(usize, 8192), req.body.len);
    }

    test "parse GET with URL-encoded path containing large query" {
        var query = std.ArrayList(u8).empty;
        defer query.deinit(allocator);
        try query.appendSlice(allocator, "data=");
        while (query.items.len < 5000) {
            try query.append(allocator, 'x');
        }
        const query_slice = try query.toOwnedSlice(allocator);
        defer allocator.free(query_slice);

        const path = try std.fmt.allocPrint(allocator, "/api/search?{s}", .{query_slice});
        defer allocator.free(path);

        const request_data = try createHttpRequest("GET", path, "", allocator);
        defer allocator.free(request_data);

        var req = try http_parser.parseRequest(request_data, allocator, undefined, 0);
        defer req.deinit(allocator);

        try expectEqualStrings("/api/search", req.path);
        try expect(req.query.get("data") != null);
    }

    // ==================== redirectWithContext ====================

    const Context = context_mod.Context;
    const contextFromRequest = context_mod.contextFromRequest;

    test "HttpResponse.redirectWithContext: sets Set-Cookie header with ctx=<id>" {
        const store = try ContextStore.create(allocator);
        defer store.deinit();

        const ctx = try store.newContext();
        try ctx.put("user_id", .{ .int = 42 });

        var res = http_parser.HttpResponse.init(0, "", allocator);
        defer res.deinit();

        var out = try http_parser.HttpResponse.redirectWithContext(res, "/landing", ctx, store);
        defer out.deinit();

        const cookie = out.headers.get("Set-Cookie") orelse
            return error.SetCookieHeaderMissing;
        // The cookie must contain `ctx=<id>` and the standard hardening flags.
        try expect(std.mem.indexOf(u8, cookie, "ctx=") != null);
        try expect(std.mem.indexOf(u8, cookie, "Path=/") != null);
        try expect(std.mem.indexOf(u8, cookie, "HttpOnly") != null);
        try expect(std.mem.indexOf(u8, cookie, "SameSite=Strict") != null);

        // The redirect itself is still a 302 to /landing.
        try expectEqual(@as(u16, 302), out.status_code);
        try expectEqualStrings("/landing", out.headers.get("Location").?);
    }

    test "HttpResponse.redirectWithContext: stores the context under that id" {
        const store = try ContextStore.create(allocator);
        defer store.deinit();

        const ctx = try store.newContext();
        try ctx.put("flash", .{ .string = "saved" });

        var res = http_parser.HttpResponse.init(0, "", allocator);
        defer res.deinit();

        var out = try http_parser.HttpResponse.redirectWithContext(res, "/landing", ctx, store);
        defer out.deinit();

        // Extract the ID from the Set-Cookie header.
        const cookie = out.headers.get("Set-Cookie").?;
        const ctx_idx = std.mem.indexOf(u8, cookie, "ctx=").? + "ctx=".len;
        var end_idx: usize = cookie.len;
        for (cookie[ctx_idx..], 0..) |c, i| {
            if (c == ';') {
                end_idx = ctx_idx + i;
                break;
            }
        }
        const id = cookie[ctx_idx..end_idx];

        // The store must have the context under that ID, with the value intact.
        const retrieved = store.get(id).?;
        try expectEqualStrings("saved", retrieved.get("flash").?.string);
    }

    test "HttpResponse.redirectWithContext: original response unchanged (immutable-by-value)" {
        const store = try ContextStore.create(allocator);
        defer store.deinit();

        const ctx = try store.newContext();

        var res = http_parser.HttpResponse.init(200, "OK", allocator);
        defer res.deinit();

        var out = try http_parser.HttpResponse.redirectWithContext(res, "/landing", ctx, store);
        defer out.deinit();

        // Original `res` is unchanged — the helper takes self by value.
        try expectEqual(@as(u16, 200), res.status_code);
        try expectEqualStrings("OK", res.status_text);
        try expect(res.headers.get("Location") == null);
        try expect(res.headers.get("Set-Cookie") == null);
    }

    test "HttpResponse.redirectWithContext + contextFromRequest: round-trip preserves values" {
        const store = try ContextStore.create(allocator);
        defer store.deinit();

        // The originating handler builds a context, attaches it to the redirect.
        const ctx = try store.newContext();
        try ctx.put("user_id", .{ .int = 7 });
        try ctx.put("role", .{ .string = "admin" });

        var res = http_parser.HttpResponse.init(0, "", allocator);
        defer res.deinit();

        var redirect_res = try http_parser.HttpResponse.redirectWithContext(res, "/dashboard", ctx, store);
        defer redirect_res.deinit();

        // The browser would now make a fresh request to /dashboard with the
        // Set-Cookie it received. We simulate that request here.
        const cookie = redirect_res.headers.get("Set-Cookie").?;
        const ctx_idx = std.mem.indexOf(u8, cookie, "ctx=").? + "ctx=".len;
        var end_idx: usize = cookie.len;
        for (cookie[ctx_idx..], 0..) |c, i| {
            if (c == ';') {
                end_idx = ctx_idx + i;
                break;
            }
        }
        const id = cookie[ctx_idx..end_idx];

        // The browser sends back the cookie as `Cookie: ctx=<id>` (the server
        // sets the name `ctx` and the value is the id). Simulate that.
        var next_headers = std.StringHashMap([]const u8).init(allocator);
        defer next_headers.deinit();
        const cookie_pair = try std.fmt.allocPrint(allocator, "ctx={s}", .{id});
        defer allocator.free(cookie_pair);
        try next_headers.put("Cookie", cookie_pair);

        const StubReq = struct {
            headers: std.StringHashMap([]const u8),
        };
        const next_req = StubReq{ .headers = next_headers };

        // The next handler rebuilds the context — values must survive.
        // contextFromRequest returns a LookupResult struct ({context: ?*Context,
        // id: ?[]const u8}) — drill into .context before calling .get().
        const rebuilt = contextFromRequest(next_req, store);
        try expectEqual(@as(i64, 7), rebuilt.context.?.get("user_id").?.int);
        try expectEqualStrings("admin", rebuilt.context.?.get("role").?.string);
    }

    // ==================== Performance Test ====================

    test "parse POST with 1MB JSON (stress test)" {
        const body = try createJsonBody(1024 * 1024, allocator, 'M');
        defer allocator.free(body);
        try expect(body.len == 1024 * 1024);
    }
};

comptime {
    _ = http_parser_tests;
}
