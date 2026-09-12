// context.zig — per-request Context value bag + server-side ContextStore.
//
// The HTTP layer is stateless: a 302 redirect makes the browser issue a NEW
// request, so any in-memory context (handlers' local variables, middleware
// accumulators) dies with the redirect. To pass state across a redirect,
// handlers put values into a `Context` and call
// `HttpResponse.redirectWithContext(loc, &ctx, &store)`, which serialises
// the context into a cookie. The next handler reads the cookie and calls
// `contextFromRequest(req, &store)` to reconstruct the context.
//
// The `parent: ?*const Context` field lets a chain of contexts (request →
// middleware → handler) walk up to find a value one level up. `get` walks
// the chain; `put` only writes to the local level.

const std = @import("std");

/// A value in the context. Lightweight union — covers the small set of
/// types handlers typically stash (flash messages, request IDs, role).
pub const Value = union(enum) {
    string: []const u8,
    int: i64,
    bool: bool,
};

/// Per-request value bag. One per request. Optional `parent` pointer lets
/// `get` walk up the chain.
pub const Context = struct {
    allocator: std.mem.Allocator,
    values: std.StringHashMap(Value),
    parent: ?*const Context,

    pub fn init(allocator: std.mem.Allocator) Context {
        return .{
            .allocator = allocator,
            .values = std.StringHashMap(Value).init(allocator),
            .parent = null,
        };
    }

    pub fn deinit(self: *Context) void {
        // The map keys are duped strings and any `.string` Value is also
        // deep-copied into the context's allocator (see `put`). Free
        // both before the underlying map deinit so `std.testing.allocator`
        // doesn't flag leaks.
        var it = self.values.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            switch (entry.value_ptr.*) {
                .string => |s| self.allocator.free(s),
                else => {},
            }
        }
        self.values.deinit();
        self.* = undefined;
    }

    /// Insert a value. Allocates a copy of `key` AND of any heap-typed
    /// value (strings) from the context's allocator, so the context
    /// fully owns its data and `deinit` is sufficient to free
    /// everything. Caller passes plain string literals or slices —
    /// the context takes the copy.
    pub fn put(self: *Context, key: []const u8, value: Value) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);
        const value_copy = switch (value) {
            .string => |s| Value{ .string = try self.allocator.dupe(u8, s) },
            .int, .bool => value,
        };
        errdefer switch (value_copy) {
            .string => |s| self.allocator.free(s),
            else => {},
        };
        try self.values.put(key_copy, value_copy);
    }

    /// Look up a value. Walks the parent chain if the key is not local.
    /// Returns `null` if the key is absent at every level.
    pub fn get(self: *const Context, key: []const u8) ?Value {
        if (self.values.get(key)) |v| return v;
        if (self.parent) |p| return p.get(key);
        return null;
    }

    /// Remove a key from this context (does NOT walk the parent chain).
    /// Frees the duped key and any heap-typed value the context owns.
    /// Returns `true` if the key was present, `false` if it wasn't.
    ///
    /// Used by the Rails-style flash message consume-on-read path: the
    /// handler calls `session.flashString(key)` which reads + removes
    /// from the underlying Context.
    pub fn remove(self: *Context, key: []const u8) bool {
        if (self.values.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            switch (kv.value) {
                .string => |s| self.allocator.free(s),
                else => {},
            }
            return true;
        }
        return false;
    }

    /// Create a child context whose parent is this one. The child owns
    /// its own copy of the values map; the parent pointer is borrowed
    /// (the parent must outlive the child).
    pub fn withParent(self: *const Context) Context {
        return .{
            .allocator = self.allocator,
            .values = std.StringHashMap(Value).init(self.allocator),
            .parent = self,
        };
    }
};

/// Server-side storage of contexts keyed by opaque session ID. The
/// redirect helper mints the ID, stores the context, and sets the ID as
/// a cookie. The next request reads the cookie and looks up the context.
///
/// The store is exposed to handlers via `HttpContext` so they can call
/// `contextFromRequest` on each new request. Production lifetimes are
/// scoped to the server's lifetime; tests use `std.testing.allocator`.
///
/// **One entry point: `create(allocator) !*ContextStore`.** Heap-allocates
/// the store so the pointer is stable for the entire server lifetime (the
/// GinwaServer holds it; HttpContext borrows it per request). The
/// matching `deinit` frees the store itself — no separate `destroy` call.
///
/// **Ownership:** the store OWNS every Context passed to `put`. Handlers
/// must obtain a Context via `newContext` (which heap-allocates with
/// the store's allocator) and must NOT call `Context.deinit` on it —
/// the store does that on `remove` or `deinit`. This avoids the
/// use-after-free that happens when a per-request arena frees the
/// Context but the long-lived store still has a pointer to it.
pub const ContextStore = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap(*Context),

    /// Single entry point for creating a ContextStore. Heap-allocates the
    /// store so the returned pointer is stable for the entire server
    /// lifetime. Pair with `deinit` to free everything.
    pub fn create(allocator: std.mem.Allocator) !*ContextStore {
        const store = try allocator.create(ContextStore);
        store.* = .{
            .allocator = allocator,
            .map = std.StringHashMap(*Context).init(allocator),
        };
        return store;
    }

    pub fn deinit(self: *ContextStore) void {
        // Free every owned Context (deinit + destroy), then free the
        // duped ID keys, then free the map structure. Finally free the
        // store itself — callers always heap-allocate via `create`.
        var vit = self.map.iterator();
        while (vit.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        var kit = self.map.iterator();
        while (kit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit();
        self.allocator.destroy(self);
    }

    /// Heap-allocate a fresh Context owned by the store. Allocations
    /// inside the Context (key dupes, value copies) also come from the
    /// store's allocator so the entire Context lives as long as the
    /// store does.
    pub fn newContext(self: *ContextStore) !*Context {
        const ctx = try self.allocator.create(Context);
        ctx.* = Context.init(self.allocator);
        return ctx;
    }

    /// Take ownership of `ctx` and store it under the duped `id`. The
    /// store will deinit + destroy the Context on `remove` or on the
    /// store's own `deinit`. Do NOT call `Context.deinit` on `ctx`
    /// after this — the store owns it now.
    pub fn put(self: *ContextStore, id: []const u8, ctx: *Context) !void {
        const id_copy = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(id_copy);
        try self.map.put(id_copy, ctx);
    }

    /// Like `put` but the caller transfers ownership of `id` to the
    /// store — the store will free it on `remove` / `deinit`. Useful
    /// when the id is heap-allocated and the caller doesn't need it
    /// after the put (e.g. `HttpContext.flushPending` mints an id and
    /// returns it to a caller that uses it for a cookie — the cookie's
    /// lifetime is bounded by response.deinit, and the id's lifetime is
    /// bounded by store.deinit, so the cookie contents stay valid until
    /// the response is sent).
    pub fn putOwned(self: *ContextStore, id: []const u8, ctx: *Context) !void {
        try self.map.put(id, ctx);
    }

    pub fn get(self: *const ContextStore, id: []const u8) ?*Context {
        return self.map.get(id);
    }

    /// Drop the entry and free both the duped ID and the owned Context.
    pub fn remove(self: *ContextStore, id: []const u8) void {
        if (self.map.fetchRemove(id)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        }
    }
};

/// Parse the `Cookie` header for `ctx=<id>`. Returns the ID slice
/// (a sub-slice of the header — no allocation). Returns `null` if the
/// header is missing or has no `ctx=` entry.
pub fn parseCtxCookie(cookie_header: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, cookie_header, ';');
    while (it.next()) |pair| {
        var trimmed = std.mem.trim(u8, pair, " \t");
        if (std.mem.startsWith(u8, trimmed, "ctx=")) {
            return trimmed["ctx=".len..];
        }
    }
    return null;
}

/// Rebuild a Context from the incoming request. Reads `ctx=<id>` from
/// the `Cookie` header, looks up the context in the store. The
/// returned struct carries both the Context (if any) AND the cookie id
/// used to look it up — the listen loop needs the id so the
/// Rails-style `flashString` consume path can evict the entry.
///
/// `req` is `anytype` so tests can pass a stub struct with only the
/// `.headers` field. The real `HttpRequest` also satisfies this shape.
pub const LookupResult = struct {
    context: ?*Context,
    id: ?[]const u8,
};

pub fn contextFromRequest(req: anytype, store: *const ContextStore) LookupResult {
    const T = @TypeOf(req);
    if (!@hasField(T, "headers")) return .{ .context = null, .id = null };
    const cookie = req.headers.get("Cookie") orelse return .{ .context = null, .id = null };
    const id = parseCtxCookie(cookie) orelse return .{ .context = null, .id = null };
    return .{ .context = store.get(id), .id = id };
}
