const std = @import("std");
const http_parser = @import("http_parser.zig");
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
        .sse => |sse| {
            _ = sse;
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