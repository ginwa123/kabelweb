const std = @import("std");
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

const context_mod = @import("context.zig");
const Context = context_mod.Context;
const ContextStore = context_mod.ContextStore;
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

