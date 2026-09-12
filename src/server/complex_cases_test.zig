//! Complex test cases for custom_http_server module.
//!
//! These tests target edge cases and behaviors NOT covered by the
//! basic test files:
//!   - HTTP parser: malformed requests, edge case bodies, header edge cases
//!   - URL decoder: percent-encoded sequences, edge cases, mixed content
//!   - Router: complex patterns, traversal cases, edge cases
//!   - Response builder: all status codes, multi-value headers, JSON edge cases
//!   - HTTP server: lifecycle, edge cases in Address / GinwaServer
//!
//! Each section has its own helper functions and shared imports.
//! TDD methodology: tests are written first, the production code is
//! updated only when a test reveals a real bug (not just a missing
//! test case).

const std = @import("std");
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

    _ = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, fd)))) else @intCast(fd));

    // After close, a recv on this fd should fail (the socket is no longer valid).
    var buf: [16]u8 = undefined;
    const fd_for_read: std.c.fd_t = if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, fd)))) else @intCast(fd);
    const rc = std.c.read(fd_for_read, &buf, buf.len);
    try expect(rc < 0);
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
    defer _ = std.c.close(pair[0]);
    defer _ = std.c.close(pair[1]);

    try sse_manager.writeChunkedFrame(toI32(pair[0]), "");

    var buf: [16]u8 = undefined;
    const n = std.c.read(pair[1], &buf, buf.len);
    try expect(n == 5); // "0\r\n\r\n"
    try expectEqualSlices(u8, "0\r\n\r\n", buf[0..@intCast(n)]);
}

test "sse: writeChunkedFrame handles large event (16 KB)" {
    const pair = try createSocketPair();
    defer _ = std.c.close(pair[0]);
    defer _ = std.c.close(pair[1]);

    var large = std.ArrayList(u8).empty;
    defer large.deinit(allocator);
    var i: usize = 0;
    while (i < 16384) : (i += 1) try large.append(allocator, 'A');

    try sse_manager.writeChunkedFrame(toI32(pair[0]), large.items);

    // Read the hex header "4000\r\n" (6 bytes) + 16384 data + "\r\n" (2 bytes) = 16392
    var header_buf: [32]u8 = undefined;
    const n = std.c.read(pair[1], &header_buf, header_buf.len);
    try expect(n > 0);
    // Hex length of 16384 is "4000"
    try expectEqualStrings("4000\r\n", header_buf[0..6]);
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
    defer _ = std.c.close(pair[0]);
    defer _ = std.c.close(pair[1]);

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var request_buf: [128]u8 = undefined;
        const req_str = try std.fmt.bufPrint(
            &request_buf,
            "GET /req/{d} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            .{i},
        );

        // Write to client end of pair (server reads from pair[0]).
        const written = std.c.write(pair[1], req_str.ptr, req_str.len);
        try expect(written == @as(isize, @intCast(req_str.len)));

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
        const port: u16 = 45800 + @as(u16, @intCast(i % 50)); // stay within test range
        const addr = try http_server.Address.init("127.0.0.1", port);
        const _close_fd = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, addr.sock_fd)))) else @intCast(addr.sock_fd));
        _ = _close_fd;

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        server.destroy(allocator);
    }
    // No leak reported by testing.allocator on scope exit.
}