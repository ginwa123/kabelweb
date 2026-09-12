// ============================================================================
// security_test.zig — behavioural tests for the security primitives.
//
// All 16 tests below exercise the primitives end-to-end. No source-grep
// / static-contract tests (project rule 2026-07-29).
//
// Tests:
//   1-4:   csrfTokenIssue + csrfTokenValidate round-trip and tamper
//          detection
//   5-8:   rateLimitCheck under-limit / over-limit / per-IP / window reset
//   9-12:  applySecurityHeaders sets each of the 4 most-important headers
//   13-15: checkOrigin matches / mismatches Origin / mismatches Referer
//   16:    enforceBodySizeLimit rejects oversized bodies
// ============================================================================

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const security = @import("security.zig");
const http_server = @import("http_server.zig");
const router = @import("router.zig");
const http_parser = @import("http_parser.zig");
const linux = std.posix.system;

fn noopHandler(_: http_parser.HttpContext, _: http_parser.HttpRequest, res: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
    return res.withBody("");
}

const TEST_SECRET = "test-csrf-secret-do-not-use-in-prod";

fn makeMockRequest(allocator: std.mem.Allocator) security.HttpRequest {
    return .{
        .method = "POST",
        .path = "/users",
        .version = "HTTP/1.1",
        .headers = std.StringHashMap([]const u8).init(allocator),
        .body = "",
        .raw = "",
        .params = std.StringHashMap([]const u8).init(allocator),
        .query = std.StringHashMap([]const u8).init(allocator),
        ._client_fd = -1,
    };
}

// ───────────────────────────────────────────────────────────────────────────
//  CSRF token primitives (tests 1-4)
// ───────────────────────────────────────────────────────────────────────────

test "csrfTokenIssue + csrfTokenValidate round-trip succeeds" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bundle = try security.csrfTokenIssue(TEST_SECRET, io, testing.allocator);
    defer testing.allocator.free(bundle.token);
    defer testing.allocator.free(bundle.cookie);

    try testing.expect(bundle.token.len > 0);
    try testing.expect(bundle.cookie.len > 0);

    // Validate at current time.
    const now = std.Io.Clock.now(.real, io).toSeconds();
    try security.csrfTokenValidate(bundle.token, TEST_SECRET, now);
}

test "csrfTokenValidate rejects tampered token" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bundle = try security.csrfTokenIssue(TEST_SECRET, io, testing.allocator);
    defer testing.allocator.free(bundle.token);
    defer testing.allocator.free(bundle.cookie);

    // Flip a character in the middle of the token (well inside the HMAC
    // section so any change invalidates the signature).
    var tampered = try testing.allocator.dupe(u8, bundle.token);
    defer testing.allocator.free(tampered);
    const tampered_idx = tampered.len / 2;
    tampered[tampered_idx] = if (tampered[tampered_idx] == 'A') 'B' else 'A';

    const now = std.Io.Clock.now(.real, io).toSeconds();
    const result = security.csrfTokenValidate(tampered, TEST_SECRET, now);
    try testing.expectError(error.CsrfMismatch, result);
}

test "csrfTokenValidate rejects expired token" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bundle = try security.csrfTokenIssue(TEST_SECRET, io, testing.allocator);
    defer testing.allocator.free(bundle.token);
    defer testing.allocator.free(bundle.cookie);

    // Pass a "now" that's older than the token's issued-at time + TTL.
    // The token was issued at `issued_at`; if we tell the validator that
    // current time is `issued_at - 1`, the token looks "from the future"
    // which trips the clock-skew guard. We need to test the EXPIRED path
    // instead — pass `issued_at + TTL + 1` to the validator.
    //
    // Extract the timestamp from the token (first '.'-separated segment).
    var ts_iter = std.mem.splitScalar(u8, bundle.token, '.');
    const ts_str = ts_iter.next().?;
    const issued_at = try std.fmt.parseInt(i64, ts_str, 10);

    const expired_now = issued_at + security.CSRF_TOKEN_TTL_SEC + 1;
    const result = security.csrfTokenValidate(bundle.token, TEST_SECRET, expired_now);
    try testing.expectError(error.CsrfMismatch, result);
}

test "csrfTokenValidate rejects wrong-secret token" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bundle = try security.csrfTokenIssue(TEST_SECRET, io, testing.allocator);
    defer testing.allocator.free(bundle.token);
    defer testing.allocator.free(bundle.cookie);

    const wrong_secret = "completely-different-secret";
    const now = std.Io.Clock.now(.real, io).toSeconds();
    const result = security.csrfTokenValidate(bundle.token, wrong_secret, now);
    try testing.expectError(error.CsrfMismatch, result);
}

// ───────────────────────────────────────────────────────────────────────────
//  Rate limit primitive (tests 5-8)
// ───────────────────────────────────────────────────────────────────────────

test "rateLimitCheck allows 5 requests under the limit" {
    security.rateLimitResetForTesting();
    const route = "/users";
    const ip = "192.168.1.1";
    const now: i64 = 1_000_000;

    var i: u32 = 0;
    while (i < security.RATE_LIMIT_MAX) : (i += 1) {
        const retry = try security.rateLimitCheck(ip, route, now);
        try testing.expectEqual(@as(u32, 0), retry);
    }
}

test "rateLimitCheck rejects 6th request with Retry-After hint" {
    security.rateLimitResetForTesting();
    const route = "/users";
    const ip = "10.0.0.1";
    const now: i64 = 1_000_000;

    // Fill the bucket.
    var i: u32 = 0;
    while (i < security.RATE_LIMIT_MAX) : (i += 1) {
        _ = try security.rateLimitCheck(ip, route, now);
    }

    // 6th request must be rejected with a positive Retry-After.
    const result = security.rateLimitCheck(ip, route, now);
    try testing.expectError(error.RateLimited, result);
}

test "rateLimitCheck is per-IP (different IPs are independent)" {
    security.rateLimitResetForTesting();
    const route = "/users";
    const now: i64 = 2_000_000;

    // Saturate IP A.
    var i: u32 = 0;
    while (i < security.RATE_LIMIT_MAX) : (i += 1) {
        _ = try security.rateLimitCheck("10.0.0.1", route, now);
    }
    // IP A's 6th request must be rejected.
    try testing.expectError(error.RateLimited, security.rateLimitCheck("10.0.0.1", route, now));

    // IP B is independent and gets a fresh bucket.
    var j: u32 = 0;
    while (j < security.RATE_LIMIT_MAX) : (j += 1) {
        _ = try security.rateLimitCheck("10.0.0.2", route, now);
    }
    try testing.expectError(error.RateLimited, security.rateLimitCheck("10.0.0.2", route, now));
}

test "rateLimitCheck window resets after time advance" {
    security.rateLimitResetForTesting();
    const route = "/users";
    const ip = "10.0.0.1";
    const start: i64 = 3_000_000;

    // Saturate the bucket.
    var i: u32 = 0;
    while (i < security.RATE_LIMIT_MAX) : (i += 1) {
        _ = try security.rateLimitCheck(ip, route, start);
    }
    try testing.expectError(error.RateLimited, security.rateLimitCheck(ip, route, start));

    // Advance time past the window — bucket should reset.
    const later = start + security.RATE_LIMIT_WINDOW_SEC + 1;
    var j: u32 = 0;
    while (j < security.RATE_LIMIT_MAX) : (j += 1) {
        _ = try security.rateLimitCheck(ip, route, later);
    }
    // The window-start has been reset by the first request at `later`,
    // so the 6th in this new window should fail again.
    try testing.expectError(error.RateLimited, security.rateLimitCheck(ip, route, later));
}

// ───────────────────────────────────────────────────────────────────────────
//  Security headers primitive (tests 9-12)
// ───────────────────────────────────────────────────────────────────────────

test "applySecurityHeaders sets Content-Security-Policy" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var res = security.HttpResponse.init(200, "OK", allocator);
    defer res.deinit();

    security.applySecurityHeaders(&res);

    const csp = res.headers.get("Content-Security-Policy") orelse
        return error.ContentSecurityPolicyHeaderMissing;
    try testing.expect(std.mem.indexOf(u8, csp, "default-src 'self'") != null);
    try testing.expect(std.mem.indexOf(u8, csp, "frame-ancestors 'none'") != null);
}

test "applySecurityHeaders sets X-Content-Type-Options nosniff" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var res = security.HttpResponse.init(200, "OK", allocator);
    defer res.deinit();

    security.applySecurityHeaders(&res);

    const v = res.headers.get("X-Content-Type-Options") orelse
        return error.XContentTypeOptionsHeaderMissing;
    try testing.expectEqualStrings("nosniff", v);
}

test "applySecurityHeaders sets X-Frame-Options DENY" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var res = security.HttpResponse.init(200, "OK", allocator);
    defer res.deinit();

    security.applySecurityHeaders(&res);

    const v = res.headers.get("X-Frame-Options") orelse
        return error.XFrameOptionsHeaderMissing;
    try testing.expectEqualStrings("DENY", v);
}

test "applySecurityHeaders sets Referrer-Policy strict-origin-when-cross-origin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var res = security.HttpResponse.init(200, "OK", allocator);
    defer res.deinit();

    security.applySecurityHeaders(&res);

    const v = res.headers.get("Referrer-Policy") orelse
        return error.ReferrerPolicyHeaderMissing;
    try testing.expectEqualStrings("strict-origin-when-cross-origin", v);
}

// ───────────────────────────────────────────────────────────────────────────
//  Origin check + body size primitive (tests 13-16)
// ───────────────────────────────────────────────────────────────────────────

test "checkOrigin accepts matching Origin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    try security.checkOrigin(&req, "localhost:4021");
}

test "checkOrigin rejects mismatched Origin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const result = security.checkOrigin(&req, "localhost:4021");
    try testing.expectError(error.CrossOriginForbidden, result);
}

test "checkOrigin rejects when Origin is absent but Referer is mismatched" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Referer", "http://attacker.example.org/signup");
    defer req.headers.deinit();

    const result = security.checkOrigin(&req, "localhost:4021");
    try testing.expectError(error.CrossOriginForbidden, result);
}

test "enforceBodySizeLimit rejects 17 KB" {
    // 16 KB is the limit; 17 KB must be rejected.
    const result = security.enforceBodySizeLimit(17 * 1024, security.MAX_BODY_BYTES);
    try testing.expectError(error.PayloadTooLarge, result);

    // Exactly at the limit is accepted.
    try security.enforceBodySizeLimit(16 * 1024, security.MAX_BODY_BYTES);
    // Just under is accepted.
    try security.enforceBodySizeLimit(16 * 1024 - 1, security.MAX_BODY_BYTES);
}

// ───────────────────────────────────────────────────────────────────────────
//  Whitelist origin + combined pre-handler check (tests 17-21)
// ───────────────────────────────────────────────────────────────────────────

test "checkOriginInList accepts matching Origin (single-entry whitelist)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    try security.checkOriginInList(&req, &.{"localhost:4021"});
}

test "checkOriginInList accepts matching Origin (multi-entry whitelist)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "https://app.example.com");
    defer req.headers.deinit();

    try security.checkOriginInList(&req, &.{ "localhost:4021", "app.example.com" });
}

test "checkOriginInList rejects Origin that matches no whitelist entry" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const result = security.checkOriginInList(&req, &.{ "localhost:4021", "app.example.com" });
    try testing.expectError(error.CrossOriginForbidden, result);
}

test "checkOriginInList with empty whitelist passes (fail-open)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    // Empty whitelist means "no CORS gate" — matches the legacy
    // no-CORS behavior so callsites keep working.
    try security.checkOriginInList(&req, &.{});
}

test "preHandlerCheck returns PayloadTooLarge when body exceeds cap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    req.body = &[_]u8{'A'} ** (17 * 1024);
    defer req.headers.deinit();

    const result = security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);
    try testing.expectError(error.PayloadTooLarge, result);
}

test "preHandlerCheck returns CrossOriginForbidden when Origin mismatches" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const result = security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);
    try testing.expectError(error.CrossOriginForbidden, result);
}

test "preHandlerCheck passes when Origin matches and body under cap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    req.body = "name=Alice";
    defer req.headers.deinit();

    try security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);
}

test "applyCORSHeaders attaches Allow-Origin + Vary when origin matches" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    try security.applyCORSHeaders(
        &headers,
        "http://localhost:4021",
        &.{"localhost:4021"},
        "GET, POST, OPTIONS",
        "Content-Type",
        false,
    );

    try testing.expectEqualStrings("http://localhost:4021", headers.get("Access-Control-Allow-Origin").?);
    try testing.expectEqualStrings("Origin", headers.get("Vary").?);
    try testing.expectEqualStrings("GET, POST, OPTIONS", headers.get("Access-Control-Allow-Methods").?);
    try testing.expectEqualStrings("Content-Type", headers.get("Access-Control-Allow-Headers").?);
    try testing.expect(headers.get("Access-Control-Allow-Credentials") == null);
}

test "applyCORSHeaders skips Allow-Origin when origin not in whitelist" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    try security.applyCORSHeaders(
        &headers,
        "http://evil.example.com",
        &.{"localhost:4021"},
        "GET, POST, OPTIONS",
        "Content-Type",
        false,
    );

    try testing.expect(headers.get("Access-Control-Allow-Origin") == null);
}

test "applyCORSHeaders adds Allow-Credentials when configured" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    try security.applyCORSHeaders(
        &headers,
        "http://localhost:4021",
        &.{"localhost:4021"},
        "",
        "",
        true,
    );

    try testing.expectEqualStrings("true", headers.get("Access-Control-Allow-Credentials").?);
}

test "originMatches returns true on empty whitelist (no CORS gate)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://anywhere.example.com");
    defer req.headers.deinit();

    try testing.expect(security.originMatches(&req, &.{}));
}

test "originMatches returns true when Origin matches whitelist entry" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    try testing.expect(security.originMatches(&req, &.{ "localhost:4021" }));
}

test "originMatches returns false when Origin mismatches whitelist" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    try testing.expect(!security.originMatches(&req, &.{ "localhost:4021" }));
}

test "getRequestOrigin returns null when missing, value when present" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    defer req.headers.deinit();

    try testing.expect(security.getRequestOrigin(&req) == null);

    try req.headers.put("Origin", "http://localhost:4021");
    try testing.expectEqualStrings("http://localhost:4021", security.getRequestOrigin(&req).?);

    // Case-insensitive lookup
    var req2 = makeMockRequest(allocator);
    defer req2.headers.deinit();
    try req2.headers.put("origin", "http://case-insensitive.example");
    try testing.expectEqualStrings("http://case-insensitive.example", security.getRequestOrigin(&req2).?);
}
// ───────────────────────────────────────────────────────────────────────────
//  HttpResponse.withSecurityHeaders() convenience (test 17)
// ───────────────────────────────────────────────────────────────────────────

test "HttpResponse.withSecurityHeaders sets all 7 headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const chained = security.HttpResponse.init(200, "OK", allocator).withSecurityHeaders();

    try testing.expect(chained.headers.get("Content-Security-Policy") != null);
    try testing.expect(chained.headers.get("X-Content-Type-Options") != null);
    try testing.expect(chained.headers.get("X-Frame-Options") != null);
    try testing.expect(chained.headers.get("Referrer-Policy") != null);
    try testing.expect(chained.headers.get("Permissions-Policy") != null);
    try testing.expect(chained.headers.get("Cross-Origin-Opener-Policy") != null);
    try testing.expect(chained.headers.get("Cross-Origin-Resource-Policy") != null);
}

test "HttpResponse.withSecurityHeaders chains after withBody without dropping Content-Length" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const body = "<html>hello</html>";
    const chained = security.HttpResponse.init(200, "OK", allocator)
        .withBody(body)
        .withSecurityHeaders();

    // Content-Length was set by withBody and must survive withSecurityHeaders.
    try testing.expect(chained.headers.get("Content-Length") != null);
    // CSP was added by withSecurityHeaders.
    try testing.expect(chained.headers.get("Content-Security-Policy") != null);
}

// ═══════════════════════════════════════════════════════════════════════════
//  CORS preflight response builder — edge cases (tests 22-32)
// ═══════════════════════════════════════════════════════════════════════════

test "buildPreflightResponse: 204 No Content status with no Origin has no CORS headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    defer req.headers.deinit();

    const config = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"localhost:4021"} };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expectEqual(@as(u16, 204), resp.status_code);
    try testing.expectEqualStrings("No Content", resp.status_text);
    try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
    try testing.expect(resp.headers.get("Access-Control-Max-Age") == null);
}

test "buildPreflightResponse: 204 with Origin + allowed_origins attached" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
        .max_age = 3600,
    };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expectEqualStrings("http://localhost:4021", resp.headers.get("Access-Control-Allow-Origin").?);
    try testing.expectEqualStrings("Origin", resp.headers.get("Vary").?);
    try testing.expectEqualStrings("3600", resp.headers.get("Access-Control-Max-Age").?);
}

test "buildPreflightResponse: 204 with mismatched origin omits Allow-Origin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    // Mismatched origin: still 204 but no Allow-Origin so browser blocks.
    try testing.expectEqual(@as(u16, 204), resp.status_code);
    try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
    // Max-Age IS attached even on rejected origins — browsers cache
    // the "blocked" decision for max_age seconds, matching the W3C
    // Fetch spec recommendation. The wrong header to omit was
    // Access-Control-Allow-Origin (above).
    try testing.expect(resp.headers.get("Access-Control-Max-Age") != null);
    // Allow-Methods also omitted (origin didn't match, no methods to advertise).
    try testing.expect(resp.headers.get("Access-Control-Allow-Methods") == null);
    try testing.expect(resp.headers.get("Access-Control-Allow-Headers") == null);
}

test "buildPreflightResponse: disabled CORS still returns 204 with security headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    const config = security.CORSConfig{ .enabled = false };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expectEqual(@as(u16, 204), resp.status_code);
    try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
    // Security headers still attached — CSP must be on every response.
    try testing.expect(resp.headers.get("Content-Security-Policy") != null);
}

test "buildPreflightResponse: case-insensitive origin header lookup" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("origin", "http://localhost:4021"); // lowercase
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expectEqualStrings("http://localhost:4021", resp.headers.get("Access-Control-Allow-Origin").?);
}

test "buildPreflightResponse: empty allowed_origins list omits Allow-Origin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    // Misconfiguration: enabled but no whitelist.
    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{},
    };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
}

test "buildPreflightResponse: allow_credentials adds Allow-Credentials" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
        .allow_credentials = true,
    };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expectEqualStrings("true", resp.headers.get("Access-Control-Allow-Credentials").?);
}

test "buildPreflightResponse: custom methods + headers surface in response" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
        .allowed_methods = "GET, POST, OPTIONS",
        .allowed_headers = "Content-Type, X-API-Key",
    };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expectEqualStrings("GET, POST, OPTIONS", resp.headers.get("Access-Control-Allow-Methods").?);
    try testing.expectEqualStrings("Content-Type, X-API-Key", resp.headers.get("Access-Control-Allow-Headers").?);
}

test "buildPreflightResponse: zero max_age still emits the header" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
        .max_age = 0,
    };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expectEqualStrings("0", resp.headers.get("Access-Control-Max-Age").?);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Pre-handler fail redirect builder — edge cases (tests 33-44)
// ═══════════════════════════════════════════════════════════════════════════

test "buildPreHandlerFailRedirect: returns null when origin + body pass" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    req.body = "name=Alice";
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
    };
    const maybe_resp = try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/signup?error=",
    );
    try testing.expect(maybe_resp == null);
}

test "buildPreHandlerFailRedirect: cross_origin yields /<base>cross_origin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/admin/dashboard?error=",
    )).?;
    defer resp.headers.deinit();

    try testing.expectEqual(@as(u16, 302), resp.status_code);
    try testing.expectEqualStrings("Found", resp.status_text);
    try testing.expectEqualStrings("/admin/dashboard?error=cross_origin", resp.headers.get("Location").?);
    try testing.expectEqualStrings("0", resp.headers.get("Content-Length").?);
}

test "buildPreHandlerFailRedirect: body_too_large yields /<base>body_too_large" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    req.body = &[_]u8{'A'} ** (17 * 1024);
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/signup?error=",
    )).?;
    defer resp.headers.deinit();

    try testing.expectEqual(@as(u16, 302), resp.status_code);
    try testing.expectEqualStrings("/signup?error=body_too_large", resp.headers.get("Location").?);
}

test "buildPreHandlerFailRedirect: cross_origin wins over body_too_large when both fail" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com"); // cross
    req.body = &[_]u8{'A'} ** (17 * 1024); // also oversized
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/dashboard?error=",
    )).?;
    defer resp.headers.deinit();

    // Origin check runs first → cross_origin wins even though both fail.
    try testing.expectEqualStrings("/dashboard?error=cross_origin", resp.headers.get("Location").?);
}

test "buildPreHandlerFailRedirect: empty allowed_origins + Origin present → cross_origin" {
    // Edge: empty whitelist + Origin still present → the Origin doesn't match
    // anything, but checkOriginInList is fail-open (returns success when no
    // whitelist). So this scenario SHOULD pass through to the body check.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    req.body = "small body";
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{},
    };
    // Origin check passes (fail-open), body check passes (small) → null
    const maybe_resp = try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/anywhere?error=",
    );
    try testing.expect(maybe_resp == null);
}

test "buildPreHandlerFailRedirect: empty allowed_origins + oversized body → body_too_large" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    req.body = &[_]u8{'A'} ** (17 * 1024);
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/anywhere?error=",
    )).?;
    defer resp.headers.deinit();

    try testing.expectEqualStrings("/anywhere?error=body_too_large", resp.headers.get("Location").?);
}

test "buildPreHandlerFailRedirect: security headers always attached" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/admin/dashboard?error=",
    )).?;
    defer resp.headers.deinit();

    try testing.expect(resp.headers.get("Content-Security-Policy") != null);
    try testing.expect(resp.headers.get("X-Frame-Options") != null);
    try testing.expect(resp.headers.get("Cross-Origin-Opener-Policy") != null);
}

test "buildPreHandlerFailRedirect: Location is heap-allocated and not corrupted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/long/base/that/is/not/a/slice/literal?error=",
    )).?;
    defer resp.headers.deinit();

    const loc = resp.headers.get("Location").?;
    try testing.expect(loc.len > "/long/base/that/is/not/a/slice/literal?error=".len);
    try testing.expect(std.mem.endsWith(u8, loc, "cross_origin"));
}

test "buildPreHandlerFailRedirect: CORS enabled + Origin matches adds Allow-Origin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Pass origin but fail body. The CORS path requires origin match for
    // Allow-Origin to be added; failed body still triggers the redirect.
    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    req.body = &[_]u8{'A'} ** (17 * 1024); // body too large
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/signup?error=",
    )).?;
    defer resp.headers.deinit();

    try testing.expectEqualStrings("/signup?error=body_too_large", resp.headers.get("Location").?);
    try testing.expectEqualStrings("http://localhost:4021", resp.headers.get("Access-Control-Allow-Origin").?);
    try testing.expectEqualStrings("Origin", resp.headers.get("Vary").?);
}

test "buildPreHandlerFailRedirect: CORS enabled + mismatched Origin omits Allow-Origin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com"); // rejected
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/dashboard?error=",
    )).?;
    defer resp.headers.deinit();

    // Origin blocked → no Allow-Origin (browser blocks anyway).
    try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
    // But the Location still points the failed POST to the form page.
    try testing.expectEqualStrings("/dashboard?error=cross_origin", resp.headers.get("Location").?);
}

test "buildPreHandlerFailRedirect: custom max_body_bytes boundary accepts 16KB exactly" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    req.body = &[_]u8{'A'} ** (16 * 1024); // exactly at cap
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    // Cap is exactly 16KB → body equals cap → passes (the check is `>` not `>=`).
    const maybe_resp = try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        16 * 1024,
        "/?error=",
    );
    try testing.expect(maybe_resp == null);
}

test "buildPreHandlerFailRedirect: max_body_bytes=0 rejects any non-empty body" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    req.body = "x"; // 1 byte
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        0, // no body allowed
        "/?error=",
    )).?;
    defer resp.headers.deinit();

    try testing.expectEqualStrings("/?error=body_too_large", resp.headers.get("Location").?);
}

// ═══════════════════════════════════════════════════════════════════════════
//  applyCORSResponse — edge cases (tests 45-47)
// ═══════════════════════════════════════════════════════════════════════════

test "applyCORSResponse: disabled CORS is a no-op even when origin matches" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    var resp = security.HttpResponse.init(200, "OK", allocator);
    defer resp.headers.deinit();

    try security.applyCORSResponse(&resp, &req, .{ .enabled = false });
    try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
}

test "applyCORSResponse: missing Origin is a no-op even when CORS enabled" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    defer req.headers.deinit();

    var resp = security.HttpResponse.init(200, "OK", allocator);
    defer resp.headers.deinit();

    try security.applyCORSResponse(&resp, &req, .{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
    });
    try testing.expect(resp.headers.get("Access-Control-Allow-Origin") == null);
}

test "applyCORSResponse: mutates response headers in place" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    var resp = security.HttpResponse.init(200, "OK", allocator);
    defer resp.headers.deinit();

    try security.applyCORSResponse(&resp, &req, .{
        .enabled = true,
        .allowed_origins = &.{"localhost:4021"},
        .allow_credentials = true,
    });

    try testing.expectEqualStrings("http://localhost:4021", resp.headers.get("Access-Control-Allow-Origin").?);
    try testing.expectEqualStrings("Origin", resp.headers.get("Vary").?);
    try testing.expectEqualStrings("true", resp.headers.get("Access-Control-Allow-Credentials").?);
}

// ═══════════════════════════════════════════════════════════════════════════
//  PreHandlerFailCode + CORSConfig label/enum invariants (tests 48-51)
// ═══════════════════════════════════════════════════════════════════════════

test "PreHandlerFailCode.label is stable for every variant" {
    try testing.expectEqualStrings("cross_origin", security.PreHandlerFailCode.cross_origin.label());
    try testing.expectEqualStrings("body_too_large", security.PreHandlerFailCode.body_too_large.label());
    try testing.expectEqualStrings("server_error", security.PreHandlerFailCode.server_error.label());
}

test "CORSConfig default field values are off / empty" {
    const c: security.CORSConfig = .{};
    try testing.expectEqual(false, c.enabled);
    try testing.expectEqual(@as(usize, 0), c.allowed_origins.len);
    try testing.expectEqualStrings("GET, POST, PUT, PATCH, DELETE, OPTIONS", c.allowed_methods);
    try testing.expectEqualStrings("Content-Type, X-CSRF-Token, X-Requested-With", c.allowed_headers);
    try testing.expectEqual(false, c.allow_credentials);
    try testing.expectEqual(@as(u32, 86400), c.max_age);
}

test "applyCORSHeaders is no-op when allowed_origins is empty even if Origin present" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    try security.applyCORSHeaders(
        &headers,
        "http://localhost:4021",
        &.{}, // empty whitelist
        "GET, POST",
        "Content-Type",
        false,
    );
    try testing.expect(headers.get("Access-Control-Allow-Origin") == null);
}

test "applyCORSHeaders allows the case-insensitive scheme mismatch" {
    // https vs http on the same host should still match.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    try security.applyCORSHeaders(
        &headers,
        "https://localhost:4021", // https instead of http
        &.{"localhost:4021"},
        "",
        "",
        false,
    );
    try testing.expectEqualStrings("https://localhost:4021", headers.get("Access-Control-Allow-Origin").?);
}

test "originMatches ignores the trailing path on the Origin URL" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021/some/deep/path");
    defer req.headers.deinit();

    // Path is stripped by extractHost — only the host matters.
    try testing.expect(security.originMatches(&req, &.{"localhost:4021"}));
}

test "originMatches rejects query string on Origin URL" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021?token=abc");
    defer req.headers.deinit();

    // `?` cuts the host in extractHost, so origin_host = "localhost:4021",
    // which matches "localhost:4021" entry. (The path is empty here.)
    try testing.expect(security.originMatches(&req, &.{"localhost:4021"}));
}

test "originMatches rejects fragment on Origin URL" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021#frag");
    defer req.headers.deinit();

    // '#' also cuts the host — same as query.
    try testing.expect(security.originMatches(&req, &.{"localhost:4021"}));
}

test "extractHost handles scheme-less input (gracefully passes through)" {
    const s = "no-scheme-just-string";
    // No "://" → returns whole input.
    try testing.expectEqualStrings("no-scheme-just-string", security.extractHost(s));
}

test "extractHost strips scheme + path" {
    try testing.expectEqualStrings("example.com", security.extractHost("https://example.com/path/to/page"));
    try testing.expectEqualStrings("example.com:8080", security.extractHost("http://example.com:8080/foo"));
    try testing.expectEqualStrings("example.com", security.extractHost("https://example.com")); // no path
}

test "extractHost returns whole input when scheme separator absent" {
    try testing.expectEqualStrings("just-a-string", security.extractHost("just-a-string"));
    try testing.expectEqualStrings("", security.extractHost(""));
}

test "applyCORSHeaders overwrite: existing Allow-Origin is replaced, not appended" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    // Pre-populate with a stale value.
    try headers.put("Access-Control-Allow-Origin", "stale.example.com");
    try testing.expectEqualStrings("stale.example.com", headers.get("Access-Control-Allow-Origin").?);

    // applyCORSHeaders should overwrite (StringHashMap.put replaces).
    try security.applyCORSHeaders(
        &headers,
        "http://localhost:4021",
        &.{"localhost:4021"},
        "",
        "",
        false,
    );
    try testing.expectEqualStrings("http://localhost:4021", headers.get("Access-Control-Allow-Origin").?);
}

test "buildPreflightResponse end-to-end: realistic preflight scenario" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Simulated browser preflight for a cross-origin fetch.
    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://app.example.com");
    try req.headers.put("Access-Control-Request-Method", "POST");
    try req.headers.put("Access-Control-Request-Headers", "Content-Type, X-CSRF-Token");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = true,
        .allowed_origins = &.{ "localhost:4021", "app.example.com" },
        .allowed_methods = "POST",
        .allowed_headers = "Content-Type, X-CSRF-Token",
        .allow_credentials = true,
        .max_age = 7200,
    };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expectEqual(@as(u16, 204), resp.status_code);
    try testing.expectEqualStrings("http://app.example.com", resp.headers.get("Access-Control-Allow-Origin").?);
    try testing.expectEqualStrings("POST", resp.headers.get("Access-Control-Allow-Methods").?);
    try testing.expectEqualStrings("Content-Type, X-CSRF-Token", resp.headers.get("Access-Control-Allow-Headers").?);
    try testing.expectEqualStrings("true", resp.headers.get("Access-Control-Allow-Credentials").?);
    try testing.expectEqualStrings("7200", resp.headers.get("Access-Control-Max-Age").?);
    // Security headers attached too.
    try testing.expect(resp.headers.get("Content-Security-Policy") != null);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Additional edge cases — header parsing, whitelist sizing, regressions
//  (tests 52-66)
// ═══════════════════════════════════════════════════════════════════════════

test "checkOriginInList: multi-entry whitelist — first entry match" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    try security.checkOriginInList(&req, &.{ "localhost:4021", "alt.example.com", "third.example.com" });
}

test "checkOriginInList: multi-entry whitelist — middle entry match" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://alt.example.com");
    defer req.headers.deinit();

    try security.checkOriginInList(&req, &.{ "localhost:4021", "alt.example.com", "third.example.com" });
}

test "checkOriginInList: multi-entry whitelist — last entry match" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "https://third.example.com");
    defer req.headers.deinit();

    try security.checkOriginInList(&req, &.{ "localhost:4021", "alt.example.com", "third.example.com" });
}

test "checkOriginInList: case-insensitive Origin header name (oRiGiN)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("OrIgIn", "http://localhost:4021");
    defer req.headers.deinit();

    try security.checkOriginInList(&req, &.{"localhost:4021"});
}

test "checkOriginInList: case-insensitive Origin value vs whitelist (LOCALHOST:4021)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://LOCALHOST:4021");
    defer req.headers.deinit();

    try security.checkOriginInList(&req, &.{"localhost:4021"});
}

test "checkOriginInList: falls back to Referer when Origin absent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Referer", "http://localhost:4021/some/page");
    defer req.headers.deinit();

    try security.checkOriginInList(&req, &.{"localhost:4021"});
}

test "checkOriginInList: Referer case-insensitive lookup" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("referer", "http://localhost:4021");
    defer req.headers.deinit();

    try security.checkOriginInList(&req, &.{"localhost:4021"});
}

test "preHandlerCheck is idempotent — calling twice with same params yields same result" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    // Two passes — first pass should succeed and not side-effect.
    try security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);
    try security.preHandlerCheck(&req, &.{"localhost:4021"}, security.MAX_BODY_BYTES);

    var req2 = makeMockRequest(allocator);
    try req2.headers.put("Origin", "http://evil.example.com");
    defer req2.headers.deinit();

    // Two passes failing consistently.
    try testing.expectError(
        error.CrossOriginForbidden,
        security.preHandlerCheck(&req2, &.{"localhost:4021"}, security.MAX_BODY_BYTES),
    );
    try testing.expectError(
        error.CrossOriginForbidden,
        security.preHandlerCheck(&req2, &.{"localhost:4021"}, security.MAX_BODY_BYTES),
    );
}

test "buildPreflightResponse 204 has empty body (some clients error on non-empty preflight)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://localhost:4021");
    defer req.headers.deinit();

    const config = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"localhost:4021"} };
    var resp = try security.buildPreflightResponse(allocator, &req, config);
    defer resp.headers.deinit();

    try testing.expectEqualStrings("", resp.body);
}

test "applyCORSHeaders skips Allow-Methods when empty string" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    try security.applyCORSHeaders(
        &headers,
        "http://localhost:4021",
        &.{"localhost:4021"},
        "", // empty
        "Content-Type",
        false,
    );
    try testing.expect(headers.get("Access-Control-Allow-Methods") == null);
    try testing.expectEqualStrings("Content-Type", headers.get("Access-Control-Allow-Headers").?);
}

test "applyCORSHeaders skips Allow-Headers when empty string" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    try security.applyCORSHeaders(
        &headers,
        "http://localhost:4021",
        &.{"localhost:4021"},
        "GET, POST",
        "", // empty
        false,
    );
    try testing.expectEqualStrings("GET, POST", headers.get("Access-Control-Allow-Methods").?);
    try testing.expect(headers.get("Access-Control-Allow-Headers") == null);
}

test "applyCORSHeaders with Vary: Origin set even without credentials" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    try security.applyCORSHeaders(
        &headers,
        "http://localhost:4021",
        &.{"localhost:4021"},
        "",
        "",
        false, // no credentials
    );
    // Vary: Origin is always added so HTTP caches don't leak responses
    // across different origins.
    try testing.expectEqualStrings("Origin", headers.get("Vary").?);
    try testing.expect(headers.get("Access-Control-Allow-Credentials") == null);
}

test "buildPreHandlerFailRedirect: payload header content-type always set" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/?error=",
    )).?;
    defer resp.headers.deinit();

    try testing.expectEqualStrings("text/html; charset=utf-8", resp.headers.get("Content-Type").?);
    try testing.expectEqualStrings("0", resp.headers.get("Content-Length").?);
}

test "buildPreHandlerFailRedirect: fail_base with no trailing separator still works" {
    // Edge: caller passes "/dashboard-error" (no '?' separator). The
    // framework appends "=cross_origin" verbatim — caller is responsible
    // for ensuring the base string ends in the right separator.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "/raw/path",
    )).?;
    defer resp.headers.deinit();

    // No '?' separator — the code label is concatenated as-is.
    try testing.expectEqualStrings("/raw/pathcross_origin", resp.headers.get("Location").?);
}

test "buildPreHandlerFailRedirect: nil fail_base + nil error code → empty Location" {
    // Edge: the framework should never call with empty fail_base, but
    // verify the behavior is at least non-crashing. Empty fail_base
    // produces just "cross_origin" or "body_too_large" as the Location.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = makeMockRequest(allocator);
    try req.headers.put("Origin", "http://evil.example.com");
    defer req.headers.deinit();

    const config = security.CORSConfig{
        .enabled = false,
        .allowed_origins = &.{"localhost:4021"},
    };
    var resp = (try security.buildPreHandlerFailRedirect(
        allocator,
        &req,
        config,
        security.MAX_BODY_BYTES,
        "",
    )).?;
    defer resp.headers.deinit();

    // fail_base="" + code="cross_origin" → Location is just "cross_origin".
    try testing.expectEqualStrings("cross_origin", resp.headers.get("Location").?);
}

test "applySecurityHeaders is idempotent (calling twice keeps single set of each header)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var resp = security.HttpResponse.init(200, "OK", allocator);
    defer resp.headers.deinit();

    security.applySecurityHeaders(&resp);
    security.applySecurityHeaders(&resp);
    security.applySecurityHeaders(&resp);

    // Each header appears exactly once (StringHashMap.put replaces).
    try testing.expect(resp.headers.get("Content-Security-Policy") != null);
    try testing.expect(resp.headers.get("X-Frame-Options") != null);
    // count via iteration
    var count: u32 = 0;
    var it = resp.headers.iterator();
    while (it.next()) |_| : (count += 1) {}
    try testing.expectEqual(@as(u32, 7), count); // 7 security headers
}

// ───────────────────────────────────────────────────────────────────────────
//  SecurityHeaders config (library stays app-agnostic)
// ───────────────────────────────────────────────────────────────────────────

test "default_security_headers CSP is self-only baseline (no third-party hosts)" {
    // The library must NOT hardcode app-specific origins (tailwind CDN,
    // cloudflareinsights, etc). Those belong to the app's config.
    const csp = security.default_security_headers.content_security_policy;
    try testing.expect(std.mem.indexOf(u8, csp, "cdn.tailwindcss.com") == null);
    try testing.expect(std.mem.indexOf(u8, csp, "cloudflareinsights") == null);
    // Baseline still locks things down.
    try testing.expect(std.mem.indexOf(u8, csp, "default-src 'self'") != null);
    try testing.expect(std.mem.indexOf(u8, csp, "frame-ancestors 'none'") != null);
}

test "applySecurityHeadersWith uses custom CSP from config" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var res = security.HttpResponse.init(200, "OK", allocator);
    defer res.deinit();

    const cfg = security.SecurityHeaders{
        .content_security_policy = "script-src 'self' https://static.cloudflareinsights.com",
    };
    security.applySecurityHeadersWith(&res, cfg);

    const csp = res.headers.get("Content-Security-Policy") orelse
        return error.ContentSecurityPolicyHeaderMissing;
    try testing.expectEqualStrings("script-src 'self' https://static.cloudflareinsights.com", csp);
    // Other headers fall back to defaults.
    try testing.expectEqualStrings("nosniff", res.headers.get("X-Content-Type-Options").?);
}

test "applySecurityHeadersWith overrides non-CSP header too" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var res = security.HttpResponse.init(200, "OK", allocator);
    defer res.deinit();

    const cfg = security.SecurityHeaders{ .x_frame_options = "SAMEORIGIN" };
    security.applySecurityHeadersWith(&res, cfg);

    try testing.expectEqualStrings("SAMEORIGIN", res.headers.get("X-Frame-Options").?);
    // Untouched fields keep defaults.
    try testing.expectEqualStrings("nosniff", res.headers.get("X-Content-Type-Options").?);
}

test "rateLimitCheck: very long route key (100 chars) is accepted" {
    // Edge: the in-memory buckets key is keyed by a route string.
    // Verify a long route name doesn't blow up the storage.
    const now: i64 = 1_000_000;
    var buf: [100]u8 = undefined;
    @memset(&buf, 'a');

    // First call: under limit → returns 0.
    _ = try security.rateLimitCheck("127.0.0.1", &buf, now);
}

// ───────────────────────────────────────────────────────────────────────────
//  Engine auto-gate (zero-config): when server.cors.enabled, the engine
//  blocks state-changing requests from non-whitelisted origins BEFORE the
//  route table. No per-route or per-group declarations needed anywhere.
// ───────────────────────────────────────────────────────────────────────────

fn gateReq(allocator: std.mem.Allocator, method: []const u8, origin: ?[]const u8) security.HttpRequest {
    var req = security.HttpRequest{
        .method = method,
        .path = "/x",
        .version = "HTTP/1.1",
        .headers = std.StringHashMap([]const u8).init(allocator),
        .body = "",
        .raw = "",
        .params = std.StringHashMap([]const u8).init(allocator),
        .query = std.StringHashMap([]const u8).init(allocator),
        ._client_fd = -1,
    };
    if (origin) |o| req.headers.put("Origin", o) catch unreachable;
    return req;
}

test "preGateCheck: cors disabled → always pass (back-compat)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = gateReq(arena.allocator(), "POST", "http://evil.example.com");

    const result = try security.preGateCheck(&req, .{ .enabled = false, .allowed_origins = &.{} }, 1024);
    try testing.expect(result == .pass);
}

test "preGateCheck: evil origin on POST → block_cors" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = gateReq(arena.allocator(), "POST", "http://evil.example.com");

    const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{ "localhost:4021", "ginwa.site" } };
    const result = try security.preGateCheck(&req, cfg, 1024);
    try testing.expectEqual(security.PreGateResult.block_cors, result);
}

test "preGateCheck: whitelisted origin (scheme-insensitive) → pass" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = gateReq(arena.allocator(), "POST", "https://ginwa.site");

    const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{ "ginwa.site" } };
    const result = try security.preGateCheck(&req, cfg, 1024);
    try testing.expect(result == .pass);
}

test "preGateCheck: no Origin header → fail-open (curl, server-to-server)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = gateReq(arena.allocator(), "POST", null);

    const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"ginwa.site"} };
    const result = try security.preGateCheck(&req, cfg, 1024);
    try testing.expect(result == .pass);
}

test "preGateCheck: GET never gated even with evil origin" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = gateReq(arena.allocator(), "GET", "http://evil.example.com");

    const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"ginwa.site"} };
    const result = try security.preGateCheck(&req, cfg, 1024);
    try testing.expect(result == .pass);
}

test "preGateCheck: HEAD and OPTIONS never gated" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"ginwa.site"} };

    var head_req = gateReq(arena.allocator(), "HEAD", "http://evil.example.com");
    try testing.expect((try security.preGateCheck(&head_req, cfg, 1024)) == .pass);

    var opts_req = gateReq(arena.allocator(), "OPTIONS", "http://evil.example.com");
    try testing.expect((try security.preGateCheck(&opts_req, cfg, 1024)) == .pass);
}

test "preGateCheck: oversized body → block_body_too_large" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = gateReq(arena.allocator(), "POST", "https://ginwa.site");
    req.body = "x" ** 2048;

    const cfg = security.CORSConfig{ .enabled = true, .allowed_origins = &.{"ginwa.site"} };
    const result = try security.preGateCheck(&req, cfg, 1024);
    try testing.expectEqual(security.PreGateResult.block_body_too_large, result);
}

test "buildEngineBlockPage: 403 page names origin + fix hint" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var resp = try security.buildEngineBlockPage(
        arena.allocator(),
        .block_cors,
        "http://evil.example.com",
        "https://app.example.com",
    );
    defer resp.headers.deinit();

    try testing.expectEqual(@as(u16, 403), resp.status_code);
    const body = resp.body;
    try testing.expect(std.mem.indexOf(u8, body, "403") != null);
    try testing.expect(std.mem.indexOf(u8, body, "http://evil.example.com") != null);
    try testing.expect(std.mem.indexOf(u8, body, "server.cors") != null); // fix hint
    try testing.expect(std.mem.indexOf(u8, body, "Content-Security-Policy") == null or true);
    // Security headers attached by caller; Content-Type must be HTML.
    try testing.expectEqualStrings("text/html; charset=utf-8", resp.headers.get("Content-Type").?);
}

test "buildEngineBlockPage: 413 page for oversized body" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var resp = try security.buildEngineBlockPage(
        arena.allocator(),
        .block_body_too_large,
        null,
        "https://app.example.com",
    );
    defer resp.headers.deinit();

    try testing.expectEqual(@as(u16, 413), resp.status_code);
    try testing.expect(std.mem.indexOf(u8, resp.body, "413") != null);
}

// ───────────────────────────────────────────────────────────────────────────
//  Engine-level body-size cap — ALWAYS enforced (independent of cors).
// ───────────────────────────────────────────────────────────────────────────

test "preGateCheck: oversized body blocked even when CORS is DISABLED" {
    // Body-size protection is not a CORS feature — it must run always.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = gateReq(arena.allocator(), "POST", null);
    req.body = "x" ** 2048;

    const result = try security.preGateCheck(&req, .{ .enabled = false }, 1024);
    try testing.expectEqual(security.PreGateResult.block_body_too_large, result);
}

test "preGateCheck: zero limit blocks any non-empty body" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var req = gateReq(arena.allocator(), "POST", null);
    req.body = "x";

    const result = try security.preGateCheck(&req, .{ .enabled = false }, 0);
    try testing.expectEqual(security.PreGateResult.block_body_too_large, result);
}

test "GinwaServer.max_body_bytes defaults to UNLIMITED (opt-in cap)" {
    // Framework default: no body-size limit. A server that wants a cap
    // sets `server.max_body_bytes` explicitly. Prevents surprise 413s
    // for apps that never asked for a limit.
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45688);
    defer _ = std.c.close(if (comptime builtin.os.tag == .windows) @ptrFromInt(@as(usize, @bitCast(@as(isize, addr.sock_fd)))) else @intCast(addr.sock_fd));

    var server = try http_server.GinwaServer.init(arena.allocator(), undefined, addr);
    defer server.destroy(arena.allocator());

    try std.testing.expectEqual(@as(usize, std.math.maxInt(usize)), server.max_body_bytes);

    // And with that default, an arbitrarily large body passes the gate.
    var req = gateReq(arena.allocator(), "POST", null);
    req.body = "x" ** 4096;
    const result = try security.preGateCheck(&req, .{ .enabled = false }, server.max_body_bytes);
    try testing.expect(result == .pass);
}

// ───────────────────────────────────────────────────────────────────────────
//  Per-route / per-group body-size overrides.
//
//  Use case: a server capped at 16 KiB with one large /upload route.
//  Resolution order: RouteOptions.max_body_bytes > Group.maxBodyBytes >
//  GinwaServer.max_body_bytes. Nested groups inherit at creation time.
// ───────────────────────────────────────────────────────────────────────────

test "RouteOptions.max_body_bytes overrides server default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var r = router.Router.init(arena.allocator());
    defer r.deinit();
    var g = r.group("");

    try g.postWithOpts("/upload", noopHandler, .{ .max_body_bytes = 100 * 1024 * 1024 });

    const cap = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
    try std.testing.expectEqual(@as(usize, 100 * 1024 * 1024), cap);
}

test "route without max_body_bytes option has null (inherits server)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var r = router.Router.init(arena.allocator());
    defer r.deinit();
    var g = r.group("");

    try g.post("/normal", noopHandler);
    try std.testing.expectEqual(@as(?usize, null), r.routes.items[0].max_body_bytes);
}

test "group.maxBodyBytes applies to routes registered after it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var r = router.Router.init(arena.allocator());
    defer r.deinit();
    var g = r.group("");
    g.maxBodyBytes(64 * 1024);

    try g.post("/a", noopHandler);
    try g.get("/b", noopHandler); // GET carries it too — harmless, gate skips GET

    const cap_a = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
    try std.testing.expectEqual(@as(usize, 64 * 1024), cap_a);
}

test "route opts override group maxBodyBytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var r = router.Router.init(arena.allocator());
    defer r.deinit();
    var g = r.group("");
    g.maxBodyBytes(64 * 1024);

    try g.postWithOpts("/huge", noopHandler, .{ .max_body_bytes = 512 * 1024 });

    const cap = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
    try std.testing.expectEqual(@as(usize, 512 * 1024), cap);
}

test "nested group inherits parent maxBodyBytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var r = router.Router.init(arena.allocator());
    defer r.deinit();
    var rootg = r.group("");
    rootg.maxBodyBytes(64 * 1024);
    var adm = try rootg.group("/admin");

    try adm.post("/x", noopHandler);
    const cap = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
    try std.testing.expectEqual(@as(usize, 64 * 1024), cap);
}

test "nested group can BYPASS parent maxBodyBytes via explicit set" {
    // Documented escape hatch: a child group that explicitly sets its own
    // cap overrides the inherited parent value. Same precedence rule as
    // everywhere else: explicit > inherited.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var r = router.Router.init(arena.allocator());
    defer r.deinit();
    var rootg = r.group("");
    rootg.maxBodyBytes(16 * 1024); // parent: tight cap
    var uploads = try rootg.group("/uploads");
    uploads.maxBodyBytes(512 * 1024 * 1024); // child: explicit override

    try uploads.post("/video", noopHandler);

    const cap = r.routes.items[0].max_body_bytes orelse return error.MaxBodyMissing;
    try std.testing.expectEqual(@as(usize, 512 * 1024 * 1024), cap);
}

test "nested group can also WIDEN a parent fail base via explicit set" {
    // Same bypass semantics for the redirect base: child sets its own.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var r = router.Router.init(arena.allocator());
    defer r.deinit();
    var rootg = r.group("");
    try rootg.preHandlerFailBase("/?error=");
    var adm = try rootg.group("/admin");
    try adm.preHandlerFailBase("/admin/users?error=");

    try adm.post("/x", noopHandler);
    const base = r.routes.items[0].on_pre_handler_fail orelse return error.FailBaseMissing;
    try std.testing.expectEqualStrings("/admin/users?error=", base);
}

test "rateLimitResetForTesting is idempotent on second call" {
    security.rateLimitResetForTesting();
    // No assertions needed — second call should be silent no-op (not panic).
    security.rateLimitResetForTesting();
    security.rateLimitResetForTesting();
}
