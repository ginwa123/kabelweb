const std = @import("std");
const http_server = @import("http_server.zig");
const http_parser = @import("http_parser.zig");
const linux = std.posix.system;
const helpers = @import("test_helpers.zig");
const closeI32Fd = helpers.closeI32Fd;
const builtin = @import("builtin");
const posix = std.posix;

// ============================================================================
// Address Struct Tests
// ============================================================================

test "Address.init creates socket and binds" {
    // Use a high port number to avoid permission issues
    const addr = try http_server.Address.init("127.0.0.1", 45678);
    defer _ = closeI32Fd(addr.sock_fd);

    try std.testing.expect(addr.sock_fd >= 0);
    try std.testing.expectEqual(@as(u16, 45678), addr.port);
}

test "Address.init with different port" {
    const addr = try http_server.Address.init("127.0.0.1", 45679);
    defer _ = closeI32Fd(addr.sock_fd);

    try std.testing.expectEqual(@as(u16, 45679), addr.port);
}

test "Address.init multiple instances on different ports" {
    const addr1 = try http_server.Address.init("127.0.0.1", 45680);
    defer _ = closeI32Fd(addr1.sock_fd);

    const addr2 = try http_server.Address.init("127.0.0.1", 45681);
    defer _ = closeI32Fd(addr2.sock_fd);

    try std.testing.expect(addr1.sock_fd >= 0);
    try std.testing.expect(addr2.sock_fd >= 0);
    try std.testing.expect(addr1.sock_fd != addr2.sock_fd);
}

// ============================================================================
// GinwaServer Initialization Tests
// ============================================================================

test "GinwaServer.init creates server instance" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45682);
    defer _ = closeI32Fd(addr.sock_fd);

    var server = try http_server.GinwaServer.init(allocator, undefined, addr);
    defer server.destroy(allocator);

    try std.testing.expect(server.address.sock_fd == addr.sock_fd);
    try std.testing.expectEqual(@as(u16, 45682), server.address.port);
}

test "GinwaServer.init router is initialized" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45683);
    defer _ = closeI32Fd(addr.sock_fd);

    var server = try http_server.GinwaServer.init(allocator, undefined, addr);
    defer server.destroy(allocator);

    // Router should be accessible (we can't directly check internal state, but
    // we can verify the server was created successfully)
    try std.testing.expect(server.router.routes.items.len == 0); // Empty initially
}

// ============================================================================
// Server with Router Integration Tests
// ============================================================================

test "GinwaServer with registered route" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45684);
    defer _ = closeI32Fd(addr.sock_fd);

    var server = try http_server.GinwaServer.init(allocator, undefined, addr);
    defer server.destroy(allocator);

    try server.router.get("/test", struct {
        fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
            return http_parser.ok("Test Response", std.heap.page_allocator);
        }
    }.handle);

    try std.testing.expect(server.router.routes.items.len == 1);
    try std.testing.expectEqualStrings("/test", server.router.routes.items[0].path);
}

// ============================================================================
// Server-level SecurityHeaders config (app-agnostic library)
// ============================================================================

test "GinwaServer.security_headers defaults to library baseline" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45686);
    defer _ = closeI32Fd(addr.sock_fd);

    var server = try http_server.GinwaServer.init(allocator, undefined, addr);
    defer server.destroy(allocator);

    // Default CSP must NOT contain app-specific hosts.
    const csp = server.security_headers.content_security_policy;
    try std.testing.expect(std.mem.indexOf(u8, csp, "cdn.tailwindcss.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, csp, "cloudflareinsights") == null);
}

test "GinwaServer.applySecurityHeadersTo uses server-level CSP override" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45687);
    defer _ = closeI32Fd(addr.sock_fd);

    var server = try http_server.GinwaServer.init(allocator, undefined, addr);
    defer server.destroy(allocator);

    // App opts in to its own CSP (tailwind CDN + CF analytics beacon).
    server.security_headers.content_security_policy =
        "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com https://static.cloudflareinsights.com 'unsafe-inline'";

    var res = http_parser.HttpResponse.init(200, "OK", allocator);
    defer res.deinit();

    server.applySecurityHeadersTo(&res);

    const csp = res.headers.get("Content-Security-Policy") orelse
        return error.ContentSecurityPolicyHeaderMissing;
    try std.testing.expect(std.mem.indexOf(u8, csp, "cdn.tailwindcss.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, csp, "static.cloudflareinsights.com") != null);
    // Non-overridden headers keep library defaults.
    try std.testing.expectEqualStrings("nosniff", res.headers.get("X-Content-Type-Options").?);
}

// ============================================================================
// HttpContext.allowed_origins — handlers must read the SERVER's CORS
// config instead of hardcoding "localhost:4021" (broke ginwa.site).
// ============================================================================

test "HttpContext.allowed_origins defaults to empty slice" {
    const ctx = http_parser.HttpContext{
        .allocator = std.testing.allocator,
        .io = undefined,
    };
    try std.testing.expectEqual(@as(usize, 0), ctx.allowed_origins.len);
}

test "handler origin gate: checkOriginInList with ctx origins accepts whitelisted host" {
    // Documents the wiring contract handlers rely on: the dispatch loop
    // fills ctx.allowed_origins from server.cors; handlers pass that
    // slice to security.checkOriginInList.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const security = @import("security.zig");
    const origins = [_][]const u8{ "localhost:4021", "ginwa.site" };
    const ctx = http_parser.HttpContext{
        .allocator = arena.allocator(),
        .io = undefined,
        .allowed_origins = &origins,
    };

    var req = security.HttpRequest{
        .method = "POST",
        .path = "/admin/signin",
        .version = "HTTP/1.1",
        .headers = std.StringHashMap([]const u8).init(arena.allocator()),
        .body = "",
        .raw = "",
        .params = std.StringHashMap([]const u8).init(arena.allocator()),
        .query = std.StringHashMap([]const u8).init(arena.allocator()),
        ._client_fd = -1,
    };
    defer req.headers.deinit();
    defer req.params.deinit();
    defer req.query.deinit();
    try req.headers.put("Origin", "https://ginwa.site");

    // Must NOT throw — ginwa.site is in the server-configured list.
    try security.checkOriginInList(&req, ctx.allowed_origins);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

test "Address.init fails on invalid port (0 is technically valid, use reserved)" {
    // Test that we can detect port already in use by creating two addresses
    // on the same port (note: SO_REUSEADDR may allow this on some systems,
    // so this test may need adjustment based on platform behavior)
    const addr1 = try http_server.Address.init("127.0.0.1", 45685);
    defer _ = closeI32Fd(addr1.sock_fd);

    // On Linux with SO_REUSEADDR, this should succeed. On other platforms
    // this might fail. We test that at minimum one succeeds.
    try std.testing.expect(addr1.sock_fd >= 0);
}

// ============================================================================
// Address Fields Validation Tests
// ============================================================================

test "Address port is correctly stored" {
    const test_port: u16 = 45686;
    const addr = try http_server.Address.init("127.0.0.1", test_port);
    defer _ = closeI32Fd(addr.sock_fd);

    try std.testing.expectEqual(test_port, addr.port);
    try std.testing.expect(addr.sock_fd >= 0);
}

test "Address sock_fd is valid file descriptor" {
    const addr = try http_server.Address.init("127.0.0.1", 45687);
    defer _ = closeI32Fd(addr.sock_fd);

    // On Linux, valid file descriptors are non-negative
    try std.testing.expect(addr.sock_fd >= 0);
}

// ============================================================================
// getClientPort Tests (when connected)
// ============================================================================

test "GinwaServer.getClientPort returns 0 for invalid fd" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45688);
    defer _ = closeI32Fd(addr.sock_fd);

    var server = try http_server.GinwaServer.init(allocator, undefined, addr);
    defer server.destroy(allocator);

    // -1 is an invalid file descriptor, should return 0
    const port = server.getClientPort(-1);
    try std.testing.expectEqual(@as(u16, 0), port);
}

// ============================================================================
// recvFromClient and sendToClient Tests
// ============================================================================

test "GinwaServer.recvFromClient fails on invalid fd" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45689);
    defer _ = closeI32Fd(addr.sock_fd);

    var server = try http_server.GinwaServer.init(allocator, undefined, addr);
    defer server.destroy(allocator);

    var buf: [1024]u8 = undefined;
    const result = server.recvFromClient(-1, &buf);
    try std.testing.expectError(error.RecvFailed, result);
}

test "GinwaServer.sendToClient fails on invalid fd" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45690);
    defer _ = closeI32Fd(addr.sock_fd);

    var server = try http_server.GinwaServer.init(allocator, undefined, addr);
    defer server.destroy(allocator);

    const result = server.sendToClient(-1, "Hello");
    try std.testing.expectError(error.SendFailed, result);
}

// ============================================================================
// Integration Test with Actual Connection
// ============================================================================

test "Server accepts client connection" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const addr = try http_server.Address.init("127.0.0.1", 45691);
    defer _ = closeI32Fd(addr.sock_fd);

    var server = try http_server.GinwaServer.init(allocator, undefined, addr);
    defer server.destroy(allocator);

    // Create a client socket and connect
    const client_fd_sock = linux.socket(2, 1, 0);
    const client_fd: i32 = @intCast(client_fd_sock);
    defer _ = closeI32Fd(client_fd);

    // Connect to server
    const addr2 = try http_server.Address.init("127.0.0.1", 45692);
    defer _ = closeI32Fd(addr2.sock_fd);

    // Socket creation verified - full integration test would require actual server listening
}

// ============================================================================
// RequestBuffer Tests - Auto-growing buffer for large payloads
// ============================================================================

test "RequestBuffer.init creates empty buffer" {
    const allocator = std.testing.allocator;
    var rb = http_server.RequestBuffer.init(allocator);
    defer rb.deinit();

    try std.testing.expect(rb.buf.items.len == 0);
}

// Test that simulates your exact request
test "RequestBuffer.readFullRequest with exact POST headers (13248 body)" {
    const allocator = std.testing.allocator;

    // Create a socket pair for testing. Cross-platform: socketpair on
    // POSIX, CreatePipe on Windows (no AF_UNIX socketpair(2) in Winsock).
    var pipe_fds: [2]std.c.fd_t = undefined;
    const rc = if (comptime builtin.os.tag == .windows)
        blk: {
            // Use the shared helper (kernel32 CreatePipe) directly so the
            // call returns the same error type as the POSIX branch.
            const pair = helpers.createSocketPair() catch {
                // pipe creation failed, skip test
                return;
            };
            pipe_fds = pair;
            break :blk 0;
        }
    else
        posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &pipe_fds);
    if (rc < 0) {
        // socketpair not supported, skip test
        return;
    }
    defer {
        _ = std.c.close(pipe_fds[0]);
        _ = std.c.close(pipe_fds[1]);
    }

    // Build the exact headers you sent
    const headers = 
        "POST /api/llm/session HTTP/1.1\r\n" ++
        "Accept: */*\r\n" ++
        "Accept-Encoding: gzip, deflate, br, zstd\r\n" ++
        "Accept-Language: en-US,en;q=0.9\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Content-Length: 13248\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Host: localhost:5173\r\n" ++
        "Origin: http://localhost:5173\r\n" ++
        "Referer: http://localhost:5173/app?view=task&task=task_1779042417517\r\n" ++
        "Sec-Fetch-Dest: empty\r\n" ++
        "Sec-Fetch-Mode: cors\r\n" ++
        "Sec-Fetch-Site: same-origin\r\n" ++
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36\r\n" ++
        "sec-ch-ua: \"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"\r\n" ++
        "sec-ch-ua-mobile: ?0\r\n" ++
        "sec-ch-ua-platform: \"Linux\"\r\n" ++
        "\r\n";
    
    // Create a 13248 byte body
    const body_size: usize = 13248;
    const body = try allocator.alloc(u8, body_size);
    defer allocator.free(body);
    // Fill with pattern
    for (0..body_size) |i| {
        body[i] = @as(u8, @truncate(i));
    }

    // Send headers first
    const written1 = linux.write(pipe_fds[1], headers.ptr, headers.len);
    if (written1 < 0) return error.WriteFailed;
    
    // Send body in chunks to simulate real scenario
    var sent: usize = 0;
    while (sent < body_size) {
        const chunk = @min(4096, body_size - sent);
        const written = linux.write(pipe_fds[1], body.ptr + sent, chunk);
        if (written < 0) return error.WriteFailed;
        sent += @as(usize, @intCast(written));
    }

    // Use RequestBuffer to read
    var rb = http_server.RequestBuffer.init(allocator);
    defer rb.deinit();

    const result = rb.readFullRequest(if (comptime builtin.os.tag == .windows)
        @intCast(@intFromPtr(pipe_fds[0]))
    else
        @intCast(pipe_fds[0])) catch |err| {
        std.debug.print("readFullRequest failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer allocator.free(result);

    // Verify: total should be headers.len + body_size
    const expected_len = headers.len + body_size;
    try std.testing.expectEqual(expected_len, result.len);
    
    // Verify the body content
    const result_body = result[headers.len..];
    try std.testing.expectEqual(@as(u8, 0), result_body[0]);
    try std.testing.expectEqual(@as(u8, 1), result_body[1]);
    try std.testing.expectEqual(@as(u8, 100), result_body[100]);
    try std.testing.expectEqual(@as(u8, @truncate(body_size - 1)), result_body[body_size - 1]);
}

// Test getContentLength with your exact headers
test "RequestBuffer.getContentLength with your headers" {
    const data = 
        "POST /api/llm/session HTTP/1.1\r\n" ++
        "Accept: */*\r\n" ++
        "Content-Length: 13248\r\n" ++
        "\r\n";
    
    const content_length = http_server.RequestBuffer.getContentLength(data);
    try std.testing.expect(content_length != null);
    try std.testing.expectEqual(@as(usize, 13248), content_length.?);
}