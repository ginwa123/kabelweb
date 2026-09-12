//! Tests for the WebSocket HTTP upgrade handshake (RFC 6455 §4).
//!
//! These tests are written FIRST (TDD red phase). The handshake converts
//! an HTTP/1.1 request into a WebSocket connection by upgrading the protocol.
//!
//! Flow (RFC 6455 §4):
//!   1. Client sends HTTP/1.1 GET request with:
//!      - Upgrade: websocket
//!      - Connection: Upgrade
//!      - Sec-WebSocket-Key: <16-byte base64-encoded random>
//!      - Sec-WebSocket-Version: 13
//!   2. Server responds with:
//!      - HTTP/1.1 101 Switching Protocols
//!      - Upgrade: websocket
//!      - Connection: Upgrade
//!      - Sec-WebSocket-Accept: <base64(SHA1(key + MAGIC_GUID))>
//!
//! The Sec-WebSocket-Accept value is deterministic: it's the SHA-1 hash of
//! the concatenation of the client's key and the magic GUID
//! "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", then base64-encoded.

const std = @import("std");
const testing = std.testing;
const http_parser = @import("http_parser.zig");
const ws_handshake = @import("websocket_handshake.zig");

test "computeAcceptKey: RFC 6455 known-vector" {
    // RFC 6455 §1.3 example:
    //   Client key: "dGhlIHNhbXBsZSBub25jZQ=="
    //   Expected Accept: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    const accept = try ws_handshake.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    defer std.heap.page_allocator.free(accept);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "computeAcceptKey: alternating key produces deterministic output" {
    // Same input always produces same output (deterministic SHA-1).
    const a = try ws_handshake.computeAcceptKey("AAAAAAAAAAAAAAAAAAAAAA==");
    defer std.heap.page_allocator.free(a);
    const b = try ws_handshake.computeAcceptKey("AAAAAAAAAAAAAAAAAAAAAA==");
    defer std.heap.page_allocator.free(b);
    try testing.expectEqualStrings(a, b);
}

test "buildAcceptResponse: returns complete 101 response bytes" {
    const resp = try ws_handshake.buildAcceptResponse(
        testing.allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
    );
    defer testing.allocator.free(resp);

    // Must start with "HTTP/1.1 101" and end with the exact Accept value.
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 101 Switching Protocols\r\n"));
    try testing.expect(std.mem.indexOf(u8, resp, "Upgrade: websocket\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "Connection: Upgrade\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\n"));
}

test "isWebSocketRequest: matches when all required headers are present" {
    const raw =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    var req = try http_parser.parseRequest(raw, testing.allocator, undefined, -1);
    defer req.deinit(testing.allocator);

    try testing.expect(ws_handshake.isWebSocketRequest(&req));
}

test "isWebSocketRequest: rejects HTTP/1.0 request" {
    const raw =
        "GET /chat HTTP/1.0\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    var req = try http_parser.parseRequest(raw, testing.allocator, undefined, -1);
    defer req.deinit(testing.allocator);

    try testing.expect(!ws_handshake.isWebSocketRequest(&req));
}

test "isWebSocketRequest: rejects request missing Sec-WebSocket-Key" {
    const raw =
        "GET /chat HTTP/1.1\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    var req = try http_parser.parseRequest(raw, testing.allocator, undefined, -1);
    defer req.deinit(testing.allocator);

    try testing.expect(!ws_handshake.isWebSocketRequest(&req));
}

test "isWebSocketRequest: rejects request with wrong version" {
    const raw =
        "GET /chat HTTP/1.1\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 8\r\n" ++ // old draft version
        "\r\n";

    var req = try http_parser.parseRequest(raw, testing.allocator, undefined, -1);
    defer req.deinit(testing.allocator);

    try testing.expect(!ws_handshake.isWebSocketRequest(&req));
}

test "isWebSocketRequest: rejects non-GET method (e.g. POST)" {
    const raw =
        "POST /chat HTTP/1.1\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    var req = try http_parser.parseRequest(raw, testing.allocator, undefined, -1);
    defer req.deinit(testing.allocator);

    try testing.expect(!ws_handshake.isWebSocketRequest(&req));
}

test "extractWebSocketKey: reads case-insensitive header value" {
    // Headers might be sent as "sec-websocket-key" (lowercase) by some clients.
    const raw =
        "GET /chat HTTP/1.1\r\n" ++
        "sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "\r\n";

    var req = try http_parser.parseRequest(raw, testing.allocator, undefined, -1);
    defer req.deinit(testing.allocator);

    const key = try ws_handshake.extractWebSocketKey(&req);
    try testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", key);
}

test "extractWebSocketKey: returns MissingKey error when absent" {
    const raw = "GET /chat HTTP/1.1\r\n\r\n";

    var req = try http_parser.parseRequest(raw, testing.allocator, undefined, -1);
    defer req.deinit(testing.allocator);

    try testing.expectError(error.MissingKey, ws_handshake.extractWebSocketKey(&req));
}
