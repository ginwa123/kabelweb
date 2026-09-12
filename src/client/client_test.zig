const std = @import("std");
const testing = std.testing;
const custom_http_client = @import("root.zig");

test "Method.parse handles every supported verb (case-sensitive)" {
    try testing.expectEqual(@as(custom_http_client.Method, .GET), custom_http_client.Method.parse("GET").?);
    try testing.expectEqual(@as(custom_http_client.Method, .POST), custom_http_client.Method.parse("POST").?);
    try testing.expectEqual(@as(custom_http_client.Method, .PUT), custom_http_client.Method.parse("PUT").?);
    try testing.expectEqual(@as(custom_http_client.Method, .PATCH), custom_http_client.Method.parse("PATCH").?);
    try testing.expectEqual(@as(custom_http_client.Method, .DELETE), custom_http_client.Method.parse("DELETE").?);
    try testing.expectEqual(@as(?custom_http_client.Method, null), custom_http_client.Method.parse("get")); // case-sensitive
    try testing.expectEqual(@as(?custom_http_client.Method, null), custom_http_client.Method.parse("BREW"));
    try testing.expectEqual(@as(?custom_http_client.Method, null), custom_http_client.Method.parse(""));
}

test "Method.asString round-trips parse" {
    const methods = [_]custom_http_client.Method{ .GET, .POST, .PUT, .PATCH, .DELETE };
    for (methods) |m| {
        try testing.expectEqual(m, custom_http_client.Method.parse(m.asString()).?);
    }
}

test "Client.init/deinit is a no-op pair" {
    const allocator = testing.allocator;
    var client = custom_http_client.Client.init(allocator);
    client.deinit();
}

test "Request is plain-data — no constructor required" {
    const r: custom_http_client.Request = .{ .method = .GET, .url = "https://example.com" };
    try testing.expectEqualStrings("https://example.com", r.url);
    try testing.expectEqual(@as(?[]const u8, null), r.body);
    try testing.expectEqual(@as(usize, 0), r.headers.len);
}
