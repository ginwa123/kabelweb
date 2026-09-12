const std = @import("std");
const testing = std.testing;
const custom_http_client = @import("root.zig");

test "Options defaults match libcurl's 'do nothing special' baseline" {
    const opts: custom_http_client.Options = .{};
    try testing.expectEqual(@as(?u32, null), opts.timeout_ms);
    try testing.expectEqual(@as(?u32, null), opts.connect_timeout_ms);
    try testing.expectEqual(false, opts.follow_redirects);
    try testing.expectEqual(@as(u16, 5), opts.max_redirects);
    try testing.expectEqualStrings("", opts.user_agent);
    try testing.expectEqual(true, opts.verify_ssl);
}

test "Options can be constructed with one-of-each field set" {
    const opts: custom_http_client.Options = .{
        .timeout_ms = 1500,
        .connect_timeout_ms = 500,
        .follow_redirects = true,
        .max_redirects = 10,
        .user_agent = "test/1.0",
        .verify_ssl = false,
    };
    try testing.expectEqual(@as(u32, 1500), opts.timeout_ms.?);
    try testing.expectEqual(@as(u32, 500), opts.connect_timeout_ms.?);
    try testing.expectEqual(true, opts.follow_redirects);
    try testing.expectEqual(@as(u16, 10), opts.max_redirects);
    try testing.expectEqualStrings("test/1.0", opts.user_agent);
    try testing.expectEqual(false, opts.verify_ssl);
}
