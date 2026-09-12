//! Minimal CLI: `custom_http_client <METHOD> <URL>` → prints
//! "status=N bytes=N ip=v4" on success, exits 1 on failure.
//! Used for manual smoke tests against real endpoints.

const std = @import("std");
const custom_http_client = @import("kabelweb").client;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    // `toSlice` returns args including the program name as [0]; the actual
    // positional args are [1..]. We expect exactly one extra METHOD and
    // one URL.
    if (args.len < 3) {
        std.debug.print("usage: custom_http_client <METHOD> <URL>\n", .{});
        std.process.exit(1);
    }

    const method_name = args[1];
    const url = args[2];
    const method = custom_http_client.Method.parse(method_name) orelse {
        std.debug.print("unknown method: {s}\n", .{method_name});
        std.process.exit(1);
    };

    var client = custom_http_client.Client.init(arena);
    defer client.deinit();

    var response = client.perform(.{ .method = method, .url = url }, .{}) catch |err| {
        std.debug.print("request failed: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer response.deinit(arena);

    std.debug.print("status={d} bytes={d} ip={s}\n", .{
        response.status_code, response.body.len, response.primary_ip,
    });
}
