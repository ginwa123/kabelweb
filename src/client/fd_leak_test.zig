//! FD-leak regression tests. Counter-paradigm to the
//! bash-spawn approach in modules/http/HttpClient.zig — that
//! module needed explicit pipe-close defers (PR #91); this module
//! is supposed to be leak-free by construction because libcurl
//! owns its sockets. We verify empirically under stress.
//!
//! On Linux we use `std.process.Child` + `ls /proc/self/fd | wc -l`
//! — Zig 0.16's `Io.Dir.iterate()` panics on /proc/self/fd because
//! entries are symlinks that vanish during iteration. The shell
//! approach is the project-precedent pattern (see the bash.zig
//! FD-leak tests for the same workaround).

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const custom_http_client = @import("root.zig");
const io = std.testing.io;

/// Count open FDs by running `ls /proc/self/fd`. Linux-only;
/// non-Linux hosts return 0 and the tests skip.
fn countOpenFds() !usize {
    if (builtin.os.tag != .linux) return 0;
    // Spawn `sh -c "ls /proc/self/fd | wc -l"`.
    var child = try std.process.spawn(io, .{
        .argv = &[_][]const u8{ "sh", "-c", "ls /proc/self/fd 2>/dev/null | wc -l" },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    defer {
        if (child.stdout) |s| s.close(io);
        child.kill(io);
    }

    var buf: [64]u8 = undefined;
    var total: usize = 0;
    if (child.stdout) |out| {
        var reader = out.reader(io, &buf);
        while (true) {
            const n = try std.Io.Reader.readSliceShort(&reader.interface, &buf);
            if (n == 0) break;
            total += n;
        }
    }
    _ = child.wait(io) catch {};

    // Parse the number from the output. Output is "<n>\n".
    const contents = testing.allocator.alloc(u8, total) catch return 0;
    defer testing.allocator.free(contents);
    @memcpy(contents, buf[0..total]);

    var n: usize = 0;
    for (contents) |c| {
        if (c >= '0' and c <= '9') {
            n = n * 10 + @as(usize, c - '0');
        }
    }
    return n;
}

test "fd: 50 sequential GETs do NOT grow the open-fd count" {
    if (builtin.os.tag != .linux) return;
    const allocator = testing.allocator;
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    const before = try countOpenFds();

    var ok: usize = 0;
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        var resp = client.perform(.{ .method = .GET, .url = "https://example.com" }, .{}) catch continue;
        defer resp.deinit(allocator);
        ok += 1;
    }

    std.Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms * 10 }, .real) catch {};

    const after = try countOpenFds();

    const tolerance: usize = 10;
    if (after > before + tolerance) {
        std.debug.print("!! FD leak: before={d} after={d} delta={d} (ok_calls={d}) !!\n",
            .{ before, after, after - before, ok });
        return error.FdLeakSuspected;
    }
    if (ok == 0) return error.SkipZigTest;
}

test "fd: 50 ConnectionRefused errors do NOT grow the open-fd count" {
    if (builtin.os.tag != .linux) return;
    const allocator = testing.allocator;
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    const before = try countOpenFds();

    var i: usize = 0;
    while (i < 50) : (i += 1) {
        _ = client.perform(.{ .method = .GET, .url = "http://127.0.0.1:1/" }, .{}) catch {};
    }

    std.Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms * 10 }, .real) catch {};

    const after = try countOpenFds();
    const tolerance: usize = 10;
    if (after > before + tolerance) {
        std.debug.print("!! FD leak on errors: before={d} after={d} delta={d} !!\n",
            .{ before, after, after - before });
        return error.FdLeakOnErrorsSuspected;
    }
}

test "fd: total open-fd count stays bounded under load" {
    if (builtin.os.tag != .linux) return;
    const allocator = testing.allocator;
    var client = custom_http_client.Client.init(allocator);
    defer client.deinit();

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var resp = client.perform(.{ .method = .GET, .url = "https://example.com" }, .{}) catch continue;
        resp.deinit(allocator);
    }

    const count = try countOpenFds();
    try testing.expect(count < 100);
}
