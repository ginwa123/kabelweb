// Static-contract regression tests for the static HTML example served by
// `main.zig::landingPageHandler` at `GET /`.
//
// Why static-contract (vs. behavioural):
//   * Behavioural (start server, open TCP, read bytes) is already covered
//     by the smoke-test recipe in the plan. Static-contract tests are
//     fast, deterministic, and catch silent regressions where someone
//     changes main.zig in a way that breaks the HTML contract (removes
//     `Content-Type`, deletes the doctype, drops the `LANDING_PAGE_HTML`
//     constant, etc.) without ever running the binary.
//   * Matches the convention used elsewhere in this codebase
//     (see .nalar/memories/project-working-patterns.md, "Naming
//     conventions ... Static contract tests").
//
// Each test reads `main.zig` as text and asserts on required substrings.

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

// Zig 0.16 stdlib does NOT expose fseek/ftell in std.c (see zig-cross-
// platform.md). Declare them as module-scope extern "c" fn — at module
// scope because Zig 0.16 forbids extern "c" inside function bodies.
//
// Clong matches the C `long` type: 64-bit on Linux/macOS, 32-bit on
// Windows. We only need to read files in CI on Linux, but the declaration
// still has to compile on every target.
const Clong = if (@bitSizeOf(usize) == 64 and builtin.os.tag != .windows)
    i64
else
    i32;

extern "c" fn fseek(stream: *std.c.FILE, offset: Clong, whence: c_int) c_int;
extern "c" fn ftell(stream: *std.c.FILE) Clong;

// Candidate cwd-relative paths for the demo source — the suite runs
// both from the repo root (root gate) and from the kabelweb package
// dir (package's own build).
const main_zig_candidates = &.{
    "src/modules/kabelweb/src/examples/server_demo.zig",
    "src/examples/server_demo.zig",
};

/// Read the demo source into a heap-allocated buffer. Caller frees the slice.
/// Uses Zig 0.16's std.Io.Dir.cwd() + readFileAlloc with std.testing.io,
/// which is the canonical replacement for the removed std.fs.cwd() in
/// tests — see `.nalar/memories/zig-0.16-stdlib-changes.md`.
fn readMainSource(allocator: std.mem.Allocator) ![]u8 {
    // std.Io.Dir.cwd() works in `zig build test` because std.testing.io
    // provides a Threaded Io runtime (test_target uses real threads even
    // for unit tests).
    var last_err: anyerror = error.FileNotFound;
    inline for (main_zig_candidates) |path| {
        if (std.Io.Dir.cwd().readFileAlloc(
            std.testing.io,
            path,
            allocator,
            .limited(1 << 20), // cap at 1 MiB
        )) |source| {
            return source;
        } else |err| {
            last_err = err;
        }
    }
    return last_err;
}

test "main.zig declares LANDING_PAGE_HTML constant" {
    const source = try readMainSource(testing.allocator);
    defer testing.allocator.free(source);

    // The constant name is part of the public contract — the handler
    // references it by name, so the constant must exist at module scope.
    if (std.mem.indexOf(u8, source, "const LANDING_PAGE_HTML") == null) {
        std.debug.print("!! main.zig is missing 'const LANDING_PAGE_HTML' !!\n", .{});
        return error.LandingPageHtmlConstantMissing;
    }
}

test "main.zig declares landingPageHandler function" {
    const source = try readMainSource(testing.allocator);
    defer testing.allocator.free(source);

    if (std.mem.indexOf(u8, source, "fn landingPageHandler") == null) {
        std.debug.print("!! main.zig is missing 'fn landingPageHandler' !!\n", .{});
        return error.LandingPageHandlerFunctionMissing;
    }
}

test "landingPageHandler sets Content-Type text/html header" {
    const source = try readMainSource(testing.allocator);
    defer testing.allocator.free(source);

    // The handler must explicitly set text/html — without it browsers may
    // sniff and fall back to plain-text rendering. We anchor on the exact
    // substring the handler writes so a typo (e.g. text/htm) would fail.
    if (std.mem.indexOf(u8, source, "Content-Type") == null or
        std.mem.indexOf(u8, source, "text/html; charset=utf-8") == null)
    {
        std.debug.print(
            "!! landingPageHandler does not set Content-Type 'text/html; charset=utf-8' !!\n",
            .{},
        );
        return error.HtmlContentTypeHeaderMissing;
    }
}

test "landingPageHandler duplicates HTML into the per-request arena" {
    const source = try readMainSource(testing.allocator);
    defer testing.allocator.free(source);

    // The contract is: HTML lives as a comptime constant in rodata; the
    // handler allocates a per-request copy via ctx.allocator.dupe(u8, ...).
    // Forgetting the .dupe and returning the const reference would alias
    // rodata bytes — works for read-only content but breaks any future
    // plan that wants to mutate the body.
    if (std.mem.indexOf(u8, source, "ctx.allocator.dupe(u8, LANDING_PAGE_HTML)") == null) {
        std.debug.print(
            "!! landingPageHandler does not .dupe the HTML into ctx.allocator !!\n",
            .{},
        );
        return error.HtmlDupeMissing;
    }
}

test "GET / route is registered to landingPageHandler" {
    const source = try readMainSource(testing.allocator);
    defer testing.allocator.free(source);

    // The router registration line must point at landingPageHandler —
    // protects against someone "fixing" the registration to a different
    // handler while leaving the HTML handler dangling. Accepts either
    // a direct `server.router.get(...)` registration OR a group-relative
    // `root.get(...)` (the latter is the recommended pattern when
    // middleware is applied at the root group level).
    const line = std.mem.indexOf(u8, source, "router.get(\"/\", landingPageHandler)") orelse
        std.mem.indexOf(u8, source, "root.get(\"/\", landingPageHandler)") orelse
        std.mem.indexOf(u8, source, "root.get(\"/\", http_handlers_mod.landingPageHandler)") orelse
    {
        std.debug.print("!! main.zig does not register GET / -> landingPageHandler !!\n", .{});
        return error.LandingPageRouteMissing;
    };
    _ = line;
}

test "LANDING_PAGE_HTML page contains the full doctype preamble" {
    const source = try readMainSource(testing.allocator);
    defer testing.allocator.free(source);

    // The HTML constant must start with the doctype so browsers parse
    // it as standards-mode HTML5 (vs. quirks mode or text/plain).
    if (std.mem.indexOf(u8, source, "<!doctype html>") == null) {
        std.debug.print("!! LANDING_PAGE_HTML missing '<!doctype html>' preamble !!\n", .{});
        return error.DoctypeMissing;
    }
    if (std.mem.indexOf(u8, source, "<html lang=\"en\">") == null) {
        std.debug.print("!! LANDING_PAGE_HTML missing '<html lang=\"en\">' tag !!\n", .{});
        return error.HtmlLangTagMissing;
    }
    if (std.mem.indexOf(u8, source, "<meta charset=\"utf-8\"") == null) {
        std.debug.print("!! LANDING_PAGE_HTML missing utf-8 meta charset !!\n", .{});
        return error.Utf8MetaMissing;
    }
}

test "LANDING_PAGE_HTML documents all five demo endpoints" {
    const source = try readMainSource(testing.allocator);
    defer testing.allocator.free(source);

    // The HTML page is the SERVER's own documentation — every route
    // registered in `run()` must appear in the table so users have a
    // discoverable index. Pin them to catch accidental removals.
    const required_paths = [_][]const u8{
        "/health",
        "/hello",
        "/hello/:name",
        "/users",
        "/stream",
    };
    for (required_paths) |path| {
        if (std.mem.indexOf(u8, source, path) == null) {
            std.debug.print(
                "!! LANDING_PAGE_HTML does not document endpoint '{s}' !!\n",
                .{path},
            );
            return error.EndpointDocumentationMissing;
        }
    }
}

test "LANDING_PAGE_HTML includes a working JavaScript EventSource demo" {
    const source = try readMainSource(testing.allocator);
    defer testing.allocator.free(source);

    // The page should be more than a curl cheat-sheet — it should
    // demonstrate the SSE feature live. The EventSource constructor
    // pointing at /stream is the proof.
    if (std.mem.indexOf(u8, source, "new EventSource('/stream')") == null) {
        std.debug.print(
            "!! LANDING_PAGE_HTML missing 'new EventSource(\"/stream\")' demo !!\n",
            .{},
        );
        return error.EventSourceDemoMissing;
    }
}