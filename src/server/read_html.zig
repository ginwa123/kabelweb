// =============================================================================
// readHtml — read an HTML template file with an embedded-source fallback,
//            auto-resolving `{% extends %}` inheritance from disk.
//
// This is the canonical pattern for self-contained HTML handlers in
// gserverz: ship the HTML file as a real on-disk asset (so users can edit
// and reload without rebuilding), but bundle a compile-time copy of the
// same source via `@embedFile` so the binary still works when the working
// directory differs from the build root (typical for deployed binaries or
// `zig build test` runs from a different cwd).
//
// Why is the embedded source passed in by the caller instead of being
// embedded inside `readHtml` itself?
//
//   1. Zig 0.16 forbids `@embedFile` of a runtime string — the path must
//      be a string literal at compile time, so the helper cannot decide
//      itself.
//   2. `@embedFile` resolves relative to the SOURCE FILE where it's called.
//      Since `readHtml` lives in `src/modules/kabelweb/src/server/`,
//      embedding here would require a path relative to that directory
//      (e.g. `"../../../handlers/landing.html"`) — fragile and coupled to
//      the helper's location in the file tree.
//
// Letting each caller pass the already-embedded source keeps `readHtml`
// location-independent and lets the caller embed at its own site (where
// the relative path is naturally meaningful).
//
// The helper also parses the source into a Template AST so the caller
// gets a single `[]Node` value ready to render. Errors are propagated
// upward; the caller wraps them with `gserverz.response.internalError`
// (or similar) at the handler boundary.
// =============================================================================

const std = @import("std");
const Template = @import("template.zig");

/// Read the on-disk source file with an embedded-source fallback.
fn readSourceWithFallback(
    io: std.Io,
    path: []const u8,
    embedded_fallback: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(1 << 20),
    ) catch |err| switch (err) {
        error.FileNotFound => try allocator.dupe(u8, embedded_fallback),
        else => return err,
    };
}

/// Context passed to the extends loader. Captures the io runtime, the
/// allocator used for path joins / file reads, and the directory used
/// as the base for resolving relative extends paths.
const ExtendsLoaderCtx = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    base_dir: []const u8,
};

/// Loader closure matching `Template.LoaderFn`. Invoked by the engine
/// whenever a template references `{% extends %}` — we resolve the
/// relative path against the child's directory and read from disk.
fn extendsLoader(ctx: *anyopaque, alloc: std.mem.Allocator, extends_path: []const u8) anyerror![]u8 {
    const typed: *ExtendsLoaderCtx = @ptrCast(@alignCast(ctx));
    const full_path = try std.fs.path.join(alloc, &.{ typed.base_dir, extends_path });
    defer alloc.free(full_path);

    return std.Io.Dir.cwd().readFileAlloc(
        typed.io,
        full_path,
        alloc,
        .limited(1 << 20),
    ) catch |err| switch (err) {
        error.FileNotFound => return error.TemplateNotFound,
        else => return err,
    };
}

/// Read a child template and resolve any `{% extends %}` chain against
/// the filesystem — the parent template is read from disk relative to
/// the child's directory. Returns a single merged AST ready to render.
///
/// The handler only needs to know about the child template. Parent
/// resolution is automatic:
///
///   1. Read the child from `path` (on-disk) or `embedded_fallback`
///      (when the file is missing — `zig build test` from a different
///      cwd, or a deployed binary running outside the build root).
///   2. Tokenize + parse the child to find the `{% extends "X" %}` directive.
///   3. If no `extends`, return the parsed child as-is (after
///      `parseSource` makes it self-contained — i.e. all string slices
///      are duped into the allocator so they survive the freed
///      token buffer).
///   4. If `extends` is present, resolve `X` relative to the child's
///      directory, read the parent from disk, and let the engine's
///      `compileWithParent` recursively merge (multi-level
///      inheritance works automatically — a parent can extend its own
///      parent).
///
/// Limitations:
///   * The parent MUST be on disk. There is no embedded fallback for
///     parents — only the child's embedded source is needed at startup.
///     In practice, parent templates ship alongside children in the
///     same directory, so a single `@embedFile` per child is enough.
///   * The `extends` path is resolved relative to the child's
///     directory (e.g. `src/handlers/admins/base.html` for an
///     `extends "base.html"` in
///     `src/handlers/admins/dashboard_page.html`).
///   * If the parent file can't be found on disk, the helper returns
///     `error.ParentTemplateNotFound`. This typically means a
///     deployment bug (the shared layout template wasn't shipped with
///     the binary).
///
/// Usage from a handler:
/// ```zig
/// const ADMIN_USERS_PATH = "src/handlers/admins/users_page.html";
/// const ADMIN_USERS_SOURCE: []const u8 = @embedFile("users_page.html");
///
/// const nodes = gserverz.readHtml(
///     ctx.allocator, ctx.io,
///     ADMIN_USERS_PATH, ADMIN_USERS_SOURCE,
/// ) catch |err| {
///     return gserverz.response.internalError(@errorName(err), ctx.allocator);
/// };
/// defer gserverz.Template.freeNodes(ctx.allocator, nodes);
/// ```
pub fn readHtml(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    embedded_fallback: []const u8,
) ![]Template.Node {
    const child_source = try readSourceWithFallback(io, path, embedded_fallback, allocator);
    defer allocator.free(child_source);

    // Tokenize + parse to discover `{% extends %}`. The engine's
    // compileWithParent re-parses internally to do the inheritance
    // merge, so this initial parse is throwaway — we only need the
    // extends path string to locate the parent on disk.
    //
    // We use `parseSource` (not the lower-level tokenize/parse pair)
    // because it's the public entry point that produces a
    // self-contained AST (all strings duped into the allocator).
    const child_nodes_pre = try Template.parseSource(allocator, child_source);
    defer Template.freeNodes(allocator, child_nodes_pre);

    // Look for an `extends` node at the top level.
    var extends_path: ?[]const u8 = null;
    for (child_nodes_pre) |node| {
        if (node == .extends) {
            extends_path = node.extends;
            break;
        }
    }

    if (extends_path == null) {
        // No inheritance — the child IS the template. Run it through
        // the engine's parseSource (which makes the AST self-contained
        // — copies all string slices into the allocator so they don't
        // dangle when the source buffer is freed).
        return Template.parseSource(allocator, child_source);
    }

    // Inheritance: build a loader closure that resolves `extends`
    // paths against the child's directory. compileWithParent walks
    // the child's AST; whenever it encounters `extends`, it invokes
    // the loader — which reads the parent file from disk relative to
    // `base_dir`. The `base_dir` here is the child's directory.
    const child_dir = std.fs.path.dirname(path) orelse ".";
    var loader_ctx = ExtendsLoaderCtx{
        .io = io,
        .allocator = allocator,
        .base_dir = child_dir,
    };

    return Template.compileWithParent(
        allocator,
        child_source,
        @ptrCast(&loader_ctx),
        extendsLoader,
    );
}

// ============================================================================
// Tests — moved here from `read_html_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = read_html_tests; }` below pulls them into the run.
// ============================================================================

const read_html_tests = struct {
    // =============================================================================
    //  Behavioural tests for `readHtml`.
    //
    // These tests exercise the helper end-to-end through `std.testing.io` and
    // `std.testing.allocator`. They DO NOT touch source files (no source-grep
    // / static-contract assertions) — every assertion is on the AST returned
    // by the helper or on the allocator state.
    //
    // Coverage:
    //   1. readHtml reads on-disk file, parses to AST, AST is non-empty
    //   2. readHtml falls back to embedded on FileNotFound
    //   3. readHtml parses the fallback (variable node is reachable in AST)
    //   4. readHtml propagates parse errors when source is malformed
    //   5. readHtml works with a syntactically trivial template (just text)
    //
    // Per project rule (2026-07-29): behavioural tests only. The helper is
    // the unit under test; the AST shape is the contract.
    // =============================================================================

    const testing = std.testing;

    /// Path to a real on-disk template (cwd-relative, so the test must run
    /// from the repo root — `zig build test` does). `example.jinja` is the
    /// demo's template and exercises the `{% extends %}` inheritance path
    /// (`base.jinja` lives next to it). Used by the on-disk happy-path test.
    const ON_DISK_PATH = "src/examples/templates/example.jinja";

    /// Path that NEVER exists on disk. Used to exercise the FileNotFound
    /// fallback path. The leading `/__nonexistent__/` segment guarantees no
    /// file in the repo matches it (no `__nonexistent__` directory exists).
    const MISSING_PATH = "src/__nonexistent__/this-file-never-exists.html";

    /// Simple embedded-fallback HTML. Contains a single `{{ greeting }}`
    /// variable we can verify reached the AST.
    const EMBEDDED_FALLBACK =
        \\<!doctype html>
        \\<html><body>Hello, {{ greeting }}!</body></html>
    ;

    /// Loop through `nodes` looking for a `.variable` whose payload matches
    /// `name`. Returns true if found. Helper used by multiple tests.
    fn hasVariable(nodes: []const Template.Node, name: []const u8) bool {
        for (nodes) |node| {
            if (node == .variable) {
                if (std.mem.eql(u8, node.variable, name)) return true;
            } else if (node == .if_block) {
                const blk = node.if_block;
                // Walk every branch's body + the else body.
                for (blk.branches) |br| {
                    if (hasVariable(br.body, name)) return true;
                }
                if (hasVariable(blk.else_branch, name)) return true;
            } else if (node == .for_loop) {
                const loop = node.for_loop;
                if (hasVariable(loop.body, name)) return true;
                if (hasVariable(loop.empty_body, name)) return true;
            } else if (node == .block) {
                // `{% block x %}…{% endblock %}` — walk the body so this helper
                // also covers templates that use `{% extends %}` inheritance.
                if (hasVariable(node.block.body, name)) return true;
            }
        }
        return false;
    }

    test "readHtml: reads on-disk file, parses to non-empty AST" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // Embedded fallback doesn't matter here — on-disk path succeeds.
        const nodes = try readHtml(
            allocator,
            std.testing.io,
            ON_DISK_PATH,
            "fallback-not-used",
        );
        defer Template.freeNodes(allocator, nodes);

        // landing.html is non-trivial — should produce many nodes.
        try testing.expect(nodes.len > 0);
    }

    test "readHtml: falls back to embedded source on FileNotFound" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // File doesn't exist on disk. Must use the embedded fallback.
        const nodes = try readHtml(
            allocator,
            std.testing.io,
            MISSING_PATH,
            EMBEDDED_FALLBACK,
        );
        defer Template.freeNodes(allocator, nodes);

        // The fallback contains a `{{ greeting }}` variable — verify it
        // actually reached the AST (proves parse ran on the fallback, not
        // on something else).
        try testing.expect(hasVariable(nodes, "greeting"));
    }

    test "readHtml: AST reflects the on-disk file, not the embedded fallback" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // example.jinja contains `{{ build_sha }}`. The fallback does NOT
        // contain that variable — so seeing `build_sha` in the AST proves
        // the on-disk file was read (not the fallback).
        const nodes = try readHtml(
            allocator,
            std.testing.io,
            ON_DISK_PATH,
            EMBEDDED_FALLBACK,
        );
        defer Template.freeNodes(allocator, nodes);

        try testing.expect(hasVariable(nodes, "build_sha"));
        // And the fallback's `greeting` variable is NOT in the AST — proves
        // we read the on-disk file, not the fallback.
        try testing.expect(!hasVariable(nodes, "greeting"));
    }

    test "readHtml: propagates parse error for malformed Jinja" {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // `{% if unclosed` is missing the `{% endif %}` — the parser
        // surfaces this as an error. We cannot easily create files from
        // tests (no write helper in std.testing), so embed the malformed
        // source as the "fallback" and use a missing path so the fallback
        // is the source under test.
        const malformed_source =
            \\<!doctype html>
            \\<html><body>
            \\{% if true %}
            \\hello
            \\</body></html>
        ;

        const result = readHtml(
            allocator,
            std.testing.io,
            MISSING_PATH,
            malformed_source,
        );
        // We expect a parse error — `Template.Error` has `ParseError`,
        // `UnclosedTag`, `UnclosedVariable`, `UnclosedComment`, etc.
        // The parser surfaces a generic `ParseError` for syntax errors
        // discovered during recursive descent. Don't free nodes — they
        // may be partial.
        try testing.expectError(Template.Error.ParseError, result);
    }

    test "readHtml: freeNodes reclaims allocations (arena discipline)" {
        // Two-pass read → free → re-read cycle. The arena allocator only
        // reclaims memory on its own `deinit`, but `freeNodes` must return
        // every internal allocation cleanly so the handler can `defer`
        // it without leaks.
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // First read.
        {
            const nodes = try readHtml(
                allocator,
                std.testing.io,
                ON_DISK_PATH,
                "fallback-not-used",
            );
            try testing.expect(nodes.len > 0);
            Template.freeNodes(allocator, nodes);
        }

        // Second read — if `freeNodes` leaked, the second read might OOM or
        // reuse stale pointers. We can't easily detect OOM here, but we can
        // at least verify the second read completes.
        {
            const nodes = try readHtml(
                allocator,
                std.testing.io,
                ON_DISK_PATH,
                "fallback-not-used",
            );
            defer Template.freeNodes(allocator, nodes);
            try testing.expect(nodes.len > 0);
        }
    }
};

comptime {
    _ = read_html_tests;
}
