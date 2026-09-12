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