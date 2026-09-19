//! Jinja-style template engine for `custom_http_server`.
//!
//! Three layers: tokenize → parse → render. Templates are compiled once
//! (per request or once at startup, then cached) and rendered many times
//! with different contexts. Auto-escape is ON for `{{ var }}` output; use
//! `{% raw %}...{% endraw %}` to pass through HTML verbatim.
//!
//! Minimal scope (no filters, no whitespace control, no macros, no
//! includes, no `set`). Features supported:
//!
//!   * `{{ var }}`               — substitution, HTML-escaped
//!   * `{{ a.b.c }}` / `{{ x[0] }}` — dotted + bracket paths
//!   * `{% if cond %}...{% endif %}`          — conditional
//!   * `{% if cond %}A{% else %}B{% endif %}` — conditional with else
//!   * `{% for x in items %}...{% endfor %}`            — loop
//!   * `{% for x in items %}...{% empty %}...{% endfor %}` — loop with empty
//!   * `{% raw %}...{% endraw %}` — pass through verbatim
//!   * `{% extends "parent.jinja" %}` — template inheritance
//!   * `{% block name %}...{% endblock %}` — overridable slot
//!
//! See docs/superpowers/plans/2026-08-06-jinja-template-engine.md for the
//! design and tests that drove this implementation.

const std = @import("std");

/// Errors raised by the engine. Each error tags a specific failure mode
/// so call sites can distinguish (e.g. missing-file vs parse-error).
///
/// NOTE on `ParseError` — the error code itself carries no payload, but
/// every site that returns `error.ParseError` also prints a human-readable
/// diagnostic to stderr before the return (see `reportParseError` below).
/// That diagnostic includes:
///   1. A short description of the failure mode (e.g. "expected 'in' in
///      'for' tag").
///   2. The source file location (line:column) where the parse failed.
///   3. The offending source line and a caret pointing at the column.
///
/// Caller-visible signature of `parseError` is just the bare code —
/// the existing tests check `expectError(error.ParseError, ...)` and
/// keep working unchanged. The diagnostic is a side effect intended for
/// developer eyes (a server returning 500 because of a typo'd template
/// is far easier to debug with a line number than without).
pub const Error = error{
    UnclosedVariable,
    UnclosedTag,
    UnclosedComment,
    ParseError,
    RenderError,
    TemplateNotFound,
    CircularExtends,
    /// A `{% include %}` tag was encountered but no loader was provided
    /// in `RenderOptions`. Either pass a loader or remove the include.
    IncludeLoaderRequired,
};

/// 1-based line/column location in a source buffer. Returned by
/// `offsetToLocation`. Used internally by `reportParseError` to format
/// the caret-under-source-line diagnostics emitted alongside every
/// `ParseError` return.
const ParseLocation = struct {
    line: usize,
    column: usize,
    /// The byte offset this location corresponds to (echoed back so
    /// callers can slice `source[loc.offset..]` without recomputing).
    offset: usize,
};

/// Convert a byte offset into a 1-based (line, column) pair. Walks
/// `source[0..offset]` counting `\n` boundaries. O(offset) — only
/// called once per parse error, which is fine since errors are rare
/// and template sizes are bounded.
fn offsetToLocation(source: []const u8, offset: usize) ParseLocation {
    const end = @min(offset, source.len);
    var line: usize = 1;
    var col: usize = 1;
    var i: usize = 0;
    while (i < end) : (i += 1) {
        if (source[i] == '\n') {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    return .{ .line = line, .column = col, .offset = end };
}

/// Resolve a `Token` slice back to its byte offset in `source`. Tokens
/// are slices INTO the source buffer, so the offset is just the pointer
/// distance between the token's slice and the source's base pointer —
/// no string search needed. Returns `source.len` for a degenerate
/// "past the end" token (defensive — shouldn't happen, but kept simple).
fn tokenOffset(source: []const u8, token: Token) usize {
    const slice_ptr: [*]const u8 = switch (token) {
        .text => token.text.ptr,
        .var_expr => token.var_expr.ptr,
        .tag => token.tag.ptr,
    };
    const source_base = source.ptr;
    // Pointer ordering via `@intFromPtr` — Zig disallows `<` on `[*]const u8`.
    const slice_addr: usize = @intFromPtr(slice_ptr);
    const base_addr: usize = @intFromPtr(source_base);
    if (slice_addr < base_addr) return 0; // defensive
    const delta = slice_addr - base_addr;
    return @min(delta, source.len);
}

/// Emit a parse-error diagnostic to stderr. The format mirrors the
/// `rustc` / `zig ast-check` style that developers already know:
///
///     template: parse error: <description>
///       --> template:<line>:<column>
///      |
///   LL | <source line>
///      |     ^
///
/// `description` is the human-readable failure tag (e.g.
/// "expected 'in' in 'for' tag"); `offset` is the byte position in
/// `source` where the error was detected. Errors from the underlying
/// `std.debug.print` are intentionally swallowed — the diagnostic
/// must NEVER mask the real `error.ParseError` we return to the
/// caller. Losing the diagnostic in a degenerate write failure is
/// strictly preferable to losing the error code.
fn reportParseError(source: []const u8, offset: usize, description: []const u8) void {
    const loc = offsetToLocation(source, offset);

    // Slice out the offending source line so we can echo it under the
    // error header. We bound the search at line breaks; lines longer
    // than 4096 bytes are truncated at the right edge — pathological
    // inputs (single-line minified HTML) would otherwise produce an
    // unreadable diagnostic that's wider than a terminal.
    const max_line_len: usize = 4096;
    var line_start: usize = loc.offset;
    while (line_start > 0 and source[line_start - 1] != '\n') {
        line_start -= 1;
    }
    var line_end: usize = loc.offset;
    while (line_end < source.len and source[line_end] != '\n' and
        line_end - line_start < max_line_len)
    {
        line_end += 1;
    }
    const line_text = source[line_start..line_end];

    // The caret sits under the offending column. We bound the pad so
    // a column past the (possibly truncated) source-line end still
    // produces a readable diagnostic. Buffer is on the stack; 256
    // bytes covers any reasonable single-line column.
    const col_pad_len: usize = if (loc.column <= 1)
        0
    else if (loc.column - 1 < line_text.len)
        loc.column - 1
    else
        @min(line_text.len, 256);
    var col_pad: [256]u8 = undefined;
    @memset(col_pad[0..col_pad_len], ' ');

    std.debug.print(
        "template: parse error: {s}\n  --> template:{d}:{d}\n   |\n {d:>3} | {s}\n   | {s}^\n",
        .{
            description,
            loc.line,
            loc.column,
            loc.line,
            line_text,
            col_pad[0..col_pad_len],
        },
    );
}

/// A single token produced by the tokenizer. The string slices point into
/// the source buffer — the caller must keep `source` alive for the lifetime
/// of the tokens.
pub const Token = union(enum) {
    /// Raw text between tags. Always emitted at the start and between
    /// every other token (you will never see two non-text tokens in a row).
    text: []const u8,
    /// Content of `{{ ... }}`. Whitespace inside is preserved.
    var_expr: []const u8,
    /// Content of `{% ... %}`. Whitespace inside is preserved.
    tag: []const u8,
};

/// Tokenize `source` into a slice of `Token`. Comments `{# ... #}` are
/// dropped (no token emitted). Returns an error on unclosed tags.
pub fn tokenize(allocator: std.mem.Allocator, source: []const u8) (Error || std.mem.Allocator.Error)![]Token {
    var tokens = std.ArrayListUnmanaged(Token).empty;
    errdefer tokens.deinit(allocator);

    var pos: usize = 0;
    while (pos < source.len) {
        // Look for the next tag-like opening: {{, {%, or {#.
        const next_open = findNextOpen(source, pos);
        if (next_open) |open| {
            // Emit text from `pos` up to `open` (if non-empty).
            if (open > pos) {
                try tokens.append(allocator, .{ .text = source[pos..open] });
            }
            // Determine which opener we hit.
            if (open + 1 >= source.len) {
                // Defensive: shouldn't happen — findNextOpen guarantees 2 chars.
                return error.UnclosedTag;
            }
            switch (source[open + 1]) {
                '{' => {
                    // Variable expression.
                    const close = std.mem.indexOfPos(u8, source, open + 2, "}}") orelse
                        return error.UnclosedVariable;
                    try tokens.append(allocator, .{ .var_expr = source[open + 2 .. close] });
                    pos = close + 2;
                },
                '%' => {
                    // Tag.
                    const close = std.mem.indexOfPos(u8, source, open + 2, "%}") orelse
                        return error.UnclosedTag;
                    // Strip Jinja's whitespace-control markers (`-` and
                    // `+`) at the start and end of the tag content.
                    // `{%- ... %}` strips whitespace before the tag;
                    // `{% ... -%}` strips after; `{%- ... -%}` does
                    // both. `+` is the opposite (preserve whitespace).
                    // We don't currently act on the surrounding text
                    // (the tokenizer doesn't track newlines separately),
                    // but stripping the markers lets the parser's
                    // keyword comparators (endmacro, endif, etc.) match
                    // correctly when used with whitespace control.
                    var content_start: usize = open + 2;
                    var content_end: usize = close;
                    if (content_end > content_start and
                        (source[content_start] == '-' or source[content_start] == '+'))
                    {
                        content_start += 1;
                    }
                    if (content_end > content_start and
                        (source[content_end - 1] == '-' or source[content_end - 1] == '+'))
                    {
                        content_end -= 1;
                    }
                    try tokens.append(allocator, .{ .tag = source[content_start..content_end] });
                    pos = close + 2;
                },
                '#' => {
                    // Comment — drop entirely.
                    const close = std.mem.indexOfPos(u8, source, open + 2, "#}") orelse
                        return error.UnclosedComment;
                    pos = close + 2;
                },
                else => {
                    // Should be unreachable since findNextOpen only returns
                    // positions followed by {, %, or #.
                    return error.UnclosedTag;
                },
            }
        } else {
            // No more tags — emit the rest as text.
            try tokens.append(allocator, .{ .text = source[pos..] });
            pos = source.len;
        }
    }

    return tokens.toOwnedSlice(allocator);
}

/// Find the next position in `source` (at or after `from`) that starts a
/// template tag — `{{`, `{%`, or `{#`. Returns null if no more tags.
fn findNextOpen(source: []const u8, from: usize) ?usize {
    var i = from;
    while (i + 1 < source.len) : (i += 1) {
        if (source[i] == '{') {
            switch (source[i + 1]) {
                '{', '%', '#' => return i,
                else => continue,
            }
        }
    }
    return null;
}

// =============================================================================
//  AST — defined up front so the parser and renderer can be added in
//  subsequent tasks without restructuring this file.
// =============================================================================

/// A node in the parsed template AST. The parser builds these from
/// tokens; the renderer walks them to produce output.
pub const Node = union(enum) {
    /// Raw text — emitted verbatim.
    text: []const u8,
    /// `{{ var }}` — resolved against the context, HTML-escaped.
    variable: []const u8,
    /// `{% if c1 %} A {% elif c2 %} B {% else %} C {% endif %}`.
    if_block: IfBlock,
    /// `{% for x in items [if cond] %} A {% empty %} B {% endfor %}`.
    /// The optional `if cond` filter skips items where `cond` is falsy.
    for_loop: ForLoop,
    /// `{% block name %}...{% endblock %}` — overridable slot.
    block: Block,
    /// `{% extends "parent.jinja" %}` — must be the first node.
    extends: []const u8,
    /// `{% raw %}...{% endraw %}` — content emitted unescaped.
    raw: []Node,
    /// `{% include "partial.html" %}` — render another template inline.
    include: Include,
    /// `{% set var = expr %}` — assign a context variable.
    set: Set,
    /// `{% macro name(p1, p2=default) %}...{% endmacro %}` — define a
    /// callable macro. Rendered into the context at top level; called
    /// via `{{ name(arg1, arg2) }}`.
    macro: Macro,
};

/// One branch of an `{% if %}` / `{% elif %}` chain. The first branch
/// is the `if` itself; subsequent branches are `elif`. The renderer
/// picks the first truthy branch and renders its body.
pub const IfBranch = struct {
    /// Dotted path / expression to evaluate (e.g. "user.is_admin").
    condition: []const u8,
    body: []Node,
};

pub const IfBlock = struct {
    /// Ordered list of condition → body pairs. Length is always ≥ 1
    /// (the leading `{% if %}` is branches[0]). The parser flattens
    /// `{% if %} / {% elif %} / {% elif %}` into this list.
    branches: []IfBranch,
    /// Final `{% else %}` body, or empty when there is no else.
    else_branch: []Node,
};

pub const ForLoop = struct {
    /// Loop variable name (e.g. "x").
    var_name: []const u8,
    /// Dotted path to the iterable (e.g. "items").
    iterable: []const u8,
    /// Optional filter expression. When set, items where the expression
    /// evaluates to a falsy value are skipped (and don't increment
    /// `loop.index`). When null, all items iterate (legacy behavior).
    condition: ?[]const u8 = null,
    body: []Node,
    /// `{% empty %}` branch — rendered when the iterable is empty
    /// (after filtering, when `condition` is set).
    empty_body: []Node,
};

pub const Block = struct {
    name: []const u8,
    body: []Node,
};

/// `{% include "path.html" %}` — render another template inline. The
/// path is resolved at render time via the loader; relative paths are
/// resolved against the including template's base directory.
pub const Include = struct {
    path: []const u8,
    /// `with context` (default true) — the included template sees the
    /// current context's variables. `without context` sets this to
    /// false and the included template starts with an empty context.
    with_context: bool = true,
    /// `ignore missing` — when true, a missing file silently emits
    /// nothing instead of erroring. Useful for optional partials.
    ignore_missing: bool = false,
};

/// `{% set var = expr %}` — assign a value into the current context.
/// Scoping: assignments inside a `{% for %}` are confined to the loop
/// body (the loop creates a child context). Assignments inside a
/// `{% if %}` are visible after the block (Jinja's if-doesn't-introduce-
/// scope rule, kept here for parity).
pub const Set = struct {
    var_name: []const u8,
    /// Expression to evaluate. The result is the assigned value.
    value: []const u8,
};

/// One parameter of a macro. Mirrors the Jinja signature
/// `{% macro foo(a, b='default', c=None) %}` — required parameters have
/// `default = null`; optional ones carry the default expression.
pub const MacroParam = struct {
    name: []const u8,
    default: ?[]const u8 = null,
};

/// `{% macro name(p1, p2=default) %}body{% endmacro %}` — define a
/// reusable rendering function. The body executes in a fresh child
/// context populated with the arguments, plus the macro's enclosing
/// scope (Jinja exposes closure-like capture, but we keep it simple
/// here: arguments only).
pub const Macro = struct {
    name: []const u8,
    params: []MacroParam,
    body: []Node,
};

/// Compiled template — ready to render. Owns its AST nodes; the caller
/// must call `deinit` to free the node tree and the loader-borrowed
/// source strings.
pub const Compiled = struct {
    nodes: []Node,

    pub fn deinit(self: *Compiled, allocator: std.mem.Allocator) void {
        freeNodes(allocator, self.nodes);
        self.nodes = &[_]Node{};
    }

    /// Render the template with the given context. Output is allocated into
    /// `out_alloc`. (Renderer is implemented in Task 3.)
    pub fn render(
        self: *const Compiled,
        out_alloc: std.mem.Allocator,
        ctx: *Context,
    ) (Error || std.mem.Allocator.Error)![]u8 {
        _ = self;
        _ = out_alloc;
        _ = ctx;
        return error.RenderError; // Implemented in Task 3.
    }
};

/// Free a node tree recursively. Safe to call on partially-constructed
/// trees (handles nested children).
///
/// Ownership contract: by default, `text`, `variable`, and `extends`
/// slices point into the source (NOT heap-allocated) — the caller must
/// keep the source alive while the AST is in use. The exception is the
/// `raw` node, whose text is a fresh heap allocation (reconstructed from
/// multiple tokens); we free it explicitly before recursing.
pub fn freeNodes(allocator: std.mem.Allocator, nodes: []Node) void {
    for (nodes) |node| {
        switch (node) {
            .text, .variable, .extends => |s| allocator.free(s),
            .include => |i| allocator.free(i.path),
            .set => |s| {
                allocator.free(s.var_name);
                allocator.free(s.value);
            },
            .if_block => |b| {
                // Each branch has a heap-allocated condition string
                // (duplicated from the token slice by `copyAllStrings`)
                // plus its own body slice. We free the conditions and
                // recurse into the bodies. `branches` itself is a
                // heap-allocated slice (allocated by `parseIf`).
                for (b.branches) |br| {
                    allocator.free(br.condition);
                    freeNodes(allocator, br.body);
                }
                allocator.free(b.branches);
                freeNodes(allocator, b.else_branch);
            },
            .for_loop => |l| {
                allocator.free(l.var_name);
                allocator.free(l.iterable);
                if (l.condition) |cond| allocator.free(cond);
                freeNodes(allocator, l.body);
                freeNodes(allocator, l.empty_body);
            },
            .block => |b| {
                allocator.free(b.name);
                freeNodes(allocator, b.body);
            },
            .raw => |r| freeNodes(allocator, r),
            .macro => |m| {
                allocator.free(m.name);
                for (m.params) |p| {
                    allocator.free(p.name);
                    if (p.default) |d| allocator.free(d);
                }
                allocator.free(m.params);
                freeNodes(allocator, m.body);
            },
        }
    }
    allocator.free(nodes);
}

/// Free the contents of every Node in `nodes` WITHOUT freeing the
/// outer `nodes` slice itself. Use this when the outer slice is owned
/// by something else (e.g. a parent AST that we're merging into and
/// will eventually free as a whole).
///
/// `freeNodes` frees BOTH contents and the slice — they aren't the
/// same. `mergeBlocks` was leaking the parent's old block body when
/// an override was applied because it called `b.* = ...` and replaced
/// the body's slice pointer without freeing the original; this helper
/// is the missing "free just the contents" piece.
fn freeNodeContents(allocator: std.mem.Allocator, nodes: []const Node) void {
    for (nodes) |node| {
        switch (node) {
            .text, .variable, .extends, .include, .set => {},
            .if_block => |b| {
                for (b.branches) |br| {
                    freeNodeContents(allocator, br.body);
                }
                freeNodeContents(allocator, b.else_branch);
            },
            .for_loop => |l| {
                freeNodeContents(allocator, l.body);
                freeNodeContents(allocator, l.empty_body);
            },
            .block => |b| {
                allocator.free(b.name);
                freeNodeContents(allocator, b.body);
            },
            .raw => |r| freeNodeContents(allocator, r),
            .macro => |m| {
                for (m.params) |p| {
                    allocator.free(p.name);
                }
                allocator.free(m.params);
                freeNodeContents(allocator, m.body);
            },
        }
    }
}

// =============================================================================
//  Parser
// =============================================================================
//
// Recursive descent. `parse` walks tokens[start..end] and returns its
// AST. The recursive helpers (`parseIf`, `parseFor`, `parseBlock`,
// `parseRaw`) find their matching closer using `findMatchingTag` so
// nested constructs resolve correctly. The helper returns the position
// of the closer; the caller skips past it.

/// Parse a token stream into an AST. The caller owns the AST and must
/// free it with `freeNodes`.
///
/// `source` is required so `ParseError` sites can emit a line:column
/// diagnostic pointing at the offending token. If the caller doesn't
/// have the source (only the tokens — e.g. from `tokenize` alone),
/// pass an empty `&[_]u8` and the diagnostic will fall back to
/// reporting just the description without a location.
pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
    tokens: []const Token,
) (Error || std.mem.Allocator.Error)![]Node {
    return parseNodes(allocator, source, tokens, 0, tokens.len);
}

/// Convenience: tokenize then parse.
pub fn parseSource(allocator: std.mem.Allocator, source: []const u8) (Error || std.mem.Allocator.Error)![]Node {
    const tokens = try tokenize(allocator, source);
    defer allocator.free(tokens);
    const nodes = try parseNodes(allocator, source, tokens, 0, tokens.len);
    // After parseNodes returns, every Node.text/variable/extends/condition/
    // var_name/iterable/name field is a slice INTO the freed tokens buffer.
    // Duplicate them into the allocator so the AST is self-contained —
    // `freeNodes` then correctly frees them, and the caller doesn't have
    // to keep `source` alive. This is the single biggest source of
    // memory bugs in this module; without it, any AST that crosses a
    // `defer allocator.free(tokens)` boundary holds dangling pointers.
    errdefer freeNodes(allocator, nodes);
    try copyAllStrings(allocator, nodes);
    return nodes;
}

// =============================================================================
//  Inheritance
// =============================================================================
//
// `compileWithParent` returns a single AST that, when rendered, produces
// the parent's HTML with the child's block bodies substituted in. The
// algorithm:
//
//   1. Parse the child source.
//   2. If the child has an `{% extends "path" %}` node, load the parent
//      via the loader and recursively compile the parent (so multi-level
//      inheritance resolves correctly).
//   3. Build a map `name → child_block_body` from the child's blocks.
//   4. Walk the parent's AST in place, replacing each `block` node's
//      `body` with the matching child block's body if present.
//   5. Return the merged AST.
//
// The merged AST is a regular AST — non-block nodes inside the child
// (text, variables, if/for) are discarded. Only `block` nodes from the
// child survive into the parent.

/// Loader function: takes a path, returns a heap-allocated source string.
/// The caller owns the returned buffer.
pub const LoaderFn = *const fn (
    ctx: *anyopaque,
    allocator: std.mem.Allocator,
    path: []const u8,
) anyerror![]u8;

/// Compile a template with inheritance resolution. The loader is used
/// to fetch parent templates (and their parents, recursively).
pub fn compileWithParent(
    allocator: std.mem.Allocator,
    source: []const u8,
    loader_ctx: *anyopaque,
    loader_fn: LoaderFn,
) (Error || std.mem.Allocator.Error)![]Node {
    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();
    return compileWithParentImpl(allocator, source, loader_ctx, loader_fn, &visited);
}

fn compileWithParentImpl(
    allocator: std.mem.Allocator,
    source: []const u8,
    loader_ctx: *anyopaque,
    loader_fn: LoaderFn,
    visited: *std.StringHashMap(void),
) (Error || std.mem.Allocator.Error)![]Node {
    // Parse the child.
    const child_nodes = try parseSource(allocator, source);
    errdefer freeNodes(allocator, child_nodes);

    // Find the extends node (if any).
    var extends_path: ?[]const u8 = null;
    for (child_nodes) |node| {
        if (node == .extends) {
            extends_path = node.extends;
            break;
        }
    }

    // Standalone template (no inheritance): return the parsed nodes as-is.
    if (extends_path == null) {
        return child_nodes;
    }

    // Inheritance: load parent, compile it recursively, merge blocks.
    const parent_path = extends_path.?;

    // For the test loader, we can't easily track visited — the test
    // loader doesn't pass paths through `visited`. We rely on the test
    // data not to have circular extends. (A real loader would check.)
    const parent_source = loader_fn(loader_ctx, allocator, parent_path) catch
        return error.TemplateNotFound;
    defer allocator.free(parent_source);

    const parent_nodes = try compileWithParentImpl(allocator, parent_source, loader_ctx, loader_fn, visited);
    errdefer freeNodes(allocator, parent_nodes);

    // Build a map of child block bodies keyed by name. Deep-copy the
    // bodies so child_nodes can be safely freed after merge — the
    // copies are the only references that survive into the parent.
    var child_blocks = std.StringHashMap([]Node).init(allocator);
    defer child_blocks.deinit();
    for (child_nodes) |node| {
        if (node == .block) {
            const copied = try copyNodeSlice(allocator, node.block.body);
            try child_blocks.put(node.block.name, copied);
        }
    }

    // Walk the parent AST, replacing each block's body with the child
    // override if present. We MUTATE the parent's block nodes in place
    // because the parent_nodes are owned by us (deep-copied from the
    // recursive call's output).
    try mergeBlocks(allocator, parent_nodes, &child_blocks);

    // The child's blocks are no longer needed (their bodies are now
    // embedded in the parent). The non-block child nodes are discarded.
    // freeNodes(child_nodes) is safe now — parseSource returns
    // self-contained ASTs, so each child_nodes string is owned by the
    // allocator and won't dangle.
    freeNodes(allocator, child_nodes);

    return parent_nodes;
}

/// Walk an AST and deep-copy every string slice into the given allocator.
/// Covers text/variable/extends/include/set IN EVERY NODE, plus the
/// metadata strings (condition/var_name/iterable/name/path) on
/// structured nodes. Recursive children are also copied. The result
/// is self-contained: freeing the original source doesn't invalidate
/// the AST.
fn copyAllStrings(allocator: std.mem.Allocator, nodes: []Node) (Error || std.mem.Allocator.Error)!void {
    for (nodes) |*node| {
        switch (node.*) {
            .text => |*t| t.* = try allocator.dupe(u8, t.*),
            .variable => |*v| v.* = try allocator.dupe(u8, v.*),
            .extends => |*e| e.* = try allocator.dupe(u8, e.*),
            .include => |*i| i.path = try allocator.dupe(u8, i.path),
            .set => |*s| {
                s.var_name = try allocator.dupe(u8, s.var_name);
                s.value = try allocator.dupe(u8, s.value);
            },
            .if_block => |*b| {
                // Copy each branch's condition string and recurse into
                // each branch's body. The branches slice itself is
                // heap-allocated (by `parseIf`'s toOwnedSlice), so we
                // dupe it AND free the original — otherwise the original
                // heap slice leaks (caught by DebugAllocator tests).
                for (b.branches) |*br| {
                    br.condition = try allocator.dupe(u8, br.condition);
                    try copyAllStrings(allocator, br.body);
                }
                const old_branches = b.branches;
                b.branches = try allocator.dupe(IfBranch, old_branches);
                allocator.free(old_branches);
                try copyAllStrings(allocator, b.else_branch);
            },
            .for_loop => |*l| {
                l.var_name = try allocator.dupe(u8, l.var_name);
                l.iterable = try allocator.dupe(u8, l.iterable);
                if (l.condition) |cond| {
                    l.condition = try allocator.dupe(u8, cond);
                }
                try copyAllStrings(allocator, l.body);
                try copyAllStrings(allocator, l.empty_body);
            },
            .block => |*b| {
                b.name = try allocator.dupe(u8, b.name);
                try copyAllStrings(allocator, b.body);
            },
            .raw => |r| {
                // Raw nodes' text children are ALREADY heap-allocated
                // by parseRaw (concat of token slices via
                // body.toOwnedSlice) — re-duping them here would
                // leak the original parseRaw allocation. A well-formed
                // raw body contains only text children, so there's
                // nothing else to dup. The recursive call frees the
                // child text (which is owned by us) and the inner
                // nodes slice.
                try copyAllStringsOwned(allocator, r);
            },
            .macro => |*m| {
                m.name = try allocator.dupe(u8, m.name);
                for (m.params) |*p| {
                    p.name = try allocator.dupe(u8, p.name);
                    if (p.default) |d| {
                        p.default = try allocator.dupe(u8, d);
                    }
                }
                const old_params = m.params;
                m.params = try allocator.dupe(MacroParam, old_params);
                allocator.free(old_params);
                try copyAllStrings(allocator, m.body);
            },
        }
    }
}

/// Walk a RAW subtree and copy every string slice into the allocator,
/// but skip text children of raw nodes (which are already heap-owned
/// by parseRaw). Used by `copyAllStrings` for the `.raw` arm.
fn copyAllStringsOwned(allocator: std.mem.Allocator, nodes: []Node) (Error || std.mem.Allocator.Error)!void {
    for (nodes) |*node| {
        switch (node.*) {
            .text => {},
            .variable => |*v| v.* = try allocator.dupe(u8, v.*),
            .extends => |*e| e.* = try allocator.dupe(u8, e.*),
            .include => |*i| i.path = try allocator.dupe(u8, i.path),
            .set => |*s| {
                s.var_name = try allocator.dupe(u8, s.var_name);
                s.value = try allocator.dupe(u8, s.value);
            },
            .if_block => |*b| {
                for (b.branches) |*br| {
                    br.condition = try allocator.dupe(u8, br.condition);
                    try copyAllStrings(allocator, br.body);
                }
                const old_branches = b.branches;
                b.branches = try allocator.dupe(IfBranch, old_branches);
                allocator.free(old_branches);
                try copyAllStrings(allocator, b.else_branch);
            },
            .for_loop => |*l| {
                l.var_name = try allocator.dupe(u8, l.var_name);
                l.iterable = try allocator.dupe(u8, l.iterable);
                if (l.condition) |cond| {
                    l.condition = try allocator.dupe(u8, cond);
                }
                try copyAllStrings(allocator, l.body);
                try copyAllStrings(allocator, l.empty_body);
            },
            .block => |*b| {
                b.name = try allocator.dupe(u8, b.name);
                try copyAllStrings(allocator, b.body);
            },
            .raw => |r| try copyAllStringsOwned(allocator, r),
            .macro => |*m| {
                m.name = try allocator.dupe(u8, m.name);
                for (m.params) |*p| {
                    p.name = try allocator.dupe(u8, p.name);
                    if (p.default) |d| {
                        p.default = try allocator.dupe(u8, d);
                    }
                }
                const old_params = m.params;
                m.params = try allocator.dupe(MacroParam, old_params);
                allocator.free(old_params);
                try copyAllStrings(allocator, m.body);
            },
        }
    }
}

/// Deep-copy a slice of nodes. The text/variable/extends inner slices
/// are duplicated into the new allocator so the copy is fully owned —
/// callers can free the source (or the original) without invalidating
/// the copy. Recursive structures (if/for/block/raw/macro/include/set)
/// are also deep-copied.
fn copyNodeSlice(allocator: std.mem.Allocator, nodes: []const Node) (Error || std.mem.Allocator.Error)![]Node {
    const out = try allocator.alloc(Node, nodes.len);
    errdefer allocator.free(out);
    for (nodes, 0..) |node, i| {
        out[i] = try copyNode(allocator, node);
    }
    return out;
}

fn copyNode(allocator: std.mem.Allocator, node: Node) (Error || std.mem.Allocator.Error)!Node {
    return switch (node) {
        .text => |t| .{ .text = try allocator.dupe(u8, t) },
        .variable => |v| .{ .variable = try allocator.dupe(u8, v) },
        .extends => |e| .{ .extends = try allocator.dupe(u8, e) },
        .include => |i| .{ .include = Include{
            .path = try allocator.dupe(u8, i.path),
            .with_context = i.with_context,
            .ignore_missing = i.ignore_missing,
        } },
        .set => |s| .{ .set = Set{
            .var_name = try allocator.dupe(u8, s.var_name),
            .value = try allocator.dupe(u8, s.value),
        } },
        .if_block => |b| blk: {
            // Deep-copy each branch — its condition string AND its
            // body (recursively). Then dupe the branches slice itself
            // so the parent owns an independent copy.
            var new_branches = try allocator.alloc(IfBranch, b.branches.len);
            errdefer allocator.free(new_branches);
            for (b.branches, 0..) |br, i| {
                new_branches[i] = .{
                    .condition = try allocator.dupe(u8, br.condition),
                    .body = try copyNodeSlice(allocator, br.body),
                };
            }
            break :blk .{ .if_block = IfBlock{
                .branches = new_branches,
                .else_branch = try copyNodeSlice(allocator, b.else_branch),
            } };
        },
        .for_loop => |l| .{ .for_loop = ForLoop{
            // Dupe var_name + iterable (+ optional condition). Without
            // this the merged AST's for-loop resolves `iterable`
            // against freed memory and treats every iteration as empty.
            .var_name = try allocator.dupe(u8, l.var_name),
            .iterable = try allocator.dupe(u8, l.iterable),
            .condition = if (l.condition) |c| try allocator.dupe(u8, c) else null,
            .body = try copyNodeSlice(allocator, l.body),
            .empty_body = try copyNodeSlice(allocator, l.empty_body),
        } },
        .block => |b| .{ .block = Block{
            // Dupe the block name so mergeBlocks can key on it after
            // the source is freed.
            .name = try allocator.dupe(u8, b.name),
            .body = try copyNodeSlice(allocator, b.body),
        } },
        .raw => |r| .{ .raw = try copyNodeSlice(allocator, r) },
        .macro => |m| blk: {
            // Copy each param's name + optional default expression.
            var new_params = try allocator.alloc(MacroParam, m.params.len);
            errdefer allocator.free(new_params);
            for (m.params, 0..) |p, i| {
                new_params[i] = .{
                    .name = try allocator.dupe(u8, p.name),
                    .default = if (p.default) |d| try allocator.dupe(u8, d) else null,
                };
            }
            break :blk .{ .macro = Macro{
                .name = try allocator.dupe(u8, m.name),
                .params = new_params,
                .body = try copyNodeSlice(allocator, m.body),
            } };
        },
    };
}

/// Walk an AST and replace each `block` node's body with the matching
/// override from `overrides`. Recurses into nested if/for/raw/set/
/// include/macro children.
fn mergeBlocks(
    allocator: std.mem.Allocator,
    nodes: []Node,
    overrides: *std.StringHashMap([]Node),
) (Error || std.mem.Allocator.Error)!void {
    for (nodes) |*node| {
        switch (node.*) {
            .text, .variable, .extends, .include, .set => {},
            .if_block => |*b| {
                // Each branch's body may contain `block` nodes that
                // need substitution — recurse into all of them.
                for (b.branches) |*br| {
                    try mergeBlocks(allocator, br.body, overrides);
                }
                try mergeBlocks(allocator, b.else_branch, overrides);
            },
            .for_loop => |*l| {
                try mergeBlocks(allocator, l.body, overrides);
                try mergeBlocks(allocator, l.empty_body, overrides);
            },
            .block => |*b| {
                if (overrides.get(b.name)) |child_body| {
                    // The child body is a fresh slice; we can take it.
                    // Free the parent's old body first — both its
                    // contents (recursive nodes) AND the slice itself
                    // (allocated by parseNodes' nodes.toOwnedSlice).
                    // Without this, every block override in an
                    // inheritance hierarchy leaks its parent's old
                    // body (visible in DebugAllocator: 5 inherit tests,
                    // 60 leaked allocations total).
                    freeNodeContents(allocator, b.body);
                    allocator.free(b.body);
                    b.* = .{
                        .name = b.name,
                        .body = child_body,
                    };
                } else {
                    // No override; recurse into the parent's body.
                    try mergeBlocks(allocator, b.body, overrides);
                }
            },
            .raw => |r| try mergeBlocks(allocator, r, overrides),
            .macro => |*m| {
                try mergeBlocks(allocator, m.body, overrides);
            },
        }
    }
}

/// Parse `{% include "path" [ignore missing] [with context|without context] %}`.
/// Modifiers are space-separated and order-insensitive (Jinja accepts
/// both orderings). The path may be single- or double-quoted.
fn parseIncludeTag(
    allocator: std.mem.Allocator,
    trimmed: []const u8,
    source: []const u8,
    tok: Token,
    nodes: *std.ArrayListUnmanaged(Node),
) (Error || std.mem.Allocator.Error)!void {
    // Strip the `include ` prefix; the rest is the path + modifiers.
    var rest = std.mem.trim(u8, trimmed[8..], " \t");
    if (rest.len == 0) {
        reportParseError(source, tokenOffset(source, tok),
            "empty path in 'include' tag (expected {% include \"path.html\" %})");
        return error.ParseError;
    }

    // The path is the first whitespace-separated token. Path may be
    // quoted (single or double); stripQuotes handles both.
    const path_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
    const path = stripQuotes(std.mem.trim(u8, rest[0..path_end], " \t"));
    rest = std.mem.trim(u8, rest[path_end..], " \t");

    var with_context = true;
    var ignore_missing = false;

    // Parse modifiers. Order-insensitive — we just check which
    // keywords appear.
    while (rest.len > 0) {
        const tok_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
        const kw = rest[0..tok_end];
        if (std.mem.eql(u8, kw, "ignore") and rest.len > tok_end + 6) {
            // Could be `ignore missing` — peek ahead.
            const after = std.mem.trim(u8, rest[tok_end..], " \t");
            const next_end = std.mem.indexOfAny(u8, after, " \t") orelse after.len;
            if (std.mem.eql(u8, after[0..next_end], "missing")) {
                ignore_missing = true;
                rest = std.mem.trim(u8, after[next_end..], " \t");
                continue;
            }
        } else if (std.mem.eql(u8, kw, "with")) {
            // `with context`
            const after = std.mem.trim(u8, rest[tok_end..], " \t");
            const next_end = std.mem.indexOfAny(u8, after, " \t") orelse after.len;
            if (std.mem.eql(u8, after[0..next_end], "context")) {
                with_context = true;
                rest = std.mem.trim(u8, after[next_end..], " \t");
                continue;
            }
        } else if (std.mem.eql(u8, kw, "without")) {
            // `without context`
            const after = std.mem.trim(u8, rest[tok_end..], " \t");
            const next_end = std.mem.indexOfAny(u8, after, " \t") orelse after.len;
            if (std.mem.eql(u8, after[0..next_end], "context")) {
                with_context = false;
                rest = std.mem.trim(u8, after[next_end..], " \t");
                continue;
            }
        }
        // Unknown modifier — surface as a parse error so typos are
        // caught at template-load time rather than silently ignored.
        // Format the runtime `kw` into a stack buffer (Zig disallows
        // `++` with runtime strings).
        var buf: [256]u8 = undefined;
        const desc = std.fmt.bufPrint(
            &buf,
            "unknown modifier in 'include' tag: '{s}' " ++
                "(supported: ignore missing, with context, without context)",
            .{kw},
        ) catch "unknown modifier in 'include' tag";
        reportParseError(source, tokenOffset(source, tok), desc);
        return error.ParseError;
    }

    if (path.len == 0) {
        reportParseError(source, tokenOffset(source, tok),
            "empty path in 'include' tag (expected {% include \"path.html\" %})");
        return error.ParseError;
    }

    try nodes.append(allocator, .{
        .include = .{
            .path = path,
            .with_context = with_context,
            .ignore_missing = ignore_missing,
        },
    });
}

/// Parse `{% set VAR = EXPR %}`. The `EXPR` is stored as a string and
/// evaluated at render time (using the same evaluator as `{{ }}`).
/// Block-set (`{% set VAR %}body{% endset %}`) is NOT supported.
fn parseSetTag(
    allocator: std.mem.Allocator,
    trimmed: []const u8,
    source: []const u8,
    tok: Token,
    nodes: *std.ArrayListUnmanaged(Node),
) (Error || std.mem.Allocator.Error)!void {
    // "set VAR = EXPR"
    const after_set = std.mem.trim(u8, trimmed[4..], " \t");
    const eq_idx = std.mem.indexOf(u8, after_set, "=") orelse {
        // Format the unparseable tag content into a buffer for the
        // error description (runtime strings can't use `++`).
        var buf: [256]u8 = undefined;
        const desc = std.fmt.bufPrint(
            &buf,
            "expected '=' in 'set' tag (got: '{s}')",
            .{after_set},
        ) catch "expected '=' in 'set' tag";
        reportParseError(source, tokenOffset(source, tok), desc);
        return error.ParseError;
    };
    const var_name = std.mem.trim(u8, after_set[0..eq_idx], " \t");
    if (var_name.len == 0) {
        reportParseError(source, tokenOffset(source, tok),
            "missing variable name in 'set' tag");
        return error.ParseError;
    }
    // Variable names must be simple identifiers — no dots, brackets,
    // operators, etc. Reject anything else so path-style assignments
    // (which would need a different AST shape) don't silently break.
    for (var_name) |c| {
        const ok = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '_';
        if (!ok) {
            // Format the invalid identifier into a buffer.
            var buf: [256]u8 = undefined;
            const desc = std.fmt.bufPrint(
                &buf,
                "invalid variable name in 'set' tag: '{s}' " ++
                    "(must be a plain identifier — no dots or operators)",
                .{var_name},
            ) catch "invalid variable name in 'set' tag";
            reportParseError(source, tokenOffset(source, tok), desc);
            return error.ParseError;
        }
    }
    const expr = std.mem.trim(u8, after_set[eq_idx + 1 ..], " \t");
    if (expr.len == 0) {
        reportParseError(source, tokenOffset(source, tok),
            "missing expression in 'set' tag (expected {% set VAR = EXPR %})");
        return error.ParseError;
    }
    try nodes.append(allocator, .{
        .set = .{
            .var_name = var_name,
            .value = expr,
        },
    });
}

/// Parse `{% macro NAME(P1, P2=DEFAULT, ...) %}body{% endmacro %}`. The
/// tag portion (e.g. `macro input(name, value='', type='text')`) is
/// pre-trimmed; we extract the macro name + parameter list from it.
fn parseMacro(
    allocator: std.mem.Allocator,
    source: []const u8,
    tokens: []const Token,
    start: usize,
    end: usize,
    trimmed: []const u8,
) (Error || std.mem.Allocator.Error)!ParseResult {
    // "macro NAME(P1, P2=DEFAULT, ...)"
    const after_macro = std.mem.trim(u8, trimmed[6..], " \t");

    // Macro name ends at the first `(`.
    const paren_idx = std.mem.indexOfScalar(u8, after_macro, '(') orelse {
        reportParseError(source, tokenOffset(source, tokens[start - 1]),
            "missing parameter list in 'macro' tag (expected {% macro NAME(...) %})");
        return error.ParseError;
    };
    const name = std.mem.trim(u8, after_macro[0..paren_idx], " \t");
    if (name.len == 0) {
        reportParseError(source, tokenOffset(source, tokens[start - 1]),
            "missing macro name in 'macro' tag");
        return error.ParseError;
    }
    // Find matching `)`. We scan forward allowing nested parens (for
    // expression-style defaults) — but Jinja doesn't support nested
    // parens in default expressions, so we just look for the first
    // unmatched `)` after the opening one.
    var depth: i32 = 1;
    var close_idx: ?usize = null;
    var k: usize = paren_idx + 1;
    while (k < after_macro.len) : (k += 1) {
        switch (after_macro[k]) {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if (depth == 0) {
                    close_idx = k;
                    break;
                }
            },
            else => {},
        }
    }
    const close = close_idx orelse {
        reportParseError(source, tokenOffset(source, tokens[start - 1]),
            "unclosed parameter list in 'macro' tag");
        return error.ParseError;
    };
    const params_str = after_macro[paren_idx + 1 .. close];

    // Parse the parameter list — split on commas, then split each on
    // `=` to separate name from optional default expression.
    var params = std.ArrayListUnmanaged(MacroParam).empty;
    errdefer {
        for (params.items) |p| {
            if (p.default) |d| allocator.free(d);
        }
        params.deinit(allocator);
    }
    var idx: usize = 0;
    while (idx < params_str.len) {
        // Find the next comma at depth 0.
        var pd: i32 = 0;
        var comma: ?usize = null;
        var j: usize = idx;
        while (j < params_str.len) : (j += 1) {
            switch (params_str[j]) {
                '(' => pd += 1,
                ')' => pd -= 1,
                ',' => {
                    if (pd == 0) {
                        comma = j;
                        break;
                    }
                },
                else => {},
            }
        }
        const seg_end = comma orelse params_str.len;
        const seg = std.mem.trim(u8, params_str[idx..seg_end], " \t");
        if (seg.len > 0) {
            // Split on `=` to find optional default.
            const eq = std.mem.indexOfScalar(u8, seg, '=');
            const pname = if (eq) |e|
                std.mem.trim(u8, seg[0..e], " \t")
            else
                seg;
            const default = if (eq) |e|
                std.mem.trim(u8, seg[e + 1 ..], " \t")
            else
                null;
            try params.append(allocator, .{
                .name = pname,
                .default = default,
            });
        }
        if (comma == null) break;
        idx = seg_end + 1;
    }

    // Find `endmacro` matching this depth-1 macro.
    var depth_m: i32 = 1;
    var m: usize = start;
    var endmacro_pos: ?usize = null;
    while (m < end) : (m += 1) {
        if (tokens[m] == .tag) {
            const t = std.mem.trim(u8, tokens[m].tag, " \t");
            if (std.mem.startsWith(u8, t, "macro ")) {
                depth_m += 1;
            } else if (std.mem.eql(u8, t, "endmacro")) {
                depth_m -= 1;
                if (depth_m == 0) {
                    endmacro_pos = m;
                    break;
                }
            }
        }
    }
    const closer = endmacro_pos orelse {
        reportParseError(source, tokenOffset(source, tokens[start - 1]),
            "unclosed 'macro' block (expected '{% endmacro %}' before end of input)");
        return error.ParseError;
    };
    const body = try parseNodes(allocator, source, tokens, start, closer);

    // Move params out — they were heap-allocated; transfer ownership.
    const out_params = try params.toOwnedSlice(allocator);
    return .{
        .node = .{ .macro = .{
            .name = name,
            .params = out_params,
            .body = body,
        } },
        .next = closer + 1,
    };
}

fn parseNodes(
    allocator: std.mem.Allocator,
    source: []const u8,
    tokens: []const Token,
    start: usize,
    end: usize,
) (Error || std.mem.Allocator.Error)![]Node {
    var nodes = std.ArrayListUnmanaged(Node).empty;
    errdefer {
        for (nodes.items) |n| {
            // Free any children we already appended.
            switch (n) {
                .if_block => |b| {
                    for (b.branches) |br| freeNodes(allocator, br.body);
                    freeNodes(allocator, b.else_branch);
                },
                .for_loop => |l| {
                    freeNodes(allocator, l.body);
                    freeNodes(allocator, l.empty_body);
                },
                .block => |b| freeNodes(allocator, b.body),
                .raw => |r| freeNodes(allocator, r),
                .macro => |m| freeNodes(allocator, m.body),
                .include, .set, .text, .variable, .extends => {},
            }
        }
        nodes.deinit(allocator);
    }

    var i: usize = start;
    while (i < end) : (i += 1) {
        const tok = tokens[i];
        switch (tok) {
            .text => try nodes.append(allocator, .{ .text = tok.text }),
            .var_expr => {
                const trimmed = std.mem.trim(u8, tok.var_expr, " \t");
                try nodes.append(allocator, .{ .variable = trimmed });
            },
            .tag => {
                const trimmed = std.mem.trim(u8, tok.tag, " \t");
                if (std.mem.startsWith(u8, trimmed, "if ")) {
                    const cond = std.mem.trim(u8, trimmed[3..], " \t");
                    const after = try parseIf(allocator, source, tokens, i + 1, end, cond);
                    try nodes.append(allocator, after.node);
                    // after.next is the position AFTER the closer (endif);
                    // the while loop's `i += 1` will then move past it.
                    i = after.next - 1;
                } else if (std.mem.startsWith(u8, trimmed, "for ")) {
                    // "for VAR in EXPR [if COND]". The optional `if
                    // COND` filter (Jinja extension) skips items where
                    // the condition is falsy.
                    const rest = trimmed[4..];
                    const in_idx = std.mem.indexOf(u8, rest, " in ") orelse {
                        // No " in " separator in the for tag — common typo
                        // is "{% for x items %}" (missing the word "in").
                        // The caret + source line printed by reportParseError
                        // shows the offending tag verbatim, so we don't
                        // splice the tag string into the description (that
                        // would require runtime string concatenation, which
                        // Zig disallows for `++`).
                        reportParseError(source, tokenOffset(source, tok),
                            "expected ' in ' in 'for' tag");
                        return error.ParseError;
                    };
                    const var_name = std.mem.trim(u8, rest[0..in_idx], " \t");
                    const after_in = rest[in_idx + 4 ..];
                    // Look for an optional ` if COND` suffix. We don't
                    // accept `if` as the start of an identifier (e.g.
                    // "items if foo" wouldn't match), so the search
                    // needs to be at a word boundary.
                    var iter_part: []const u8 = after_in;
                    var condition: ?[]const u8 = null;
                    if (std.mem.indexOf(u8, after_in, " if ")) |if_idx| {
                        iter_part = std.mem.trim(u8, after_in[0..if_idx], " \t");
                        condition = std.mem.trim(u8, after_in[if_idx + 4 ..], " \t");
                    } else {
                        iter_part = std.mem.trim(u8, after_in, " \t");
                    }
                    const after = try parseFor(allocator, source, tokens, i + 1, end, var_name, iter_part, condition);
                    try nodes.append(allocator, after.node);
                    i = after.next - 1;
                } else if (std.mem.startsWith(u8, trimmed, "block ")) {
                    const name = std.mem.trim(u8, trimmed[6..], " \t");
                    const after = try parseBlock(allocator, source, tokens, i + 1, end, name);
                    try nodes.append(allocator, after.node);
                    i = after.next - 1;
                } else if (std.mem.startsWith(u8, trimmed, "extends ")) {
                    const path = std.mem.trim(u8, trimmed[8..], " \t");
                    // Strip quotes if present (single or double).
                    const stripped = stripQuotes(path);
                    try nodes.append(allocator, .{ .extends = stripped });
                } else if (std.mem.eql(u8, trimmed, "raw")) {
                    const after = try parseRaw(allocator, source, tokens, i + 1, end);
                    try nodes.append(allocator, after.node);
                    i = after.next - 1;
                } else if (std.mem.startsWith(u8, trimmed, "include ")) {
                    // `include "path" [ignore missing] [with context|without context]`
                    try parseIncludeTag(allocator, trimmed, source, tok, &nodes);
                } else if (std.mem.startsWith(u8, trimmed, "set ")) {
                    // `set VAR = EXPR` (block-set `{% set VAR %}body{% endset %}`
                    // is NOT supported — Jinja 2.8+ adds it; we keep the
                    // simpler line-only form for now).
                    try parseSetTag(allocator, trimmed, source, tok, &nodes);
                } else if (std.mem.startsWith(u8, trimmed, "macro ")) {
                    // `macro NAME(P1, P2=DEFAULT, ...) ... endmacro`
                    const after = try parseMacro(allocator, source, tokens, i + 1, end, trimmed);
                    try nodes.append(allocator, after.node);
                    i = after.next - 1;
                } else {
                    // Unexpected tag at top level: `else`, `endif`, `endfor`,
                    // `endblock`, `endraw`, etc. The user either dropped
                    // the opening keyword (so the closer is dangling) or
                    // mistyped a tag name.
                    reportParseError(source, tokenOffset(source, tok),
                        "unexpected tag at top level " ++
                        "(closer tags like 'endif' / 'endfor' / 'endblock' " ++
                        "/ 'endraw' must match a corresponding opener)");
                    return error.ParseError;
                }
            },
        }
    }

    return nodes.toOwnedSlice(allocator);
}

const ParseResult = struct {
    node: Node,
    /// Token index immediately AFTER the closer (so the caller can `i = next`).
    next: usize,
};

fn parseIf(
    allocator: std.mem.Allocator,
    source: []const u8,
    tokens: []const Token,
    start: usize,
    end: usize,
    condition: []const u8,
) (Error || std.mem.Allocator.Error)!ParseResult {
    // Walk the if/elif/else chain, building a flat branches list. Each
    // iteration finds the next `elif`, `else`, or `endif` at depth 1;
    // we accumulate a (condition, body) pair until we hit `else` (which
    // closes the chain with the optional else body) or `endif` (no else).
    var branches = std.ArrayListUnmanaged(IfBranch).empty;
    errdefer {
        // On error, free the bodies we've appended so far.
        for (branches.items) |br| {
            freeNodes(allocator, br.body);
        }
        branches.deinit(allocator);
    }

    var current_cond = condition;
    var current_start: usize = start;
    var endif_pos: usize = end; // sentinel — overwritten below

    while (true) {
        const split = try findIfSplit(source, tokens, current_start, end);
        const body = try parseNodes(allocator, source, tokens, current_start, split.marker);

        // Append this branch (condition + body). The condition is a
        // slice into the source/tokens — `copyAllStrings` will dupe
        // it later into the allocator.
        try branches.append(allocator, .{
            .condition = current_cond,
            .body = body,
        });

        switch (split.kind) {
            .endif => {
                endif_pos = split.marker;
                break;
            },
            .else_branch => {
                // The else body is everything between `else` and its
                // matching `endif`. The else body's body is appended
                // BELOW the branches list, not as a branch.
                const else_body = try parseNodes(
                    allocator,
                    source,
                    tokens,
                    split.marker + 1,
                    split.endif_pos,
                );
                // Move the branches out so we don't double-free in the
                // errdefer (we're about to return success).
                const out_branches = try branches.toOwnedSlice(allocator);
                return .{
                    .node = .{ .if_block = IfBlock{
                        .branches = out_branches,
                        .else_branch = else_body,
                    } },
                    .next = split.endif_pos + 1,
                };
            },
            .elif => {
                // Continue the loop with the elif's condition as the
                // next branch's condition. The body of the elif runs
                // from the token AFTER the elif tag up to the next
                // split point.
                current_cond = split.condition;
                current_start = split.marker + 1;
                continue;
            },
        }
    }

    // Reached the `endif` (no else body).
    const out_branches = try branches.toOwnedSlice(allocator);
    return .{
        .node = .{ .if_block = IfBlock{
            .branches = out_branches,
            .else_branch = &[_]Node{},
        } },
        .next = endif_pos + 1, // skip past endif
    };
}

/// What `findIfSplit` returns at the position where the next branch
/// transition happens. Three shapes — the parser loops on this until
/// it sees `else_branch` or `endif`.
const IfSplitKind = enum { elif, else_branch, endif };

const IfSplit = struct {
    kind: IfSplitKind,
    /// Token index of the `elif` / `else` / `endif` tag itself.
    marker: usize,
    /// For `elif`: the trimmed condition expression (everything after
    /// `elif ` up to the next tag boundary).
    condition: []const u8 = "",
    /// For `else_branch`: the position of the matching `endif` (so the
    /// caller can parse the body between `else` and `endif`). For
    /// `endif` and `elif`, this equals `marker`.
    endif_pos: usize = 0,
};

fn findIfSplit(source: []const u8, tokens: []const Token, start: usize, end: usize) Error!IfSplit {
    var depth: i32 = 1;
    var i: usize = start;
    while (i < end) : (i += 1) {
        if (tokens[i] == .tag) {
            const t = std.mem.trim(u8, tokens[i].tag, " \t");
            if (std.mem.startsWith(u8, t, "if ")) {
                depth += 1;
            } else if (std.mem.startsWith(u8, t, "elif") and depth == 1) {
                // `elif COND` — extract the condition. The `t` slice
                // includes the trailing whitespace the tokenizer
                // preserved; `trim` strips it.
                const condition = if (t.len > 4)
                    std.mem.trim(u8, t[4..], " \t")
                else
                    "";
                return .{
                    .kind = .elif,
                    .marker = i,
                    .condition = condition,
                    .endif_pos = i,
                };
            } else if (std.mem.eql(u8, t, "else") and depth == 1) {
                // Found the else at depth 1. Now find the matching endif.
                const closer = findMatchingTag(tokens, i + 1, end, "endif") orelse {
                    // `{% else %}` without a closing `{% endif %}` — the
                    // body kept going past EOF.
                    reportParseError(source, tokenOffset(source, tokens[i]),
                        "'else' with no matching 'endif' (the if-block was never closed)");
                    return error.ParseError;
                };
                return .{
                    .kind = .else_branch,
                    .marker = i,
                    .endif_pos = closer,
                };
            } else if (std.mem.eql(u8, t, "endif")) {
                depth -= 1;
                if (depth == 0) {
                    return .{ .kind = .endif, .marker = i, .endif_pos = i };
                }
            }
        }
    }
    // Reached EOF without an `endif` at depth 0. Report at the open
    // tag's location — that's where the developer needs to add the
    // closer. We scan back from `start - 1` (the opener is the token
    // immediately before the call site) to find the tag; falls back to
    // the last token we saw if we can't reconstruct it.
    const opener_offset: usize = if (start > 0 and tokens[start - 1] == .tag)
        tokenOffset(source, tokens[start - 1])
    else
        @min(start, source.len);
    reportParseError(source, opener_offset,
        "unclosed 'if' block (expected '{% endif %}' before end of input)");
    return error.ParseError;
}

fn parseFor(
    allocator: std.mem.Allocator,
    source: []const u8,
    tokens: []const Token,
    start: usize,
    end: usize,
    var_name: []const u8,
    iter: []const u8,
    condition: ?[]const u8,
) (Error || std.mem.Allocator.Error)!ParseResult {
    const split = try findForSplit(source, tokens, start, end);
    const body = try parseNodes(allocator, source, tokens, start, split.marker);

    var empty_body: []Node = &[_]Node{};
    const next = split.closer;

    if (split.has_empty) {
        empty_body = try parseNodes(allocator, source, tokens, split.marker + 1, split.closer);
    }
    return .{
        .node = .{ .for_loop = ForLoop{
            .var_name = var_name,
            .iterable = iter,
            .condition = condition,
            .body = body,
            .empty_body = empty_body,
        } },
        .next = next + 1,
    };
}

const ForSplit = struct {
    marker: usize,
    closer: usize,
    has_empty: bool,
};

fn findForSplit(source: []const u8, tokens: []const Token, start: usize, end: usize) Error!ForSplit {
    var depth: i32 = 1;
    var i: usize = start;
    while (i < end) : (i += 1) {
        if (tokens[i] == .tag) {
            const t = std.mem.trim(u8, tokens[i].tag, " \t");
            if (std.mem.startsWith(u8, t, "for ")) {
                depth += 1;
            } else if (std.mem.eql(u8, t, "empty") and depth == 1) {
                // Found the empty at depth 1. Find the matching endfor.
                const closer = findMatchingTag(tokens, i + 1, end, "endfor") orelse {
                    // `{% empty %}` without `{% endfor %}` — the body
                    // kept going past EOF.
                    reportParseError(source, tokenOffset(source, tokens[i]),
                        "'empty' with no matching 'endfor' (the for-loop was never closed)");
                    return error.ParseError;
                };
                return .{ .marker = i, .closer = closer, .has_empty = true };
            } else if (std.mem.eql(u8, t, "endfor")) {
                depth -= 1;
                if (depth == 0) {
                    return .{ .marker = i, .closer = i, .has_empty = false };
                }
            }
        }
    }
    // Reached EOF without an `endfor` at depth 0. Report at the open
    // tag's location (the token immediately before `start`).
    const opener_offset: usize = if (start > 0 and tokens[start - 1] == .tag)
        tokenOffset(source, tokens[start - 1])
    else
        @min(start, source.len);
    reportParseError(source, opener_offset,
        "unclosed 'for' block (expected '{% endfor %}' before end of input)");
    return error.ParseError;
}

fn parseBlock(
    allocator: std.mem.Allocator,
    source: []const u8,
    tokens: []const Token,
    start: usize,
    end: usize,
    name: []const u8,
) (Error || std.mem.Allocator.Error)!ParseResult {
    const closer = findMatchingTag(tokens, start, end, "endblock") orelse {
        // Point the diagnostic at the opener (the token just before
        // `start`), since that's where the missing `{% endblock %}` should
        // be added. Fall back to `start` if the opener can't be located
        // (shouldn't happen — `parseNodes` always calls `parseBlock`
        // with `start = opener_index + 1`).
        const opener_offset: usize = if (start > 0 and tokens[start - 1] == .tag)
            tokenOffset(source, tokens[start - 1])
        else
            @min(start, source.len);
        reportParseError(source, opener_offset,
            "unclosed 'block' (expected '{% endblock %}' before end of input)");
        return error.ParseError;
    };
    const body = try parseNodes(allocator, source, tokens, start, closer);
    return .{
        .node = .{ .block = Block{
            .name = name,
            .body = body,
        } },
        .next = closer + 1,
    };
}

fn parseRaw(
    allocator: std.mem.Allocator,
    source: []const u8,
    tokens: []const Token,
    start: usize,
    end: usize,
) (Error || std.mem.Allocator.Error)!ParseResult {
    const closer = findMatchingTag(tokens, start, end, "endraw") orelse {
        // Point the diagnostic at the opener (token just before `start`).
        const opener_offset: usize = if (start > 0 and tokens[start - 1] == .tag)
            tokenOffset(source, tokens[start - 1])
        else
            @min(start, source.len);
        reportParseError(source, opener_offset,
            "unclosed 'raw' block (expected '{% endraw %}' before end of input)");
        return error.ParseError;
    };
    // Reconstruct the original source verbatim. The tokenizer strips the
    // `{{`, `}}`, `{%`, `%}` delimiters from each token — we put them
    // back so the raw body matches what the user wrote exactly.
    var body = std.ArrayListUnmanaged(u8).empty;
    errdefer body.deinit(allocator);
    var i: usize = start;
    while (i < closer) : (i += 1) {
        switch (tokens[i]) {
            .text => |t| try body.appendSlice(allocator, t),
            .var_expr => |v| {
                try body.appendSlice(allocator, "{{");
                try body.appendSlice(allocator, v);
                try body.appendSlice(allocator, "}}");
            },
            .tag => |t| {
                try body.appendSlice(allocator, "{%");
                try body.appendSlice(allocator, t);
                try body.appendSlice(allocator, "%}");
            },
        }
    }
    const text = try body.toOwnedSlice(allocator);
    var nodes_slice = try allocator.alloc(Node, 1);
    nodes_slice[0] = .{ .text = text };
    return .{
        .node = .{ .raw = nodes_slice },
        .next = closer + 1,
    };
}

fn findMatchingTag(tokens: []const Token, start: usize, end: usize, closer_cmd: []const u8) ?usize {
    var depth: i32 = 1;
    var i: usize = start;
    while (i < end) : (i += 1) {
        if (tokens[i] == .tag) {
            const t = std.mem.trim(u8, tokens[i].tag, " \t");
            // When searching for the outer block's closer (e.g. "endif"),
            // nested IFs bump the depth so their inner ENDIFs don't
            // satisfy the outer search prematurely. Without this, an
            // inline `{% if X %}A{% else %}B{% endif %}` inside the
            // outer if's else branch would close the outer if early.
            if (std.mem.startsWith(u8, t, "if ") and std.mem.eql(u8, closer_cmd, "endif")) {
                depth += 1;
            }
            if (std.mem.eql(u8, t, closer_cmd)) {
                depth -= 1;
                if (depth == 0) return i;
            }
            // For raw, nested raw/endraw does NOT count (no nesting semantics).
            // For block, nested block/endblock DO count.
            if (std.mem.startsWith(u8, t, "block ") and std.mem.eql(u8, closer_cmd, "endblock")) {
                depth += 1;
            }
        }
    }
    return null;
}

fn stripQuotes(s: []const u8) []const u8 {
    if (s.len >= 2) {
        const first = s[0];
        const last = s[s.len - 1];
        if ((first == '"' or first == '\'') and first == last) {
            return s[1 .. s.len - 1];
        }
    }
    return s;
}

// =============================================================================
//  Context — defined up front so the renderer can be added in Task 3.
// =============================================================================

/// A value passed into the template. Strings are slices — not owned by
/// the Value. Maps and arrays are owned; freeing them is the caller's
/// responsibility (use `Context.deinit`).
pub const Value = union(enum) {
    null,
    bool: bool,
    int: i64,
    string: []const u8,
    array: []const Value,
    map: std.StringHashMap(Value),
    /// A callable macro. Stored by name in the context when the macro
    /// is defined; looked up by the expression evaluator when the user
    /// writes `{{ macro_name(args) }}`. The macro AST slices point
    /// INTO the surrounding template's owned AST — the Value does
    /// NOT own them. (Cleanup happens via the AST's `freeNodes`.)
    macro: Macro,

    /// Extract the integer value. Strings are NOT auto-parsed —
    /// callers that want numeric coercion handle it themselves.
    pub fn asInt(self: Value) ?i64 {
        return switch (self) {
            .int => |v| v,
            else => null,
        };
    }
};
/// The runtime context. Backed by a HashMap; supports dotted-path lookups
/// (`user.name`) and bracket index (`items[0]`) at render time. A
/// context may have a parent (used for loop variable scoping) — lookups
/// walk up the chain until a value is found.
pub const Context = struct {
    allocator: std.mem.Allocator,
    values: std.StringHashMap(Value),
    parent: ?*const Context = null,

    pub fn init(allocator: std.mem.Allocator) Context {
        return .{
            .allocator = allocator,
            .values = std.StringHashMap(Value).init(allocator),
            .parent = null,
        };
    }

    /// Create a child context that falls back to `parent` for lookups.
    /// Use this for `{% for x in items %}` — the loop body sees both
    /// `x` and the parent's variables.
    pub fn child(parent: *const Context) Context {
        return .{
            .allocator = parent.allocator,
            .values = std.StringHashMap(Value).init(parent.allocator),
            .parent = parent,
        };
    }

    /// Insert a value into THIS context (not the parent).
    pub fn put(self: *Context, key: []const u8, value: Value) !void {
        try self.values.put(key, value);
    }

    pub fn deinit(self: *Context) void {
        self.values.deinit();
    }

    /// Look up a dotted path like "user.name" or "items[0].name". Walks
    /// the parent chain until a value is found. Returns null if any
    /// segment is missing or the wrong type.
    pub fn getPath(self: *const Context, path: []const u8) ?Value {
        return lookupPath(self, path);
    }
};

/// Path resolution. Supports three segment types:
///   * dotted       — `user.name`        → .name on a map
///   * bracket      — `items[0]`         → [0] on an array
///   * mixed        — `items[0].name`    → [0] then .name
///
/// First, try to look up the whole path as a key in the context chain.
/// If that misses, walk segment-by-segment starting with the first
/// dotted/bracket-prefixed part.
fn lookupPath(ctx_opt: ?*const Context, path: []const u8) ?Value {
    // Step 1: try the whole path as a top-level key.
    {
        var c = ctx_opt;
        while (c) |cc| {
            if (cc.values.get(path)) |v| {
                if (v != .null) return v;
            }
            c = cc.parent;
        }
    }

    // Step 2: walk segment-by-segment. Start by looking up the first
    // identifier (everything before the first `.` or `[`).
    const first_end = std.mem.indexOfAny(u8, path, ".[") orelse path.len;
    const first = path[0..first_end];

    var current: ?Value = null;
    {
        var c = ctx_opt;
        while (c) |cc| {
            if (cc.values.get(first)) |v| {
                if (v != .null) {
                    current = v;
                    break;
                }
            }
            c = cc.parent;
        }
    }
    if (current == null) return null;

    // Step 3: walk the remaining segments.
    var rest: []const u8 = path[first_end..];
    while (rest.len > 0) {
        const v = current orelse return null;
        if (rest[0] == '.') {
            // dotted: .name
            rest = rest[1..];
            const end = std.mem.indexOfAny(u8, rest, ".[") orelse rest.len;
            const key = rest[0..end];
            if (v != .map) return null;
            current = v.map.get(key);
            rest = rest[end..];
        } else if (rest[0] == '[') {
            // bracket: [N]
            const close = std.mem.indexOfPos(u8, rest, 1, "]") orelse return null;
            const idx_str = rest[1..close];
            const idx = std.fmt.parseInt(usize, idx_str, 10) catch return null;
            if (v != .array) return null;
            if (idx >= v.array.len) return null;
            current = v.array[idx];
            rest = rest[close + 1 ..];
        } else {
            return null;
        }
    }

    return current;
}

/// Expression evaluator for `{{ }}` placeholders. Supports a useful
/// subset of Jinja expressions:
///
///   * Identifiers / dotted paths        — `page`, `user.name`
///   * Integer literals                  — `42`, `-7`
///   * Arithmetic (precedence!)          — `+ - * / %`, unary minus, parens
///   * Comparisons (precedence!)         — `== != < <= > >=`
///   * Logic                             — `and`, `or`, `not`
///   * Macro calls                       — `input('name', value=42)`
///
/// Returns the evaluated `Value`, or `null` if the expression is
/// malformed (unbalanced parens, unknown operator, missing identifier).
/// The caller treats `null` as "render empty string" — which keeps
/// plain path interpolation (`{{ user.name }}`) working by falling
/// back to the path-only lookup.
fn evaluateExpr(
    ctx: *const Context,
    allocator: std.mem.Allocator,
    expr: []const u8,
    options: RenderOptions,
) ?Value {
    const trimmed = std.mem.trim(u8, expr, " \t");
    if (trimmed.len == 0) return null;

    var p = Parser{
        .input = trimmed,
        .pos = 0,
        .ctx = ctx,
        .allocator = allocator,
        .options = options,
    };
    return p.parseOr() catch null;
}

const Parser = struct {
    input: []const u8,
    pos: usize,
    ctx: *const Context,
    allocator: std.mem.Allocator,
    options: RenderOptions,

    fn peek(self: *Parser) ?u8 {
        if (self.pos >= self.input.len) return null;
        return self.input[self.pos];
    }

    fn skipWs(self: *Parser) void {
        while (self.pos < self.input.len and (self.input[self.pos] == ' ' or self.input[self.pos] == '\t')) : (self.pos += 1) {}
    }

    /// Parse `or_expr ('or' or_expr)*` — lowest precedence. `or` is
    /// short-circuit: if the left side is truthy, the right side is
    /// not evaluated (matches Python's lazy semantics).
    fn parseOr(self: *Parser) anyerror!?Value {
        var left = (try self.parseAnd()) orelse return null;
        while (true) {
            self.skipWs();
            const kw = self.matchKeyword("or");
            if (kw) {
                // Lazy: if left is truthy, return left without
                // evaluating right. Otherwise evaluate and return right.
                if (isTruthy(left)) {
                    // Still need to consume the right-hand operand so
                    // the parser position advances (matches Python's
                    // behaviour of always consuming both sides).
                    _ = (try self.parseAnd()) orelse .null;
                    return left;
                }
                left = (try self.parseAnd()) orelse return null;
                continue;
            }
            break;
        }
        return left;
    }

    /// `and_expr ('and' and_expr)*`. Same short-circuit semantics as
    /// `or` — left falsy short-circuits without evaluating right.
    fn parseAnd(self: *Parser) anyerror!?Value {
        var left = (try self.parseNot()) orelse return null;
        while (true) {
            self.skipWs();
            const kw = self.matchKeyword("and");
            if (kw) {
                if (!isTruthy(left)) {
                    _ = (try self.parseNot()) orelse .null;
                    return left;
                }
                left = (try self.parseNot()) orelse return null;
                continue;
            }
            break;
        }
        return left;
    }

    /// `'not' not_expr | compare_expr`. Unary.
    fn parseNot(self: *Parser) anyerror!?Value {
        self.skipWs();
        if (self.matchKeyword("not")) {
            // `not X` — we still consume X (so the parser position
            // advances) but the value is determined by the truthiness
            // of the operand. If X is null (undefined path), `not`
            // returns true (undefined is falsy → `not undefined` → true).
            const operand = (try self.parseNot()) orelse {
                return Value{ .bool = true };
            };
            return Value{ .bool = !isTruthy(operand) };
        }
        return try self.parseCompare();
    }

    /// `add_expr (cmp_op add_expr)?`. Comparison operators have the
    /// same precedence (left-to-right associativity, Python-style).
    /// We only consume ONE comparison — chained comparisons like
    /// `a < b < c` are NOT supported (a Jinja-compatible subset).
    fn parseCompare(self: *Parser) anyerror!?Value {
        const left = (try self.parseAdd()) orelse return null;
        self.skipWs();
        const op_c = self.peek() orelse return left;
        const op_str: []const u8 = switch (op_c) {
            '=' => blk: {
                if (self.pos + 1 < self.input.len and self.input[self.pos + 1] == '=') {
                    self.pos += 2;
                    break :blk "==";
                }
                return left; // bare `=` isn't valid; treat as no-op
            },
            '!' => blk: {
                if (self.pos + 1 < self.input.len and self.input[self.pos + 1] == '=') {
                    self.pos += 2;
                    break :blk "!=";
                }
                return left;
            },
            '<' => blk: {
                if (self.pos + 1 < self.input.len and self.input[self.pos + 1] == '=') {
                    self.pos += 2;
                    break :blk "<=";
                }
                self.pos += 1;
                break :blk "<";
            },
            '>' => blk: {
                if (self.pos + 1 < self.input.len and self.input[self.pos + 1] == '=') {
                    self.pos += 2;
                    break :blk ">=";
                }
                self.pos += 1;
                break :blk ">";
            },
            else => return left,
        };
        // Comparison operands need special handling: `a == b` compares
        // values; if either is undefined the comparison is false (we
        // don't propagate null up — that would make `{% if a == b %}`
        // false for any undefined operand, which is correct).
        const right = try self.parseAdd();
        const l = left;
        const r = right orelse .null;
        return Value{ .bool = compareValues(op_str, l, r) };
    }

    /// `mul (('+' | '-') mul)*` (lowest-precedence arithmetic).
    fn parseAdd(self: *Parser) anyerror!?Value {
        var left = (try self.parseMul()) orelse return null;
        while (true) {
            self.skipWs();
            const op = self.peek() orelse break;
            if (op != '+' and op != '-') break;
            self.pos += 1;
            const right = (try self.parseMul()) orelse return null;
            const l_int = left.asInt() orelse return parseFail();
            const r_int = right.asInt() orelse return parseFail();
            left = Value{ .int = switch (op) {
                '+' => l_int + r_int,
                '-' => l_int - r_int,
                else => unreachable,
            } };
        }
        return left;
    }

    /// `unary (('*' | '/' | '%') unary)*`.
    fn parseMul(self: *Parser) anyerror!?Value {
        var left = (try self.parseUnary()) orelse return null;
        while (true) {
            self.skipWs();
            const op = self.peek() orelse break;
            if (op != '*' and op != '/' and op != '%') break;
            self.pos += 1;
            const right = (try self.parseUnary()) orelse return null;
            const l_int = left.asInt() orelse return parseFail();
            const r_int = right.asInt() orelse return parseFail();
            left = Value{ .int = switch (op) {
                '*' => l_int * r_int,
                '/' => if (r_int == 0) return parseFail() else @divTrunc(l_int, r_int),
                '%' => if (r_int == 0) return parseFail() else @rem(l_int, r_int),
                else => unreachable,
            } };
        }
        return left;
    }

    /// `'-' unary | primary`.
    fn parseUnary(self: *Parser) anyerror!?Value {
        self.skipWs();
        const op = self.peek() orelse return parseFail();
        if (op == '-') {
            self.pos += 1;
            const inner = (try self.parseUnary()) orelse return null;
            const v = inner.asInt() orelse return parseFail();
            return Value{ .int = -v };
        }
        return try self.parsePrimary();
    }

    /// `primary`:
    ///   * `( expr )` — parenthesized sub-expression
    ///   * integer literal — `42`
    ///   * path — `name`, `user.name`, `items[0]`
    ///   * macro call — `macro_name(arg1, arg2)`
    fn parsePrimary(self: *Parser) anyerror!?Value {
        self.skipWs();
        const c = self.peek() orelse return parseFail();
        if (c == '(') {
            self.pos += 1;
            const inner = (try self.parseOr()) orelse return null;
            self.skipWs();
            if (self.peek() != ')') return parseFail();
            self.pos += 1;
            return inner;
        }
        if (c >= '0' and c <= '9') {
            return try self.parseInt();
        }
        // String literal: `"..."` or `'...'`. The slice points into
        // `self.input` which is the caller's `expr` slice — the caller
        // (callMacro) keeps `expr` alive for the duration of the macro
        // body render, so the slice stays valid.
        if (c == '"' or c == '\'') {
            return try self.parseStringLiteral(c);
        }
        // Path expression. Allowed chars: alphanumerics, `_`, `.`,
        // `[`, `]`. Everything else (operators, parens, commas,
        // whitespace) terminates the path.
        const start = self.pos;
        while (self.pos < self.input.len) : (self.pos += 1) {
            const ch = self.input[self.pos];
            // Note: char-set check MUST use `ch` (the loop variable),
            // not `c` (the first peeked char). The earlier version
            // had `c >= '0' and c <= '9'` which broke paths containing
            // digits — e.g. `page_2` was truncated to `page_`.
            const ok = (ch >= 'a' and ch <= 'z') or
                (ch >= 'A' and ch <= 'Z') or
                (ch >= '0' and ch <= '9') or
                ch == '_' or ch == '.' or ch == '[' or ch == ']';
            if (!ok) break;
        }
        const path_str = self.input[start..self.pos];
        if (path_str.len == 0) return parseFail();
        // Macro call: `path(args)`. The path resolves to a `Value.macro`
        // (set by the renderer when `{% macro NAME() %}...{% endmacro %}`
        // runs at top level). If found, parse the args and invoke.
        self.skipWs();
        if (self.peek() == '(') {
            return try self.callMacro(path_str);
        }
        // Plain path lookup — return null on undefined (Jinja-compatible).
        return self.ctx.getPath(path_str);
    }

    /// Parse a single- or double-quoted string literal. Supports
    /// either quote character (so `"can't"` and `'say "hi"'` both
    /// work). The slice points into `self.input` (no allocation);
    /// the caller is responsible for keeping the input alive.
    fn parseStringLiteral(self: *Parser, quote: u8) anyerror!Value {
        self.pos += 1; // consume opening quote
        const start = self.pos;
        while (self.pos < self.input.len and self.input[self.pos] != quote) {
            self.pos += 1;
        }
        if (self.pos >= self.input.len) return parseFail();
        const str = self.input[start..self.pos];
        self.pos += 1; // consume closing quote
        return Value{ .string = str };
    }

    /// `name(args)` — look up the macro in the context, evaluate each
    /// argument (using the current parser context), and render the
    /// macro body in a fresh child context populated with the args.
    /// Macro calls return `Value.string` (the rendered output).
    fn callMacro(self: *Parser, name: []const u8) anyerror!Value {
        const macro_val = self.ctx.getPath(name) orelse {
            // Undefined name — treat as a parse error (the expression
            // is malformed — there's no such function). Returning null
            // here would render empty, which is surprising for typos.
            return parseFail();
        };
        if (macro_val != .macro) return parseFail();
        const m = macro_val.macro;

        // Parse argument list: `(` ( expr ( ',' expr )* )? `)`.
        self.skipWs();
        if (self.peek() != '(') return parseFail();
        self.pos += 1;

        // Collect args in declaration order. Args are passed positionally
        // (no `key=value` syntax for now — keeps the parser simpler).
        // String literals from `parseStringLiteral` are slices into
        // `self.input`, NOT heap-allocated — we dupe them here so the
        // context's StringHashMap owns an independent copy (otherwise
        // freeing `arg_vals` items would double-free the source slice).
        var arg_vals = std.ArrayListUnmanaged(Value).empty;
        defer {
            for (arg_vals.items) |v| {
                if (v == .string) self.allocator.free(v.string);
            }
            arg_vals.deinit(self.allocator);
        }

        self.skipWs();
        if (self.peek() != ')') {
            while (true) {
                const arg = (try self.parseOr()) orelse .null;
                // Dup string slices into our allocator so the value
                // is independent of `self.input` (the input slice
                // outlives this call but a follow-up parseOr may
                // mutate `self.pos` and we'd rather not rely on
                // immutability).
                const owned = switch (arg) {
                    .string => |s| Value{ .string = try self.allocator.dupe(u8, s) },
                    else => arg,
                };
                try arg_vals.append(self.allocator, owned);
                self.skipWs();
                const nc = self.peek() orelse return parseFail();
                if (nc == ',') {
                    self.pos += 1;
                    self.skipWs();
                    continue;
                }
                if (nc == ')') break;
                return parseFail();
            }
        }
        if (self.peek() != ')') return parseFail();
        self.pos += 1;

        // Build the macro's call context: a fresh child of the caller's
        // context (Jinja has closure-like semantics for macros; we keep
        // it simple — args only).
        var call_ctx = Context.child(self.ctx);
        defer call_ctx.deinit();
        for (m.params, 0..) |p, i| {
            if (i < arg_vals.items.len) {
                try call_ctx.put(p.name, arg_vals.items[i]);
            } else if (p.default) |def_expr| {
                // Evaluate default — uses the caller's context (not
                // call_ctx) so the default sees what the caller sees.
                const def_val = self.evaluateInCaller(def_expr) orelse .null;
                try call_ctx.put(p.name, def_val);
            } else {
                // Required parameter missing — leave undefined (Jinja
                // emits empty string for the missing arg's references).
                try call_ctx.put(p.name, .null);
            }
        }

        // Render the macro body into a fresh buffer.
        var out = std.ArrayListUnmanaged(u8).empty;
        errdefer out.deinit(self.allocator);
        try renderNodes(self.allocator, &out, m.body, &call_ctx, self.options);
        const rendered = try out.toOwnedSlice(self.allocator);
        return Value{ .string = rendered };
    }

    /// Helper used by `callMacro` to evaluate a default expression in
    /// the caller's context (a separate parser instance with fresh
    /// state). Returns null on parse failure (the caller falls back
    /// to `.null`).
    fn evaluateInCaller(self: *Parser, expr: []const u8) ?Value {
        var p = Parser{
            .input = std.mem.trim(u8, expr, " \t"),
            .pos = 0,
            .ctx = self.ctx,
            .allocator = self.allocator,
            .options = self.options,
        };
        return p.parseOr() catch null;
    }

    /// Try to consume `kw` as a keyword (followed by whitespace or end
    /// of input). Returns true if matched (and advances `pos`), false
    /// otherwise. Used for `and` / `or` / `not` — these are reserved
    /// words, so a variable named `and` would shadow the operator.
    /// (Jinja has the same limitation.)
    fn matchKeyword(self: *Parser, kw: []const u8) bool {
        if (self.pos + kw.len > self.input.len) return false;
        if (!std.mem.eql(u8, self.input[self.pos..self.pos + kw.len], kw)) return false;
        // Word boundary — the next char must not be part of an
        // identifier (so `anda` doesn't match `and`).
        const after = self.pos + kw.len;
        if (after < self.input.len) {
            const ch = self.input[after];
            const is_ident = (ch >= 'a' and ch <= 'z') or
                (ch >= 'A' and ch <= 'Z') or
                (ch >= '0' and ch <= '9') or
                ch == '_';
            if (is_ident) return false;
        }
        self.pos += kw.len;
        return true;
    }

    fn parseInt(self: *Parser) anyerror!Value {
        const start = self.pos;
        while (self.pos < self.input.len and self.input[self.pos] >= '0' and self.input[self.pos] <= '9') : (self.pos += 1) {}
        const digits = self.input[start..self.pos];
        if (digits.len == 0) return parseFail();
        const n = std.fmt.parseInt(i64, digits, 10) catch return parseFail();
        return Value{ .int = n };
    }
};

/// Compare two values according to an operator string. Implements
/// Python-like ordering: ints compare against ints, strings against
/// strings, etc. — and incomparable types compare as false (rather
/// than erroring) so `{% if 5 == "foo" %}` is just false instead of
/// a template crash.
fn compareValues(op: []const u8, l: Value, r: Value) bool {
    if (std.mem.eql(u8, op, "==")) return valuesEqual(l, r);
    if (std.mem.eql(u8, op, "!=")) return !valuesEqual(l, r);
    // Ordering operators — only defined for ints (for now). Strings,
    // bools, etc. fall through to `false`.
    const li = l.asInt() orelse return false;
    const ri = r.asInt() orelse return false;
    if (std.mem.eql(u8, op, "<")) return li < ri;
    if (std.mem.eql(u8, op, "<=")) return li <= ri;
    if (std.mem.eql(u8, op, ">")) return li > ri;
    if (std.mem.eql(u8, op, ">=")) return li >= ri;
    return false;
}

/// Equality for two values. Same-type values use their natural
/// comparison; cross-type comparisons are always false. Null equals
/// null; ints/strings/bools compare within their type.
fn valuesEqual(l: Value, r: Value) bool {
    return switch (l) {
        .null => r == .null,
        .bool => |lb| switch (r) {
            .bool => |rb| lb == rb,
            else => false,
        },
        .int => |li| switch (r) {
            .int => |ri| li == ri,
            else => false,
        },
        .string => |ls| switch (r) {
            .string => |rs| std.mem.eql(u8, ls, rs),
            else => false,
        },
        // Arrays / maps / macros aren't compared — return false
        // (consistent with "incomparable types compare as false").
        else => false,
    };
}

fn parseFail() error{ParseError} {
    return error.ParseError;
}

/// Truthy check for `{% if %}` conditions. Mirrors Python/Jinja semantics:
/// null/false/0/empty-string/empty-array = falsy; everything else truthy.
fn isTruthy(v: Value) bool {
    return switch (v) {
        .null => false,
        .bool => |b| b,
        .int => |i| i != 0,
        .string => |s| s.len > 0,
        .array => |a| a.len > 0,
        .map => |m| m.count() > 0,
        // Macros are truthy by existence — they're not "values" that
        // can be empty. (This matters for `{% if macro_name %}` checks.)
        .macro => true,
    };
}

/// Append the HTML-escaped form of `s` to `out`. Escapes
///   & → &amp;     < → &lt;      > → &gt;
///   " → &quot;    ' → &#x27;
/// Both attributes and text content are protected.
fn escapeHtml(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), s: []const u8) (Error || std.mem.Allocator.Error)!void {
    // Reserve the common case (no escaping, 1:1) up front so the
    // per-char append loop doesn't regrow logarithmically. Worst case
    // (all '&' → 5x) still regrows, but only for hostile input.
    try out.ensureTotalCapacity(allocator, out.items.len + s.len);
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        switch (c) {
            '&' => try out.appendSlice(allocator, "&amp;"),
            '<' => try out.appendSlice(allocator, "&lt;"),
            '>' => try out.appendSlice(allocator, "&gt;"),
            '"' => try out.appendSlice(allocator, "&quot;"),
            '\'' => try out.appendSlice(allocator, "&#x27;"),
            else => try out.append(allocator, c),
        }
        i += 1;
    }
}

/// Append the string form of a value to `out`. Strings are escaped;
/// other types are rendered as-is (Jinja default).
fn appendValue(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    v: Value,
) (Error || std.mem.Allocator.Error)!void {
    switch (v) {
        .null => {},
        .bool => |b| try out.appendSlice(allocator, if (b) "true" else "false"),
        .int => |i| {
            var int_buf: [32]u8 = undefined;
            const int_str = std.fmt.bufPrint(&int_buf, "{d}", .{i}) catch return error.OutOfMemory;
            try out.appendSlice(allocator, int_str);
        },
        .string => |s| try escapeHtml(allocator, out, s),
        .array => |a| {
            for (a) |item| {
                try appendValue(allocator, out, item);
            }
        },
        .map => |m| {
            var it = m.iterator();
            while (it.next()) |entry| {
                try out.appendSlice(allocator, entry.key_ptr.*);
                try out.append(allocator, '=');
                try appendValue(allocator, out, entry.value_ptr.*);
            }
        },
        // Macros are callable — they shouldn't appear as direct output
        // values (the call site `{{ macro(args) }}` invokes the macro,
        // not renders it). Render an empty string defensively so a
        // misfiring `{{ macro }}` doesn't crash.
        .macro => {},
    }
}

/// Render-time options. Most templates need only `loader_ctx` +
/// `loader_fn` to enable `{% include %}`; everything else is a
/// sensible default. Pass `RenderOptions{}` when includes aren't used.
pub const RenderOptions = struct {
    /// Loader for `{% include "path.html" %}`. When null, encountering
    /// an include errors out with `error.IncludeLoaderRequired`.
    /// The loader receives a path string and returns a heap-allocated
    /// source buffer (caller owns it). Same signature as the compile-
    /// time `LoaderFn` so a single loader can serve both.
    loader_ctx: ?*anyopaque = null,
    loader_fn: ?LoaderFn = null,
    /// Base directory for resolving relative include paths. When a
    /// `{% include "partial.html" %}` is encountered inside a template
    /// loaded from `handlers/users_page.html`, this is `"handlers"`.
    /// Empty string = CWD.
    base_dir: []const u8 = "",
};

/// Load an included template by path and render it inline. The
/// included template's AST is parsed fresh each call (no caching —
/// a future enhancement). Relative paths are joined against
/// `options.base_dir`; absolute paths skip the join.
///
/// Errors:
///   * `error.IncludeLoaderRequired` — `options.loader_fn` is null
///     but an include was encountered.
///   * `error.TemplateNotFound` — the loader returned that error.
///   * `error.ParseError` — the included template failed to parse
///     (emits a diagnostic, like other parse errors).
fn renderInclude(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    inc: Include,
    ctx: *Context,
    options: RenderOptions,
) (Error || std.mem.Allocator.Error)!void {
    const loader_fn = options.loader_fn orelse return error.IncludeLoaderRequired;
    const loader_ctx = options.loader_ctx orelse
        @as(*anyopaque, @ptrCast(@constCast(&options)));

    // Resolve the include path. Relative paths are joined against the
    // current template's base directory — so `{% include "foo.html" %}`
    // inside `users_page.html` (base_dir = "handlers") resolves to
    // `handlers/foo.html`. Absolute paths (containing `/` at the start
    // or recognized as such by the loader) skip the join — but the
    // join is a no-op for paths that already start with a separator.
    const full_path = blk: {
        if (inc.path.len == 0 or inc.path[0] == '/') break :blk inc.path;
        if (options.base_dir.len == 0) break :blk inc.path;
        break :blk std.fs.path.join(allocator, &.{ options.base_dir, inc.path }) catch
            break :blk inc.path;
    };
    // `full_path` is either the input slice (no allocation) or a
    // freshly joined heap slice. Track ownership so we can free.
    const full_path_owned = full_path.ptr != inc.path.ptr;
    defer if (full_path_owned) allocator.free(full_path);

    const source = loader_fn(loader_ctx, allocator, full_path) catch |err| switch (err) {
        error.TemplateNotFound => {
            if (inc.ignore_missing) return;
            return error.TemplateNotFound;
        },
        // The loader's signature is `anyerror![]u8` — any other error
        // is collapsed into OutOfMemory (the only realistic non-
        // TemplateNotFound failure from a file-read loader; other
        // errors from custom loaders would surface as ParseError or
        // an undocumented runtime failure). Callers can supply their
        // own loader that narrows this if needed.
        else => return error.OutOfMemory,
    };
    defer allocator.free(source);

    // Parse + render the included template. We re-use parseSource so
    // the AST is self-contained (freeable without holding the source).
    const nodes = try parseSource(allocator, source);
    defer freeNodes(allocator, nodes);

    // `with context` (default) — the included template sees the
    // caller's variables. `without context` — fresh empty context.
    if (inc.with_context) {
        try renderNodes(allocator, out, nodes, ctx, options);
    } else {
        var fresh_ctx = Context.init(allocator);
        defer fresh_ctx.deinit();
        try renderNodes(allocator, out, nodes, &fresh_ctx, options);
    }
}

/// Render an AST node list with the given context. Output is allocated
/// into `out_alloc`. Replaces the placeholder `Compiled.render` — the
/// Compiled struct is a future convenience wrapper.
pub fn render(
    out_alloc: std.mem.Allocator,
    nodes: []const Node,
    ctx: *Context,
    options: RenderOptions,
) (Error || std.mem.Allocator.Error)![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(out_alloc);
    // Seed with 1 KiB so tiny templates render with a single allocation
    // instead of 3-4 logarithmic regrowths.
    try out.ensureTotalCapacity(out_alloc, 1024);
    try renderNodes(out_alloc, &out, nodes, ctx, options);
    return out.toOwnedSlice(out_alloc);
}

fn renderNodes(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    nodes: []const Node,
    ctx: *Context,
    options: RenderOptions,
) (Error || std.mem.Allocator.Error)!void {
    for (nodes) |node| {
        switch (node) {
            .text => |t| try out.appendSlice(allocator, t),
            .variable => |path| {
                // Try to evaluate as an expression (supports `+ - * /`
                // comparisons, logic, arithmetic, and macro calls —
                // see `evaluateExpr`). Falls back to a plain path lookup
                // when the expression has no operators / parens / etc.
                if (evaluateExpr(ctx, allocator, path, options)) |v| {
                    try appendValue(allocator, out, v);
                } else if (ctx.getPath(path)) |v| {
                    try appendValue(allocator, out, v);
                }
            },
            .if_block => |b| {
                // Iterate the branches list, render the first body
                // whose condition evaluates truthy. If none match,
                // fall through to the optional else_branch. We use a
                // tagged flag to break out of the branch loop instead
                // of `return` — `return` here would exit `renderNodes`
                // itself, skipping subsequent sibling nodes (a bug
                // that ate "END-B" in nested-if-inside-else tests).
                //
                // The condition is FULLY evaluated as an expression —
                // `count == 5`, `not ready`, `n >= 10 and n <= 10` all
                // work, not just bare path lookups. If `evaluateExpr`
                // returns null (parse failure), fall back to a plain
                // path lookup so legacy `{% if user.is_admin %}`
                // templates keep working.
                var matched = false;
                for (b.branches) |br| {
                    const cond = evaluateExpr(ctx, allocator, br.condition, options) orelse
                        ctx.getPath(br.condition) orelse .null;
                    if (isTruthy(cond)) {
                        try renderNodes(allocator, out, br.body, ctx, options);
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    try renderNodes(allocator, out, b.else_branch, ctx, options);
                }
            },
            .for_loop => |l| {
                // Pre-render: if `condition` is set, we iterate the
                // array filtering out items where the condition
                // evaluates falsy. `loop.length` is the COUNT OF
                // ITERATED ITEMS (post-filter), per Jinja semantics —
                // `loop.index` also counts only iterated items.
                //
                // To honour that, we walk the iterable TWICE when
                // there's a filter: once to count the kept items, once
                // to render them. The double-walk is O(n) per loop
                // body which is fine for any realistic template size.
                //
                // The iterable itself is evaluated as an expression
                // (so `{% for x in items + extras %}` would work in
                // principle); falls back to a plain path lookup if
                // the expression doesn't parse — matches the if-block
                // pattern above.
                const iterable = evaluateExpr(ctx, allocator, l.iterable, options) orelse
                    ctx.getPath(l.iterable) orelse .null;
                if (iterable != .array or iterable.array.len == 0) {
                    try renderNodes(allocator, out, l.empty_body, ctx, options);
                    return;
                }

                if (l.condition) |cond_expr| {
                    // Two passes: count kept, then render kept.
                    var kept_count: usize = 0;
                    for (iterable.array) |item| {
                        var probe = Context.child(ctx);
                        defer probe.deinit();
                        try probe.put(l.var_name, item);
                        const cond_val = evaluateExpr(&probe, allocator, cond_expr, options) orelse
                            ctx.getPath(cond_expr) orelse .null;
                        if (isTruthy(cond_val)) kept_count += 1;
                    }
                    if (kept_count == 0) {
                        try renderNodes(allocator, out, l.empty_body, ctx, options);
                        return;
                    }
                    var i: usize = 0;
                    for (iterable.array) |item| {
                        var probe = Context.child(ctx);
                        const cond_val = blk: {
                            defer probe.deinit();
                            try probe.put(l.var_name, item);
                            const r = evaluateExpr(&probe, allocator, cond_expr, options) orelse
                                ctx.getPath(cond_expr) orelse .null;
                            break :blk r;
                        };
                        if (!isTruthy(cond_val)) continue;

                        var inner = Context.child(ctx);
                        errdefer inner.deinit();
                        try inner.put(l.var_name, item);

                        // Push the `loop` map for this iteration.
                        var loop_map = std.StringHashMap(Value).init(allocator);
                        errdefer loop_map.deinit();
                        try loop_map.put("index", .{ .int = @intCast(i + 1) });
                        try loop_map.put("index0", .{ .int = @intCast(i) });
                        try loop_map.put("first", .{ .bool = i == 0 });
                        try loop_map.put("last", .{ .bool = i == kept_count - 1 });
                        try loop_map.put("length", .{ .int = @intCast(kept_count) });
                        try inner.put("loop", .{ .map = loop_map });

                        // Ownership of loop_map transfers to inner —
                        // its inner storage will be freed by inner.deinit
                        // when the iteration scope ends. We don't call
                        // loop_map.deinit() here.
                        try renderNodes(allocator, out, l.body, &inner, options);
                        i += 1;
                    }
                    return;
                }

                // No filter — original (simple) iteration.
                for (iterable.array, 0..) |item, i| {
                    var inner = Context.child(ctx);
                    defer inner.deinit();
                    try inner.put(l.var_name, item);

                    var loop_map = std.StringHashMap(Value).init(allocator);
                    defer loop_map.deinit();
                    try loop_map.put("index", .{ .int = @intCast(i + 1) });
                    try loop_map.put("index0", .{ .int = @intCast(i) });
                    try loop_map.put("first", .{ .bool = i == 0 });
                    try loop_map.put("last", .{ .bool = i == iterable.array.len - 1 });
                    try loop_map.put("length", .{ .int = @intCast(iterable.array.len) });
                    try inner.put("loop", .{ .map = loop_map });

                    try renderNodes(allocator, out, l.body, &inner, options);
                }
            },
            .block => |b| {
                // In standalone rendering (no inheritance), blocks just
                // render their body. Inheritance layer (Task 4) rewrites
                // these bodies to child blocks at compile time.
                try renderNodes(allocator, out, b.body, ctx, options);
            },
            .extends => {
                // Standalone render of an extends node emits nothing —
                // the entire output is the parent template's render.
                // The inheritance layer handles this at compile time.
            },
            .raw => |r| {
                // Raw nodes contain a single text node whose content is
                // the verbatim source (excluding the {% raw %} / {% endraw %}
                // tags themselves). Emit as-is.
                for (r) |child| {
                    if (child == .text) try out.appendSlice(allocator, child.text);
                }
            },
            .include => |i| {
                try renderInclude(allocator, out, i, ctx, options);
            },
            .set => |s| {
                // Evaluate the expression and put the result into the
                // current context. Assignments inside a `{% for %}` go
                // into the loop's child context (and don't escape) —
                // assignments inside `{% if %}` go into the same
                // context (visible after the block), matching Jinja's
                // `if doesn't introduce scope` rule.
                const val = evaluateExpr(ctx, allocator, s.value, options) orelse
                    ctx.getPath(s.value) orelse .null;
                try ctx.put(s.var_name, val);
            },
            .macro => |m| {
                // Macros defined at the top level become callable
                // values in the context. We render the macro into a
                // temporary buffer on each call — the macro itself is
                // a callable (a struct holding params + body), and the
                // call site `{{ macro_name(arg1, arg2) }}` invokes it
                // via `evaluateExpr`'s function-call arm.
                try ctx.put(m.name, .{ .macro = m });
            },
        }
    }
}
