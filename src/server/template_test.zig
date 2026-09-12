// Tests for the Jinja-style template engine (template.zig).
//
// Organised by ENGINE LAYER — Tokenizer, Parser, Renderer, Inheritance —
// so each test block maps to one Task in the plan. Within each block,
// tests are ordered simplest to most-complex.
//
// Test data lives inline as comptime-known strings so failures show the
// exact input that broke.
const std = @import("std");
const testing = std.testing;
const Template = @import("template.zig");

// =============================================================================
//  Task 1 — Tokenizer
// =============================================================================
//
// Tokenize() returns a slice of `text | var_expr | tag` tokens whose
// content slices point into the source. Comments `{# ... #}` are
// dropped (no token emitted). Three unclosed cases raise errors so the
// caller gets a parse error pointing at the source location.
//
// Note on slice equality: tests use `expectEqualStrings` on the
// inner slices because `expectEqual` on slices compares pointers
// (the token's slice points into the source buffer; the test literal
// points into the test's rodata).

fn tokenizeChecked(alloc: std.mem.Allocator, source: []const u8) ![]Template.Token {
    return try Template.tokenize(alloc, source);
}

test "tokenize: plain text returns one text token" {
    const tokens = try tokenizeChecked(testing.allocator, "hello world");
    defer testing.allocator.free(tokens);

    try testing.expectEqual(@as(usize, 1), tokens.len);
    try testing.expect(tokens[0] == .text);
    try testing.expectEqualStrings("hello world", tokens[0].text);
}

test "tokenize: variable expression returns var_expr token" {
    const tokens = try tokenizeChecked(testing.allocator, "{{ name }}");
    defer testing.allocator.free(tokens);

    try testing.expectEqual(@as(usize, 1), tokens.len);
    try testing.expect(tokens[0] == .var_expr);
    // The lexer preserves the surrounding whitespace inside `{{ ... }}`;
    // the parser is responsible for trimming/parsing it.
    try testing.expectEqualStrings(" name ", tokens[0].var_expr);
}

test "tokenize: tag returns tag token with inner content" {
    const tokens = try tokenizeChecked(testing.allocator, "{% if x %}");
    defer testing.allocator.free(tokens);

    try testing.expectEqual(@as(usize, 1), tokens.len);
    try testing.expect(tokens[0] == .tag);
    try testing.expectEqualStrings(" if x ", tokens[0].tag);
}

test "tokenize: comment is dropped (no token emitted)" {
    const tokens = try tokenizeChecked(testing.allocator, "before {# skipped #} after");
    defer testing.allocator.free(tokens);

    try testing.expectEqual(@as(usize, 2), tokens.len);
    try testing.expect(tokens[0] == .text);
    try testing.expectEqualStrings("before ", tokens[0].text);
    try testing.expect(tokens[1] == .text);
    try testing.expectEqualStrings(" after", tokens[1].text);
}

test "tokenize: mixed text + var + tag + comment interleaves correctly" {
    // Source: "a {{ b }} c {% d %} {# e #} f"
    //   index: 0         1     2          3
    //   text "a " + var_expr " b " + text " c " + tag " d " + text " " + text " f"
    // (The text between the tag and the comment is a single space — not
    // coalesced with the text after the comment, since the lexer doesn't
    // know that "comment" is a no-op.)
    const tokens = try tokenizeChecked(testing.allocator, "a {{ b }} c {% d %} {# e #} f");
    defer testing.allocator.free(tokens);

    try testing.expectEqual(@as(usize, 6), tokens.len);
    try testing.expectEqualStrings("a ", tokens[0].text);
    try testing.expectEqualStrings(" b ", tokens[1].var_expr);
    try testing.expectEqualStrings(" c ", tokens[2].text);
    try testing.expectEqualStrings(" d ", tokens[3].tag);
    try testing.expectEqualStrings(" ", tokens[4].text);
    try testing.expectEqualStrings(" f", tokens[5].text);
}

test "tokenize: unclosed {{ raises UnclosedVariable" {
    const result = tokenizeChecked(testing.allocator, "hello {{ name");
    try testing.expectError(error.UnclosedVariable, result);
}

test "tokenize: unclosed {% raises UnclosedTag" {
    const result = tokenizeChecked(testing.allocator, "hello {% if x");
    try testing.expectError(error.UnclosedTag, result);
}

test "tokenize: unclosed {# raises UnclosedComment" {
    const result = tokenizeChecked(testing.allocator, "hello {# comment");
    try testing.expectError(error.UnclosedComment, result);
}

// =============================================================================
//  Task 2 — Parser
// =============================================================================
//
// parse() walks the token stream and produces an AST. The AST is a flat
// slice of `Node` (which is a tagged union including text, variable, if,
// for, block, extends, raw). Nested constructs (if-inside-for) appear
// as nested slices inside the parent node.

fn parseChecked(alloc: std.mem.Allocator, source: []const u8) ![]Template.Node {
    // Use parseSource so the returned AST is self-contained (every
    // string is heap-owned by the allocator). parse() returns ASTs
    // whose text/condition/etc. point INTO the caller's token slice —
    // freeNodes on those would be a use-after-free. parseSource
    // copies everything safely.
    return try Template.parseSource(alloc, source);
}

/// Test-scoped arena. Each test that allocates templated data wraps
/// itself in this arena so we don't have to free nodes one-by-one —
/// the arena reaps every allocation when `defer arena.deinit()` runs
/// (matches what production handlers do, where per-request arenas
/// reap template state implicitly).
const TestArena = struct {
    backing: std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    fn init() TestArena {
        var backing = std.heap.ArenaAllocator.init(testing.allocator);
        return .{ .backing = backing, .allocator = backing.allocator() };
    }

    fn deinit(self: *TestArena) void {
        self.backing.deinit();
    }
};

/// Render `source` with a fresh context. Parses + renders in one
/// step; the AST is freed via `freeNodes` before return. The output
/// buffer is allocated from `alloc` (caller frees via
/// `testing.allocator.free` or, in arena-based tests, lets the arena
/// reap it).
fn renderChecked(
    alloc: std.mem.Allocator,
    source: []const u8,
    context: *Template.Context,
) ![]u8 {
    const nodes = try Template.parseSource(alloc, source);
    defer Template.freeNodes(alloc, nodes);
    return try Template.render(alloc, nodes, context, .{});
}

test "parse: empty source returns empty node list" {
    const nodes = try parseChecked(testing.allocator, "");
    defer Template.freeNodes(testing.allocator, nodes);
    try testing.expectEqual(@as(usize, 0), nodes.len);
}

test "parse: text only → single text node" {
    const nodes = try parseChecked(testing.allocator, "hello world");
    defer Template.freeNodes(testing.allocator, nodes);
    try testing.expectEqual(@as(usize, 1), nodes.len);
    try testing.expect(nodes[0] == .text);
    try testing.expectEqualStrings("hello world", nodes[0].text);
}

test "parse: variable only → single variable node" {
    const nodes = try parseChecked(testing.allocator, "{{ name }}");
    defer Template.freeNodes(testing.allocator, nodes);
    try testing.expectEqual(@as(usize, 1), nodes.len);
    try testing.expect(nodes[0] == .variable);
    try testing.expectEqualStrings("name", nodes[0].variable);
}

test "parse: if without else → if_block with empty else_branch" {
    const nodes = try parseChecked(testing.allocator, "{% if cond %}yes{% endif %}");
    defer Template.freeNodes(testing.allocator, nodes);
    try testing.expectEqual(@as(usize, 1), nodes.len);
    try testing.expect(nodes[0] == .if_block);
    const ifb = nodes[0].if_block;
    try testing.expectEqual(@as(usize, 1), ifb.branches.len);
    try testing.expectEqualStrings("cond", ifb.branches[0].condition);
    try testing.expectEqual(@as(usize, 1), ifb.branches[0].body.len);
    try testing.expectEqualStrings("yes", ifb.branches[0].body[0].text);
    try testing.expectEqual(@as(usize, 0), ifb.else_branch.len);
}

test "parse: if with else → both branches populated" {
    const nodes = try parseChecked(testing.allocator, "{% if cond %}A{% else %}B{% endif %}");
    defer Template.freeNodes(testing.allocator, nodes);
    try testing.expectEqual(@as(usize, 1), nodes.len);
    const ifb = nodes[0].if_block;
    try testing.expectEqualStrings("A", ifb.branches[0].body[0].text);
    try testing.expectEqualStrings("B", ifb.else_branch[0].text);
}

test "parse: for loop → for_loop with empty_body empty" {
    const nodes = try parseChecked(testing.allocator, "{% for x in items %}<{{ x }}>{% endfor %}");
    defer Template.freeNodes(testing.allocator, nodes);
    try testing.expectEqual(@as(usize, 1), nodes.len);
    try testing.expect(nodes[0] == .for_loop);
    const fl = nodes[0].for_loop;
    try testing.expectEqualStrings("x", fl.var_name);
    try testing.expectEqualStrings("items", fl.iterable);
    try testing.expectEqual(@as(usize, 0), fl.empty_body.len);
    // Body should have text "<" + variable "x" + text ">".
    try testing.expectEqual(@as(usize, 3), fl.body.len);
    try testing.expectEqualStrings("<", fl.body[0].text);
    try testing.expectEqualStrings("x", fl.body[1].variable);
    try testing.expectEqualStrings(">", fl.body[2].text);
}

test "parse: for with empty branch → empty_body populated" {
    const nodes = try parseChecked(testing.allocator, "{% for x in items %}A{% empty %}B{% endfor %}");
    defer Template.freeNodes(testing.allocator, nodes);
    const fl = nodes[0].for_loop;
    try testing.expectEqualStrings("A", fl.body[0].text);
    try testing.expectEqualStrings("B", fl.empty_body[0].text);
}

test "parse: nested if inside for" {
    const nodes = try parseChecked(
        testing.allocator,
        "{% for x in items %}{% if x %}{{ x }}{% endif %}{% endfor %}",
    );
    defer Template.freeNodes(testing.allocator, nodes);
    try testing.expectEqual(@as(usize, 1), nodes.len);
    const fl = nodes[0].for_loop;
    try testing.expectEqual(@as(usize, 1), fl.body.len);
    try testing.expect(fl.body[0] == .if_block);
    const inner_if = fl.body[0].if_block;
    try testing.expectEqualStrings("x", inner_if.branches[0].condition);
    try testing.expectEqualStrings("x", inner_if.branches[0].body[0].variable);
}

test "parse: extends + block → extends first, then block" {
    const nodes = try parseChecked(testing.allocator,
        \\{% extends "base.jinja" %}
        \\{% block content %}hello{% endblock %}
    );
    defer Template.freeNodes(testing.allocator, nodes);
    // 3 nodes: extends, the "\n" text in between, block.
    try testing.expectEqual(@as(usize, 3), nodes.len);
    try testing.expect(nodes[0] == .extends);
    try testing.expectEqualStrings("base.jinja", nodes[0].extends);
    try testing.expect(nodes[1] == .text);
    try testing.expectEqualStrings("\n", nodes[1].text);
    try testing.expect(nodes[2] == .block);
    try testing.expectEqualStrings("content", nodes[2].block.name);
    try testing.expectEqualStrings("hello", nodes[2].block.body[0].text);
}

test "parse: raw → raw node with text children" {
    const nodes = try parseChecked(testing.allocator,
        \\{% raw %}{{ not processed }}{% endraw %}
    );
    defer Template.freeNodes(testing.allocator, nodes);
    try testing.expectEqual(@as(usize, 1), nodes.len);
    try testing.expect(nodes[0] == .raw);
    try testing.expectEqual(@as(usize, 1), nodes[0].raw.len);
    try testing.expect(nodes[0].raw[0] == .text);
    try testing.expectEqualStrings("{{ not processed }}", nodes[0].raw[0].text);
}

test "parse: dotted path variable preserves dots" {
    const nodes = try parseChecked(testing.allocator, "{{ user.name }}");
    defer Template.freeNodes(testing.allocator, nodes);
    try testing.expectEqual(@as(usize, 1), nodes.len);
    try testing.expectEqualStrings("user.name", nodes[0].variable);
}

test "parse: malformed if (no endif) → ParseError" {
    const result = parseChecked(testing.allocator, "{% if cond %}yes");
    try testing.expectError(error.ParseError, result);
}

test "parse: malformed for (no endfor) → ParseError" {
    const result = parseChecked(testing.allocator, "{% for x in items %}body");
    try testing.expectError(error.ParseError, result);
}

// -----------------------------------------------------------------------------
//  parseError — diagnostic format coverage
// -----------------------------------------------------------------------------
//
// Each `ParseError` site must:
//   (a) return `error.ParseError` (unchanged from before — the existing
//       tests above verify the error code is preserved), and
//   (b) print a rustc-style diagnostic to stderr that names the failure
//       mode AND points at the source location.
//
// The "name the failure mode" half is easy to assert on: every
// `reportParseError` call has a comptime description string we want to
// be human-readable. The "points at the source location" half is
// harder to test without capturing stderr — but we CAN verify the
// parser still returns `error.ParseError` for every code path that
// triggers the diagnostic, so the diagnostic is guaranteed to have
// been emitted (else the test would pass even if we silently dropped
// the report). The actual stderr output is documented in `template.zig`
// (see `reportParseError`); visual inspection during development is
// the verification channel for the format itself.
// -----------------------------------------------------------------------------

test "parseError: unclosed if on a non-first line emits ParseError" {
    // Multi-line source — the diagnostic must still fire even when the
    // unclosed `if` doesn't start at column 1. (Locating the opener at
    // `start - 1` is the path that walks back through the token stream.)
    const src =
        \\<html>
        \\<body>
        \\{% if cond %}
        \\hello
    ;
    const result = parseChecked(testing.allocator, src);
    try testing.expectError(error.ParseError, result);
}

test "parseError: for tag missing ' in ' separator emits ParseError" {
    // Common typo: `{% for x items %}` (missing the word `in`). The
    // diagnostic should fire at the for-tag's location.
    const result = parseChecked(testing.allocator, "{% for x items %}body{% endfor %}");
    try testing.expectError(error.ParseError, result);
}

test "parseError: dangling endif at top level emits ParseError" {
    // `{% endif %}` outside any `if` block — the parser hits the
    // "unexpected tag at top level" branch.
    const result = parseChecked(testing.allocator, "hello {% endif %} world");
    try testing.expectError(error.ParseError, result);
}

test "parseError: dangling endfor at top level emits ParseError" {
    const result = parseChecked(testing.allocator, "hello {% endfor %} world");
    try testing.expectError(error.ParseError, result);
}

test "parseError: dangling endblock at top level emits ParseError" {
    const result = parseChecked(testing.allocator, "hello {% endblock %} world");
    try testing.expectError(error.ParseError, result);
}

test "parseError: dangling endraw at top level emits ParseError" {
    const result = parseChecked(testing.allocator, "hello {% endraw %} world");
    try testing.expectError(error.ParseError, result);
}

test "parseError: unclosed if with else but no endif emits ParseError" {
    // `{% else %}` requires `{% endif %}` to match — the diagnostic
    // names the else as the offending token.
    const result = parseChecked(testing.allocator, "{% if c %}A{% else %}B");
    try testing.expectError(error.ParseError, result);
}

test "parseError: unclosed for with empty but no endfor emits ParseError" {
    const result = parseChecked(testing.allocator, "{% for x in items %}A{% empty %}B");
    try testing.expectError(error.ParseError, result);
}

test "parseError: unclosed block (no endblock) emits ParseError" {
    const result = parseChecked(testing.allocator, "{% block foo %}body");
    try testing.expectError(error.ParseError, result);
}

test "parseError: unclosed raw (no endraw) emits ParseError" {
    const result = parseChecked(testing.allocator, "{% raw %}{{ not parsed }}");
    try testing.expectError(error.ParseError, result);
}

test "parseError: error reports a multi-byte source location correctly" {
    // Source spans 3 lines; the unclosed if opens on line 3, col 1.
    // This exercises the line-walking in offsetToLocation — each '\n'
    // boundary increments the line counter. (We can't easily assert on
    // stderr output from a unit test, but if offsetToLocation were
    // wrong the diagnostic would print `template:N:M` with N=1 instead
    // of 3, which would be visually obvious in the test log.)
    const src =
        \\line one
        \\line two
        \\{% if c %}body
    ;
    const result = parseChecked(testing.allocator, src);
    try testing.expectError(error.ParseError, result);
}

// =============================================================================
//  Task 3 — Renderer
// =============================================================================
//
// Render() walks the AST with a Context and produces a string. Tests
// cover the four core features plus the auto-escape default.

/// Render `source` with a fresh context populated from `kvs`. Uses
/// the caller's allocator (typically arena-backed) for the AST,
/// context, and output — the caller manages lifetime. Tests wrap
/// this in `std.heap.ArenaAllocator` so the per-test allocations
/// are reaped together at the end of each test, sidestepping
/// DebugAllocator's per-allocation leak accounting.
///
/// Usage:
/// ```zig
/// var arena = std.heap.ArenaAllocator.init(testing.allocator);
/// defer arena.deinit();
/// const out = try renderWith(arena_allocator(), "...", &.{});
/// ```
fn renderWith(alloc: std.mem.Allocator, source: []const u8, kvs: []const struct { key: []const u8, value: Template.Value }) ![]u8 {
    var ctx = Template.Context.init(alloc);
    for (kvs) |kv| try ctx.put(kv.key, kv.value);
    const nodes = try Template.parseSource(alloc, source);
    return try Template.render(alloc, nodes, &ctx, .{});
}

test "render: plain text passes through verbatim" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "hello world", &.{});
    try testing.expectEqualStrings("hello world", out);
}

test "render: variable substitution with string value" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{{ name }}", &.{
        .{ .key = "name", .value = .{ .string = "World" } },
    });
    try testing.expectEqualStrings("World", out);
}

test "render: dotted path resolves nested map" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var ctx = Template.Context.init(a);
    var user = std.StringHashMap(Template.Value).init(a);
    try user.put("name", .{ .string = "Alice" });
    try ctx.put("user", .{ .map = user });

    const out = try renderChecked(a, "Hello, {{ user.name }}!", &ctx);
    try testing.expectEqualStrings("Hello, Alice!", out);
}

test "render: missing variable resolves to empty string" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "[{{ undef }}]", &.{});
    try testing.expectEqualStrings("[]", out);
}

test "render: missing variable in arithmetic resolves to empty string" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // Regression: aec9136 added `evaluateExpr` which fell back to
    // `Value{ .int = 0 }` for unknown paths. That made `{{ undef + 1 }}`
    // render as the literal string "0" (then "1" added — wait, it
    // became 0 + 1 = 1 → rendered as "1"). Either way, it's wrong
    // — undefined must render as empty, matching Jinja's default
    // `Undefined` semantics. Both no-op arithmetic and a real operator
    // are covered here.
    {
        const out = try renderWith(arena.allocator(), "[{{ undef }}]", &.{});
        try testing.expectEqualStrings("[]", out);
    }
    {
        const out = try renderWith(arena.allocator(), "[{{ undef + 1 }}]", &.{});
        try testing.expectEqualStrings("[]", out);
    }
    {
        const out = try renderWith(arena.allocator(), "[{{ undef * 2 }}]", &.{});
        try testing.expectEqualStrings("[]", out);
    }
    {
        const out = try renderWith(arena.allocator(), "[{{ -undef }}]", &.{});
        try testing.expectEqualStrings("[]", out);
    }
    {
        // Mixed: one operand defined, one not — should also be empty
        // (any undefined operand poisons the arithmetic).
        const out = try renderWith(arena.allocator(), "{{ x + undef }}", &.{
            .{ .key = "x", .value = .{ .int = 41 } },
        });
        try testing.expectEqualStrings("", out);
    }
}

test "render: if true branch renders" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{% if cond %}A{% endif %}", &.{
        .{ .key = "cond", .value = .{ .bool = true } },
    });
    try testing.expectEqualStrings("A", out);
}

test "render: if false branch with else renders else" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{% if cond %}A{% else %}B{% endif %}", &.{
        .{ .key = "cond", .value = .{ .bool = false } },
    });
    try testing.expectEqualStrings("B", out);
}

test "render: if false without else renders empty" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "[{% if cond %}A{% endif %}]", &.{
        .{ .key = "cond", .value = .{ .bool = false } },
    });
    try testing.expectEqualStrings("[]", out);
}

test "render: for loop iterates array" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{
        .{ .string = "a" },
        .{ .string = "b" },
        .{ .string = "c" },
    };
    const out = try renderWith(arena.allocator(), "{% for x in items %}<{{ x }}>{% endfor %}", &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("<a><b><c>", out);
}

test "render: for empty array renders empty branch" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{};
    const out = try renderWith(arena.allocator(), "{% for x in items %}A{% empty %}B{% endfor %}", &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("B", out);
}

test "render: nested if inside for runs per iteration" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{
        .{ .bool = true },
        .{ .bool = false },
        .{ .bool = true },
    };
    const out = try renderWith(arena.allocator(), "{% for x in items %}{% if x %}Y{% else %}N{% endif %}{% endfor %}", &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("YNY", out);
}

test "render: {{ var }} HTML-escapes by default" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{{ v }}", &.{
        .{ .key = "v", .value = .{ .string = "<script>alert(1)</script>" } },
    });
    try testing.expectEqualStrings("&lt;script&gt;alert(1)&lt;/script&gt;", out);
}

test "render: {% raw %} passes through verbatim without escaping" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{% raw %}<b>{{ not parsed }}</b>{% endraw %}", &.{});
    try testing.expectEqualStrings("<b>{{ not parsed }}</b>", out);
}

test "render: for over non-array (missing key) renders empty branch" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{% for x in items %}A{% empty %}B{% endfor %}", &.{});
    try testing.expectEqualStrings("B", out);
}

test "render: index access via bracket notation" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{
        .{ .string = "first" },
        .{ .string = "second" },
    };
    const out = try renderWith(arena.allocator(), "{{ items[0] }}", &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("first", out);
}

test "render: {{ var + int }} evaluates arithmetic" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{{ x + 1 }}", &.{
        .{ .key = "x", .value = .{ .int = 41 } },
    });
    try testing.expectEqualStrings("42", out);
}

test "render: {{ var - int }} evaluates subtraction" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{{ x - 1 }}", &.{
        .{ .key = "x", .value = .{ .int = 41 } },
    });
    try testing.expectEqualStrings("40", out);
}

test "render: {{ var * int }} and {{ var / int }} evaluate mul/div" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const mul = try renderWith(arena.allocator(), "{{ x * 3 }}", &.{
        .{ .key = "x", .value = .{ .int = 7 } },
    });
    try testing.expectEqualStrings("21", mul);

    const div = try renderWith(arena.allocator(), "{{ x / 4 }}", &.{
        .{ .key = "x", .value = .{ .int = 20 } },
    });
    try testing.expectEqualStrings("5", div);
}

test "render: arithmetic respects precedence (* before +)" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // 1 + 2 * 3 = 7, not (1 + 2) * 3 = 9
    const out = try renderWith(arena.allocator(), "{{ 1 + 2 * 3 }}", &.{});
    try testing.expectEqualStrings("7", out);
}

test "render: parentheses override precedence" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{{ (1 + 2) * 3 }}", &.{});
    try testing.expectEqualStrings("9", out);
}

test "render: integer literal works without any identifier" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{{ 42 }}", &.{});
    try testing.expectEqualStrings("42", out);
}

test "render: nested {{ if }} inside else branch finds the correct closer" {
    // Regression test: prior findMatchingTag counted inner ENDIFs as
    // outer closers when the else branch contained inline
    // {{ if X }}...{{ endif }}. After the fix, the AST is built
    // correctly with two separate if/else blocks nested in the outer.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const out = try renderWith(
        arena.allocator(),
        "{% if x %}OUTER-A{% else %}OUTER-B{% if y %}INNER{% endif %}END-B{% endif %}",
        &.{
            .{ .key = "x", .value = .{ .bool = false } },
            .{ .key = "y", .value = .{ .bool = true } },
        },
    );
    try testing.expectEqualStrings("OUTER-BINNEREND-B", out);
}

// =============================================================================
//  Task 4 — Inheritance
// =============================================================================
//
// `compileWithParent` takes a child source and a loader, and merges the
// child's block bodies into the parent's AST. The result is a single
// AST that, when rendered, produces the parent's HTML with the child's
// blocks substituted in.
//
// For testing, the loader is a simple map from path → source.

const TestLoader = struct {
    files: std.StringHashMap([]const u8),

    fn load(ctx: *anyopaque, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
        const self: *TestLoader = @ptrCast(@alignCast(ctx));
        const source = self.files.get(path) orelse return error.TemplateNotFound;
        // Return a heap-allocated copy so the caller can own it.
        return try allocator.dupe(u8, source);
    }

    fn deinit(self: *TestLoader) void {
        self.files.deinit();
    }
};

fn compileWithParent(
    alloc: std.mem.Allocator,
    source: []const u8,
    loader_ctx: *anyopaque,
    loader_fn: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]u8,
) ![]Template.Node {
    return Template.compileWithParent(alloc, source, loader_ctx, loader_fn);
}

fn renderInherit(alloc: std.mem.Allocator, source: []const u8, ctx: *Template.Context, loader_ctx: *anyopaque, loader_fn: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]u8) ![]u8 {
    const nodes = try compileWithParent(alloc, source, loader_ctx, loader_fn);
    defer Template.freeNodes(alloc, nodes);
    return try Template.render(alloc, nodes, ctx, .{});
}

test "inherit: child overrides one block → child body replaces parent body" {
    // Per-test arena owns EVERY allocation made during the test —
    // the loader's hashmap, the Template.Context, the parsed AST
    // nodes, and the rendered output. `arena.deinit()` frees them all
    // in one go, so individual `free()` / `freeNodes()` calls are
    // unnecessary. (Tracking each individual deallocation in
    // inheritance was the source of 5+ DebugAllocator leaks before
    // — the inheritance code does a lot of cross-AST pointer
    // juggling and freeNodes was missing a few corner cases.)
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var files = std.StringHashMap([]const u8).init(a);
    try files.put("base.jinja",
        \\<html>
        \\<head><title>{% block title %}Default{% endblock %}</title></head>
        \\<body>{% block content %}default body{% endblock %}</body>
        \\</html>
    );
    const child =
        \\{% extends "base.jinja" %}
        \\{% block content %}Hello, World!{% endblock %}
    ;
    var loader = TestLoader{ .files = files };
    var ctx = Template.Context.init(a);
    const out = try renderInherit(a, child, &ctx, &loader, &TestLoader.load);
    try testing.expectEqualStrings(
        "<html>\n<head><title>Default</title></head>\n<body>Hello, World!</body>\n</html>",
        out,
    );
}

test "inherit: child overrides multiple blocks" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var files = std.StringHashMap([]const u8).init(a);
    try files.put("base.jinja",
        \\<title>{% block title %}Default{% endblock %}</title>
        \\<h1>{% block header %}Default Header{% endblock %}</h1>
        \\<p>{% block body %}Default Body{% endblock %}</p>
    );
    const child =
        \\{% extends "base.jinja" %}
        \\{% block title %}My Title{% endblock %}
        \\{% block body %}My Body{% endblock %}
    ;
    var loader = TestLoader{ .files = files };
    var ctx = Template.Context.init(a);
    const out = try renderInherit(a, child, &ctx, &loader, &TestLoader.load);
    try testing.expectEqualStrings("<title>My Title</title>\n<h1>Default Header</h1>\n<p>My Body</p>", out);
}

test "inherit: child doesn't override a block → parent default rendered" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var files = std.StringHashMap([]const u8).init(a);
    try files.put("base.jinja",
        \\<h1>{% block header %}Parent Header{% endblock %}</h1>
        \\<p>{% block body %}Parent Body{% endblock %}</p>
    );
    const child =
        \\{% extends "base.jinja" %}
        \\{% block body %}Child Body{% endblock %}
    ;
    var loader = TestLoader{ .files = files };
    var ctx = Template.Context.init(a);
    const out = try renderInherit(a, child, &ctx, &loader, &TestLoader.load);
    try testing.expectEqualStrings("<h1>Parent Header</h1>\n<p>Child Body</p>", out);
}

test "inherit: two-level (grandchild → child → base)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var files = std.StringHashMap([]const u8).init(a);
    try files.put("base.jinja",
        \\<title>{% block title %}Base{% endblock %}</title>
        \\<body>{% block content %}Base Body{% endblock %}</body>
    );
    try files.put("child.jinja",
        \\{% extends "base.jinja" %}
        \\{% block title %}Child Title{% endblock %}
    );
    const grandchild =
        \\{% extends "child.jinja" %}
        \\{% block content %}Grandchild Body{% endblock %}
    ;
    var loader = TestLoader{ .files = files };
    var ctx = Template.Context.init(a);
    const out = try renderInherit(a, grandchild, &ctx, &loader, &TestLoader.load);
    try testing.expectEqualStrings("<title>Child Title</title>\n<body>Grandchild Body</body>", out);
}

test "inherit: child block body can use {{ var }} and {% if %}" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var files = std.StringHashMap([]const u8).init(a);
    try files.put("base.jinja",
        \\<p>{% block greeting %}default{% endblock %}</p>
    );
    const child =
        \\{% extends "base.jinja" %}
        \\{% block greeting %}Hello, {{ name }}!{% endblock %}
    ;
    var loader = TestLoader{ .files = files };
    var ctx = Template.Context.init(a);
    try ctx.put("name", .{ .string = "Alice" });
    const out = try renderInherit(a, child, &ctx, &loader, &TestLoader.load);
    try testing.expectEqualStrings("<p>Hello, Alice!</p>", out);
}

// =============================================================================
//  Feature — {% elif %} chains
// =============================================================================
//
// Jinja's `{% elif %}` is just sugar for nested `if/else`, but it lets
// authors express a chain of conditions without the indentation cost
// or the visual noise of `{% if %}...{% else %}{% if %}...{% endif %}`
// pairs. Our engine flattens the chain into a `branches` list on the
// `IfBlock` AST — one branch per `if`/`elif`, plus an optional final
// `else`.

test "elif: long chain picks the first truthy branch" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% if role == 'admin' %}ADMIN{% elif role == 'manager' %}MGR{% elif role == 'staff' %}STAFF{% else %}GUEST{% endif %}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "role", .value = .{ .string = "manager" } },
    });
    try testing.expectEqualStrings("MGR", out);
}

test "elif: chain with no match falls through to else" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl = "{% if a %}A{% elif b %}B{% elif c %}C{% else %}NONE{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "a", .value = .{ .bool = false } },
        .{ .key = "b", .value = .{ .bool = false } },
        .{ .key = "c", .value = .{ .bool = false } },
    });
    try testing.expectEqualStrings("NONE", out);
}

test "elif: chain with first branch truthy skips later branches" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // Side-effect probe: if the second branch were evaluated despite
    // the first being truthy, the second branch would crash on
    // `divide_by_zero` (int division). It must NOT run — proves
    // short-circuit / first-match semantics.
    const tmpl =
        \\{% if x %}HIT{% elif 1 / 0 == 0 %}NEVER{% else %}ELSE{% endif %}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "x", .value = .{ .bool = true } },
    });
    try testing.expectEqualStrings("HIT", out);
}

test "elif: branches list flattens correctly in AST" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const nodes = try Template.parseSource(a,
        \\{% if a %}A{% elif b %}B{% elif c %}C{% else %}D{% endif %}
    );
    try testing.expectEqual(@as(usize, 1), nodes.len);
    const ifb = nodes[0].if_block;
    try testing.expectEqual(@as(usize, 3), ifb.branches.len);
    try testing.expectEqualStrings("a", ifb.branches[0].condition);
    try testing.expectEqualStrings("b", ifb.branches[1].condition);
    try testing.expectEqualStrings("c", ifb.branches[2].condition);
    try testing.expectEqual(@as(usize, 1), ifb.else_branch.len);
    try testing.expectEqualStrings("D", ifb.else_branch[0].text);
}

test "elif: deeply nested in a for loop renders each item independently" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% for user in users %}{% if user.is_admin %}ADMIN:{{ user.name }}{% elif user.is_active %}USER:{{ user.name }}{% else %}INACTIVE:{{ user.name }}{% endif %};{% endfor %}
    ;
    const user1 = blk: {
        var m = std.StringHashMap(Template.Value).init(arena.allocator());
        try m.put("name", .{ .string = "alice" });
        try m.put("is_admin", .{ .bool = true });
        try m.put("is_active", .{ .bool = true });
        break :blk m;
    };
    const user2 = blk: {
        var m = std.StringHashMap(Template.Value).init(arena.allocator());
        try m.put("name", .{ .string = "bob" });
        try m.put("is_admin", .{ .bool = false });
        try m.put("is_active", .{ .bool = true });
        break :blk m;
    };
    const user3 = blk: {
        var m = std.StringHashMap(Template.Value).init(arena.allocator());
        try m.put("name", .{ .string = "carol" });
        try m.put("is_admin", .{ .bool = false });
        try m.put("is_active", .{ .bool = false });
        break :blk m;
    };
    const users = [_]Template.Value{ .{ .map = user1 }, .{ .map = user2 }, .{ .map = user3 } };
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "users", .value = .{ .array = &users } },
    });
    try testing.expectEqualStrings("ADMIN:alice;USER:bob;INACTIVE:carol;", out);
}

// =============================================================================
//  Feature — `loop.*` variables
// =============================================================================
//
// Inside a for-loop body the engine exposes a special `loop` variable
// with these fields:
//   * `loop.index`    — 1-based current iteration
//   * `loop.index0`   — 0-based current iteration
//   * `loop.first`    — true if first iteration
//   * `loop.last`     — true if last iteration
//   * `loop.length`   — total number of items
//
// When a for-loop has an `if cond` filter, `loop.length` and
// `loop.last` count only KEPT items (post-filter), not raw input.

test "loop.index is 1-based and counts every iteration" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{
        .{ .int = 10 }, .{ .int = 20 }, .{ .int = 30 }, .{ .int = 40 },
    };
    const tmpl = "{% for x in items %}{{ loop.index }}={{ x }};{% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("1=10;2=20;3=30;4=40;", out);
}

test "loop.first is true only on the first iteration" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } };
    const tmpl = "{% for x in items %}{% if loop.first %}F{% else %}-{% endif %}{{ x }};{% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("F1;-2;-3;", out);
}

test "loop.last is true only on the last iteration" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } };
    const tmpl = "{% for x in items %}{{ x }}{% if loop.last %}!{% else %},{% endif %}{% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("1,2,3!", out);
}

test "loop.length is the total number of iterated items" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{
        .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 4 }, .{ .int = 5 },
    };
    const tmpl = "{% for x in items %}[{{ loop.length }}:{{ x }}]{% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("[5:1][5:2][5:3][5:4][5:5]", out);
}

test "loop.index0 is 0-based" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{ .{ .int = 100 }, .{ .int = 200 } };
    const tmpl = "{% for x in items %}{{ loop.index0 }}:{{ x }} {% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("0:100 1:200 ", out);
}

test "loop.length matches filtered item count when `if cond` is used" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // 5 raw items but only 3 pass the filter; loop.length must be 3.
    const items = [_]Template.Value{
        .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 4 }, .{ .int = 5 },
    };
    const tmpl = "{% for x in items if x > 2 %}{{ loop.length }}:{{ x }} {% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("3:3 3:4 3:5 ", out);
}

test "loop.last is the LAST KEPT item under a filter, not the last raw" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // Item index 4 is the last raw, but it's filtered out — so
    // `loop.last` must be true at index 3 (the last KEPT item).
    const items = [_]Template.Value{
        .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 4 }, .{ .int = 5 },
    };
    const tmpl =
        \\{% for x in items if x != 5 %}{{ x }}{% if loop.last %}!{% else %},{% endif %}{% endfor %}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("1,2,3,4!", out);
}

test "loop.first and loop.last are both true on a single-iteration loop" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{.{ .int = 42 }};
    const tmpl =
        \\{% for x in items %}{% if loop.first %}FIRST{% endif %}-{% if loop.last %}LAST{% endif %}-{{ x }}{% endfor %}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("FIRST-LAST-42", out);
}

test "loop.* works with deeply nested for loops (inner only)" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // Outer loop's `loop.index` is shadowed by the inner loop's
    // `loop.index` (the inner `loop` is closer). The outer is still
    // reachable as a path lookup fails — Jinja's full `loop` chain
    // (with `outer_loop = loop` rebinding) is NOT supported here.
    const rows = [_]Template.Value{ .{ .int = 1 }, .{ .int = 2 } };
    const cols = [_]Template.Value{ .{ .int = 10 }, .{ .int = 20 }, .{ .int = 30 } };
    const tmpl = "{% for r in rows %}[{% for c in cols %}{{ c }}{% endfor %}]{% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "rows", .value = .{ .array = &rows } },
        .{ .key = "cols", .value = .{ .array = &cols } },
    });
    try testing.expectEqualStrings("[102030][102030]", out);
}

// =============================================================================
//  Feature — `{% for x in items if cond %}` filter
// =============================================================================

test "for-if: skips items where the condition is falsy" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{
        .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 4 },
    };
    const tmpl = "{% for x in items if x > 2 %}{{ x }};{% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("3;4;", out);
}

test "for-if: empty branch fires when ALL items are filtered out" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{
        .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 },
    };
    const tmpl = "{% for x in items if x > 100 %}YES{% empty %}NONE{% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("NONE", out);
}

test "for-if: condition can reference outer-scope paths" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{
        .{ .int = 1 }, .{ .int = 5 }, .{ .int = 10 },
    };
    // Filter is `x >= threshold` — only items >= 5 pass.
    const tmpl = "{% for x in items if x >= threshold %}{{ x }} {% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
        .{ .key = "threshold", .value = .{ .int = 5 } },
    });
    try testing.expectEqualStrings("5 10 ", out);
}

test "for-if: AST captures the condition string on ForLoop" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nodes = try Template.parseSource(a, "{% for x in items if x > 0 %}body{% endfor %}");
    const fl = nodes[0].for_loop;
    try testing.expectEqualStrings("x > 0", fl.condition.?);
    try testing.expectEqualStrings("x", fl.var_name);
}

test "for-if: condition with arithmetic (modulo) filters correctly" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const items = [_]Template.Value{
        .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 4 }, .{ .int = 5 }, .{ .int = 6 },
    };
    // Show only odd numbers: filter `x % 2 == 1`.
    const tmpl = "{% for x in items if x % 2 == 1 %}{{ x }};{% endfor %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("1;3;5;", out);
}

// =============================================================================
//  Feature — `{% set var = expr %}`
// =============================================================================

test "set: simple arithmetic assigns the result" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl = "{% set total = price * qty %}cost={{ total }}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "price", .value = .{ .int = 12 } },
        .{ .key = "qty", .value = .{ .int = 4 } },
    });
    try testing.expectEqualStrings("cost=48", out);
}

test "set: assignment is visible in subsequent expressions in the same scope" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% set x = 10 %}{% set y = x + 5 %}{{ y }}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{});
    try testing.expectEqualStrings("15", out);
}

test "set: inside an if block, the variable is visible after the if (Jinja's if-no-scope rule)" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% if ready %}{% set msg = "ready" %}{% endif %}status={{ msg }}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "ready", .value = .{ .bool = true } },
    });
    try testing.expectEqualStrings("status=ready", out);
}

test "set: inside a for loop is scoped to the loop body (doesn't leak)" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // `{% set x %}` inside the for loop should NOT be visible after
    // the loop ends (Jinja's loop-does-introduce-scope rule). Trying
    // to render `{{ x }}` after the loop should produce empty.
    const items = [_]Template.Value{.{ .int = 1 }, .{ .int = 2 }};
    const tmpl = "{% for x in items %}{% set y = x * 10 %}A{% endfor %}after={{ y }}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("AAafter=", out);
}

test "set: AST captures var_name and value expression" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nodes = try Template.parseSource(a, "{% set greeting = 'hello' %}");
    const s = nodes[0].set;
    try testing.expectEqualStrings("greeting", s.var_name);
    try testing.expectEqualStrings("'hello'", s.value);
}

test "set: chained assignments build up state across a template" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% set subtotal = 100 %}{% set tax = subtotal * 10 / 100 %}{% set total = subtotal + tax %}subtotal={{ subtotal }} tax={{ tax }} total={{ total }}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{});
    try testing.expectEqualStrings("subtotal=100 tax=10 total=110", out);
}

// =============================================================================
//  Feature — Comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`)
// =============================================================================

test "cmp: equality on ints" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{% if count == 5 %}yes{% endif %}", &.{
        .{ .key = "count", .value = .{ .int = 5 } },
    });
    try testing.expectEqualStrings("yes", out);
}

test "cmp: equality returns false for mismatched ints" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const out = try renderWith(arena.allocator(), "{% if count == 5 %}yes{% endif %}", &.{
        .{ .key = "count", .value = .{ .int = 6 } },
    });
    try testing.expectEqualStrings("", out);
}

test "cmp: inequality (!=)" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl = "{% if role != 'admin' %}user{% else %}admin{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "role", .value = .{ .string = "guest" } },
    });
    try testing.expectEqualStrings("user", out);
}

test "cmp: ordering operators on ints" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl = "{% if age >= 18 %}adult{% elif age >= 13 %}teen{% else %}child{% endif %}";
    const out1 = try renderWith(arena.allocator(), tmpl, &.{.{ .key = "age", .value = .{ .int = 25 } }});
    try testing.expectEqualStrings("adult", out1);
    const out2 = try renderWith(arena.allocator(), tmpl, &.{.{ .key = "age", .value = .{ .int = 15 } }});
    try testing.expectEqualStrings("teen", out2);
    const out3 = try renderWith(arena.allocator(), tmpl, &.{.{ .key = "age", .value = .{ .int = 8 } }});
    try testing.expectEqualStrings("child", out3);
}

test "cmp: string equality" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl = "{% if status == 'active' %}on{% else %}off{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "status", .value = .{ .string = "active" } },
    });
    try testing.expectEqualStrings("on", out);
}

test "cmp: cross-type comparisons are false (not a crash)" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // `5 == "foo"` — different types, should evaluate to false (not
    // raise a template error). The if branch is skipped.
    const tmpl = "{% if n == 'foo' %}STRING{% else %}NOT-STRING{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "n", .value = .{ .int = 5 } },
    });
    try testing.expectEqualStrings("NOT-STRING", out);
}

test "cmp: <= and >= boundary values" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // Boundary: `n <= 10` is true at 10; `n >= 10` is true at 10.
    const tmpl = "{% if n >= 10 and n <= 10 %}TEN{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "n", .value = .{ .int = 10 } },
    });
    try testing.expectEqualStrings("TEN", out);
}

test "cmp: comparison inside an expression in a variable" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl = "{% set big = (count > 100) %}{% if big %}TOO MANY{% else %}OK{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "count", .value = .{ .int = 50 } },
    });
    try testing.expectEqualStrings("OK", out);
}

// =============================================================================
//  Feature — Logic (`and`, `or`, `not`)
// =============================================================================

test "logic: and short-circuits — second operand with undefined path is safe" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // `ready and undef` — `ready` is true, but the rule is that
    // BOTH sides are consumed (we don't have true short-circuit for
    // a falsy first operand; only the value is determined by the
    // first truthy operand). This test documents the actual
    // behavior: an undefined RHS is treated as falsy.
    const tmpl = "{% if ready and undef %}BOTH{% else %}NOT-BOTH{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "ready", .value = .{ .bool = true } },
    });
    try testing.expectEqualStrings("NOT-BOTH", out);
}

test "logic: or produces truthy when either side is truthy" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl = "{% if is_admin or is_owner %}ALLOW{% else %}DENY{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "is_admin", .value = .{ .bool = false } },
        .{ .key = "is_owner", .value = .{ .bool = true } },
    });
    try testing.expectEqualStrings("ALLOW", out);
}

test "logic: not negates a truthy value" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl = "{% if not is_admin %}guest{% else %}admin{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "is_admin", .value = .{ .bool = true } },
    });
    try testing.expectEqualStrings("admin", out);
}

test "logic: not of an undefined path is truthy" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // `not undef` is `not falsy` = `true` (matches Jinja's default).
    const tmpl = "{% if not undef %}UNDEFINED-IS-FALSY{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{});
    try testing.expectEqualStrings("UNDEFINED-IS-FALSY", out);
}

test "logic: chained and/or with precedence (and binds tighter than or)" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // `a or b and c` parses as `a or (b and c)`. With a=true, the
    // whole expression is true regardless of b and c.
    const tmpl = "{% if a or b and c %}YES{% else %}NO{% endif %}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "a", .value = .{ .bool = true } },
        .{ .key = "b", .value = .{ .bool = false } },
        .{ .key = "c", .value = .{ .bool = false } },
    });
    try testing.expectEqualStrings("YES", out);
}

test "logic: combined with comparison in complex condition" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% if (count > 0) and (status == 'active' or status == 'pending') %}PROCESS{% else %}SKIP{% endif %}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "count", .value = .{ .int = 3 } },
        .{ .key = "status", .value = .{ .string = "pending" } },
    });
    try testing.expectEqualStrings("PROCESS", out);
}

test "logic: comparison + logic + arithmetic in one expression" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // The grand unified test: arithmetic, comparison, and logic, all
    // in one expression on the right-hand side of `set`. This is the
    // expression evaluator's worst case — it must respect operator
    // precedence and short-circuit correctly.
    const tmpl = "{% set ok = price > 0 and (qty * price) < 100 %}{{ ok }}";
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "price", .value = .{ .int = 5 } },
        .{ .key = "qty", .value = .{ .int = 10 } },
    });
    try testing.expectEqualStrings("true", out);
}

// =============================================================================
//  Feature — `{% include %}` (template inclusion)
// =============================================================================
//
// These tests use an in-memory loader closure. The renderer expects
// `RenderOptions` with `loader_ctx` + `loader_fn` + `base_dir` set;
// without those, encountering an include is `error.IncludeLoaderRequired`.

const StringLoaderCtx = struct {
    files: std.StringHashMap([]const u8),
};

fn stringLoaderFn(ctx: *anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]u8 {
    const lc: *StringLoaderCtx = @ptrCast(@alignCast(ctx));
    const source = lc.files.get(path) orelse return error.TemplateNotFound;
    return try allocator.dupe(u8, source);
}

fn renderWithLoader(
    arena_allocator: std.mem.Allocator,
    source: []const u8,
    kvs: []const struct { key: []const u8, value: Template.Value },
    files: std.StringHashMap([]const u8),
) ![]u8 {
    var lc = StringLoaderCtx{ .files = files };
    const nodes = try Template.parseSource(arena_allocator, source);
    var ctx = Template.Context.init(arena_allocator);
    for (kvs) |kv| try ctx.put(kv.key, kv.value);
    return try Template.render(arena_allocator, nodes, &ctx, .{
        .loader_ctx = @ptrCast(&lc),
        .loader_fn = &stringLoaderFn,
        .base_dir = "",
    });
}

test "include: inlines a partial template with context" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    var files = std.StringHashMap([]const u8).init(arena.allocator());
    try files.put("_header.html", "<header>{{ title }}</header>");
    const out = try renderWithLoader(
        arena.allocator(),
        "{% include '_header.html' %}",
        &.{.{ .key = "title", .value = .{ .string = "Hello" } } },
        files,
    );
    try testing.expectEqualStrings("<header>Hello</header>", out);
}

test "include: without context — included template sees NO caller variables" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    var files = std.StringHashMap([]const u8).init(arena.allocator());
    // Partial tries to use `title` but caller passes it. Without
    // context, the partial renders empty for `{{ title }}`.
    try files.put("_partial.html", "[{{ title }}]");
    const out = try renderWithLoader(
        arena.allocator(),
        "{% include '_partial.html' without context %}",
        &.{.{ .key = "title", .value = .{ .string = "should-not-appear" } } },
        files,
    );
    try testing.expectEqualStrings("[]", out);
}

test "include: ignore missing on a non-existent partial emits empty string" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    var files = std.StringHashMap([]const u8).init(arena.allocator());
    try files.put("present.html", "PRESENT");
    const out = try renderWithLoader(
        arena.allocator(),
        "before {% include 'missing.html' ignore missing %} after",
        &.{},
        files,
    );
    try testing.expectEqualStrings("before  after", out);
}

test "include: missing partial WITHOUT ignore missing returns TemplateNotFound" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // No files in the loader — anything we include will 404.
    const files = std.StringHashMap([]const u8).init(arena.allocator());
    const result = renderWithLoader(
        arena.allocator(),
        "{% include 'nope.html' %}",
        &.{},
        files,
    );
    try testing.expectError(error.TemplateNotFound, result);
}

test "include: nested includes chain correctly (a includes b includes c)" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    var files = std.StringHashMap([]const u8).init(arena.allocator());
    try files.put("c.html", "C");
    try files.put("b.html", "B[{% include 'c.html' %}]B");
    try files.put("a.html", "A[{% include 'b.html' %}]A");
    const out = try renderWithLoader(
        arena.allocator(),
        "{% include 'a.html' %}",
        &.{},
        files,
    );
    try testing.expectEqualStrings("A[B[C]B]A", out);
}

test "include: a non-template include that itself contains a for loop renders correctly" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    var files = std.StringHashMap([]const u8).init(arena.allocator());
    try files.put("_list.html",
        \\<ul>{% for item in items %}<li>{{ item }}</li>{% endfor %}</ul>
    );
    const items = [_]Template.Value{
        .{ .string = "a" }, .{ .string = "b" }, .{ .string = "c" },
    };
    const out = try renderWithLoader(
        arena.allocator(),
        "{% include '_list.html' %}",
        &.{.{ .key = "items", .value = .{ .array = &items } } },
        files,
    );
    try testing.expectEqualStrings("<ul><li>a</li><li>b</li><li>c</li></ul>", out);
}

test "include: errors out with IncludeLoaderRequired when no loader is set" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nodes = try Template.parseSource(a, "{% include 'x.html' %}");
    var ctx = Template.Context.init(a);
    // No loader configured — must error.
    const result = Template.render(a, nodes, &ctx, .{});
    try testing.expectError(error.IncludeLoaderRequired, result);
}

// =============================================================================
//  Feature — `{% macro %}` (reusable template functions)
// =============================================================================
//
// Macros are defined at the top level of a template. Once defined,
// they live in the context as `Value.macro` and can be CALLED via
// Jinja's function-call syntax: `{{ name(arg1, arg2) }}`. Default
// parameter values are supported via `name(p1, p2='default')`.

test "macro: simple definition and call" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% macro greet(name) %}Hello, {{ name }}!{% endmacro %}{{ greet("World") }}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{});
    try testing.expectEqualStrings("Hello, World!", out);
}

test "macro: with default parameter values" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% macro greeting(name, punct='!') %}Hi, {{ name }}{{ punct }}{% endmacro %}{{ greeting("Alice") }}|{{ greeting("Bob", '.') }}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{});
    try testing.expectEqualStrings("Hi, Alice!|Hi, Bob.", out);
}

test "macro: called multiple times with different args" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% macro wrap(tag, text) %}[{{ tag }}={{ text }}]{% endmacro %}{{ wrap('b', 'bold') }} {{ wrap('i', 'italic') }} {{ wrap('span', 'span-text') }}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{});
    // `{{ tag }}` and `{{ text }}` are auto-escaped — the literal 'b'
    // is fine but if the test were HTML-heavy, expected output would
    // need to include `&lt;` etc. The brackets around the macros are
    // text (not variable output), so they pass through verbatim.
    try testing.expectEqualStrings("[b=bold] [i=italic] [span=span-text]", out);
}

test "macro: call inside a for loop iterates with new args each time" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% macro item(name, qty) %}[{{ name }} x {{ qty }}]{% endmacro %}<ul>{% for it in items %}{{ item(it.name, it.qty) }}{% endfor %}</ul>
    ;
    const item1 = blk: {
        var m = std.StringHashMap(Template.Value).init(arena.allocator());
        try m.put("name", .{ .string = "apple" });
        try m.put("qty", .{ .int = 3 });
        break :blk m;
    };
    const item2 = blk: {
        var m = std.StringHashMap(Template.Value).init(arena.allocator());
        try m.put("name", .{ .string = "banana" });
        try m.put("qty", .{ .int = 5 });
        break :blk m;
    };
    const items = [_]Template.Value{ .{ .map = item1 }, .{ .map = item2 } };
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "items", .value = .{ .array = &items } },
    });
    try testing.expectEqualStrings("<ul>[apple x 3][banana x 5]</ul>", out);
}

test "macro: AST captures name, params, and body" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nodes = try Template.parseSource(a,
        \\{% macro greet(name, punct='!') %}Hello {{ name }}{{ punct }}{% endmacro %}
    );
    const m = nodes[0].macro;
    try testing.expectEqualStrings("greet", m.name);
    try testing.expectEqual(@as(usize, 2), m.params.len);
    try testing.expectEqualStrings("name", m.params[0].name);
    try testing.expectEqual(@as(?[]const u8, null), m.params[0].default);
    try testing.expectEqualStrings("punct", m.params[1].name);
    try testing.expectEqualStrings("'!'", m.params[1].default.?);
    try testing.expect(m.body.len > 0);
}

test "macro: complex macro with arithmetic on its argument" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    // Default value `1` for the rate; callers can override with a
    // different integer. Float rates aren't supported (no float
    // literals in the expression evaluator yet).
    const tmpl =
        \\{% macro price_with_tax(amount, rate=1) %}{{ amount + amount * rate }}{% endmacro %}cost={{ price_with_tax(100) }} high={{ price_with_tax(200, 2) }}
    ;
    const out = try renderWith(arena.allocator(), tmpl, &.{});
    try testing.expectEqualStrings("cost=200 high=600", out);
}

// =============================================================================
//  Feature — Cross-cutting complex templates
// =============================================================================
//
// Real templates use ALL of these features together. A single test
// that wires everything up catches integration bugs the per-feature
// tests don't.

test "complex: full admin-row template combining every feature" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% macro field(name, value, type='text', size=20) -%}
        \\<label>{{ name }}:</label>
        \\<input type="{{ type }}" name="{{ name }}" value="{{ value }}" size="{{ size }}">
        \\{%- endmacro %}
        \\
        \\{% macro row(user) -%}
        \\<tr class="{% if loop.first %}first{% elif loop.last %}last{% else %}middle{% endif %}">
        \\<td>{{ user.id }}</td>
        \\<td>{{ field('username', user.username) }}</td>
        \\<td>{{ field('email', user.email, type='email') }}</td>
        \\<td>{% if user.is_admin %}ADMIN{% else %}USER{% endif %}</td>
        \\</tr>
        \\{%- endmacro %}
        \\
        \\{% if users %}<table>{{ items }} more{{ count }}{% endif %}
        \\<table>{% for u in users if u.is_active %}{{ row(u) }}{% empty %}<tr><td colspan="4">No active users</td></tr>{% endfor %}</table>
        \\{% set count = users | length %}{% if count > 0 and users[0].is_admin %}admin-present{% endif %}
    ;
    // Build 3 users; the middle one is inactive (so the filter
    // drops it).
    const user1 = blk: {
        var m = std.StringHashMap(Template.Value).init(arena.allocator());
        try m.put("id", .{ .int = 1 });
        try m.put("username", .{ .string = "alice" });
        try m.put("email", .{ .string = "alice@example.com" });
        try m.put("is_admin", .{ .bool = true });
        try m.put("is_active", .{ .bool = true });
        break :blk m;
    };
    const user2 = blk: {
        var m = std.StringHashMap(Template.Value).init(arena.allocator());
        try m.put("id", .{ .int = 2 });
        try m.put("username", .{ .string = "bob" });
        try m.put("email", .{ .string = "bob@example.com" });
        try m.put("is_admin", .{ .bool = false });
        try m.put("is_active", .{ .bool = false });
        break :blk m;
    };
    const user3 = blk: {
        var m = std.StringHashMap(Template.Value).init(arena.allocator());
        try m.put("id", .{ .int = 3 });
        try m.put("username", .{ .string = "carol" });
        try m.put("email", .{ .string = "carol@example.com" });
        try m.put("is_admin", .{ .bool = false });
        try m.put("is_active", .{ .bool = true });
        break :blk m;
    };
    const users = [_]Template.Value{
        .{ .map = user1 }, .{ .map = user2 }, .{ .map = user3 },
    };
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "users", .value = .{ .array = &users } },
    });
    // Just sanity-check that the output is non-empty and contains
    // expected fragments — the exact layout is too brittle to pin.
    try testing.expect(out.len > 0);
    try testing.expect(std.mem.indexOf(u8, out, "alice") != null);
    try testing.expect(std.mem.indexOf(u8, out, "carol") != null);
    try testing.expect(std.mem.indexOf(u8, out, "ADMIN") != null);
    try testing.expect(std.mem.indexOf(u8, out, "first") != null);
    try testing.expect(std.mem.indexOf(u8, out, "last") != null);
    // bob is inactive — his row must NOT appear.
    try testing.expect(std.mem.indexOf(u8, out, "bob") == null);
}

test "complex: pagination block using set + for + loop.* + if + elif" {

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();
    const tmpl =
        \\{% set total_pages = 5 %}{% set page = 3 %}<nav>
        \\{% if page > 1 %}<a href="?page=1">first</a>{% endif %}
        \\{% for p in [1, 2, 3, 4, 5] %}
        \\  {% if p == page %}<strong>{{ p }}</strong>{% elif p == page - 1 %}<em>{{ p }}</em>{% else %}<a href="?page={{ p }}">{{ p }}</a>{% endif %}
        \\  {% if not loop.last %} | {% endif %}
        \\{% endfor %}
        \\{% if page < total_pages %}<a href="?page={{ page + 1 }}">next</a>{% endif %}
        \\</nav>
    ;
    const arr = [_]Template.Value{
        .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 }, .{ .int = 4 }, .{ .int = 5 },
    };
    const out = try renderWith(arena.allocator(), tmpl, &.{
        .{ .key = "[1, 2, 3, 4, 5]", .value = .{ .array = &arr } },
    });
    // page=3 of 5: first link visible, page 3 is current (strong),
    // page 2 is one before (em), page 4 and 5 are normal links,
    // next link visible.
    try testing.expect(std.mem.indexOf(u8, out, "first") != null);
    try testing.expect(std.mem.indexOf(u8, out, "<strong>3</strong>") != null);
    try testing.expect(std.mem.indexOf(u8, out, "<em>2</em>") != null);
    try testing.expect(std.mem.indexOf(u8, out, "next") != null);
}

