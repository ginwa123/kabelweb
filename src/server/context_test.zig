// Tests for the per-request Context value bag and its HttpResponse
// redirectWithContext integration. Tests are written FIRST (TDD); impl in
// context.zig is the smallest change that turns each test green.
const std = @import("std");
const context_mod = @import("context.zig");

const Context = context_mod.Context;
const Value = context_mod.Value;
const ContextStore = context_mod.ContextStore;
const contextFromRequest = context_mod.contextFromRequest;

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;
const testing_allocator = std.testing.allocator;

// ═══════════════════════════════════════════════════════════════════════════
//  Context value bag — basic put/get
// ═══════════════════════════════════════════════════════════════════════════

test "Context: put then get returns the value" {
    var ctx = Context.init(testing_allocator);
    defer ctx.deinit();

    try ctx.put("user_id", .{ .int = 42 });

    const got = ctx.get("user_id").?;
    try expectEqual(@as(i64, 42), got.int);
}

test "Context: get on missing key returns null" {
    var ctx = Context.init(testing_allocator);
    defer ctx.deinit();

    try expect(ctx.get("nope") == null);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Context value bag — parent chain
// ═══════════════════════════════════════════════════════════════════════════

test "Context: child get walks parent chain" {
    var parent = Context.init(testing_allocator);
    defer parent.deinit();
    try parent.put("flash", .{ .string = "saved" });

    var child = parent.withParent();
    defer child.deinit();
    try child.put("request_id", .{ .string = "abc" });

    // The child sees its own value.
    try expectEqualStrings("abc", child.get("request_id").?.string);
    // The child also walks the parent chain.
    try expectEqualStrings("saved", child.get("flash").?.string);
}

test "Context: child get overrides parent value with same key" {
    var parent = Context.init(testing_allocator);
    defer parent.deinit();
    try parent.put("role", .{ .string = "guest" });

    var child = parent.withParent();
    defer child.deinit();
    try child.put("role", .{ .string = "admin" });

    // The child's local value shadows the parent's.
    try expectEqualStrings("admin", child.get("role").?.string);
    // The parent's value is unchanged.
    try expectEqualStrings("guest", parent.get("role").?.string);
}

// ═══════════════════════════════════════════════════════════════════════════
//  ContextStore — server-side session storage keyed by opaque ID
// ═══════════════════════════════════════════════════════════════════════════

test "ContextStore: put then get returns the context" {
    const store = try ContextStore.create(testing_allocator);
    defer store.deinit();

    // newContext returns a store-owned Context — no defer deinit.
    const ctx = try store.newContext();
    try ctx.put("user_id", .{ .int = 7 });

    try store.put("abc123", ctx);

    const got = store.get("abc123").?;
    try expectEqual(@as(i64, 7), got.get("user_id").?.int);
}

test "ContextStore: remove drops the entry AND frees the owned Context" {
    const store = try ContextStore.create(testing_allocator);
    defer store.deinit();

    const ctx = try store.newContext();
    try ctx.put("user_id", .{ .int = 7 });

    try store.put("abc123", ctx);
    try expect(store.get("abc123") != null);

    store.remove("abc123");
    try expect(store.get("abc123") == null);
}

test "ContextStore: get on missing id returns null" {
    const store = try ContextStore.create(testing_allocator);
    defer store.deinit();

    try expect(store.get("missing") == null);
}

// ═══════════════════════════════════════════════════════════════════════════
//  contextFromRequest — rebuild a Context from the incoming Cookie header
// ═══════════════════════════════════════════════════════════════════════════

test "contextFromRequest: reads ctx=<id> from Cookie header" {
    const store = try ContextStore.create(testing_allocator);
    defer store.deinit();

    const ctx = try store.newContext();
    try ctx.put("user_id", .{ .int = 99 });
    try store.put("abc123", ctx);

    var headers = std.StringHashMap([]const u8).init(testing_allocator);
    defer headers.deinit();
    try headers.put("Cookie", "ctx=abc123");

    const StubReq = struct {
        headers: std.StringHashMap([]const u8),
    };
    const stub = StubReq{ .headers = headers };

    const got = contextFromRequest(stub, store);
    try expectEqualStrings("abc123", got.id.?);
    try expectEqual(@as(i64, 99), got.context.?.get("user_id").?.int);
}

test "contextFromRequest: returns null when no Cookie header" {
    const store = try ContextStore.create(testing_allocator);
    defer store.deinit();

    const StubReq = struct {
        headers: std.StringHashMap([]const u8),
    };

    var headers = std.StringHashMap([]const u8).init(testing_allocator);
    defer headers.deinit();
    const stub = StubReq{ .headers = headers };

    const got = contextFromRequest(stub, store);
    try expect(got.context == null);
    try expect(got.id == null);
}

test "contextFromRequest: returns null context when ctx=<id> not in store" {
    const store = try ContextStore.create(testing_allocator);
    defer store.deinit();

    const StubReq = struct {
        headers: std.StringHashMap([]const u8),
    };

    var headers = std.StringHashMap([]const u8).init(testing_allocator);
    defer headers.deinit();
    try headers.put("Cookie", "ctx=ghost");
    const stub = StubReq{ .headers = headers };

    const got = contextFromRequest(stub, store);
    // The id parsed from the cookie IS present (so the listen loop can
    // decide to evict it if it ever existed), but the context lookup
    // returns null.
    try expectEqualStrings("ghost", got.id.?);
    try expect(got.context == null);
}

test "contextFromRequest: ignores non-ctx cookies in the header" {
    const store = try ContextStore.create(testing_allocator);
    defer store.deinit();

    const ctx = try store.newContext();
    try store.put("right-id", ctx);

    var headers = std.StringHashMap([]const u8).init(testing_allocator);
    defer headers.deinit();
    // Multiple cookies; only the ctx= one should be matched.
    try headers.put("Cookie", "session=foo; ctx=right-id; theme=dark");

    const StubReq = struct {
        headers: std.StringHashMap([]const u8),
    };
    const stub = StubReq{ .headers = headers };

    // The lookup should find "right-id" via the ctx= cookie — proves the
    // parser ignores the surrounding non-ctx cookies.
    const got = contextFromRequest(stub, store);
    try expect(got.context != null);
    try expectEqualStrings("right-id", got.id.?);
}