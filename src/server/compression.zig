//! gzip response compression (RFC 1952) over std.compress.flate, no dependencies.

const std = @import("std");
const flate = std.compress.flate;
const http_parser = @import("http_parser.zig");

const HttpRequest = http_parser.HttpRequest;
const HttpResponse = http_parser.HttpResponse;
const Headers = std.StringHashMap([]const u8);

/// Response codings this server can pick (no brotli/zstd: no deps, no std encoder).
pub const Encoding = enum { identity, gzip };

/// Bodies below this many bytes go out as-is: gzip framing outweighs the saving.
pub const default_min_bytes: usize = 512;

pub const Config = struct {
    /// Master switch. On by default, like nginx's `gzip on`.
    enabled: bool = true,
    /// Bodies shorter than this are sent as-is. See `default_min_bytes`.
    min_bytes: usize = default_min_bytes,
    /// Level 6 by default: what Cloudflare and nginx use on the fly (~80% smaller).
    level: flate.Compress.Options = .default,
};

/// One reusable gzip encoder: a ~225 KiB flate working set plus its 64 KiB window.
pub const Workspace = struct {
    compress: flate.Compress = undefined,
    window: [flate.max_window_len]u8 = undefined,

    pub fn create(allocator: std.mem.Allocator) !*Workspace {
        return allocator.create(Workspace);
    }

    pub fn destroy(self: *Workspace, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

/// A bounded set of workspaces (one per concurrent compression), owned by the server.
pub const Pool = struct {
    /// How many compressions may run at once; past this a response stays identity.
    pub const capacity: usize = 8;

    slots: [capacity]?*Workspace = [_]?*Workspace{null} ** capacity,
    busy: [capacity]std.atomic.Value(bool) = [_]std.atomic.Value(bool){
        std.atomic.Value(bool).init(false),
    } ** capacity,

    /// Borrow a workspace for the duration of one compression; null when all busy.
    pub fn acquire(self: *Pool, allocator: std.mem.Allocator) ?Lease {
        for (&self.slots, 0..) |*slot, index| {
            if (self.busy[index].cmpxchgStrong(false, true, .acquire, .monotonic) != null) continue;
            if (slot.* == null) {
                const workspace = allocator.create(Workspace) catch {
                    self.busy[index].store(false, .release);
                    return null;
                };
                slot.* = workspace;
            }
            return .{ .pool = self, .index = index, .workspace = slot.*.? };
        }
        return null;
    }

    pub fn deinit(self: *Pool, allocator: std.mem.Allocator) void {
        for (&self.slots) |*slot| {
            if (slot.*) |workspace| workspace.destroy(allocator);
            slot.* = null;
        }
    }

    pub const Lease = struct {
        pool: *Pool,
        index: usize,
        workspace: *Workspace,

        pub fn release(self: Lease) void {
            self.pool.busy[self.index].store(false, .release);
        }
    };
};

/// Pick a coding from an `Accept-Encoding` value: explicit gzip, else wildcard, else none.
pub fn negotiate(accept_encoding: ?[]const u8) Encoding {
    const header = accept_encoding orelse return .identity;
    var explicit_gzip: ?f32 = null;
    var wildcard: ?f32 = null;

    var it = std.mem.splitScalar(u8, header, ',');
    while (it.next()) |raw| {
        const item = std.mem.trim(u8, raw, " \t");
        if (item.len == 0) continue;
        var coding = item;
        var q: f32 = 1.0;
        if (std.mem.indexOfScalar(u8, item, ';')) |semi| {
            coding = std.mem.trim(u8, item[0..semi], " \t");
            q = parseQuality(item[semi + 1 ..]);
        }
        if (std.ascii.eqlIgnoreCase(coding, "gzip") or std.ascii.eqlIgnoreCase(coding, "x-gzip")) {
            explicit_gzip = q;
        } else if (std.mem.eql(u8, coding, "*")) {
            wildcard = q;
        }
    }

    if (explicit_gzip) |q| return if (q > 0) .gzip else .identity;
    if (wildcard) |q| return if (q > 0) .gzip else .identity;
    return .identity;
}

fn parseQuality(params: []const u8) f32 {
    var it = std.mem.splitScalar(u8, params, ';');
    while (it.next()) |raw| {
        const param = std.mem.trim(u8, raw, " \t");
        if (param.len < 2) continue;
        if (!std.ascii.eqlIgnoreCase(param[0..1], "q")) continue;
        const value = std.mem.trim(u8, param[1..], " \t");
        if (value.len == 0 or value[0] != '=') continue;
        const digits = std.mem.trim(u8, value[1..], " \t");
        const q = std.fmt.parseFloat(f32, digits) catch return 1.0;
        return std.math.clamp(q, 0, 1);
    }
    return 1.0;
}

/// The request's `Accept-Encoding` value, if it sent one.
pub fn acceptEncodingOf(req: *const HttpRequest) ?[]const u8 {
    return headerValue(&req.headers, "accept-encoding");
}

/// Whether a `Content-Type` describes bytes gzip shrinks; no type means no gzip.
pub fn isCompressibleType(content_type: []const u8) bool {
    const bare = std.mem.trim(u8, if (std.mem.indexOfScalar(u8, content_type, ';')) |semi|
        content_type[0..semi]
    else
        content_type, " \t");
    if (bare.len == 0) return false;
    if (std.ascii.startsWithIgnoreCase(bare, "text/")) return true;
    if (std.ascii.endsWithIgnoreCase(bare, "+json")) return true;
    if (std.ascii.endsWithIgnoreCase(bare, "+xml")) return true;
    const exact = [_][]const u8{
        "application/json",
        "application/javascript",
        "application/xml",
        "application/wasm",
        "application/x-www-form-urlencoded",
        "image/svg+xml",
    };
    for (exact) |candidate| {
        if (std.ascii.eqlIgnoreCase(bare, candidate)) return true;
    }
    return false;
}

/// gzip `body` into a slice owned by `allocator`, using `ws` as encoder state.
pub fn encodeGzip(
    allocator: std.mem.Allocator,
    body: []const u8,
    ws: *Workspace,
    level: flate.Compress.Options,
) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, initialCapacity(body.len));
    errdefer out.deinit();
    ws.compress = try flate.Compress.init(&out.writer, &ws.window, .gzip, level);
    try ws.compress.writer.writeAll(body);
    try ws.compress.finish();
    return out.toOwnedSlice();
}

fn initialCapacity(body_len: usize) usize {
    const half = body_len / 2 + 64;
    return std.math.clamp(half, 256, 64 * 1024);
}

/// Compress `resp` in place; the body uses `resp.allocator`, the pool `pool_allocator`.
pub fn maybeCompress(
    pool_allocator: std.mem.Allocator,
    resp: *HttpResponse,
    accept_encoding: ?[]const u8,
    cfg: Config,
    pool: *Pool,
) bool {
    if (!cfg.enabled) return false;
    if (negotiate(accept_encoding) != .gzip) return false;
    const lease = pool.acquire(pool_allocator) orelse return false;
    defer lease.release();
    return maybeCompressWith(resp.allocator, resp, accept_encoding, cfg, lease.workspace) catch false;
}

/// `maybeCompress` with an explicit workspace: the injectable seam, and no free.
pub fn maybeCompressWith(
    allocator: std.mem.Allocator,
    resp: *HttpResponse,
    accept_encoding: ?[]const u8,
    cfg: Config,
    ws: *Workspace,
) !bool {
    if (!cfg.enabled) return false;
    if (negotiate(accept_encoding) != .gzip) return false;
    if (resp.body.len == 0 or resp.body.len < cfg.min_bytes) return false;
    if (!statusAllowsBody(resp.status_code)) return false;
    if (headerValue(&resp.headers, "content-encoding") != null) return false;
    if (headerValue(&resp.headers, "content-range") != null) return false;
    if (headerValue(&resp.headers, "transfer-encoding") != null) return false;
    if (headerValue(&resp.headers, "cache-control")) |cache_control| {
        if (std.ascii.indexOfIgnoreCase(cache_control, "no-transform") != null) return false;
    }
    const content_type = headerValue(&resp.headers, "content-type") orelse return false;
    if (!isCompressibleType(content_type)) return false;

    const encoded = try encodeGzip(allocator, resp.body, ws, cfg.level);
    if (encoded.len >= resp.body.len) {
        allocator.free(encoded);
        return false;
    }

    resp.body = encoded;
    dropHeader(&resp.headers, "content-length");
    try resp.headers.put("Content-Encoding", "gzip");
    try appendVary(&resp.headers, allocator, "Accept-Encoding");
    return true;
}

fn statusAllowsBody(status: u16) bool {
    if (status == 204 or status == 304) return false;
    if (status == 206) return false;
    if (status >= 100 and status < 200) return false;
    return true;
}

fn headerValue(headers: *const Headers, name: []const u8) ?[]const u8 {
    var it = headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, name)) return entry.value_ptr.*;
    }
    return null;
}

fn dropHeader(headers: *Headers, name: []const u8) void {
    var found: ?[]const u8 = null;
    var it = headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, name)) {
            found = entry.key_ptr.*;
            break;
        }
    }
    if (found) |key| _ = headers.remove(key);
}

/// Add `Accept-Encoding` to `Vary` so a shared cache never crosses codings.
fn appendVary(headers: *Headers, allocator: std.mem.Allocator, token: []const u8) !void {
    const existing = headerValue(headers, "vary") orelse {
        try headers.put("Vary", token);
        return;
    };
    if (std.ascii.indexOfIgnoreCase(existing, token) != null) return;
    const merged = try std.fmt.allocPrint(allocator, "{s}, {s}", .{ existing, token });
    dropHeader(headers, "vary");
    try headers.put("Vary", merged);
}

// Tests: what a client sees (wire bytes, headers, decodability) and what it costs.

const testing = std.testing;

/// An API-shaped JSON body, comfortably over `default_min_bytes`.
const sample_json =
    \\{"users":[{"id":1,"name":"ada","email":"ada@example.com","role":"admin","active":true},
    \\{"id":2,"name":"grace","email":"grace@example.com","role":"admin","active":true},
    \\{"id":3,"name":"linus","email":"linus@example.com","role":"member","active":false},
    \\{"id":4,"name":"barbara","email":"barbara@example.com","role":"member","active":true},
    \\{"id":5,"name":"edsger","email":"edsger@example.com","role":"member","active":true},
    \\{"id":6,"name":"margaret","email":"margaret@example.com","role":"member","active":false},
    \\{"id":7,"name":"alan","email":"alan@example.com","role":"admin","active":true},
    \\{"id":8,"name":"donald","email":"donald@example.com","role":"member","active":true},
    \\{"id":9,"name":"frances","email":"frances@example.com","role":"member","active":false},
    \\{"id":10,"name":"ken","email":"ken@example.com","role":"admin","active":true},
    \\{"id":11,"name":"dennis","email":"dennis@example.com","role":"member","active":true},
    \\{"id":12,"name":"radia","email":"radia@example.com","role":"member","active":false}],
    \\"page":1,"per_page":12,"total":12}
;

/// One request's worth of state: an arena, an encoder workspace, response builders.
const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    ws: *Workspace,

    fn init() !Fixture {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        errdefer arena.deinit();
        const ws = try Workspace.create(arena.allocator());
        return .{ .arena = arena, .ws = ws };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
    }

    fn allocator(self: *Fixture) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// A response shaped like `res.withJson(body)`, built by hand so the test owns it.
    fn json(self: *Fixture, body: []const u8) HttpResponse {
        var resp = HttpResponse.init(200, "OK", self.allocator());
        resp.body = body;
        resp.headers.put("Content-Type", "application/json") catch @panic("OOM");
        return resp;
    }

    /// A response with `body` and `content_type`, built by hand.
    fn typed(self: *Fixture, status: u16, body: []const u8, content_type: []const u8) HttpResponse {
        var resp = HttpResponse.init(status, "OK", self.allocator());
        resp.body = body;
        resp.headers.put("Content-Type", content_type) catch @panic("OOM");
        return resp;
    }
};

/// Decode a body with a real inflater: the outcome of compressing is what a client reads.
fn gunzip(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    var source = std.Io.Reader.fixed(compressed);
    var window: [flate.max_window_len]u8 = undefined;
    var d = flate.Decompress.init(&source, .gzip, &window);
    return d.reader.allocRemaining(allocator, .unlimited);
}

test "negotiation picks gzip for the browser accept-encoding header" {
    try testing.expectEqual(Encoding.gzip, negotiate("gzip, deflate, br, zstd"));
    try testing.expectEqual(Encoding.gzip, negotiate("br;q=1.0, gzip;q=0.8, *;q=0.1"));
}

test "negotiation stays identity without an accept-encoding header" {
    try testing.expectEqual(Encoding.identity, negotiate(null));
    try testing.expectEqual(Encoding.identity, negotiate(""));
    try testing.expectEqual(Encoding.identity, negotiate("br, zstd"));
}

test "negotiation honours an explicit gzip refusal" {
    try testing.expectEqual(Encoding.identity, negotiate("gzip;q=0"));
    try testing.expectEqual(Encoding.identity, negotiate("identity;q=1, gzip;q=0.000"));
    try testing.expectEqual(Encoding.identity, negotiate("gzip;q=0, *;q=1"));
}

test "negotiation treats a wildcard as permission and tolerates odd spacing" {
    try testing.expectEqual(Encoding.gzip, negotiate("*"));
    try testing.expectEqual(Encoding.gzip, negotiate("  GZIP ;  q=0.5 "));
    try testing.expectEqual(Encoding.gzip, negotiate("x-gzip"));
}

test "a json response with an accepting client comes back gzipped and decodes" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = f.json(sample_json);
    try testing.expect(try maybeCompressWith(f.allocator(), &resp, "gzip, deflate", .{}, f.ws));

    try testing.expectEqualSlices(u8, &[_]u8{ 0x1f, 0x8b }, resp.body[0..2]);
    try testing.expect(resp.body.len * 2 <= sample_json.len);
    try testing.expectEqualStrings(sample_json, try gunzip(f.allocator(), resp.body));
}

test "a compressed response advertises gzip and is framed at the compressed length" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = f.json(sample_json);
    try resp.headers.put("Content-Length", "17");
    try testing.expect(try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));

    try testing.expectEqualStrings("gzip", headerValue(&resp.headers, "content-encoding").?);
    try testing.expect(headerValue(&resp.headers, "content-length") == null);

    const wire = try resp.toBytes();
    const framed = try std.fmt.allocPrint(f.allocator(), "Content-Length: {d}\r\n", .{resp.body.len});
    try testing.expect(std.mem.indexOf(u8, wire, framed) != null);
    try testing.expect(std.mem.indexOf(u8, wire, "Content-Encoding: gzip\r\n") != null);
    const body_start = std.mem.indexOf(u8, wire, "\r\n\r\n").? + 4;
    try testing.expectEqualSlices(u8, resp.body, wire[body_start..]);
}

test "a compressed response varies on accept-encoding" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = f.json(sample_json);
    try testing.expect(try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    const vary = headerValue(&resp.headers, "vary").?;
    try testing.expect(std.ascii.indexOfIgnoreCase(vary, "accept-encoding") != null);
}

test "an existing vary header keeps its value and gains accept-encoding" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = f.json(sample_json);
    try resp.headers.put("Vary", "Origin");
    try testing.expect(try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqualStrings("Origin, Accept-Encoding", headerValue(&resp.headers, "vary").?);
}

test "an html page is compressed" {
    var f = try Fixture.init();
    defer f.deinit();

    const html = "<html><body><h1>kabelweb</h1>" ++
        ("<p>the reactor serves this page</p>" ** 20) ++
        "</body></html>";
    var resp = f.typed(200, html, "text/html; charset=utf-8");

    try testing.expect(try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqualStrings(html, try gunzip(f.allocator(), resp.body));
}

test "a body larger than the flate window round-trips" {
    var f = try Fixture.init();
    defer f.deinit();

    const big = try f.allocator().alloc(u8, 200 * 1024);
    for (big, 0..) |*byte, index| byte.* = "abcdefgh"[(index / 7) % 8];

    var resp = f.typed(200, big, "text/plain; charset=utf-8");
    try testing.expect(try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqualSlices(u8, big, try gunzip(f.allocator(), resp.body));
}

test "every compression level decodes back to the original body" {
    var f = try Fixture.init();
    defer f.deinit();

    const levels = [_]flate.Compress.Options{ .fastest, .level_3, .default, .best };
    for (levels) |level| {
        var resp = f.json(sample_json);
        try testing.expect(try maybeCompressWith(f.allocator(), &resp, "gzip", .{ .level = level }, f.ws));
        try testing.expectEqualStrings(sample_json, try gunzip(f.allocator(), resp.body));
    }
}

test "a client that cannot decode gzip gets the identity body" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = f.json(sample_json);
    try testing.expect(!try maybeCompressWith(f.allocator(), &resp, "br", .{}, f.ws));
    try testing.expectEqualStrings(sample_json, resp.body);
    try testing.expect(headerValue(&resp.headers, "content-encoding") == null);
}

test "a body below the minimum size is left untouched" {
    var f = try Fixture.init();
    defer f.deinit();

    const small = "<p>hello world</p>" ** 24;
    var resp = f.typed(200, small, "text/html");
    try testing.expect(!try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqualStrings(small, resp.body);

    var lowered = f.typed(200, small, "text/html");
    try testing.expect(try maybeCompressWith(f.allocator(), &lowered, "gzip", .{ .min_bytes = 64 }, f.ws));
    try testing.expectEqualStrings(small, try gunzip(f.allocator(), lowered.body));
}

test "a response without a content-type is left untouched" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = HttpResponse.init(200, "OK", f.allocator());
    resp.body = sample_json;
    try testing.expect(!try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqualStrings(sample_json, resp.body);
}

test "an already encoded response is left alone" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = f.json(sample_json);
    try resp.headers.put("Content-Encoding", "br");
    try testing.expect(!try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqualStrings(sample_json, resp.body);
    try testing.expectEqualStrings("br", headerValue(&resp.headers, "content-encoding").?);
}

test "a png body is left untouched" {
    var f = try Fixture.init();
    defer f.deinit();

    const pixels = try f.allocator().alloc(u8, 4096);
    @memset(pixels, 0x89);
    var resp = f.typed(200, pixels, "image/png");

    try testing.expect(!try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqual(@as(usize, 4096), resp.body.len);
    try testing.expect(headerValue(&resp.headers, "content-encoding") == null);
}

test "a no-transform response is left untouched" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = f.json(sample_json);
    try resp.headers.put("Cache-Control", "public, no-transform");
    try testing.expect(!try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqualStrings(sample_json, resp.body);
}

test "a partial content response is left untouched" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = f.typed(206, sample_json, "application/json");
    try testing.expect(!try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqualStrings(sample_json, resp.body);
}

test "incompressible bytes keep the identity body" {
    var f = try Fixture.init();
    defer f.deinit();

    var prng = std.Random.DefaultPrng.init(0x6b6162656c776562);
    const noise = try f.allocator().alloc(u8, 4096);
    prng.random().bytes(noise);

    var resp = f.typed(200, noise, "text/plain; charset=utf-8");
    try testing.expect(!try maybeCompressWith(f.allocator(), &resp, "gzip", .{}, f.ws));
    try testing.expectEqualSlices(u8, noise, resp.body);
}

test "a disabled config never touches the body" {
    var f = try Fixture.init();
    defer f.deinit();

    var resp = f.json(sample_json);
    try testing.expect(!try maybeCompressWith(f.allocator(), &resp, "gzip", .{ .enabled = false }, f.ws));
    try testing.expectEqualStrings(sample_json, resp.body);
}

// --- what a call costs: one workspace, reused; nothing accumulates ----------

/// Allocator wrapper that counts live bytes and allocations (test-only).
const CountingAllocator = struct {
    child: std.mem.Allocator,
    live_bytes: usize = 0,
    live_allocs: usize = 0,

    fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const memory = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.live_bytes += len;
        self.live_allocs += 1;
        return memory;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.live_bytes = self.live_bytes - memory.len + new_len;
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const remapped = self.child.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.live_bytes = self.live_bytes - memory.len + new_len;
        return remapped;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.live_bytes -= memory.len;
        self.live_allocs -= 1;
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

test "compressing many responses reuses one workspace and leaks nothing" {
    var counting: CountingAllocator = .{ .child = testing.allocator };
    const alloc = counting.allocator();

    var pool: Pool = .{};
    defer pool.deinit(alloc);

    // Warm up: the first response is the one that builds the workspace.
    var warm = HttpResponse.init(200, "OK", alloc);
    warm.body = sample_json;
    try warm.headers.put("Content-Type", "application/json");
    try testing.expect(maybeCompress(alloc, &warm, "gzip", .{}, &pool));
    alloc.free(warm.body);
    warm.headers.deinit();

    const baseline_bytes = counting.live_bytes;
    const baseline_allocs = counting.live_allocs;

    var first_len: usize = 0;
    for (0..16) |iteration| {
        var resp = HttpResponse.init(200, "OK", alloc);
        resp.body = sample_json;
        try resp.headers.put("Content-Type", "application/json");

        try testing.expect(maybeCompress(alloc, &resp, "gzip", .{}, &pool));
        if (iteration == 0) {
            first_len = resp.body.len;
        } else {
            try testing.expectEqual(first_len, resp.body.len);
        }
        alloc.free(resp.body);
        resp.headers.deinit();
    }

    try testing.expectEqual(baseline_bytes, counting.live_bytes);
    try testing.expectEqual(baseline_allocs, counting.live_allocs);
}

test "a full pool stops handing out workspaces instead of growing without bound" {
    var counting: CountingAllocator = .{ .child = testing.allocator };
    const alloc = counting.allocator();

    var pool: Pool = .{};
    defer pool.deinit(alloc);

    var leases: [Pool.capacity]Pool.Lease = undefined;
    for (&leases) |*lease| lease.* = pool.acquire(alloc).?;
    try testing.expect(pool.acquire(alloc) == null);

    // Releasing one makes room again, and the borrowed workspace is the same one.
    leases[0].release();
    const again = pool.acquire(alloc).?;
    try testing.expect(again.workspace == leases[0].workspace);
    again.release();
    for (leases[1..]) |lease| lease.release();

    pool.deinit(alloc);
    try testing.expectEqual(@as(usize, 0), counting.live_allocs);
}
