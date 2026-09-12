const std = @import("std");
const testing = std.testing;

const constants = @import("constants.zig");
const connection = @import("connection.zig");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const settings = @import("settings.zig");

const Connection = connection.Connection;

/// Everything the tests need to drive a connection without a socket.
const Harness = struct {
    alloc: std.mem.Allocator,
    conn: Connection,
    inbound: std.ArrayList(u8) = .empty,
    outbound: std.ArrayList(u8) = .empty,

    fn init(alloc: std.mem.Allocator, opts: connection.Options) !*Harness {
        const h = try alloc.create(Harness);
        h.* = .{ .alloc = alloc, .conn = Connection.init(alloc, opts) };
        return h;
    }

    fn deinit(self: *Harness) void {
        self.conn.deinit();
        self.inbound.deinit(self.alloc);
        self.outbound.deinit(self.alloc);
        self.alloc.destroy(self);
    }

    /// Send the client preface + an (optionally non-empty) SETTINGS frame and
    /// collect the server's reply.
    fn handshake(self: *Harness, client_settings: ?settings.Settings) !void {        try self.inbound.appendSlice(self.alloc, constants.PREFACE);
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.alloc);
        if (client_settings) |s| try settings.encode(self.alloc, &payload, s);
        try frame.writeFrame(self.alloc, &self.inbound, .{
            .length = @intCast(payload.items.len),
            .type = .settings,
            .flags = 0,
            .stream_id = 0,
        }, payload.items);
        try self.pump();
    }

    fn pump(self: *Harness) !void {
        try self.conn.feed(self.inbound.items);
        self.inbound.clearRetainingCapacity();
        try self.conn.drain(&self.outbound);
        try self.conn.flush();
        try self.conn.drain(&self.outbound);
    }

    /// Feed arbitrary bytes.
    fn feed(self: *Harness, bytes: []const u8) !void {
        try self.conn.feed(bytes);
        try self.conn.flush();
        try self.conn.drain(&self.outbound);
    }

    fn takeOut(self: *Harness) []u8 {
        const slice = self.outbound.toOwnedSlice(self.alloc) catch unreachable;
        self.outbound = .empty;
        return slice;
    }

    fn out(self: *Harness) []const u8 {
        return self.outbound.items;
    }
};

fn findFrame(bytes: []const u8, want: constants.FrameType) ?frame.Frame {
    var pos: usize = 0;
    while (pos < bytes.len) {
        const d = frame.decode(bytes[pos..], constants.max_allowed_frame_size) catch return null;
        if (d.frame.header.type == want) return d.frame;
        pos += d.consumed;
    }
    return null;
}

fn countFrames(bytes: []const u8, want: constants.FrameType) usize {
    var pos: usize = 0;
    var n: usize = 0;
    while (pos < bytes.len) {
        const d = frame.decode(bytes[pos..], constants.max_allowed_frame_size) catch return n;
        if (d.frame.header.type == want) n += 1;
        pos += d.consumed;
    }
    return n;
}

/// Build a client request HEADERS frame (encoding the pseudo-headers for us).
fn writeRequest(
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
    stream_id: u32,
    method: []const u8,
    path: []const u8,
    end_stream: bool,
    extra: []const hpack.Pair,
) !void {
    var pairs = std.ArrayList(hpack.Pair).empty;
    defer pairs.deinit(alloc);
    try pairs.append(alloc, .{ .name = ":method", .value = method });
    try pairs.append(alloc, .{ .name = ":scheme", .value = "http" });
    try pairs.append(alloc, .{ .name = ":path", .value = path });
    try pairs.append(alloc, .{ .name = ":authority", .value = "127.0.0.1" });
    for (extra) |e| try pairs.append(alloc, e);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(alloc);
    var enc = hpack.Encoder.init(alloc);
    try enc.encode(pairs.items, &block);

    var flags: u8 = constants.flag_end_headers;
    if (end_stream) flags |= constants.flag_end_stream;
    try frame.writeFrame(alloc, out, .{
        .length = @intCast(block.items.len),
        .type = .headers,
        .flags = flags,
        .stream_id = stream_id,
    }, block.items);
}

fn writeClientData(alloc: std.mem.Allocator, out: *std.ArrayList(u8), stream_id: u32, body: []const u8, end_stream: bool) !void {
    try frame.writeFrame(alloc, out, .{
        .length = @intCast(body.len),
        .type = .data,
        .flags = if (end_stream) constants.flag_end_stream else 0,
        .stream_id = stream_id,
    }, body);
}

test "handshake: server answers the preface with SETTINGS and ACKs the client's" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();

    try h.handshake(.{});
    const server_settings = findFrame(h.out(), .settings) orelse return error.NoSettingsFrame;
    try testing.expectEqual(@as(u32, 0), server_settings.header.stream_id);
    try testing.expectEqual(@as(u8, 0), server_settings.header.flags & constants.flag_ack);
    const decoded = try settings.decode(server_settings.payload);
    try testing.expectEqual(constants.our_max_concurrent_streams, decoded.maxConcurrentStreams());
    try testing.expectEqual(constants.our_initial_window_size, decoded.initialWindowSize());
    try testing.expectEqual(false, decoded.enablePush());

    // The server ACKs the client's SETTINGS: exactly two SETTINGS frames, one
    // of them an ACK with an empty payload.
    try testing.expectEqual(@as(usize, 2), countFrames(h.out(), .settings));
    var pos: usize = 0;
    var acks: usize = 0;
    while (pos < h.out().len) {
        const d = try frame.decode(h.out()[pos..], constants.max_allowed_frame_size);
        pos += d.consumed;
        if (d.frame.header.type == .settings and d.frame.header.flags & constants.flag_ack != 0) {
            acks += 1;
            try testing.expectEqual(@as(u32, 0), d.frame.header.length);
        }
    }
    try testing.expectEqual(@as(usize, 1), acks);
}

test "handshake: a bad preface is a connection error (GOAWAY PROTOCOL_ERROR)" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();

    try h.feed("GET / HTTP/1.1\r\n\r\n");
    try testing.expect(h.conn.isClosed());
    const g = findFrame(h.out(), .goaway) orelse return error.NoGoaway;
    const code = std.mem.readInt(u32, g.payload[4..8], .big);
    try testing.expectEqual(@as(u32, @intFromEnum(constants.ErrorCode.protocol_error)), code);
}

test "request: GET is published to the server and answered with HEADERS + DATA" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var req_bytes: std.ArrayList(u8) = .empty;
    defer req_bytes.deinit(testing.allocator);
    try writeRequest(testing.allocator, &req_bytes, 1, "GET", "/health", true, &.{});
    try h.feed(req_bytes.items);

    const req = h.conn.nextRequest() orelse return error.NoRequest;
    try testing.expectEqual(@as(u32, 1), req.stream_id);
    try testing.expectEqualStrings("GET", req.method);
    try testing.expectEqualStrings("/health", req.path);
    try testing.expectEqualStrings("http", req.scheme);
    try testing.expectEqualStrings("127.0.0.1", req.authority);
    try testing.expectEqual(@as(usize, 0), req.body.len);
    try testing.expect(h.conn.nextRequest() == null);

    try h.conn.respond(1, .{ .status = 200, .headers = &.{.{ .name = "content-type", .value = "text/plain" }}, .body = "OK" });
    try h.conn.flush();
    try h.conn.drain(&h.outbound);

    const headers_frame = findFrame(h.out(), .headers) orelse return error.NoHeaders;
    try testing.expectEqual(@as(u32, 1), headers_frame.header.stream_id);
    try testing.expectEqual(@as(u8, 0), headers_frame.header.flags & constants.flag_end_stream); // body follows
    var dec = hpack.Decoder.init(testing.allocator, 4096, 65536);
    defer dec.deinit();
    var pairs = std.ArrayList(hpack.Pair).empty;
    defer {
        for (pairs.items) |p| {
            testing.allocator.free(p.name);
            testing.allocator.free(p.value);
        }
        pairs.deinit(testing.allocator);
    }
    try dec.decode(headers_frame.payload, &pairs);
    try testing.expectEqualStrings(":status", pairs.items[0].name);
    try testing.expectEqualStrings("200", pairs.items[0].value);
    try testing.expectEqualStrings("content-type", pairs.items[1].name);
    try testing.expectEqualStrings("text/plain", pairs.items[1].value);

    const data = findFrame(h.out(), .data) orelse return error.NoData;
    try testing.expectEqualStrings("OK", data.payload);
    try testing.expect(data.header.flags & constants.flag_end_stream != 0);
}

test "request: a streamed body is assembled from DATA frames" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try writeRequest(testing.allocator, &buf, 1, "POST", "/api/echo", false, &.{.{ .name = "content-type", .value = "application/json" }});
    try writeClientData(testing.allocator, &buf, 1, "{\"a\":", false);
    try writeClientData(testing.allocator, &buf, 1, "1}", true);
    try h.feed(buf.items);

    const req = h.conn.nextRequest() orelse return error.NoRequest;
    try testing.expectEqualStrings("POST", req.method);
    try testing.expectEqualStrings("{\"a\":1}", req.body);
    try testing.expectEqual(@as(usize, 1), req.headers.len);
    try testing.expectEqualStrings("content-type", req.headers[0].name);
}

test "multiplexing: two streams are served independently and out of order" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try writeRequest(testing.allocator, &buf, 3, "GET", "/slow", true, &.{});
    try writeRequest(testing.allocator, &buf, 5, "GET", "/fast", true, &.{});
    try h.feed(buf.items);

    const first = h.conn.nextRequest() orelse return error.NoRequest;
    const second = h.conn.nextRequest() orelse return error.NoRequest;
    try testing.expectEqual(@as(u32, 3), first.stream_id);
    try testing.expectEqual(@as(u32, 5), second.stream_id);

    // Answer the second stream first — the wire order follows the responses,
    // not the requests.
    try h.conn.respond(5, .{ .status = 204 });
    try h.conn.respond(3, .{ .status = 200, .body = "slow" });
    try h.conn.flush();
    try h.conn.drain(&h.outbound);
    try testing.expectEqual(@as(usize, 2), countFrames(h.out(), .headers));
    const first_headers = findFrame(h.out(), .headers).?;
    try testing.expectEqual(@as(u32, 5), first_headers.header.stream_id);
}

test "client reset: a RST_STREAM drops the queued request" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try writeRequest(testing.allocator, &buf, 1, "GET", "/gone", true, &.{});
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = 4,
        .type = .rst_stream,
        .flags = 0,
        .stream_id = 1,
    }, &frame.rstStreamPayload(.cancel));
    try h.feed(buf.items);

    try testing.expect(h.conn.nextRequest() == null);
}

test "ping is echoed with the ACK flag and the same payload" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    const payload = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = 8,
        .type = .ping,
        .flags = 0,
        .stream_id = 0,
    }, &payload);
    try h.feed(buf.items);

    const ping = findFrame(h.out(), .ping) orelse return error.NoPing;
    try testing.expect(ping.header.flags & constants.flag_ack != 0);
    try testing.expectEqualSlices(u8, &payload, ping.payload[0..8]);
}

test "malformed request: missing :method is a stream error, not a connection error" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var pairs = [_]hpack.Pair{.{ .name = ":path", .value = "/x" }};
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    var enc = hpack.Encoder.init(testing.allocator);
    try enc.encode(&pairs, &block);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = @intCast(block.items.len),
        .type = .headers,
        .flags = constants.flag_end_headers | constants.flag_end_stream,
        .stream_id = 1,
    }, block.items);
    try h.feed(buf.items);

    try testing.expect(!h.conn.isClosed());
    const rst = findFrame(h.out(), .rst_stream) orelse return error.NoRst;
    try testing.expectEqual(@as(u32, 1), rst.header.stream_id);
    try testing.expect(h.conn.nextRequest() == null);
}

test "malformed request: a connection-specific header is rejected" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try writeRequest(testing.allocator, &buf, 1, "GET", "/x", true, &.{.{ .name = "connection", .value = "keep-alive" }});
    try h.feed(buf.items);

    try testing.expect(!h.conn.isClosed());
    const rst = findFrame(h.out(), .rst_stream) orelse return error.NoRst;
    try testing.expectEqual(@as(u32, 1), rst.header.stream_id);
}

test "protocol error: PUSH_PROMISE from a client kills the connection" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = 4,
        .type = .push_promise,
        .flags = constants.flag_end_headers,
        .stream_id = 1,
    }, &[_]u8{ 0, 0, 0, 0 });
    try h.feed(buf.items);

    try testing.expect(h.conn.isClosed());
    _ = findFrame(h.out(), .goaway) orelse return error.NoGoaway;
}

test "continuation: a header block split across frames is reassembled" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var pairs = std.ArrayList(hpack.Pair).empty;
    defer pairs.deinit(testing.allocator);
    try pairs.append(testing.allocator, .{ .name = ":method", .value = "GET" });
    try pairs.append(testing.allocator, .{ .name = ":scheme", .value = "http" });
    try pairs.append(testing.allocator, .{ .name = ":path", .value = "/split" });
    try pairs.append(testing.allocator, .{ .name = ":authority", .value = "example.com" });
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(testing.allocator);
    var enc = hpack.Encoder.init(testing.allocator);
    try enc.encode(pairs.items, &block);
    try testing.expect(block.items.len >= 4);

    const half = block.items.len / 2;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = @intCast(half),
        .type = .headers,
        .flags = constants.flag_end_stream, // END_HEADERS deliberately absent
        .stream_id = 1,
    }, block.items[0..half]);
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = @intCast(block.items.len - half),
        .type = .continuation,
        .flags = constants.flag_end_headers,
        .stream_id = 1,
    }, block.items[half..]);
    try h.feed(buf.items);

    const req = h.conn.nextRequest() orelse return error.NoRequest;
    try testing.expectEqualStrings("/split", req.path);
}

test "continuation: another frame interleaved mid-block is a connection error" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = 1,
        .type = .headers,
        .flags = 0, // no END_HEADERS
        .stream_id = 1,
    }, &[_]u8{0x82});
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = 8,
        .type = .ping,
        .flags = 0,
        .stream_id = 0,
    }, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 });
    try h.feed(buf.items);

    try testing.expect(h.conn.isClosed());
    _ = findFrame(h.out(), .goaway) orelse return error.NoGoaway;
}

test "flow control: a response larger than the window is paced by WINDOW_UPDATE" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    // The client advertises a 5-byte stream window.
    try h.handshake(.{ .initial_window_size = 5 });

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try writeRequest(testing.allocator, &buf, 1, "GET", "/big", true, &.{});
    try h.feed(buf.items);
    _ = h.conn.nextRequest() orelse return error.NoRequest;

    try h.conn.respond(1, .{ .status = 200, .body = "0123456789ABCDEFGHIJ" }); // 20 bytes
    try h.conn.flush();
    try h.conn.drain(&h.outbound);

    const first_data = findFrame(h.out(), .data) orelse return error.NoData;
    try testing.expectEqual(@as(usize, 5), first_data.payload.len);
    try testing.expect(h.conn.hasPendingOutput());

    // Let the rest through.
    var upd: std.ArrayList(u8) = .empty;
    defer upd.deinit(testing.allocator);
    try frame.writeFrame(testing.allocator, &upd, .{
        .length = 4,
        .type = .window_update,
        .flags = 0,
        .stream_id = 1,
    }, &frame.windowUpdatePayload(1000));
    try h.feed(upd.items);

    try testing.expect(!h.conn.hasPendingOutput());
    // Second DATA frame carries the remainder and END_STREAM.
    var pos: usize = 0;
    var saw_end = false;
    var total: usize = 0;
    while (pos < h.out().len) {
        const d = try frame.decode(h.out()[pos..], constants.max_allowed_frame_size);
        pos += d.consumed;
        if (d.frame.header.type == .data) {
            total += d.frame.payload.len;
            if (d.frame.header.flags & constants.flag_end_stream != 0) saw_end = true;
        }
    }
    try testing.expectEqual(@as(usize, 20), total);
    try testing.expect(saw_end);
}

test "flow control: receiving a body produces WINDOW_UPDATE frames" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try writeRequest(testing.allocator, &buf, 1, "POST", "/upload", false, &.{});
    // The connection-level receive window starts at the protocol default
    // (65535) and is NOT settable via SETTINGS, so a well-behaved client stops
    // well short of 64 KiB until our WINDOW_UPDATE arrives. 40768 bytes crosses
    // the half-window coalescing threshold, which is what triggers the update.
    const chunk = try testing.allocator.alloc(u8, 16 * 1024);
    defer testing.allocator.free(chunk);
    @memset(chunk, 'x');
    try writeClientData(testing.allocator, &buf, 1, chunk, false);
    try writeClientData(testing.allocator, &buf, 1, chunk, false);
    try writeClientData(testing.allocator, &buf, 1, chunk[0..8000], false);
    try h.feed(buf.items);

    try testing.expect(!h.conn.isClosed());
    try testing.expect(countFrames(h.out(), .window_update) >= 1);
    // Only the CONNECTION window update fires here: it starts at the protocol
    // default 65535 (SETTINGS cannot change it), so half-window is ~32 KiB. The
    // stream window is our advertised 1 MiB, so its coalescing threshold needs a
    // much larger body than the connection window permits.
    var pos: usize = 0;
    var saw_conn = false;
    while (pos < h.out().len) {
        const d = try frame.decode(h.out()[pos..], constants.max_allowed_frame_size);
        pos += d.consumed;
        if (d.frame.header.type == .window_update and d.frame.header.stream_id == 0) saw_conn = true;
    }
    try testing.expect(saw_conn);

    // END_STREAM now publishes the request with the accumulated body.
    var fin: std.ArrayList(u8) = .empty;
    defer fin.deinit(testing.allocator);
    try writeClientData(testing.allocator, &fin, 1, "end", true);
    try h.feed(fin.items);
    const req = h.conn.nextRequest() orelse return error.NoRequest;
    try testing.expectEqual(@as(usize, 40_768 + 3), req.body.len);
    try testing.expectEqualStrings("end", req.body[40_768..]);
}

test "settings: ACK with a body, and a bad max_frame_size, are frame errors" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    // SETTINGS ACK must have a zero-length payload.
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = 6,
        .type = .settings,
        .flags = constants.flag_ack,
        .stream_id = 0,
    }, &[_]u8{ 0, 5, 0, 0, 0, 1 });
    try h.feed(buf.items);
    try testing.expect(h.conn.isClosed());
    const g = findFrame(h.out(), .goaway) orelse return error.NoGoaway;
    try testing.expectEqual(
        @as(u32, @intFromEnum(constants.ErrorCode.frame_size_error)),
        std.mem.readInt(u32, g.payload[4..8], .big),
    );
}

test "unknown frame types are ignored (RFC 9113 §4.1)" {
    const h = try Harness.init(testing.allocator, .{});
    defer h.deinit();
    try h.handshake(.{});

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try frame.writeFrame(testing.allocator, &buf, .{
        .length = 3,
        .type = @enumFromInt(0x2a),
        .flags = 0,
        .stream_id = 0,
    }, "xyz");
    try h.feed(buf.items);
    try testing.expect(!h.conn.isClosed());

    // ...and a subsequent valid request still works.
    try writeRequest(testing.allocator, &buf, 1, "GET", "/after", true, &.{});
    try h.feed(buf.items);
    const req = h.conn.nextRequest() orelse return error.NoRequest;
    try testing.expectEqualStrings("/after", req.path);
}
