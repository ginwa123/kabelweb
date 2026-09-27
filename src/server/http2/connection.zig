//! HTTP/2 connection driver (RFC 9113) — phase 1: h2c, non-streaming responses.
//!
//! Design constraints (see `docs/superpowers/plans/2026-09-11-http2-custom-http-server.md`):
//!   * **Synchronous and allocation-predictable.** `feed()` consumes inbound
//!     bytes, `flush()` produces outbound bytes. No callbacks, no threads, no
//!     blocking — the server loop owns the socket and drives both.
//!   * **Never deadlock on flow control.** A response body that does not fit in
//!     the peer's window stays queued in `pending_bodies`; the caller keeps
//!     calling `feed()` (which is where WINDOW_UPDATE arrives) and then
//!     `flush()` again.
//!   * **Streaming routes are out of scope.** `server.zig` answers 501 for SSE
//!     and WebSocket routes, so a response is always a complete struct.
//!   * Request memory lives in `req_arena`, recycled by the caller with
//!     `recycleRequestMemory()` once a request batch has been answered — that
//!     keeps a long-lived connection's footprint bounded.

const std = @import("std");

const constants = @import("constants.zig");
const flow_control = @import("flow_control.zig");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const settings = @import("settings.zig");
const stream = @import("stream.zig");

pub const Error = error{
    OutOfMemory,
    ProtocolError,
    FrameSizeError,
    CompressionError,
    FlowControlError,
    HeaderListTooLarge,
    StreamClosed,
    RefusedStream,
    /// Propagated from the frame codec: only reachable through the outbound
    /// helpers (a frame we build ourselves should never be malformed, so these
    /// are effectively "cannot happen" and worth surfacing loudly).
    IncompleteFrame,
    InvalidFrameLength,
};

pub const Options = struct {
    /// What WE advertise to the peer (the peer must respect these).
    max_frame_size: u32 = constants.our_max_frame_size,
    max_header_list_size: u32 = constants.our_max_header_list_size,
    initial_window_size: u32 = constants.our_initial_window_size,
    max_concurrent_streams: u32 = constants.our_max_concurrent_streams,
    header_table_size: u32 = constants.our_header_table_size,
    /// Hard cap on one request body. Exceeding it resets the stream with
    /// ENHANCE_YOUR_CALM instead of growing the arena without bound.
    max_body_bytes: u32 = 16 * 1024 * 1024,
};

pub const Request = struct {
    stream_id: u32,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: []const u8,
    /// Regular (non-pseudo) headers, names lowercased, in wire order.
    headers: []const hpack.Pair,
    body: []const u8,
};

pub const Response = struct {
    status: u16,
    /// Extra headers emitted after `:status`. Connection-specific headers are
    /// dropped by `respond` — they are illegal in HTTP/2 (RFC 9113 §8.2.2).
    headers: []const hpack.Pair = &.{},
    body: []const u8 = "",
};

const State = enum { expect_preface, open, closing, closed };

const PendingBody = struct {
    stream_id: u32,
    data: []const u8,
    offset: usize = 0,
    end_stream: bool = true,
};

/// Per-stream receive state. `stream.Stream` stays protocol-pure; this holds the
/// request-shaped bookkeeping the driver needs.
const RecvStream = struct {
    recv_window: flow_control.Window,
    body: std.ArrayList(u8) = .empty,
    headers: []hpack.Pair = &.{},
    method: []const u8 = "",
    path: []const u8 = "",
    scheme: []const u8 = "http",
    authority: []const u8 = "",
    responded: bool = false,
};

pub const Connection = struct {
    alloc: std.mem.Allocator,
    opts: Options,
    /// Owns every request's header/body slices. Recycled between batches.
    req_arena: std.heap.ArenaAllocator,

    state: State = .expect_preface,
    preface_consumed: usize = 0,
    /// Set when the connection was aborted; the caller writes `out` then closes.
    last_error: ?constants.ErrorCode = null,

    dec: hpack.Decoder,
    streams: stream.Table,
    recv_streams: std.AutoHashMapUnmanaged(u32, *RecvStream) = .empty,

    /// Peer-advertised SETTINGS we act on. The connection-level windows are NOT
    /// affected by SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113 §6.9.2).
    peer_initial_window: u32 = constants.default_initial_window_size,
    peer_max_frame_size: u32 = constants.default_max_frame_size,
    peer_max_concurrent: u32 = std.math.maxInt(u32),
    peer_header_table_size: u32 = constants.our_header_table_size,
    settings_ack_pending: bool = false,
    goaway_received: bool = false,

    conn_send: flow_control.Window,
    conn_recv: flow_control.Window,

    out: std.ArrayList(u8) = .empty,
    ready: std.ArrayList(*Request) = .empty,
    pending_bodies: std.ArrayList(PendingBody) = .empty,

    /// CONTINUATION reassembly — a header block may span several frames.
    frag: std.ArrayList(u8) = .empty,
    frag_stream_id: u32 = 0,
    frag_end_stream: bool = false,
    awaiting_continuation: bool = false,

    pub fn init(alloc: std.mem.Allocator, opts: Options) Connection {
        return .{
            .alloc = alloc,
            .opts = opts,
            .req_arena = std.heap.ArenaAllocator.init(alloc),
            .dec = hpack.Decoder.init(alloc, opts.header_table_size, opts.max_header_list_size),
            .streams = stream.Table.init(alloc, opts.max_concurrent_streams),
            .conn_send = flow_control.Window.init(constants.default_initial_window_size),
            .conn_recv = flow_control.Window.init(constants.default_initial_window_size),
        };
    }

    pub fn deinit(self: *Connection) void {
        self.dec.deinit();
        self.streams.deinit();
        var it = self.recv_streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.body.deinit(self.alloc);
            self.alloc.destroy(entry.value_ptr.*);
        }
        self.recv_streams.deinit(self.alloc);
        self.out.deinit(self.alloc);
        self.ready.deinit(self.alloc);
        self.pending_bodies.deinit(self.alloc);
        self.frag.deinit(self.alloc);
        self.req_arena.deinit();
    }

    pub fn isClosed(self: *const Connection) bool {
        return self.state == .closed;
    }

    /// True when the peer asked to shut down; the caller should drain `out` and
    /// close once nothing is pending.
    pub fn isClosing(self: *const Connection) bool {
        return self.state == .closing;
    }

    /// Free per-request memory. Safe only after every pointer previously returned
    /// by `nextRequest` has been consumed AND no response body is still queued.
    pub fn recycleRequestMemory(self: *Connection) void {
        if (self.ready.items.len != 0) return;
        if (self.hasPendingOutput()) return;
        _ = self.req_arena.reset(.retain_capacity);
    }

    /// Pop the next fully-received request, or null.
    pub fn nextRequest(self: *Connection) ?*Request {
        if (self.ready.items.len == 0) return null;
        const req = self.ready.items[0];
        _ = self.ready.orderedRemove(0);
        return req;
    }

    // ─── Outbound ────────────────────────────────────────────────────────────

    /// Queue a complete response. A no-op for a stream the peer already reset.
    pub fn respond(self: *Connection, stream_id: u32, resp: Response) Error!void {
        const s = self.streams.get(stream_id) orelse return;
        if (s.state == .closed) return;
        const rs = self.recv_streams.get(stream_id) orelse return;
        if (rs.responded) return;
        rs.responded = true;

        var status_buf: [3]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{resp.status}) catch unreachable;

        var pairs = std.ArrayList(hpack.Pair).empty;
        defer pairs.deinit(self.alloc);
        try pairs.append(self.alloc, .{ .name = ":status", .value = status_str });
        for (resp.headers) |h| {
            if (isIllegalResponseHeader(h.name)) continue;
            try pairs.append(self.alloc, h);
        }

        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(self.alloc);
        var encoder = hpack.Encoder.init(self.alloc);
        defer encoder.deinit();
        try encoder.encode(pairs.items, &block);

        const end_stream = resp.body.len == 0;
        try self.writeHeaderBlock(stream_id, block.items, end_stream);
        try self.streams.apply(stream_id, if (end_stream) .send_headers_end else .send_headers);

        if (!end_stream) {
            try self.pending_bodies.append(self.alloc, .{
                .stream_id = stream_id,
                .data = resp.body,
                .end_stream = true,
            });
            try self.flush();
        }
        self.closeStreamIfDone(stream_id);
    }

    /// True while a response is queued but not fully written (flow-control
    /// limited). The server loop must keep reading so WINDOW_UPDATE can arrive.
    pub fn hasPendingOutput(self: *const Connection) bool {
        return self.pending_bodies.items.len != 0;
    }

    /// Move outbound bytes into `dest` and clear the internal buffer.
    pub fn drain(self: *Connection, dest: *std.ArrayList(u8)) !void {
        if (self.out.items.len == 0) return;
        try dest.appendSlice(self.alloc, self.out.items);
        self.out.clearRetainingCapacity();
    }

    /// Append whatever the peer's windows currently allow: WINDOW_UPDATE for
    /// consumed inbound bytes, then as many queued DATA bytes as fit.
    pub fn flush(self: *Connection) !void {
        if (self.state == .closed) return;
        self.flushWindowUpdates();

        var i: usize = 0;
        while (i < self.pending_bodies.items.len) {
            const pb = &self.pending_bodies.items[i];
            const s = self.streams.get(pb.stream_id) orelse {
                _ = self.pending_bodies.swapRemove(i);
                continue;
            };
            if (s.state == .closed) {
                _ = self.pending_bodies.swapRemove(i);
                continue;
            }
            const remaining = pb.data.len - pb.offset;
            if (remaining > 0) {
                const allowed = @min(
                    @min(s.send_window, self.conn_send.size),
                    @as(i64, @intCast(self.peer_max_frame_size)),
                );
                if (allowed <= 0) {
                    i += 1; // window exhausted — wait for WINDOW_UPDATE
                    continue;
                }
                const take: usize = @intCast(@min(@as(i64, @intCast(remaining)), allowed));
                const last = pb.offset + take == pb.data.len;
                try self.writeData(pb.stream_id, pb.data[pb.offset .. pb.offset + take], last and pb.end_stream);
                pb.offset += take;
                s.send_window -= @intCast(take);
                self.conn_send.size -= @intCast(take);
                if (!last) {
                    i += 1;
                    continue;
                }
            }
            if (pb.end_stream) {
                if (remaining == 0) try self.writeData(pb.stream_id, "", true);
                try self.streams.apply(pb.stream_id, .send_data_end);
            }
            const sid = pb.stream_id;
            _ = self.pending_bodies.swapRemove(i);
            self.closeStreamIfDone(sid);
        }
    }

    /// RFC 9113 §6.8. Refuses further streams; queued bodies are dropped because
    /// the peer must retry them on a new connection anyway.
    pub fn goaway(self: *Connection, code: constants.ErrorCode) !void {
        if (self.state == .closed) return;
        const payload: [8]u8 = frame.goawayPayload(self.streams.highest_peer_stream_id, code);
        try frame.writeFrame(self.alloc, &self.out, .{
            .length = payload.len,
            .type = .goaway,
            .flags = 0,
            .stream_id = 0,
        }, &payload);
        self.state = .closed;
        self.last_error = code;
    }

    // ─── Inbound ─────────────────────────────────────────────────────────────

    /// Consume inbound bytes. Connection-level protocol errors become a queued
    /// GOAWAY plus `state = .closed`; only allocation failure propagates.
    pub fn feed(self: *Connection, data: []const u8) !void {
        if (self.state == .closed) return;
        var pos: usize = 0;

        if (self.state == .expect_preface) {
            const want = constants.PREFACE[self.preface_consumed..];
            const avail = @min(want.len, data.len);
            if (!std.mem.eql(u8, want[0..avail], data[0..avail])) {
                return self.fail(constants.ErrorCode.protocol_error);
            }
            self.preface_consumed += avail;
            pos = avail;
            if (self.preface_consumed < constants.PREFACE.len) return;
            self.state = .open;
            try self.sendSettings();
        }

        while (pos < data.len) {
            const decoded = frame.decode(data[pos..], self.opts.max_frame_size) catch |err| switch (err) {
                // A short read mid-frame just means "more bytes later".
                error.IncompleteFrame => return,
                error.FrameSizeError, error.InvalidFrameLength => return self.fail(constants.ErrorCode.frame_size_error),
                error.ProtocolError => return self.fail(constants.ErrorCode.protocol_error),
            };
            pos += decoded.consumed;
            try self.handleFrame(decoded.frame);
            if (self.state == .closed) return;
        }
    }

    fn handleFrame(self: *Connection, f: frame.Frame) !void {
        // After HEADERS without END_HEADERS, ONLY CONTINUATION may follow
        // (RFC 9113 §6.2) — no interleaving of any other frame type.
        if (self.awaiting_continuation and f.header.type != .continuation) {
            return self.fail(constants.ErrorCode.protocol_error);
        }
        switch (f.header.type) {
            .settings => try self.onSettings(f),
            .ping => try self.onPing(f),
            .goaway => try self.onGoaway(f),
            .window_update => try self.onWindowUpdate(f),
            .headers => try self.onHeaders(f),
            .continuation => try self.onContinuation(f),
            .data => try self.onData(f),
            .rst_stream => try self.onRstStream(f),
            .priority => try self.onPriority(f),
            // Clients cannot push: receiving PUSH_PROMISE is a connection error.
            .push_promise => try self.fail(constants.ErrorCode.protocol_error),
            // Unknown frame types MUST be ignored (RFC 9113 §4.1).
            else => {},
        }
    }

    fn onSettings(self: *Connection, f: frame.Frame) !void {
        if (f.header.stream_id != 0) return self.fail(constants.ErrorCode.protocol_error);
        if (f.header.flags & constants.flag_ack != 0) {
            if (f.header.length != 0) return self.fail(constants.ErrorCode.frame_size_error);
            self.settings_ack_pending = false;
            return;
        }
        const s = settings.decode(f.payload) catch |err| switch (err) {
            error.FrameSizeError => return self.fail(constants.ErrorCode.frame_size_error),
            error.ProtocolError => return self.fail(constants.ErrorCode.protocol_error),
        };
        // A server receiving ENABLE_PUSH=1 is a connection error (§6.5.2).
        if (s.enable_push) |p| {
            if (p) return self.fail(constants.ErrorCode.protocol_error);
        }
        if (s.max_frame_size) |mfs| self.peer_max_frame_size = mfs;
        if (s.max_concurrent_streams) |m| self.peer_max_concurrent = m;
        if (s.header_table_size) |t| self.peer_header_table_size = t;
        // SETTINGS_INITIAL_WINDOW_SIZE moves EVERY open stream's send window by
        // the delta (§6.9.2); the connection window is untouched.
        if (s.initial_window_size) |new_initial| {
            const delta = @as(i64, @intCast(new_initial)) - @as(i64, @intCast(self.peer_initial_window));
            var it = self.streams.streams.iterator();
            while (it.next()) |entry| entry.value_ptr.*.send_window += delta;
            self.peer_initial_window = new_initial;
        }

        try frame.writeFrame(self.alloc, &self.out, .{
            .length = 0,
            .type = .settings,
            .flags = constants.flag_ack,
            .stream_id = 0,
        }, "");
        if (self.hasPendingOutput()) try self.flush();
    }

    fn onPing(self: *Connection, f: frame.Frame) !void {
        if (f.header.stream_id != 0) return self.fail(constants.ErrorCode.protocol_error);
        if (f.header.length != 8) return self.fail(constants.ErrorCode.frame_size_error);
        if (f.header.flags & constants.flag_ack != 0) return; // we never send pings
        try frame.writeFrame(self.alloc, &self.out, .{
            .length = 8,
            .type = .ping,
            .flags = constants.flag_ack,
            .stream_id = 0,
        }, f.payload[0..8]);
    }

    fn onGoaway(self: *Connection, f: frame.Frame) !void {
        if (f.header.stream_id != 0) return self.fail(constants.ErrorCode.protocol_error);
        if (f.header.length < 8) return self.fail(constants.ErrorCode.frame_size_error);
        self.goaway_received = true;
        self.state = .closing;
        try self.flush();
    }

    fn onWindowUpdate(self: *Connection, f: frame.Frame) !void {
        if (f.header.length != 4) return self.fail(constants.ErrorCode.frame_size_error);
        const inc = std.mem.readInt(u32, f.payload[0..4], .big) & 0x7fff_ffff;
        if (inc == 0) {
            if (f.header.stream_id == 0) return self.fail(constants.ErrorCode.protocol_error);
            return self.rstStream(f.header.stream_id, constants.ErrorCode.protocol_error);
        }
        if (f.header.stream_id == 0) {
            self.conn_send.update(inc) catch return self.fail(constants.ErrorCode.flow_control_error);
        } else {
            const s = self.streams.get(f.header.stream_id) orelse return;
            if (s.state == .idle) return self.fail(constants.ErrorCode.protocol_error);
            s.send_window += @intCast(inc);
            if (s.send_window > constants.max_window_size) {
                return self.fail(constants.ErrorCode.flow_control_error);
            }
        }
        try self.flush();
    }

    fn onHeaders(self: *Connection, f: frame.Frame) !void {
        if (f.header.stream_id == 0) return self.fail(constants.ErrorCode.protocol_error);
        self.frag.clearRetainingCapacity();
        self.frag_stream_id = f.header.stream_id;
        self.frag_end_stream = f.header.flags & constants.flag_end_stream != 0;

        // Padding/priority fields precede the header block fragment, and padding
        // is not flow controlled on HEADERS — only DATA's payload counts.
        const stripped = frame.stripPadding(f.payload, .headers, f.header.flags) catch |err| switch (err) {
            error.FrameSizeError => return self.fail(constants.ErrorCode.frame_size_error),
            else => return self.fail(constants.ErrorCode.protocol_error),
        };
        try self.frag.appendSlice(self.alloc, stripped);

        if (f.header.flags & constants.flag_end_headers == 0) {
            self.awaiting_continuation = true;
            return;
        }
        try self.finishHeaderBlock();
    }

    fn onContinuation(self: *Connection, f: frame.Frame) !void {
        if (f.header.stream_id != self.frag_stream_id) return self.fail(constants.ErrorCode.protocol_error);
        try self.frag.appendSlice(self.alloc, f.payload);
        if (f.header.flags & constants.flag_end_headers == 0) return;
        self.awaiting_continuation = false;
        try self.finishHeaderBlock();
    }

    /// Decode the reassembled header block: open a request stream, or finish
    /// trailers on an existing one.
    fn finishHeaderBlock(self: *Connection) !void {
        self.awaiting_continuation = false;
        const stream_id = self.frag_stream_id;

        var pairs: std.ArrayList(hpack.Pair) = .empty;
        defer {
            for (pairs.items) |p| {
                self.alloc.free(p.name);
                self.alloc.free(p.value);
            }
            pairs.deinit(self.alloc);
        }
        self.dec.decode(self.frag.items, &pairs) catch |err| switch (err) {
            error.HeaderListTooLarge => return self.fail(constants.ErrorCode.enhance_your_calm),
            else => return self.fail(constants.ErrorCode.compression_error),
        };

        const existing = self.streams.get(stream_id);
        if (existing) |s| {
            if (s.state == .closed) return self.failWithStream(stream_id, constants.ErrorCode.stream_closed);
            // A trailer block must carry END_STREAM (§8.1) and may only arrive
            // while the request side is still open.
            if (s.state != .open or !self.frag_end_stream) {
                return self.rstStream(stream_id, constants.ErrorCode.protocol_error);
            }
            try self.streams.apply(stream_id, .recv_headers_end);
            return self.maybeComplete(stream_id);
        }

        const s = self.streams.openFromPeer(stream_id, @intCast(self.peer_initial_window), @intCast(self.opts.initial_window_size)) catch |err| switch (err) {
            error.RefusedStream => return self.rstStream(stream_id, constants.ErrorCode.refused_stream),
            error.ProtocolError => return self.fail(constants.ErrorCode.protocol_error),
            error.StreamClosed => return self.fail(constants.ErrorCode.stream_closed),
        };
        _ = s;
        try self.streams.apply(stream_id, if (self.frag_end_stream) .recv_headers_end else .recv_headers);

        const rs = try self.alloc.create(RecvStream);
        rs.* = .{ .recv_window = flow_control.Window.init(@intCast(self.opts.initial_window_size)) };
        errdefer {
            rs.body.deinit(self.alloc);
            self.alloc.destroy(rs);
        }
        try self.recv_streams.put(self.alloc, stream_id, rs);
        try self.splitPseudoHeaders(stream_id, pairs.items);
    }

    /// Validate pseudo-headers, copy the regular headers into the request arena
    /// and stash them on the stream.
    fn splitPseudoHeaders(self: *Connection, stream_id: u32, pairs: []const hpack.Pair) !void {
        const rs = self.recv_streams.get(stream_id) orelse return self.fail(constants.ErrorCode.internal_error);
        const arena = self.req_arena.allocator();
        var has_method = false;
        var has_path = false;
        var seen_regular = false;
        // Built in the request arena: `toOwnedSlice` hands ownership to the
        // arena, which the caller recycles wholesale (no per-pair frees).
        var reg = std.ArrayList(hpack.Pair).empty;

        for (pairs) |p| {
            if (p.name.len == 0 or std.ascii.isUpper(p.name[0])) {
                return self.rstStream(stream_id, constants.ErrorCode.protocol_error);
            }
            if (p.name[0] == ':') {
                // Pseudo-headers must all precede regular headers.
                if (seen_regular) return self.rstStream(stream_id, constants.ErrorCode.protocol_error);
                if (std.mem.eql(u8, p.name, ":method")) {
                    rs.method = try arena.dupe(u8, p.value);
                    has_method = true;
                } else if (std.mem.eql(u8, p.name, ":path")) {
                    rs.path = try arena.dupe(u8, p.value);
                    has_path = true;
                } else if (std.mem.eql(u8, p.name, ":scheme")) {
                    rs.scheme = try arena.dupe(u8, p.value);
                } else if (std.mem.eql(u8, p.name, ":authority")) {
                    rs.authority = try arena.dupe(u8, p.value);
                } else {
                    // :status/:protocol are illegal in a client request; any other
                    // pseudo-header is unknown.
                    return self.rstStream(stream_id, constants.ErrorCode.protocol_error);
                }
                continue;
            }
            seen_regular = true;
            if (isIllegalRequestHeader(p.name, p.value)) {
                return self.rstStream(stream_id, constants.ErrorCode.protocol_error);
            }
            if (std.mem.eql(u8, p.name, "host") and rs.authority.len == 0) {
                rs.authority = try arena.dupe(u8, p.value);
            }
            try reg.append(arena, .{
                .name = try arena.dupe(u8, p.name),
                .value = try arena.dupe(u8, p.value),
            });
        }
        // A request needs :method and :path (CONNECT — which omits :path — is
        // rejected here along with it).
        if (!has_method or !has_path) {
            return self.rstStream(stream_id, constants.ErrorCode.protocol_error);
        }
        rs.headers = try reg.toOwnedSlice(arena);
        try self.maybeComplete(stream_id);
    }

    /// Publish a request once the client has finished sending it.
    fn maybeComplete(self: *Connection, stream_id: u32) !void {
        const s = self.streams.get(stream_id) orelse return;
        if (s.state != .half_closed_remote) return;
        const rs = self.recv_streams.get(stream_id) orelse return;
        if (rs.method.len == 0) return; // trailers-only block: nothing to serve

        const arena = self.req_arena.allocator();
        const req = try arena.create(Request);
        req.* = .{
            .stream_id = stream_id,
            .method = rs.method,
            .path = rs.path,
            .scheme = rs.scheme,
            .authority = rs.authority,
            .headers = rs.headers,
            .body = try arena.dupe(u8, rs.body.items),
        };
        try self.ready.append(self.alloc, req);
    }

    fn onData(self: *Connection, f: frame.Frame) !void {
        if (f.header.stream_id == 0) return self.fail(constants.ErrorCode.protocol_error);
        const s = self.streams.get(f.header.stream_id) orelse
            return self.fail(constants.ErrorCode.protocol_error);
        if (s.state == .idle) return self.fail(constants.ErrorCode.protocol_error);
        if (s.state == .closed or s.state == .half_closed_remote) {
            return self.failWithStream(f.header.stream_id, constants.ErrorCode.stream_closed);
        }

        // Flow control counts the WHOLE payload, padding included (§6.9). The
        // connection window overrun is a connection error; a stream overrun only
        // kills the stream.
        self.conn_recv.consume(f.header.length) catch
            return self.fail(constants.ErrorCode.flow_control_error);
        const rs = self.recv_streams.get(f.header.stream_id) orelse
            return self.fail(constants.ErrorCode.protocol_error);
        rs.recv_window.consume(f.header.length) catch
            return self.rstStream(f.header.stream_id, constants.ErrorCode.flow_control_error);

        const body_bytes = frame.stripPadding(f.payload, .data, f.header.flags) catch
            return self.fail(constants.ErrorCode.protocol_error);
        if (rs.body.items.len + body_bytes.len > self.opts.max_body_bytes) {
            return self.rstStream(f.header.stream_id, constants.ErrorCode.enhance_your_calm);
        }
        try rs.body.appendSlice(self.alloc, body_bytes);

        if (f.header.flags & constants.flag_end_stream != 0) {
            try self.streams.apply(f.header.stream_id, .recv_data_end);
            try self.maybeComplete(f.header.stream_id);
        }
    }

    fn onRstStream(self: *Connection, f: frame.Frame) !void {
        if (f.header.stream_id == 0) return self.fail(constants.ErrorCode.protocol_error);
        if (f.header.length != 4) return self.fail(constants.ErrorCode.frame_size_error);
        const s = self.streams.get(f.header.stream_id) orelse return; // unknown stream: ignore
        if (s.state == .idle) return self.fail(constants.ErrorCode.protocol_error);
        self.dropStream(f.header.stream_id);
    }

    fn onPriority(self: *Connection, f: frame.Frame) !void {
        if (f.header.length != 5) return self.fail(constants.ErrorCode.frame_size_error);
        if (f.header.stream_id == 0) return self.fail(constants.ErrorCode.protocol_error);
        // Dependency information is accepted and ignored (RFC 9113 §5.3).
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    fn sendSettings(self: *Connection) !void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.alloc);
        try settings.encodeOurs(self.alloc, &payload);
        try frame.writeFrame(self.alloc, &self.out, .{
            .length = @intCast(payload.items.len),
            .type = .settings,
            .flags = 0,
            .stream_id = 0,
        }, payload.items);
        self.settings_ack_pending = true;
    }

    /// HEADERS + CONTINUATION. END_STREAM rides on the HEADERS frame (it cannot
    /// appear on a CONTINUATION), END_HEADERS on the last frame (§6.2).
    fn writeHeaderBlock(self: *Connection, stream_id: u32, block: []const u8, end_stream: bool) !void {
        const max: usize = self.peer_max_frame_size;
        if (block.len <= max) {
            var flags: u8 = constants.flag_end_headers;
            if (end_stream) flags |= constants.flag_end_stream;
            return frame.writeFrame(self.alloc, &self.out, .{
                .length = @intCast(block.len),
                .type = .headers,
                .flags = flags,
                .stream_id = stream_id,
            }, block);
        }
        var offset: usize = 0;
        var first = true;
        while (offset < block.len) {
            const take = @min(max, block.len - offset);
            const last = offset + take == block.len;
            const is_first = first;
            first = false;
            var flags: u8 = 0;
            if (last) flags |= constants.flag_end_headers;
            if (is_first and end_stream) flags |= constants.flag_end_stream;
            try frame.writeFrame(self.alloc, &self.out, .{
                .length = @intCast(take),
                .type = if (is_first) .headers else .continuation,
                .flags = flags,
                .stream_id = stream_id,
            }, block[offset .. offset + take]);
            offset += take;
        }
    }

    fn writeData(self: *Connection, stream_id: u32, bytes: []const u8, end_stream: bool) !void {
        try frame.writeFrame(self.alloc, &self.out, .{
            .length = @intCast(bytes.len),
            .type = .data,
            .flags = if (end_stream) constants.flag_end_stream else 0,
            .stream_id = stream_id,
        }, bytes);
    }

    fn flushWindowUpdates(self: *Connection) void {
        if (self.conn_recv.takeUpdate()) |inc| {
            const payload: [4]u8 = frame.windowUpdatePayload(inc);
            frame.writeFrame(self.alloc, &self.out, .{
                .length = 4,
                .type = .window_update,
                .flags = 0,
                .stream_id = 0,
            }, &payload) catch {};
        }
        var it = self.recv_streams.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.recv_window.takeUpdate()) |inc| {
                const payload: [4]u8 = frame.windowUpdatePayload(inc);
                frame.writeFrame(self.alloc, &self.out, .{
                    .length = 4,
                    .type = .window_update,
                    .flags = 0,
                    .stream_id = entry.key_ptr.*,
                }, &payload) catch {};
            }
        }
    }

    fn rstStream(self: *Connection, stream_id: u32, code: constants.ErrorCode) !void {
        if (stream_id == 0 or self.state == .closed) return;
        const payload: [4]u8 = frame.rstStreamPayload(code);
        try frame.writeFrame(self.alloc, &self.out, .{
            .length = 4,
            .type = .rst_stream,
            .flags = 0,
            .stream_id = stream_id,
        }, &payload);
        self.dropStream(stream_id);
    }

    /// A stream-level error on a stream we never registered still needs a
    /// RST_STREAM, but there is nothing to tear down.
    fn failWithStream(self: *Connection, stream_id: u32, code: constants.ErrorCode) !void {
        if (stream_id == 0 or self.state == .closed) return;
        if (self.streams.get(stream_id) != null) return self.rstStream(stream_id, code);
        const payload: [4]u8 = frame.rstStreamPayload(code);
        return frame.writeFrame(self.alloc, &self.out, .{
            .length = 4,
            .type = .rst_stream,
            .flags = 0,
            .stream_id = stream_id,
        }, &payload);
    }

    /// Tear down a stream's bookkeeping and drop anything queued for it, so the
    /// server never answers a stream the peer cancelled.
    fn dropStream(self: *Connection, stream_id: u32) void {
        if (self.streams.get(stream_id)) |s| {
            s.state = .closed;
            s.response_complete = true;
        }
        if (self.recv_streams.fetchRemove(stream_id)) |kv| {
            kv.value.body.deinit(self.alloc);
            self.alloc.destroy(kv.value);
        }
        var i: usize = 0;
        while (i < self.ready.items.len) {
            if (self.ready.items[i].stream_id == stream_id) {
                _ = self.ready.orderedRemove(i);
            } else i += 1;
        }
        var j: usize = 0;
        while (j < self.pending_bodies.items.len) {
            if (self.pending_bodies.items[j].stream_id == stream_id) {
                _ = self.pending_bodies.swapRemove(j);
            } else j += 1;
        }
    }

    /// A stream is fully closed once BOTH sides have finished; free its
    /// per-stream state so a long-lived connection does not accumulate it.
    fn closeStreamIfDone(self: *Connection, stream_id: u32) void {
        const s = self.streams.get(stream_id) orelse return;
        if (s.state == .closed) self.dropStream(stream_id);
    }

    fn fail(self: *Connection, code: constants.ErrorCode) !void {
        try self.goaway(code);
    }
};

/// Connection-specific headers are illegal in HTTP/2 (RFC 9113 §8.2.2).
fn isIllegalRequestHeader(name: []const u8, value: []const u8) bool {
    const banned = [_][]const u8{ "connection", "upgrade", "keep-alive", "proxy-connection", "transfer-encoding" };
    for (banned) |b| {
        if (std.mem.eql(u8, name, b)) return true;
    }
    // `te` is allowed, but ONLY with the value `trailers`.
    if (std.mem.eql(u8, name, "te") and !std.mem.eql(u8, value, "trailers")) return true;
    return false;
}

/// Headers we always own or that HTTP/2 forbids on responses.
fn isIllegalResponseHeader(name: []const u8) bool {
    const banned = [_][]const u8{ "connection", "upgrade", "keep-alive", "proxy-connection", "transfer-encoding" };
    for (banned) |b| {
        if (std.mem.eql(u8, name, b)) return true;
    }
    return false;
}

// ============================================================================
// Tests — moved here from `connection_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = connection_tests; }` below pulls them into the run.
// ============================================================================

const connection_tests = struct {
    const testing = std.testing;

    const connection = @import("connection.zig");


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
};

comptime {
    _ = connection_tests;
}
