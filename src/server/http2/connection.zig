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

test {
    _ = @import("connection_test.zig");
}
