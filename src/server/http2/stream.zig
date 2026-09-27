//! HTTP/2 stream state machine (RFC 9113 §5.1) and the per-connection stream
//! table that holds it.
//!
//! Pure: no I/O, no threads, no clock. One `Table` per connection; the
//! connection driver feeds it one `Event` per frame that lands on a stream and
//! turns the returned error into the matching RST_STREAM / GOAWAY code. Keeping
//! the §5.1 matrix in this one place is what lets the driver stay a
//! straight-line frame pump with no protocol state of its own.
//!
//! Deliberately *not* policed here (both are the driver's business):
//!   * §8.1 field/content rules — e.g. that a trailing HEADERS block carries
//!     END_STREAM, that `:method` is present, that `connection` is absent.
//!   * Flow-control arithmetic — `Stream.send_window` / `recv_window` are
//!     carried here so the driver has one object per stream, but the accounting
//!     itself belongs to `flow_control.zig`.

const std = @import("std");
const constants = @import("constants.zig");

/// RFC 9113 §5.1 states. `half_closed_local` is only reachable by a server that
/// sends END_STREAM while the client has not yet. `reserved_*` exists so a
/// PUSH_PROMISE (which we never send, but must recognise) can be modelled.
pub const State = enum { idle, open, half_closed_remote, half_closed_local, closed, reserved_local, reserved_remote };

/// Events that drive transitions.
pub const Event = enum {
    recv_headers, // HEADERS received (not END_STREAM)
    recv_headers_end, // HEADERS with END_STREAM
    recv_data, // DATA received (not END_STREAM)
    recv_data_end, // DATA with END_STREAM
    recv_rst, // RST_STREAM received
    recv_push_promise, // PUSH_PROMISE received (only legal on an idle stream we did not open)
    send_headers, // we send HEADERS (not END_STREAM)
    send_headers_end, // we send HEADERS with END_STREAM
    send_data, // we send DATA (not END_STREAM)
    send_data_end, // we send DATA with END_STREAM
    send_rst, // we send RST_STREAM
};

pub const Error = error{ ProtocolError, StreamClosed, RefusedStream };

pub const Stream = struct {
    id: u32,
    state: State = .idle,
    /// Bytes we may still send (peer's view of our window).
    send_window: i64,
    /// Bytes the peer may still send to us.
    recv_window: i64,
    /// Bytes received since our last WINDOW_UPDATE for this stream.
    recv_unacked: i64 = 0,
    /// Set once a request body has been fully received and the response has not
    /// finished yet (used by the connection driver to keep the stream open).
    response_complete: bool = false,
};

/// Highest id a stream may use: ids are 31-bit (RFC 9113 §5.1.1), so bit 31 is
/// reserved for future use and must be zero.
const max_stream_id: u32 = 0x7FFF_FFFF;

pub const Table = struct {
    streams: std.AutoHashMapUnmanaged(u32, *Stream),
    highest_peer_stream_id: u32 = 0,
    max_concurrent: u32,
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator, max_concurrent: u32) Table {
        return .{
            .streams = .empty,
            .highest_peer_stream_id = 0,
            .max_concurrent = max_concurrent,
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Table) void {
        // `Stream` is heap-allocated so the driver can hand out a stable
        // `*Stream`; every entry must therefore be destroyed explicitly. The
        // map holds no owned keys, so tearing it down is enough for the rest.
        var it = self.streams.valueIterator();
        while (it.next()) |stream| self.alloc.destroy(stream.*);
        self.streams.deinit(self.alloc);
    }

    /// Validate a client-initiated stream id and open the stream.
    /// Rejects: id == 0, an even id (clients use odd ids), an id <= highest_peer_stream_id
    /// (monotonically increasing), and exceeding max_concurrent (error.RefusedStream).
    pub fn openFromPeer(self: *Table, id: u32, send_window: i64, recv_window: i64) Error!*Stream {
        // RFC 9113 §5.1.1: stream 0 is the connection itself, clients use odd
        // ids, ids must strictly increase, and bit 31 is reserved. Reusing an id
        // would resurrect a stream whose frames may still be in flight, so a
        // non-increasing id is a connection error, not a stream error.
        if (id == 0) return error.ProtocolError;
        if (id > max_stream_id) return error.ProtocolError;
        if (id % 2 == 0) return error.ProtocolError;
        if (id <= self.highest_peer_stream_id) return error.ProtocolError;

        // A window outside [0, 2^31-1] cannot be produced by a valid SETTINGS
        // frame, so it means the caller fed us garbage (RFC 9113 §6.9.1).
        if (!validWindow(send_window) or !validWindow(recv_window)) return error.ProtocolError;

        if (self.slotsInUse() >= self.max_concurrent) {
            // RFC 9113 §5.1.2: refuse the stream rather than killing the
            // connection. REFUSED_STREAM promises the request was not processed,
            // so the client may safely replay it on a fresh id — which also
            // means the refused id is burned: this and every lower id can never
            // be opened now, so record that before bailing out.
            self.highest_peer_stream_id = id;
            return error.RefusedStream;
        }

        const stream = self.alloc.create(Stream) catch return error.RefusedStream;
        stream.* = .{
            .id = id,
            .state = .idle,
            .send_window = send_window,
            .recv_window = recv_window,
            .recv_unacked = 0,
            .response_complete = false,
        };
        // An allocation failure is reported as REFUSED_STREAM too: the peer can
        // retry, and the alternative (an unnamed error) would leave the driver
        // with no wire code to send.
        self.streams.put(self.alloc, id, stream) catch {
            self.alloc.destroy(stream);
            return error.RefusedStream;
        };
        self.highest_peer_stream_id = id;
        return stream;
    }

    pub fn get(self: *Table, id: u32) ?*Stream {
        return self.streams.get(id);
    }

    pub fn getOrNull(self: *Table, id: u32) ?*Stream {
        // Same lookup, spelled for call sites where "may be absent" reads better
        // than a bare `get`.
        return self.streams.get(id);
    }

    /// Apply an event to a stream, enforcing RFC 9113 §5.1. Illegal transitions
    /// return error.ProtocolError (DATA/HEADERS on an idle or closed stream,
    /// WINDOW_UPDATE on idle, etc.).
    ///
    /// WINDOW_UPDATE has no `Event` arm: it is a window change, not a state
    /// change, so the driver checks `get(id).?.state` itself before applying the
    /// increment (rejecting it on an idle/closed stream) and then calls
    /// `flow_control.Window.update`.
    pub fn apply(self: *Table, id: u32, event: Event) Error!void {
        // No entry at all means this id was never opened (or was already swept
        // after closing). Either way the driver must not silently drop the
        // frame: an unknown stream is a protocol error, while a *known* stream
        // that has closed answers with STREAM_CLOSED (see `transition`).
        const stream = self.get(id) orelse return error.ProtocolError;

        const next = switch (transition(stream.state, event)) {
            .to => |s| s,
            .fail => |e| return e,
        };

        stream.state = next;
        // The response half is done for good once we send END_STREAM or reset
        // the stream, regardless of what the request half is still doing.
        if (endsResponse(event)) stream.response_complete = true;
    }

    /// Remove a finished stream. Idempotent.
    pub fn remove(self: *Table, id: u32) void {
        if (self.streams.fetchRemove(id)) |kv| self.alloc.destroy(kv.value);
    }

    /// Number of streams that are neither idle nor closed.
    pub fn activeCount(self: *Table) u32 {
        var n: u32 = 0;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*.state;
            // Reserved streams count: RFC 9113 §5.1.2 charges every stream that
            // is open, half-closed *or* reserved against MAX_CONCURRENT_STREAMS.
            if (state != .idle and state != .closed) n += 1;
        }
        return n;
    }

    /// Streams currently occupying one of the peer's concurrency slots. Differs
    /// from `activeCount` in two ways the §5.1.2 limit cares about: a freshly
    /// registered (still `.idle`) stream already holds a slot, and a `.closed`
    /// one releases it immediately — before the driver gets around to `remove`.
    fn slotsInUse(self: *Table) u32 {
        var n: u32 = 0;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.state != .closed) n += 1;
        }
        return n;
    }
};

fn validWindow(w: i64) bool {
    return w >= 0 and w <= constants.max_window_size;
}

/// True for the events that end the response half of a stream.
fn endsResponse(event: Event) bool {
    return switch (event) {
        .send_headers_end, .send_data_end, .send_rst => true,
        else => false,
    };
}

const Transition = union(enum) {
    to: State,
    fail: Error,
};

fn st(state: State) Transition {
    return .{ .to = state };
}

fn bad(e: Error) Transition {
    return .{ .fail = e };
}

/// The RFC 9113 §5.1 state table, transcribed literally — one row per state,
/// one arm per event. Read the RFC's table next to this function.
///
/// Two rows deserve a note because our table is *server-side only*:
///
///   * `.idle` here means "the peer sent us HEADERS, we registered the id but
///     have not applied `.recv_headers` yet". The peer's view of that stream is
///     already `.open`, so a local `send_rst` (we cannot build a request out of
///     the header block) is legal and lands in `.closed`.
///   * `.idle` + `.recv_rst` is therefore a genuine §6.4 violation — the peer
///     cannot reset a stream it never opened — and is reported as a *connection*
///     error (ProtocolError), not StreamClosed.
fn transition(state: State, event: Event) Transition {
    return switch (state) {
        .idle => switch (event) {
            // The peer's HEADERS creates the stream; END_STREAM closes its half
            // straight away (the common GET).
            .recv_headers => st(.open),
            .recv_headers_end => st(.half_closed_remote),
            // PUSH_PROMISE is the only way a stream leaves idle without
            // HEADERS, and it reserves the stream to the *peer*. We never act
            // on it (ENABLE_PUSH: 0) but the state must be representable.
            .recv_push_promise => st(.reserved_remote),
            // RST_STREAM for a stream the peer never opened (RFC 9113 §6.4).
            .recv_rst => bad(error.ProtocolError),
            // Local refusal of a peer-registered stream (see the doc comment).
            .send_rst => st(.closed),
            // DATA can only follow HEADERS on the same stream.
            .recv_data, .recv_data_end => bad(error.ProtocolError),
            // A server never creates a stream with HEADERS — that would be a
            // PUSH_PROMISE, which we do not send.
            .send_headers, .send_headers_end, .send_data, .send_data_end => bad(error.ProtocolError),
        },
        .open => switch (event) {
            // A HEADERS without END_STREAM mid-stream stays `.open` per the
            // §5.1 table; whether it is a *legal* trailer block is a §8.1
            // question the driver answers.
            .recv_headers => st(.open),
            .recv_headers_end => st(.half_closed_remote),
            .recv_data => st(.open),
            .recv_data_end => st(.half_closed_remote),
            .recv_rst => st(.closed),
            // PUSH_PROMISE is only ever legal on an idle stream (RFC 9113 §6.6).
            .recv_push_promise => bad(error.ProtocolError),
            // Informational (1xx) responses are HEADERS without END_STREAM on a
            // live stream, so this stays `.open`.
            .send_headers => st(.open),
            .send_headers_end => st(.half_closed_local),
            .send_data => st(.open),
            .send_data_end => st(.half_closed_local),
            .send_rst => st(.closed),
        },
        .half_closed_local => switch (event) {
            // We ended our response; the peer may still finish its request
            // (trailers with END_STREAM is the normal shape, but §5.1 keeps the
            // state on a non-final HEADERS — §8.1 rejects it as malformed).
            .recv_headers => st(.half_closed_local),
            .recv_headers_end => st(.closed),
            .recv_data => st(.half_closed_local),
            .recv_data_end => st(.closed),
            .recv_rst => st(.closed),
            .recv_push_promise => bad(error.ProtocolError),
            // We already sent END_STREAM: no further HEADERS or DATA from us.
            .send_headers, .send_headers_end, .send_data, .send_data_end => bad(error.ProtocolError),
            .send_rst => st(.closed),
        },
        .half_closed_remote => switch (event) {
            // RFC 9113 §5.1: anything but WINDOW_UPDATE / PRIORITY / RST_STREAM
            // arriving after the peer's END_STREAM is a STREAM_CLOSED stream
            // error (frames in flight from the peer are the usual cause).
            .recv_headers, .recv_headers_end, .recv_data, .recv_data_end => bad(error.StreamClosed),
            .recv_rst => st(.closed),
            .recv_push_promise => bad(error.ProtocolError),
            // Our half is the only one left, so the response still flows freely.
            .send_headers => st(.half_closed_remote),
            .send_headers_end => st(.closed),
            .send_data => st(.half_closed_remote),
            .send_data_end => st(.closed),
            .send_rst => st(.closed),
        },
        .reserved_remote => switch (event) {
            // A pushed stream becomes usable once the peer's HEADERS lands.
            .recv_headers => st(.half_closed_local),
            .recv_headers_end => st(.closed),
            .recv_rst => st(.closed),
            // Nothing else may arrive on a reserved stream (RFC 9113 §5.1).
            .recv_data, .recv_data_end => bad(error.ProtocolError),
            .recv_push_promise => bad(error.ProtocolError),
            .send_headers, .send_headers_end, .send_data, .send_data_end => bad(error.ProtocolError),
            .send_rst => st(.closed),
        },
        .reserved_local => switch (event) {
            // The mirror row: this is the state our own PUSH_PROMISE would have
            // created, so only the send side can move out of it.
            .send_headers => st(.half_closed_remote),
            .send_headers_end => st(.closed),
            .send_rst => st(.closed),
            .send_data, .send_data_end => bad(error.ProtocolError),
            .recv_headers, .recv_headers_end, .recv_data, .recv_data_end => bad(error.ProtocolError),
            .recv_push_promise => bad(error.ProtocolError),
            .recv_rst => st(.closed),
        },
        .closed => switch (event) {
            // Terminal: every further frame is a stream error (the driver
            // ignores it). Frames race with RST_STREAM/END_STREAM by design, so
            // this is an expected, recoverable outcome — not a connection error.
            .recv_headers, .recv_headers_end, .recv_data, .recv_data_end, .recv_rst => bad(error.StreamClosed),
            // PUSH_PROMISE is a *connection* error wherever it appears except on
            // an idle stream, closed ones included (RFC 9113 §6.6).
            .recv_push_promise => bad(error.ProtocolError),
            .send_headers, .send_headers_end, .send_data, .send_data_end, .send_rst => bad(error.StreamClosed),
        },
    };
}

// ============================================================================
// Tests — moved here from `stream_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = stream_tests; }` below pulls them into the run.
// ============================================================================

const stream_tests = struct {
    const stream = @import("stream.zig");
    const testing = std.testing;


    /// The windows a driver would hand a brand-new stream: whatever the connection
    /// windows currently are (RFC 9113 §6.9.2 — a new stream starts at the current
    /// INITIAL_WINDOW_SIZE, not at its default).
    const peer_send_window: i64 = constants.default_initial_window_size; // 65535, what we may send
    const our_recv_window: i64 = constants.our_initial_window_size; // 1 MiB, what the peer may send

    fn newTable(max_concurrent: u32) Table {
        // testing.allocator fails the test on any leaked Stream or map allocation.
        return Table.init(testing.allocator, max_concurrent);
    }

    test "openFromPeer registers the id idle; recv_headers opens it" {
        var t = newTable(100);
        defer t.deinit();

        const s = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try testing.expectEqual(@as(u32, 1), s.id);
        try testing.expectEqual(State.idle, s.state);
        try testing.expectEqual(State.idle, t.get(1).?.state);
        try testing.expectEqual(@as(u32, 1), t.highest_peer_stream_id);

        try t.apply(1, .recv_headers);
        try testing.expectEqual(State.open, t.get(1).?.state);
        // The pointer handed out at open time is the live stream, not a copy.
        try testing.expectEqual(State.open, s.state);
    }

    test "openFromPeer: an existing-id lookup misses for a stream we never opened" {
        var t = newTable(100);
        defer t.deinit();

        try testing.expect(t.get(5) == null);
        try testing.expect(t.getOrNull(5) == null);
        _ = try t.openFromPeer(5, peer_send_window, our_recv_window);
        try testing.expect(t.get(5) == t.getOrNull(5));
    }

    test "peer END_STREAM then our END_STREAM closes the stream" {
        var t = newTable(100);
        defer t.deinit();

        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try t.apply(1, .recv_headers_end);
        try testing.expectEqual(State.half_closed_remote, t.get(1).?.state);

        try t.apply(1, .send_headers_end);
        try testing.expectEqual(State.closed, t.get(1).?.state);
    }

    test "request and response halves close independently" {
        var t = newTable(100);
        defer t.deinit();

        _ = try t.openFromPeer(3, peer_send_window, our_recv_window);
        try t.apply(3, .recv_headers);
        try testing.expectEqual(State.open, t.get(3).?.state);

        try t.apply(3, .send_headers);
        try testing.expectEqual(State.open, t.get(3).?.state);

        try t.apply(3, .recv_data_end);
        try testing.expectEqual(State.half_closed_remote, t.get(3).?.state);

        try t.apply(3, .send_data_end);
        try testing.expectEqual(State.closed, t.get(3).?.state);
    }

    test "our END_STREAM first reaches half_closed_local, then the peer closes it" {
        var t = newTable(100);
        defer t.deinit();

        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try t.apply(1, .recv_headers);
        try t.apply(1, .send_data_end); // we answer before the body finishes
        try testing.expectEqual(State.half_closed_local, t.get(1).?.state);

        // Informational-free response already sent: another HEADERS from us is a
        // protocol error, and the peer's END_STREAM is the only way out.
        try testing.expectError(error.ProtocolError, t.apply(1, .send_headers));
        try t.apply(1, .recv_data_end);
        try testing.expectEqual(State.closed, t.get(1).?.state);
    }

    test "response_complete flips when we end the response half" {
        var t = newTable(100);
        defer t.deinit();

        const s = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try t.apply(1, .recv_headers);
        try testing.expect(!s.response_complete);

        try t.apply(1, .send_headers);
        try testing.expect(!s.response_complete); // 1xx-style, response still open

        try t.apply(1, .send_data_end);
        try testing.expect(s.response_complete);
    }

    test "RST_STREAM in either direction closes any active stream" {
        // `.idle` is excluded on purpose: a peer RST on an idle stream is a §6.4
        // connection error (asserted separately below), and the local-reset case
        // has its own test.
        const active_states = [_]State{ .open, .half_closed_remote, .half_closed_local, .reserved_local, .reserved_remote };
        const rst_events = [_]Event{ .recv_rst, .send_rst };

        for (active_states) |state| {
            for (rst_events) |event| {
                var t = newTable(100);
                defer t.deinit();

                const s = try t.openFromPeer(1, peer_send_window, our_recv_window);
                // Only `.open` / `.half_closed_remote` are reachable through
                // `apply` alone; seed the rest so every row of the table is covered
                // (`reserved_local` in particular is unreachable for a server that
                // never sends PUSH_PROMISE).
                s.state = state;

                try t.apply(1, event);
                try testing.expectEqual(State.closed, s.state);
            }
        }
    }

    test "local RST on a peer-registered idle stream closes it (we refuse the request)" {
        var t = newTable(100);
        defer t.deinit();

        // The driver registered the id from HEADERS but could not build a request
        // out of the header block; the peer already considers the stream open, so
        // RST_STREAM(PROTOCOL_ERROR) is the correct wire answer.
        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try t.apply(1, .send_rst);
        try testing.expectEqual(State.closed, t.get(1).?.state);
    }

    test "peer RST on an idle stream is a §6.4 connection error" {
        var t = newTable(100);
        defer t.deinit();

        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try testing.expectError(error.ProtocolError, t.apply(1, .recv_rst));
        // The stream is left untouched by the failed transition.
        try testing.expectEqual(State.idle, t.get(1).?.state);
    }

    test "DATA on a stream that was never opened is a protocol error" {
        var t = newTable(100);
        defer t.deinit();

        // (a) No entry at all.
        try testing.expectError(error.ProtocolError, t.apply(1, .recv_data));

        // (b) Registered (HEADERS arrived) but still idle: DATA reached us before
        // the HEADERS that would have opened it.
        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try testing.expectError(error.ProtocolError, t.apply(1, .recv_data));
        try testing.expectError(error.ProtocolError, t.apply(1, .recv_data_end));
        try testing.expectEqual(State.idle, t.get(1).?.state);
    }

    test "events on a closed stream report STREAM_CLOSED" {
        var t = newTable(100);
        defer t.deinit();

        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try t.apply(1, .recv_headers);
        try t.apply(1, .recv_rst);
        try testing.expectEqual(State.closed, t.get(1).?.state);

        try testing.expectError(error.StreamClosed, t.apply(1, .recv_data));
        try testing.expectError(error.StreamClosed, t.apply(1, .recv_data_end));
        try testing.expectError(error.StreamClosed, t.apply(1, .recv_headers));
        try testing.expectError(error.StreamClosed, t.apply(1, .recv_headers_end));
        try testing.expectError(error.StreamClosed, t.apply(1, .recv_rst));
        try testing.expectError(error.StreamClosed, t.apply(1, .send_headers));
        try testing.expectError(error.StreamClosed, t.apply(1, .send_data));
        try testing.expectError(error.StreamClosed, t.apply(1, .send_rst));
    }

    test "peer DATA after its END_STREAM is STREAM_CLOSED, not a connection error" {
        var t = newTable(100);
        defer t.deinit();

        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try t.apply(1, .recv_headers_end);
        try testing.expectEqual(State.half_closed_remote, t.get(1).?.state);

        // In-flight frames racing the END_STREAM must not tear the connection down.
        try testing.expectError(error.StreamClosed, t.apply(1, .recv_data));
        try testing.expectError(error.StreamClosed, t.apply(1, .recv_headers));
        // ...but we can still send the whole response.
        try t.apply(1, .send_headers);
        try t.apply(1, .send_data_end);
        try testing.expectEqual(State.closed, t.get(1).?.state);
    }

    test "stream ids: 0, even ids and 31-bit overflow are rejected" {
        var t = newTable(100);
        defer t.deinit();

        try testing.expectError(error.ProtocolError, t.openFromPeer(0, peer_send_window, our_recv_window));
        try testing.expectError(error.ProtocolError, t.openFromPeer(2, peer_send_window, our_recv_window));
        try testing.expectError(error.ProtocolError, t.openFromPeer(1 << 31, peer_send_window, our_recv_window));
        try testing.expectError(error.ProtocolError, t.openFromPeer((1 << 31) | 1, peer_send_window, our_recv_window));

        // A rejected id must not have burned a slot or moved the high-water mark.
        try testing.expectEqual(@as(u32, 0), t.highest_peer_stream_id);
        try testing.expectEqual(@as(u32, 0), t.activeCount());
    }

    test "windows must be inside [0, 2^31-1]" {
        var t = newTable(100);
        defer t.deinit();

        try testing.expectError(error.ProtocolError, t.openFromPeer(1, -1, our_recv_window));
        try testing.expectError(error.ProtocolError, t.openFromPeer(1, peer_send_window, constants.max_window_size + 1));
        _ = try t.openFromPeer(1, constants.max_window_size, constants.max_window_size);
    }

    test "stream ids are monotonic: a lower or repeated id is a protocol error" {
        var t = newTable(100);
        defer t.deinit();

        _ = try t.openFromPeer(3, peer_send_window, our_recv_window);
        try testing.expectError(error.ProtocolError, t.openFromPeer(1, peer_send_window, our_recv_window));
        try testing.expectError(error.ProtocolError, t.openFromPeer(3, peer_send_window, our_recv_window));
        _ = try t.openFromPeer(5, peer_send_window, our_recv_window);
        try testing.expectEqual(@as(u32, 5), t.highest_peer_stream_id);
    }

    test "a refused stream still burns its id (and every lower one)" {
        var t = newTable(1);
        defer t.deinit();

        _ = try t.openFromPeer(3, peer_send_window, our_recv_window);
        try testing.expectError(error.RefusedStream, t.openFromPeer(5, peer_send_window, our_recv_window));
        // The client may only retry on a *new* id: 5 and anything below it are gone.
        try testing.expectError(error.ProtocolError, t.openFromPeer(5, peer_send_window, our_recv_window));
        try testing.expectError(error.ProtocolError, t.openFromPeer(1, peer_send_window, our_recv_window));
    }

    test "max_concurrent refuses the overflow; remove frees the slot" {
        var t = newTable(2);
        defer t.deinit();

        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        _ = try t.openFromPeer(3, peer_send_window, our_recv_window);
        try testing.expectError(error.RefusedStream, t.openFromPeer(5, peer_send_window, our_recv_window));

        t.remove(1);
        _ = try t.openFromPeer(7, peer_send_window, our_recv_window);

        // remove is idempotent, for ids that exist and ids that never did.
        t.remove(1);
        t.remove(99);
    }

    test "a closed stream releases its concurrency slot before remove" {
        var t = newTable(2);
        defer t.deinit();

        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        _ = try t.openFromPeer(3, peer_send_window, our_recv_window);
        try testing.expectError(error.RefusedStream, t.openFromPeer(5, peer_send_window, our_recv_window));

        // Keep the entry in the table (the driver sweeps later) but close it.
        try t.apply(3, .recv_headers);
        try t.apply(3, .recv_rst);
        _ = try t.openFromPeer(7, peer_send_window, our_recv_window);
    }

    test "activeCount counts open/half-closed streams, not idle or closed ones" {
        var t = newTable(100);
        defer t.deinit();

        try testing.expectEqual(@as(u32, 0), t.activeCount());

        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try testing.expectEqual(@as(u32, 0), t.activeCount()); // idle

        try t.apply(1, .recv_headers);
        try testing.expectEqual(@as(u32, 1), t.activeCount());

        _ = try t.openFromPeer(3, peer_send_window, our_recv_window);
        try t.apply(3, .recv_headers_end);
        try testing.expectEqual(@as(u32, 2), t.activeCount());

        try t.apply(1, .recv_rst);
        try testing.expectEqual(@as(u32, 1), t.activeCount()); // closed, still in table

        t.remove(3);
        try testing.expectEqual(@as(u32, 0), t.activeCount());
    }

    test "PUSH_PROMISE is legal only on an idle stream" {
        var t = newTable(100);
        defer t.deinit();

        const s = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try t.apply(1, .recv_push_promise);
        try testing.expectEqual(State.reserved_remote, s.state);
        // A pushed stream opens when the peer's HEADERS arrives.
        try t.apply(1, .recv_headers);
        try testing.expectEqual(State.half_closed_local, s.state);

        var open_t = newTable(100);
        defer open_t.deinit();
        _ = try open_t.openFromPeer(1, peer_send_window, our_recv_window);
        try open_t.apply(1, .recv_headers);
        try testing.expectError(error.ProtocolError, open_t.apply(1, .recv_push_promise));

        var closed_t = newTable(100);
        defer closed_t.deinit();
        _ = try closed_t.openFromPeer(1, peer_send_window, our_recv_window);
        try closed_t.apply(1, .recv_headers);
        try closed_t.apply(1, .recv_rst);
        try testing.expectError(error.ProtocolError, closed_t.apply(1, .recv_push_promise));
    }

    test "a server cannot initiate a stream with HEADERS or DATA" {
        var t = newTable(100);
        defer t.deinit();

        _ = try t.openFromPeer(1, peer_send_window, our_recv_window);
        try testing.expectError(error.ProtocolError, t.apply(1, .send_headers));
        try testing.expectError(error.ProtocolError, t.apply(1, .send_headers_end));
        try testing.expectError(error.ProtocolError, t.apply(1, .send_data));
        try testing.expectError(error.ProtocolError, t.apply(1, .send_data_end));
        try testing.expectEqual(State.idle, t.get(1).?.state);
    }
};

comptime {
    _ = stream_tests;
}
