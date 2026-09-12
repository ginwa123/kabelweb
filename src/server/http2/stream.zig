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

test {
    _ = @import("stream_test.zig");
}
