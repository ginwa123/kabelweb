const std = @import("std");
const stream = @import("stream.zig");
const constants = @import("constants.zig");
const testing = std.testing;

const State = stream.State;
const Event = stream.Event;
const Table = stream.Table;

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
