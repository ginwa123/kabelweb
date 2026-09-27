//! HTTP/2 flow control (RFC 9113 §5.2, §6.9): per-stream and per-connection
//! windows, DATA accounting, and WINDOW_UPDATE coalescing.
//!
//! Pure arithmetic — no allocation, no I/O, no locks. One `Window` per direction
//! (a stream has a send window and a recv window; the connection has its own
//! pair), so the driver never has to guess which side a number belongs to.
//!
//! `size` is `i64`, not `u32`, for one specific reason: a SETTINGS frame that
//! lowers INITIAL_WINDOW_SIZE must shrink existing send windows *by the delta*,
//! and the result is allowed to go negative (RFC 9113 §6.9.2 — the sender then
//! waits for WINDOW_UPDATE frames before sending more). An unsigned window would
//! have to wrap, which is how this turns into a "sends 2 GiB by accident" bug.
//!
//! Recv-side lifecycle (the driver must run all three steps):
//!   1. DATA arrives  → `consume(n)`          (borrow credit, count it as unacked)
//!   2. coalesce      → `takeUpdate()`        (a WINDOW_UPDATE to put on the wire,
//!                                            once at least half the window is spent)
//!   3. credit it back→ `update(increment)`   (restore the local window to match
//!                                            what the peer now believes)
//! Step 3 is easy to forget and its symptom is a window that drains to zero after
//! ~2× the initial size of received data, then a connection that stalls.
//!
//! Send-side lifecycle: `grow(delta)` on a SETTINGS change, `update(increment)`
//! for every inbound WINDOW_UPDATE, and `allowed(want)` (via
//! `ConnectionWindows.payloadLimit`) to decide how many DATA bytes fit right now.

const constants = @import("constants.zig");

pub const Error = error{ ProtocolError, FlowControlError };

/// A single direction's window. `size` is what may still be sent (send side) or
/// what may still be received (recv side).
pub const Window = struct {
    size: i64,
    initial: i64,
    /// Bytes consumed on the receive side since the last WINDOW_UPDATE was emitted.
    unacked: i64 = 0,

    pub fn init(initial: i64) Window {
        // `initial` doubles as the coalescing baseline for `takeUpdate`, so it is
        // captured here and never mutated afterwards — a SETTINGS change moves
        // `size` (`grow`) but not the threshold we measure consumption against.
        return .{ .size = initial, .initial = initial, .unacked = 0 };
    }

    /// Receive-side accounting: the peer just sent `n` DATA bytes.
    /// Decrementing below zero -> error.FlowControlError.
    pub fn consume(self: *Window, n: u32) Error!void {
        const bytes: i64 = @as(i64, n);
        self.size -= bytes;
        if (self.size < 0) {
            // Terminal by design: an overrun is a connection error
            // (GOAWAY(FLOW_CONTROL_ERROR), §6.9.1), so there is nothing to roll
            // back for — rolling the window forward here would invite the caller
            // to keep using a connection that must be torn down.
            return error.FlowControlError;
        }
        self.unacked += bytes;
    }

    /// Receive side: remember consumed bytes and return the increment to emit via
    /// WINDOW_UPDATE once it reaches at least half the initial window, else null.
    /// Takes and resets `unacked` when it returns a value.
    pub fn takeUpdate(self: *Window) ?u32 {
        // A zero increment is itself a PROTOCOL_ERROR on the wire (§6.9.1), and a
        // window with nothing consumed has nothing to acknowledge — so the empty
        // case has to come first, before the threshold comparison (which is
        // trivially true when `initial` is small).
        if (self.unacked <= 0) return null;

        // Half a window is the coalescing point the plan adopts: emitting one
        // WINDOW_UPDATE per half-window keeps the peer's window open without a
        // frame per DATA (the same rule as common h2 stacks).
        const half = @divTrunc(self.initial, 2);
        if (self.unacked < half) return null;

        const increment = self.unacked;
        self.unacked = 0;
        // `unacked` only ever grows by consumed DATA, which `consume` has already
        // proven fits inside a window bounded by 2^31-1.
        return @intCast(increment);
    }

    /// Receive side: apply an incoming WINDOW_UPDATE increment (0 -> ProtocolError;
    /// pushing past 2^31-1 -> FlowControlError).
    pub fn update(self: *Window, increment: u32) Error!void {
        // A zero increment is a protocol error rather than a no-op: the sender
        // gains nothing by it, so it only ever means a broken peer.
        if (increment == 0) return error.ProtocolError;

        const next = self.size + @as(i64, increment);
        // RFC 9113 §6.9.1: no window may exceed 2^31-1. Note we *may* go from
        // negative (a SETTINGS debt) up through zero — only the ceiling is
        // enforced here, the floor is the caller's business.
        if (next > constants.max_window_size) return error.FlowControlError;
        self.size = next;
    }

    /// Send side: apply a SETTINGS_INITIAL_WINDOW_SIZE change (delta may be negative;
    /// going below zero keeps the value (the peer must send WINDOW_UPDATE) but must
    /// not panic).
    pub fn grow(self: *Window, delta: i64) void {
        // No clamping and no error return on purpose. §6.9.2 makes "the window went
        // negative" a normal, recoverable state, and the one illegal outcome (a
        // raise that pushes a window past 2^31-1) is caught by the SETTINGS layer
        // before it gets here — it has the connection-wide view needed to raise
        // FLOW_CONTROL_ERROR, which this signature deliberately cannot express.
        self.size += delta;
    }

    /// Send side: how many of `want` bytes may be sent right now.
    pub fn allowed(self: *Window, want: usize) usize {
        // A negative window is a debt: nothing may be sent until it comes back up.
        if (self.size <= 0) return 0;
        // Safe by construction: `size` is bounded by constants.max_window_size
        // (2^31-1), which fits in `usize` on every supported target.
        const window_bytes: usize = @intCast(self.size);
        return @min(want, window_bytes);
    }
};

/// Connection-level pair: one window for what we send, one for what we receive.
pub const ConnectionWindows = struct {
    send: Window,
    recv: Window,

    pub fn init(send_initial: i64, recv_initial: i64) ConnectionWindows {
        return .{ .send = Window.init(send_initial), .recv = Window.init(recv_initial) };
    }

    /// Largest DATA payload allowed right now: min(stream window, connection window, max_frame_size).
    pub fn payloadLimit(self: *const ConnectionWindows, stream: *const Window, max_frame_size: u32) usize {
        // Three independent limits, all mandatory: the stream window (the peer's
        // per-stream credit), the connection window (shared by every stream), and
        // MAX_FRAME_SIZE (§4.2 — a DATA frame may not exceed it however much
        // credit exists). Taking the minimum is what keeps a large response from
        // overshooting either window or the frame size.
        var limit = self.send.size;
        if (stream.size < limit) limit = stream.size;
        const frame_limit: i64 = @as(i64, max_frame_size);
        if (frame_limit < limit) limit = frame_limit;

        // A depleted (or negative) window means zero payload, never a wrapped
        // usize — that wrap is the classic "tried to send 18 quintillion bytes".
        if (limit <= 0) return 0;
        return @intCast(limit);
    }
};

// ============================================================================
// Tests — moved here from `flow_control_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = flow_control_tests; }` below pulls them into the run.
// ============================================================================

const flow_control_tests = struct {
    const std = @import("std");
    const fc = @import("flow_control.zig");
    const testing = std.testing;


    test "allowed() clamps the request to the remaining window" {
        var w = Window.init(65_535);

        try testing.expectEqual(@as(usize, 1000), w.allowed(1000));
        try testing.expectEqual(@as(usize, 65_535), w.allowed(70_000));
        // Asking for nothing is always allowed, even with credit in hand.
        try testing.expectEqual(@as(usize, 0), w.allowed(0));

        _ = try w.consume(65_535);
        try testing.expectEqual(@as(i64, 0), w.size);
        // A drained window allows zero payload (the DATA frame would be empty; the
        // driver simply waits for a WINDOW_UPDATE).
        try testing.expectEqual(@as(usize, 0), w.allowed(1000));
    }

    test "consume() decrements the window and counts the bytes as unacked" {
        var w = Window.init(65_535);

        try w.consume(100);
        try testing.expectEqual(@as(i64, 65_435), w.size);
        try testing.expectEqual(@as(i64, 100), w.unacked);

        // Zero-length DATA frames exist and consume nothing.
        try w.consume(0);
        try testing.expectEqual(@as(i64, 65_435), w.size);
        try testing.expectEqual(@as(i64, 100), w.unacked);
    }

    test "consume() below zero is a flow-control error" {
        var w = Window.init(65_535);
        try w.consume(100);
        // 65535 more bytes than the peer was allowed: it overshot by exactly 100.
        try testing.expectError(error.FlowControlError, w.consume(65_535));

        // The exact-drain boundary is legal; one byte past it is not.
        var exact = Window.init(65_535);
        try exact.consume(65_535);
        try testing.expectEqual(@as(i64, 0), exact.size);
        try testing.expectError(error.FlowControlError, exact.consume(1));
    }

    test "update() rejects a zero increment and grows the window otherwise" {
        var w = Window.init(65_535);

        try testing.expectError(error.ProtocolError, w.update(0));
        try testing.expectEqual(@as(i64, 65_535), w.size);

        try w.update(1000);
        try testing.expectEqual(@as(i64, 66_535), w.size);

        // The ceiling is exclusive for errors and inclusive for legal values.
        var at_max = Window.init(constants.max_window_size - 1);
        try at_max.update(1);
        try testing.expectEqual(constants.max_window_size, at_max.size);
        try testing.expectError(error.FlowControlError, at_max.update(1));
        try testing.expectEqual(constants.max_window_size, at_max.size);
    }

    test "update() refuses an increment that would push a window past 2^31-1" {
        var w = Window.init(constants.max_window_size);
        try testing.expectError(error.FlowControlError, w.update(0x8000_0000));

        // Same for a window that is nowhere near the ceiling: the sum is what counts.
        var small = Window.init(65_535);
        try testing.expectError(error.FlowControlError, small.update(0x8000_0000));
        try testing.expectEqual(@as(i64, 65_535), small.size);
    }

    test "takeUpdate() coalesces until half the initial window, then resets" {
        var w = Window.init(65_535);
        // Nothing consumed yet — a WINDOW_UPDATE would carry zero, which is itself a
        // protocol error on the wire.
        try testing.expectEqual(@as(?u32, null), w.takeUpdate());

        try w.consume(32_766);
        try testing.expectEqual(@as(?u32, null), w.takeUpdate()); // one byte short of half

        try w.consume(1);
        try testing.expectEqual(@as(?u32, 32_767), w.takeUpdate()); // exact accumulated amount
        // The counter is reset by the emission above.
        try testing.expectEqual(@as(?u32, null), w.takeUpdate());

        try w.consume(10);
        try testing.expectEqual(@as(?u32, null), w.takeUpdate());
        try w.consume(32_757);
        try testing.expectEqual(@as(?u32, 32_767), w.takeUpdate());
        try testing.expectEqual(@as(i64, 0), w.unacked);
    }

    test "takeUpdate() never emits a zero increment for a zero-sized window" {
        var w = Window.init(0);
        try testing.expectEqual(@as(?u32, null), w.takeUpdate());
        // A window with no credit cannot legally receive DATA at all.
        try testing.expectError(error.FlowControlError, w.consume(1));
    }

    test "the recv-side lifecycle keeps the window from draining" {
        var w = Window.init(constants.our_initial_window_size); // 1 MiB

        // Four half-window worth of DATA arrives; each one emits exactly one
        // WINDOW_UPDATE, and feeding that increment back keeps the window whole.
        var round: usize = 0;
        while (round < 4) : (round += 1) {
            const chunk: u32 = @intCast(@divTrunc(constants.our_initial_window_size, 2));
            try w.consume(chunk);

            const increment = w.takeUpdate().?;
            try testing.expectEqual(chunk, increment);
            try w.update(increment);

            try testing.expectEqual(@as(i64, constants.our_initial_window_size), w.size);
            try testing.expectEqual(@as(usize, 16_384), w.allowed(16_384));
        }
    }

    test "grow() accepts a negative delta and leaves the window in debt" {
        var w = Window.init(65_535);
        w.grow(-100_000);
        try testing.expectEqual(@as(i64, -34_465), w.size);
        // A debt blocks every byte until WINDOW_UPDATE arrives — no wrap-around, no
        // panic, just an empty payload.
        try testing.expectEqual(@as(usize, 0), w.allowed(1000));
        try testing.expectEqual(@as(usize, 0), w.allowed(0));

        // A later WINDOW_UPDATE (this window is the send side) restores it.
        try w.update(34_565);
        try testing.expectEqual(@as(i64, 100), w.size);
        try testing.expectEqual(@as(usize, 100), w.allowed(1000));
        try testing.expectEqual(@as(usize, 50), w.allowed(50));
        try testing.expectEqual(@as(usize, 100), w.allowed(70_000));
    }

    test "grow() accepts a positive delta (SETTINGS raises the initial window)" {
        var w = Window.init(constants.default_initial_window_size);
        w.grow(@as(i64, constants.our_initial_window_size) - @as(i64, constants.default_initial_window_size));
        try testing.expectEqual(@as(i64, constants.our_initial_window_size), w.size);
        try testing.expectEqual(@as(usize, 16_384), w.allowed(16_384));
    }

    test "ConnectionWindows.init() seeds both directions independently" {
        const cw = ConnectionWindows.init(65_535, 1_048_576);
        try testing.expectEqual(@as(i64, 65_535), cw.send.size);
        try testing.expectEqual(@as(i64, 65_535), cw.send.initial);
        try testing.expectEqual(@as(i64, 1_048_576), cw.recv.size);
        try testing.expectEqual(@as(i64, 1_048_576), cw.recv.initial);
        // The two directions are independent objects, not views of one number.
        var cw2 = ConnectionWindows.init(65_535, 1_048_576);
        _ = try cw2.send.consume(65_535);
        try testing.expectEqual(@as(i64, 0), cw2.send.size);
        try testing.expectEqual(@as(i64, 1_048_576), cw2.recv.size);
    }

    test "payloadLimit() picks the minimum of the stream window, connection window and MAX_FRAME_SIZE" {
        // (1) MAX_FRAME_SIZE binds: both windows are wide open, so §4.2 caps us.
        {
            const cw = ConnectionWindows.init(1 << 20, 1 << 20);
            const sw = Window.init(1 << 20);
            try testing.expectEqual(@as(usize, 16_384), cw.payloadLimit(&sw, constants.our_max_frame_size));
        }
        // (2) The stream window binds: it is smaller than a frame.
        {
            const cw = ConnectionWindows.init(1 << 20, 1 << 20);
            const sw = Window.init(1_000);
            try testing.expectEqual(@as(usize, 1_000), cw.payloadLimit(&sw, constants.our_max_frame_size));
        }
        // (3) The connection window binds: smaller than both the stream window and a frame.
        {
            const cw = ConnectionWindows.init(500, 1 << 20);
            const sw = Window.init(1 << 20);
            try testing.expectEqual(@as(usize, 500), cw.payloadLimit(&sw, constants.our_max_frame_size));
        }
        // (4) A debt (SETTINGS shrink) means zero payload, never a wrapped usize.
        {
            const cw = ConnectionWindows.init(1 << 20, 1 << 20);
            var sw = Window.init(constants.default_initial_window_size);
            sw.grow(-70_000);
            try testing.expect(sw.size < 0);
            try testing.expectEqual(@as(usize, 0), cw.payloadLimit(&sw, constants.our_max_frame_size));
        }
        // (5) Same for a drained *connection* window while the stream still has credit.
        {
            var cw = ConnectionWindows.init(100, 1 << 20);
            _ = try cw.send.consume(100);
            const sw = Window.init(1 << 20);
            try testing.expectEqual(@as(usize, 0), cw.payloadLimit(&sw, constants.our_max_frame_size));
        }
        // (6) A tie is still that value (equal stream window and frame size).
        {
            const cw = ConnectionWindows.init(1 << 20, 1 << 20);
            const sw = Window.init(16_384);
            try testing.expectEqual(@as(usize, 16_384), cw.payloadLimit(&sw, 16_384));
        }
    }
};

comptime {
    _ = flow_control_tests;
}
