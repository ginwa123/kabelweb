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

test {
    _ = @import("flow_control_test.zig");
}
