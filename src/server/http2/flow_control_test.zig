const std = @import("std");
const fc = @import("flow_control.zig");
const constants = @import("constants.zig");
const testing = std.testing;

const Window = fc.Window;
const ConnectionWindows = fc.ConnectionWindows;

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
