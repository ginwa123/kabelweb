//! Cron expression parser and `nextFireAfter` calculator.
//!
//! Supports standard 5-field cron expressions:
//!
//!     ┌───────────── minute (0 - 59)
//!     │ ┌───────────── hour (0 - 23)
//!     │ │ ┌───────────── day of month (1 - 31)
//!     │ │ │ ┌───────────── month (1 - 12)
//!     │ │ │ │ ┌───────────── day of week (0 - 6, Sunday = 0)
//!     │ │ │ │ │
//!     * * * * *
//!
//! Each field supports:
//!   - `*`        every value in range
//!   - `N`        exactly N
//!   - `N-M`      range (inclusive)
//!   - `*/N`      step (every N units, starting at min)
//!   - `N,M,K`    list (any of N, M, K)
//!
//! Times are UTC. Minute-precision only (no seconds field).
//!
//! This is intentionally minimal — for `@hourly` aliases, 6-field cron, or
//! timezone-aware arithmetic, add a richer parser behind the same
//! `CronExpression.parse` / `CronExpression.nextFireAfter` API.

const std = @import("std");
const epoch = std.time.epoch;

pub const CronError = error{
    InvalidExpression,
    InvalidField,
};

/// Bitfield used to represent which values a single cron field matches.
/// The bits are indexed by the field's natural value (e.g. minute `15` is
/// bit 15). For dom/month/dow, the bits are indexed starting at the
/// field's min (1 for dom/month, 0 for dow) so a `dom` of `1` is bit 1.
pub const BitField = struct {
    bits: u64,

    pub fn empty() BitField {
        return .{ .bits = 0 };
    }

    pub fn set(self: *BitField, value: u8) void {
        self.bits |= @as(u64, 1) << @intCast(value);
    }

    pub fn any(self: BitField) bool {
        return self.bits != 0;
    }

    pub fn matches(self: BitField, value: u8) bool {
        if (value >= 64) return false;
        return (self.bits >> @intCast(value)) & 1 == 1;
    }
};

/// Standard 5-field cron expression. All fields are stored as bitfields so
/// `matches` is O(1) and `nextFireAfter` can iterate minute-by-minute
/// without re-parsing.
pub const CronExpression = struct {
    minute: BitField, // 60 bits  (0..59)
    hour: BitField,   // 24 bits  (0..23)
    dom: BitField,    // 32 bits  (1..31)
    month: BitField,  // 12 bits  (1..12)
    dow: BitField,    //  7 bits  (0..6,  Sunday = 0)

    /// Parse a 5-field cron expression. Whitespace around fields is
    /// trimmed; internal whitespace is the field separator.
    pub fn parse(input: []const u8) CronError!CronExpression {
        var fields: [5][]const u8 = undefined;
        var field_count: usize = 0;
        var iter = std.mem.splitScalar(u8, input, ' ');
        while (iter.next()) |raw| {
            const trimmed = std.mem.trim(u8, raw, &std.ascii.whitespace);
            if (trimmed.len == 0) continue;
            if (field_count >= 5) return error.InvalidExpression;
            fields[field_count] = trimmed;
            field_count += 1;
        }
        if (field_count != 5) return error.InvalidExpression;

        return .{
            .minute = try parseField(fields[0], 0, 59),
            .hour = try parseField(fields[1], 0, 23),
            .dom = try parseField(fields[2], 1, 31),
            .month = try parseField(fields[3], 1, 12),
            .dow = try parseField(fields[4], 0, 6),
        };
    }

    /// Compute the next Unix-seconds timestamp `>= after_unix` (UTC) that
    /// matches this expression, OR the exact `after_unix` itself if it
    /// matches. Returns `null` if no match is found within 4 years
    /// (defensive upper bound for impossible expressions like Feb 30).
    pub fn nextFireAfter(self: CronExpression, after_unix: i64) ?i64 {
        // 4 years = ~2,103,840 minutes. We step minute-by-minute from
        // `after_unix`. The loop is bounded by this constant so a bug
        // in the matching logic cannot spin forever.
        const max_minutes: i64 = 4 * 366 * 24 * 60;

        // Pre-1970 dates aren't supported by std.time.epoch (which is
        // u64-only). Cron use cases won't hit that range, but be
        // explicit: return null for negative timestamps.
        if (after_unix < 0) return null;

        // Align `after_unix` UP to the next minute boundary so the
        // returned match is always `>= after_unix`. If `after_unix` is
        // already minute-aligned, the candidate is exactly `after_unix`
        // and we may match it (this is what test 294 verifies).
        var candidate: i64 = @divFloor(after_unix + 59, 60) * 60;
        var steps: i64 = 0;
        while (steps <= max_minutes) : (steps += 1) {
            if (matchesUnix(self, candidate)) return candidate;
            candidate += 60;
        }
        return null;
    }
};

/// Calendar fields extracted from a Unix timestamp. All UTC.
pub const CronTimestamp = struct {
    minute: u8,
    hour: u8,
    dom: u8,
    month: u8,
    dow: u8, // 0..6, Sunday = 0

    pub fn fromUnix(secs: i64) CronTimestamp {
        return unixToTimestamp(secs);
    }
};

/// `true` iff `ts` matches `expr`.
fn matchesUnix(expr: CronExpression, ts: i64) bool {
    const t = unixToTimestamp(ts);
    if (!expr.minute.matches(t.minute)) return false;
    if (!expr.hour.matches(t.hour)) return false;
    if (!expr.dom.matches(t.dom)) return false;
    if (!expr.month.matches(t.month)) return false;
    if (!expr.dow.matches(t.dow)) return false;
    return true;
}

/// Convert Unix seconds → `{minute, hour, dom, month, dow}` in UTC.
/// Uses `std.time.epoch` for calendar arithmetic (leap years, etc.) and
/// a small formula for day-of-week.
fn unixToTimestamp(secs: i64) CronTimestamp {
    const sec_u: u64 = std.math.cast(u64, secs) orelse {
        // Pre-1970 — return a zero value that won't match a real cron
        // expression. `nextFireAfter` already filters this case.
        return .{ .minute = 0, .hour = 0, .dom = 0, .month = 0, .dow = 0 };
    };

    const es = epoch.EpochSeconds{ .secs = sec_u };
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();

    return .{
        .minute = ds.getMinutesIntoHour(),
        .hour = ds.getHoursIntoDay(),
        // `MonthAndDay.day_index` is 0-based; cron dom is 1-based.
        .dom = @intCast(md.day_index + 1),
        // `Month` enum is already 1-based (jan = 1, dec = 12).
        .month = @intFromEnum(md.month),
        .dow = dowFromUnix(secs),
    };
}

/// Day-of-week from a Unix timestamp. Returns 0..6 with Sunday = 0.
/// Formula: 1970-01-01 was a Thursday. Adding N days shifts the dow by
/// N, so `(4 + N) mod 7` gives the dow where Sunday = 0.
fn dowFromUnix(secs: i64) u8 {
    const days: i64 = @divFloor(secs, std.time.s_per_day);
    const raw: i64 = @mod(days + 4, 7);
    return @intCast(if (raw < 0) raw + 7 else raw);
}

/// Parse a single cron field into a BitField. Supports `*`, `N`, `N-M`,
/// `*/N`, and `N,M,K`.
fn parseField(field: []const u8, min: u8, max: u8) CronError!BitField {
    var bf = BitField.empty();

    // Split on commas into sub-tokens.
    var sub_iter = std.mem.splitScalar(u8, field, ',');
    while (sub_iter.next()) |sub_raw| {
        const sub = std.mem.trim(u8, sub_raw, &std.ascii.whitespace);
        if (sub.len == 0) return error.InvalidField;

        // Wildcard with step: "*/N"
        if (std.mem.startsWith(u8, sub, "*/")) {
            const step_str = sub[2..];
            const step = std.fmt.parseInt(u8, step_str, 10) catch return error.InvalidField;
            if (step == 0) return error.InvalidField;
            var v: u8 = min;
            while (v <= max) : (v += step) bf.set(v);
            continue;
        }

        // Plain wildcard: "*"
        if (std.mem.eql(u8, sub, "*")) {
            var v: u8 = min;
            while (v <= max) : (v += 1) bf.set(v);
            continue;
        }

        // Range: "N-M"
        if (std.mem.indexOf(u8, sub, "-")) |dash_idx| {
            const lo_str = sub[0..dash_idx];
            const hi_str = sub[dash_idx + 1 ..];
            const lo = std.fmt.parseInt(u8, lo_str, 10) catch return error.InvalidField;
            const hi = std.fmt.parseInt(u8, hi_str, 10) catch return error.InvalidField;
            if (lo > hi) return error.InvalidField;
            if (lo < min or hi > max) return error.InvalidField;
            var v: u8 = lo;
            while (v <= hi) : (v += 1) bf.set(v);
            continue;
        }

        // Single value: "N"
        const v = std.fmt.parseInt(u8, sub, 10) catch return error.InvalidField;
        if (v < min or v > max) return error.InvalidField;
        bf.set(v);
    }

    if (!bf.any()) return error.InvalidField;
    return bf;
}