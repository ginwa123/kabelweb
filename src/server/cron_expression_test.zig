//! Unit tests for `cron_expression.zig`.
//!
//! These tests cover the parser and `nextFireAfter` calculator. No threading,
//! no I/O — just pure functions over strings and Unix timestamps.

const std = @import("std");
const cron_expr = @import("cron_expression.zig");
const CronExpression = cron_expr.CronExpression;
const CronError = cron_expr.CronError;

const testing = std.testing;

// ============================================================================
// Parser tests — `*`
// ============================================================================

test "parse: \"* * * * *\" matches every minute of every hour" {
    const expr = try CronExpression.parse("* * * * *");
    // Every value 0..max in every field should match.
    try testing.expect(expr.minute.any());
    try testing.expect(expr.hour.any());
    try testing.expect(expr.dom.any());
    try testing.expect(expr.month.any());
    try testing.expect(expr.dow.any());

    // Spot-check a few values
    try testing.expect(expr.minute.matches(0));
    try testing.expect(expr.minute.matches(59));
    try testing.expect(expr.hour.matches(0));
    try testing.expect(expr.hour.matches(23));
    try testing.expect(expr.dom.matches(1));
    try testing.expect(expr.dom.matches(31));
    try testing.expect(expr.month.matches(1));
    try testing.expect(expr.month.matches(12));
    try testing.expect(expr.dow.matches(0));
    try testing.expect(expr.dow.matches(6));
}

test "parse: \"0 9 * * 1-5\" matches weekdays at 9am" {
    const expr = try CronExpression.parse("0 9 * * 1-5");
    try testing.expect(expr.minute.matches(0));
    try testing.expect(!expr.minute.matches(1));
    try testing.expect(expr.hour.matches(9));
    try testing.expect(!expr.hour.matches(8));
    try testing.expect(expr.dom.any());
    try testing.expect(expr.month.any());
    // Mon..Fri
    try testing.expect(expr.dow.matches(1));
    try testing.expect(expr.dow.matches(5));
    try testing.expect(!expr.dow.matches(0)); // Sunday excluded
    try testing.expect(!expr.dow.matches(6)); // Saturday excluded
}

test "parse: \"*/15 * * * *\" matches minutes 0,15,30,45" {
    const expr = try CronExpression.parse("*/15 * * * *");
    try testing.expect(expr.minute.matches(0));
    try testing.expect(expr.minute.matches(15));
    try testing.expect(expr.minute.matches(30));
    try testing.expect(expr.minute.matches(45));
    try testing.expect(!expr.minute.matches(14));
    try testing.expect(!expr.minute.matches(16));
    try testing.expect(!expr.minute.matches(59));
    try testing.expect(expr.hour.any());
}

test "parse: \"0,30 * * * *\" matches minutes 0 and 30 only" {
    const expr = try CronExpression.parse("0,30 * * * *");
    try testing.expect(expr.minute.matches(0));
    try testing.expect(expr.minute.matches(30));
    try testing.expect(!expr.minute.matches(1));
    try testing.expect(!expr.minute.matches(15));
    try testing.expect(!expr.minute.matches(59));
}

test "parse: \"5 4 * * 7\" returns InvalidField (dow 7 out of range)" {
    try testing.expectError(error.InvalidField, CronExpression.parse("5 4 * * 7"));
}

test "parse: \"* * *\" (3 fields) returns InvalidExpression" {
    try testing.expectError(error.InvalidExpression, CronExpression.parse("* * *"));
}

test "parse: \"60 * * * *\" returns InvalidField (minute 60 out of range)" {
    try testing.expectError(error.InvalidField, CronExpression.parse("60 * * * *"));
}

test "parse: empty string returns InvalidExpression" {
    try testing.expectError(error.InvalidExpression, CronExpression.parse(""));
}

test "parse: \"* 24 * * *\" returns InvalidField (hour 24 out of range)" {
    try testing.expectError(error.InvalidField, CronExpression.parse("* 24 * * *"));
}

test "parse: \"0 0 32 * *\" returns InvalidField (dom 32 out of range)" {
    try testing.expectError(error.InvalidField, CronExpression.parse("0 0 32 * *"));
}

test "parse: \"0 0 * 13 *\" returns InvalidField (month 13 out of range)" {
    try testing.expectError(error.InvalidField, CronExpression.parse("0 0 * 13 *"));
}

test "parse: leading/trailing whitespace is trimmed" {
    const expr = try CronExpression.parse("   * * * * *   ");
    try testing.expect(expr.minute.any());
    try testing.expect(expr.hour.any());
}

// ============================================================================
// nextFireAfter tests
// ============================================================================

// Reference timestamps (UTC). Compute via:
//   date -u -d "2025-01-01 00:00:00" +%s  → 1735689600
//   date -u -d "2025-01-04 00:00:00" +%s  → 1735948800 (Saturday)
//   date -u -d "2025-01-06 00:00:00" +%s  → 1736121600 (Monday)
//   date -u -d "2025-01-06 09:00:00" +%s  → 1736153400 (Monday 9am)
//   date -u -d "2025-01-01 00:14:30" +%s  → 1735689270
//   date -u -d "2025-01-01 00:15:00" +%s  → 1735689300
//   date -u -d "2025-12-31 23:59:59" +%s  → 1767225599
//   date -u -d "2026-01-01 00:00:00" +%s  → 1767225600
//   date -u -d "2025-01-01 00:00:01" +%s  → 1735689601
//   date -u -d "2025-01-02 00:00:00" +%s  → 1735776000

test "nextFireAfter: \"0 0 * * *\" fires on the exact second when from == boundary" {
    const expr = try CronExpression.parse("0 0 * * *");
    const from: i64 = 1735689600; // 2025-01-01T00:00:00Z
    const next = try testing.expectEqual(@as(i64, 1735689600), expr.nextFireAfter(from));
    _ = next;
}

test "nextFireAfter: \"0 0 * * *\" after midnight+1s fires next day midnight" {
    const expr = try CronExpression.parse("0 0 * * *");
    const from: i64 = 1735689601; // 2025-01-01T00:00:01Z
    try testing.expectEqual(@as(i64, 1735776000), expr.nextFireAfter(from)); // 2025-01-02T00:00:00Z
}

test "nextFireAfter: \"*/15 * * * *\" from 14:30 fires 15:00" {
    const expr = try CronExpression.parse("*/15 * * * *");
    const from: i64 = 1735690470; // 2025-01-01T00:14:30Z
    try testing.expectEqual(@as(i64, 1735690500), expr.nextFireAfter(from)); // 2025-01-01T00:15:00Z
}

test "nextFireAfter: \"0 9 * * 1-5\" from Saturday fires next Monday 9am" {
    const expr = try CronExpression.parse("0 9 * * 1-5");
    const from: i64 = 1735948800; // 2025-01-04T00:00:00Z (Saturday)
    try testing.expectEqual(@as(i64, 1736154000), expr.nextFireAfter(from)); // 2025-01-06T09:00:00Z (Monday)
}

test "nextFireAfter: \"0 0 1 1 *\" from 2025-12-31T23:59:59Z fires 2026-01-01T00:00:00Z" {
    const expr = try CronExpression.parse("0 0 1 1 *");
    const from: i64 = 1767225599; // 2025-12-31T23:59:59Z
    try testing.expectEqual(@as(i64, 1767225600), expr.nextFireAfter(from)); // 2026-01-01T00:00:00Z
}

test "nextFireAfter: \"* * * * *\" from 1s past minute boundary fires next minute" {
    const expr = try CronExpression.parse("* * * * *");
    const from: i64 = 1735689601; // 2025-01-01T00:00:01Z
    try testing.expectEqual(@as(i64, 1735689660), expr.nextFireAfter(from)); // 2025-01-01T00:01:00Z
}

test "nextFireAfter: \"0 0 31 2 *\" returns null (Feb 31 never exists within 4y)" {
    // Feb 31 is impossible in every year. From 2025-01-01, no Feb 31
    // exists within 4 years → returns null as a safety bound.
    const expr = try CronExpression.parse("0 0 31 2 *");
    const from: i64 = 1735689600; // 2025-01-01T00:00:00Z
    try testing.expectEqual(@as(?i64, null), expr.nextFireAfter(from));
}