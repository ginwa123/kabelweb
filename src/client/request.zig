//! HTTP request description. Plain-data struct consumed by `Client.perform`.
//!
//! Owned slices: this module never borrows; the client copies what it
//! needs (libcurl handles are per-thread and don't share memory with
//! the caller across `perform()` returns).

const std = @import("std");

pub const Method = enum {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,

    /// Parse a method name (case-sensitive: `POST`, `POST`, `POST`).
    /// Returns null for unknown verbs so callers can decide whether to
    /// fail or fallback.
    pub fn parse(s: []const u8) ?Method {
        // ASCII-equality compare against the canonical names. We use a
        // short explicit ladder because std.ascii.eqlIgnoreCase isn't
        // standard — keeps the module's dep surface to just `std`.
        if (std.mem.eql(u8, s, "GET")) return .GET;
        if (std.mem.eql(u8, s, "PUT")) return .PUT;
        if (std.mem.eql(u8, s, "POST")) return .POST;
        if (std.mem.eql(u8, s, "PATCH")) return .PATCH;
        if (std.mem.eql(u8, s, "DELETE")) return .DELETE;
        return null;
    }

    pub fn asString(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .PATCH => "PATCH",
            .DELETE => "DELETE",
        };
    }
};

/// A single HTTP header (`Name: Value` line). Both fields are
/// caller-owned, non-null-terminated slices.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: Method,
    url: []const u8,
    /// Caller may pass `&.{}` for a header-less request.
    headers: []const Header = &.{},
    /// `null` for GET/DELETE; non-null for POST/PUT/PATCH.
    body: ?[]const u8 = null,
};
