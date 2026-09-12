//! HTTP response — body + headers + status.
//!
//! All fields are owned by the `Response`; `deinit` frees everything
//! that was heap-allocated by `Client.perform()`. The caller MUST
//! call `deinit` exactly once on success OR error path.

const std = @import("std");
const Header = @import("request.zig").Header;

pub const Response = struct {
    status_code: u16,
    body: []u8,
    headers: []Header,
    /// Final URL after redirects (empty if libcurl didn't record one).
    url_effective: []const u8,
    /// Wallclock duration of the transfer, in milliseconds.
    total_time_ms: u64,
    /// Resolved IP of the last connection, if any.
    primary_ip: []const u8,

    /// Free all heap-allocated fields. Safe to call ONCE per Response.
    /// After calling, the Response is left in zero-state.
    ///
    /// Accepts `*const` so callers can use `const resp = ...; defer resp.deinit(...)`
    /// without needing `@constCast`.
    pub fn deinit(self: *const Response, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        for (self.headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(self.headers);
        allocator.free(self.url_effective);
        allocator.free(self.primary_ip);
    }
};
