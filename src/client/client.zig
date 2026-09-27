//! The high-level HTTP client. Buffers entire response in-memory;
//! no streaming. Thread-unsafe by design — instantiate one
//! `Client` per worker (libcurl's per-handle state is per-thread).

const std = @import("std");
const builtin = @import("builtin");
const curl = @import("curl.zig");
const Method = @import("request.zig").Method;
const Header = @import("request.zig").Header;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Options = @import("options.zig").Options;

/// All errors this module surfaces. CAREFUL: keep this in sync with
/// `mapCurlCode` — every branch should produce a unique name so
/// `expectError(Error.ConnectionRefused, ...)` works in tests.
pub const Error = error{
    InitFailed,
    InvalidUrl,
    ConnectionRefused,
    ConnectionTimeout,
    OperationTimedOut,
    TlsError,
    DnsError,
    ProtocolError,
    TooManyRedirects,
    UnsupportedProtocol,
    OutOfMemory,
    /// Server spoke HTTP but the transfer failed at the HTTP layer
    /// (CURLE_HTTP_RETURNED_ERROR, WEIRD_SERVER_REPLY, GOT_NOTHING,
    /// RANGE/POST errors, REMOTE_ACCESS_DENIED).
    HttpError,
    /// Local write callback aborted the transfer (CURLE_WRITE_ERROR).
    /// Usually means our own header/body append failed to allocate.
    WriteError,
    /// Local read callback failed (CURLE_READ_ERROR).
    ReadError,
    /// Failed sending data to the server (CURLE_SEND_ERROR,
    /// SEND_FAIL_REWIND).
    SendError,
    /// Failed receiving data from the server (CURLE_RECV_ERROR) —
    /// the classic "connection reset / server hung up mid-stream".
    RecvError,
    /// Transfer completed but fewer bytes arrived than expected
    /// (CURLE_PARTIAL_FILE).
    PartialFile,
    /// Catch-all for CURLcodes we haven't classified yet.
    /// New libcurl versions add codes; we don't want a code bump to
    /// crash the process.
    UnknownCurl,
};

/// Process-global flag for `curl_global_init`. Must be initialised
/// before any `curl_easy_init` call. Lazy because unit tests that
/// never perform a request should still be able to construct a Client.
/// Guarded by an `std.atomic.Value(bool)` because nalar's HTTP
/// callers are single-threaded today, but the atomic costs nothing
/// to add.
var global_inited = std.atomic.Value(bool).init(false);

/// Buffer used as the libcurl error message sink (via CURLOPT_ERRORBUFFER).
/// libcurl writes a NUL-terminated human message here on failure.
/// Stack-allocated per-perform — kept inside one function for RAII-like
/// cleanup on the error path.
const ERRBUF_LEN: usize = 256;

pub const Client = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Client {
        if (!global_inited.load(.acquire)) {
            // CURL_GLOBAL_DEFAULT expands via macro to all known init
            // flags. `curl_global_init` returns CURLcode (CURLE_OK on
            // success). On failure the first perform() returns InitFailed.
            if (curl.init(curl.C.CURL_GLOBAL_DEFAULT) == curl.C.CURLE_OK) {
                global_inited.store(true, .release);
            }
        }
        return .{ .allocator = allocator };
    }

    pub fn deinit(_: *Client) void {
        // No per-handle resources (the Client struct is stateless;
        // every perform() builds and tears down its own CURL*).
        // curl_global_cleanup is left to process exit; matches the
        // existing HttpClient.zig posture.
    }

    /// Open a streaming HTTP request. The transfer runs in a worker
    /// thread (spawned by the stream module); chunks arrive via
    /// `ResponseStream.next`. The caller MUST call `deinit` on the
    /// returned stream exactly once. Implemented in `stream.zig`
    /// to keep this file focused on the buffered path.
    pub fn openStream(
        self: *Client,
        io: std.Io,
        req: @import("request.zig").Request,
        options: @import("options.zig").Options,
    ) Error!@import("stream.zig").ResponseStream {
        return @import("stream.zig").openStream(self, io, req, options);
    }

    /// Make a HTTP call. Always buffers the entire response.
    /// Caller owns the returned `Response` and MUST call `.deinit()`.
    /// Memory bounds (from `Options`): URL capped at `max_url_bytes`,
    /// single header line at 8 KiB, total headers at `max_headers` /
    /// `max_header_bytes`, body at `max_body_bytes`. Exceeding a cap
    /// aborts with `Error.OutOfMemory` (write/header callback returns 0).
    pub fn perform(self: *Client, req: Request, options: Options) Error!Response {
        if (req.url.len > options.max_url_bytes) return Error.OutOfMemory;
        for (req.headers) |h| {
            if (h.name.len + 2 + h.value.len > 8 * 1024) return Error.OutOfMemory;
        }
        const handle = curl.easy_init() orelse return Error.InitFailed;
        // Every code path that exits must call easy_cleanup. The `defer`
        // runs on both the success path (right before returning) and the
        // error path (right before propagating the error). Verified by
        // static-contract test `client.zig: curl_easy_cleanup always paired
        // with curl_easy_init (no FD leak class)`.
        defer curl.easy_cleanup(handle);

        // Per-handle error buffer (filled by libcurl on failure).
        // CURLOPT_ERRORBUFFER takes a `char *` (pointer to a writable
        // buffer), NOT a long — the prior `@intCast(@intFromPtr(&errbuf))`
        // cast silently works on Linux (c_long = 64-bit) and panics on
        // Windows (c_long = 32-bit; the pointer's high bits overflow the
        // 32-bit destination). `setoptPtr` is the right helper — same
        // signature as `setoptPtr` for URL / CUSTOMREQUEST / POSTFIELDS
        // below, all of which are *const u8 buffers that libcurl copies
        // or reads into.
        var errbuf: [ERRBUF_LEN]u8 = [_]u8{0} ** ERRBUF_LEN;
        _ = setoptPtr(handle, curl.OPT.ERRORBUFFER, &errbuf);

        // URL — must outlive curl_easy_perform. We allocate a sentinel-
        // terminated copy because libcurl requires NUL-terminated strings
        // AND the caller-supplied slice may not have capacity for the
        // sentinel. Freed at the end of this scope via the url_z_owner
        // helper below.
        const url_buf = try self.allocator.allocSentinel(u8, req.url.len, 0);
        defer self.allocator.free(url_buf);
        @memcpy(url_buf, req.url);
        const url_z: [:0]const u8 = url_buf;
        _ = setoptPtr(handle, curl.OPT.URL, url_z.ptr);

        // Method via CUSTOMREQUEST. Works for every verb including the
        // non-POST-with-body cases. Method strings are tiny (≤6 chars) so
        // we use a stack buffer.
        var method_z: [16:0]u8 = undefined;
        const mlen = @min(req.method.asString().len, method_z.len - 1);
        @memcpy(method_z[0..mlen], req.method.asString()[0..mlen]);
        method_z[mlen] = 0;
        const method_slice: [:0]const u8 = method_z[0..mlen :0];
        _ = setoptPtr(handle, curl.OPT.CUSTOMREQUEST, method_slice.ptr);

        // ----- Headers: build a slist chain.
        // Each header becomes "Name: Value\0" in a stack buffer, then is
        // appended to the slist. We own the slist; cleanup via slist_free_all.
        var slist: ?*curl.C.struct_curl_slist = null;
        defer if (slist) |s| curl.slist_free_all(s);

        // Decide on User-Agent: caller override > caller-provided header > module default.
        var ua_buf: [256]u8 = undefined;
        var ua_to_send: []const u8 = "";
        if (options.user_agent.len > 0) {
            ua_to_send = options.user_agent;
        } else {
            var has_in_headers = false;
            for (req.headers) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "user-agent")) {
                    has_in_headers = true;
                    break;
                }
            }
            if (!has_in_headers) ua_to_send = "custom_http_client/0.1.0";
        }
        if (ua_to_send.len > 0 and ua_to_send.len < ua_buf.len) {
            @memcpy(ua_buf[0..ua_to_send.len], ua_to_send);
            ua_buf[ua_to_send.len] = 0;
            slist = curl.slist_append(slist, &ua_buf);
        }

        for (req.headers) |h| {
            // Allocate a sentinel-terminated "Name: Value\0" string
            // sized exactly to the header. We allocate (not stack-buffer)
            // because header values can be unbounded (HTTP allows KiB+
            // values) and `slist_append` requires NUL-terminated text.
            const total_len = h.name.len + 2 + h.value.len;
            const line = try self.allocator.allocSentinel(u8, total_len, 0);
            defer self.allocator.free(line);
            @memcpy(line[0..h.name.len], h.name);
            line[h.name.len] = ':';
            line[h.name.len + 1] = ' ';
            @memcpy(line[h.name.len + 2 ..][0..h.value.len], h.value);
            slist = curl.slist_append(slist, line);
        }
        _ = setoptSlist(handle, curl.OPT.HTTPHEADER, slist);

        // ----- Body (POST/PUT/PATCH).
        if (req.body) |body| {
            _ = setoptPtr(handle, curl.OPT.POSTFIELDS, body.ptr);
            // POSTFIELDSIZE_LARGE takes off_t; cast through c_long for safety
            // on 32-bit platforms. 1 MiB request fits into either type.
            _ = setoptLong(handle, curl.OPT.POSTFIELDSIZE_LARGE, @as(c_long, @intCast(body.len)));
        }

        // ----- Timeouts / redirects / TLS.
        // `@intCast` lets Zig infer the destination type from the function
        // parameter (`c_long`). On Linux x64 `c_long = i64`; on Windows x64
        // `c_long = i32` (LP64 vs LLP64). Runtime check is a no-op for the
        // small values we pass (timeouts in ms, redirect counts).
        if (options.timeout_ms) |t| _ = setoptLong(handle, curl.OPT.TIMEOUT_MS, @intCast(t));
        if (options.connect_timeout_ms) |t| _ = setoptLong(handle, curl.OPT.CONNECTTIMEOUT_MS, @intCast(t));
        _ = setoptLong(handle, curl.OPT.FOLLOWLOCATION, if (options.follow_redirects) @as(c_long, 1) else @as(c_long, 0));
        if (options.follow_redirects) {
            _ = setoptLong(handle, curl.OPT.MAXREDIRS, @intCast(options.max_redirects));
        }
        _ = setoptLong(handle, curl.OPT.NOSIGNAL, @as(c_long, 1)); // multi-thread safety
        _ = setoptLong(handle, curl.OPT.SSL_VERIFYPEER, if (options.verify_ssl) @as(c_long, 1) else @as(c_long, 0));
        _ = setoptLong(handle, curl.OPT.SSL_VERIFYHOST, if (options.verify_ssl) @as(c_long, 2) else @as(c_long, 0));

        // ----- Write callback: buffers response body into an ArrayList.
        // Bounded by Options.max_body_bytes (default 10 MiB) so a
        // malicious/large body can't OOM the caller. Use openStream
        // for large downloads.
        const BodyCtx = struct {
            list: *std.ArrayList(u8),
            allocator: std.mem.Allocator,
            max_bytes: ?usize,
        };
        var body_list: std.ArrayList(u8) = .empty;
        errdefer body_list.deinit(self.allocator);
        var body_ctx = BodyCtx{ .list = &body_list, .allocator = self.allocator, .max_bytes = options.max_body_bytes };
        _ = curl.easy_setopt_raw(handle, curl.OPT.WRITEFUNCTION, @as(curl.WriteCallback, @ptrCast(&writeCallback)));
        _ = curl.easy_setopt_raw(handle, curl.OPT.WRITEDATA, @as(*anyopaque, @ptrCast(&body_ctx)));

        // ----- Header callback: parses "Name: Value\r\n" into the headers list.
        // Bounded by Options.max_headers / max_header_bytes.
        const HeaderCtx = struct {
            list: *std.ArrayList(Header),
            allocator: std.mem.Allocator,
            max_headers: usize,
            max_bytes: usize,
            total_bytes: usize = 0,
        };
        var header_list: std.ArrayList(Header) = .empty;
        // Cleanup on any error path. The errdefer reverses partial state.
        errdefer {
            for (header_list.items) |h| {
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            }
            header_list.deinit(self.allocator);
        }
        var header_ctx = HeaderCtx{ .list = &header_list, .allocator = self.allocator, .max_headers = options.max_headers, .max_bytes = options.max_header_bytes };
        _ = curl.easy_setopt_raw(handle, curl.OPT.HEADERFUNCTION, @as(curl.HeaderCallback, @ptrCast(&headerCallback)));
        _ = curl.easy_setopt_raw(handle, curl.OPT.HEADERDATA, @as(*anyopaque, @ptrCast(&header_ctx)));

        // ----- Perform!
        const rc: c_uint = curl.easy_perform(handle);
        if (rc != curl.C.CURLE_OK) {
            const err_msg: []const u8 = std.mem.sliceTo(&errbuf, 0);
            if (err_msg.len > 0) {
                std.log.warn("curl_easy_perform failed: code={d} msg={s}", .{ rc, err_msg });
            } else {
                // errbuf is empty for many failures (e.g. connection
                // reset before any server text). Fall back to libcurl's
                // built-in string so the log always names the real
                // reason instead of a bare number. easy_strerror exists
                // in every libcurl version (and in our Windows stub).
                const str_ptr = curl.easy_strerror(rc);
                const str_slice: []const u8 = if (str_ptr != null)
                    std.mem.sliceTo(str_ptr, 0)
                else
                    "unknown error";
                std.log.warn("curl_easy_perform failed: code={d} msg={s}", .{ rc, str_slice });
            }
            return mapCurlCode(rc);
        }

        // ----- Extract results.
        var status: c_long = 0;
        _ = curl.easy_getinfo(handle, curl.OPT.RESPONSE_CODE, &status);

        var eff_url_ptr: [*c]const u8 = &[_]u8{0};
        _ = curl.easy_getinfo(handle, curl.OPT.EFFECTIVE_URL, &eff_url_ptr);
        const eff_url_slice = std.mem.sliceTo(eff_url_ptr, 0);

        var total_time: f64 = 0;
        _ = curl.easy_getinfo(handle, curl.OPT.TOTAL_TIME, &total_time);

        var primary_ip_ptr: [*c]const u8 = &[_]u8{0};
        _ = curl.easy_getinfo(handle, curl.OPT.PRIMARY_IP, &primary_ip_ptr);
        const primary_ip_slice = std.mem.sliceTo(primary_ip_ptr, 0);

        return .{
            .status_code = @intCast(status),
            .body = try body_list.toOwnedSlice(self.allocator),
            .headers = try header_list.toOwnedSlice(self.allocator),
            .url_effective = try self.allocator.dupe(u8, eff_url_slice),
            .total_time_ms = @intFromFloat(total_time * 1000.0),
            .primary_ip = try self.allocator.dupe(u8, primary_ip_slice),
        };
    }
};

/// Write callback — called once per chunk of the response body.
/// Returns the number of bytes consumed. Returning less than
/// `size * nmemb` aborts the transfer with CURLE_WRITE_ERROR.
fn writeCallback(buf: [*]const u8, size: u64, nmemb: u64, userdata: *anyopaque) callconv(.c) u64 {
    const BodyCtx = struct {
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        max_bytes: ?usize,
    };
    const ctx: *BodyCtx = @ptrCast(@alignCast(userdata));
    const n: usize = @intCast(size * nmemb);
    if (ctx.max_bytes) |cap| {
        if (ctx.list.items.len + n > cap) return 0;
    }
    const slice = buf[0 .. size * nmemb];
    ctx.list.appendSlice(ctx.allocator, slice) catch return 0;
    return size * nmemb;
}

/// Header callback — called once per response header line.
/// Libcurl sends CRLF-terminated lines; we skip the status line
/// ("HTTP/1.1 200 OK") and the blank separator.
fn headerCallback(buf: [*]const u8, size: u64, nmemb: u64, userdata: *anyopaque) callconv(.c) u64 {
    const HeaderCtx = struct {
        list: *std.ArrayList(struct { name: []const u8, value: []const u8 }),
        allocator: std.mem.Allocator,
        max_headers: usize,
        max_bytes: usize,
        total_bytes: usize = 0,
    };
    const ctx: *HeaderCtx = @ptrCast(@alignCast(userdata));
    if (ctx.list.items.len >= ctx.max_headers) return 0;
    const slice = buf[0 .. size * nmemb];

    // Skip status line and blank separator.
    if (slice.len == 0) return size * nmemb;
    if (slice.len >= 5 and std.mem.startsWith(u8, slice, "HTTP/")) return size * nmemb;

    // Trim trailing CRLF (or just LF).
    const trimmed: []const u8 = trim: {
        if (slice.len >= 2 and slice[slice.len - 2] == '\r' and slice[slice.len - 1] == '\n') {
            break :trim slice[0 .. slice.len - 2];
        }
        if (slice.len >= 1 and slice[slice.len - 1] == '\n') {
            break :trim slice[0 .. slice.len - 1];
        }
        break :trim slice;
    };

    // Find the ": " separator.
    const sep = std.mem.indexOf(u8, trimmed, ": ") orelse return size * nmemb;
    // Enforce total header-bytes cap before duping (prevents header-bomb OOM).
    const entry_bytes = sep + (trimmed.len - sep - 2);
    if (ctx.total_bytes + entry_bytes > ctx.max_bytes) return 0;
    if (trimmed.len > 8 * 1024) return 0;
    const name_owned = ctx.allocator.dupe(u8, trimmed[0..sep]) catch return 0;
    errdefer ctx.allocator.free(name_owned);
    const value_owned = ctx.allocator.dupe(u8, trimmed[sep + 2 ..]) catch return 0;
    errdefer ctx.allocator.free(value_owned);
    ctx.total_bytes += entry_bytes;

    ctx.list.append(ctx.allocator, .{ .name = name_owned, .value = value_owned }) catch {
        // Allocation failed — return 0 to abort. Libcurl will report
        // CURLE_WRITE_ERROR → our `mapCurlCode` falls through to
        // UnknownCurl (we don't classify it as OutOfMemory but the
        // Performance.Cancel path also returns Error.OutOfMemory
        // because the append failed on alloc).
        ctx.allocator.free(name_owned);
        ctx.allocator.free(value_owned);
        return 0;
    };
    return size * nmemb;
}

/// setopt wrappers. libcurl's `curl_easy_setopt` is a varargs C
/// function. In Zig 0.16 @cImport, both `CURLoption` and `CURLcode`
/// are exposed as `c_uint` typedefs. We accept c_int (matching the
/// `OPT.*` constants from curl.zig) and widen internally.
fn setoptLong(handle: *curl.C.CURL, option: c_int, value: c_long) c_uint {
    return curl.easy_setopt_raw(handle, @as(c_uint, @intCast(option)), value);
}

fn setoptPtr(handle: *curl.C.CURL, option: c_int, value: [*]const u8) c_uint {
    return curl.easy_setopt_raw(handle, @as(c_uint, @intCast(option)), value);
}

fn setoptSlist(handle: *curl.C.CURL, option: c_int, value: ?*curl.C.struct_curl_slist) c_uint {
    return curl.easy_setopt_raw(handle, @as(c_uint, @intCast(option)), value);
}

/// Translate libcurl's `CURLcode` to our `Error` set. Documented
/// exhaustively so a curl version bump that adds a new code falls
/// into `UnknownCurl` (no silent misclassification).
///
/// `CURLcode` is `c_uint` per @cImport; cases are `c_int` values
/// but cast to `c_uint` for the switch.
fn mapCurlCode(rc: c_uint) Error {
    const rc_int: c_int = @intCast(rc);
    return switch (rc_int) {
        // 0 = CURLE_OK — caller checks before calling us
        0 => unreachable,
        @intCast(curl.C.CURLE_URL_MALFORMAT) => Error.InvalidUrl,
        @intCast(curl.C.CURLE_COULDNT_RESOLVE_PROXY),
        @intCast(curl.C.CURLE_COULDNT_RESOLVE_HOST) => Error.DnsError,
        // libcurl 8.x collapses connect-timeout and operation-timeout
        // into CURLE_OPERATION_TIMEDOUT. Map both error names to the
        // same code — callers can't distinguish the two anyway.
        @intCast(curl.C.CURLE_OPERATION_TIMEDOUT) => Error.OperationTimedOut,
        @intCast(curl.C.CURLE_COULDNT_CONNECT) => Error.ConnectionRefused,
        @intCast(curl.C.CURLE_PEER_FAILED_VERIFICATION),
        @intCast(curl.C.CURLE_SSL_CERTPROBLEM),
        @intCast(curl.C.CURLE_SSL_CIPHER),
        @intCast(curl.C.CURLE_SSL_CONNECT_ERROR) => Error.TlsError,
        @intCast(curl.C.CURLE_UNSUPPORTED_PROTOCOL) => Error.UnsupportedProtocol,
        @intCast(curl.C.CURLE_TOO_MANY_REDIRECTS) => Error.TooManyRedirects,
        @intCast(curl.C.CURLE_OUT_OF_MEMORY) => Error.OutOfMemory,
        @intCast(curl.C.CURLE_FAILED_INIT) => Error.InitFailed,
        // HTTP-layer failures: server spoke but the exchange failed.
        @intCast(curl.C.CURLE_WEIRD_SERVER_REPLY),
        @intCast(curl.C.CURLE_REMOTE_ACCESS_DENIED),
        @intCast(curl.C.CURLE_HTTP_RETURNED_ERROR),
        @intCast(curl.C.CURLE_HTTP_RANGE_ERROR),
        @intCast(curl.C.CURLE_HTTP_POST_ERROR),
        @intCast(curl.C.CURLE_GOT_NOTHING) => Error.HttpError,
        // Local callback / transfer-direction failures.
        @intCast(curl.C.CURLE_WRITE_ERROR) => Error.WriteError,
        @intCast(curl.C.CURLE_READ_ERROR) => Error.ReadError,
        @intCast(curl.C.CURLE_SEND_ERROR),
        @intCast(curl.C.CURLE_SEND_FAIL_REWIND) => Error.SendError,
        @intCast(curl.C.CURLE_RECV_ERROR) => Error.RecvError,
        @intCast(curl.C.CURLE_PARTIAL_FILE) => Error.PartialFile,
        // Remaining TLS-engine failures fold into TlsError.
        @intCast(curl.C.CURLE_SSL_ENGINE_NOTFOUND),
        @intCast(curl.C.CURLE_SSL_ENGINE_SETFAILED),
        @intCast(curl.C.CURLE_USE_SSL_FAILED),
        @intCast(curl.C.CURLE_SSL_CACERT_BADFILE),
        @intCast(curl.C.CURLE_SSL_SHUTDOWN_FAILED),
        @intCast(curl.C.CURLE_SSL_CRL_BADFILE),
        @intCast(curl.C.CURLE_SSL_ISSUER_ERROR) => Error.TlsError,
        // Aborted by our own callback (e.g. OOM in writeCallback):
        // surfaced as a timeout so callers retry rather than crash.
        @intCast(curl.C.CURLE_ABORTED_BY_CALLBACK) => Error.OperationTimedOut,
        else => Error.UnknownCurl,
    };
}

// ============================================================================
// Tests — moved here from `client_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = client_tests; }` below pulls them into the run.
// ============================================================================

const client_tests = struct {
    const testing = std.testing;
    const custom_http_client = @import("root.zig");

    test "Method.parse handles every supported verb (case-sensitive)" {
        try testing.expectEqual(@as(custom_http_client.Method, .GET), custom_http_client.Method.parse("GET").?);
        try testing.expectEqual(@as(custom_http_client.Method, .POST), custom_http_client.Method.parse("POST").?);
        try testing.expectEqual(@as(custom_http_client.Method, .PUT), custom_http_client.Method.parse("PUT").?);
        try testing.expectEqual(@as(custom_http_client.Method, .PATCH), custom_http_client.Method.parse("PATCH").?);
        try testing.expectEqual(@as(custom_http_client.Method, .DELETE), custom_http_client.Method.parse("DELETE").?);
        try testing.expectEqual(@as(?custom_http_client.Method, null), custom_http_client.Method.parse("get")); // case-sensitive
        try testing.expectEqual(@as(?custom_http_client.Method, null), custom_http_client.Method.parse("BREW"));
        try testing.expectEqual(@as(?custom_http_client.Method, null), custom_http_client.Method.parse(""));
    }

    test "Method.asString round-trips parse" {
        const methods = [_]custom_http_client.Method{ .GET, .POST, .PUT, .PATCH, .DELETE };
        for (methods) |m| {
            try testing.expectEqual(m, custom_http_client.Method.parse(m.asString()).?);
        }
    }

    test "Client.init/deinit is a no-op pair" {
        const allocator = testing.allocator;
        var client = custom_http_client.Client.init(allocator);
        client.deinit();
    }

    test "Request is plain-data — no constructor required" {
        const r: custom_http_client.Request = .{ .method = .GET, .url = "https://example.com" };
        try testing.expectEqualStrings("https://example.com", r.url);
        try testing.expectEqual(@as(?[]const u8, null), r.body);
        try testing.expectEqual(@as(usize, 0), r.headers.len);
    }
};

comptime {
    _ = client_tests;
}

// ============================================================================
// Tests — moved here from `fd_leak_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = fd_leak_tests; }` below pulls them into the run.
// ============================================================================

const fd_leak_tests = struct {
    // FD-leak regression tests. Counter-paradigm to the
    // bash-spawn approach in modules/http/HttpClient.zig — that
    // module needed explicit pipe-close defers (PR #91); this module
    // is supposed to be leak-free by construction because libcurl
    // owns its sockets. We verify empirically under stress.
    //
    // On Linux we use `std.process.Child` + `ls /proc/self/fd | wc -l`
    // — Zig 0.16's `Io.Dir.iterate()` panics on /proc/self/fd because
    // entries are symlinks that vanish during iteration. The shell
    // approach is the project-precedent pattern (see the bash.zig
    // FD-leak tests for the same workaround).

    const testing = std.testing;
    const custom_http_client = @import("root.zig");
    const io = std.testing.io;

    /// Count open FDs by running `ls /proc/self/fd`. Linux-only;
    /// non-Linux hosts return 0 and the tests skip.
    fn countOpenFds() !usize {
        if (builtin.os.tag != .linux) return 0;
        // Spawn `sh -c "ls /proc/self/fd | wc -l"`.
        var child = try std.process.spawn(io, .{
            .argv = &[_][]const u8{ "sh", "-c", "ls /proc/self/fd 2>/dev/null | wc -l" },
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .ignore,
        });
        defer {
            if (child.stdout) |s| s.close(io);
            child.kill(io);
        }

        var buf: [64]u8 = undefined;
        var total: usize = 0;
        if (child.stdout) |out| {
            var reader = out.reader(io, &buf);
            while (true) {
                const n = try std.Io.Reader.readSliceShort(&reader.interface, &buf);
                if (n == 0) break;
                total += n;
            }
        }
        _ = child.wait(io) catch {};

        // Parse the number from the output. Output is "<n>\n".
        const contents = testing.allocator.alloc(u8, total) catch return 0;
        defer testing.allocator.free(contents);
        @memcpy(contents, buf[0..total]);

        var n: usize = 0;
        for (contents) |c| {
            if (c >= '0' and c <= '9') {
                n = n * 10 + @as(usize, c - '0');
            }
        }
        return n;
    }

    test "fd: 50 sequential GETs do NOT grow the open-fd count" {
        if (builtin.os.tag != .linux) return;
        const allocator = testing.allocator;
        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();

        const before = try countOpenFds();

        var ok: usize = 0;
        var i: usize = 0;
        while (i < 50) : (i += 1) {
            var resp = client.perform(.{ .method = .GET, .url = "https://example.com" }, .{}) catch continue;
            defer resp.deinit(allocator);
            ok += 1;
        }

        std.Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms * 10 }, .real) catch {};

        const after = try countOpenFds();

        const tolerance: usize = 10;
        if (after > before + tolerance) {
            std.debug.print("!! FD leak: before={d} after={d} delta={d} (ok_calls={d}) !!\n",
                .{ before, after, after - before, ok });
            return error.FdLeakSuspected;
        }
        if (ok == 0) return error.SkipZigTest;
    }

    test "fd: 50 ConnectionRefused errors do NOT grow the open-fd count" {
        if (builtin.os.tag != .linux) return;
        const allocator = testing.allocator;
        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();

        const before = try countOpenFds();

        var i: usize = 0;
        while (i < 50) : (i += 1) {
            _ = client.perform(.{ .method = .GET, .url = "http://127.0.0.1:1/" }, .{}) catch {};
        }

        std.Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms * 10 }, .real) catch {};

        const after = try countOpenFds();
        const tolerance: usize = 10;
        if (after > before + tolerance) {
            std.debug.print("!! FD leak on errors: before={d} after={d} delta={d} !!\n",
                .{ before, after, after - before });
            return error.FdLeakOnErrorsSuspected;
        }
    }

    test "fd: total open-fd count stays bounded under load" {
        if (builtin.os.tag != .linux) return;
        const allocator = testing.allocator;
        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();

        var i: usize = 0;
        while (i < 10) : (i += 1) {
            var resp = client.perform(.{ .method = .GET, .url = "https://example.com" }, .{}) catch continue;
            resp.deinit(allocator);
        }

        const count = try countOpenFds();
        try testing.expect(count < 100);
    }
};

comptime {
    _ = fd_leak_tests;
}

// ============================================================================
// Tests — moved here from `stress_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = stress_tests; }` below pulls them into the run.
// ============================================================================

const stress_tests = struct {
    // Stress / soak tests — slow by design. Gated behind
    // `-Dintegration=true -Dstress=true` because they take ~5 minutes
    // wall-clock and hit the network hard.

    const testing = std.testing;
    const custom_http_client = @import("root.zig");
    const gserverz = @import("../server/http_server.zig");

    const HttpContext = gserverz.HttpContext;
    const HttpRequest = gserverz.HttpRequest;
    const HttpResponse = gserverz.HttpResponse;

    fn runOne(allocator: std.mem.Allocator, url: []const u8, method: custom_http_client.Method) !bool {
        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        const resp = client.perform(.{ .method = method, .url = url }, .{ .timeout_ms = 30_000 }) catch return false;
        resp.deinit(allocator);
        return true;
    }

    test "stress: 100 sequential successful GETs to example.com" {
        const allocator = testing.allocator;
        var ok: usize = 0;
        var i: usize = 0;
        while (i < 100) : (i += 1) {
            if (try runOne(allocator, "https://example.com", .GET)) ok += 1;
        }
        if (ok < 50) return error.SkipZigTest;
        std.debug.print("\nstress: {d}/100 successful\n", .{ok});
    }

    test "stress: 100 KiB body round-trips" {
        // Was https://example.com — flaky in air-gapped sandboxes. Converted
        // to a local TestServer echo so the test runs network-independently.
        // The 100 KiB body exercises the same write/read path as the
        // 1 MiB edge case test.
        const allocator = testing.allocator;
        const io = std.testing.io;
        const ts = TestServer.init(allocator, io) catch return error.SkipZigTest;
        defer ts.deinit();
        ts.registerRoutes() catch return error.SkipZigTest;
        ts.start() catch return error.SkipZigTest;

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(allocator);
        var i: usize = 0;
        while (i < 100 * 1024) : (i += 1) try body.append(allocator, 'x');

        const url = ts.url("/post") catch return error.SkipZigTest;
        defer allocator.free(url);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var resp = client.perform(.{ .method = .POST, .url = url, .body = body.items }, .{ .timeout_ms = 10_000 }) catch return error.SkipZigTest;
        defer resp.deinit(allocator);

        try testing.expectEqual(@as(u16, 200), resp.status_code);
        try testing.expectEqual(body.items.len, resp.body.len);
        try testing.expectEqual(@as(u8, 'x'), resp.body[0]);
        try testing.expectEqual(@as(u8, 'x'), resp.body[resp.body.len - 1]);
    }

    const TestServer = struct {
        server: *gserverz.GinwaServer,
        io: std.Io,
        allocator: std.mem.Allocator,
        listener_thread: std.Thread,
        port: u16,

        pub fn init(allocator: std.mem.Allocator, io: std.Io) !*TestServer {
            const ts = try allocator.create(TestServer);
            const addr = try gserverz.Address.init("127.0.0.1", 0);
            const port: u16 = try getBoundPort(addr.sock_fd);
            const gs = try gserverz.GinwaServer.init(allocator, io, addr);
            ts.* = .{
                .server = gs,
                .io = io,
                .allocator = allocator,
                .listener_thread = undefined,
                .port = port,
            };
            return ts;
        }

        pub fn registerRoutes(self: *TestServer) !void {
            try self.server.router.post("/post", echoPostHandler);
        }

        pub fn start(self: *TestServer) !void {
            self.listener_thread = try std.Thread.spawn(.{}, listenFn, .{self.server});
        }

        pub fn url(self: *TestServer, path: []const u8) ![]u8 {
            return std.fmt.allocPrint(self.allocator, "http://127.0.0.1:{d}{s}", .{ self.port, path });
        }

        pub fn deinit(self: *TestServer) void {
            self.server.shutdown();
            self.listener_thread.join();
            self.server.destroy(self.allocator);
            self.allocator.destroy(self);
        }
    };

    fn echoPostHandler(_: HttpContext, req: HttpRequest, res: HttpResponse) !HttpResponse {
        return res.withBody(req.body);
    }

    fn listenFn(server: *gserverz.GinwaServer) void {
        server.listenEventLoop(.{ .dispatch_mode = .worker_pool }) catch {};
    }

    extern "c" fn getsockname(
        sockfd: c_int,
        addr: *std.posix.sockaddr,
        addrlen: *std.posix.socklen_t,
    ) c_int;

    fn getBoundPort(sock_fd: c_int) !u16 {
        if (builtin.os.tag == .windows) {
            var raw: std.c.sockaddr.in = undefined;
            var len: c_int = @intCast(@sizeOf(@TypeOf(raw)));
            const rc = getsockname(sock_fd, @ptrCast(&raw), @ptrCast(&len));
            if (rc != 0) return error.BindFailed;
            return @byteSwap(@as(u16, @intCast(raw.port)));
        }
        var raw: std.posix.sockaddr.in = undefined;
        var len: std.posix.socklen_t = @sizeOf(@TypeOf(raw));
        const rc = getsockname(sock_fd, @ptrCast(&raw), &len);
        if (rc != 0) return error.BindFailed;
        return @byteSwap(@as(u16, @intCast(raw.port)));
    }

    test "stress: alternating success / refused calls do not interleave state" {
        const allocator = testing.allocator;
        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();

        var ok: usize = 0;
        var refused: usize = 0;
        var i: usize = 0;
        while (i < 40) : (i += 1) {
            const url = if (i % 2 == 0) "https://example.com" else "http://127.0.0.1:1/";
            const result = client.perform(.{ .method = .GET, .url = url }, .{ .timeout_ms = 5_000 }) catch |err| switch (err) {
                error.ConnectionRefused, error.ConnectionTimeout, error.OperationTimedOut => {
                    refused += 1;
                    continue;
                },
                error.DnsError, error.TlsError => return error.SkipZigTest,
                else => return err,
            };
            result.deinit(allocator);
            ok += 1;
        }
        try testing.expect(ok + refused == 40);
        std.debug.print("\nstress: alternating — ok={d} refused={d}\n", .{ ok, refused });
    }

    test "stress: 4 threads × 25 concurrent in-flight GETs each" {
        if (builtin.single_threaded) return error.SkipZigTest;

        const allocator = testing.allocator;
        const WorkerCtx = struct {
            allocator: std.mem.Allocator,
            success_count: std.atomic.Value(usize) = .init(0),
            error_count: std.atomic.Value(usize) = .init(0),
        };

        const N_THREADS: usize = 4;
        const PER_THREAD: usize = 25;

        var ctx: WorkerCtx = .{ .allocator = allocator };

        var threads: [N_THREADS]std.Thread = undefined;
        var t: usize = 0;
        while (t < N_THREADS) : (t += 1) {
            threads[t] = try std.Thread.spawn(.{}, struct {
                fn run(c: *WorkerCtx) void {
                    var i: usize = 0;
                    while (i < PER_THREAD) : (i += 1) {
                        var client = custom_http_client.Client.init(c.allocator);
                        defer client.deinit();
                        const result = client.perform(.{ .method = .GET, .url = "https://example.com" }, .{ .timeout_ms = 10_000 }) catch {
                            _ = c.error_count.fetchAdd(1, .monotonic);
                            continue;
                        };
                        result.deinit(c.allocator);
                        _ = c.success_count.fetchAdd(1, .monotonic);
                    }
                }
            }.run, .{&ctx});
        }

        t = 0;
        while (t < N_THREADS) : (t += 1) threads[t].join();

        const ok = ctx.success_count.load(.acquire);
        const err = ctx.error_count.load(.acquire);
        std.debug.print("\nstress: 4 threads × 25 = {d} ok / {d} err\n", .{ ok, err });
        try testing.expect(ok + err == N_THREADS * PER_THREAD);
    }

    test "stress: 500 small GET requests in a tight loop — no allocation growth leak" {
        const allocator = testing.allocator;
        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();

        var ok: usize = 0;
        var i: usize = 0;
        while (i < 500) : (i += 1) {
            const r = client.perform(.{ .method = .GET, .url = "https://example.com" }, .{ .timeout_ms = 5_000 }) catch {
                if (i > 50 and ok < 5) return error.SkipZigTest;
                continue;
            };
            r.deinit(allocator);
            ok += 1;
        }
        try testing.expect(ok >= 50);
    }

    test "stress: 100 KiB body round-trips (legacy httpbin variant)" {
        // SKIPPED: superseded by the local-server variant added in
        // custom-http-client-cross-platform. Kept as a skip-stub so any
        // historical grep for the old name still finds something.
        return error.SkipZigTest;
    }

    fn client_fetch(allocator: std.mem.Allocator, req: custom_http_client.Request) !custom_http_client.Response {
        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        return client.perform(req, .{ .timeout_ms = 30_000 }) catch |err| switch (err) {
            error.ConnectionRefused, error.ConnectionTimeout, error.OperationTimedOut,
            error.DnsError, error.TlsError => return error.SkipZigTest,
            else => return err,
        };
    }
};

comptime {
    _ = stress_tests;
}
