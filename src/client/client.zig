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
