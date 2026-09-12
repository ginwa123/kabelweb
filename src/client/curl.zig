//! Single-source binding for libcurl's C API.
//!
//! Zig 0.16 + libcurl 8.x interaction notes:
//!  - libcurl's `curl.h` is C-clean (no `_Pragma` macros like GLib's
//!    `G_GNUC_BEGIN_IGNORE_DEPRECATIONS`), so `@cImport` works without
//!    falling back to manual `extern "c"` declarations. Verified
//!    against Arch Linux's libcurl 8.21.0.
//!  - The Zig 0.16 `@cImport` returns a single anonymous namespace
//!    (here bound to `C`); we re-export every symbol we touch so call
//!    sites import only this module, not raw `@cImport` references.
//!  - CURLcode (libcurl's error union) maps cleanly to `c_int`; we
//!    switch on `@intFromEnum` instead of forcing a Zig enum because
//!    libcurl's value space is unstable across versions.

const std = @import("std");

pub const C = @cImport({
    @cInclude("curl/curl.h");
});

/// Aliases for the C functions/types we use. Re-exporting them here
/// keeps the call surface small and makes future swaps to manual
/// `extern "c"` declarations a one-file change.
pub const init = C.curl_global_init;
pub const cleanup = C.curl_global_cleanup;
pub const easy_init = C.curl_easy_init;
pub const easy_cleanup = C.curl_easy_cleanup;
pub const easy_perform = C.curl_easy_perform;
pub const easy_getinfo = C.curl_easy_getinfo;
pub const easy_setopt_raw = C.curl_easy_setopt;
pub const slist_append = C.curl_slist_append;
pub const slist_free_all = C.curl_slist_free_all;
pub const easy_strerror = C.curl_easy_strerror;
pub const version = C.curl_version;

/// CURLOPT_* constants (as `c_int`). Zig 0.16's @cImport exposes
/// CURLOPT/CURLINFO enum members via `@intFromEnum` OR as raw `c_int`
/// constants depending on the macro expansion — we use `@intCast` which
/// works for both shapes. List only what `client.zig` actually uses.
pub const OPT = struct {
    pub const URL: c_int = @intCast(C.CURLOPT_URL);
    pub const CUSTOMREQUEST: c_int = @intCast(C.CURLOPT_CUSTOMREQUEST);
    pub const HTTPHEADER: c_int = @intCast(C.CURLOPT_HTTPHEADER);
    pub const POSTFIELDS: c_int = @intCast(C.CURLOPT_POSTFIELDS);
    pub const COPYPOSTFIELDS: c_int = @intCast(C.CURLOPT_COPYPOSTFIELDS);
    pub const POSTFIELDSIZE: c_int = @intCast(C.CURLOPT_POSTFIELDSIZE);
    pub const POSTFIELDSIZE_LARGE: c_int = @intCast(C.CURLOPT_POSTFIELDSIZE_LARGE);
    pub const WRITEFUNCTION: c_int = @intCast(C.CURLOPT_WRITEFUNCTION);
    pub const WRITEDATA: c_int = @intCast(C.CURLOPT_WRITEDATA);
    pub const HEADERFUNCTION: c_int = @intCast(C.CURLOPT_HEADERFUNCTION);
    pub const HEADERDATA: c_int = @intCast(C.CURLOPT_HEADERDATA);
    pub const TIMEOUT_MS: c_int = @intCast(C.CURLOPT_TIMEOUT_MS);
    pub const CONNECTTIMEOUT_MS: c_int = @intCast(C.CURLOPT_CONNECTTIMEOUT_MS);
    pub const FOLLOWLOCATION: c_int = @intCast(C.CURLOPT_FOLLOWLOCATION);
    pub const MAXREDIRS: c_int = @intCast(C.CURLOPT_MAXREDIRS);
    pub const USERAGENT: c_int = @intCast(C.CURLOPT_USERAGENT);
    pub const SSL_VERIFYPEER: c_int = @intCast(C.CURLOPT_SSL_VERIFYPEER);
    pub const SSL_VERIFYHOST: c_int = @intCast(C.CURLOPT_SSL_VERIFYHOST);
    pub const NOSIGNAL: c_int = @intCast(C.CURLOPT_NOSIGNAL);
    pub const NOPROGRESS: c_int = @intCast(C.CURLOPT_NOPROGRESS);
    pub const XFERINFOFUNCTION: c_int = @intCast(C.CURLOPT_XFERINFOFUNCTION);
    pub const XFERINFODATA: c_int = @intCast(C.CURLOPT_XFERINFODATA);
    pub const ERRORBUFFER: c_int = @intCast(C.CURLOPT_ERRORBUFFER);
    pub const RESPONSE_CODE: c_int = @intCast(C.CURLINFO_RESPONSE_CODE);
    pub const EFFECTIVE_URL: c_int = @intCast(C.CURLINFO_EFFECTIVE_URL);
    pub const TOTAL_TIME: c_int = @intCast(C.CURLINFO_TOTAL_TIME);
    pub const PRIMARY_IP: c_int = @intCast(C.CURLINFO_PRIMARY_IP);
};

/// `extern "c"` callback signatures. We declare them at module scope
/// because Zig 0.16 requires `extern "c"` (and `callconv(.c)`) decls
/// to be at file top-level (per zig-language-quirks rule #5).
pub const WriteCallback = *const fn (buf: [*]const u8, size: u64, nmemb: u64, userdata: *anyopaque) callconv(.c) u64;
pub const HeaderCallback = *const fn (buf: [*]const u8, size: u64, nmemb: u64, userdata: *anyopaque) callconv(.c) u64;
pub const ProgressCallback = *const fn (handle: *C.CURL, dltotal: c_longlong, dlnow: c_longlong, ultotal: c_longlong, ulnow: c_longlong, userdata: *anyopaque) callconv(.c) c_int;
