// Minimal stub of <curl/curl.h> for Windows dev boxes that don't have
// vcpkg libcurl + openssl installed and can't build the vendored archive
// (no gcc/make/perl available — see build-vendor-curl.sh's Windows-host
// bail-out for context).
//
// Why a stub instead of skipping the libcurl dependency entirely:
// `src/modules/agent/Agent.zig` transitively imports `custom_http_client`
// (the Client struct, StreamScanner, Request/Header/Options types). The
// `zig build test` root (`src/root.zig`) imports the Agent test runner,
// which forces `custom_http_client`'s source to be compiled and linked.
// `custom_http_client/src/curl.zig` does `@cImport(@cInclude("curl/curl.h"))`
// to bind libcurl's C symbols — without a curl.h header, the cimport
// fails at semantic-analysis time with "'curl/curl.h' not found". And
// without a libcurl archive, the Zig link step fails with "file not
// found" for `vendor/curl/windows-amd64/lib/libcurl.a`.
//
// The stub below defines JUST the symbols `custom_http_client/src/curl.zig`
// actually touches (verified by greping `C.<symbol>` references in that
// file). The companion `stub_libcurl.c` provides empty/no-op
// implementations — they're enough to make `zig build test` link, but
// any test that actually opens a network connection will fail at
// runtime (which is the expected behavior on a Windows dev box without
// libcurl).
//
// To replace the stub with a real libcurl on Windows, install vcpkg
// (`vcpkg install curl:x64-windows openssl:x64-windows`) — the
// `custom_http_client/build.zig` system probe then takes over and the
// stub is bypassed.
#ifndef NALAR_STUB_LIBCURL_H
#define NALAR_STUB_LIBCURL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles. Real libcurl's CURL struct has internal state; the
// stub just needs a non-zero type tag so `@cImport` produces a usable
// Zig type (Zig's `*CURL` / `**CURL` references compile against an
// incomplete type).
typedef struct CURL CURL;
typedef struct curl_slist curl_slist;

// CURLcode — real libcurl uses an enum (~95 values). Tests only check
// return codes numerically (CURLE_OK = 0, anything else = error), so a
// plain int is sufficient for the stub. `custom_http_client/src/client.zig`
// does `@intFromEnum(C.CURLE_OK)` — works fine when the underlying type
// is `int`.
//
// We declare CURLcode as `unsigned int` (= c_uint in Zig) because
// `custom_http_client/src/stream.zig` does
// `const rc: c_uint = curl.easy_perform(state.handle)` — calling code
// expects the return to match `c_uint`. Real libcurl's CURLcode is
// `int` in libcurl 7.x but `unsigned int`/`enum` with unsigned
// underlying type in 8.x — both are ABI-compatible (same size +
// calling convention); declaring unsigned avoids the Zig-side type
// mismatch without breaking runtime semantics.
typedef unsigned int CURLcode;

// CURLoption — real libcurl declares this as `unsigned int` (c_uint in
// Zig). The stub MUST match — `custom_http_client/src/client.zig` and
// `src/stream.zig` both cast options via `@as(c_uint, @intCast(...))`
// before passing them to `curl_easy_setopt`, so the second param of
// that vararg function has to be `unsigned int` or the call site fails
// to compile (signed/unsigned mismatch under @cImport). Defined BEFORE
// the function signatures below so `curl_easy_setopt(CURL *, CURLoption,
// ...)` resolves correctly.
typedef unsigned int CURLoption;

// Option constants. Only the ones `custom_http_client/src/curl.zig`'s
// `OPT` struct references — verified by grep against that file. Values
// are arbitrary (the stub's implementations ignore them anyway); only
// uniqueness across the enum space is required so `@intCast` in Zig
// doesn't collide.
#define CURLOPT_URL 10000
#define CURLOPT_CUSTOMREQUEST 10001
#define CURLOPT_HTTPHEADER 10002
#define CURLOPT_POSTFIELDS 10003
#define CURLOPT_COPYPOSTFIELDS 10004
#define CURLOPT_POSTFIELDSIZE 10005
#define CURLOPT_POSTFIELDSIZE_LARGE 10006
#define CURLOPT_WRITEFUNCTION 10007
#define CURLOPT_WRITEDATA 10008
#define CURLOPT_HEADERFUNCTION 10009
#define CURLOPT_HEADERDATA 10010
#define CURLOPT_TIMEOUT_MS 10011
#define CURLOPT_CONNECTTIMEOUT_MS 10012
#define CURLOPT_FOLLOWLOCATION 10013
#define CURLOPT_MAXREDIRS 10014
#define CURLOPT_USERAGENT 10015
#define CURLOPT_SSL_VERIFYPEER 10016
#define CURLOPT_SSL_VERIFYHOST 10017
#define CURLOPT_NOSIGNAL 10018
#define CURLOPT_NOPROGRESS 10019
#define CURLOPT_XFERINFOFUNCTION 10020
#define CURLOPT_XFERINFODATA 10021
#define CURLOPT_ERRORBUFFER 10022

#define CURLINFO_RESPONSE_CODE 20000
#define CURLINFO_EFFECTIVE_URL 20001
#define CURLINFO_TOTAL_TIME 20002
#define CURLINFO_PRIMARY_IP 20003

// Function signatures. The stub implementations in stub_libcurl.c
// return null / 0 / no-op so the link succeeds and tests that merely
// *instantiate* `custom_http_client.Client` (which most of them do)
// don't crash. Tests that actually *call* a network method will fail
// at runtime — that's the expected behavior on a Windows dev box
// without libcurl installed.
//
// `curl_easy_setopt` and `curl_easy_getinfo` are vararg functions in
// real libcurl. The vararg signature is REQUIRED here — cimport on
// `void *param` would force the Zig caller to cast every argument
// to `?*anyopaque`, but real libcurl callers pass `char**`,
// `*c_long`, `*f64`, `*[*c]const u8` etc. depending on which CURLINFO
// is being queried, and the Zig compiler rejects `*[*c]const u8 →
// ?*anyopaque` implicit conversions. Mirroring real libcurl's
// `curl_easy_getinfo(CURL *, CURLINFO, ...)` lets cimport produce
// the same per-CURLINFO typed wrapper that real libcurl callers use.
//
// `curl_easy_setopt`'s `option` parameter type is `CURLoption` (=
// `unsigned int`); `CURLINFO_*` (used by curl_easy_getinfo) is `int`
// (signed) in real libcurl — both match the Zig call sites' `@as(
// c_uint, …)` / `@as(c_int, …)` casts.
CURLcode curl_global_init(long flags);
void     curl_global_cleanup(void);
CURL*    curl_easy_init(void);
void     curl_easy_cleanup(CURL* handle);
CURLcode curl_easy_perform(CURL* handle);
CURLcode curl_easy_getinfo(CURL* handle, int info, ...);
CURLcode curl_easy_setopt(CURL* handle, CURLoption option, ...);
curl_slist* curl_slist_append(curl_slist* list, const char* data);
void       curl_slist_free_all(curl_slist* list);
const char* curl_easy_strerror(CURLcode code);
const char* curl_version(void);

// CURLE_URL_MALFORMAT (3), CURLE_OPERATION_TIMEDOUT (28), and
// CURLE_FAILED_INIT (2) — real libcurl error codes used by
// `custom_http_client/src/stream.zig` and `src/client.zig`'s error
// mappers (`@intCast(curl.C.CURLE_URL_MALFORMAT) => LocalError.
// InvalidUrl`). The Zig call sites do `switch (rc)` and pattern-match
// against specific CURLE_* values; the stub defines all the values
// the call sites reference so the Zig switch compiles.
//
// CURL_GLOBAL_DEFAULT (3) — flag value passed to `curl_global_init`
// by `custom_http_client/src/client.zig`'s `init` function. Real
// libcurl uses bit-flags (CURL_GLOBAL_DEFAULT = 3 == SSL + WIN32);
// the stub ignores the value entirely (the stub's `curl_global_init`
// always returns CURLE_OK), so the numeric value doesn't matter for
// runtime — only for the cimport to expose the symbol.
#define CURLE_OK 0
#define CURLE_UNSUPPORTED_PROTOCOL 1
#define CURLE_FAILED_INIT 2
#define CURLE_URL_MALFORMAT 3
#define CURLE_COULDNT_RESOLVE_PROXY 5
#define CURLE_COULDNT_RESOLVE_HOST 6
#define CURLE_COULDNT_CONNECT 7
#define CURLE_OPERATION_TIMEDOUT 28
#define CURLE_TOO_MANY_REDIRECTS 47
#define CURLE_PEER_FAILED_VERIFICATION 51
#define CURLE_SSL_CERTPROBLEM 58
#define CURLE_SSL_CIPHER 59
#define CURLE_SSL_CONNECT_ERROR 35
#define CURLE_ABORTED_BY_CALLBACK 42
#define CURLE_OUT_OF_MEMORY 27
#define CURLE_WEIRD_SERVER_REPLY 8
#define CURLE_REMOTE_ACCESS_DENIED 9
#define CURLE_PARTIAL_FILE 18
#define CURLE_HTTP_RETURNED_ERROR 22
#define CURLE_WRITE_ERROR 23
#define CURLE_READ_ERROR 26
#define CURLE_HTTP_RANGE_ERROR 33
#define CURLE_HTTP_POST_ERROR 34
#define CURLE_GOT_NOTHING 52
#define CURLE_SSL_ENGINE_NOTFOUND 53
#define CURLE_SSL_ENGINE_SETFAILED 54
#define CURLE_SEND_ERROR 55
#define CURLE_RECV_ERROR 56
#define CURLE_USE_SSL_FAILED 64
#define CURLE_SEND_FAIL_REWIND 65
#define CURLE_SSL_CACERT_BADFILE 77
#define CURLE_SSL_SHUTDOWN_FAILED 80
#define CURLE_SSL_CRL_BADFILE 82
#define CURLE_SSL_ISSUER_ERROR 83
#define CURL_GLOBAL_DEFAULT 3

#ifdef __cplusplus
}
#endif

#endif  // NALAR_STUB_LIBCURL_H