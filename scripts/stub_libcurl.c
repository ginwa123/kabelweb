// Empty/no-op implementations of the libcurl symbols declared in
// stub_libcurl.h. Compiled to vendor/curl/windows-amd64/lib/libcurl.a on
// Windows dev boxes that don't have a real libcurl archive (no vcpkg,
// no MinGW gcc + perl). See stub_libcurl.h's top comment for context.
//
// Behavior:
//   - curl_easy_init returns NULL → `custom_http_client.Client.init`
//     returns an error. Most tests that merely *reference* Client (and
//     don't call .get/.post/.stream) still compile + link.
//   - curl_easy_perform returns CURLE_FAILED_INIT (2) → any test that
//     actually fires a network request fails at runtime with a clear
//     error from custom_http_client.Error.UnsupportedProtocol / InitFailed.
//     Tests that use the static check pattern
//     (e.g. `call_streaming_test.zig`'s "imports custom_http_client"
//     contract tests) still pass because they only read source text.
//
// We use distinct non-zero sentinel return codes so it's obvious from
// a test failure log that the stub fired (vs. a real libcurl error).

#include "stub_libcurl.h"

CURLcode curl_global_init(long flags) {
    (void)flags;
    return CURLE_OK;
}

void curl_global_cleanup(void) {
    /* no-op */
}

CURL* curl_easy_init(void) {
    // Returning NULL here means custom_http_client.Client.init will
    // surface an InitFailed error to the caller. Most tests just
    // construct a Client and immediately deinit it without firing a
    // request, so this works for the `zig build test` happy path on
    // Windows-without-libcurl dev boxes.
    return 0;
}

void curl_easy_cleanup(CURL* handle) {
    (void)handle;
}

CURLcode curl_easy_perform(CURL* handle) {
    (void)handle;
    // 2 = CURLE_FAILED_INIT in real libcurl. Distinct from CURLE_OK
    // (0) so test assertions can tell "stub fired" apart from a real
    // success.
    return 2;
}

CURLcode curl_easy_getinfo(CURL* handle, int info, ...) {
    (void)handle;
    (void)info;
    // Stub: don't write to the varargs param (callers expect
    // CURLE_OK on success to use the value; we return CURLE_FAILED_INIT
    // instead so callers don't depend on the out-param contents).
    return CURLE_FAILED_INIT;
}

CURLcode curl_easy_setopt(CURL* handle, CURLoption option, ...) {
    (void)handle;
    (void)option;
    return CURLE_OK;  // silently accept setopt
}

curl_slist* curl_slist_append(curl_slist* list, const char* data) {
    (void)list;
    (void)data;
    return 0;
}

void curl_slist_free_all(curl_slist* list) {
    (void)list;
}

const char* curl_easy_strerror(CURLcode code) {
    (void)code;
    return "stub libcurl: not implemented";
}

const char* curl_version(void) {
    return "stub/0.0.0";
}