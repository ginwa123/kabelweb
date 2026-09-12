# custom_http_client

A libcurl-backed HTTP client for nalar. Buffers the entire response
in-memory; no streaming.

## Why this exists

The sibling `modules/http/HttpClient.zig` shells out to `bash -c
"curl ..."` subprocesses. That approach (a) leaks FDs on error paths
(PR #91 added explicit pipe-close `defer` blocks but the class is
fragile), (b) has no timeouts, (c) has no streaming/SSE, (d) has no
HTTP/2. This module wraps libcurl's `curl_easy_*` API directly so
those problems don't exist by construction.

This module is **new and currently unused by the rest of nalar**.
A future plan moves `handle_mcp_tool.zig` and
`prompts_build_messages_for_agent_prompt.zig` off the bash-spawning client
onto this one.

## Build

```bash
zig build                                          # default
zig build test                                     # ~13 tests pass (no network)
zig build test -Dintegration=true                 # +6 httpbin.org behavioural
zig build test -Dintegration=true -Dstress=true    # +5 stress (slow)
zig-out/bin/custom_http_client GET https://example.com
```

Requires libcurl installed (Arch Linux ships `libcurl.so.4` at
v8.21.0; verified with `pkg-config --modversion libcurl`).

## Public API

```zig
const c = @import("custom_http_client");
var client = c.Client.init(allocator);
defer client.deinit();

var resp = try c.get(&client, "https://example.com", .{});
defer resp.deinit(allocator);

std.debug.print("status={d} body_len={d}\n", .{ resp.status_code, resp.body.len });
```

### Convenience methods

| Function | Equivalent `Request` |
|---|---|
| `c.get(url, opts)` | `.{method=.GET, .url=url}` |
| `c.post(url, body, headers, opts)` | `.{method=.POST, .url=url, .body=body, .headers=headers}` |
| `c.put(url, body, headers, opts)` | `.method=.PUT` |
| `c.patch(url, body, headers, opts)` | `.method=.PATCH` |
| `c.delete(url, headers, opts)` | `.method=.DELETE` |

### Errors

See `Error` in `root.zig`. The most common:
- `DnsError` (CURLE_COULDNT_RESOLVE_HOST/PROXY)
- `ConnectionRefused` (CURLE_COULDNT_CONNECT)
- `OperationTimedOut` (CURLE_OPERATION_TIMEDOUT — also covers connect timeouts in libcurl 8.x)
- `TlsError` (CURLE_PEER_FAILED_VERIFICATION, _SSL_*)
- `TooManyRedirects` (only when `follow_redirects=true` and the cap is hit)
- `HttpError` (CURLE_HTTP_RETURNED_ERROR / WEIRD_SERVER_REPLY / GOT_NOTHING / RANGE+POST errors / REMOTE_ACCESS_DENIED)
- `WriteError` (CURLE_WRITE_ERROR — our own write callback aborted: out-of-memory copying a chunk, `cancel()`/`deinit()` asking the transfer to stop, or the consumer stalling past the 120s backpressure budget. A merely FULL chunk queue does NOT abort — the callback blocks and retries until the consumer drains)
- `ReadError` (CURLE_READ_ERROR)
- `SendError` (CURLE_SEND_ERROR / SEND_FAIL_REWIND)
- `RecvError` (CURLE_RECV_ERROR — connection reset / server hung up mid-stream)
- `PartialFile` (CURLE_PARTIAL_FILE — fewer bytes than expected)
- `UnknownCurl` (libcurl version added a new CURLcode we haven't classified)

### Limits (v1)

- No streaming / no SSE — entire response buffered to `[]u8`.
- One `CURL*` per call. No connection pooling.
- Cross-platform build verified on Linux (Arch). Cross-compile tests
  pass on **macOS (aarch64)** and **Windows (x86_64-gnu)** for the
  source code; linking requires the matching platform's libcurl:
  - macOS: Homebrew's keg-only curl at `$(brew --prefix curl)/{include,lib}`.
    Override the default `/opt/homebrew` (Apple Silicon) with
    `-Dcurl-prefix=/usr/local` for Intel macs.
  - Windows: vcpkg at `C:/vcpkg/installed/x64-windows/{include,lib}`.
    Override with `-Dcurl-vcpkg-root=...`.

## Comparison with `modules/http/HttpClient.zig`

| Capability | old (`bash curl`) | this module |
|---|---|---|
| Spawns subprocess | yes | no |
| FD leak on error | previously yes, patched | no (libcurl owns sockets) |
| Timeout | no (`curl -s` default infinite) | yes (`Options.timeout_ms`) |
| Redirects | no | yes (`Options.follow_redirects`) |
| HTTP methods | GET, POST | all 5 |
| TLS tuning | inherited from system curl | `Options.verify_ssl` |
| Streams | no | no (v1) |
| Tests | subprocess + httpbin | ~31, organised by class (unit/memory/FD/edge/stress/integration) |
