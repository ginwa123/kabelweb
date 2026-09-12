# custom_http_client — internal notes

## Design decisions

### `@cImport` over manual `extern "c"`

`curl/curl.h` is C-clean — no `_Pragma`, no
`__attribute__((deprecated))` on declarations we touch. Verified against
libcurl 8.21.0 on Arch Linux.

Tried (and rejected) the manual `extern "c"` route because the curl API
is huge (300+ `CURLOPT_*` constants). Manual declarations would bloat
`curl.zig` by 1000+ lines for zero behavioural gain.

### Lazy `curl_global_init` guarded by `std.atomic`

`curl_global_init` is NOT thread-safe. We call it from `Client.init`
when the first handle is created, guarded by an `std.atomic.Value(bool)`
so two threads racing on first request don't double-init (idempotent
on libcurl's side but adds a CAS for predictability).

We DO NOT call `curl_global_cleanup`. Process exit handles it; matches
the existing `HttpClient.zig` "best effort, don't care about shutdown"
posture.

### Error mapping via `@intCast` (not a Zig enum)

`CURLcode` is a C `enum` whose value space grows between libcurl
versions. In Zig 0.16, `@cImport` exposes `CURLcode` as `c_uint`
typedef (not a Zig enum), so `switch` on the enum form is unavailable.
We use `@intCast(curl.C.CURLE_X) => Error.Y` cases which work today
and fall through to `UnknownCurl` for any new CURLcode that a future
libcurl adds.

### URL NUL-termination via `allocSentinel`

Caller-supplied `req.url: []const u8` slices lack capacity for a
trailing NUL (libcurl requires NUL-terminated `const char*`). We use
`allocator.allocSentinel(u8, len, 0)` to get a `[:0]u8` with a real
sentinel byte, free it on every exit path via `defer`. The whole
`perform()` is wrapped in static-contract tests that ensure the
allocation and free are paired.

### Buffers entire response, no streaming

Decision: defer streaming to a v2. The two real consumers of the
sibling `HttpClient.zig` (MCP path) buffer today; the LLM streaming
path uses `Agent.zig`'s `std.http.Client`, not this module. No need
for v1.

## Streaming backpressure — a full chunk queue must never abort the transfer

`stream.zig`'s libcurl WRITEFUNCTION owns a fixed 64-slot ring buffer
between the libcurl worker thread (producer) and the caller's
`ResponseStream.next()` (consumer). Three rules keep that design honest;
each is locked by a test:

1. **A FULL queue is backpressure, not an error.** `writeCallback` blocks
   (5 ms poll, 120 s budget) and retries the same slice until the
   consumer drains. Returning 0 from a WRITEFUNCTION makes libcurl abort
   the whole transfer with `CURLE_WRITE_ERROR` → `LocalError.WriteError`,
   which the agent surfaces as
   `scanner.next failed after N chunk(s): WriteError` (→
   `StreamInterrupted` → the entire LLM response is discarded and
   retried). That was the production symptom this rule fixes. The
   callback returns 0 ONLY on: real OOM, `cancel()`, or the 120 s budget
   elapsing.
2. **The wake decision is atomic with the store.** `ChunkQueue.push`
   returns `PushOutcome.pushed.wake` — "was the queue empty immediately
   before this push?" — computed under the SAME lock acquisition as the
   store. The previous `isEmpty()` + `push()` pair took the lock twice,
   so a consumer that drained the queue in between parked on
   `signal_gen` with a non-empty queue and slept its full 300 s budget
   while the producer filled the buffer.
3. **`cancelled` is sampled by the producer.** `ResponseStream.cancel()`
   only works because `writeCallback` checks `state.cancelled` on every
   backpressure poll. Without it `deinit()`'s `cancel()` + `join()`
   blocks for up to `CURLOPT_TIMEOUT_MS` (300 s).

Consumer-side note: the caller thread runs `stream_callback` → SSE emit
between `next()` calls, and that emit is synchronous — see
`custom_http_server/src/sse_manager.zig`'s `SSE_SEND_TIMEOUT_MS` for why
a stuck SSE peer used to be able to stall this consumer in the first
place.

## Quirks bit during implementation

- **`CURLOPT_*` are exposed as `c_int`, not Zig enums.** Zig 0.16
  `@cImport` made our `C.CURLoption = c_uint` typedef (so we use
  `@as(c_uint, @intCast(option))` for `setopt` wrappers). The earlier
  attempt with `@intFromEnum(C.CURLOPT_X)` failed for
  `CURLOPT_ERRORBUFFER` specifically because that one symbol was
  promoted to `c_int` instead of being exposed as an enum member.

- **`easy_setopt` is varargs.** We dispatch with three typed wrappers
  (`setoptLong` / `setoptPtr` / `setoptSlist`) because Zig doesn't
  call varargs through cImport cleanly.

- **Method strings are tiny** (`GET`/`POST`/`PUT`/`PATCH`/`DELETE`),
  so we use a stack `[16:0]u8` buffer for the NUL-terminated copy
  instead of an allocation.

- **`build.zig` `linkSystemLibrary` lives on `*Build.Module`, not
  `*Step.Compile`.** The first build failed at `mod_tests.linkSystemLibrary`
  until we changed to `mod_tests.root_module.linkSystemLibrary`.

- **Test runner must live in `root.zig`, not a separate file.**
  The test step's `root_module` is rooted at `root.zig`; a `test_runner.zig`
  sibling was invisible to the test walker. Discovered when
  `zig build test --summary all` reported `All 0 tests passed.`
  Even when `test_runner.zig` is imported by `root.zig` via `pub const`,
  Zig's lazy analysis skips modules not reachable from `root_module`.
  Resolution: place the `test {}` block inside `root.zig`.

- **`var url_buf` → `const url_buf`.** Zig 0.16 catches unused
  mutable bindings (`var` with no mutations) as a compile error.

- **Stdout via `std.fs.File` doesn't exist in 0.16.** The CLI's
  first draft used `std.fs.File.stderr()` — replaced with
  `std.debug.print` (which already routes to stderr).

- **Minimal args API convention: `args[0]` is the binary name.**
  Initial CLI tried `args[0]` as the method; had to skip with
  `args[1]`.

## FD-leak verification recipe (Linux)

When debugging a hypothetical FD leak:

```bash
PID=$(pgrep -f "custom_http_client")
echo "FD count: $(ls /proc/$PID/fd | wc -l)"

# Detect orphan sockets (FD pointing at socket that's gone from
# /proc/net/tcp{,6}):
for fd in /proc/$PID/fd/*; do
    target=$(readlink "$fd" 2>/dev/null)
    [[ "$target" == socket:* ]] || continue
    inode=$(echo "$target" | sed 's/socket:\[\(.*\)\]/\1/')
    if ! grep -q ": $inode " /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
        echo "ORPHAN FD: $fd -> $target"
    fi
done
```

Reference: `~/.nalar/memories/nalar-backend-architecture.md` "Diagnostic recipe".

## Future work (out of this plan)

- Migrate `handle_mcp_tool.zig` and `prompts_build_messages_for_agent_prompt.zig`
- Add `Connection: keep-alive` pooling via `curl_share_*`
- Add streaming response (`ResponseStream` + `CURLOPT_XFERINFOFUNCTION`)
- `Options.max_body_bytes` to cap response allocation

## Cross-platform status

This module now compiles + links on:

- **Linux x86_64** — primary target, all 47 behaviour tests pass.
- **macOS aarch64** — source code compiles cleanly. Linking requires
  the host to have macOS SDK + brew keg at the configured prefix.
  Verified via `zig build test -Dtarget=aarch64-macos` (no source
  errors; only the expected TBD-file parse failure when running
  cross-compile on a Linux host without macOS libraries).
- **Windows x86_64 (GNU ABI)** — source code compiles cleanly.
  Linking requires vcpkg with libcurl at the configured root.
  Verified via `zig build test -Dtarget=x86_64-windows-gnu`.

### Known platform-specific source changes

- `client.zig` — `@intCast` instead of `@as(c_long, u32)` for the
  `CURLOPT_*_MS` setopts (Windows x64 `c_long` is 32-bit, Linux is
  64-bit; `@as` rejects lossy narrowing on Windows).
- `stream.zig` — manual `extern "c"` declaration for `clock_gettime`
  isn't possible (Zig stdlib's `clockid_t` resolves to `void` on
  Windows MSVC); falls back to `RtlQueryPerformanceCounter` /
  `RtlQueryPerformanceFrequency` for Windows.

### Test fixture cross-platform

The integration / streaming / CPU-usage tests need to introspect the
ephemeral port of a bound socket. Originally used `std.os.linux.getsockname`
(Linux-only). Replaced with a manual `extern "c" fn getsockname` +
a comptime `builtin.os.tag == .windows` branch that uses `std.c.sockaddr.in`
(via the test module's `link_libc = true`). Verified to compile on
all three target OSes.
