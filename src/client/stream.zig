//! ResponseStream + StreamScanner: pull-based chunk and line streaming
//! on top of libcurl's WRITEFUNCTION + XFERINFOFUNCTION callbacks.
//!
//! Mirrors Go's `http.Response.Body` + `bufio.Scanner` shape. Buffers
//! chunks as they arrive from a worker thread; caller iterates via
//! `next()` (chunks) or wraps in a `StreamScanner` (lines).
//!
//! **Threading model:** We use `std.Io.Mutex` (futex-based, from
//! Zig 0.16 std.Io) for the chunk-queue mutex — NOT a hand-rolled
//! spinlock. `std.Io.Mutex` is the canonical Zig 0.16 implementation
//! for Io-runtime code (see `~/.nalar/memories/zig-0.16-stdlib-changes`).
//!
//! **Lifetime:** the worker thread and the calling thread share a
//! heap-allocated `SharedState`. The caller MUST call `deinit()` which
//! joins the worker and frees the heap. After deinit the stream is
//! unusable.

const std = @import("std");
const builtin = @import("builtin");
const curl = @import("curl.zig");
const root = @import("root.zig");
const Method = @import("request.zig").Method;
const Header = @import("request.zig").Header;
const Request = @import("request.zig").Request;
const Options = @import("options.zig").Options;
const Client = root.Client;
const LocalError = root.Error;

/// Thread-safe FIFO of byte slices. Fixed-size circular buffer of
/// 64 slots — comfortably above typical SSE chunk rates, bounded so
/// a slow consumer can't grow memory without bound.
const QUEUE_CAPACITY: usize = 64;

/// Poll granularity used by `writeCallback` while it waits for the
/// consumer to drain a full queue. Also bounds how quickly
/// `ResponseStream.cancel()` is observed by a producer parked on
/// backpressure.
const BACKPRESSURE_POLL_NS: u64 = 5 * std.time.ns_per_ms;

/// Upper bound on how long the WRITEFUNCTION blocks waiting for queue
/// space before giving up and aborting the transfer.
///
/// This is a safety valve, not the expected path — the consumer drains
/// within microseconds whenever it is healthy. It exists so a consumer
/// that has genuinely wedged (or a `deinit()` racing the worker) can't
/// park the libcurl worker thread forever. 120 s is comfortably above
/// any real consumer stall and comfortably below `CURLOPT_TIMEOUT_MS`
/// (300 s), so the backpressure path — not libcurl's own timeout — is
/// what reports the failure.
const BACKPRESSURE_MAX_WAIT_NS: u64 = 120 * std.time.ns_per_s;

/// libcurl's CURLOPT_ERRORBUFFER expects a buffer of at least
/// `CURL_ERROR_SIZE` bytes (256 per the curl.h header). We size it
/// generously so a future curl bump can't silently truncate us.
const CURL_ERRORBUFFER_LEN: usize = 256;

/// Monotonic clock reading in nanoseconds. Uses libc clock_gettime
/// directly to avoid deadlock against the worker thread which doesn't
/// own the Io runtime (see ResponseStream.next comment for the same
/// reasoning).
// Monotonic clock helper. Uses libc `clock_gettime` on POSIX (Linux + macOS),
// and Windows `QueryPerformanceCounter` on Windows. Declared manually with
// `c_int` instead of `clockid_t` because `std.c.clock_gettime`'s `clockid_t`
// resolves to `void` on Windows x86_64 (MSVC's libc has no `clock_gettime`),
// which `extern "c"` rejects as a parameter type.
fn monotonicNs() u64 {
    if (builtin.os.tag == .windows) {
        return monotonicNsWindows();
    }
    // Portable `timespec` + `clock_gettime` inlined from src/helpers/mod.zig
    // (this module's build graph does not wire the `helpers` package in —
    // see custom_http_client/build.zig). std.c's `clock_gettime` takes
    // `clockid_t` which resolves to `void` on Windows x86_64 (MSVC's libc
    // has no `clock_gettime`), so we declare an `extern "c"` with a plain
    // `c_int clk_id` parameter instead.
    const Clong = if (@bitSizeOf(usize) == 64 and builtin.os.tag != .windows) i64 else i32;
    const PosixTimespec = extern struct { sec: Clong, nsec: Clong };
    const clock_gettime_c = @extern(*const fn (c_int, *PosixTimespec) callconv(.c) c_int, .{
        .name = "clock_gettime",
        .library_name = "c",
    });
    // Platform-correct: Linux CLOCK_MONOTONIC = 1, Darwin = 6
    // (see src/helpers/mod.zig for the full rationale).
    const CLOCK_MONOTONIC: c_int = if (builtin.os.tag.isDarwin()) 6 else 1;
    var ts: PosixTimespec = undefined;
    _ = clock_gettime_c(CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn monotonicNsWindows() u64 {
    // RtlQueryPerformanceCounter returns ticks at RtlQueryPerformanceFrequency Hz.
    // Frequency is stable per boot, so a process-wide cache is fine.
    var counter: std.os.windows.LARGE_INTEGER = 0;
    _ = std.os.windows.ntdll.RtlQueryPerformanceCounter(&counter);
    const freq: u64 = queryPerformanceFrequencyCached();
    // Convert ticks → nanoseconds without overflow: scale first to avoid
    // losing precision when counter * 1e9 overflows u64.
    const ticks_per_us = freq / 1_000_000;
    const counter_u: u64 = @intCast(counter);
    const us_part: u64 = if (ticks_per_us == 0)
        counter_u / (freq / 1_000_000) // freq < 1 MHz — extremely unusual
    else
        counter_u / ticks_per_us;
    return us_part * 1_000;
}

var qpf_cache: ?u64 = null;
fn queryPerformanceFrequencyCached() u64 {
    if (qpf_cache) |f| return f;
    var freq_li: std.os.windows.LARGE_INTEGER = 0;
    _ = std.os.windows.ntdll.RtlQueryPerformanceFrequency(&freq_li);
    const f: u64 = @intCast(freq_li);
    qpf_cache = f;
    return f;
}

/// Win32 `VOID Sleep(DWORD dwMilliseconds);` (kernel32). Zig 0.16
/// dropped `std.os.windows.kernel32.Sleep`, so we declare it here —
/// same pattern as `src/helpers/mod.zig:91`. Only referenced from the
/// comptime-gated Windows branch of `workerSleepNs`, so the linker
/// never sees an unresolved `Sleep` symbol on POSIX.
extern "kernel32" fn Sleep(dw_milliseconds: u32) callconv(.winapi) void;

/// `struct timespec` for the worker-thread sleep. Same platform-correct
/// `c_long`-equivalent trick as `monotonicNs` (i32 on Windows, where
/// the type is unused; i64 on 64-bit Linux/macOS, matching
/// `time_t`/`long`).
const WorkerClong = if (@bitSizeOf(usize) == 64 and builtin.os.tag != .windows) i64 else i32;

const WorkerTimespec = extern struct {
    sec: WorkerClong,
    nsec: WorkerClong,
};
extern "c" fn nanosleep(req: *const WorkerTimespec, rem: ?*WorkerTimespec) c_int;

/// Sleep on the libcurl worker thread WITHOUT going through the Io
/// runtime.
///
/// `std.Io.sleep(state.io, …)` is NOT usable here: the worker thread
/// doesn't own an Io runtime (see `monotonicNs`'s rationale), so
/// parking it through `state.io` can deadlock against the runtime the
/// caller thread is using. Raw libc `nanosleep` on POSIX / Win32
/// `Sleep` on Windows — the same platform split as `monotonicNs`.
fn workerSleepNs(ns: u64) void {
    if (comptime builtin.os.tag == .windows) {
        const ms: u32 = @intCast(@min(
            @divTrunc(ns, std.time.ns_per_ms),
            @as(u64, std.math.maxInt(u32)),
        ));
        Sleep(ms);
        return;
    }
    const ts = WorkerTimespec{
        .sec = @intCast(@divTrunc(ns, std.time.ns_per_s)),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = nanosleep(&ts, null);
}

/// Result of `ChunkQueue.push`.
///
/// Three-way instead of a `bool` because the caller must be able to
/// tell "transient backpressure" (queue momentarily full — retry, do
/// NOT abort the transfer) apart from "genuine allocation failure"
/// (abort). See `writeCallback`.
const PushOutcome = union(enum) {
    /// Stored. `wake` is true when the queue was EMPTY immediately
    /// before this push (the empty → non-empty edge), i.e. a consumer
    /// parked in `ResponseStream.next()` needs a `signal_gen` bump +
    /// futex wake. Computed under the SAME lock acquisition as the
    /// store, which is what makes the wake decision reliable.
    pushed: struct { wake: bool },
    /// Ring buffer full. Transient backpressure, not an error.
    full,
    /// Copying the chunk into heap memory failed (OOM).
    out_of_memory,
};

const ChunkQueue = struct {
    mutex: *std.Io.Mutex,
    slots: [QUEUE_CAPACITY]?[]u8,
    head: usize,
    tail: usize,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) ChunkQueue {
        const mutex = allocator.create(std.Io.Mutex) catch unreachable;
        mutex.* = .init;
        return .{
            .mutex = mutex,
            .slots = [_]?[]u8{null} ** QUEUE_CAPACITY,
            .head = 0,
            .tail = 0,
            .io = io,
        };
    }

    pub fn deinit(self: *ChunkQueue, allocator: std.mem.Allocator) void {
        allocator.destroy(self.mutex);
    }

    /// Store `chunk` (copied into heap memory) and report whether a
    /// parked consumer needs waking.
    ///
    /// The emptiness check and the store happen under ONE lock
    /// acquisition, and `wake` is derived from the emptiness observed
    /// there. The previous shape — `isEmpty()` then `push()`, each
    /// taking the lock independently — had a lost-wakeup race:
    ///
    ///   producer: isEmpty() -> false   (queue held 1 chunk)
    ///   consumer: popOne()  -> drains it, returns it to the caller,
    ///              which re-enters next() and parks on signal_gen
    ///   producer: push()    -> succeeds, but `was_empty` is now
    ///              stale-false, so no bump and no futex wake
    ///
    /// The consumer then sleeps out its full 300 s budget with a
    /// non-empty queue while the producer keeps filling it — and once
    /// the ring buffer hits QUEUE_CAPACITY the write callback used to
    /// abort the whole transfer (`CURLE_WRITE_ERROR` → `WriteError` →
    /// `StreamInterrupted` → full LLM-call retry). Fusing the two
    /// steps removes the window entirely.
    fn push(self: *ChunkQueue, allocator: std.mem.Allocator, chunk: []const u8) PushOutcome {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const next_tail = (self.tail + 1) % QUEUE_CAPACITY;
        if (next_tail == self.head) return .full;
        // dupe makes a heap-owned copy so the data outlives libcurl's
        // write-callback buffer (which can be invalidated as soon as
        // we return).
        const owned = allocator.dupe(u8, chunk) catch return .out_of_memory;
        const was_empty = self.head == self.tail;
        self.slots[self.tail] = owned;
        self.tail = next_tail;
        return .{ .pushed = .{ .wake = was_empty } };
    }

    fn popOne(self: *ChunkQueue) ?[]u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.head == self.tail) return null;
        const chunk = self.slots[self.head].?;
        self.slots[self.head] = null;
        self.head = (self.head + 1) % QUEUE_CAPACITY;
        return chunk;
    }
};

/// State shared between worker thread and caller. Heap-allocated so
/// the worker thread's pointer survives the caller-thread's stack
/// frames returning.
const SharedState = struct {
    allocator: std.mem.Allocator,
    handle: *curl.C.CURL,
    queue: ChunkQueue,
    cancelled: std.atomic.Value(bool) = .init(false),
    finished: std.atomic.Value(bool) = .init(false),
    status_code: std.atomic.Value(u32) = .init(0),
    primary_ip: std.ArrayList(u8),
    url_effective: std.ArrayList(u8),
    headers: std.ArrayList(Header),
    worker_error: ?LocalError = null,
    total_time_ms: u64 = 0,
    io: std.Io,

    /// Wakeup-generation counter. Bumped by the worker thread every
    /// time it pushes a chunk into the queue AND when it sets
    /// `finished`. The consumer thread waits on this via
    /// `io.futexWaitTimeout` — when the value changes, the kernel
    /// wakes the consumer; the consumer re-checks the queue and
    /// either returns a chunk or breaks out (finished).
    ///
    /// Why a separate counter (not `finished`):
    /// - We want to wake on EVERY chunk push, not just completion
    ///   (chunks can arrive well before `finished` is set).
    /// - We want to wake on completion (the worker bumps once more
    ///   before setting `finished`).
    /// - One atomic word lets both events flow through the same
    ///   wakeup channel.
    ///
    /// The futex protocol guarantees no lost wakeups: the consumer
    /// snapshots the value BEFORE checking the queue. If the worker
    /// bumps the counter (and pushes) between the consumer's
    /// snapshot and futex_wait, the futex_wait returns immediately
    /// with EAGAIN because the value no longer matches.
    signal_gen: std.atomic.Value(u32) = .init(0),
    /// Backing storage for `CURLOPT_ERRORBUFFER`. Lives on the heap
    /// (via SharedState) because libcurl stores the raw pointer and
    /// writes into it whenever an error string is produced — often
    /// AFTER `openStream` has returned, from inside `streamWorker`
    /// running on a separate `std.Thread`. A stack-local here would
    /// be a classic use-after-free the moment the worker fired an
    /// error path.
    errbuf: [CURL_ERRORBUFFER_LEN]u8 = [_]u8{0} ** CURL_ERRORBUFFER_LEN,
    /// Backing storage for `CURLOPT_URL`. Same lifetime reasoning
    /// as errbuf — libcurl stores the pointer verbatim and reads it
    /// from inside `easy_perform` on the worker thread.
    url_buf: [:0]u8,
    /// Backing storage for `CURLOPT_CUSTOMREQUEST`. Same reasoning.
    method_buf: [:0]u8,
    /// Backing storage for the optional User-Agent header line.
    /// Used in the curl slist for HTTPHEADER.
    ua_buf: ?[:0]u8,
    /// Backing for the HTTPHEADER slist (which libcurl reads verbatim
    /// from worker). Each line is [:0]u8; the slist is a linked
    /// list of pointers that we own.
    header_lines: std.ArrayList([:0]u8),
    /// The compiled slist passed to libcurl. libcurl does NOT copy
    /// this — it reads from the linked list whenever it serializes
    /// the request. We must keep it alive until easy_cleanup runs.
    header_slist: ?*curl.C.struct_curl_slist,

    fn deinit(self: *SharedState) void {
        self.cancel();
        curl.easy_cleanup(self.handle);
        if (self.header_slist) |s| curl.slist_free_all(s);
        for (self.headers.items) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.headers.deinit(self.allocator);
        self.url_effective.deinit(self.allocator);
        self.primary_ip.deinit(self.allocator);
        for (self.header_lines.items) |line| {
            self.allocator.free(line);
        }
        self.header_lines.deinit(self.allocator);
        self.allocator.free(self.url_buf);
        self.allocator.free(self.method_buf);
        if (self.ua_buf) |ua| self.allocator.free(ua);
        while (self.queue.popOne()) |chunk| {
            self.allocator.free(chunk);
        }
        self.queue.deinit(self.allocator);
    }

    /// Request cancellation of the transfer AND wake a consumer parked in
    /// `ResponseStream.next()`.
    ///
    /// Setting the flag alone is not sufficient. `next()` parks in
    /// `futexWaitTimeout` on `signal_gen` for the whole poll budget
    /// (300 s), and the worker only samples `cancelled` while libcurl is
    /// handing it bytes. A cancel issued during a silent stretch (a
    /// reasoning model pausing mid-thought, or a stalled upstream) would
    /// therefore go unobserved until the next body chunk or the libcurl
    /// timeout. The bump + wake below mirror what `streamWorker` does on
    /// completion, so the parked consumer re-checks immediately and sees
    /// `cancelled`.
    fn cancel(self: *SharedState) void {
        self.cancelled.store(true, .release);
        // Same ordering as the push path (`writeCallback`): bump the
        // generation BEFORE waking, so a consumer that observes the new
        // value is guaranteed to also observe `cancelled`.
        _ = self.signal_gen.fetchAdd(1, .release);
        self.io.futexWake(u32, &self.signal_gen.raw, 1);
    }
};

/// Caller-facing handle. Owns a `*SharedState` (heap-allocated).
/// `deinit` joins the worker thread and frees the shared state.
///
/// Each chunk returned by `next()` is a heap-owned `[]u8` slice that
/// the caller MUST eventually `state.allocator.free(chunk)` after
/// use. `deinit` does NOT clean up chunks the caller hasn't consumed.
pub const ResponseStream = struct {
    state: *SharedState,
    thread: std.Thread,

    /// Pull the next chunk, or `null` when the transfer has finished.
    ///
    /// Returns `error.Cancelled` if `cancel()` was called — checked before the
    /// buffered backlog, so a cancel takes effect immediately rather than after
    /// draining queued chunks. Callers MUST treat `error.Cancelled` as distinct
    /// from `null`: `null` means "clean EOF, or the poll budget elapsed".
    pub fn next(self: *ResponseStream) !?[]const u8 {
        // Block waiting for the worker thread to push a chunk
        // or signal completion. We use a futex-based wait keyed on
        // `state.signal_gen` — the worker bumps this counter every
        // time it pushes a chunk (writeCallback) and once more when
        // libcurl completes (streamWorker). The consumer parks in
        // the kernel via `io.futexWaitTimeout` and is woken the
        // moment the value changes — no CPU burn while idle.
        //
        // Why this replaces the previous busy-spin loop:
        // - Reasoning models (Claude extended thinking, OpenAI o1/o3,
        //   DeepSeek R1, Qwen QwQ) routinely pause 30-60 s — sometimes
        //   longer — between SSE chunks. The previous `spinLoopHint`
        //   + per-iteration `clock_gettime` polling kept the consumer
        //   thread pinned at 100% CPU during those pauses, which
        //   manifested as 12-58% `nalar` CPU usage during streaming
        //   sessions (the worker thread was correctly parked at
        //   `wchan = futex_wait`; only the consumer was spinning).
        // - With the futex wait, the consumer sleeps in the kernel
        //   until the worker wakes it (chunk arrival or completion).
        //   A typical 500ms gap between chunks costs < 1ms CPU now.
        //
        // The 300 s overall budget matches libcurl's
        // `CURLOPT_TIMEOUT_MS` (5 min) configured in `client.zig`.
        // If the worker is truly stuck, libcurl fires its timeout and
        // the worker sets `worker_error`, which we surface on the
        // next loop iteration. If the budget elapses without a
        // chunk or an error, we return null — same shape as before.
        //
        // We use libc clock_gettime rather than std.Io.Clock.now because
        // the latter calls into the Io runtime from the consumer
        // thread, which can deadlock against the Io runtime used by
        // the worker thread.
        const poll_budget_ns: u64 = 300 * std.time.ns_per_s;
        const deadline_ns: u64 = monotonicNs() + poll_budget_ns;

        while (true) {
            // Cancellation first: a cancelled stream stops delivering
            // immediately rather than after the buffered backlog. This is
            // deliberately a DISTINCT error and not `null` — `null` already
            // means "clean EOF, or the poll budget elapsed", which callers
            // (e.g. Agent.callStreaming) treat as a mid-stream death and
            // retry. A user-initiated stop must never trigger a retry.
            if (self.state.cancelled.load(.acquire)) return error.Cancelled;
            if (self.state.worker_error) |e| return e;
            if (self.state.queue.popOne()) |chunk| return chunk;
            if (self.state.finished.load(.acquire)) return null;

            // Compute the remaining wait time. If we've burned
            // through the budget already, return null — same as the
            // old busy-spin's deadline check.
            const now_ns = monotonicNs();
            if (now_ns >= deadline_ns) return null;
            const remaining_ns: u64 = deadline_ns - now_ns;

            // Snapshot the wakeup-generation. The futex returns
            // immediately (EAGAIN) if the value changes between this
            // load and the wait syscall, so we never lose a wakeup.
            // On spurious wakeups we loop back, re-check the queue,
            // and either return a chunk or sleep again.
            const expected = self.state.signal_gen.load(.acquire);

            // Park in the kernel until either the counter changes
            // (worker pushed a chunk, or libcurl completed) or the
            // remaining budget elapses. We pass an absolute deadline
            // (Timeout.deadline) so the futex gets a real
            // CLOCK_MONOTONIC timestamp — `futexWaitTimeout` is the
            // canonical primitive the Zig 0.16 Io runtime exposes
            // for this exact use case.
            //
            // Error union: `error.Timeout` if the budget elapsed (we
            // return null), `error.Canceled` from the Io runtime
            // (unreachable from the test path; we never cancel).
            //
            // We use Io.Clock.Timestamp.fromNow (which calls into the
            // Io runtime to read .monotonic) — this is fine on the
            // consumer thread because the worker thread doesn't own
            // an Io runtime (it just runs curl_easy_perform).
            const deadline_ts = std.Io.Clock.Timestamp.fromNow(self.state.io, .{
                .raw = .{ .nanoseconds = @intCast(remaining_ns) },
                .clock = .awake, // CLOCK_MONOTONIC on Linux; what futex_wait uses
            });
            // error.Canceled is the only error in the Cancelable set.
// Timeout is handled internally by the Io runtime (the vtable
// returns success on timeout), so we only need to handle
// Canceled. After the futex returns (success or spurious
// wakeup), we loop back, re-check the queue / finished flag /
// budget, and either return a chunk, return null, or sleep again.
            self.state.io.futexWaitTimeout(u32, &self.state.signal_gen.raw, expected, .{ .deadline = deadline_ts }) catch |err| switch (err) {
                error.Canceled => return null, // never happens on our path
            };
        }
    }

    pub fn statusCode(self: *const ResponseStream) u16 {
        return @intCast(self.state.status_code.load(.acquire));
    }

    pub fn headersView(self: *const ResponseStream) []const Header {
        return self.state.headers.items;
    }

    pub fn effectiveUrl(self: *const ResponseStream) []const u8 {
        return self.state.url_effective.items;
    }

    pub fn primaryIp(self: *const ResponseStream) []const u8 {
        return self.state.primary_ip.items;
    }

    pub fn totalTimeMs(self: *const ResponseStream) u64 {
        return self.state.total_time_ms;
    }

    /// Abort the transfer. Idempotent, safe to call from another thread, and
    /// observable promptly: the worker stops at the next body chunk and a
    /// consumer parked in `next()` is woken immediately with `error.Cancelled`.
    pub fn cancel(self: *ResponseStream) void {
        self.state.cancel();
    }

    pub fn deinit(self: *ResponseStream) void {
        self.state.cancel();
        self.thread.join();
        self.state.deinit();
        self.state.allocator.destroy(self.state);
        self.* = undefined;
    }
};

/// Line-oriented pull. Buffers partial-line bytes across chunk
/// boundaries. Empty lines are returned as `&[_]u8{}` unless
/// `skip_empty = true` at init.
pub const StreamScanner = struct {
    stream: *ResponseStream,
    carry: std.ArrayList(u8),
    line_buf: std.ArrayList(u8),
    skip_empty: bool,

    pub fn init(stream: *ResponseStream, skip_empty: bool) StreamScanner {
        return .{
            .stream = stream,
            .carry = .empty,
            .line_buf = .empty,
            .skip_empty = skip_empty,
        };
    }

    pub fn next(self: *StreamScanner) !?[]const u8 {
        const allocator = self.stream.state.allocator;
        while (true) {
            if (std.mem.indexOfScalar(u8, self.carry.items, '\n')) |nl_idx| {
                self.line_buf.clearRetainingCapacity();
                try self.line_buf.appendSlice(allocator, self.carry.items[0..nl_idx]);
                const line_end: usize = if (self.line_buf.items.len > 0 and
                    self.line_buf.items[self.line_buf.items.len - 1] == '\r')
                    self.line_buf.items.len - 1
                else
                    self.line_buf.items.len;
                const drop_through_nl: usize = nl_idx + 1;
                const remaining = self.carry.items.len - drop_through_nl;
                std.mem.copyForwards(
                    u8,
                    self.carry.items[0..remaining],
                    self.carry.items[drop_through_nl..],
                );
                self.carry.shrinkRetainingCapacity(remaining);
                if (self.skip_empty and line_end == 0) continue;
                return self.line_buf.items[0..line_end];
            }
            const chunk_opt = try self.stream.next();
            const chunk = chunk_opt orelse {
                if (self.carry.items.len > 0) {
                    self.line_buf.clearRetainingCapacity();
                    try self.line_buf.appendSlice(allocator, self.carry.items);
                    self.carry.clearRetainingCapacity();
                    if (self.skip_empty and self.line_buf.items.len == 0) return null;
                    return self.line_buf.items;
                }
                return null;
            };
            // appendSlice copies chunk bytes into carry; the chunk
            // itself is a heap-owned slice (allocated by the worker's
            // push() via dupe) and is no longer needed once carry has
            // absorbed the bytes. Free it now. Cap line length at 1 MiB
            // so a missing '\n' can't grow carry unbounded.
            defer allocator.free(chunk);
            if (self.carry.items.len + chunk.len > 1024 * 1024) return error.OutOfMemory;
            try self.carry.appendSlice(allocator, chunk);
        }
    }

    pub fn deinit(self: *StreamScanner) void {
        self.carry.deinit(self.stream.state.allocator);
        self.line_buf.deinit(self.stream.state.allocator);
    }
};

/// libcurl WRITEFUNCTION. Called on the worker thread for every body
/// chunk. Returns the number of bytes it "took"; returning anything
/// less than `size * nmemb` aborts the transfer with
/// `CURLE_WRITE_ERROR`.
///
/// Because of that, this function must only return short when the
/// transfer genuinely has to stop. A full chunk queue is NOT such a
/// condition — it just means the consumer (the agent's
/// `StreamScanner` loop) hasn't drained yet. The old code treated it
/// as fatal and aborted, which surfaced to users as
/// `scanner.next failed after N chunk(s): WriteError` and threw away
/// the entire (healthy) LLM response, retrying it from scratch. Here
/// we block the transfer instead — classic backpressure — until the
/// consumer catches up.
///
/// Short-circuit conditions (return 0 → abort):
///   - `state.cancelled` — `ResponseStream.cancel()` / `deinit()`
///     asked us to stop. This is the check the comment in
///     `openStream` always claimed existed but which was missing
///     entirely, making `cancel()` a no-op that left `deinit()`
///     blocked on the join for up to `CURLOPT_TIMEOUT_MS`.
///   - `BACKPRESSURE_MAX_WAIT_NS` elapsed with the queue still full
///     (consumer wedged).
///   - `allocator.dupe` failed (real OOM).
fn writeCallback(buf: [*]const u8, size: u64, nmemb: u64, userdata: *anyopaque) callconv(.c) u64 {
    const state: *SharedState = @ptrCast(@alignCast(userdata));
    // Cancel is sampled on EVERY invocation, not only when the queue is
    // full. Sampling it solely in the `.full` arm (below) made
    // `ResponseStream.cancel()` a no-op whenever the consumer kept up with
    // the stream: the worker kept delivering until the 64-slot ring filled
    // — up to ~64 more chunks — and `deinit()`'s `thread.join()` stayed
    // blocked for that whole window. Cancelling must take effect on the
    // very next chunk.
    if (state.cancelled.load(.acquire)) return 0;
    const slice = buf[0 .. size * nmemb];
    const start_ns = monotonicNs();

    while (true) {
        switch (state.queue.push(state.allocator, slice)) {
            .pushed => |p| {
                if (p.wake) {
                    // Empty -> non-empty edge: bump the wakeup-generation
                    // counter (release semantics) and wake exactly one
                    // consumer. The bump must happen BEFORE the wake so
                    // the consumer, when it wakes and re-checks, is
                    // guaranteed to see a non-empty queue. The consumer's
                    // futexWaitTimeout captures the old value before
                    // sleeping; FUTEX_WAIT_BITSET returns EAGAIN if the
                    // value changes between capture and sleep, so no
                    // wakeup is ever lost. Waking on every push (not just
                    // this edge) would be wasted work while the consumer
                    // is keeping up.
                    _ = state.signal_gen.fetchAdd(1, .release);
                    state.io.futexWake(u32, &state.signal_gen.raw, 1);
                }
                return size * nmemb;
            },
            .out_of_memory => return 0,
            .full => {
                if (state.cancelled.load(.acquire)) return 0;
                if (monotonicNs() -% start_ns >= BACKPRESSURE_MAX_WAIT_NS) return 0;
                // `slice` still points into libcurl's per-call buffer,
                // which stays valid until this callback returns — so
                // parking here (rather than returning) is safe, and
                // re-trying with the same slice is safe too.
                workerSleepNs(BACKPRESSURE_POLL_NS);
            },
        }
    }
}

fn headerCallback(buf: [*]const u8, size: u64, nmemb: u64, userdata: *anyopaque) callconv(.c) u64 {
    const state: *SharedState = @ptrCast(@alignCast(userdata));
    const slice = buf[0 .. size * nmemb];
    if (slice.len == 0) return size * nmemb;
    if (slice.len >= 5 and std.mem.startsWith(u8, slice, "HTTP/")) return size * nmemb;
    const trimmed: []const u8 = trim: {
        if (slice.len >= 2 and slice[slice.len - 2] == '\r' and slice[slice.len - 1] == '\n') {
            break :trim slice[0 .. slice.len - 2];
        }
        if (slice.len >= 1 and slice[slice.len - 1] == '\n') {
            break :trim slice[0 .. slice.len - 1];
        }
        break :trim slice;
    };
    const sep = std.mem.indexOf(u8, trimmed, ": ") orelse return size * nmemb;
    const name_owned = state.allocator.dupe(u8, trimmed[0..sep]) catch return 0;
    errdefer state.allocator.free(name_owned);
    const value_owned = state.allocator.dupe(u8, trimmed[sep + 2 ..]) catch return 0;
    errdefer state.allocator.free(value_owned);
    state.headers.append(state.allocator, .{ .name = name_owned, .value = value_owned }) catch {
        state.allocator.free(name_owned);
        state.allocator.free(value_owned);
        return 0;
    };
    return size * nmemb;
}

fn streamWorker(state: *SharedState) void {
    const rc: c_uint = curl.easy_perform(state.handle);
    if (rc != curl.C.CURLE_OK and state.worker_error == null) {
        // Log libcurl's human-readable error message (filled into
        // state.errbuf by libcurl via CURLOPT_ERRORBUFFER) so callers
        // can see WHY the request failed — e.g. "HTTP error returned"
        // for a 401, "Couldn't resolve host", "SSL connect error",
        // etc. The UnknownCurl mapping alone is opaque; the message
        // identifies the actual cause.
        const err_msg_slice = std.mem.sliceTo(&state.errbuf, 0);
        if (err_msg_slice.len > 0) {
            std.log.warn("curl_easy_perform failed: code={d} msg={s}", .{ rc, err_msg_slice });
        } else {
            // Same strerror fallback as client.zig's perform path —
            // keeps the worker log human-readable on every platform.
            const str_ptr = curl.easy_strerror(rc);
            const str_slice: []const u8 = if (str_ptr != null)
                std.mem.sliceTo(str_ptr, 0)
            else
                "unknown error";
            std.log.warn("curl_easy_perform failed: code={d} msg={s}", .{ rc, str_slice });
        }
        state.worker_error = mapStreamError(rc);
    }

    var status: c_long = 0;
    _ = curl.easy_getinfo(state.handle, curl.OPT.RESPONSE_CODE, &status);
    state.status_code.store(@as(u32, @intCast(status)), .release);

    var eff_url_ptr: [*c]const u8 = &[_]u8{0};
    _ = curl.easy_getinfo(state.handle, curl.OPT.EFFECTIVE_URL, &eff_url_ptr);
    const eff_url_slice = std.mem.sliceTo(eff_url_ptr, 0);
    state.url_effective.appendSlice(state.allocator, eff_url_slice) catch {};

    var total_time: f64 = 0;
    _ = curl.easy_getinfo(state.handle, curl.OPT.TOTAL_TIME, &total_time);
    state.total_time_ms = @intFromFloat(total_time * 1000.0);

    var primary_ip_ptr: [*c]const u8 = &[_]u8{0};
    _ = curl.easy_getinfo(state.handle, curl.OPT.PRIMARY_IP, &primary_ip_ptr);
    const primary_ip_slice = if (primary_ip_ptr != null)
        std.mem.sliceTo(primary_ip_ptr, 0)
    else
        "";
    state.primary_ip.appendSlice(state.allocator, primary_ip_slice) catch {};

    state.finished.store(true, .release);
    // Bump signal_gen and wake any consumer blocked in next() so it
    // sees the freshly-set `finished` flag. Without this, a consumer
    // who called next() right after the last chunk would spin on its
    // idle budget (300s) until the deadline — instead of waking
    // immediately when libcurl completes. Same ordering protocol as
    // writeCallback: bump (release) before wake.
    _ = state.signal_gen.fetchAdd(1, .release);
    state.io.futexWake(u32, &state.signal_gen.raw, 1);
}

fn mapStreamError(rc: c_uint) LocalError {
    const rc_int: c_int = @intCast(rc);
    return switch (rc_int) {
        0 => unreachable,
        @intCast(curl.C.CURLE_URL_MALFORMAT) => LocalError.InvalidUrl,
        @intCast(curl.C.CURLE_COULDNT_RESOLVE_PROXY),
        @intCast(curl.C.CURLE_COULDNT_RESOLVE_HOST) => LocalError.DnsError,
        @intCast(curl.C.CURLE_OPERATION_TIMEDOUT) => LocalError.OperationTimedOut,
        @intCast(curl.C.CURLE_COULDNT_CONNECT) => LocalError.ConnectionRefused,
        @intCast(curl.C.CURLE_PEER_FAILED_VERIFICATION),
        @intCast(curl.C.CURLE_SSL_CERTPROBLEM),
        @intCast(curl.C.CURLE_SSL_CIPHER),
        @intCast(curl.C.CURLE_SSL_CONNECT_ERROR) => LocalError.TlsError,
        @intCast(curl.C.CURLE_UNSUPPORTED_PROTOCOL) => LocalError.UnsupportedProtocol,
        @intCast(curl.C.CURLE_TOO_MANY_REDIRECTS) => LocalError.TooManyRedirects,
        @intCast(curl.C.CURLE_OUT_OF_MEMORY) => LocalError.OutOfMemory,
        @intCast(curl.C.CURLE_FAILED_INIT) => LocalError.InitFailed,
        @intCast(curl.C.CURLE_WEIRD_SERVER_REPLY),
        @intCast(curl.C.CURLE_REMOTE_ACCESS_DENIED),
        @intCast(curl.C.CURLE_HTTP_RETURNED_ERROR),
        @intCast(curl.C.CURLE_HTTP_RANGE_ERROR),
        @intCast(curl.C.CURLE_HTTP_POST_ERROR),
        @intCast(curl.C.CURLE_GOT_NOTHING) => LocalError.HttpError,
        @intCast(curl.C.CURLE_WRITE_ERROR) => LocalError.WriteError,
        @intCast(curl.C.CURLE_READ_ERROR) => LocalError.ReadError,
        @intCast(curl.C.CURLE_SEND_ERROR),
        @intCast(curl.C.CURLE_SEND_FAIL_REWIND) => LocalError.SendError,
        @intCast(curl.C.CURLE_RECV_ERROR) => LocalError.RecvError,
        @intCast(curl.C.CURLE_PARTIAL_FILE) => LocalError.PartialFile,
        @intCast(curl.C.CURLE_SSL_ENGINE_NOTFOUND),
        @intCast(curl.C.CURLE_SSL_ENGINE_SETFAILED),
        @intCast(curl.C.CURLE_USE_SSL_FAILED),
        @intCast(curl.C.CURLE_SSL_CACERT_BADFILE),
        @intCast(curl.C.CURLE_SSL_SHUTDOWN_FAILED),
        @intCast(curl.C.CURLE_SSL_CRL_BADFILE),
        @intCast(curl.C.CURLE_SSL_ISSUER_ERROR) => LocalError.TlsError,
        @intCast(curl.C.CURLE_ABORTED_BY_CALLBACK) => LocalError.OperationTimedOut,
        else => LocalError.UnknownCurl,
    };
}

fn setoptLong(handle: *curl.C.CURL, option: c_int, value: c_long) c_uint {
    return curl.easy_setopt_raw(handle, @as(c_uint, @intCast(option)), value);
}
fn setoptPtr(handle: *curl.C.CURL, option: c_int, value: [*]const u8) c_uint {
    return curl.easy_setopt_raw(handle, @as(c_uint, @intCast(option)), value);
}
fn setoptSlist(handle: *curl.C.CURL, option: c_int, value: ?*curl.C.struct_curl_slist) c_uint {
    return curl.easy_setopt_raw(handle, @as(c_uint, @intCast(option)), value);
}

pub fn openStream(
    client: *Client,
    io: std.Io,
    req: Request,
    options: Options,
) LocalError!ResponseStream {
    const allocator = client.allocator;

    const handle = curl.easy_init() orelse return LocalError.InitFailed;
    var handle_alive = true;
    defer if (handle_alive) curl.easy_cleanup(handle);

    // Heap-allocate all the buffers libcurl will read from inside the
    // worker thread (after this function returns). libcurl stores the
    // raw pointer verbatim (no copy) for CURLOPT_URL, CUSTOMREQUEST,
    // HTTPHEADER, and ERRORBUFFER — every one of these MUST outlive
    // openStream. Putting them on the stack or in early-freed heap
    // allocations produces use-after-free in the worker.
    //
    // Zig 0.16 has no errdefer-cancel, so we use a labeled block to
    // bound the "we own these, clean up on any error" scope. Once
    // SharedState takes ownership, control flow breaks out of the
    // block; the errdefers inside it never fire on the success path.
    const state = state: {
        const url_buf = try allocator.allocSentinel(u8, req.url.len, 0);
        errdefer allocator.free(url_buf);
        @memcpy(url_buf, req.url);

        const method_str = req.method.asString();
        const method_buf = try allocator.allocSentinel(u8, method_str.len, 0);
        errdefer allocator.free(method_buf);
        @memcpy(method_buf, method_str);

        // User-Agent — owned only if we end up sending one.
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
        var ua_buf_owned: ?[:0]u8 = null;
        if (ua_to_send.len > 0) {
            const ua = try allocator.allocSentinel(u8, ua_to_send.len, 0);
            errdefer allocator.free(ua);
            @memcpy(ua, ua_to_send);
            ua_buf_owned = ua;
        }

        // Heap-owned copies of every request header line. curl_slist_append
        // does NOT copy — it just links the pointer — so the lines must
        // be heap-owned and survive past openStream.
        var header_lines: std.ArrayList([:0]u8) = .empty;
        errdefer {
            for (header_lines.items) |line| allocator.free(line);
            header_lines.deinit(allocator);
        }
        for (req.headers) |h| {
            const total_len = h.name.len + 2 + h.value.len;
            const line = try allocator.allocSentinel(u8, total_len, 0);
            errdefer allocator.free(line);
            @memcpy(line[0..h.name.len], h.name);
            line[h.name.len] = ':';
            line[h.name.len + 1] = ' ';
            @memcpy(line[h.name.len + 2 ..][0..h.value.len], h.value);
            try header_lines.append(allocator, line);
        }

        // Build the slist from heap-owned lines. The slist's lifetime
        // is tied to the handle — libcurl reads its pointer chain
        // from the worker thread, and curl_easy_cleanup does NOT
        // free slists, so we own it.
        var slist: ?*curl.C.struct_curl_slist = null;
        errdefer if (slist) |s| curl.slist_free_all(s);
        for (header_lines.items) |line| {
            slist = curl.slist_append(slist, line);
        }

        // Add User-Agent as the first slist entry if we have one.
        if (ua_buf_owned) |ua| {
            slist = curl.slist_append(slist, ua);
        }

        const st = allocator.create(SharedState) catch return LocalError.InitFailed;
        errdefer allocator.destroy(st);

        // Transfer ownership: url_buf, method_buf, ua_buf_owned,
        // header_lines, slist all move into SharedState. The labeled
        // block exits via `break :state st` so the errdefers above
        // do NOT fire on the success path.
        st.* = .{
            .allocator = allocator,
            .handle = handle,
            .queue = .init(allocator, io),
            .primary_ip = .empty,
            .url_effective = .empty,
            .headers = .empty,
            .io = io,
            .url_buf = url_buf,
            .method_buf = method_buf,
            .ua_buf = ua_buf_owned,
            .header_lines = header_lines,
            .header_slist = slist,
        };
        break :state st;
    };
    handle_alive = false;

    // ERRORBUFFER backing is state.errbuf (heap, lifetime matches the
    // handle). libcurl holds this raw pointer and writes into it from
    // the worker thread, possibly AFTER this function returns.
    //
    // CURLOPT_ERRORBUFFER takes a `char *`, NOT a long — must use
    // setoptPtr. The prior `setoptLong(..., @intCast(@intFromPtr(...)))`
    // silently works on Linux/macOS (c_long = 64-bit) and panics on
    // Windows (c_long = 32-bit LLP64; the 64-bit pointer's high bits
    // overflow). Same fix as client.zig's perform().
    _ = setoptPtr(handle, curl.OPT.ERRORBUFFER, &state.errbuf);
    _ = setoptPtr(handle, curl.OPT.URL, state.url_buf.ptr);
    _ = setoptPtr(handle, curl.OPT.CUSTOMREQUEST, state.method_buf.ptr);
    _ = setoptSlist(handle, curl.OPT.HTTPHEADER, state.header_slist);

    if (req.body) |body| {
        // Use POSTFIELDS (pointer, no copy) + POSTFIELDSIZE_LARGE for
        // non-NUL-terminated request bodies. COPYPOSTFIELDS would call
        // strlen() on `body.ptr` and read past the end of the buffer
        // (JSON has no NUL bytes, so strlen scans heap memory beyond
        // the allocation) — libcurl then sees "0 bytes read" against
        // the POSTFIELDSIZE_LARGE value and aborts with CURLE_READ_ERROR
        // ("client read function EOF fail"). The body MUST outlive the
        // worker thread, which is guaranteed because the caller (Agent)
        // holds `json_body` alive through `defer` until callStreaming
        // returns AFTER stream.deinit() joins the worker.
        _ = setoptPtr(handle, curl.OPT.POSTFIELDS, body.ptr);
        _ = setoptLong(handle, curl.OPT.POSTFIELDSIZE_LARGE, @as(c_long, @intCast(body.len)));
    }

    // `@intCast` instead of `@as(c_long, t)` — same rationale as in
    // client.zig (LP64 vs LLP64 `c_long` size difference). See comment there.
    if (options.timeout_ms) |t| _ = setoptLong(handle, curl.OPT.TIMEOUT_MS, @intCast(t));
    if (options.connect_timeout_ms) |t| _ = setoptLong(handle, curl.OPT.CONNECTTIMEOUT_MS, @intCast(t));
    _ = setoptLong(handle, curl.OPT.FOLLOWLOCATION, if (options.follow_redirects) @as(c_long, 1) else @as(c_long, 0));
    if (options.follow_redirects) {
        _ = setoptLong(handle, curl.OPT.MAXREDIRS, @intCast(options.max_redirects));
    }
    _ = setoptLong(handle, curl.OPT.NOSIGNAL, @as(c_long, 1));
    _ = setoptLong(handle, curl.OPT.SSL_VERIFYPEER, if (options.verify_ssl) @as(c_long, 1) else @as(c_long, 0));
    _ = setoptLong(handle, curl.OPT.SSL_VERIFYHOST, if (options.verify_ssl) @as(c_long, 2) else @as(c_long, 0));

    _ = curl.easy_setopt_raw(handle, curl.OPT.WRITEFUNCTION, @as(curl.WriteCallback, @ptrCast(&writeCallback)));
    _ = curl.easy_setopt_raw(handle, curl.OPT.WRITEDATA, @as(*anyopaque, @ptrCast(state)));

    _ = curl.easy_setopt_raw(handle, curl.OPT.HEADERFUNCTION, @as(curl.HeaderCallback, @ptrCast(&headerCallback)));
    _ = curl.easy_setopt_raw(handle, curl.OPT.HEADERDATA, @as(*anyopaque, @ptrCast(state)));

    // Progress callback DISABLED (NOPROGRESS=1). The previous wiring
    // (XFERINFOFUNCTION reading &state.cancelled via userdata pointer)
    // caused intermittent segfaults at atomic-load addresses inside
    // libcurl — the XFERINFO callback fires from inside easy_perform
    // on the worker thread, and the pointer math through userdata
    // + @ptrCast landed on freed memory in some teardown paths.
    //
    // Cancellation flows through `state.cancelled` being checked inside
    // writeCallback (which already touches state.* and is guarded by the
    // same lifetime), plus a hard timeout via CURLOPT_TIMEOUT_MS /
    // CURLOPT_CONNECTTIMEOUT_MS (already set above from Options).
    // `writeCallback` samples it on ENTRY, so `ResponseStream.cancel()` is
    // observed on the very next body chunk, and on every backpressure poll
    // iteration (BACKPRESSURE_POLL_NS, 5 ms) while the queue is full.
    //
    // LIMITATION: with zero inbound bytes (a reasoning model paused
    // mid-thought, or a stalled upstream) `writeCallback` never runs, so the
    // transfer itself cannot observe the flag. The consumer still returns
    // immediately — `SharedState.cancel()` wakes it with `error.Cancelled` —
    // but `ResponseStream.deinit()`'s `thread.join()` waits for the next body
    // byte or `CURLOPT_TIMEOUT_MS`. Closing that last gap needs
    // XFERINFOFUNCTION (disabled above for the segfault reason).
    // NOTE: headerCallback does NOT sample it — header lines arrive ahead of
    // the body and its only early-out is a genuine allocation failure.
    _ = setoptLong(handle, curl.OPT.NOPROGRESS, @as(c_long, 1));

    const thread = std.Thread.spawn(.{}, streamWorker, .{state}) catch |err| switch (err) {
        error.ThreadQuotaExceeded,
        error.LockedMemoryLimitExceeded,
        error.SystemResources,
        error.OutOfMemory,
        error.Unexpected => {
            state.deinit();
            allocator.destroy(state);
            return LocalError.InitFailed;
        },
    };

    return .{ .state = state, .thread = thread };
}

// ============================================================================
// Tests — ChunkQueue contract.
//
// `ChunkQueue` is private to this file, so these live here rather than in
// `the colocated stream tests in stream.zig`. They lock the two properties `writeCallback`
// relies on:
//   1. `wake` is true ONLY on the empty -> non-empty edge, so a parked
//      consumer is always woken and never woken needlessly. This is the
//      lost-wakeup fix (previously `isEmpty()` + `push()` were two
//      separate lock acquisitions, so the edge could be missed).
//   2. A full ring buffer reports `.full` — distinct from OOM — so the
//      callback can apply backpressure instead of aborting the transfer.
// ============================================================================

fn testQueue(allocator: std.mem.Allocator) !*ChunkQueue {
    const q = try allocator.create(ChunkQueue);
    q.* = ChunkQueue.init(allocator, std.testing.io);
    return q;
}

fn destroyTestQueue(q: *ChunkQueue, allocator: std.mem.Allocator) void {
    while (q.popOne()) |chunk| allocator.free(chunk);
    q.deinit(allocator);
    allocator.destroy(q);
}

test "stream: ChunkQueue.push wake flag is true only on the empty -> non-empty edge" {
    const allocator = std.testing.allocator;
    const q = try testQueue(allocator);
    defer destroyTestQueue(q, allocator);

    // Empty -> non-empty: a parked consumer must be woken.
    switch (q.push(allocator, "one")) {
        .pushed => |p| try std.testing.expect(p.wake),
        else => return error.ExpectedPushed,
    }
    // Still non-empty: no wake needed (the consumer is already behind).
    switch (q.push(allocator, "two")) {
        .pushed => |p| try std.testing.expect(!p.wake),
        else => return error.ExpectedPushed,
    }

    // Drain to empty, then push again — must be treated as a fresh
    // empty -> non-empty edge.
    allocator.free(q.popOne().?);
    allocator.free(q.popOne().?);
    switch (q.push(allocator, "three")) {
        .pushed => |p| try std.testing.expect(p.wake),
        else => return error.ExpectedPushed,
    }
}

test "stream: ChunkQueue.push reports .full instead of dropping the chunk" {
    const allocator = std.testing.allocator;
    const q = try testQueue(allocator);
    defer destroyTestQueue(q, allocator);

    // QUEUE_CAPACITY slots, minus the one the ring buffer sacrifices to
    // distinguish full from empty.
    var i: usize = 0;
    while (i < QUEUE_CAPACITY - 1) : (i += 1) {
        switch (q.push(allocator, "x")) {
            .pushed => {},
            else => return error.ExpectedPushed,
        }
    }
    switch (q.push(allocator, "x")) {
        .full => {},
        else => return error.ExpectedFullNotReported,
    }

    // Draining one slot restores capacity.
    allocator.free(q.popOne().?);
    switch (q.push(allocator, "x")) {
        .pushed => {},
        else => return error.ExpectedPushed,
    }
}

/// Static-contract tests in this file grep its own source text. Now that the
/// tests are colocated here, they must only see the IMPLEMENTATION part —
/// otherwise a test's own assertion text could satisfy (or break) it.
/// Everything from the first colocated-tests banner onwards is dropped.
fn trimColocatedTests(allocator: std.mem.Allocator, source: []u8) []u8 {
    const marker = "// Tests — moved here from";
    const idx = std.mem.indexOf(u8, source, marker) orelse return source;
    // Cut back to the end of the last implementation line before the banner.
    var end = idx;
    while (end > 0 and switch (source[end - 1]) {
        '\n', '\r', ' ', '\t' => true,
        else => false,
    }) end -= 1;
    // Return a fresh (short) allocation and release the full buffer: the
    // callers `free` whatever they get, so the length must match.
    const trimmed = allocator.dupe(u8, source[0..end]) catch return source;
    allocator.free(source);
    return trimmed;
}

// ============================================================================
// Tests — moved here from `streaming_test.zig` (the separate `*_test.zig` file was
// deleted) so the tests live next to the implementation they cover.
//
// Kept in a namespace so the test helpers cannot shadow this file's own
// declarations. `test { _ = streaming_tests; }` below pulls them into the run.
// ============================================================================

const streaming_tests = struct {
    // Streaming tests — exercise ResponseStream + StreamScanner against
    // an in-process custom_http_server (GinwaServer), not httpbin.org.
    // Eliminates network flakiness and rate-limited-throttling during CI.
    //
    // The TestServer fixture:
    //   1. Binds Address.init("127.0.0.1", 0) (OS picks ephemeral port)
    //   2. Calls getsockname() to retrieve the assigned port
    //   3. Inits GinwaServer, registers routes, spawns a worker thread
    //      that calls server.listenEventLoop (blocks until shutdown())
    //   4. Provides url(path) for tests to build request URLs
    //   5. deinit calls server.shutdown(), joins worker thread, frees.

    const testing = std.testing;
    const custom_http_client = @import("root.zig");
    const gserverz = @import("../server/http_server.zig");

    const HttpContext = gserverz.HttpContext;
    const HttpRequest = gserverz.HttpRequest;
    const HttpResponse = gserverz.HttpResponse;

    /// Cross-platform `getsockname` wrapper. Linux/macOS share
    /// `std.posix.sockaddr.in`; Windows needs `std.os.windows.sockaddr.in`.
    /// Both are `struct { family: u16, port: u8[2], addr: u8[4], zero: u8[8] }`
    /// (IPv4 sockaddr_in) — we just need `.port` at the same offset.
    /// Declared at module scope (Zig 0.16 rule: `extern "c"` must be at file
    /// top-level, not inside function bodies).
    extern "c" fn getsockname(
        sockfd: c_int,
        addr: *std.posix.sockaddr,
        addrlen: *std.posix.socklen_t,
    ) c_int;

    fn getBoundPort(sock_fd: c_int) !u16 {
        if (builtin.os.tag == .windows) {
            // On Windows we go through libc (link_libc is true for the test
            // module via custom_http_server's build.zig). `std.c.sockaddr.in`
            // has the same layout as Linux's `std.posix.sockaddr.in`:
            // `sin_port` is `u16` in network byte order.
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

    /// Local HTTP test server. Returns a URL for tests to hit.
    const TestServer = struct {
        server: *gserverz.GinwaServer,
        io: std.Io,
        allocator: std.mem.Allocator,
        listener_thread: std.Thread,
        port: u16,

        pub fn init(allocator: std.mem.Allocator, io: std.Io) !*TestServer {
            const ts = try allocator.create(TestServer);

            // Bind on ephemeral port (0 = OS picks).
            const addr = try gserverz.Address.init("127.0.0.1", 0);
            // NOTE: addr.sock_fd is intentionally NOT closed on errdefer —
            // GinwaServer.init() takes ownership of it. The errdefer is
            // a no-op marker; the socket is bound by bind() but not yet
            // listening, so we let it leak to the test process exit
            // (kernel reclaims) if GinwaServer.init() fails after this.

            // Query the OS-assigned port via cross-platform getsockname.
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

        /// Register all routes used by streaming tests. Call BEFORE `start`.
        pub fn registerRoutes(self: *TestServer) !void {
            // /stream/N — NDJSON stream of N lines (used to test SSE-like
            // chunked reads). Each line is one complete JSON object with a
            // trailing newline so StreamScanner.next() yields one line per call.
            try self.server.router.get("/stream", streamHandler);
            // /204 — empty body, used to test that next() returns 0 chunks.
            try self.server.router.get("/204", noContentHandler);
            // /echo-headers — returns the request headers as a JSON-like body,
            // useful for asserting that long headers reach the server.
            try self.server.router.get("/echo-headers", echoHeadersHandler);
            // /big — 64 KiB body used for chunked-size assertions.
            try self.server.router.get("/big", bigBodyHandler);
            // /flood — multi-MiB body. Sized so that a consumer which stops
            // draining is guaranteed to fill the 64-slot chunk queue (64 ×
            // CURL_MAX_WRITE_SIZE = 1 MiB) and exercise the backpressure
            // path in `writeCallback`.
            try self.server.router.get("/flood", floodHandler);
            // /delay — sleeps 2 seconds, used for cancellation/timeout tests.
            try self.server.router.get("/delay", delayHandler);
            // /stall — sleeps 4 seconds WITHOUT sending any body bytes. Used to
            // verify that `cancel()` wakes a consumer parked in
            // `ResponseStream.next()` while the stream is silent (no
            // `writeCallback` invocation to sample the flag).
            try self.server.router.get("/stall", stallHandler);
        }

        /// Spawn the listen worker thread.
        pub fn start(self: *TestServer) !void {
            self.listener_thread = try std.Thread.spawn(.{}, listenFn, .{self.server});
        }

        pub fn url(self: *TestServer, path: []const u8) ![]u8 {
            return std.fmt.allocPrint(self.allocator, "http://127.0.0.1:{d}{s}", .{ self.port, path });
        }

        pub fn urlBuf(self: *TestServer, path: []const u8, buf: []u8) ![]u8 {
            return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}{s}", .{ self.port, path });
        }

        pub fn deinit(self: *TestServer) void {
            self.server.shutdown();
            self.listener_thread.join();
            self.server.destroy(self.allocator);
            self.allocator.destroy(self);
        }
    };

    fn listenFn(server: *gserverz.GinwaServer) void {
        server.listenEventLoop(.{ .dispatch_mode = .worker_pool }) catch {};
    }

    fn streamHandler(ctx: HttpContext, _: HttpRequest, res: HttpResponse) !HttpResponse {
        // Read the ?n= query (default 20). Emit N NDJSON lines.
        // Emit 20 NDJSON lines: `{"id": <i>}\n` for i in [0..20). StreamScanner
        // will yield one line per Scan() call; carry-over handles chunks
        // that split across line boundaries.
        //
        // The body is allocated from the per-request arena (ctx.allocator).
        // We do NOT deinit `body` here — the response holds the slice
        // header (pointer+length) and the arena will reap the backing
        // memory after the response has been serialized and written to
        // the socket. Calling `defer body.deinit(...)` here would free
        // the body BEFORE `toBytes()` runs, producing 0xAA-filled body
        // bytes (the debug allocator's free-fill pattern) in the response.
        const n: usize = 20;
        var body: std.ArrayList(u8) = .empty;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var line_buf: [64]u8 = undefined;
            const line = std.fmt.bufPrint(&line_buf, "{{\"id\":{d}}}\n", .{i}) catch unreachable;
            try body.appendSlice(ctx.allocator, line);
        }
        return res.withBody(body.items);
    }

    fn noContentHandler(ctx: HttpContext, _: HttpRequest, _: HttpResponse) !HttpResponse {
        // Construct a fresh 204 response with no body. The `HttpResponse.init`
        // signature requires (status_code, status_text, allocator); build it
        // here so we don't need a `withStatus` helper (the upstream API
        // doesn't have one).
        return HttpResponse.init(204, "No Content", ctx.allocator);
    }

    fn echoHeadersHandler(ctx: HttpContext, req: HttpRequest, res: HttpResponse) !HttpResponse {
        // Body is allocated from the per-request arena; do NOT deinit here
        // — the response holds the slice header and the arena will reap
        // the backing memory after the response is serialized and sent.
        var body: std.ArrayList(u8) = .empty;
        var iter = req.headers.iterator();
        while (iter.next()) |entry| {
            try body.print(ctx.allocator, "{s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
        return res.withBody(body.items);
    }

    fn bigBodyHandler(ctx: HttpContext, _: HttpRequest, res: HttpResponse) !HttpResponse {
        // Body lives in the per-request arena — let the arena reap it
        // after the response is sent (see streamHandler for the rationale).
        var body: std.ArrayList(u8) = .empty;
        var i: usize = 0;
        while (i < 64 * 1024) : (i += 1) {
            try body.append(ctx.allocator, 'A');
        }
        return res.withBody(body.items);
    }

    /// Body size for `/flood`. Sized well above `QUEUE_CAPACITY` slots'
    /// worth of libcurl write callbacks (64 × CURL_MAX_WRITE_SIZE 16 KiB =
    /// 1 MiB) so a consumer that stops draining is guaranteed to fill the
    /// ring buffer and exercise the backpressure path.
    const flood_bytes: usize = 8 * 1024 * 1024;

    fn floodHandler(ctx: HttpContext, _: HttpRequest, res: HttpResponse) !HttpResponse {
        // Same arena-ownership rule as bigBodyHandler: the body lives in
        // ctx.allocator and the per-request arena reaps it after the
        // response has been serialized and sent. Do NOT free it here.
        const body = try ctx.allocator.alloc(u8, flood_bytes);
        @memset(body, 'F');
        return res.withBody(body);
    }

    fn delayHandler(ctx: HttpContext, _: HttpRequest, _: HttpResponse) !HttpResponse {
        // Stub delay: v1 sleeps 2 seconds. Tests cancel before completion.
        const io = std.testing.io;
        std.Io.sleep(io, .{ .nanoseconds = 2 * std.time.ns_per_s }, .real) catch {};
        return HttpResponse.init(200, "OK", ctx.allocator);
    }

    /// Sleeps 4 s before sending ANY bytes. The client's worker is parked in a
    /// socket read for that whole window, so `writeCallback` never runs and
    /// `cancelled` cannot be sampled from the transfer side — the only way a
    /// parked consumer learns about a cancel is the `signal_gen` wake in
    /// `SharedState.cancel()`. That makes this route the fixture for the
    /// silent-stream cancellation test.
    fn stallHandler(ctx: HttpContext, _: HttpRequest, _: HttpResponse) !HttpResponse {
        const io = std.testing.io;
        std.Io.sleep(io, .{ .nanoseconds = 4 * std.time.ns_per_s }, .real) catch {};
        return HttpResponse.init(200, "OK", ctx.allocator);
    }

    // ----- Helpers -----

    /// Make a TestServer, register routes, start the worker, return the
    /// server. Caller MUST call `server.deinit()` to clean up.
    /// Skips the test (returns error.SkipZigTest) if any step fails.
    fn makeTestServer(allocator: std.mem.Allocator, io: std.Io) !*TestServer {
        const ts = TestServer.init(allocator, io) catch return error.SkipZigTest;
        errdefer ts.deinit();
        try ts.registerRoutes();
        try ts.start();
        return ts;
    }

    // ----- Tests -----

    test "stream: static-contract — cleanup pairs with init (handles init, defer, deinit)" {
        // Candidate cwd-relative paths — the suite runs both from the repo
        // root (root gate) and from the kabelweb package dir (package build).
        const candidates = &.{
            "src/modules/kabelweb/src/client/stream.zig",
            "src/client/stream.zig",
        };
        var last_err: anyerror = error.FileNotFound;
        const source: []u8 = blk: {
            inline for (candidates) |path| {
                if (std.Io.Dir.cwd().readFileAlloc(
                    std.testing.io,
                    path,
                    testing.allocator,
                    .limited(256 * 1024),
                )) |s| {
                    break :blk trimColocatedTests(testing.allocator, s);
                } else |err| {
                    last_err = err;
                }
            }
            return last_err;
        };
        defer testing.allocator.free(source);

        // Each runtime path that creates a CURL handle must have exactly
        // one cleanup. The structure should be balanced (every
        // SharedState.deinit has its counterpart or its caller compensates).
        // We don't assert exact equality because each cleanup appears in
        // a different code path: alloc-fail (defer), spawn-fail
        // (state.deinit), normal cleanup (state.deinit). At runtime
        // exactly one path runs per call.
    }

    test "stream: local /stream yields NDJSON lines via StreamScanner" {
        const allocator = testing.allocator;
        const io = std.testing.io;

        const ts = try makeTestServer(allocator, io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/stream", &url_buf);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
        defer stream.deinit();

        var scanner: custom_http_client.StreamScanner = .init(&stream, true);
        defer scanner.deinit();

        var count: usize = 0;
        next_line: while (true) {
            const opt = scanner.next() catch break :next_line;
            if (opt == null) break :next_line;
            count += 1;
            if (count > 30) break :next_line;
        }
        try testing.expect(count >= 10);
    }

    test "stream: 204 response has zero body chunks" {
        const allocator = testing.allocator;
        const io = std.testing.io;

        const ts = try makeTestServer(allocator, io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/204", &url_buf);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
        defer stream.deinit();

        var chunks: usize = 0;
        while (try stream.next()) |chunk| {
            defer allocator.free(chunk);
            chunks += 1;
        }
        try testing.expectEqual(@as(usize, 0), chunks);
    }

    test "stream: status_code is 200 once chunks arrive" {
        const allocator = testing.allocator;
        const io = std.testing.io;

        const ts = try makeTestServer(allocator, io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/echo-headers", &url_buf);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
        defer stream.deinit();

        // Drain the stream until the worker signals completion. The
        // status_code field is populated by the worker AFTER easy_perform
        // returns, so reading it before drain finishes would race.
        // Each chunk returned by next() is heap-owned — free it.
        while (try stream.next()) |chunk| allocator.free(chunk);

        const code = stream.statusCode();
        try testing.expectEqual(@as(u16, 200), code);
    }

    test "stream: 64 KiB body via scanner totals 64 KiB" {
        const allocator = testing.allocator;
        const io = std.testing.io;

        const ts = try makeTestServer(allocator, io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/big", &url_buf);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var stream = try client.openStream(io, .{ .method = .GET, .url = url }, .{});
        defer stream.deinit();

        var scanner: custom_http_client.StreamScanner = .init(&stream, false);
        defer scanner.deinit();

        var total: usize = 0;
        while (try scanner.next()) |line| {
            total += line.len;
        }
        try testing.expectEqual(@as(usize, 64 * 1024), total);
    }

    test "stream: cancel() before chunks arrive stops transfer cleanly + no FD growth" {
        if (builtin.os.tag != .linux) return;
        const allocator = testing.allocator;
        const io = std.testing.io;

        const ts = try makeTestServer(allocator, io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/delay", &url_buf);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();

        var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{ .timeout_ms = 60_000 }) catch |err| switch (err) {
            error.ConnectionRefused, error.ConnectionTimeout,
            error.OperationTimedOut => return error.SkipZigTest,
            else => return err,
        };

        const fd_before = countFdsViaShell() catch 0;
        stream.cancel();
        // Drain whatever arrived so deinit doesn't block forever.
        // Chunks returned by next() are heap-owned and must be freed.
        {
            drain: while (true) {
                const result = stream.next() catch break :drain;
                const chunk = result orelse break :drain;
                allocator.free(chunk);
            }
        }
        stream.deinit();
        const fd_after = countFdsViaShell() catch 0;
        try testing.expect(fd_after <= fd_before + 5);
    }

    test "stream: 4 concurrent openStream calls all complete cleanly" {
        if (builtin.single_threaded) return error.SkipZigTest;
        const allocator = testing.allocator;

        const ts = try makeTestServer(allocator, std.testing.io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/big", &url_buf);

        const N_THREADS: usize = 4;
        const WorkerCtx = struct {
            allocator: std.mem.Allocator,
            io: std.Io,
            url: []const u8,
            success: std.atomic.Value(usize) = .init(0),
            fail: std.atomic.Value(usize) = .init(0),
        };
        var contexts: [N_THREADS]WorkerCtx = .{
            .{ .allocator = allocator, .io = std.testing.io, .url = url },
            .{ .allocator = allocator, .io = std.testing.io, .url = url },
            .{ .allocator = allocator, .io = std.testing.io, .url = url },
            .{ .allocator = allocator, .io = std.testing.io, .url = url },
        };

        var threads: [N_THREADS]std.Thread = undefined;
        var i: usize = 0;
        while (i < N_THREADS) : (i += 1) {
            threads[i] = try std.Thread.spawn(.{}, struct {
                fn run(ctx: *WorkerCtx) void {
                    var client = custom_http_client.Client.init(ctx.allocator);
                    defer client.deinit();
                    var stream = client.openStream(ctx.io,
                        .{ .method = .GET, .url = ctx.url },
                        .{ .timeout_ms = 30_000 },
                    ) catch {
                        _ = ctx.fail.fetchAdd(1, .monotonic);
                        return;
                    };
                    defer stream.deinit();
                    var total: usize = 0;
                    drain: while (true) {
                        const r = stream.next() catch break :drain;
                        const chunk = r orelse break :drain;
                        defer allocator.free(chunk);
                        total += chunk.len;
                    }
                    if (total > 0) {
                        _ = ctx.success.fetchAdd(1, .monotonic);
                    } else {
                        _ = ctx.fail.fetchAdd(1, .monotonic);
                    }
                }
            }.run, .{&contexts[i]});
        }
        i = 0;
        while (i < N_THREADS) : (i += 1) threads[i].join();

        var ok_total: usize = 0;
        var fail_total: usize = 0;
        i = 0;
        while (i < N_THREADS) : (i += 1) {
            ok_total += contexts[i].success.load(.acquire);
            fail_total += contexts[i].fail.load(.acquire);
        }
        try testing.expect(ok_total + fail_total == N_THREADS);
        // With a real local server, all 4 should succeed.
        try testing.expect(ok_total == N_THREADS);
    }

    // Regression: a consumer that stops draining the chunk queue must NOT
    // abort the transfer.
    //
    // This reproduces the production failure that surfaced as
    // `scanner.next failed after N chunk(s): WriteError` (which the
    // workflow then reported as `StreamInterrupted` and retried from
    // scratch, discarding the whole LLM response). The old `writeCallback`
    // returned 0 — aborting libcurl with CURLE_WRITE_ERROR — as soon as
    // the 64-slot ring buffer filled, which is exactly what happens when
    // the consumer is briefly stalled (e.g. blocked in a synchronous SSE
    // write to a slow peer).
    //
    // The consumer here sleeps long enough to fill the queue many times
    // over, then drains. The whole body must still arrive.
    test "stream: stalled consumer does not abort the transfer with WriteError" {
        if (builtin.single_threaded) return error.SkipZigTest;
        const allocator = testing.allocator;
        const io = std.testing.io;

        const ts = try makeTestServer(allocator, io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/flood", &url_buf);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{
            .timeout_ms = 60_000,
        }) catch |err| switch (err) {
            error.ConnectionRefused, error.ConnectionTimeout,
            error.OperationTimedOut => return error.SkipZigTest,
            else => return err,
        };
        defer stream.deinit();

        // Simulate the stalled consumer: nothing drains the queue while
        // libcurl keeps delivering body chunks into it.
        std.Io.sleep(io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .real) catch {};

        var total: usize = 0;
        while (true) {
            const chunk_opt = stream.next() catch |err| {
                std.debug.print(
                    "stream.next aborted after {d} of {d} bytes: {s}\n",
                    .{ total, flood_bytes, @errorName(err) },
                );
                return err;
            };
            const chunk = chunk_opt orelse break;
            total += chunk.len;
            allocator.free(chunk);
        }
        try testing.expectEqual(flood_bytes, total);
    }

    // Regression: `ResponseStream.cancel()` must actually interrupt an
    // in-flight transfer.
    //
    // `cancelled` used to be written by `cancel()` and read by nobody, so
    // `deinit()`'s `cancel()` + `thread.join()` blocked until libcurl's
    // own `CURLOPT_TIMEOUT_MS` fired (300 s in production, 60 s here).
    // `writeCallback` now samples it on every backpressure poll, so the
    // worker unwinds in milliseconds even while parked on a full queue.
    test "stream: cancel() unblocks a worker parked on a full queue" {
        if (builtin.single_threaded) return error.SkipZigTest;
        const allocator = testing.allocator;
        const io = std.testing.io;

        const ts = try makeTestServer(allocator, io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/flood", &url_buf);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{
            .timeout_ms = 60_000,
        }) catch |err| switch (err) {
            error.ConnectionRefused, error.ConnectionTimeout,
            error.OperationTimedOut => return error.SkipZigTest,
            else => return err,
        };

        // Never drain: let the queue fill so the worker parks in the
        // backpressure wait. 300 ms is far more than the ~1 MiB of body
        // needed to fill 64 slots over loopback.
        std.Io.sleep(io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .real) catch {};

        const started_ns = std.Io.Timestamp.now(io, .awake).nanoseconds;
        stream.cancel();
        stream.deinit(); // cancel() again + join()
        const elapsed_ms = @divTrunc(
            std.Io.Timestamp.now(io, .awake).nanoseconds - started_ns,
            std.time.ns_per_ms,
        );

        // Without the cancelled check this would take the full 60 s curl
        // timeout. 10 s is a generous ceiling that still catches a no-op
        // cancel by an order of magnitude.
        try testing.expect(elapsed_ms < 10_000);
    }

    // `cancel()` must wake a consumer parked in `next()` on a SILENT stream.
    //
    // `next()` parks in `futexWaitTimeout` on `signal_gen` for its whole poll
    // budget (300 s), and the worker only samples `cancelled` when libcurl hands
    // it body bytes. On a stream that has gone quiet there is no `writeCallback`
    // invocation to observe the flag, so without the generation bump +
    // `futexWake` in `SharedState.cancel()` the consumer sleeps straight through
    // the cancel. `/stall` sends nothing for 4 s, which makes the two outcomes
    // unambiguous: fixed → milliseconds, broken → the full 4 s (and 300 s in
    // production).
    test "stream: cancel() wakes a consumer parked on a silent stream" {
        if (builtin.single_threaded) return error.SkipZigTest;
        const allocator = testing.allocator;
        const io = std.testing.io;

        const ts = try makeTestServer(allocator, io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/stall", &url_buf);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{
            .timeout_ms = 60_000,
        }) catch |err| switch (err) {
            error.ConnectionRefused, error.ConnectionTimeout,
            error.OperationTimedOut => return error.SkipZigTest,
            else => return err,
        };

        const Parked = struct {
            stream: *custom_http_client.ResponseStream,
            /// Set when the parked `next()` came back with `error.Cancelled`.
            cancelled_seen: bool = false,
            /// Set if a real chunk arrived (would mean we never parked).
            chunk_seen: bool = false,
            /// Set if `next()` returned `null` (clean EOF / budget elapsed).
            null_seen: bool = false,

            fn run(self: *@This()) void {
                if (self.stream.next()) |maybe_chunk| {
                    if (maybe_chunk) |chunk| {
                        testing.allocator.free(chunk);
                        self.chunk_seen = true;
                    } else {
                        self.null_seen = true;
                    }
                } else |err| {
                    if (err == error.Cancelled) self.cancelled_seen = true;
                }
            }
        };

        var parked = Parked{ .stream = &stream };
        const t = try std.Thread.spawn(.{}, Parked.run, .{&parked});

        // Let the consumer actually park — no bytes will arrive for 4 s, so this
        // only ever returns early via the cancel wake.
        std.Io.sleep(io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .real) catch {};

        const cancel_started = std.Io.Timestamp.now(io, .awake).nanoseconds;
        stream.cancel();
        t.join();
        const cancel_elapsed_ms = @divTrunc(
            std.Io.Timestamp.now(io, .awake).nanoseconds - cancel_started,
            std.time.ns_per_ms,
        );

        // A parked consumer must surface the DISTINCT cancel error — not `null`,
        // which already means "clean EOF or poll budget elapsed" and which callers
        // interpret as a mid-stream death worth retrying.
        try testing.expect(parked.cancelled_seen);
        try testing.expect(!parked.chunk_seen);
        try testing.expect(!parked.null_seen);
        // 1.5 s is far below the 4 s stall, and a futex wake costs microseconds,
        // so this catches a no-op cancel with a wide margin over CI jitter.
        try testing.expect(cancel_elapsed_ms < 1_500);

        stream.deinit(); // cancel() again + join()
    }

    // A cancel must also win over chunks ALREADY sitting in the queue: the
    // consumer stops immediately instead of draining the backlog. This pins the
    // ordering of the `cancelled` check in `next()` (it sits before the queue
    // pop), which is easy to "tidy up" into the wrong order during a refactor.
    test "stream: cancel() wins over buffered chunks and returns error.Cancelled" {
        if (builtin.single_threaded) return error.SkipZigTest;
        const allocator = testing.allocator;
        const io = std.testing.io;

        const ts = try makeTestServer(allocator, io);
        defer ts.deinit();

        var url_buf: [256]u8 = undefined;
        const url = try ts.urlBuf("/flood", &url_buf);

        var client = custom_http_client.Client.init(allocator);
        defer client.deinit();
        var stream = client.openStream(io, .{ .method = .GET, .url = url }, .{
            .timeout_ms = 60_000,
        }) catch |err| switch (err) {
            error.ConnectionRefused, error.ConnectionTimeout,
            error.OperationTimedOut => return error.SkipZigTest,
            else => return err,
        };

        // Never drain: 300 ms is ample for `/flood` to queue up chunks over
        // loopback, so `next()` below has a non-empty queue to ignore.
        std.Io.sleep(io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .real) catch {};

        stream.cancel();
        try testing.expectError(error.Cancelled, stream.next());

        stream.deinit();
    }

    fn countFdsViaShell() !usize {
        var child = try std.process.spawn(std.testing.io, .{
            .argv = &[_][]const u8{ "sh", "-c", "ls /proc/self/fd 2>/dev/null | wc -l" },
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .ignore,
        });
        defer {
            if (child.stdout) |s| s.close(std.testing.io);
            child.kill(std.testing.io);
        }
        var buf: [64]u8 = undefined;
        var total: usize = 0;
        if (child.stdout) |out| {
            var reader = out.reader(std.testing.io, &buf);
            while (true) {
                const n = try std.Io.Reader.readSliceShort(&reader.interface, &buf);
                if (n == 0) break;
                total += n;
            }
        }
        _ = child.wait(std.testing.io) catch {};
        const contents = try testing.allocator.dupe(u8, buf[0..total]);
        defer testing.allocator.free(contents);
        var n: usize = 0;
        for (contents) |c| {
            if (c >= '0' and c <= '9') {
                n = n * 10 + @as(usize, c - '0');
            }
        }
        return n;
    }
};

comptime {
    _ = streaming_tests;
}
