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

    fn cancel(self: *SharedState) void {
        self.cancelled.store(true, .release);
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
            // absorbed the bytes. Free it now.
            defer allocator.free(chunk);
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
    // Cancellation now flows through `state.cancelled` being checked
    // inside writeCallback (which already touches state.* and is
    // guarded by the same lifetime), plus a hard timeout via
    // CURLOPT_TIMEOUT_MS / CURLOPT_CONNECTTIMEOUT_MS (already set above
    // from Options). writeCallback samples it on every body chunk and
    // on every backpressure poll iteration, so `ResponseStream.cancel()`
    // is observed within BACKPRESSURE_POLL_NS (5 ms) even when the
    // consumer has stopped draining the queue. NOTE: headerCallback
    // does NOT sample it — header lines arrive ahead of the body and
    // its only early-out is a genuine allocation failure.
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
// `streaming_test.zig`. They lock the two properties `writeCallback`
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
