# Agent Memory Convention

## Request allocations

- Use Zig's standard `std.heap.StackFallbackAllocator` or `std.heap.FixedBufferAllocator` for request-lifecycle allocations.
- Keep the existing request arena as overflow so large requests and responses retain their current behavior.
- Production code must not implement a custom `std.mem.Allocator` vtable; test-only counting allocators are allowed.
- Never truncate a path, header, body, or response to make it fit.
- Do not create a new owned request copy per request unless its size is bounded and its storage is reused.
- Preserve public allocator ownership and `deinit`/`free` contracts.

## Long-lived state

- Sessions, registries, caches, and connection tables need explicit capacity or eviction.
- Use the server allocator for state that outlives a request.
- Do not hide unbounded growth behind `std.heap.page_allocator`.

## Verification

- Add behavior tests for ordinary requests, repeated requests, fixed-buffer exhaustion, and overflow compatibility.
- Count fallback allocations across repeated calls; the delta must be zero after warmup.
- Run `zig fmt`, `zig build`, focused tests, and the full test suite.
- Run `zginlint --max-comment-lines 1` on changed Zig files and keep each file at or below 3000 lines.
