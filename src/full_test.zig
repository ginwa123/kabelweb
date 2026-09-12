//! Full kabelweb test entry — fast suites (via root.zig) PLUS the slow
//! soaks. Used ONLY by this package's own `zig build test`
//! (`cd src/modules/kabelweb && zig build test`).
//!
//! The repo-root `zig build test` gate runs kabelweb through the lib
//! root (src/root.zig) instead, which skips the soaks so the gate stays
//! fast — same split as before the merge (the old parent runner never
//! imported sse_keepalive_test.zig).

test {
    _ = @import("root.zig");
    // 2×60 s SSE-keepalive soaks — intentionally ONLY here, not in the
    // root gate (they dominate runtime at ~120 s).
    _ = @import("server/sse_keepalive_test.zig");
}
