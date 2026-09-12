//! Test aggregator for the `http2` subsystem.
//!
//! Each implementation file pulls its own sibling `*_test.zig` in a `test {}`
//! block, so importing the implementation here is enough to make every unit
//! test discoverable. Registering THIS file in the two runners
//! (`src/modules/custom_http_server/src/test_runner.zig` for the module's own
//! `zig build test`, and `src/root.zig` for the CI gate) keeps the wiring to one
//! line per runner — and `src/root.zig:876-953` only imports a handful of module
//! test files by hand, so forgetting one silently skips it in CI.
//!
//! `generated_tables.zig` and `rfc7541_vectors.zig` are data-only (no tests);
//! they are pulled in transitively by `hpack.zig` / `hpack_test.zig`.

test {
    _ = @import("constants.zig");
    _ = @import("frame.zig");
    _ = @import("huffman.zig");
    _ = @import("hpack.zig");
    _ = @import("settings.zig");
    _ = @import("stream.zig");
    _ = @import("flow_control.zig");
    // Socket-side glue: needs the module root (imports ../http_server.zig), so it
    // is only compile-checked through this aggregator, never standalone.
    _ = @import("server.zig");
}
