// Mirrors the convention in src/modules/http/test_runner.zig:
// a single `test {}` block that imports every `*_test.zig` so
// `zig build test` from this module's directory discovers them.
//
// Chunk 3 will add memory_leak_test.zig, fd_leak_test.zig,
// edge_case_test.zig to this block. integration_test.zig and
// stress_test.zig are gated by build options `-Dintegration=true`
// and `-Dstress=true` respectively (skipped by default to keep
// air-gapped builds green).

test {
    _ = @import("client_test.zig");
    _ = @import("options_test.zig");
    _ = @import("cpu_usage_test.zig");
}
