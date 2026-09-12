//! Client-only test entry for the `test-client` step.
//!
//! Lives at src/ (not src/client/) on purpose: the client suites spin
//! an in-process server via a relative `../server/http_server.zig`
//! import, and Zig 0.16 forbids relative imports that escape the test
//! root's directory — rooting this at src/client/root.zig would reject
//! them with "import of file outside module path".
test {
    _ = @import("client/root.zig");
}
