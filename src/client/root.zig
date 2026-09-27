//! Public API surface for kabelweb's client half.
//!
//! Consumers import this file as `@import("kabelweb").client` and
//! reach `Client`, `Request`, `Response`, etc. directly.
//!
//! Naming style matches `std.http.Client` and the existing
//! `modules/http/HttpClient.zig` so this module is a drop-in shape.

const client_mod = @import("client.zig");
const request_mod = @import("request.zig");
const response_mod = @import("response.zig");
const options_mod = @import("options.zig");
const methods_mod = @import("methods.zig");
const stream_mod = @import("stream.zig");

pub const Client = client_mod.Client;
pub const Request = request_mod.Request;
pub const Response = response_mod.Response;
pub const Method = request_mod.Method;
pub const Header = request_mod.Header;
pub const Options = options_mod.Options;
pub const Error = client_mod.Error;

// Convenience verb wrappers (declared in methods.zig).
pub const get = methods_mod.get;
pub const post = methods_mod.post;
pub const put = methods_mod.put;
pub const patch = methods_mod.patch;
pub const delete = methods_mod.delete;

// Streaming layer (declared in stream.zig).
pub const ResponseStream = stream_mod.ResponseStream;
pub const StreamScanner = stream_mod.StreamScanner;
pub const openStream = stream_mod.openStream;

// ----- Tests -----
//
// The client suites are colocated with the implementation they cover:
// `client.zig`, `methods.zig`, `request.zig`, `response.zig`, `stream.zig`,
// `curl.zig` and `options.zig` each carry their own `test { ... }` blocks
// (the old `*_test.zig` files were merged into them and deleted).
//
// Test discovery lives in the package root (`src/root.zig`) because the test
// targets are rooted there — that is also what lets the client suites reach
// the in-process server through `@import("../server/http_server.zig")`
// (a relative import that must stay inside the module path). Keeping the
// discovery block here would make this file's own module root `src/client/`,
// which rejects that relative import.
//
// `zig build test-client` runs exactly these suites: the root is compiled
// with the `client.` test-name filter.
