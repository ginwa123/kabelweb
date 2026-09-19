const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

pub const http_parser = @import("http_parser.zig");
pub const router = @import("router.zig");
// HTTP/2 (h2c). `connection_reader` peeks the socket so the h2 preface can be
// detected BEFORE the HTTP/1.1 reader eats it (the preface contains CRLFCRLF at
// byte 14); `http2_server` owns the h2 connection loop.
const connection_reader = @import("connection_reader.zig");
const http2_server = @import("http2/server.zig");
pub const security = @import("security.zig");
pub const sse_manager = @import("sse_manager.zig");
pub const ws_manager = @import("websocket_manager.zig");
pub const ws_frames = @import("websocket_frames.zig");
pub const ws_handshake = @import("websocket_handshake.zig");
pub const cronjob_manager = @import("cronjob_manager.zig");
pub const Template = @import("template.zig");
pub const readHtml = @import("read_html.zig").readHtml;
pub const context = @import("context.zig");
const gserverz_context = context;
pub const HttpRequest = http_parser.HttpRequest;
pub const HttpResponse = http_parser.HttpResponse;
pub const HttpContext = http_parser.HttpContext;
pub const Session = http_parser.Session;
pub const Context = context.Context;
pub const ContextStore = context.ContextStore;
pub const contextFromRequest = context.contextFromRequest;
pub const response = http_parser;
pub const SseManager = sse_manager.SseManager;
pub const WsManager = ws_manager.WsManager;
pub const CronjobManager = cronjob_manager.CronjobManager;
pub const WsOpcode = ws_frames.Opcode;
pub const WsConnection = ws_manager.WsClient;
// Router re-exports — let module users (and other modules referencing
// `gserverz.MiddlewareFn` / `gserverz.MiddlewareChain`) wire up groups
// and middlewares without reaching into the file-private Router module.
pub const Router = router.Router;
pub const Group = router.Group;
pub const HandlerFn = router.HandlerFn;
pub const MiddlewareFn = router.MiddlewareFn;
pub const MiddlewareChain = router.MiddlewareChain;

/// Platform abstraction for socket operations
/// On POSIX: uses std.posix.system (low-level socket API)
/// On Windows: uses ws2_32 Winsock API directly
const socket = posix.system;

/// Winsock extern declarations for Windows
// Winsock SOCKET type — opaque handle (pointer-sized) returned by
// socket() and accepted by all other winsock calls. Locally declared
// as `*anyopaque` (same ABI as the underlying HANDLE on Win32/Win64).
// Used at the call-site @ptrCast boundaries so the winsock decls can
// stay typed as `c_int` (matching SocketFd = i32).
const SOCKET = *anyopaque;

const winsock = if (builtin.os.tag == .windows) struct {
    extern "ws2_32" fn WSAStartup(wVersionRequested: c_ushort, wsaData: *WSADATA) callconv(.c) c_int;
    extern "ws2_32" fn WSACleanup() callconv(.c) c_int;
    extern "ws2_32" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) callconv(.c) c_int;
    extern "ws2_32" fn closesocket(sockfd: c_int) callconv(.c) c_int;
    extern "ws2_32" fn shutdown(sockfd: c_int, how: c_int) callconv(.c) c_int;
    extern "ws2_32" fn bind(sockfd: c_int, addr: ?*const anyopaque, addrlen: c_int) callconv(.c) c_int;
    extern "ws2_32" fn listen(sockfd: c_int, backlog: c_int) callconv(.c) c_int;
    extern "ws2_32" fn accept(sockfd: c_int, addr: ?*anyopaque, addrlen: ?*c_int) callconv(.c) c_int;
    extern "ws2_32" fn recv(sockfd: c_int, buf: ?*anyopaque, len: c_int, flags: c_int) callconv(.c) c_int;
    extern "ws2_32" fn send(sockfd: c_int, buf: ?*const anyopaque, len: c_int, flags: c_int) callconv(.c) c_int;
    extern "ws2_32" fn setsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: ?*const anyopaque, optlen: c_int) callconv(.c) c_int;
    extern "ws2_32" fn getpeername(sockfd: c_int, addr: ?*anyopaque, addrlen: ?*c_int) callconv(.c) c_int;

    /// WSADATA struct passed to WSAStartup. 400 bytes is the canonical
    /// size per Winsock 2 docs; the contents are intentionally ignored
    /// (we just need the call to succeed so the winsock runtime is
    /// available for subsequent socket() calls).
    const WSADATA = [400]u8;
} else struct {};

/// Winsock must be initialised with WSAStartup() before any other
/// winsock function call. Without this call, `socket()` returns
/// `INVALID_SOCKET` (WSAEINPROGRESS / WSANOTINITIALISED) on every
/// invocation. The runtime keeps an internal ref count, so calling
/// WSAStartup multiple times is safe as long as each call is paired
/// with a matching WSACleanup(). The ref-counted behaviour makes the
/// lazy-init pattern safe — every `createSocket()` calls it, but
/// the winsock DLL is only loaded once.
///
/// This block is a no-op on non-Windows targets.
var wsa_init_lock: std.atomic.Mutex = .unlocked;
var wsa_initialized: bool = false;

fn ensureWinsockInitialized() void {
    if (wsa_initialized) return;
    while (!wsa_init_lock.tryLock()) std.atomic.spinLoopHint();
    defer wsa_init_lock.unlock();
    if (wsa_initialized) return;
    var wsa_data: winsock.WSADATA = undefined;
    // MAKEWORD(2, 2) = 0x0202 — request Winsock 2.2 (the highest version
    // every Windows version since Windows 98 supports). Winsock 2 is the
    // API surface this file relies on (WSASocket/setsockopt with the
    // SOL_SOCKET/SO_REUSEADDR constants).
    const version: c_ushort = (2 << 8) | 2;
    const rc = winsock.WSAStartup(version, &wsa_data);
    if (rc != 0) {
        std.log.err("WSAStartup failed with rc={d}", .{rc});
        return;
    }
    wsa_initialized = true;
}

/// Close a listener socket fd (cross-platform: closesocket on Windows,
/// close(2) elsewhere). Public so the web-launch port picker
/// (`modules/config/web_port.zig`) can release its probe bind — the
/// probe uses `Address.init` (same bind path as the real server) and
/// must not leak the fd per attempt.
pub fn closeFd(fd: SocketFd) void {
    if (builtin.os.tag == .windows) {
        _ = winsock.closesocket(fd);
    } else {
        _ = socket.close(fd);
    }
}

/// Wake up a pending accept() call on the listener socket without closing
/// the fd. `shutdown(sock, SHUT_RDWR)` makes accept() return immediately
/// with an error on both Linux and Windows — this is the portable way to
/// unblock a listening socket.
///
/// Closing the fd from another thread does NOT reliably wake up a
/// blocked accept() on Linux (the kernel doesn't re-poll pending
/// accepts when the fd table entry is freed), and on Windows there is
/// no signal mechanism at all (Git Bash's `kill -TERM` calls
/// TerminateProcess, which is forceful — it doesn't unblock accept).
/// `shutdown(SHUT_RDWR)` works on both.
fn shutdownListenerFd(fd: SocketFd) void {
    // SHUT_RDWR = 2 on Linux, SD_BOTH = 2 on Windows. Both platforms
    // define the constant as 2 (POSIX / Win32). The literal is safe
    // because the platform-independent std.posix.SO enum is not
    // available in this project's low-level socket path (it uses
    // `std.posix.system` directly).
    const SHUT_RDWR: c_int = 2;
    if (builtin.os.tag == .windows) {
        _ = winsock.shutdown(fd, SHUT_RDWR);
    } else {
        _ = socket.shutdown(fd, SHUT_RDWR);
    }
}

const c = std.c;

/// Address family constants
const AF_INET = if (builtin.os.tag == .windows) @as(u32, 2) else posix.AF.INET;
const AF_UNIX = if (builtin.os.tag == .windows) @as(u32, 1) else posix.AF.UNIX;

/// Socket type constants
const SOCK_STREAM = if (builtin.os.tag == .windows) @as(u32, 1) else posix.SOCK.STREAM;
const IPPROTO_TCP = if (builtin.os.tag == .windows) @as(u32, 6) else posix.IPPROTO.TCP;

// Cross-platform socket fd type. On Linux/macOS this is i32 (no behavior
// change vs. the prior hard-coded `i32`). On Windows the production code
// uses winsock handles via SOCKET (= *anyopaque); callers cast
// `addr.sock_fd` to `c_int` at the winsock call site when needed.
//
// NB: keeping this as `i32` (not `std.c.fd_t`) is deliberate — the test
// suite compares `addr.sock_fd` against integer literals (e.g. `>= 0`,
// `== -1`) and casts it via `@intCast`/`@intFromPtr` in only a handful of
// places. Switching to `std.c.fd_t` (= *anyopaque on Windows) would
// cascade into 50+ test-comparison sites. The winsock declarations use
// `SOCKET` directly, so the type mismatch surfaces only at the @ptrCast
// boundaries that already exist.
pub const SocketFd = i32;

pub const Address = struct {
    sock_fd: SocketFd,
    port: u16,

    /// Parse a dotted-quad IPv4 string ("127.0.0.1", "0.0.0.0", …) into
    /// the little-endian u32 layout `sockaddr.in.addr` expects on LE
    /// machines (first octet in the most significant byte:
    /// "127.0.0.1" → 0x0100007f). Returns error.InvalidHost for anything
    /// that isn't exactly 4 decimal octets 0-255.
    pub fn parseHostLe(host: []const u8) !u32 {
        var octets: [4]u16 = .{ 0, 0, 0, 0 };
        var idx: usize = 0;
        var it = std.mem.splitScalar(u8, host, '.');
        while (it.next()) |part| {
            if (idx >= 4) return error.InvalidHost;
            if (part.len == 0 or part.len > 3) return error.InvalidHost;
            octets[idx] = std.fmt.parseInt(u16, part, 10) catch return error.InvalidHost;
            if (octets[idx] > 255) return error.InvalidHost;
            idx += 1;
        }
        if (idx != 4) return error.InvalidHost;
        // Little-endian layout: first octet in the LOW byte.
        // "127.0.0.1" → 0x0100007f (matches the historical hardcoded value).
        return @as(u32, octets[0]) | (@as(u32, octets[1]) << 8) |
            (@as(u32, octets[2]) << 16) | (@as(u32, octets[3]) << 24);
    }

    /// Bind to `host` (dotted-quad IPv4 string) on `port`.
    ///   init("127.0.0.1", 4021) — loopback only (dev default)
    ///   init("0.0.0.0", 4021)   — all interfaces (required in containers,
    ///                             where the runtime's port-forward proxy
    ///                             connects via the container's VM IP)
    pub fn init(host: []const u8, port: u16) !Address {
        const socket_fd = try createSocket();
        errdefer closeFd(socket_fd);

        try setReuseAddr(socket_fd);
        try bindPort(try parseHostLe(host), port, socket_fd);

        return .{
            .sock_fd = socket_fd,
            .port = port,
        };
    }

    fn createSocket() !SocketFd {
        if (comptime builtin.os.tag == .windows) {
            ensureWinsockInitialized();
            const fd_raw = winsock.socket(@intCast(AF_INET), @intCast(SOCK_STREAM), @intCast(IPPROTO_TCP));
            // winsock.socket returns c_int — but the underlying return
            // value is a SOCKET (pointer-sized). Compare to the Winsock
            // sentinel INVALID_SOCKET (the C constant ((SOCKET)(LONG_PTR)-1), i.e.
            // ~0usize) via intFromPtr == maxInt(usize), then narrow
            // fd_raw back to SocketFd (= i32) — Windows socket handles
            // are small integers assigned sequentially by the kernel
            // (typically < 2^31) so the @intCast is safe here.
            const fd_handle: SOCKET = @ptrFromInt(@as(usize, @intCast(fd_raw)));
            if (@intFromPtr(fd_handle) == std.math.maxInt(usize)) return error.SocketCreationFailed;
            return @intCast(fd_raw); // narrow SOCKET → SocketFd (i32)
        } else {
            const fd = socket.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (fd < 0) return error.SocketCreationFailed;
            return @intCast(fd);
        }
    }

    fn setReuseAddr(sock_fd: SocketFd) !void {
        if (builtin.os.tag == .windows) {
            const opt: c_int = 1;
            const rc = winsock.setsockopt(sock_fd, 0xffff, 4, &opt, @sizeOf(c_int));
            if (rc != 0) return error.SetSockOptFailed;
        } else {
            // Use the OS-correct SOL_SOCKET / SO_REUSEADDR constants from
            // std.posix (which routes to std.os.<platform>.SO). The previous
            // hardcoded `1, 2` happened to be `SOL_SOCKET, SO_DEBUG` on
            // Linux (silently succeeded — DEBUG is a benign no-op-ish
            // option) but was `SOL_SOCKET, SO_TYPE` on macOS, which is an
            // invalid direction on a listen socket and triggers an
            // `INVAL` in `posix.setsockopt`'s switch — the `unreachable`
            // arm crashes the process during GinwaServer.init().
            //
            // sys/socket.h SOL_SOCKET = 1 on Linux and 0xffff on macOS;
            // SO_REUSEADDR = 0x0004 on both. Using the standard library's
            // os-tagged aliases keeps both platforms correct.
            const opt: i32 = 1;
            try posix.setsockopt(
                sock_fd,
                @intCast(posix.SOL.SOCKET),
                @intCast(posix.SO.REUSEADDR),
                std.mem.asBytes(&opt),
            );
        }
    }

    fn bindPort(host_le: u32, port: u16, sock_fd: SocketFd) !void {
        // Create sockaddr_in structure manually for portability
        // port must be in network byte order (big-endian)
        var sockaddr: socket.sockaddr.in = .{
            .family = 2, // AF_INET
            .port = @byteSwap(port), // Convert to network byte order
            .addr = @bitCast(host_le), // e.g. parseHostLe("127.0.0.1") = 0x0100007f
            .zero = undefined,
        };

        if (builtin.os.tag == .windows) {
            const rc = winsock.bind(sock_fd, @ptrCast(&sockaddr), @sizeOf(socket.sockaddr.in));
            if (rc != 0) return error.BindFailed;
        } else {
            const rc = socket.bind(sock_fd, @ptrCast(&sockaddr), @sizeOf(socket.sockaddr.in));
            if (rc < 0) return error.BindFailed;
        }
    }
};

const constants_preface = @import("http2/constants.zig");
// Transport abstraction (plain socket | TLS) and the OpenSSL server-side TLS
// wrapper. TLS is opt-in: with `tls_ctx == null` every path below is byte-for-byte
// today's plaintext behaviour.
const stream_mod = @import("stream.zig");
/// Re-exported so the app can talk about transports and generate a certificate
/// without importing the module's internals directly.
pub const Stream = stream_mod.Stream;
pub const tls = tls_mod;
pub const tls_cert = @import("http2/tls_cert.zig");
const tls_mod = @import("http2/tls.zig");

//  reaches the TLS implementation through a function table (it cannot
// import the TLS module without a cycle), so these adapters are registered by
// . Without the registration every read/write on a TLS stream returns
//  - which looks exactly like a client that hangs up:
// the handshake succeeds, then the connection resets with no response.
fn tlsStreamRead(conn: *anyopaque, buf: []u8) anyerror!usize {
    const tc: *tls_mod.Conn = @ptrCast(@alignCast(conn));
    return tc.read(buf);
}
fn tlsStreamWriteAll(conn: *anyopaque, bytes: []const u8) anyerror!void {
    const tc: *tls_mod.Conn = @ptrCast(@alignCast(conn));
    return tc.writeAll(bytes);
}
/// Register the TLS implementations with `Stream`. Idempotent, process-global;
/// without it every read/write on a TLS stream fails with `TlsOpsNotInstalled`
/// (which presents as a client that hangs up right after the handshake).
fn installTlsStreamOps() void {
    stream_mod.Stream.installTlsOps(.{
        .read = tlsStreamRead,
        .write_all = tlsStreamWriteAll,
        .close = tlsStreamClose,
    });
}

fn tlsStreamClose(conn: *anyopaque) void {
    const tc: *tls_mod.Conn = @ptrCast(@alignCast(conn));
    // shutdown frees the SSL object; the per-connection scope frees the Conn
    // itself, so this must not free it here (double free).
    tc.shutdown();
}

pub const GinwaServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    address: Address,
    router: router.Router,
    sse_manager: SseManager,
    ws_manager: *WsManager,
    /// In-process scheduler for cron-syntax callbacks. Started by
    /// `listen()` and stopped by `deinit()`. See `cronjob_manager.zig`.
    cronjob_manager: CronjobManager,
    ctx: ?*anyopaque = null,
    environment: ?*const std.process.Environ.Map = null,
    is_running: bool = false,

    /// HTTP/2 cleartext (h2c) — OFF by default. When enabled, a connection whose
    /// first bytes are the h2 connection preface is handed to the HTTP/2 driver;
    /// every other connection takes the HTTP/1.1 path unchanged. Enable with
    /// `--http2=h2c` (see src/main.zig). There is no TLS/ALPN here, so browsers
    /// keep using HTTP/1.1 — see docs/http2.md.
    enable_h2c: bool = false,

    /// TLS listener state — NULL by default. When set, `listen()` performs a TLS
    /// handshake on every accepted socket and the negotiated ALPN protocol picks
    /// the codec: `h2` → the HTTP/2 driver (this is what makes BROWSERS use h2,
    /// since they only ever speak it over TLS+ALPN), anything else → the
    /// HTTP/1.1 path over the same encrypted stream.
    ///
    /// Built by `enableTls()`. A missing or mismatched PEM pair fails there
    /// loudly — silently falling back to plaintext would be a security bug.
    tls_ctx: ?*tls_mod.Ctx = null,

    /// Server-side ContextStore passed to handlers via `HttpContext`.
    /// Always non-null after a successful `init()` — the server heap-
    /// allocates the store on init and deinits it on `deinit()` so
    /// callers don't have to manage its lifetime. Handlers that don't
    /// use cross-redirect state can simply ignore it. The pointer is
    /// typed as optional to preserve the existing `Session.set`
    /// `error.NoContextStore` contract (defensive — the listen loop
    /// always populates `Session.context_store` from this field).
    context_store: ?*gserverz_context.ContextStore = null,

    /// HMAC secret used by `security.csrfTokenIssue` / `csrfTokenValidate`.
    /// Defaults to a dev-only constant; production deployments should
    /// override via `server.csrf_secret = "..."` after `GinwaServer.init`.
    csrf_secret: []const u8 = "dev-only-csrf-secret-change-in-prod",

    /// Server-wide CORS configuration. Defaults to "CORS off" (same-origin
    /// only) so existing routes are unchanged. Configure after init:
    ///   server.cors = .{ .enabled = true, .allowed_origins = &.{"..."} };
    /// See `CORSConfig` for the full surface.
    cors: CORSConfig = .{},

    /// Engine-level request-body cap in bytes. ALWAYS enforced by the
    /// dispatch loop (independent of `cors`) — bodies over the cap get a
    /// 413 engine page + console log before any handler runs. Handlers
    /// must not re-check body size.
    ///
    /// DEFAULT: `maxInt(usize)` = effectively unlimited. A server opts
    /// into a cap explicitly, e.g.:
    ///   server.max_body_bytes = 16 * 1024;          // 16 KiB
    ///   server.max_body_bytes = 100 * 1024 * 1024;  // 100 MB uploads
    /// Per-route / per-group overrides: see `RouteOptions.max_body_bytes`
    /// and `Group.maxBodyBytes` (e.g. a large `/upload` route on an
    /// otherwise-capped server).
    max_body_bytes: usize = std.math.maxInt(usize),

    /// Server-wide security response headers (CSP etc.). Defaults to a
    /// strict `'self'`-only baseline. Apps loading third-party assets
    /// (CDN scripts, analytics beacons) override after init:
    ///   server.security_headers.content_security_policy = "...";
    /// Handlers that call `.withSecurityHeaders()` pick this up via the
    /// per-request `HttpContext` — no per-handler config needed.
    security_headers: security.SecurityHeaders = .{},

    /// Master switch for the server-level security headers applied by the
    /// dispatch loop (`applySecurityHeadersTo`). Defaults to true
    /// (historical behaviour — every routed response carries the 7
    /// headers). High-throughput services that don't need the headers
    /// (e.g. internal JSON APIs behind a gateway that already sets them)
    /// can opt out with `server.enable_security_headers = false`, which
    /// saves 7 hash-map inserts + ~300 wire bytes per response.
    /// Per-handler `.withSecurityHeaders()` calls are unaffected.
    enable_security_headers: bool = true,

    /// Optional fallback handler invoked when no route matches. It is
    /// expected to write a complete HTTP response directly to `fd` (status
    /// line, headers, body) — the listen loop will NOT call toBytes() /
    /// sendToClient afterwards. Used by `--static-dir` to serve files for
    /// any path that isn't claimed by an API route.
    ///
    /// The first argument is an opaque user pointer — typically a pointer
    /// to whatever config struct the handler needs (e.g. a static-files
    /// config). The handler is responsible for casting it back to the
    /// concrete type. This keeps the HTTP server free of any specific
    /// feature's types.
    ///
    /// The per-request `allocator` is passed in so the response buffer
    /// can be arena-freed when the request finishes.
    static_dir_handler: ?*const fn (
        cfg: *const anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request_path: []const u8,
        range_header: ?[]const u8,
        // The TRANSPORT, not an fd: with TLS enabled the same handler must emit
        // ciphertext, and only the stream knows how.
        stream: Stream,
    ) anyerror!void = null,
    /// Opaque cfg pointer forwarded to `static_dir_handler`. Set together
    /// with the handler via `setStaticDirHandler`.
    static_dir_cfg: ?*const anyopaque = null,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, address: Address) !*GinwaServer {
        const gs = try allocator.create(GinwaServer);
        errdefer allocator.destroy(gs);

        // Heap-allocate the cross-redirect ContextStore eagerly so
        // handlers can use `Session.set` / `redirectWithContext` without
        // any per-server wiring. The pointer is stored on `gs` and
        // freed by `deinit()` — callers (e.g. main.zig) never have to
        // touch it. Tests that don't need a store still get one (it's
        // just an empty StringHashMap); the cost is one allocation.
        const store = try gserverz_context.ContextStore.create(allocator);
        errdefer store.deinit();

        gs.* = .{
            .allocator = allocator,
            .io = io,
            .address = address,
            .router = router.Router.init(allocator),
            .sse_manager = try SseManager.init(allocator, allocator, io),
            .ws_manager = try WsManager.init(allocator, allocator, io),
            .cronjob_manager = CronjobManager.init(allocator, io),
            .ctx = null,
            .environment = null,
            .context_store = store,
        };
        return gs;
    }

    /// Wire a static-files fallback handler. Pass `null` for the handler
    /// to clear both `static_dir_handler` and `static_dir_cfg`.
    /// See the `static_dir_handler` field doc for the handler contract.
    pub fn setStaticDirHandler(
        self: *GinwaServer,
        handler: ?*const fn (
            cfg: *const anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            request_path: []const u8,
            range_header: ?[]const u8,
            stream: Stream,
        ) anyerror!void,
        cfg: ?*const anyopaque,
    ) void {
        self.static_dir_handler = handler;
        self.static_dir_cfg = cfg;
    }

    /// Load a PEM certificate/key pair and serve TLS. Call before `listen()`.
    ///
    /// ALPN preference is `h2` first, then `http/1.1` — the same shape Go's
    /// `http.Server` gets from `NextProtos`, so one listener serves both
    /// protocols and the client's offer decides.
    pub fn enableTls(self: *GinwaServer, cert_pem: []const u8, key_pem: []const u8) !void {
        if (self.tls_ctx) |old| old.deinit();
        installTlsStreamOps();
        self.tls_ctx = try tls_mod.Ctx.init(
            self.allocator,
            cert_pem,
            key_pem,
            &.{ tls_mod.alpn_h2, tls_mod.alpn_http1 },
        );
    }

    /// Adopt a TLS context built by the caller (e.g. so `--tls` can be validated
    /// before any background subsystem starts). Takes ownership: `deinit()` frees
    /// whatever context is installed.
    pub fn setTlsCtx(self: *GinwaServer, ctx: *tls_mod.Ctx) void {
        if (self.tls_ctx) |old_ctx| old_ctx.deinit();
        installTlsStreamOps();
        self.tls_ctx = ctx;
    }

    pub fn deinit(self: *GinwaServer) void {
        // Order matters: stop the cronjob thread BEFORE freeing its
        // registry (the tick thread holds a pointer to `self`).
        self.cronjob_manager.stop();
        self.cronjob_manager.deinit();
        self.sse_manager.gracefulShutdown();
        self.sse_manager.deinit();
        self.ws_manager.destroy();
        self.router.deinit();
        // TLS context last: live TLS connections already ended (each handle task
        // owns its own `Conn` and frees it before returning).
        if (self.tls_ctx) |ctx| ctx.deinit();
        // Drop the auto-allocated ContextStore last — it owns no threads
        // and only references the server's allocator, so it can free
        // safely after every other subsystem has shut down.
        if (self.context_store) |store| store.deinit();
    }

    /// Free the GinwaServer struct itself. Callers that allocated the
    /// server with `init(...)` (which calls `allocator.create(GinwaServer)`)
    /// MUST call this to release the struct memory — `deinit()` only cleans
    /// up the server's internal state. This method calls `deinit()` first
    /// so that `destroy(allocator)` is a complete release (sse_manager +
    /// router + struct memory).
    pub fn destroy(self: *GinwaServer, allocator: std.mem.Allocator) void {
        self.deinit();
        allocator.destroy(self);
    }

    pub fn listen(self: *GinwaServer) !void {
        if (builtin.os.tag == .windows) {
            const rc = winsock.listen(self.address.sock_fd, 1024);
            if (rc != 0) return error.ListenFailed;
        } else {
            const rc = socket.listen(self.address.sock_fd, 1024);
            if (rc < 0) return error.ListenFailed;
        }

        // Start the cronjob tick thread BEFORE accepting connections so
        // scheduled jobs can begin firing immediately. A start failure
        // is logged but does not abort listening — the manager is
        // best-effort (callers can still drive jobs manually via `tick`).
        if (self.cronjob_manager.start()) |_| {
            std.debug.print("Cronjob manager running (1s tick)\n", .{});
        } else |err| {
            std.debug.print("HTTP_SERVER: cronjob manager start failed: {s}\n", .{@errorName(err)});
        }

        var group: std.Io.Group = .init;
        errdefer group.cancel(self.io);

        self.is_running = true;
        while (self.is_running) {
            const client_fd = self.acceptClient() catch break;

            // Blocks the accept loop (not already-served connections) once
            // `max_concurrent_connections` are in flight. This is the
            // backpressure point — excess connections queue in the kernel
            // accept backlog instead of spawning unbounded threads.

            const arena = self.allocator.create(std.heap.ArenaAllocator) catch {
                _ = closeFd(client_fd);
                continue;
            };
            arena.* = std.heap.ArenaAllocator.init(self.allocator);

            // Thread-per-connection task via `Group.concurrent` — NOT
            // `Group.async`. Under `Io.Threaded`, `.async` carries no
            // concurrency guarantee and may run the handler inline on the
            // calling thread — which is the accept loop itself. That blocks
            // the loop from returning to acceptClient() until the current
            // connection's keep-alive loop finishes, which is what produced
            // a stall when this was tried (verified live: /health never
            // answered). `.concurrent` is the only primitive that
            // guarantees dedicated execution, which is why the accept loop
            // needs it despite the thread-growth cost — the semaphore above
            // is what actually bounds that cost, not the choice of `.async`
            // vs `.concurrent` itself.
            group.concurrent(
                self.io,
                struct {
                    fn handle(server: *GinwaServer, arena_allocator: *std.heap.ArenaAllocator, fd: SocketFd) void {
                        defer {
                            arena_allocator.deinit();
                            server.allocator.destroy(arena_allocator);
                        }

                        const allocator = arena_allocator.allocator();

                        // ─── TLS handshake (when configured) ───────────────
                        // Done inside the per-connection task so a slow or
                        // malicious handshake cannot stall the accept loop.
                        // `alpn_is_h2` is authoritative for the codec choice on
                        // an encrypted connection: the client already told us
                        // which protocol it will speak.
                        var tls_conn: ?*tls_mod.Conn = null;
                        defer if (tls_conn) |tc| tc.deinit();
                        var stream: stream_mod.Stream = .{ .plain = fd };
                        var alpn_is_h2 = false;
                        if (server.tls_ctx) |ctx| {
                            tls_conn = tls_mod.Conn.accept(ctx, fd) catch |err| {
                                std.debug.print("HTTP_SERVER: TLS handshake failed: {s}\n", .{@errorName(err)});
                                _ = closeFd(fd);
                                return;
                            };
                            stream = .{ .tls = @ptrCast(tls_conn.?) };
                            const negotiated = tls_conn.?.selectedAlpn();
                            // Logged because ALPN is the whole dispatch decision on
                            // an encrypted connection: an empty value here means the
                            // client offered no ALPN and must be served HTTP/1.1.
                            std.debug.print("HTTP_SERVER: TLS ok (alpn='{s}' len={d})\n", .{ negotiated, negotiated.len });
                            alpn_is_h2 = std.mem.eql(u8, negotiated, tls_mod.alpn_h2);
                        }
                        // ─── TLS + ALPN "h2": go straight to the HTTP/2 driver ─
                        if (alpn_is_h2) {
                            // The preface is still on the wire; the driver consumes
                            // it from the Stream itself (empty initial buffer).
                            http2_server.serveConnection(server, stream, allocator, "", .{}) catch |err| {
                                std.debug.print("HTTP_SERVER: h2 (TLS) connection ended: {s}\n", .{@errorName(err)});
                            };
                            _ = closeFd(fd);
                            return;
                        }

                        // ─── HTTP/2 (h2c) sniff ───────────────────────
                        // Must run BEFORE the HTTP/1.1 reader: the 24-byte h2
                        // preface contains the CRLFCRLF the h1 reader stops at
                        // (byte 14), so parsing h1 first would consume the
                        // preface AND the frames that arrived with it.
                        var cr = connection_reader.ConnectionReader.init(allocator, stream);
                        defer cr.deinit();
                        if (server.enable_h2c) {
                            _ = cr.fillOnce() catch |err| {
                                std.debug.print("HTTP_SERVER: h2 sniff read failed: {s}\n", .{@errorName(err)});
                                _ = closeFd(fd);
                                return;
                            };
                            switch (connection_reader.sniff(cr.buffered())) {
                                .h2 => {
                                    const initial = cr.takeBuffered() catch |err| {
                                        std.debug.print("HTTP_SERVER: h2 preface handoff failed: {s}\n", .{@errorName(err)});
                                        _ = closeFd(fd);
                                        return;
                                    };
                                    http2_server.serveConnection(server, stream, allocator, initial, .{}) catch |err| {
                                        std.debug.print("HTTP_SERVER: h2 connection ended: {s}\n", .{@errorName(err)});
                                    };
                                    _ = closeFd(fd);
                                    return;
                                },
                                .maybe_h2 => {
                                    cr.fillAtLeast(constants_preface.preface_len, 8) catch {};
                                    if (connection_reader.sniff(cr.buffered()) == .h2) {
                                        const initial = cr.takeBuffered() catch |err| {
                                            std.debug.print("HTTP_SERVER: h2 preface handoff failed: {s}\n", .{@errorName(err)});
                                            _ = closeFd(fd);
                                            return;
                                        };
                                        http2_server.serveConnection(server, stream, allocator, initial, .{}) catch |err| {
                                            std.debug.print("HTTP_SERVER: h2 connection ended: {s}\n", .{@errorName(err)});
                                        };
                                        _ = closeFd(fd);
                                        return;
                                    }
                                },
                                .h1 => {},
                            }
                        }

                        // ─── HTTP/1.1 keep-alive loop ───────────────────
                        var keep_alive_count: u32 = 0;
                        var recent_peak: usize = 0;
                        var samples: u32 = 0;
                        keep_alive_loop: while (true) {
                            if (keep_alive_count > 0) {
                                const cap = arena_allocator.queryCapacity();

                                // Update running peak
                                if (cap > recent_peak) recent_peak = cap;
                                samples += 1;

                                // Free when current capacity is much larger than what we normally need,
                                // or every N requests as a safety net
                                const should_free = (recent_peak > 0 and cap > recent_peak * 2) or (samples % 64 == 0);

                                _ = arena_allocator.reset(if (should_free) .free_all else .retain_capacity);

                                // Slowly forget the peak so it adapts downward
                                if (should_free) {
                                    recent_peak = cap / 2; // or set to 0
                                    samples = 0;
                                }
                            }
                            keep_alive_count += 1;

                            var rb = RequestBuffer.init(allocator);
                            defer rb.deinit();

                            // Hand the sniffed bytes to the HTTP/1.1 reader so the
                            // pre-read is not lost (it is a no-op when the sniff is
                            // disabled: `cr` then holds nothing). Only the first
                            // iteration can hold buffered bytes (the h2-preface
                            // sniff runs once per connection, before the loop).
                            if (keep_alive_count == 1 and cr.buffered().len > 0) {
                                rb.buf.appendSlice(allocator, cr.buffered()) catch {
                                    _ = closeFd(fd);
                                    return;
                                };
                                _ = cr.takeBuffered() catch {};
                            }

                            const request_data = rb.readFullRequestStream(stream) catch |err| {
                                // Normal keep-alive teardown (client closed an
                                // idle persistent connection) is silent; anything
                                // else is logged. Either way the loop exits and
                                // the fd is closed once, below.
                                if (err != error.ConnectionClosed) {
                                    std.debug.print("HTTP_SERVER: readFullRequest failed: {s}\n", .{@errorName(err)});
                                }
                                break :keep_alive_loop;
                            };
                            defer allocator.free(request_data);

                            var req = http_parser.parseRequest(request_data, allocator, server.io, fd) catch |err| {
                                std.debug.print("HTTP_SERVER: parseRequest failed: {s}\n", .{@errorName(err)});
                                _ = closeFd(fd);
                                return;
                            };
                            defer req.headers.deinit();

                            const http_ctx = http_parser.HttpContext{
                                .allocator = allocator,
                                .io = server.io,
                                // Handlers read the server's CORS allowlist from
                                // here — no hardcoded hosts in handler code.
                                .allowed_origins = server.cors.allowed_origins,
                            };
                            // Build the Session right after parsing. `incoming`
                            // is populated from the Cookie header via
                            // `contextFromRequest` so handlers can `session.getString`
                            // without knowing about cookies, ContextStore, or
                            // contextFromRequest. When the server has no
                            // `context_store` wired, Session.context_store is
                            // `null` and `session.set` returns
                            // `error.NoContextStore` (handlers that need set
                            // don't register against a no-store server).
                            const lookup: context.LookupResult = if (server.context_store) |store|
                                context.contextFromRequest(req, store)
                            else
                                .{ .context = null, .id = null };
                            var session = http_parser.Session.init(
                                server.context_store,
                                lookup.context,
                                lookup.id,
                            );
                            defer session.deinit();
                            // Wire the session into the request so handlers can
                            // call `req.session.set / getString` directly. The
                            // pointer outlives the listen loop's handle scope.
                            req.session = &session;

                            // ─── Engine auto-gate (zero-config) ─────────────
                            // Two engine-owned protections, both before route
                            // matching:
                            //   1. Body-size cap (ALWAYS on; effective cap =
                            //      route/group override or server.max_body_bytes)
                            //   2. Origin allowlist (when server.cors.enabled)
                            // Failure → built-in 403/413 explanation page +
                            // console log so the developer sees the issue.
                            {
                                const gate = security.preGateCheck(&req, server.cors, server.max_body_bytes) catch .pass;
                                if (gate != .pass) {
                                    const origin = blk: {
                                        var oit = req.headers.iterator();
                                        while (oit.next()) |entry| {
                                            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "origin")) {
                                                break :blk entry.value_ptr.*;
                                            }
                                        }
                                        break :blk null;
                                    };
                                    std.debug.print(
                                        "HTTP_SERVER [pre-gate]: {s} {s} blocked ({s}) origin={s} — add it to server.cors.allowed_origins\n",
                                        .{ req.method, req.path, @tagName(gate), origin orelse "-" },
                                    );
                                    const host = if (server.cors.allowed_origins.len > 0) server.cors.allowed_origins[0] else "your-domain";
                                    var block_page = security.buildEngineBlockPage(allocator, gate, origin, host) catch {
                                        _ = closeFd(fd);
                                        return;
                                    };
                                    defer block_page.headers.deinit();
                                    server.applySecurityHeadersTo(&block_page);
                                    if (origin) |o| {
                                        security.applyCORSHeaders(
                                            &block_page.headers,
                                            o,
                                            server.cors.allowed_origins,
                                            server.cors.allowed_methods,
                                            server.cors.allowed_headers,
                                            server.cors.allow_credentials,
                                        ) catch {};
                                    }
                                    const page_bytes = block_page.toBytes() catch {
                                        _ = closeFd(fd);
                                        return;
                                    };
                                    defer allocator.free(page_bytes);
                                    _ = server.sendToStream(stream, page_bytes) catch {};
                                    _ = closeFd(fd);
                                    return;
                                }
                            }

                            // CORS preflight: when CORS is enabled and the
                            // request is OPTIONS, reply with the configured
                            // `Access-Control-*` headers and short-circuit
                            // before the router sees the request. Preflight
                            // is browser-driven and doesn't carry a route
                            // match, so handling it globally keeps route
                            // registration simple.
                            if (server.cors.enabled and std.mem.eql(u8, req.method, "OPTIONS")) {
                                const preflight = server.buildCORSPreflight(&req, allocator) catch |err| {
                                    std.debug.print("HTTP_SERVER: buildCORSPreflight failed: {s}\n", .{@errorName(err)});
                                    _ = closeFd(fd);
                                    return;
                                };
                                const preflight_bytes = preflight.toBytes() catch {
                                    std.debug.print("HTTP_SERVER: preflight toBytes failed\n", .{});
                                    _ = closeFd(fd);
                                    return;
                                };
                                defer preflight.allocator.free(preflight_bytes);
                                _ = server.sendToStream(stream, preflight_bytes) catch {
                                    std.debug.print("HTTP_SERVER: preflight send failed\n", .{});
                                };
                                return;
                            }

                            if (server.router.matchRoute(req.method, req.path, &req, http_ctx)) |result| {
                                // SSE streams chunked frames and WebSocket hijacks the
                                // fd: neither can run on an encrypted connection until
                                // the streaming work lands (see docs/http2-tls.md and
                                // plan D2 — a browser negotiates h2 for the WHOLE
                                // origin, so this is exactly the case that must be
                                // finished before the UI is served over https).
                                if (stream.isTls() and (result == .sse or result == .websocket)) {
                                    var res = http_parser.HttpResponse
                                        .init(501, "Not Implemented", allocator)
                                        .withBody("SSE and WebSocket are not available over TLS yet; use the plaintext listener");
                                    server.applyCORSResponse(&req, &res) catch {};
                                    server.applySecurityHeadersTo(&res);
                                    if (res.toBytes()) |bytes| {
                                        _ = server.sendToStream(stream, bytes) catch {};
                                    } else |_| {}
                                    _ = closeFd(fd);
                                    return;
                                }
                                switch (result) {
                                    .handler => |h| {
                                        // ─── Route-level body cap (override) ───
                                        // When the matched route (or its group)
                                        // declared a body cap, re-check with THAT
                                        // limit — it may be tighter OR looser than
                                        // the server default. `0` = no override.
                                        if (h.max_body_bytes != 0 and h.max_body_bytes != server.max_body_bytes) {
                                            const route_gate = security.preGateCheck(&h.req, .{ .enabled = false }, h.max_body_bytes) catch .pass;
                                            if (route_gate != .pass) {
                                                std.debug.print(
                                                    "HTTP_SERVER [pre-gate]: {s} {s} blocked ({s}) — route body cap {d} bytes\n",
                                                    .{ h.req.method, h.req.path, @tagName(route_gate), h.max_body_bytes },
                                                );
                                                var page = security.buildEngineBlockPage(allocator, route_gate, null, "this route") catch {
                                                    _ = closeFd(fd);
                                                    return;
                                                };
                                                defer page.headers.deinit();
                                                server.applySecurityHeadersTo(&page);
                                                const page_bytes = page.toBytes() catch {
                                                    _ = closeFd(fd);
                                                    return;
                                                };
                                                defer allocator.free(page_bytes);
                                                _ = server.sendToStream(stream, page_bytes) catch {};
                                                _ = closeFd(fd);
                                                return;
                                            }
                                        }

                                        // ─── Framework pre-handler security gate ───
                                        // When the route opted in via
                                        // `on_pre_handler_fail`, run origin +
                                        // body-size checks from server.cors BEFORE
                                        // any middleware/handler. On failure return
                                        // 302 → <fail_base><code> and never invoke
                                        // the handler. This is THE enforcement
                                        // point — handlers must not re-check.
                                        if (h.chain.on_pre_handler_fail) |fail_base| {
                                            const maybe_fail: ?security.HttpResponse = security.buildPreHandlerFailRedirect(
                                                allocator,
                                                &h.req,
                                                server.cors,
                                                if (h.max_body_bytes != 0) h.max_body_bytes else security.MAX_BODY_BYTES,
                                                fail_base,
                                            ) catch |err| blk: {
                                                std.debug.print("pre-handler gate failed: {s}\n", .{@errorName(err)});
                                                break :blk null;
                                            };
                                            if (maybe_fail) |fail_resp| {
                                                var gated = fail_resp;
                                                server.applyCORSResponse(&h.req, &gated) catch @panic("OOM");
                                                server.applySecurityHeadersTo(&gated);
                                                const fail_bytes = gated.toBytes() catch {
                                                    std.debug.print("Failed to build pre-handler fail response\n", .{});
                                                    _ = closeFd(fd);
                                                    return;
                                                };
                                                defer gated.allocator.free(fail_bytes);
                                                _ = server.sendToStream(stream, fail_bytes) catch {
                                                    std.debug.print("Failed to send pre-handler fail response\n", .{});
                                                };
                                                _ = closeFd(fd);
                                                return;
                                            }
                                        }

                                        // Run the per-request middleware chain. When the
                                        // route has no middleware the chain dispatches
                                        // straight to the final handler — same behavior
                                        // as before groups/middleware were added. When
                                        // middlewares exist they run in registration
                                        // order (outermost group first, innermost last);
                                        // a middleware that returns without calling
                                        // `chain.next(...)` short-circuits the chain.
                                        var final_res = h.chain.run(h.ctx, h.req, h.res) catch http_parser.internalError("Handler error", allocator);

                                        // CORS response headers — only when CORS is
                                        // enabled and the request carried an Origin
                                        // that matches `cors.allowed_origins`.
                                        server.applyCORSResponse(&h.req, &final_res) catch @panic("OOM");

                                        // Server-level security headers (CSP etc.)
                                        // — the app's config wins over any handler
                                        // default so policy lives in ONE place.
                                        server.applySecurityHeadersTo(&final_res);

                                        // Frame the keep-alive decision BEFORE
                                        // serialising: `toBytes()`/`writeTo()`
                                        // stamp `Connection: keep-alive` vs
                                        // `close` from this flag. Framing is
                                        // guaranteed (auto Content-Length, or
                                        // self-delimiting 1xx/204/304), so reuse
                                        // needs only an explicit or default
                                        // keep-alive from the client. Capped at
                                        // 1000 requests per connection (matches
                                        // the `Keep-Alive: max=1000` hint).
                                        final_res.keep_alive = server.clientWantsKeepAlive(&h.req) and
                                            keep_alive_count < 1000;

                                        // Zero-alloc fast path for small responses
                                        // (stack buffer); large ones fall back to
                                        // the heap inside writeTo. Wire bytes are
                                        // identical to toBytes.
                                        final_res.writeTo(stream) catch {
                                            std.debug.print("Failed to send response\n", .{});
                                            break :keep_alive_loop;
                                        };
                                        if (final_res.keep_alive) {
                                            continue :keep_alive_loop;
                                        } else {
                                            break :keep_alive_loop;
                                        }
                                    },
                                    .websocket => |ws| {
                                        // WebSocket upgrade path. We must:
                                        //   1. Validate the request is a valid upgrade (RFC 6455 §4.1).
                                        //   2. Send the 101 response with the computed Accept.
                                        //   3. Register the client with the WsManager (so broadcasts
                                        //      and targeted sends work).
                                        //   4. Run the handler in the current per-connection worker.
                                        //   5. Send a close frame and remove from registry on return.
                                        if (!ws_handshake.isWebSocketRequest(&req)) {
                                            const bad = http_parser.badRequest("WebSocket upgrade required", allocator);
                                            const bytes = bad.toBytes() catch {
                                                _ = closeFd(fd);
                                                return;
                                            };
                                            defer bad.allocator.free(bytes);
                                            _ = server.sendToStream(stream, bytes) catch {};
                                            _ = closeFd(fd);
                                            return;
                                        }

                                        const key = ws_handshake.extractWebSocketKey(&req) catch {
                                            _ = closeFd(fd);
                                            return;
                                        };
                                        const accept_resp = ws_handshake.buildAcceptResponse(allocator, key) catch {
                                            _ = closeFd(fd);
                                            return;
                                        };
                                        defer allocator.free(accept_resp);

                                        _ = server.sendToStream(stream, accept_resp) catch {
                                            _ = closeFd(fd);
                                            return;
                                        };

                                        // Register the client with the WsManager. The write callback bridges
                                        // the manager's `fn(ctx, fd, data)` API to the server's
                                        // `sendToClient` method via the ctx pointer.
                                        const WriteAdapter = struct {
                                            fn w(ctx: ?*anyopaque, target_fd: i32, data: []const u8) anyerror!usize {
                                                const server_ptr: *GinwaServer = @ptrCast(@alignCast(ctx.?));
                                                return server_ptr.sendToClient(target_fd, data);
                                            }
                                        }.w;
                                        var client_id = server.ws_manager.registerClient(fd, WriteAdapter, @ptrCast(server)) catch {
                                            _ = closeFd(fd);
                                            return;
                                        };

                                        // Run the user handler.
                                        ws.handler(ws.ctx, ws.req, @ptrCast(server), fd, &client_id) catch |err| {
                                            std.debug.print("WebSocket handler error: {s}\n", .{@errorName(err)});
                                        };

                                        // Send a close frame and remove from registry. The client
                                        // arena is freed by removeClient.
                                        const close_payload = "\x03\xe8"; // status 1000 normal closure
                                        const close_frame = ws_frames.encodeFrame(allocator, .{
                                            .opcode = .close,
                                            .payload = close_payload,
                                        }) catch null;
                                        if (close_frame) |cf| {
                                            defer allocator.free(cf);
                                            _ = server.sendToStream(stream, cf) catch {};
                                        }
                                        server.ws_manager.removeClient(&client_id, .explicit);
                                        return;
                                    },
                                    .sse => |sse| {
                                        const headers = "HTTP/1.1 200 OK\r\n" ++
                                            "Content-Type: text/event-stream\r\n" ++
                                            "Cache-Control: no-cache\r\n" ++
                                            // Connection: close (NOT keep-alive). SSE is a single-use,
                                            // long-lived stream — the connection is never reused for a
                                            // follow-up request, so advertising keep-alive confuses
                                            // intermediaries. Vite (Node.js) in dev mode stamps
                                            // `Keep-Alive: timeout=5` on keep-alive responses, and some
                                            // browser/webview engines (Chromium, WebKitGTK, WKWebView)
                                            // enforce that timeout aggressively — closing the upstream
                                            // socket ~5s after the last heartbeat. Empirically this
                                            // matches the user's reported pattern of heartbeats
                                            // stopping after ~30s in the browser DevTools. Telling
                                            // intermediaries this connection will close on EOF keeps
                                            // the stream open for as long as the backend keeps
                                            // sending chunked frames.
                                            "Connection: close\r\n" ++
                                            // Required by HTTP/1.1: a response with neither Content-Length
                                            // nor Transfer-Encoding is implicitly framed by connection-close.
                                            // For SSE we never close the connection voluntarily, so we MUST
                                            // declare chunked encoding. Otherwise Vite / proxies / browsers
                                            // will misinterpret the response and surface
                                            // ERR_INCOMPLETE_CHUNKED_ENCODING on disconnect.
                                            "Transfer-Encoding: chunked\r\n" ++
                                            // Tell intermediaries (Vite, nginx, Cloudflare, ALB) not to
                                            // buffer. X-Accel-Buffering is the de-facto convention.
                                            "X-Accel-Buffering: no\r\n" ++
                                            "Access-Control-Allow-Origin: *\r\n" ++
                                            "\r\n";
                                        _ = server.sendToStream(stream, headers) catch {
                                            _ = closeFd(fd);
                                            return;
                                        };
                                        const client_id = server.sse_manager.registerClient(fd) catch {
                                            _ = closeFd(fd);
                                            return;
                                        };
                                        var sse_ctx = sse.ctx;
                                        sse_ctx.client_id = client_id;
                                        const res = http_parser.HttpResponse.init(200, "OK", allocator);
                                        _ = sse.handler(sse_ctx, sse.req, res) catch |err| {
                                            if (err != error.WouldBlock) {
                                                std.debug.print("SSE handler error: {s}\n", .{@errorName(err)});
                                            }
                                        };
                                        return;
                                    },
                                }
                            } else {
                                // No API route matched. If a static-dir fallback
                                // handler is configured, hand the request off to
                                // it. The handler is responsible for writing a
                                // complete HTTP response directly to `fd` (it
                                // owns the wire format from status line through
                                // body) and for sending it. We only fall through
                                // to the generic 404 if the handler is absent,
                                // missing its cfg, or reports an error.
                                var static_served = false;
                                if (server.static_dir_handler) |handler| {
                                    if (server.static_dir_cfg) |cfg| {
                                        // HTTP header names are case-insensitive
                                        // per RFC 9110 §5.1, but the gserverz
                                        // preserves the case the client sent.
                                        // Walk the headers map and match
                                        // case-insensitively so the static-file
                                        // handler gets a `Range:` value
                                        // regardless of whether the client sent
                                        // "Range", "range", or "RANGE".
                                        var range_hdr: ?[]const u8 = null;
                                        var h_it = req.headers.iterator();
                                        while (h_it.next()) |entry| {
                                            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "range")) {
                                                range_hdr = entry.value_ptr.*;
                                                break;
                                            }
                                        }
                                        handler(cfg, allocator, server.io, req.path, range_hdr, stream) catch {
                                            static_served = false;
                                        };
                                        // If the handler returned without error,
                                        // trust it to have sent a response
                                        // (matching the SSE branch's contract).
                                        static_served = true;
                                    }
                                }
                                if (!static_served) {
                                    var not_found = http_parser.notFound(allocator);
                                    // Attach CORS headers to the 404 so cross-origin
                                    // callers see the rejection (with CORS headers
                                    // echoed) instead of an opaque browser-blocked
                                    // response.
                                    server.applyCORSResponse(&req, &not_found) catch @panic("OOM");
                                    // Same keep-alive framing rule as the routed
                                    // path (see above): framing is guaranteed by
                                    // toBytes (auto Content-Length), so reuse
                                    // needs only the client's keep-alive.
                                    not_found.keep_alive = server.clientWantsKeepAlive(&req) and
                                        keep_alive_count < 1000;
                                    const res_bytes = not_found.toBytes() catch {
                                        _ = closeFd(fd);
                                        return;
                                    };
                                    defer not_found.allocator.free(res_bytes);
                                    if (server.sendToStream(stream, res_bytes)) |_| {
                                        if (not_found.keep_alive) {
                                            continue :keep_alive_loop;
                                        }
                                    } else |_| {}
                                    break :keep_alive_loop;
                                }
                                // Static-dir fallback wrote its own (unframed)
                                // response — the connection cannot be reused.
                                break :keep_alive_loop;
                            }

                            // Safety net: every arm above exits explicitly
                            // (continue / break / return). Reaching here
                            // would re-enter the loop on a served connection,
                            // so close instead.
                            break :keep_alive_loop;
                        }
                        _ = closeFd(fd);
                    }
                }.handle,
                .{ self, arena, client_fd },
            ) catch |err| {
                std.debug.print("Failed to spawn handler: {s}\n", .{@errorName(err)});
                arena.deinit();
                self.allocator.destroy(arena);
                _ = closeFd(client_fd);
                continue;
            };
        }

        try group.await(self.io);
    }
    pub fn getContentLength(data: []const u8) ?usize {
        const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return null;
        const headers = data[0..header_end];
        const cl_header = "Content-Length: ";
        const cl_pos = std.mem.indexOf(u8, headers, cl_header) orelse return null;
        const cl_start = cl_pos + cl_header.len;
        // Look for \r\n after the value, or use end of headers if that's the line ending
        const after_value = headers[cl_start..];
        const cl_end = std.mem.indexOf(u8, after_value, "\r\n") orelse after_value.len;
        const cl_str = headers[cl_start .. cl_start + cl_end];
        return std.fmt.parseInt(usize, cl_str, 10) catch null;
    }

    fn isHttpRequestComplete(data: []const u8) bool {
        // Find end of headers
        const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return false;
        const headers = data[0..header_end];

        // No Content-Length means no body (GET, OPTIONS, etc.)
        const cl_header = "Content-Length: ";
        const cl_pos = std.mem.indexOf(u8, headers, cl_header) orelse return true;
        const cl_start = cl_pos + cl_header.len;
        const cl_end = std.mem.indexOf(u8, headers[cl_start..], "\r\n") orelse return false;
        const cl_str = headers[cl_start .. cl_start + cl_end];
        const content_length = std.fmt.parseInt(usize, cl_str, 10) catch return false;

        // Check body bytes received
        const body_start = header_end + 4;
        return data.len >= body_start + content_length;
    }

    /// Accept one client connection (raw `accept(2)`) and apply the
    /// per-connection tuning (TCP keepalive, NODELAY).
    fn acceptClient(self: *GinwaServer) !SocketFd {
        const fd: SocketFd = blk: {
            if (builtin.os.tag == .windows) {
                var client_addr: socket.sockaddr.in = undefined;
                var addr_len: c_int = @sizeOf(socket.sockaddr.in);
                const rc = winsock.accept(self.address.sock_fd, @ptrCast(&client_addr), &addr_len);
                if (rc < 0) return error.AcceptFailed;
                break :blk rc;
            } else {
                var client_addr: posix.sockaddr.in = undefined;
                var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
                const rc = socket.accept(self.address.sock_fd, @ptrCast(&client_addr), &addr_len);
                if (rc < 0) return error.AcceptFailed;
                break :blk @intCast(rc);
            }
        };

        // Enable TCP keepalive on the accepted client socket so a
        // silently-dropped connection (Wi-Fi loss, NAT table expiry,
        // half-open TCP after a peer crash) is detected by the kernel
        // within ~25s instead of relying solely on the application-
        // level heartbeat (every 5s in `SseManager.sendHeartbeat`).
        //
        // Without keepalive, the server keeps heartbeating into a dead
        // socket until the next write fails with EPIPE / ECONNRESET,
        // which can be hours later (Linux default `tcp_keepalive_time`
        // is 7200s). On a long-idle page that hits a silent network
        // drop, the eventual disconnect surfaces in the browser as
        // `net::ERR_INCOMPLETE_CHUNKED_ENCODING 200 (OK)` because the
        // chunked terminator is only flushed by `removeClient` once
        // the kernel finally tells us the peer is gone.
        //
        // Settings mirror `Agent.apply_tcp_keepalive`
        // (`src/modules/agent/Agent.zig:793`) so outbound LLM conns
        // and inbound browser conns fail at the same rate:
        //   keepidle  = 10s  (first probe after 10s of idle)
        //   keepintvl = 5s   (probe interval)
        //   keepcnt   = 3    (give up after 3 failed probes)
        //   → dead-conn detection in ~10 + 5*3 = 25s.
        //
        // `setsockopt` failures are best-effort: the application-
        // level heartbeat (5s) still works without OS keepalive, it
        // just won't catch silent drops as quickly.
        const on: c_int = 1;
        const keepidle: c_int = 10;
        const keepintvl: c_int = 5;
        const keepcnt: c_int = 3;
        if (builtin.os.tag == .windows) {
            _ = winsock.setsockopt(fd, 0xffff, 8, &on, @sizeOf(c_int));
            _ = winsock.setsockopt(fd, 6, 3, &keepidle, @sizeOf(c_int));
            _ = winsock.setsockopt(fd, 6, 17, &keepintvl, @sizeOf(c_int));
            _ = winsock.setsockopt(fd, 6, 16, &keepcnt, @sizeOf(c_int));
        } else {
            posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&on)) catch {};
            // `TCP.KEEPIDLE` is Linux-only; on macOS the equivalent is
            // the KEEPALIVE TCP option (which doubles as the idle
            // timer on Darwin). Skip where it does not exist — the default ~2h
            // idle combined with 5s probe + 3 probes still detects dead
            // connections quickly via SO_KEEPALIVE alone.
            //
            // The gate tests the DECL on `std.c.TCP` rather than
            // `builtin.os.tag`: the cross-compile build graph compiles this file
            // for several targets in one invocation (the app module for the
            // requested target, sibling modules for the host), so a
            // `builtin.os.tag` check can disagree with the `c.TCP` the
            // expression actually resolves against and fail the macOS build with
            // "struct 'c.darwin.TCP' has no member named 'KEEPIDLE'".
            if (@hasDecl(std.c.TCP, "KEEPIDLE")) {
                posix.setsockopt(fd, posix.IPPROTO.TCP, std.c.TCP.KEEPIDLE, std.mem.asBytes(&keepidle)) catch {};
            }
            posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, std.mem.asBytes(&keepintvl)) catch {};
            posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, std.mem.asBytes(&keepcnt)) catch {};
            // Disable Nagle's algorithm: benchmark/small-JSON responses
            // would otherwise wait up to ~40ms for ACK coalescing on
            // keep-alive connections. Best-effort like the keepalive
            // tunables above.
            posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&on)) catch {};
        }

        return fd;
    }

    pub fn recvFromClient(_: *GinwaServer, fd: SocketFd, buf: []u8) !usize {
        if (builtin.os.tag == .windows) {
            const rc = winsock.recv(fd, buf.ptr, @intCast(buf.len), 0);
            if (rc < 0) return error.RecvFailed;
            return @as(usize, @intCast(rc));
        } else {
            const rc = socket.read(fd, buf.ptr, buf.len);
            if (rc < 0) return error.RecvFailed;
            return @as(usize, @intCast(rc));
        }
    }

    /// Write a whole buffer to a `Stream` (plain socket or TLS). Used by the
    /// request path; `sendToClient` stays for the fd-only call sites (tests, the
    /// WebSocket registry) so the plaintext bytes are unchanged.
    pub fn sendToStream(_: *GinwaServer, stream: stream_mod.Stream, data: []const u8) !usize {
        try stream.writeAll(data);
        return data.len;
    }

    pub fn sendToClient(_: *GinwaServer, fd: SocketFd, data: []const u8) !usize {
        if (builtin.os.tag == .windows) {
            const rc = winsock.send(fd, data.ptr, @intCast(data.len), 0);
            if (rc < 0) return error.SendFailed;
            return @as(usize, @intCast(rc));
        } else {
            const rc = socket.write(fd, data.ptr, data.len);
            if (rc < 0) return error.SendFailed;
            return @as(usize, @intCast(rc));
        }
    }

    pub fn getClientPort(_: *GinwaServer, fd: SocketFd) u16 {
        if (builtin.os.tag == .windows) {
            var addr: socket.sockaddr.in = undefined;
            var addr_len: c_int = @sizeOf(socket.sockaddr.in);
            const rc = winsock.getpeername(fd, @ptrCast(&addr), &addr_len);
            if (rc != 0) return 0;
            return @byteSwap(addr.port);
        } else {
            // Zig 0.16's `posix.getpeername` panics on `.BADF` (it marks
            // that error branch as `unreachable` per the `// always a race
            // condition` comment at `std/posix.zig:530`). Guard the call
            // with an explicit fd validity check so callers passing -1
            // (or any other negative fd) get the historical "0 means
            // unknown port" return value rather than crashing the process.
            if (fd < 0) return 0;

            // For valid fds, Zig 0.16's `posix.getpeername` returns an
            // error union. Catch any of FileDescriptorNotASocket /
            // NetworkDown / SocketNotBound / SocketUnconnected /
            // SystemResources / Unexpected and return 0 — matches the
            // original contract for non-connected sockets.
            var addr: posix.sockaddr.in = undefined;
            var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const rc = posix.getpeername(fd, @ptrCast(&addr), &addr_len) catch return 0;
            _ = rc;
            return @byteSwap(addr.port);
        }
    }

    pub fn shutdown(self: *GinwaServer) void {
        self.is_running = false;
        // Unblock the listen loop's blocking accept() call so the
        // loop notices the is_running flag flip and breaks out.
        //
        // Just `close(sock_fd)` is NOT enough: closing the fd in one
        // thread does not reliably wake a `accept()` that another
        // thread is blocked on (Linux's kernel doesn't re-poll
        // pending accepts when the fd table entry is freed — the
        // blocked accept stays parked). On Windows, `close()` is
        // `closesocket()`, but Windows has no signal mechanism to
        // break the accept either.
        //
        // The portable fix is `shutdown(sock, SHUT_RDWR)` — this
        // actively closes the connection state on both Linux and
        // Winsock, which makes any pending `accept()` return
        // immediately with an error. We then `closeFd` to free the
        // kernel resource.
        //
        // Idempotent: safe to call multiple times — a second call
        // sees sock_fd == -1 and is a no-op.
        if (self.address.sock_fd != -1) {
            shutdownListenerFd(self.address.sock_fd);
            closeFd(self.address.sock_fd);
            self.address.sock_fd = -1;
        }
    }

    /// Apply CORS response headers to a response built elsewhere (a
    /// handler return, a 404 fallback). Thin shim that forwards to
    /// `security.applyCORSResponse`.
    fn applyCORSResponse(self: *GinwaServer, request: *const HttpRequest, resp: *HttpResponse) !void {
        return security.applyCORSResponse(resp, request, self.cors);
    }

    /// Apply this server's `security_headers` config to a response in
    /// place. Called by the dispatch loop on every routed response so the
    /// app-level policy (set once after init) governs all handlers —
    /// handlers that also call `.withSecurityHeaders()` simply get their
    /// values overwritten here (put replaces).
    /// Decide whether the connection may be reused for another request
    /// after this response (HTTP keep-alive). HTTP/1.1 and later persist
    /// by default; HTTP/1.0 closes unless the client sends
    /// `Connection: keep-alive`. An explicit `Connection: close` always
    /// wins (also covers `Connection: keep-alive, close`).
    fn clientWantsKeepAlive(_: *GinwaServer, req: *const HttpRequest) bool {
        var it = req.headers.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "connection")) {
                const v = entry.value_ptr.*;
                if (std.ascii.indexOfIgnoreCase(v, "close") != null) return false;
                if (std.ascii.indexOfIgnoreCase(v, "keep-alive") != null) return true;
                break;
            }
        }
        return !std.mem.eql(u8, req.version, "HTTP/1.0");
    }

    pub fn applySecurityHeadersTo(self: *GinwaServer, resp: *HttpResponse) void {
        if (!self.enable_security_headers) return;
        security.applySecurityHeadersWith(resp, self.security_headers);
    }

    /// Build a `204 No Content` CORS preflight response. Thin shim
    /// that forwards to `security.buildPreflightResponse`.
    fn buildCORSPreflight(self: *GinwaServer, request: *const HttpRequest, allocator: std.mem.Allocator) !HttpResponse {
        return security.buildPreflightResponse(allocator, request, self.cors);
    }
};

fn recvFromSock(fd: SocketFd, buf: [*]u8, len: usize) isize {
    if (builtin.os.tag == .windows) {
        return winsock.recv(@intCast(fd), buf, @intCast(len), 0);
    } else {
        return socket.read(fd, buf, len);
    }
}

/// Request buffer with auto-growing capability for reading HTTP requests
pub const RequestBuffer = struct {
    allocator: std.mem.Allocator,
    buf: std.ArrayList(u8),
    tmp: [4096]u8,

    /// Initialize a new RequestBuffer
    pub fn init(allocator: std.mem.Allocator) RequestBuffer {
        return .{
            .allocator = allocator,
            .buf = .empty,
            .tmp = undefined,
        };
    }

    /// Free all resources
    pub fn deinit(self: *RequestBuffer) void {
        self.buf.deinit(self.allocator);
    }

    pub fn getContentLength(data: []const u8) ?usize {
        const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return null;
        const headers = data[0..header_end];

        // Scan header lines for a case-insensitive "content-length" prefix.
        // Matches the case-insensitive scan in `readFullRequest` below
        // so a static call sees the same answer as the streaming call.
        var cl_pos: ?usize = null;
        var lines = std.mem.splitSequence(u8, headers, "\r\n");
        while (lines.next()) |line| {
            if (line.len >= 15 and std.ascii.eqlIgnoreCase(line[0..14], "content-length")) {
                cl_pos = @intCast(line.ptr - headers.ptr);
                break;
            }
        }
        if (cl_pos == null) {
            return null;
        }

        const cl_start = cl_pos.? + 14; // skip "content-length"

        // Skip the colon + OWS (optional whitespace per RFC 7230 §3.2.3)
        var actual_start = cl_start;
        while (actual_start < headers.len and
            (headers[actual_start] == ':' or
                headers[actual_start] == ' ' or
                headers[actual_start] == '\t'))
        {
            actual_start += 1;
        }

        const after_value = headers[actual_start..];

        // Find end of line
        var end_idx: usize = 0;
        while (end_idx < after_value.len and after_value[end_idx] != '\r' and after_value[end_idx] != '\n') {
            end_idx += 1;
        }

        const cl_str = after_value[0..end_idx];
        return std.fmt.parseInt(usize, cl_str, 10) catch null;
    }

    /// Read the full HTTP request (headers + body) from a socket
    /// Returns the complete request data or an error
    /// Read one complete request from a plain socket. Thin wrapper kept for
    /// today's tests and fd-only callers.
    pub fn readFullRequest(self: *RequestBuffer, fd: SocketFd) ![]u8 {
        return self.readFullRequestStream(.{ .plain = fd });
    }

    /// Hand over the buffered bytes WITHOUT copying: the caller takes
    /// ownership (frees exactly once) and the buffer is forgotten, so a
    /// later `deinit` is a no-op. Replaces `toOwnedSlice` on the hot path
    /// — saves one full-request-size alloc + memcpy per request. Safe for
    /// both arena and testing allocators: exactly one owner either way
    /// (toOwnedSlice also emptied the buffer).
    fn takeBytes(self: *RequestBuffer) []u8 {
        const out = self.buf.items;
        self.buf = .empty;
        return out;
    }

    /// Read one complete request from a `Stream` (plain socket OR TLS).
    ///
    /// The HTTP/1.1 path MUST read through the transport: on an encrypted
    /// connection the raw fd carries ciphertext, so reading the fd directly after
    /// the TLS handshake hangs or truncates the request (it looked like
    /// `IncompleteRequest` with curl timing out).
    pub fn readFullRequestStream(self: *RequestBuffer, stream: stream_mod.Stream) ![]u8 {
        // Phase 1: read until we have complete headers
        while (std.mem.indexOf(u8, self.buf.items, "\r\n\r\n") == null) {
            const n = stream.read(&self.tmp) catch return error.RecvFailed;
            if (n == 0) break;
            try self.buf.appendSlice(self.allocator, self.tmp[0..n]);
        }

        const header_end_idx = std.mem.indexOf(u8, self.buf.items, "\r\n\r\n") orelse {
            if (self.buf.items.len == 0) return error.ConnectionClosed;
            return self.takeBytes();
        };

        // Phase 2: parse Content-Length by scanning header lines
        const content_length = blk: {
            const header_section = self.buf.items[0..header_end_idx];
            var lines = std.mem.splitSequence(u8, header_section, "\r\n");
            _ = lines.next(); // skip request line
            while (lines.next()) |line| {
                // Case-insensitive match for "content-length"
                if (line.len > 15 and std.ascii.eqlIgnoreCase(line[0..14], "content-length")) {
                    // Find the colon, skip it and any whitespace
                    const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
                    const value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");
                    break :blk std.fmt.parseInt(usize, value, 10) catch {
                        return error.BadRequest;
                    };
                }
            }
            // No Content-Length header found (e.g. GET request)
            return self.takeBytes();
        };

        // Phase 3: read body
        const target_len = header_end_idx + 4 + content_length;

        while (self.buf.items.len < target_len) {
            const remaining_bytes = target_len - self.buf.items.len;
            const to_read = @min(remaining_bytes, self.tmp.len);
            const n = stream.read(self.tmp[0..to_read]) catch return error.RecvFailed;
            if (n == 0) break;
            try self.buf.appendSlice(self.allocator, self.tmp[0..n]);
        }

        return self.takeBytes();
    }
};

/// SSE Event structure
pub const SseEvent = struct {
    data: []const u8,
    event_type: ?[]const u8 = null,
};

// ═══════════════════════════════════════════════════════════════════════════
//  CORS configuration
// ═══════════════════════════════════════════════════════════════════════════

/// CORS (Cross-Origin Resource Sharing) configuration applied server-wide
/// when `enabled` is true. Defaults to "CORS off" — same-origin only — so
/// existing routes keep working with no behaviour change.
///
/// Configure after `GinwaServer.init`:
///   server.cors = .{
///       .enabled = true,
///       .allowed_origins = &.{ "localhost:4021", "app.example.com" },
///       .allow_credentials = true,
///   };
///
/// When `enabled`:
///   * `OPTIONS <path>` requests are auto-answered with the configured
///     methods + headers + max_age (`204 No Content`).
///   * Every response carries `Access-Control-Allow-Origin` (echoed from
///     the request Origin) when the Origin matches an `allowed_origins`
///     entry; requests with mismatched Origin are rejected with `403`.
///   * `Vary: Origin` is attached so caches don't leak across origins.
///
/// The pure helper functions live in `security.zig`
/// (`security.buildPreflightResponse`, `security.buildPreHandlerFailRedirect`,
/// `security.applyCORSResponse`) — this type is a thin field-mirror so
/// `GinwaServer.cors` can be forwarded by value into those helpers.
pub const CORSConfig = security.CORSConfig;
