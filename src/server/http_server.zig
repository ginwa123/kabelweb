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
// Event-loop reactor (non-blocking alternative to `listen()`).
// `listenEventLoop` serves plain HTTP/1.1 through a single poll loop;
// the threaded `listen()` path is unchanged.
const event_loop_mod = @import("event_loop.zig");
const nb_socket_mod = @import("nb_socket.zig");
pub const EventLoop = event_loop_mod.EventLoop;
pub const EventLoopConfig = event_loop_mod.Config;
pub const EventLoopStats = event_loop_mod.Stats;
/// Max poll loops one `listenEventLoop` call will run (fixed server-side
/// arrays; raise if a 16-core box ever wants more than one loop per core).
pub const max_multi_loops = 16;
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

    /// Last event-loop run's counters. Written by `listenEventLoop` on exit
    /// (summed across loops when `loop_count > 1`); untouched by the
    /// threaded `listen()`. Read after `shutdown`+join.
    el_stats: EventLoopStats = .{},

    /// Multi-loop listener fds owned by the `loop_count > 1` path of
    /// `listenEventLoop` (fixed cap; see `max_multi_loops`). Registered
    /// BEFORE loop threads spawn so `shutdown()` can close them mid-run;
    /// entries flip to -1 on close.
    el_multi_fds: [max_multi_loops]i32 = [_]i32{-1} ** max_multi_loops,
    /// Live loop pointers for `shutdown()`'s `requestShutdown` backup.
    /// Valid only while a multi-loop `listenEventLoop` runs (it joins all).
    el_multi_loops: [max_multi_loops]?*EventLoop = [_]?*EventLoop{null} ** max_multi_loops,
    /// How many of the above slots are registered.
    el_multi_count: usize = 0,

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


    /// Serve through the poll reactor — the single serve path (the old
    /// thread-per-connection `listen()` was deleted). One entry point:
    /// `cfg.loop_count` selects the shape — `0`/`1` runs a single loop
    /// on the calling thread, `>1` runs that many loops sharing the port
    /// via `SO_REUSEPORT` (kernel-balanced accepts, stats summed into
    /// `el_stats`; POSIX-only, clamped to `max_multi_loops`).
    ///
    /// The loop accepts + fast-dispatches plain HTTP/1.1 itself; anything
    /// long-lived or blocking hijacks the fd to a worker thread (blocking
    /// mode restored): static files → bounded pool, SSE/WS/H2/TLS → a
    /// dedicated thread each, reusing the existing managers verbatim.
    /// `shutdown()` closes the listener fd(s), which makes each
    /// reactor's `poll` report HUP and exit.
    pub fn listenEventLoop(self: *GinwaServer, cfg: event_loop_mod.Config) !void {
        // Runner hooks are process-global (idempotent installs for the
        // loop's indirect calls): TLS accept/serve + H2C driver.
        event_loop_mod.EventLoop.setTlsHijackRun(runTlsServe);
        event_loop_mod.EventLoop.setH2HijackRun(runH2Serve);
        var lc = cfg;
        lc.tls_enabled = self.tls_ctx != null;
        lc.h2c_enabled = self.enable_h2c;
        if (lc.loop_count > 1) {
            if (comptime builtin.os.tag == .windows) return error.Unsupported;
            return self.serveMultiLoop(lc);
        }
        return self.serveSingleLoop(lc);
    }

    /// Single-loop path: `listen()` on the bound socket, one reactor on
    /// the calling thread. Cross-platform (Windows via `WSAPoll`).
    fn serveSingleLoop(self: *GinwaServer, cfg: event_loop_mod.Config) !void {
        _ = nb_socket_mod.POLL.IN; // keep import live on all POSIX targets

        if (builtin.os.tag == .windows) {
            const rc = winsock.listen(self.address.sock_fd, 1024);
            if (rc != 0) return error.ListenFailed;
        } else {
            const rc = socket.listen(self.address.sock_fd, 1024);
            if (rc < 0) return error.ListenFailed;
        }

        // Same best-effort cron start as `listen()`.
        if (self.cronjob_manager.start()) |_| {
            std.debug.print("Cronjob manager running (1s tick)\n", .{});
        } else |err| {
            std.debug.print("HTTP_SERVER: cronjob manager start failed: {s}\n", .{@errorName(err)});
        }

        self.is_running = true;
        var loop = event_loop_mod.EventLoop.init(self.allocator, self.io, cfg);
        defer loop.deinit();
        const template = HttpContext{
            .allocator = self.allocator,
            .io = self.io,
            .allowed_origins = self.cors.allowed_origins,
        };
        // Listener close (via `shutdown()`) surfaces as POLLHUP inside
        // `run` and breaks the loop; `is_running` is cleared on exit so
        // `shutdown()` remains idempotent across both serve paths.
        // Loop stats are copied out for observability (tests, /health).
        loop.run(self.address.sock_fd, dispatchEventLoopRequest, @ptrCast(self), template) catch |err| {
            self.el_stats = loop.stats;
            self.is_running = false;
            return err;
        };
        self.el_stats = loop.stats;
        self.is_running = false;
    }

    /// Multi-loop path: N poll loops sharing one port via `SO_REUSEPORT`.
    /// POSIX-only (no Windows equivalent; the caller fails fast there).
    ///
    /// Mechanics: the bound ip:port is read off `address.sock_fd` with
    /// `getsockname` (so ephemeral port 0 works), the original socket is
    /// closed (it never listened), and each loop thread binds its own
    /// REUSEPORT listener on the same ip:port. The kernel balances
    /// accepts; per-loop `EventLoop.stats` are summed into `el_stats`.
    /// `shutdown()` closes every listener (loops exit on HUP) and flags
    /// the loops; this function joins all threads before returning.
    fn serveMultiLoop(self: *GinwaServer, cfg: event_loop_mod.Config) !void {
        var bound: socket.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(socket.sockaddr.in);
        if (socket.getsockname(self.address.sock_fd, @ptrCast(&bound), &bound_len) != 0)
            return error.GetSockNameFailed;
        const host_le: u32 = @bitCast(bound.addr);
        var port: u16 = @byteSwap(bound.port);

        // Caller guarantees loop_count > 1; clamp to the fixed slots.
        var n: usize = cfg.loop_count;
        if (n > max_multi_loops) {
            std.debug.print("HTTP_SERVER: clamping loops {d} → {d} (max_multi_loops)\n", .{ n, max_multi_loops });
            n = max_multi_loops;
        }

        // Same best-effort cron start as the other serve paths.
        if (self.cronjob_manager.start()) |_| {
            std.debug.print("Cronjob manager running (1s tick)\n", .{});
        } else |err| {
            std.debug.print("HTTP_SERVER: cronjob manager start failed: {s}\n", .{@errorName(err)});
        }

        // Bind every listener up front (sequentially — binds are cheap).
        // Loop 0 may resolve an ephemeral port; the rest reuse it.
        //
        // The original Address socket is closed FIRST (it never listened):
        // macOS refuses REUSEPORT binds while ANY non-REUSEPORT socket
        // holds the same tuple (EADDRINUSE), even one that never called
        // listen() — Linux tolerates the overlap, macOS does not.
        if (self.address.sock_fd != -1) {
            closeFd(self.address.sock_fd);
            self.address.sock_fd = -1;
        }
        var fds: [max_multi_loops]i32 = [_]i32{-1} ** max_multi_loops;
        errdefer for (fds[0..n]) |fd| {
            if (fd != -1) closeFd(fd);
        };
        for (0..n) |i| {
            fds[i] = try nb_socket_mod.bindReusePort(host_le, port);
            if (i == 0 and port == 0) {
                var b0: socket.sockaddr.in = undefined;
                var l0: posix.socklen_t = @sizeOf(socket.sockaddr.in);
                if (socket.getsockname(fds[i], @ptrCast(&b0), &l0) != 0) return error.GetSockNameFailed;
                port = @byteSwap(b0.port);
            }
        }

        for (0..n) |i| self.el_multi_fds[i] = fds[i];
        self.el_multi_count = n;
        errdefer {
            for (self.el_multi_fds[0..n]) |*fd| {
                if (fd.* != -1) {
                    closeFd(fd.*);
                    fd.* = -1;
                }
            }
            self.el_multi_count = 0;
        }

        const template = HttpContext{
            .allocator = self.allocator,
            .io = self.io,
            .allowed_origins = self.cors.allowed_origins,
        };
        const Slot = struct {
            server: *GinwaServer,
            fd: i32,
            cfg: event_loop_mod.Config,
            template: HttpContext,
            stats: EventLoopStats = .{},
            err: ?anyerror = null,
            fn run(s: *@This()) void {
                var loop = event_loop_mod.EventLoop.init(s.server.allocator, s.server.io, s.cfg);
                defer loop.deinit();
                s.server.el_multi_loops[s.cfg.loop_id] = &loop;
                defer s.server.el_multi_loops[s.cfg.loop_id] = null;
                loop.run(s.fd, dispatchEventLoopRequest, @ptrCast(s.server), s.template) catch |err| {
                    s.err = err;
                    s.stats = loop.stats;
                    return;
                };
                s.stats = loop.stats;
            }
        };
        var slots: [max_multi_loops]Slot = undefined;
        var threads: [max_multi_loops]std.Thread = undefined;
        var spawned: usize = 0;
        errdefer {
            // A spawn failed mid-way: stop what started via the same path
            // `shutdown()` uses (closes listeners → loops exit on HUP),
            // join, and reset the slots so no stale state survives.
            self.shutdown();
            for (threads[0..spawned]) |t| t.join();
            for (self.el_multi_fds[0..n]) |*fd| {
                if (fd.* != -1) {
                    closeFd(fd.*);
                    fd.* = -1;
                }
            }
            for (self.el_multi_loops[0..n]) |*maybe| maybe.* = null;
            self.el_multi_count = 0;
        }
        for (0..n) |i| {
            var lc = cfg;
            lc.loop_id = i;
            lc.loop_count = n;
            slots[i] = .{
                .server = self,
                .fd = fds[i],
                .cfg = lc,
                .template = template,
            };
            threads[i] = try std.Thread.spawn(.{}, Slot.run, .{&slots[i]});
            spawned += 1;
        }

        self.is_running = true;
        for (threads[0..n]) |t| t.join();
        self.is_running = false;

        // Aggregate + release. `shutdown()` may already have closed some
        // fds (marked -1); close only the leftovers, then reset the count
        // so the slots read "no multi run active" again.
        var total = EventLoopStats{};
        var first_err: ?anyerror = null;
        for (0..n) |i| {
            total = total.combine(slots[i].stats);
            if (slots[i].err) |e| {
                if (first_err == null) first_err = e;
            }
            if (self.el_multi_fds[i] != -1) {
                closeFd(self.el_multi_fds[i]);
                self.el_multi_fds[i] = -1;
            }
            self.el_multi_loops[i] = null;
        }
        self.el_multi_count = 0;
        self.el_stats = total;
        std.debug.print(
            "HTTP_SERVER: multi-loop exit loops={d} accepted={d} served={d}\n",
            .{ n, total.accepted, total.served },
        );
        if (first_err) |e| return e;
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
        // Event-loop multi-run: close every registered REUSEPORT listener
        // (each loop's poll reports HUP and exits) and flag the loops to
        // stop. Slots flip to -1/null so the `listenEventLoop` return path
        // (which also closes leftovers) never double-closes.
        for (self.el_multi_fds[0..self.el_multi_count]) |*fd| {
            if (fd.* != -1) {
                shutdownListenerFd(fd.*);
                closeFd(fd.*);
                fd.* = -1;
            }
        }
        for (self.el_multi_loops[0..self.el_multi_count]) |maybe_loop| {
            if (maybe_loop) |lp| lp.requestShutdown();
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

/// Reactor dispatch for `GinwaServer.listenEventLoop` (matches
/// `event_loop_mod.OnRequestFn`). Synchronous fast path: pre-gate → CORS
/// preflight → router handler → 404. Long-lived or blocking work hijacks
/// the fd to a worker thread instead of answering here:
///   - SSE / WebSocket routes → dedicated thread (existing managers).
///   - static-dir fallback → bounded static pool.
///   - (TLS connections never reach this: they hijack at accept time.
///    H2C never reaches this: it hijacks at sniff time.)
/// `Session.deinit` is a no-op so wiring `req.session` here is safe: the
/// reactor serializes the returned response from the same arena.
fn dispatchEventLoopRequest(
    ctx_ptr: *anyopaque,
    alloc: std.mem.Allocator,
    req_bytes: []const u8,
    req_in: *const HttpRequest,
    http_ctx_in: HttpContext,
) anyerror!event_loop_mod.DispatchResult {
    _ = req_bytes;
    const server: *GinwaServer = @ptrCast(@alignCast(ctx_ptr));
    var req = req_in.*;
    var http_ctx = http_ctx_in;
    http_ctx.allocator = alloc;
    http_ctx.allowed_origins = server.cors.allowed_origins;

    const lookup: context.LookupResult = if (server.context_store) |store|
        context.contextFromRequest(req, store)
    else
        .{ .context = null, .id = null };
    var session = Session.init(server.context_store, lookup.context, lookup.id);
    req.session = &session;

    // Engine pre-gate (body cap + origin allowlist). Threaded path closes
    // on block; here `keep_alive = false` makes the reactor close after
    // flushing the page.
    {
        const gate = security.preGateCheck(&req, server.cors, server.max_body_bytes) catch .pass;
        if (gate != .pass) {
            const origin: ?[]const u8 = blk: {
                var oit = req.headers.iterator();
                while (oit.next()) |entry| {
                    if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "origin")) break :blk entry.value_ptr.*;
                }
                break :blk null;
            };
            const host = if (server.cors.allowed_origins.len > 0) server.cors.allowed_origins[0] else "your-domain";
            var page = try security.buildEngineBlockPage(alloc, gate, origin, host);
            server.applySecurityHeadersTo(&page);
            if (origin) |o| {
                security.applyCORSHeaders(
                    &page.headers,
                    o,
                    server.cors.allowed_origins,
                    server.cors.allowed_methods,
                    server.cors.allowed_headers,
                    server.cors.allow_credentials,
                ) catch {};
            }
            page.keep_alive = false;
            return .{ .respond = page };
        }
    }

    // CORS preflight short-circuit (threaded path closes afterwards).
    if (server.cors.enabled and std.mem.eql(u8, req.method, "OPTIONS")) {
        var preflight = try server.buildCORSPreflight(&req, alloc);
        preflight.keep_alive = false;
        return .{ .respond = preflight };
    }

    if (server.router.matchRoute(req.method, req.path, &req, http_ctx)) |result| {
        switch (result) {
            .handler => |h| {
                if (h.max_body_bytes != 0) {
                    const gate = security.preGateCheck(&req, .{ .enabled = false }, h.max_body_bytes) catch .pass;
                    if (gate != .pass) {
                        var page = try security.buildEngineBlockPage(alloc, gate, null, "your-domain");
                        page.keep_alive = false;
                        return .{ .respond = page };
                    }
                }
                var final = try h.chain.run(h.ctx, h.req, h.res);
                server.applyCORSResponse(&req, &final) catch {};
                server.applySecurityHeadersTo(&final);
                final.keep_alive = server.clientWantsKeepAlive(&req);
                return .{ .respond = final };
            },
            .websocket => {
                // WebSocket sessions are long-lived blocking read loops —
                // hijack the fd to a dedicated thread (same manager flow
                // as the old threaded path). Over TLS there is no loop
                // upgrade yet: 501 like the old path did.
                if (server.tls_ctx != null) {
                    var res = HttpResponse.init(501, "Not Implemented", alloc)
                        .withBody("WebSocket is not available over TLS yet.");
                    res.keep_alive = false;
                    return .{ .respond = res };
                }
                return .{ .hijack_ws = .{ .ctx = ctx_ptr, .run = runWsServe } };
            },
            .sse => {
                // SSE streams are long-lived — hijack the fd to a dedicated
                // thread running the existing SseManager flow. Over TLS:
                // 501 like the old path did.
                if (server.tls_ctx != null) {
                    var res = HttpResponse.init(501, "Not Implemented", alloc)
                        .withBody("SSE is not available over TLS yet.");
                    res.keep_alive = false;
                    return .{ .respond = res };
                }
                return .{ .hijack_sse = .{ .ctx = ctx_ptr, .run = runSseServe } };
            },
        }
    }

    // No route: static-dir fallback hijacks to the bounded static pool
    // (blocking file serve). Without a configured handler, 404 with
    // keep-alive framing like the old threaded path.
    if (server.static_dir_handler != null and server.static_dir_cfg != null) {
        return .{ .hijack_static = .{ .ctx = ctx_ptr, .run = runStaticServe } };
    }
    var not_found = http_parser.notFound(alloc);
    server.applyCORSResponse(&req, &not_found) catch {};
    server.applySecurityHeadersTo(&not_found);
    not_found.keep_alive = server.clientWantsKeepAlive(&req);
    return .{ .respond = not_found };
}

/// Bridge `WsManager`'s `fn(ctx, fd, data)` write API to the server's
/// `sendToClient` (blocking raw send — hijacked fds are blocking again).
fn wsWriteAdapter(ctx: ?*anyopaque, target_fd: i32, data: []const u8) anyerror!usize {
    const server_ptr: *GinwaServer = @ptrCast(@alignCast(ctx.?));
    return server_ptr.sendToClient(target_fd, data);
}

/// Static-dir hijack runner (static pool thread or TLS worker).
/// Contract (see `event_loop.Hijack`): blocking fd, serve, close. Never
/// frees `req_bytes` (the spawner does). Mirrors the old threaded
/// no-route arm: re-parse → Range scan → handler → 404 on error → close
/// (static responses are unframed, so the conn is never reused).
fn runStaticServe(ctx_ptr: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: SocketFd, req_bytes: []const u8) void {
    const server: *GinwaServer = @ptrCast(@alignCast(ctx_ptr));
    nb_socket_mod.setBlocking(fd) catch {
        closeFd(fd);
        return;
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();
    var req = http_parser.parseRequest(req_bytes, a, io, fd) catch {
        closeFd(fd);
        return;
    };
    const lookup: context.LookupResult = if (server.context_store) |store|
        context.contextFromRequest(req, store)
    else
        .{ .context = null, .id = null };
    var session = Session.init(server.context_store, lookup.context, lookup.id);
    req.session = &session;

    const stream: Stream = .{ .plain = fd };
    const handler = server.static_dir_handler orelse {
        serveNotFound(server, a, stream);
        closeFd(fd);
        return;
    };
    const cfg = server.static_dir_cfg orelse {
        serveNotFound(server, a, stream);
        closeFd(fd);
        return;
    };
    var range_hdr: ?[]const u8 = null;
    var h_it = req.headers.iterator();
    while (h_it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "range")) {
            range_hdr = entry.value_ptr.*;
            break;
        }
    }
    handler(cfg, a, io, req.path, range_hdr, stream) catch {
        // Handler error → 404 fallback (same as the old threaded arm;
        // best-effort: a partially-written body can't be unwound).
        serveNotFound(server, a, stream);
    };
    closeFd(fd);
}

/// Best-effort 404 write for hijack runners (no keep-alive framing —
/// hijacked conns always close afterwards).
fn serveNotFound(server: *GinwaServer, alloc: std.mem.Allocator, stream: Stream) void {
    var nf = http_parser.notFound(alloc);
    server.applySecurityHeadersTo(&nf);
    const bytes = nf.toBytes() catch return;
    defer alloc.free(bytes);
    stream.writeAll(bytes) catch {};
}

/// SSE hijack runner (dedicated thread per stream). Mirrors the old
/// threaded `.sse` arm verbatim: headers → register → handler →
/// removeClient (which closes). Never frees `req_bytes` (spawner does).
fn runSseServe(ctx_ptr: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: SocketFd, req_bytes: []const u8) void {
    const server: *GinwaServer = @ptrCast(@alignCast(ctx_ptr));
    nb_socket_mod.setBlocking(fd) catch {
        closeFd(fd);
        return;
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();
    var req = http_parser.parseRequest(req_bytes, a, io, fd) catch {
        closeFd(fd);
        return;
    };
    const lookup: context.LookupResult = if (server.context_store) |store|
        context.contextFromRequest(req, store)
    else
        .{ .context = null, .id = null };
    var session = Session.init(server.context_store, lookup.context, lookup.id);
    req.session = &session;

    const http_ctx = HttpContext{
        .allocator = a,
        .io = io,
        .allowed_origins = server.cors.allowed_origins,
    };
    const result = server.router.matchRoute(req.method, req.path, &req, http_ctx) orelse {
        closeFd(fd);
        return;
    };
    const sse = switch (result) {
        .sse => |s| s,
        // Route table changed under us (or TLS raced here): close.
        else => {
            closeFd(fd);
            return;
        },
    };
    const stream: Stream = .{ .plain = fd };
    const headers = "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/event-stream\r\n" ++
        "Cache-Control: no-cache\r\n" ++
        "Connection: close\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "X-Accel-Buffering: no\r\n" ++
        "Access-Control-Allow-Origin: *\r\n" ++
        "\r\n";
    stream.writeAll(headers) catch {
        closeFd(fd);
        return;
    };
    const client_id = server.sse_manager.registerClient(fd) catch {
        closeFd(fd);
        return;
    };
    defer server.sse_manager.removeClient(client_id, .explicit_shutdown);

    var sse_ctx = sse.ctx;
    sse_ctx.client_id = client_id;
    sse_ctx.allocator = a;
    const res = http_parser.HttpResponse.init(200, "OK", a);
    _ = sse.handler(sse_ctx, sse.req, res) catch |err| {
        if (err != error.WouldBlock) {
            std.debug.print("SSE handler error: {s}\n", .{@errorName(err)});
        }
    };
}

/// WebSocket hijack runner (dedicated thread per session). Mirrors the old
/// threaded `.websocket` arm verbatim. Never frees `req_bytes`.
fn runWsServe(ctx_ptr: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: SocketFd, req_bytes: []const u8) void {
    const server: *GinwaServer = @ptrCast(@alignCast(ctx_ptr));
    nb_socket_mod.setBlocking(fd) catch {
        closeFd(fd);
        return;
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();
    var req = http_parser.parseRequest(req_bytes, a, io, fd) catch {
        closeFd(fd);
        return;
    };
    const lookup: context.LookupResult = if (server.context_store) |store|
        context.contextFromRequest(req, store)
    else
        .{ .context = null, .id = null };
    var session = Session.init(server.context_store, lookup.context, lookup.id);
    req.session = &session;

    const http_ctx = HttpContext{
        .allocator = a,
        .io = io,
        .allowed_origins = server.cors.allowed_origins,
    };
    const result = server.router.matchRoute(req.method, req.path, &req, http_ctx) orelse {
        closeFd(fd);
        return;
    };
    const ws = switch (result) {
        .websocket => |w| w,
        else => {
            closeFd(fd);
            return;
        },
    };
    const stream: Stream = .{ .plain = fd };
    if (!ws_handshake.isWebSocketRequest(&req)) {
        const bad = http_parser.badRequest("WebSocket upgrade required", a);
        const bytes = bad.toBytes() catch {
            closeFd(fd);
            return;
        };
        defer a.free(bytes);
        stream.writeAll(bytes) catch {};
        closeFd(fd);
        return;
    }
    const key = ws_handshake.extractWebSocketKey(&req) catch {
        closeFd(fd);
        return;
    };
    const accept_resp = ws_handshake.buildAcceptResponse(a, key) catch {
        closeFd(fd);
        return;
    };
    defer a.free(accept_resp);
    stream.writeAll(accept_resp) catch {
        closeFd(fd);
        return;
    };

    var client_id = server.ws_manager.registerClient(fd, wsWriteAdapter, ctx_ptr) catch {
        closeFd(fd);
        return;
    };
    ws.handler(ws.ctx, ws.req, ctx_ptr, fd, &client_id) catch |err| {
        std.debug.print("WebSocket handler error: {s}\n", .{@errorName(err)});
    };

    const close_payload = "\x03\xe8"; // status 1000 normal closure
    const close_frame = ws_frames.encodeFrame(a, .{
        .opcode = .close,
        .payload = close_payload,
    }) catch null;
    if (close_frame) |cf| {
        defer a.free(cf);
        stream.writeAll(cf) catch {};
    }
    server.ws_manager.removeClient(&client_id, .explicit);
    // WsClient.deinit frees only the arena (unlike SSE, which closes):
    // the fd close lived in the old handle() tail, so do it here.
    closeFd(fd);
}

/// H2C hijack runner (dedicated thread per H2 connection). `data` is the
/// buffered preface+frames the loop sniffed. Never frees `data`.
fn runH2Serve(ctx_ptr: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: SocketFd, data: []const u8) void {
    _ = io;
    const server: *GinwaServer = @ptrCast(@alignCast(ctx_ptr));
    nb_socket_mod.setBlocking(fd) catch {
        closeFd(fd);
        return;
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const stream: Stream = .{ .plain = fd };
    http2_server.serveConnection(server, stream, arena.allocator(), data, .{}) catch |err| {
        std.debug.print("HTTP_SERVER: h2 connection ended: {s}\n", .{@errorName(err)});
    };
    closeFd(fd);
}

/// TLS hijack runner (dedicated thread per encrypted conn). Handshake,
/// then ALPN dispatch: `h2` → H2 driver over the TLS stream, anything
/// else → blocking H1 keep-alive loop over the TLS stream (reusing the
/// loop's dispatch + RequestBuffer; SSE/WS-over-TLS stay 501 via the
/// dispatch's `tls_ctx` check, static serves with the TLS stream).
/// Never frees `data` (always empty here).
fn runTlsServe(ctx_ptr: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: SocketFd, data: []const u8) void {
    _ = data;
    const server: *GinwaServer = @ptrCast(@alignCast(ctx_ptr));
    installTlsStreamOps();
    const tls_ctx = server.tls_ctx orelse {
        closeFd(fd);
        return;
    };
    var tls_conn = tls_mod.Conn.accept(tls_ctx, fd) catch |err| {
        std.debug.print("HTTP_SERVER: TLS handshake failed: {s}\n", .{@errorName(err)});
        closeFd(fd);
        return;
    };
    defer tls_conn.deinit();
    const stream: Stream = .{ .tls = @ptrCast(tls_conn) };
    const negotiated = tls_conn.selectedAlpn();
    std.debug.print("HTTP_SERVER: TLS ok (alpn='{s}' len={d})\n", .{ negotiated, negotiated.len });
    if (std.mem.eql(u8, negotiated, tls_mod.alpn_h2)) {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        http2_server.serveConnection(server, stream, arena.allocator(), "", .{}) catch |err| {
            std.debug.print("HTTP_SERVER: h2 (TLS) connection ended: {s}\n", .{@errorName(err)});
        };
        closeFd(fd);
        return;
    }

    // Blocking H1 keep-alive loop over the encrypted stream. Per-request
    // arena discipline mirrors the old threaded path (reset per request,
    // retain capacity; max 1000 requests per conn).
    var request_arena = std.heap.ArenaAllocator.init(alloc);
    defer request_arena.deinit();
    var keep_alive_count: u32 = 0;
    while (true) {
        keep_alive_count += 1;
        _ = request_arena.reset(.retain_capacity);
        const a = request_arena.allocator();
        var rb = RequestBuffer.init(a);
        const request_data = rb.readFullRequestStream(stream) catch break;
        var req = http_parser.parseRequest(request_data, a, io, fd) catch break;
        const http_ctx = HttpContext{
            .allocator = a,
            .io = io,
            .allowed_origins = server.cors.allowed_origins,
        };
        const result = dispatchEventLoopRequest(ctx_ptr, a, request_data, &req, http_ctx) catch break;
        switch (result) {
            .respond => |r| {
                var rr = r;
                rr.keep_alive = rr.keep_alive and keep_alive_count < 1000;
                const bytes = rr.toBytes() catch break;
                defer a.free(bytes);
                stream.writeAll(bytes) catch break;
                if (!rr.keep_alive) break;
            },
            .hijack_static => {
                // Static over TLS serves inline (same worker owns the
                // encrypted stream; no fd handoff possible mid-TLS).
                var sreq = http_parser.parseRequest(request_data, a, io, fd) catch break;
                const slookup: context.LookupResult = if (server.context_store) |store|
                    context.contextFromRequest(sreq, store)
                else
                    .{ .context = null, .id = null };
                var ssession = Session.init(server.context_store, slookup.context, slookup.id);
                sreq.session = &ssession;
                const shandler = server.static_dir_handler orelse break;
                const scfg = server.static_dir_cfg orelse break;
                var range_hdr: ?[]const u8 = null;
                var h_it = sreq.headers.iterator();
                while (h_it.next()) |entry| {
                    if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "range")) {
                        range_hdr = entry.value_ptr.*;
                        break;
                    }
                }
                shandler(scfg, a, io, sreq.path, range_hdr, stream) catch {};
                break; // static responses are unframed: never reuse
            },
            // SSE/WS-over-TLS dispatch to 501 responds (tls_ctx check);
            // H2 never surfaces here (ALPN decided above). Defensive close.
            .hijack_sse, .hijack_ws => break,
        }
        rb.deinit();
    }
    closeFd(fd);
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

    /// Hand over the buffered bytes: the caller takes ownership (frees
    /// exactly once) and the buffer is emptied, so a later `deinit` is a
    /// no-op. Uses `toOwnedSlice` so the returned slice's len == capacity
    /// and `allocator.free` is valid (returning `buf.items` directly would
    /// free with the wrong length when capacity > len -> "Invalid free").
    fn takeBytes(self: *RequestBuffer) ![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
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
