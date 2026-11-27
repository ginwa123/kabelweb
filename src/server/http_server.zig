const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

pub const http_parser = @import("http_parser.zig");
pub const router = @import("router.zig");
const connection_reader = @import("connection_reader.zig");
const http2_server = @import("http2/server.zig");
pub const security = @import("security.zig");
// Response compression (gzip), zero-dependency: std.compress.flate.
pub const compression = @import("compression.zig");
const compression_mod = compression;
pub const CompressionConfig = compression.Config;
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
const event_loop_mod = @import("event_loop.zig");
const nb_socket_mod = @import("nb_socket.zig");
pub const EventLoop = event_loop_mod.EventLoop;
pub const EventLoopConfig = event_loop_mod.Config;
pub const EventLoopStats = event_loop_mod.Stats;
pub const max_multi_loops = 16;
pub const Router = router.Router;
pub const Group = router.Group;
pub const HandlerFn = router.HandlerFn;
pub const MiddlewareFn = router.MiddlewareFn;
pub const MiddlewareChain = router.MiddlewareChain;

const socket = posix.system;

const winsock = if (builtin.os.tag == .windows) struct {
    extern "ws2_32" fn WSAStartup(wVersionRequested: c_ushort, wsaData: *WSADATA) callconv(.c) c_int;
    extern "ws2_32" fn WSACleanup() callconv(.c) c_int;
    extern "ws2_32" fn WSASocketW(af: c_int, sock_type: c_int, protocol: c_int, protocol_info: ?*anyopaque, group: c_uint, flags: c_uint) callconv(.c) c_int;
    extern "ws2_32" fn closesocket(sockfd: c_int) callconv(.c) c_int;
    extern "ws2_32" fn shutdown(sockfd: c_int, how: c_int) callconv(.c) c_int;
    extern "ws2_32" fn bind(sockfd: c_int, addr: ?*const anyopaque, addrlen: c_int) callconv(.c) c_int;
    extern "ws2_32" fn listen(sockfd: c_int, backlog: c_int) callconv(.c) c_int;
    extern "ws2_32" fn accept(sockfd: c_int, addr: ?*anyopaque, addrlen: ?*c_int) callconv(.c) c_int;
    extern "ws2_32" fn recv(sockfd: c_int, buf: ?*anyopaque, len: c_int, flags: c_int) callconv(.c) c_int;
    extern "ws2_32" fn send(sockfd: c_int, buf: ?*const anyopaque, len: c_int, flags: c_int) callconv(.c) c_int;
    extern "ws2_32" fn setsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: ?*const anyopaque, optlen: c_int) callconv(.c) c_int;
    extern "ws2_32" fn getpeername(sockfd: c_int, addr: ?*anyopaque, addrlen: ?*c_int) callconv(.c) c_int;

    const WSADATA = [400]u8;
    const SOL_SOCKET: c_int = 0xffff;
    const SO_EXCLUSIVEADDRUSE: c_int = -5;
    const WSA_FLAG_NO_HANDLE_INHERIT: c_uint = 0x80;
    const INVALID_SOCKET: c_int = -1;
} else struct {};

var wsa_init_lock: std.atomic.Mutex = .unlocked;
var wsa_initialized: bool = false;

fn ensureWinsockInitialized() void {
    if (wsa_initialized) return;
    while (!wsa_init_lock.tryLock()) std.atomic.spinLoopHint();
    defer wsa_init_lock.unlock();
    if (wsa_initialized) return;
    var wsa_data: winsock.WSADATA = undefined;
    const version: c_ushort = (2 << 8) | 2;
    const rc = winsock.WSAStartup(version, &wsa_data);
    if (rc != 0) {
        std.log.err("WSAStartup failed with rc={d}", .{rc});
        return;
    }
    wsa_initialized = true;
}

pub fn closeFd(fd: SocketFd) void {
    if (builtin.os.tag == .windows) {
        _ = winsock.closesocket(fd);
    } else {
        _ = socket.close(fd);
    }
}

// Shutdown wakes blocked accept on POSIX and Windows; close alone does not.
fn shutdownListenerFd(fd: SocketFd) void {
    const SHUT_RDWR: c_int = 2;
    if (builtin.os.tag == .windows) {
        _ = winsock.shutdown(fd, SHUT_RDWR);
    } else {
        _ = socket.shutdown(fd, SHUT_RDWR);
    }
}

const c = std.c;

const AF_INET = if (builtin.os.tag == .windows) @as(u32, 2) else posix.AF.INET;
const AF_UNIX = if (builtin.os.tag == .windows) @as(u32, 1) else posix.AF.UNIX;

const SOCK_STREAM = if (builtin.os.tag == .windows) @as(u32, 1) else posix.SOCK.STREAM;
const IPPROTO_TCP = if (builtin.os.tag == .windows) @as(u32, 6) else posix.IPPROTO.TCP;

pub const SocketFd = i32;

pub const Address = struct {
    sock_fd: SocketFd,
    port: u16,

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
        return @as(u32, octets[0]) | (@as(u32, octets[1]) << 8) |
            (@as(u32, octets[2]) << 16) | (@as(u32, octets[3]) << 24);
    }

    pub fn init(host: []const u8, port: u16) !Address {
        const socket_fd = try createSocket();
        errdefer closeFd(socket_fd);

        try applyBindOption(socket_fd);
        try bindPort(try parseHostLe(host), port, socket_fd);

        return .{
            .sock_fd = socket_fd,
            .port = port,
        };
    }

    fn createSocket() !SocketFd {
        if (comptime builtin.os.tag == .windows) {
            ensureWinsockInitialized();
            const fd = winsock.WSASocketW(
                @intCast(AF_INET),
                @intCast(SOCK_STREAM),
                @intCast(IPPROTO_TCP),
                null,
                0,
                winsock.WSA_FLAG_NO_HANDLE_INHERIT,
            );
            if (fd == winsock.INVALID_SOCKET) return error.SocketCreationFailed;
            return fd;
        } else {
            const fd = socket.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (fd < 0) return error.SocketCreationFailed;
            errdefer _ = socket.close(fd);
            try setCloseOnExec(fd);
            return @intCast(fd);
        }
    }

    fn setCloseOnExec(fd: i32) !void {
        if (builtin.os.tag == .linux) {
            const rc: isize = @bitCast(std.os.linux.fcntl(fd, F_SETFD, FD_CLOEXEC));
            if (rc < 0) return error.FcntlFailed;
        } else {
            if (std.c.fcntl(fd, F_SETFD, @as(c_int, FD_CLOEXEC)) < 0) return error.FcntlFailed;
        }
    }

    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;

    fn applyBindOption(sock_fd: SocketFd) !void {
        if (builtin.os.tag == .windows) {
            const opt: c_int = 1;
            const rc = winsock.setsockopt(sock_fd, winsock.SOL_SOCKET, winsock.SO_EXCLUSIVEADDRUSE, &opt, @sizeOf(c_int));
            if (rc != 0) return error.SetSockOptFailed;
        } else {
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
const stream_mod = @import("stream.zig");
pub const Stream = stream_mod.Stream;
pub const tls = tls_mod;
pub const tls_cert = @import("http2/tls_cert.zig");
const tls_mod = @import("http2/tls.zig");

fn tlsStreamRead(conn: *anyopaque, buf: []u8) anyerror!usize {
    const tc: *tls_mod.Conn = @ptrCast(@alignCast(conn));
    return tc.read(buf);
}
fn tlsStreamWriteAll(conn: *anyopaque, bytes: []const u8) anyerror!void {
    const tc: *tls_mod.Conn = @ptrCast(@alignCast(conn));
    return tc.writeAll(bytes);
}
fn installTlsStreamOps() void {
    stream_mod.Stream.installTlsOps(.{
        .read = tlsStreamRead,
        .write_all = tlsStreamWriteAll,
        .close = tlsStreamClose,
    });
}

// shutdown frees the SSL object; the connection scope frees Conn, so do not free it here.
fn tlsStreamClose(conn: *anyopaque) void {
    const tc: *tls_mod.Conn = @ptrCast(@alignCast(conn));
    tc.shutdown();
}

pub const GinwaServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    address: Address,
    router: router.Router,
    sse_manager: SseManager,
    ws_manager: *WsManager,
    cronjob_manager: CronjobManager,
    ctx: ?*anyopaque = null,
    environment: ?*const std.process.Environ.Map = null,
    is_running: bool = false,

    enable_h2c: bool = false,

    tls_ctx: ?*tls_mod.Ctx = null,

    context_store: ?*gserverz_context.ContextStore = null,

    csrf_secret: []const u8 = "dev-only-csrf-secret-change-in-prod",

    cors: CORSConfig = .{},

    /// Response compression (gzip): on by default; see `compression.Config`.
    compression: CompressionConfig = .{},
    /// Encoder workspaces, one per concurrent compression; `capacity` bounds them.
    compression_pool: compression_mod.Pool = .{},

    max_body_bytes: usize = std.math.maxInt(usize),

    security_headers: security.SecurityHeaders = .{},

    enable_security_headers: bool = true,

    // Writes the complete response to stream; the engine does not serialize it again.
    static_dir_handler: ?*const fn (
        cfg: *const anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request_path: []const u8,
        range_header: ?[]const u8,
        stream: Stream,
    ) anyerror!void = null,

    // Return null for the default 404; custom responses still receive engine framing.
    not_found_handler: ?*const fn (
        allocator: std.mem.Allocator,
        request_path: []const u8,
    ) anyerror!?HttpResponse = null,
    static_dir_cfg: ?*const anyopaque = null,

    el_stats: EventLoopStats = .{},

    el_multi_fds: [max_multi_loops]i32 = [_]i32{-1} ** max_multi_loops,
    el_multi_loops: [max_multi_loops]?*EventLoop = [_]?*EventLoop{null} ** max_multi_loops,
    el_multi_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, address: Address) !*GinwaServer {
        const gs = try allocator.create(GinwaServer);
        errdefer allocator.destroy(gs);

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

    // Takes ownership of ctx; deinit frees it.
    pub fn setTlsCtx(self: *GinwaServer, ctx: *tls_mod.Ctx) void {
        if (self.tls_ctx) |old_ctx| old_ctx.deinit();
        installTlsStreamOps();
        self.tls_ctx = ctx;
    }

    pub fn deinit(self: *GinwaServer) void {
        self.compression_pool.deinit(self.allocator);
        self.cronjob_manager.stop();
        self.cronjob_manager.deinit();
        self.sse_manager.gracefulShutdown();
        self.sse_manager.deinit();
        self.ws_manager.destroy();
        self.router.deinit();
        if (self.tls_ctx) |ctx| ctx.deinit();
        if (self.context_store) |store| store.deinit();
    }

    // Frees the GinwaServer struct; deinit only releases its owned resources.
    pub fn destroy(self: *GinwaServer, allocator: std.mem.Allocator) void {
        self.deinit();
        allocator.destroy(self);
    }

    pub fn listenEventLoop(self: *GinwaServer, cfg: event_loop_mod.Config) !void {
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

    fn serveSingleLoop(self: *GinwaServer, cfg: event_loop_mod.Config) !void {
        _ = nb_socket_mod.POLL.IN; // keep import live on all POSIX targets

        if (builtin.os.tag == .windows) {
            const rc = winsock.listen(self.address.sock_fd, 1024);
            if (rc != 0) return error.ListenFailed;
        } else {
            const rc = socket.listen(self.address.sock_fd, 1024);
            if (rc < 0) return error.ListenFailed;
        }

        if (self.cronjob_manager.start()) |_| {
            std.log.info("Cronjob manager running (1s tick)\n", .{});
        } else |err| {
            std.log.info("HTTP_SERVER: cronjob manager start failed: {s}\n", .{@errorName(err)});
        }

        self.is_running = true;
        var loop = event_loop_mod.EventLoop.init(self.allocator, self.io, cfg);
        defer loop.deinit();
        const template = HttpContext{
            .allocator = self.allocator,
            .io = self.io,
            .allowed_origins = self.cors.allowed_origins,
        };
        loop.run(self.address.sock_fd, dispatchEventLoopRequest, @ptrCast(self), template) catch |err| {
            self.el_stats = loop.stats;
            self.is_running = false;
            return err;
        };
        self.el_stats = loop.stats;
        self.is_running = false;
    }

    fn serveMultiLoop(self: *GinwaServer, cfg: event_loop_mod.Config) !void {
        var bound: socket.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(socket.sockaddr.in);
        if (socket.getsockname(self.address.sock_fd, @ptrCast(&bound), &bound_len) != 0)
            return error.GetSockNameFailed;
        const host_le: u32 = @bitCast(bound.addr);
        var port: u16 = @byteSwap(bound.port);

        var n: usize = cfg.loop_count;
        if (n > max_multi_loops) {
            std.log.info("HTTP_SERVER: clamping loops {d} → {d} (max_multi_loops)\n", .{ n, max_multi_loops });
            n = max_multi_loops;
        }

        if (self.cronjob_manager.start()) |_| {
            std.log.info("Cronjob manager running (1s tick)\n", .{});
        } else |err| {
            std.log.info("HTTP_SERVER: cronjob manager start failed: {s}\n", .{@errorName(err)});
        }

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
        std.log.info(
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
            if (fd < 0) return 0;

            var addr: posix.sockaddr.in = undefined;
            var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const rc = posix.getpeername(fd, @ptrCast(&addr), &addr_len) catch return 0;
            _ = rc;
            return @byteSwap(addr.port);
        }
    }

    pub fn shutdown(self: *GinwaServer) void {
        self.is_running = false;
        if (self.address.sock_fd != -1) {
            shutdownListenerFd(self.address.sock_fd);
            closeFd(self.address.sock_fd);
            self.address.sock_fd = -1;
        }
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

    fn applyCORSResponse(self: *GinwaServer, request: *const HttpRequest, resp: *HttpResponse) !void {
        return security.applyCORSResponse(resp, request, self.cors);
    }

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

    /// Compress `resp` in place per `self.compression`; on an OOM it stays identity.
    pub fn compressResponse(self: *GinwaServer, req: *const HttpRequest, resp: *HttpResponse) bool {
        return compression_mod.maybeCompress(
            self.allocator,
            resp,
            compression_mod.acceptEncodingOf(req),
            self.compression,
            &self.compression_pool,
        );
    }

    fn buildCORSPreflight(self: *GinwaServer, request: *const HttpRequest, allocator: std.mem.Allocator) !HttpResponse {
        return security.buildPreflightResponse(allocator, request, self.cors);
    }
};

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

    // Every `.respond` leaves through here, so gzip runs last, on the final body.
    const respond = struct {
        fn make(s: *GinwaServer, r: *const HttpRequest, built: HttpResponse) event_loop_mod.DispatchResult {
            var resp = built;
            _ = s.compressResponse(r, &resp);
            return .{ .respond = resp };
        }
    }.make;

    // Engine pre-gate (body cap + origin allowlist).
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
            return respond(server, &req, page);
        }
    }

    if (server.cors.enabled and std.mem.eql(u8, req.method, "OPTIONS")) {
        var preflight = try server.buildCORSPreflight(&req, alloc);
        preflight.keep_alive = false;
        return respond(server, &req, preflight);
    }

    if (server.router.matchRoute(req.method, req.path, &req, http_ctx)) |result| {
        switch (result) {
            .handler => |h| {
                if (h.max_body_bytes != 0) {
                    const gate = security.preGateCheck(&req, .{ .enabled = false }, h.max_body_bytes) catch .pass;
                    if (gate != .pass) {
                        var page = try security.buildEngineBlockPage(alloc, gate, null, "your-domain");
                        page.keep_alive = false;
                        return respond(server, &req, page);
                    }
                }
                var final = try h.chain.run(h.ctx, h.req, h.res);
                server.applyCORSResponse(&req, &final) catch {};
                server.applySecurityHeadersTo(&final);
                final.keep_alive = server.clientWantsKeepAlive(&req);
                return respond(server, &req, final);
            },
            .websocket => {
                if (server.tls_ctx != null) {
                    var res = HttpResponse.init(501, "Not Implemented", alloc)
                        .withBody("WebSocket is not available over TLS yet.");
                    res.keep_alive = false;
                    return respond(server, &req, res);
                }
                return .{ .hijack_ws = .{ .ctx = ctx_ptr, .run = runWsServe } };
            },
            .sse => {
                if (server.tls_ctx != null) {
                    var res = HttpResponse.init(501, "Not Implemented", alloc)
                        .withBody("SSE is not available over TLS yet.");
                    res.keep_alive = false;
                    return respond(server, &req, res);
                }
                return .{ .hijack_sse = .{ .ctx = ctx_ptr, .run = runSseServe } };
            },
        }
    }

    if (server.static_dir_handler != null and server.static_dir_cfg != null) {
        return .{ .hijack_static = .{ .ctx = ctx_ptr, .run = runStaticServe } };
    }
    var not_found = try buildNotFoundResponse(server, alloc, req.path);
    server.applyCORSResponse(&req, &not_found) catch {};
    server.applySecurityHeadersTo(&not_found);
    not_found.keep_alive = server.clientWantsKeepAlive(&req);
    return respond(server, &req, not_found);
}

fn wsWriteAdapter(ctx: ?*anyopaque, target_fd: i32, data: []const u8) anyerror!usize {
    const server_ptr: *GinwaServer = @ptrCast(@alignCast(ctx.?));
    return server_ptr.sendToClient(target_fd, data);
}

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
        serveNotFound(server, a, stream, req.path);
        closeFd(fd);
        return;
    };
    const cfg = server.static_dir_cfg orelse {
        serveNotFound(server, a, stream, req.path);
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
        serveNotFound(server, a, stream, req.path);
    };
    closeFd(fd);
}

fn buildNotFoundResponse(server: *GinwaServer, alloc: std.mem.Allocator, request_path: []const u8) anyerror!HttpResponse {
    if (server.not_found_handler) |build| {
        if (try build(alloc, request_path)) |custom| return custom;
    }
    return http_parser.notFound(alloc);
}

fn serveNotFound(server: *GinwaServer, alloc: std.mem.Allocator, stream: Stream, request_path: []const u8) void {
    var nf = buildNotFoundResponse(server, alloc, request_path) catch http_parser.notFound(alloc);
    server.applySecurityHeadersTo(&nf);
    const bytes = nf.toBytes() catch return;
    defer alloc.free(bytes);
    stream.writeAll(bytes) catch {};
}

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

    var sse_ctx = sse.ctx;
    sse_ctx.client_id = client_id;
    sse_ctx.allocator = a;
    const res = http_parser.HttpResponse.init(200, "OK", a);
    var manager_owns_conn = false;
    _ = sse.handler(sse_ctx, sse.req, res) catch |err| {
        if (err == error.WouldBlock) {
            manager_owns_conn = true;
        } else {
            std.log.info("SSE handler error: {s}\n", .{@errorName(err)});
        }
    };

    if (manager_owns_conn) {
        return;
    }

    server.sse_manager.removeClient(client_id, .explicit_shutdown);
}

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
        std.log.info("WebSocket handler error: {s}\n", .{@errorName(err)});
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
    closeFd(fd);
}

fn runH2Serve(ctx_ptr: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: SocketFd, data: []const u8) void {
    _ = io;
    const server: *GinwaServer = @ptrCast(@alignCast(ctx_ptr));
    nb_socket_mod.setBlocking(fd) catch {
        closeFd(fd);
        return;
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    var fixed = std.heap.stackFallback(64 * 1024, arena.allocator());
    const stream: Stream = .{ .plain = fd };
    http2_server.serveConnection(server, stream, fixed.get(), data, .{}) catch |err| {
        std.log.info("HTTP_SERVER: h2 connection ended: {s}\n", .{@errorName(err)});
    };
    closeFd(fd);
}

fn runTlsServe(ctx_ptr: *anyopaque, alloc: std.mem.Allocator, io: std.Io, fd: SocketFd, data: []const u8) void {
    _ = data;
    const server: *GinwaServer = @ptrCast(@alignCast(ctx_ptr));
    installTlsStreamOps();
    const tls_ctx = server.tls_ctx orelse {
        closeFd(fd);
        return;
    };
    nb_socket_mod.setBlocking(fd) catch {
        closeFd(fd);
        return;
    };
    var tls_conn = tls_mod.Conn.accept(tls_ctx, fd) catch |err| {
        std.log.info("HTTP_SERVER: TLS handshake failed: {s}\n", .{@errorName(err)});
        closeFd(fd);
        return;
    };
    defer tls_conn.deinit();
    const stream: Stream = .{ .tls = @ptrCast(tls_conn) };
    const negotiated = tls_conn.selectedAlpn();
    std.log.info("HTTP_SERVER: TLS ok (alpn='{s}' len={d})\n", .{ negotiated, negotiated.len });
    if (std.mem.eql(u8, negotiated, tls_mod.alpn_h2)) {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        var fixed = std.heap.stackFallback(64 * 1024, arena.allocator());
        http2_server.serveConnection(server, stream, fixed.get(), "", .{}) catch |err| {
            std.log.info("HTTP_SERVER: h2 (TLS) connection ended: {s}\n", .{@errorName(err)});
        };
        closeFd(fd);
        return;
    }

    var request_arena = std.heap.ArenaAllocator.init(alloc);
    defer request_arena.deinit();
    var request_fixed = std.heap.stackFallback(8 * 1024, request_arena.allocator());
    const request_allocator = request_fixed.get();
    var keep_alive_count: u32 = 0;
    while (true) {
        keep_alive_count += 1;
        request_fixed.fixed_buffer_allocator.reset();
        _ = request_arena.reset(.retain_capacity);
        const a = request_allocator;
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
            .hijack_sse, .hijack_ws => break,
        }
        rb.deinit();
    }
    closeFd(fd);
}

pub const RequestBuffer = struct {
    allocator: std.mem.Allocator,
    buf: std.ArrayList(u8),
    tmp: [4096]u8,

    pub fn init(allocator: std.mem.Allocator) RequestBuffer {
        return .{
            .allocator = allocator,
            .buf = .empty,
            .tmp = undefined,
        };
    }

    pub fn deinit(self: *RequestBuffer) void {
        self.buf.deinit(self.allocator);
    }

    pub fn getContentLength(data: []const u8) ?usize {
        const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return null;
        const headers = data[0..header_end];

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

        var actual_start = cl_start;
        while (actual_start < headers.len and
            (headers[actual_start] == ':' or
                headers[actual_start] == ' ' or
                headers[actual_start] == '\t'))
        {
            actual_start += 1;
        }

        const after_value = headers[actual_start..];

        var end_idx: usize = 0;
        while (end_idx < after_value.len and after_value[end_idx] != '\r' and after_value[end_idx] != '\n') {
            end_idx += 1;
        }

        const cl_str = after_value[0..end_idx];
        return std.fmt.parseInt(usize, cl_str, 10) catch null;
    }

    pub fn readFullRequest(self: *RequestBuffer, fd: SocketFd) ![]u8 {
        return self.readFullRequestStream(.{ .plain = fd });
    }

    fn takeBytes(self: *RequestBuffer) ![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }

    pub fn readFullRequestStream(self: *RequestBuffer, stream: stream_mod.Stream) ![]u8 {
        while (std.mem.indexOf(u8, self.buf.items, "\r\n\r\n") == null) {
            const n = stream.read(&self.tmp) catch return error.RecvFailed;
            if (n == 0) break;
            try self.buf.appendSlice(self.allocator, self.tmp[0..n]);
        }

        const header_end_idx = std.mem.indexOf(u8, self.buf.items, "\r\n\r\n") orelse {
            if (self.buf.items.len == 0) return error.ConnectionClosed;
            return self.takeBytes();
        };

        const content_length = blk: {
            const header_section = self.buf.items[0..header_end_idx];
            var lines = std.mem.splitSequence(u8, header_section, "\r\n");
            _ = lines.next(); // skip request line
            while (lines.next()) |line| {
                if (line.len > 15 and std.ascii.eqlIgnoreCase(line[0..14], "content-length")) {
                    const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
                    const value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");
                    break :blk std.fmt.parseInt(usize, value, 10) catch {
                        return error.BadRequest;
                    };
                }
            }
            return self.takeBytes();
        };

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

pub const SseEvent = struct {
    data: []const u8,
    event_type: ?[]const u8 = null,
};

pub const CORSConfig = security.CORSConfig;

// Tests — moved here from `event_loop_server_test.zig` (file deleted; lives next to the impl).
const event_loop_server_tests = struct {
    const http_server = @import("http_server.zig");
    const event_loop = @import("event_loop.zig");
    const test_tcp = @import("test_tcp.zig");

    fn problemNotFound(allocator: std.mem.Allocator, path: []const u8) anyerror!?http_server.HttpResponse {
        const body = try std.fmt.allocPrint(
            allocator,
            "{{\"type\":\"about:blank\",\"status\":404,\"instance\":\"{s}\"}}",
            .{path},
        );
        return http_server.HttpResponse.init(404, "Not Found", allocator)
            .withBody(body)
            .setContentType("application/problem+json");
    }

    fn helloHandler(
        ctx: http_server.HttpContext,
        req: http_server.HttpRequest,
        res: http_server.HttpResponse,
    ) anyerror!http_server.HttpResponse {
        _ = ctx;
        _ = req;
        return res.withBody("event-loop-hi");
    }

    fn echoHandler(
        ctx: http_server.HttpContext,
        req: http_server.HttpRequest,
        res: http_server.HttpResponse,
    ) anyerror!http_server.HttpResponse {
        _ = ctx;
        return res.withBody(req.body);
    }

    fn sseStub(
        ctx: http_server.HttpContext,
        req: http_server.HttpRequest,
        res: http_server.HttpResponse,
    ) anyerror!http_server.HttpResponse {
        _ = ctx;
        _ = req;
        _ = res;
        return error.Unreachable; // never runs on the event-loop path (501 first)
    }

    const ServerThread = struct {
        server: *http_server.GinwaServer,
        cfg: event_loop.Config = .{},
        err: ?anyerror = null,

        fn run(self: *ServerThread) void {
            self.server.listenEventLoop(self.cfg) catch |err| {
                std.log.info("ServerThread: listenEventLoop failed: {s}\n", .{@errorName(err)});
                self.err = err;
            };
        }
    };

    fn tcpConnect(port: u16) !i32 {
        return test_tcp.connect(port);
    }

    fn writeAll(fd: i32, data: []const u8) !void {
        return test_tcp.writeAll(fd, data);
    }

    fn readHttpResponse(fd: i32, buf: []u8) ![]u8 {
        var len: usize = 0;
        while (true) {
            if (event_loop.findHeaderEnd(buf[0..len])) |he| {
                const cl = try event_loop.parseContentLength(buf[0..he]);
                if (len >= he + cl) return buf[0 .. he + cl];
            }
            if (len >= buf.len) return error.TooMuch;
            const n = try test_tcp.read(fd, buf[len..]);
            if (n == 0) return error.Closed;
            len += n;
        }
    }

    fn serverPort(sock_fd: i32) !u16 {
        const port = try test_tcp.boundPort(sock_fd);
        try std.testing.expect(port != 0);
        return port;
    }

    test "listenEventLoop serves routes, echo, 404 and 501s" {
        const alloc = std.testing.allocator;

        const addr = try http_server.Address.init("127.0.0.1", 0);
        const port = try serverPort(addr.sock_fd);

        var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
        defer server.destroy(alloc);

        try server.router.get("/hello", helloHandler);
        try server.router.post("/echo", echoHandler);
        try server.router.sse("/stream", sseStub);

        var st = ServerThread{
            .server = server,
            .cfg = .{
                .max_conns = 32,
                .idle_timeout_ms = 10_000,
                .header_timeout_ms = 2_000,
            },
        };
        const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
        defer {
            server.shutdown();
            t.join();
        }
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
        if (st.err) |err| return err;

        const cfd = try tcpConnect(port);
        defer test_tcp.close(cfd);

        var buf: [8192]u8 = undefined;

        try writeAll(cfd, "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n");
        const r1 = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, r1, "200 OK") != null);
        try std.testing.expect(std.mem.indexOf(u8, r1, "event-loop-hi") != null);

        const body = "hello-event-loop";
        const req2 = try std.fmt.allocPrint(
            alloc,
            "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\nConnection: keep-alive\r\n\r\n{s}",
            .{ body.len, body },
        );
        defer alloc.free(req2);
        try writeAll(cfd, req2);
        const r2 = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, r2, "200 OK") != null);
        try std.testing.expect(std.mem.indexOf(u8, r2, body) != null);

        try writeAll(cfd, "GET /nope HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n");
        const r3 = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, r3, "404") != null);

        try writeAll(cfd, "GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        const r4 = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, r4, "200 OK") != null);
        try std.testing.expect(std.mem.indexOf(u8, r4, "text/event-stream") != null);
    }

    test "a not_found_handler replaces the plain 404 body" {
        const alloc = std.testing.allocator;

        const addr = try http_server.Address.init("127.0.0.1", 0);
        const port = try serverPort(addr.sock_fd);

        var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
        defer server.destroy(alloc);

        try server.router.get("/hello", helloHandler);
        server.not_found_handler = problemNotFound;

        var st = ServerThread{
            .server = server,
            .cfg = .{
                .max_conns = 32,
                .idle_timeout_ms = 10_000,
                .header_timeout_ms = 2_000,
            },
        };
        const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
        defer {
            server.shutdown();
            t.join();
        }
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
        if (st.err) |err| return err;

        const cfd = try tcpConnect(port);
        defer test_tcp.close(cfd);

        var buf: [8192]u8 = undefined;
        try writeAll(cfd, "GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        const answer = try readHttpResponse(cfd, &buf);

        try std.testing.expect(std.mem.indexOf(u8, answer, "404") != null);
        try std.testing.expect(std.mem.indexOf(u8, answer, "application/problem+json") != null);
        try std.testing.expect(std.mem.indexOf(u8, answer, "\"instance\":\"/nope\"") != null);
    }

    test "listenEventLoop worker_pool mode serves correctly" {
        const alloc = std.testing.allocator;

        const addr = try http_server.Address.init("127.0.0.1", 0);
        const port = try serverPort(addr.sock_fd);

        var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
        defer server.destroy(alloc);

        try server.router.get("/hello", helloHandler);
        try server.router.post("/echo", echoHandler);

        var st = ServerThread{
            .server = server,
            .cfg = .{
                .max_conns = 32,
                .idle_timeout_ms = 10_000,
                .header_timeout_ms = 2_000,
                .dispatch_mode = .worker_pool,
                .worker_threads = 2,
                .worker_queue_depth = 64,
            },
        };
        const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
        if (st.err) |err| return err;

        const cfd = try tcpConnect(port);
        defer test_tcp.close(cfd);

        var buf: [8192]u8 = undefined;

        try writeAll(cfd, "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n");
        const r1 = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, r1, "200 OK") != null);
        try std.testing.expect(std.mem.indexOf(u8, r1, "event-loop-hi") != null);

        const p1 = "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";
        const p2 = "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping";
        try writeAll(cfd, p1);
        try writeAll(cfd, p2);
        const rp1 = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, rp1, "event-loop-hi") != null);
        const rp2 = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, rp2, "ping") != null);

        server.shutdown();
        t.join();
        if (st.err) |err| return err;
        try std.testing.expectEqual(@as(u64, 3), server.el_stats.offloaded);
        try std.testing.expectEqual(@as(u64, 3), server.el_stats.served);
        try std.testing.expectEqual(@as(u64, 0), server.el_stats.inline_fallback);
    }

    test "listenEventLoop loop_count=2 serves across loops with agg stats (POSIX)" {
        if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
        const alloc = std.testing.allocator;

        const addr = try http_server.Address.init("127.0.0.1", 0);
        const port = try serverPort(addr.sock_fd);

        var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
        defer server.destroy(alloc);

        try server.router.get("/hello", helloHandler);

        const MultiThread = struct {
            srv: *http_server.GinwaServer,
            err: ?anyerror = null,
            fn run(self: *@This()) void {
                self.srv.listenEventLoop(.{
                    .max_conns = 64,
                    .idle_timeout_ms = 10_000,
                    .header_timeout_ms = 2_000,
                    .loop_count = 2,
                }) catch |err| {
                    self.err = err;
                };
            }
        };
        var mt = MultiThread{ .srv = server };
        const t = try std.Thread.spawn(.{}, MultiThread.run, .{&mt});
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 150 * std.time.ns_per_ms }, .real) catch {};
        if (mt.err) |err| {
            std.log.info("listenEventLoop(multi) failed: {s}\n", .{@errorName(err)});
            return err;
        }

        const n_conns = 8;
        var fds: [n_conns]i32 = undefined;
        for (&fds) |*fd| fd.* = try tcpConnect(port);
        defer {
            for (fds) |fd| test_tcp.close(fd);
        }

        var buf: [8192]u8 = undefined;
        for (fds) |fd| {
            for (0..2) |k| {
                const ka: []const u8 = if (k == 0) "keep-alive" else "close";
                const req = try std.fmt.allocPrint(
                    alloc,
                    "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: {s}\r\n\r\n",
                    .{ka},
                );
                defer alloc.free(req);
                try writeAll(fd, req);
                const resp = try readHttpResponse(fd, &buf);
                try std.testing.expect(std.mem.indexOf(u8, resp, "200 OK") != null);
                try std.testing.expect(std.mem.indexOf(u8, resp, "event-loop-hi") != null);
            }
        }

        server.shutdown();
        t.join();
        if (mt.err) |err| return err;
        try std.testing.expectEqual(@as(u64, 16), server.el_stats.served);
        try std.testing.expectEqual(@as(u64, 8), server.el_stats.accepted);
    }

    fn staticTestHandler(
        cfg: *const anyopaque,
        alloc: std.mem.Allocator,
        io: std.Io,
        request_path: []const u8,
        range_header: ?[]const u8,
        stream: http_server.Stream,
    ) anyerror!void {
        _ = cfg;
        _ = io;
        _ = range_header;
        const body = try std.fmt.allocPrint(alloc, "static:{s}", .{request_path});
        defer alloc.free(body);
        const head = try std.fmt.allocPrint(
            alloc,
            "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n",
            .{body.len},
        );
        defer alloc.free(head);
        try stream.writeAll(head);
        try stream.writeAll(body);
    }

    test "listenEventLoop serves static-dir fallback via hijack (direct)" {
        const alloc = std.testing.allocator;
        const addr = try http_server.Address.init("127.0.0.1", 0);
        const port = try serverPort(addr.sock_fd);

        var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
        defer server.destroy(alloc);

        try server.router.get("/hello", helloHandler);
        var static_cfg: u8 = 0;
        server.setStaticDirHandler(staticTestHandler, @ptrCast(&static_cfg));

        var st = ServerThread{
            .server = server,
            .cfg = .{
                .max_conns = 32,
                .idle_timeout_ms = 10_000,
                .header_timeout_ms = 2_000,
                .dispatch_mode = .direct,
            },
        };
        const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
        if (st.err) |err| return err;

        {
            const cfd = try tcpConnect(port);
            defer test_tcp.close(cfd);
            var buf: [8192]u8 = undefined;
            try writeAll(cfd, "GET /file.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            const r = try readHttpResponse(cfd, &buf);
            try std.testing.expect(std.mem.indexOf(u8, r, "200 OK") != null);
            try std.testing.expect(std.mem.indexOf(u8, r, "static:/file.txt") != null);
        }
        {
            const cfd = try tcpConnect(port);
            defer test_tcp.close(cfd);
            var buf: [8192]u8 = undefined;
            try writeAll(cfd, "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            const r = try readHttpResponse(cfd, &buf);
            try std.testing.expect(std.mem.indexOf(u8, r, "event-loop-hi") != null);
        }

        server.shutdown();
        t.join();
        if (st.err) |err| return err;
        try std.testing.expect(server.el_stats.hijacked >= 1);
        try std.testing.expectEqual(@as(u64, 1), server.el_stats.served);
    }

    test "listenEventLoop serves static-dir fallback via hijack (pool)" {
        const alloc = std.testing.allocator;
        const addr = try http_server.Address.init("127.0.0.1", 0);
        const port = try serverPort(addr.sock_fd);

        var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
        defer server.destroy(alloc);

        var static_cfg: u8 = 0;
        server.setStaticDirHandler(staticTestHandler, @ptrCast(&static_cfg));

        var st = ServerThread{
            .server = server,
            .cfg = .{
                .max_conns = 32,
                .idle_timeout_ms = 10_000,
                .header_timeout_ms = 2_000,
                .dispatch_mode = .worker_pool,
                .worker_threads = 2,
                .worker_queue_depth = 64,
            },
        };
        const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
        if (st.err) |err| return err;

        const cfd = try tcpConnect(port);
        defer test_tcp.close(cfd);
        var buf: [8192]u8 = undefined;
        try writeAll(cfd, "GET /pool-file.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        const r = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, r, "200 OK") != null);
        try std.testing.expect(std.mem.indexOf(u8, r, "static:/pool-file.txt") != null);

        server.shutdown();
        t.join();
        if (st.err) |err| return err;
        try std.testing.expect(server.el_stats.hijacked >= 1);
    }

    var sse_test_server: ?*http_server.GinwaServer = null;

    fn sseTestHandler(
        ctx: http_server.HttpContext,
        req: http_server.HttpRequest,
        res: http_server.HttpResponse,
    ) anyerror!http_server.HttpResponse {
        _ = ctx;
        _ = req;
        _ = res;
        if (sse_test_server) |s| {
            s.sse_manager.broadcast("sse-ok") catch {};
            std.Io.sleep(std.testing.io, .{ .nanoseconds = 300 * std.time.ns_per_ms }, .real) catch {};
        }
        return error.WouldBlock;
    }

    test "listenEventLoop serves SSE stream via hijack" {
        const alloc = std.testing.allocator;
        const addr = try http_server.Address.init("127.0.0.1", 0);
        const port = try serverPort(addr.sock_fd);

        var server = try http_server.GinwaServer.init(alloc, std.testing.io, addr);
        defer server.destroy(alloc);

        try server.router.sse("/events", sseTestHandler);
        sse_test_server = server;
        defer sse_test_server = null;

        var st = ServerThread{
            .server = server,
            .cfg = .{
                .max_conns = 32,
                .idle_timeout_ms = 10_000,
                .header_timeout_ms = 2_000,
            },
        };
        const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
        if (st.err) |err| return err;

        const cfd = try tcpConnect(port);
        defer test_tcp.close(cfd);
        var buf: [8192]u8 = undefined;
        try writeAll(cfd, "GET /events HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n");
        const head = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, head, "200 OK") != null);
        try std.testing.expect(std.mem.indexOf(u8, head, "text/event-stream") != null);
        var evbuf: [1024]u8 = undefined;
        var evlen: usize = 0;
        while (std.mem.indexOf(u8, evbuf[0..evlen], "data: sse-ok") == null) {
            if (evlen >= evbuf.len) break;
            const n = try test_tcp.read(cfd, evbuf[evlen..]);
            if (n == 0) break;
            evlen += n;
        }
        try std.testing.expect(std.mem.indexOf(u8, evbuf[0..evlen], "data: sse-ok") != null);

        server.shutdown();
        t.join();
        if (st.err) |err| return err;
        try std.testing.expect(server.el_stats.hijacked >= 1);
    }

    fn wsTestHandler(
        ctx: http_server.HttpContext,
        req: http_server.HttpRequest,
        server_ptr: *anyopaque,
        client_fd: i32,
        client_id: *[16]u8,
    ) anyerror!void {
        _ = req;
        _ = client_id;
        const server: *http_server.GinwaServer = @ptrCast(@alignCast(server_ptr));
        var buf: [4096]u8 = undefined;
        var acc: std.ArrayList(u8) = .empty;
        defer acc.deinit(ctx.allocator);
        while (true) {
            const n = try server.recvFromClient(client_fd, &buf);
            if (n == 0) return;
            try acc.appendSlice(ctx.allocator, buf[0..n]);
            var frame = ws_frames.parseFrame(ctx.allocator, acc.items) catch |err| {
                if (err == error.IncompleteFrame) continue;
                return err;
            };
            defer frame.deinit(ctx.allocator);
            switch (frame.opcode) {
                .text => {
                    const echo = try ws_frames.encodeFrame(ctx.allocator, .{
                        .opcode = .text,
                        .payload = frame.payload,
                    });
                    defer ctx.allocator.free(echo);
                    _ = try server.sendToClient(client_fd, echo);
                },
                .ping => {
                    const pong = try ws_frames.encodeFrame(ctx.allocator, .{
                        .opcode = .pong,
                        .payload = frame.payload,
                    });
                    defer ctx.allocator.free(pong);
                    _ = try server.sendToClient(client_fd, pong);
                },
                .close => return,
                else => {},
            }
            acc.clearRetainingCapacity();
        }
    }

    fn readExact(fd: i32, buf: []u8) !void {
        var off: usize = 0;
        while (off < buf.len) {
            const n = try test_tcp.read(fd, buf[off..]);
            if (n == 0) return error.Closed;
            off += n;
        }
    }

    test "listenEventLoop serves WebSocket echo via hijack" {
        const alloc = std.testing.allocator;
        _ = alloc;
        const addr = try http_server.Address.init("127.0.0.1", 0);
        const port = try serverPort(addr.sock_fd);

        var server = try http_server.GinwaServer.init(std.testing.allocator, std.testing.io, addr);
        defer server.destroy(std.testing.allocator);

        try server.router.ws("/ws", wsTestHandler);

        var st = ServerThread{
            .server = server,
            .cfg = .{
                .max_conns = 32,
                .idle_timeout_ms = 10_000,
                .header_timeout_ms = 2_000,
            },
        };
        const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
        if (st.err) |err| return err;

        const cfd = try tcpConnect(port);
        defer test_tcp.close(cfd);

        try writeAll(cfd, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
        var buf: [8192]u8 = undefined;
        const hs = try readHttpResponse(cfd, &buf);
        try std.testing.expect(std.mem.indexOf(u8, hs, "101") != null);
        try std.testing.expect(std.mem.indexOf(u8, hs, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);

        const mask = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
        var masked = [2 + 4 + 2]u8{ 0x81, 0x82, mask[0], mask[1], mask[2], mask[3], 'h' ^ mask[0], 'i' ^ mask[1] };
        try writeAll(cfd, &masked);
        var echo: [4]u8 = undefined;
        try readExact(cfd, &echo);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x81, 0x02, 'h', 'i' }, &echo);

        var close_req = [2 + 4]u8{ 0x88, 0x80, mask[0], mask[1], mask[2], mask[3] };
        try writeAll(cfd, &close_req);
        var close_resp: [4]u8 = undefined;
        try readExact(cfd, &close_resp);
        try std.testing.expectEqual(@as(u8, 0x88), close_resp[0]);
        var tail: [64]u8 = undefined;
        const n = try test_tcp.read(cfd, &tail);
        try std.testing.expectEqual(@as(usize, 0), n);

        server.shutdown();
        t.join();
        if (st.err) |err| return err;
        try std.testing.expect(server.el_stats.hijacked >= 1);
    }

    test "listenEventLoop hijacks H2 preface to H2 driver" {
        const alloc = std.testing.allocator;
        _ = alloc;
        const addr = try http_server.Address.init("127.0.0.1", 0);
        const port = try serverPort(addr.sock_fd);

        var server = try http_server.GinwaServer.init(std.testing.allocator, std.testing.io, addr);
        defer server.destroy(std.testing.allocator);

        try server.router.get("/hello", helloHandler);
        server.enable_h2c = true;

        var st = ServerThread{
            .server = server,
            .cfg = .{
                .max_conns = 32,
                .idle_timeout_ms = 10_000,
                .header_timeout_ms = 2_000,
            },
        };
        const t = try std.Thread.spawn(.{}, ServerThread.run, .{&st});
        std.Io.sleep(std.testing.io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .real) catch {};
        if (st.err) |err| return err;

        const cfd = try tcpConnect(port);

        try writeAll(cfd, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        try writeAll(cfd, &[_]u8{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 });
        var head: [9]u8 = undefined;
        try readExact(cfd, &head);
        try std.testing.expectEqual(@as(u8, 0x04), head[3]);

        test_tcp.close(cfd);

        server.shutdown();
        t.join();
        if (st.err) |err| return err;
        try std.testing.expect(server.el_stats.hijacked >= 1);
    }
};

comptime {
    _ = event_loop_server_tests;
}

// Tests — moved here from `http_server_test.zig` (file deleted; lives next to the impl).
const http_server_tests = struct {
    const http_server = @import("http_server.zig");
    const linux = std.posix.system;
    const helpers = @import("test_helpers.zig");
    const closeI32Fd = helpers.closeI32Fd;
    const writeTestFd = helpers.writeTestFdAll;
    const closeTestFd = helpers.closeTestFd;
    const test_tcp = @import("test_tcp.zig");

    fn freePort() !u16 {
        const probe = try http_server.Address.init("127.0.0.1", 0);
        defer _ = closeI32Fd(probe.sock_fd);
        return test_tcp.boundPort(probe.sock_fd);
    }

    const RequestPump = struct {
        fd: std.c.fd_t,
        headers: []const u8,
        body: []const u8,
        err: ?anyerror = null,

        fn run(self: *RequestPump) void {
            defer closeTestFd(self.fd);
            writeTestFd(self.fd, self.headers) catch |e| {
                self.err = e;
                return;
            };
            writeTestFd(self.fd, self.body) catch |e| {
                self.err = e;
                return;
            };
        }
    };

    test "Address.init creates socket and binds" {
        const port = try freePort();
        const addr = try http_server.Address.init("127.0.0.1", port);
        defer _ = closeI32Fd(addr.sock_fd);

        try std.testing.expect(addr.sock_fd >= 0);
        try std.testing.expectEqual(port, addr.port);
    }

    test "Address.init with different port" {
        const port = try freePort();
        const addr = try http_server.Address.init("127.0.0.1", port);
        defer _ = closeI32Fd(addr.sock_fd);

        try std.testing.expectEqual(port, addr.port);
    }

    fn listenTestFd(fd: i32) !void {
        if (builtin.os.tag == .windows) {
            if (winsock.listen(fd, 8) != 0) return error.ListenFailed;
        } else {
            if (socket.listen(fd, 8) != 0) return error.ListenFailed;
        }
    }

    fn fdInheritableByaChild(fd: i32) !bool {
        if (builtin.os.tag == .windows) {
            var flags: u32 = 0;
            if (kernel32.GetHandleInformation(@ptrFromInt(@as(usize, @intCast(fd))), &flags) == 0) return error.HandleInfoFailed;
            return flags & kernel32.HANDLE_FLAG_INHERIT != 0;
        } else if (builtin.os.tag == .linux) {
            const rc: isize = @bitCast(std.os.linux.fcntl(fd, F_GETFD, 0));
            if (rc < 0) return error.HandleInfoFailed;
            return @as(usize, @bitCast(rc)) & @as(usize, @intCast(FD_CLOEXEC)) == 0;
        } else {
            const rc = std.c.fcntl(fd, F_GETFD);
            if (rc < 0) return error.HandleInfoFailed;
            return @as(u32, @intCast(rc)) & @as(u32, @intCast(FD_CLOEXEC)) == 0;
        }
    }

    const F_GETFD: i32 = 1;
    const FD_CLOEXEC: i32 = 1;

    const kernel32 = if (builtin.os.tag == .windows) struct {
        const HANDLE_FLAG_INHERIT: u32 = 0x1;
        extern "kernel32" fn GetHandleInformation(object: *anyopaque, flags: *u32) callconv(.winapi) i32;
    } else struct {};

    test "a listening socket refuses a second bind on its port" {
        const port = try freePort();
        const first = try http_server.Address.init("127.0.0.1", port);
        defer _ = closeI32Fd(first.sock_fd);
        try listenTestFd(first.sock_fd);

        try std.testing.expectError(error.BindFailed, http_server.Address.init("127.0.0.1", port));
    }

    test "the listening socket is not inheritable by a child process" {
        const port = try freePort();
        const addr = try http_server.Address.init("127.0.0.1", port);
        defer _ = closeI32Fd(addr.sock_fd);

        try std.testing.expect(!try fdInheritableByaChild(addr.sock_fd));
    }

    test "Address.init multiple instances on different ports" {
        const port1 = try freePort();
        const addr1 = try http_server.Address.init("127.0.0.1", port1);
        defer _ = closeI32Fd(addr1.sock_fd);

        const port2 = try freePort();
        const addr2 = try http_server.Address.init("127.0.0.1", port2);
        defer _ = closeI32Fd(addr2.sock_fd);

        try std.testing.expect(addr1.sock_fd >= 0);
        try std.testing.expect(addr2.sock_fd >= 0);
        try std.testing.expect(addr1.sock_fd != addr2.sock_fd);
        try std.testing.expect(addr1.port != addr2.port);
    }

    test "GinwaServer.init creates server instance" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const port = try freePort();
        const addr = try http_server.Address.init("127.0.0.1", port);
        defer _ = closeI32Fd(addr.sock_fd);

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        defer server.destroy(allocator);

        try std.testing.expect(server.address.sock_fd == addr.sock_fd);
        try std.testing.expectEqual(port, server.address.port);
    }

    test "GinwaServer.init router is initialized" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const addr = try http_server.Address.init("127.0.0.1", try freePort());
        defer _ = closeI32Fd(addr.sock_fd);

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        defer server.destroy(allocator);

        try std.testing.expect(server.router.routes.items.len == 0); // Empty initially
    }

    test "GinwaServer with registered route" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const addr = try http_server.Address.init("127.0.0.1", try freePort());
        defer _ = closeI32Fd(addr.sock_fd);

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        defer server.destroy(allocator);

        try server.router.get("/test", struct {
            fn handle(_: http_parser.HttpContext, _: http_parser.HttpRequest, _: http_parser.HttpResponse) anyerror!http_parser.HttpResponse {
                return http_parser.ok("Test Response", std.heap.page_allocator);
            }
        }.handle);

        try std.testing.expect(server.router.routes.items.len == 1);
        try std.testing.expectEqualStrings("/test", server.router.routes.items[0].path);
    }

    test "GinwaServer.security_headers defaults to library baseline" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const addr = try http_server.Address.init("127.0.0.1", 0);
        defer _ = closeI32Fd(addr.sock_fd);

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        defer server.destroy(allocator);

        const csp = server.security_headers.content_security_policy;
        try std.testing.expect(std.mem.indexOf(u8, csp, "cdn.tailwindcss.com") == null);
        try std.testing.expect(std.mem.indexOf(u8, csp, "cloudflareinsights") == null);
    }

    test "GinwaServer.applySecurityHeadersTo uses server-level CSP override" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const addr = try http_server.Address.init("127.0.0.1", try freePort());
        defer _ = closeI32Fd(addr.sock_fd);

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        defer server.destroy(allocator);

        server.security_headers.content_security_policy =
            "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com https://static.cloudflareinsights.com 'unsafe-inline'";

        var res = http_parser.HttpResponse.init(200, "OK", allocator);
        defer res.deinit();

        server.applySecurityHeadersTo(&res);

        const csp = res.headers.get("Content-Security-Policy") orelse
            return error.ContentSecurityPolicyHeaderMissing;
        try std.testing.expect(std.mem.indexOf(u8, csp, "cdn.tailwindcss.com") != null);
        try std.testing.expect(std.mem.indexOf(u8, csp, "static.cloudflareinsights.com") != null);
        try std.testing.expectEqualStrings("nosniff", res.headers.get("X-Content-Type-Options").?);
    }

    test "HttpContext.allowed_origins defaults to empty slice" {
        const ctx = http_parser.HttpContext{
            .allocator = std.testing.allocator,
            .io = undefined,
        };
        try std.testing.expectEqual(@as(usize, 0), ctx.allowed_origins.len);
    }

    test "handler origin gate: checkOriginInList with ctx origins accepts whitelisted host" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        const security_mod = @import("security.zig");
        const origins = [_][]const u8{ "localhost:4021", "ginwa.site" };
        const ctx = http_parser.HttpContext{
            .allocator = arena.allocator(),
            .io = undefined,
            .allowed_origins = &origins,
        };

        var req = security_mod.HttpRequest{
            .method = "POST",
            .path = "/admin/signin",
            .version = "HTTP/1.1",
            .headers = std.StringHashMap([]const u8).init(arena.allocator()),
            .body = "",
            .raw = "",
            .params = std.StringHashMap([]const u8).init(arena.allocator()),
            .query = std.StringHashMap([]const u8).init(arena.allocator()),
            ._client_fd = -1,
        };
        defer req.headers.deinit();
        defer req.params.deinit();
        defer req.query.deinit();
        try req.headers.put("Origin", "https://ginwa.site");

        try security_mod.checkOriginInList(&req, ctx.allowed_origins);
    }

    test "Address port is correctly stored" {
        const test_port: u16 = try freePort();
        const addr = try http_server.Address.init("127.0.0.1", test_port);
        defer _ = closeI32Fd(addr.sock_fd);

        try std.testing.expectEqual(test_port, addr.port);
        try std.testing.expect(addr.sock_fd >= 0);
    }

    test "Address sock_fd is valid file descriptor" {
        const addr = try http_server.Address.init("127.0.0.1", try freePort());
        defer _ = closeI32Fd(addr.sock_fd);

        try std.testing.expect(addr.sock_fd >= 0);
    }

    test "GinwaServer.getClientPort returns 0 for invalid fd" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const addr = try http_server.Address.init("127.0.0.1", try freePort());
        defer _ = closeI32Fd(addr.sock_fd);

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        defer server.destroy(allocator);

        const port = server.getClientPort(-1);
        try std.testing.expectEqual(@as(u16, 0), port);
    }

    test "GinwaServer.recvFromClient fails on invalid fd" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const addr = try http_server.Address.init("127.0.0.1", try freePort());
        defer _ = closeI32Fd(addr.sock_fd);

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        defer server.destroy(allocator);

        var buf: [1024]u8 = undefined;
        const result = server.recvFromClient(-1, &buf);
        try std.testing.expectError(error.RecvFailed, result);
    }

    test "GinwaServer.sendToClient fails on invalid fd" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const addr = try http_server.Address.init("127.0.0.1", try freePort());
        defer _ = closeI32Fd(addr.sock_fd);

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        defer server.destroy(allocator);

        const result = server.sendToClient(-1, "Hello");
        try std.testing.expectError(error.SendFailed, result);
    }

    test "Server accepts client connection" {
        const allocator = std.testing.allocator;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const addr = try http_server.Address.init("127.0.0.1", try freePort());
        defer _ = closeI32Fd(addr.sock_fd);

        var server = try http_server.GinwaServer.init(allocator, undefined, addr);
        defer server.destroy(allocator);

        const client_fd_sock = linux.socket(2, 1, 0);
        const client_fd: i32 = @intCast(client_fd_sock);
        defer _ = closeI32Fd(client_fd);

        const addr2 = try http_server.Address.init("127.0.0.1", try freePort());
        defer _ = closeI32Fd(addr2.sock_fd);
    }

    test "RequestBuffer.init creates empty buffer" {
        const allocator = std.testing.allocator;
        var rb = http_server.RequestBuffer.init(allocator);
        defer rb.deinit();

        try std.testing.expect(rb.buf.items.len == 0);
    }

    test "RequestBuffer.readFullRequest with exact POST headers (13248 body)" {
        const allocator = std.testing.allocator;

        var pipe_fds: [2]std.c.fd_t = undefined;
        const rc = if (comptime builtin.os.tag == .windows) blk: {
            const pair = helpers.createSocketPair() catch {
                return;
            };
            pipe_fds = pair;
            break :blk 0;
        } else posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &pipe_fds);
        if (rc < 0) {
            return;
        }

        const headers =
            "POST /api/llm/session HTTP/1.1\r\n" ++
            "Accept: */*\r\n" ++
            "Accept-Encoding: gzip, deflate, br, zstd\r\n" ++
            "Accept-Language: en-US,en;q=0.9\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Content-Length: 13248\r\n" ++
            "Content-Type: application/json\r\n" ++
            "Host: localhost:5173\r\n" ++
            "Origin: http://localhost:5173\r\n" ++
            "Referer: http://localhost:5173/app?view=task&task=task_1779042417517\r\n" ++
            "Sec-Fetch-Dest: empty\r\n" ++
            "Sec-Fetch-Mode: cors\r\n" ++
            "Sec-Fetch-Site: same-origin\r\n" ++
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36\r\n" ++
            "sec-ch-ua: \"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"\r\n" ++
            "sec-ch-ua-mobile: ?0\r\n" ++
            "sec-ch-ua-platform: \"Linux\"\r\n" ++
            "\r\n";

        const body_size: usize = 13248;
        const body = try allocator.alloc(u8, body_size);
        defer allocator.free(body);
        for (0..body_size) |i| {
            body[i] = @as(u8, @truncate(i));
        }

        var pump = RequestPump{ .fd = pipe_fds[1], .headers = headers, .body = body };
        const writer = try std.Thread.spawn(.{}, RequestPump.run, .{&pump});
        defer {
            writer.join();
            closeTestFd(pipe_fds[0]);
        }

        var rb = http_server.RequestBuffer.init(allocator);
        defer rb.deinit();

        const result = rb.readFullRequest(if (comptime builtin.os.tag == .windows)
            @intCast(@intFromPtr(pipe_fds[0]))
        else
            @intCast(pipe_fds[0])) catch |err| {
            std.log.info("readFullRequest failed: {s}\n", .{@errorName(err)});
            return err;
        };
        defer allocator.free(result);

        const expected_len = headers.len + body_size;
        try std.testing.expectEqual(expected_len, result.len);

        const result_body = result[headers.len..];
        try std.testing.expectEqual(@as(u8, 0), result_body[0]);
        try std.testing.expectEqual(@as(u8, 1), result_body[1]);
        try std.testing.expectEqual(@as(u8, 100), result_body[100]);
        try std.testing.expectEqual(@as(u8, @truncate(body_size - 1)), result_body[body_size - 1]);

        if (pump.err) |e| return e;
    }

    test "RequestBuffer.getContentLength with your headers" {
        const data =
            "POST /api/llm/session HTTP/1.1\r\n" ++
            "Accept: */*\r\n" ++
            "Content-Length: 13248\r\n" ++
            "\r\n";

        const content_length = http_server.RequestBuffer.getContentLength(data);
        try std.testing.expect(content_length != null);
        try std.testing.expectEqual(@as(usize, 13248), content_length.?);
    }
};

comptime {
    _ = http_server_tests;
}
