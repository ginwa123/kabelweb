//! Minimal TLS server probe that mirrors pabrik's boot exactly:
//!
//!   GinwaServer.init(alloc, io, Address.init("127.0.0.1", PORT))
//!   gs.setTlsCtx(tls.Ctx.init(alloc, cert, key, .{alpn_h2, alpn_http1}))
//!   gs.listenEventLoop(.{ .dispatch_mode = .worker_pool })
//!
//! That is the same three calls pabrik makes (`src/main.zig:325`,
//! `src/boot/server_boot.zig:80-100`), so whatever happens here happens in the
//! pabrik app when it is started with `--tls` / `--tls-selfsigned`.
//!
//! Run it, then:  curl -k -sS -i https://127.0.0.1:21997/health

const std = @import("std");
const gserverz = @import("kabelweb").server;

fn health(_: gserverz.HttpContext, _: gserverz.HttpRequest, res: gserverz.HttpResponse) !gserverz.HttpResponse {
    return res.withBody("OK");
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();

    const dir = "/tmp/kw-tls-probe";
    const paths = try gserverz.tls_cert.ensureSelfSigned(allocator, dir, "localhost", 365);
    const ctx = try gserverz.tls.Ctx.init(
        allocator,
        paths.cert_pem,
        paths.key_pem,
        &.{ gserverz.tls.alpn_h2, gserverz.tls.alpn_http1 },
    );
    std.debug.print("TLS enabled (ALPN: h2, http/1.1) cert={s}\n", .{paths.cert_pem});

    const address = try gserverz.Address.init("127.0.0.1", 21997);
    const gs = try gserverz.GinwaServer.init(allocator, init.io, address);
    defer gs.deinit();
    gs.setTlsCtx(ctx);

    var root = gs.router.group("");
    try root.get("/health", health);

    std.debug.print("READY https://127.0.0.1:21997 (dispatch_mode=.worker_pool)\n", .{});
    try gs.listenEventLoop(.{ .dispatch_mode = .worker_pool });
}
