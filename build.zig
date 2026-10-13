//! `kabelweb` package — self-contained Zig web-framework library used
//! by nalarcore: a pure-Zig HTTP server (`server/`) + a libcurl-backed
//! HTTP client (`client/`).
//!
//! Mirrors `src/modules/databases/build.zig`'s pattern: vendored
//! libcurl is a per-target prebuilt archive under
//! `vendor/curl/<target>/lib/libcurl.a` + a portable C header under
//! `vendor/curl/<target>/include/`. Consumers
//! (`b.dependency("kabelweb", .{...})`) get the right
//! include path + library archive for the TARGET they pass in,
//! without the consumer needing to wire per-platform system library
//! paths itself.
//!
//! Why per-TARGET (not per-Compile from the consumer): the consumer
//! build.zig's curl include-path plumbing no longer needs to know
//! about Homebrew keg-only paths or vcpkg sysroots. The
//! kabelweb module carries those for its own target, and
//! Zig's module-graph dep propagation handles the rest.
//!
//! The server half needs no vendored deps (pure Zig + system
//! ssl/crypto for the OpenSSL server-side TLS, linked via
//! `linkSystemLibrary` in the system path and covered by the fat
//! libcurl archive — curl + ssl + crypto merged — in the vendored
//! path).
//!
//! Why `addObjectFile` (not `linkSystemLibrary("curl")`): the
//! vendored `libcurl.a` lives at a non-standard path that the
//! cross-target linker can't find via `-lcurl` / `-L<dir>`. The
//! `addObjectFile` call embeds the archive's symbols directly in
//! the consumer's link line, bypassing the search-path resolution.
//! The result is that libcurl is STATICALLY LINKED into every
//! consumer — verified by `ldd zig-out/bin/nalar | grep -i curl`
//! showing no `libcurl.so.4` line (the hermetic-build goal).
//!
//! ## System-deps probe
//!
//! In addition to the vendored path, this package probes the host
//! system at build config time for libcurl + libssl + libcrypto. If
//! the host has all three (the normal case on Arch / Debian / Fedora
//! / Ubuntu dev hosts), the package links the system libs via
//! `linkSystemLibrary` and skips the vendored archive entirely. This
//! saves ~30 min of cross-compile on a fresh checkout AND produces a
//! binary that uses the host's libcurl — which is what the user asked
//! for: "before use vendor script to build, check the current system
//! deps first, if system have the lib no need use vendor".
//!
//! Override with `-Dforce-vendor=true` to always use the vendored
//! archive (useful for CI runners + testing the vendored path).

const std = @import("std");

/// Cross-platform "does this file exist" check used by the system-deps
/// probe below. Earlier revisions ran `sh -c "test -f ..."` here,
/// which is unreliable on Windows dev boxes (Git for Windows ships
/// git.exe + bash.exe but doesn't add `C:\Program Files\Git\bin` to
/// PATH automatically). The probe then silently fell through to
/// "vendor fallback" even when vcpkg had the libraries installed at
/// `C:\vcpkg\installed\x64-windows\` — same failure mode the root
/// build.zig hit (and fixed). Host-OS-specific direct syscalls via
/// `std.os`, NOT `std.c` — build.zig doesn't link libc by default
/// (Zig 0.16 requires an explicit `link_libc = true` on the build
/// runner module for `std.c` to resolve `fopen`).
///
///   - Linux:   `faccessat(AT_FDCWD, path, mode=0)` returns 0 when
///              the file exists.
///   - macOS:   same `faccessat` (POSIX).
///   - Windows: `GetFileAttributesW` returns INVALID_FILE_ATTRIBUTES
///              on missing; existence = attrs != invalid AND attrs
///              doesn't have the DIRECTORY bit set (mirror `test -f`).
fn fileExists(absolute_path: []const u8) bool {
    var buf: [std.fs.max_path_bytes:0]u8 = undefined;
    if (absolute_path.len >= buf.len) return false;
    @memcpy(buf[0..absolute_path.len], absolute_path);
    buf[absolute_path.len] = 0;
    return switch (@import("builtin").os.tag) {
        .linux => blk: {
            const rc = std.os.linux.faccessat(std.os.linux.AT.FDCWD, &buf, 0, 0);
            break :blk rc == 0;
        },
        // macOS: libc `access()` — same F_OK check as `test -f`.
        // (The build runner links libc, so the extern is always
        // resolvable; no shell-out needed. Zig 0.16 removed
        // std.posix.access / made it Io-based, and the old shell-out
        // used std.heap.GeneralPurposeAllocator + a pre-0.16
        // std.process.run signature that no longer compile.)
        .macos => blk: {
            const rc = std.c.access(&buf, 0); // F_OK = 0
            break :blk rc == 0;
        },
        .windows => blk: {
            // Win32 GetFileAttributesW (kernel32.dll, always linked on
            // Windows). UTF-8 path → WTF-16. Directory bit excluded
            // so this matches `test -f` semantics.
            var wide: [std.fs.max_path_bytes]u16 = undefined;
            const written = std.unicode.wtf8ToWtf16Le(&wide, absolute_path) catch break :blk false;
            if (written >= wide.len) break :blk false;
            wide[written] = 0;
            const attrs = GetFileAttributesW(@ptrCast(&wide));
            if (attrs == INVALID_FILE_ATTRIBUTES) break :blk false;
            if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) break :blk false;
            break :blk true;
        },
        else => false,
    };
}

// Win32 GetFileAttributesW (mirrors the root build.zig declarations —
// declared locally because std.os.windows.kernel32 0.16 doesn't expose
// it. Win32 kernel32.dll is always linked on Windows).
extern "kernel32" fn GetFileAttributesW(lpPathName: [*:0]const u16) callconv(.winapi) u32;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;

/// Windows-only stub-libcurl generator. Compiles
/// `scripts/stub_libcurl.c` (a no-op implementation of the libcurl
/// symbols kabelweb `src/client/curl.zig` references) and writes
/// the resulting `.o` + `.a` + stub `curl/curl.h` header into the
/// per-target vendor directory so the test compile's cimport + link
/// line resolve cleanly on dev boxes that don't have vcpkg libcurl
/// installed.
///
/// Runs at config time (synchronously, via `std.process.run`) rather
/// than as a deferred `addSystemCommand` step, because:
///   - The stub files only need to exist on disk BEFORE the test
///     compile's link-line-construction phase — there's no reason to
///     serialize them through the build runner's parallel-execution
///     model.
///   - A deferred step would require propagating the step handle
///     through the kabelweb module graph so root build.zig's
///     test compile could wire a `dependOn` — that's brittle and
///     cross-module-coupled.
///
/// Why Windows-only: real libcurl is available via vcpkg on Windows
/// (system probe above takes over) or via the vendored archive on
/// Linux/macOS. The stub is a dev-box-only fallback for the case
/// where neither is available.
///
/// The stub functions are empty no-ops — see scripts/stub_libcurl.c's
/// top comment for the runtime behavior (curl_easy_init returns NULL,
/// curl_easy_perform returns CURLE_FAILED_INIT, etc.).
fn generateStubLibcurlWindows(b: *std.Build, target_dir: []const u8) void {
    const zig_exe = b.graph.zig_exe;
    // Package directory: b.path("") resolves to <package_dir>.
    // The cmd.exe invocations below all set cwd to this directory so
    // that relative paths (target_dir = "vendor/curl/windows-amd64",
    // stub_src_dir = "scripts") resolve against the package root,
    // matching where b.path() places files for the consumer's link
    // line.
    const pkg_dir_bs = blk: {
        // b.build_root.path is the absolute package directory for
        // this dependency's build.zig. Strip leading "./" if present.
        var path: []const u8 = b.build_root.path orelse ".";
        if (std.mem.startsWith(u8, path, "./")) path = path[2..];
        const buf = b.allocator.alloc(u8, path.len) catch @panic("OOM");
        @memcpy(buf, path);
        std.mem.replaceScalar(u8, buf, '/', '\\');
        break :blk buf;
    };
    defer b.allocator.free(pkg_dir_bs);
    // Path to the stub source files (relative to the package root).
    const stub_src_dir = "scripts";

    // === 1. ensure target_dir/lib + target_dir/include/curl/ exist ===
    // Idempotent mkdir via cmd.exe. (Avoids the Zig 0.16 std.fs API
    // churn — the simpler `mkdir -p` semantics via cmd's `if not exist`
    // is portable across dev boxes without fighting the new Io-based
    // filesystem API.)
    {
        var cmd_buf: [512]u8 = undefined;
        // Normalize target_dir to all-backslashes (cmd.exe doesn't
        // accept mixed `/` + `\` in `if not exist` paths — fails with
        // "syntax incorrect").
        const tgt_dir_bs = blk: {
            const buf = b.allocator.alloc(u8, target_dir.len) catch @panic("OOM");
            @memcpy(buf, target_dir);
            std.mem.replaceScalar(u8, buf, '/', '\\');
            break :blk buf;
        };
        defer b.allocator.free(tgt_dir_bs);
        const mkdir_cmd = std.fmt.bufPrint(
            cmd_buf[0..],
            "cd /D {s} & if not exist {s}\\lib mkdir {s}\\lib & if not exist {s}\\include\\curl mkdir {s}\\include\\curl",
            .{ pkg_dir_bs, tgt_dir_bs, tgt_dir_bs, tgt_dir_bs, tgt_dir_bs },
        ) catch @panic("OOM formatting mkdir cmd");
        const argv = [_][]const u8{ "cmd.exe", "/c", mkdir_cmd };
        const result = std.process.run(
            b.allocator,
            b.graph.io,
            .{ .argv = &argv },
        ) catch |err| {
            std.debug.print(
                "[kabelweb] stub-libcurl mkdir failed: {t} (fallback skipped)\n",
                .{err},
            );
            return;
        };
        defer {
            b.allocator.free(result.stdout);
            b.allocator.free(result.stderr);
        }
        const bad_exit = switch (result.term) {
            .exited => |code| code != 0,
            .signal, .stopped, .unknown => true,
        };
        if (bad_exit) {
            std.debug.print(
                "[kabelweb] stub-libcurl mkdir exited non-zero ({t})\n",
                .{result.term},
            );
            std.debug.print("  stderr: {s}\n", .{result.stderr});
            return;
        }
    }

    // === 2. copy scripts/stub_libcurl.h → target_dir/include/curl/curl.h ===
    {
        var cmd_buf: [512]u8 = undefined;
        // Normalize target_dir's forward slashes to backslashes —
        // cmd.exe is happiest with all-backslash paths (mixed slashes
        // intermittently fail with "The system cannot find the path
        // specified" on Windows dev boxes).
        const tgt_dir_bs = blk: {
            const buf = b.allocator.alloc(u8, target_dir.len) catch @panic("OOM");
            @memcpy(buf, target_dir);
            std.mem.replaceScalar(u8, buf, '/', '\\');
            break :blk buf;
        };
        defer b.allocator.free(tgt_dir_bs);
        const copy_cmd = std.fmt.bufPrint(
            cmd_buf[0..],
            "cd /D {s} & copy /Y {s}\\stub_libcurl.h {s}\\include\\curl\\curl.h 1>NUL",
            .{ pkg_dir_bs, stub_src_dir, tgt_dir_bs },
        ) catch @panic("OOM formatting copy cmd");
        const argv = [_][]const u8{ "cmd.exe", "/c", copy_cmd };
        const result = std.process.run(
            b.allocator,
            b.graph.io,
            .{ .argv = &argv },
        ) catch |err| {
            std.debug.print(
                "[kabelweb] stub-libcurl header copy failed: {t} (fallback skipped)\n",
                .{err},
            );
            return;
        };
        defer {
            b.allocator.free(result.stdout);
            b.allocator.free(result.stderr);
        }
        const bad_exit = switch (result.term) {
            .exited => |code| code != 0,
            .signal, .stopped, .unknown => true,
        };
        if (bad_exit) {
            std.debug.print(
                "[kabelweb] stub-libcurl header copy exited non-zero ({t})\n",
                .{result.term},
            );
            std.debug.print("  stderr: {s}\n", .{result.stderr});
            return;
        }
        std.debug.print(
            "[kabelweb] wrote stub header: {s}\\include\\curl\\curl.h\n",
            .{target_dir},
        );
    }

    // === 3. compile scripts/stub_libcurl.c → target_dir/lib/stub_libcurl.o ===
    // Use `zig cc` (the host's bundled clang) — no MinGW gcc dependency.
    // The target x86_64-windows-gnu matches the dev box's default
    // target. Cross-compile consumers would need a per-target stub —
    // out of scope for the dev-box fallback.
    const obj_path = b.fmt("{s}/lib/stub_libcurl.o", .{target_dir});
    {
        const obj_path_bs = blk: {
            const buf = b.allocator.alloc(u8, obj_path.len) catch @panic("OOM");
            @memcpy(buf, obj_path);
            std.mem.replaceScalar(u8, buf, '/', '\\');
            break :blk buf;
        };
        defer b.allocator.free(obj_path_bs);
        const argv = [_][]const u8{
            zig_exe,                                         "cc",
            "-target",                                       "x86_64-windows-gnu",
            "-c",                                            "-I",
            b.fmt("{s}/{s}", .{ pkg_dir_bs, stub_src_dir }), "-o",
            b.fmt("{s}\\{s}", .{ pkg_dir_bs, obj_path_bs }), b.fmt("{s}\\{s}\\stub_libcurl.c", .{ pkg_dir_bs, stub_src_dir }),
        };
        const result = std.process.run(
            b.allocator,
            b.graph.io,
            .{ .argv = &argv },
        ) catch |err| {
            std.debug.print(
                "[kabelweb] zig cc (stub-libcurl compile) failed: {t}\n",
                .{err},
            );
            return;
        };
        defer {
            b.allocator.free(result.stdout);
            b.allocator.free(result.stderr);
        }
        const bad_exit = switch (result.term) {
            .exited => |code| code != 0,
            .signal, .stopped, .unknown => true,
        };
        if (bad_exit) {
            std.debug.print(
                "[kabelweb] zig cc (stub-libcurl compile) exited non-zero ({t})\n",
                .{result.term},
            );
            std.debug.print("  stderr: {s}\n", .{result.stderr});
            return;
        }
        std.debug.print(
            "[kabelweb] compiled stub object: {s}\n",
            .{obj_path},
        );
    }

    // === 4. archive stub_libcurl.o → target_dir/lib/libcurl.a ===
    {
        const archive_path = b.fmt("{s}/lib/libcurl.a", .{target_dir});
        const archive_path_bs = blk: {
            const buf = b.allocator.alloc(u8, archive_path.len) catch @panic("OOM");
            @memcpy(buf, archive_path);
            std.mem.replaceScalar(u8, buf, '/', '\\');
            break :blk buf;
        };
        defer b.allocator.free(archive_path_bs);
        const obj_path_bs = blk: {
            const buf = b.allocator.alloc(u8, obj_path.len) catch @panic("OOM");
            @memcpy(buf, obj_path);
            std.mem.replaceScalar(u8, buf, '/', '\\');
            break :blk buf;
        };
        defer b.allocator.free(obj_path_bs);
        const argv = [_][]const u8{
            zig_exe,                                             "ar",                                            "rcs",
            b.fmt("{s}\\{s}", .{ pkg_dir_bs, archive_path_bs }), b.fmt("{s}\\{s}", .{ pkg_dir_bs, obj_path_bs }),
        };
        const result = std.process.run(
            b.allocator,
            b.graph.io,
            .{ .argv = &argv },
        ) catch |err| {
            std.debug.print(
                "[kabelweb] zig ar (stub-libcurl archive) failed: {t}\n",
                .{err},
            );
            return;
        };
        defer {
            b.allocator.free(result.stdout);
            b.allocator.free(result.stderr);
        }
        const bad_exit = switch (result.term) {
            .exited => |code| code != 0,
            .signal, .stopped, .unknown => true,
        };
        if (bad_exit) {
            std.debug.print(
                "[kabelweb] zig ar (stub-libcurl archive) exited non-zero ({t})\n",
                .{result.term},
            );
            std.debug.print("  stderr: {s}\n", .{result.stderr});
            return;
        }
        std.debug.print(
            "[kabelweb] wrote stub archive: {s}\n",
            .{archive_path},
        );
    }
}

/// Result of probing the host system for libcurl / libssl / libcrypto.
///
/// SYSTEM-ONLY LINKS: when `use_system` is true, the package links against
/// the host's installed libcurl / libssl / libcrypto via `linkSystemLibrary`
/// and uses the host's `/usr/include` for the cimported headers. The
/// vendored prebuilt archive at `vendor/curl/<target>/lib/libcurl.a` is
/// NOT linked — saves ~30 min cross-compile on hosts that have the system
/// libs (Arch / Debian / Ubuntu / Fedora all do).
///
/// VENDOR FALLBACK: when the probe can't find a usable system libcurl,
/// the package uses the vendored archive as before. The archive is a
/// "fat" build with OpenSSL symbols merged in (see
/// scripts/build-vendor-curl.sh), so it works without any host-installed
/// TLS lib.
const SystemLibs = struct {
    use_system: bool,
    /// True when the probe found curl.h AND libcurl.so on the host.
    found_curl: bool,
    /// True when the probe found openssl/ssl.h AND libssl.so on the host.
    found_ssl: bool,
    /// True when the probe found openssl/ssl.h AND libcrypto.so on the host.
    found_crypto: bool,
};

/// Probe the host system for libcurl / libssl / libcrypto.
///
/// Runs `sh -c` synchronously at build config time (via
/// `std.process.run`) and parses 5 boolean fields out of its stdout.
/// The probe runs in ~25 ms on a typical Linux host — cheap enough
/// to re-run on every `zig build` invocation (no caching needed).
///
/// `use_system` is true ONLY when all three libs are present on the
/// host AND the COMPILE target is the same as the host. Cross-compile
/// (Linux host → macOS target) always falls back to vendor because
/// the host's libs are for Linux, not macOS — linking them into a
/// macOS binary would fail at link time with mismatched arch.
///
/// `target` is the COMPILE's resolved target (what the binary will
/// run on), NOT `b.graph.host` (what the build is running on). The
/// package's `build()` function passes `target` to this probe so
/// cross-compile picks up the vendored archive automatically.
///
/// A partial setup (curl but no SSL) is treated as "no system libs"
/// — the vendored archive is self-contained with OpenSSL merged in,
/// so partial system setups would create a mixed link line that
/// could fail in non-obvious ways (e.g. undefined symbol
/// `SSL_CTX_set_keylog_callback` if libssl.so is missing).
///
/// Only Linux + macOS (native) are probed. Windows needs explicit
/// .lib paths and falls back to vendor. Cross-compile (Linux host →
/// macOS target, or vice versa) also falls back to vendor because the
/// host's libs are for the host OS, not the target OS.
///
/// On macOS the probe checks Homebrew's keg-only paths under
/// `/opt/homebrew/opt/<name>/{include,lib}/`. The CI yml installs
/// `pkg-config openssl@3 coreutils` (but NOT curl) on Mac runners and
/// exports LDFLAGS/CPPFLAGS from `brew --prefix openssl@3`. For
/// system libcurl on Mac, add `brew install curl` to the CI yml — the
/// probe will then pick it up at `/opt/homebrew/opt/curl/`.
pub fn probeSystemLibs(b: *std.Build, target: std.Build.ResolvedTarget) SystemLibs {
    // Only native (target == host) goes system-only. Cross-compile
    // (Linux host → macOS target, or vice versa) always falls back to
    // vendor — the host's libs are for the host OS.
    if (target.result.os.tag != b.graph.host.result.os.tag) {
        return .{
            .use_system = false,
            .found_curl = false,
            .found_ssl = false,
            .found_crypto = false,
        };
    }

    // Pure-Zig probe — no shell, no `bash` / `sh` dependency.
    //
    // Earlier revisions ran `sh -c "test -f ..."` here via
    // `std.process.run`. Windows dev boxes without `bash` / `sh` on
    // PATH (Git for Windows ships bash.exe at `C:\Program Files\Git\
    // bin` but doesn't add it to PATH automatically) saw the probe
    // spawn-fail, fall through to `use_system = false`, and end up
    // looking for the vendored `vendor/curl/<target>/lib/libcurl.a`
    // archive — which on Windows is hardcoded to `windows-amd64/` and
    // doesn't exist for any host (the script
    // `scripts/build-vendor-curl.sh` only cross-compiles Linux + macOS
    // archives; Windows archives are intentionally NOT built).
    //
    // Pure-Zig fix: use the local `fileExists` helper (defined above)
    // with host-OS-specific paths. Mirrors the equivalent change in
    // the root build.zig's system-deps probe.
    var curl_hdr: bool = false;
    var found_curl_lib: bool = false;
    var ssl_hdr: bool = false;
    var found_ssl_lib: bool = false;
    var found_crypto_lib: bool = false;
    switch (b.graph.host.result.os.tag) {
        .linux => {
            // Linux: checks /usr/include + /usr/lib (Arch / Debian /
            // Ubuntu / Fedora layouts). Headers at the canonical
            // paths; libs probed via direct .so path glob since
            // `ldconfig -p` is shell-only.
            //
            // (We check the unversioned `libcurl.so` symlink AND the
            // unversioned `libssl.so` / `libcrypto.so` — most distros
            // keep these as symlinks to the versioned .so.N library.)
            //
            // Debian/Ubuntu multiarch puts the unversioned linker
            // symlinks under /usr/lib/<triplet>/ (e.g.
            // /usr/lib/x86_64-linux-gnu/libcurl.so from
            // libcurl4-openssl-dev) instead of /usr/lib/ — check both.
            // The curl headers can also live under the multiarch
            // include dir (/usr/include/<triplet>/curl/curl.h) since
            // curlbuild.h is arch-dependent — check those too.
            curl_hdr = fileExists("/usr/include/curl/curl.h") or
                fileExists("/usr/include/x86_64-linux-gnu/curl/curl.h") or
                fileExists("/usr/include/aarch64-linux-gnu/curl/curl.h");
            found_curl_lib = fileExists("/usr/lib/libcurl.so") or
                fileExists("/usr/lib/x86_64-linux-gnu/libcurl.so") or
                fileExists("/usr/lib/aarch64-linux-gnu/libcurl.so");
            ssl_hdr = fileExists("/usr/include/openssl/ssl.h");
            found_ssl_lib = fileExists("/usr/lib/libssl.so") or
                fileExists("/usr/lib/x86_64-linux-gnu/libssl.so") or
                fileExists("/usr/lib/aarch64-linux-gnu/libssl.so");
            found_crypto_lib = fileExists("/usr/lib/libcrypto.so") or
                fileExists("/usr/lib/x86_64-linux-gnu/libcrypto.so") or
                fileExists("/usr/lib/aarch64-linux-gnu/libcrypto.so");
        },
        .macos => {
            // macOS: Homebrew installs keg-only libs at
            // `/opt/homebrew/opt/<name>/{include,lib}/`. No ldconfig
            // equivalent — we test for the .dylib file directly at the
            // canonical brew path. We also accept a system
            // `/usr/include` install (rare).
            curl_hdr = fileExists("/opt/homebrew/opt/curl/include/curl/curl.h") or
                fileExists("/usr/include/curl/curl.h");
            found_curl_lib = fileExists("/opt/homebrew/opt/curl/lib/libcurl.dylib") or
                fileExists("/usr/lib/libcurl.dylib");
            ssl_hdr = fileExists("/opt/homebrew/opt/openssl@3/include/openssl/ssl.h") or
                fileExists("/opt/homebrew/opt/openssl/include/openssl/ssl.h") or
                fileExists("/usr/include/openssl/ssl.h");
            found_ssl_lib = fileExists("/opt/homebrew/opt/openssl@3/lib/libssl.dylib") or
                fileExists("/usr/lib/libssl.dylib");
            found_crypto_lib = fileExists("/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib") or
                fileExists("/usr/lib/libcrypto.dylib");
        },
        .windows => {
            // Windows: vcpkg at `C:/vcpkg/installed/x64-windows/`.
            // The CI installs curl + openssl via
            // `vcpkg install --recurse <port>:x64-windows`. Header-only
            // probe: vcpkg's `lib/` filenames differ between MSVC
            // (`curl.lib`) and MinGW (`libcurl.lib`), and may also be
            // hidden behind `.dll.lib` or vendor-specific names. Rather
            // than enumerate every naming variant, we just check
            // headers — `linkSystemLibrary` / `addObjectFile` will
            // fail loudly with "file not found" if the lib is actually
            // missing. Headers are stable across toolchain variants.
            curl_hdr = fileExists("C:/vcpkg/installed/x64-windows/include/curl/curl.h");
            ssl_hdr = fileExists("C:/vcpkg/installed/x64-windows/include/openssl/ssl.h");
        },
        else => {
            // Cross-compile to an unknown OS — bail.
            curl_hdr = false;
            found_curl_lib = false;
            ssl_hdr = false;
            found_ssl_lib = false;
            found_crypto_lib = false;
        },
    }

    // Two patterns of use_system:
    //
    //   - Linux/macOS: require header + matching .so/.dylib to be
    //     present. We need both: header alone (libcurl dev package
    //     installed without runtime) means consumer compile passes
    //     but the linked .so is missing → runtime crash. The .so/.dylib
    //     files live under the same brew keg / distro paths.
    //   - Windows: header-only. The kabelweb module uses
    //     `addObjectFile` to wire the exact `.lib` path into the
    //     link line; that fails loudly if the lib is actually
    //     missing (Zig prints the missing path). So we don't need
    //     a redundant lib check.
    const use_system: bool = switch (b.graph.host.result.os.tag) {
        .linux => curl_hdr and found_curl_lib and ssl_hdr and found_ssl_lib and found_crypto_lib,
        .macos => curl_hdr and found_curl_lib and ssl_hdr and found_ssl_lib and found_crypto_lib,
        .windows => curl_hdr and ssl_hdr,
        else => false,
    };
    const found_curl = curl_hdr;
    const found_ssl = ssl_hdr;
    const found_crypto = ssl_hdr; // crypto lives under openssl/ssl.h — same header

    // Log the probe result so the operator sees which path was taken.
    // On a quiet build (no --verbose) zig's std.debug.print routes to
    // stderr — easy to spot in build output.
    if (use_system) {
        std.debug.print(
            "[kabelweb] using system libcurl + ssl + crypto (host has all 3 headers)\n",
            .{},
        );
    } else {
        std.debug.print(
            "[kabelweb] using vendored libcurl fat archive (host probe: curl_hdr={} ssl_hdr={})\n",
            .{ curl_hdr, ssl_hdr },
        );
    }

    return .{
        .use_system = use_system,
        .found_curl = found_curl,
        .found_ssl = found_ssl,
        .found_crypto = found_crypto,
    };
}

// ═══════════════════════════════════════════════════════════════════════
// Sharded test execution
// ═══════════════════════════════════════════════════════════════════════
//
// `zig build test` was 402 s on a 16-core box: ~8 s of compile and ~390 s
// of ONE test binary running its 791 tests strictly in sequence inside a
// single process. No amount of `-j` touches that 390 s — the parallelism
// has to come from SEPARATE test binaries.
//
// So the same test set is split at CONFIGURE time into N shards, each its
// own `b.addTest` compile carrying a `--test-filter` subset, and `zig
// build`'s own step scheduler compiles and runs them concurrently.
//
// ── Why filters and not one module per subtree ─────────────────────────
// `src/root.zig` is the single root module every test step compiles, and
// its files self-import by relative path. A second module rooted inside
// `src/` would make Zig reject the build with "file exists in modules
// 'root' and '…'" the moment the two modules' file tables overlap.
// Filters sidestep that entirely: every shard shares ONE root module, so
// there is nothing to collide.
//
// ── The contract that makes this safe ──────────────────────────────────
//   1. EVERY named `test` under `src/` lands in EXACTLY one shard,
//      discovered by scanning the sources — never a hand-written list.
//   2. The one unnamed `test { _ = @import(...) }` discovery block in
//      `src/root.zig` has an empty name, which no `--test-filter` can
//      select, so Zig runs it in EVERY shard. Duplicated, never dropped.
//   3. A shard is a normal build step, so `zig build --summary all` still
//      prints per-shard pass counts and a failure in one shard does not
//      mask another shard's results.
//   4. `-Dtest-shards=1` restores the old single unfiltered binary
//      verbatim, which is the escape hatch if a machine cannot afford N
//      concurrent compilers (~500 MB RSS each).

/// A `--test-filter` one shard gets compiled with, plus the cost weight the
/// balancer assigns to it. Weight is relative, not milliseconds — it only
/// has to be big enough that a 60-second soak outweighs every fast test put
/// together, so the balancer gives it a shard of its own.
const TestShardEntry = struct {
    filter: []const u8,
    weight: u64,
    /// The test's real name, plus the filter shapes `name` can safely be
    /// reduced to. Both are kept so `pickLeastOverlappingFilter` can compare
    /// against every other name once the whole set is known.
    name: []const u8,
    candidates: TestFilterCandidates,
};

/// Weight of a test whose runtime is close to the suite median, which is
/// roughly 10 ms on this box. Every weight below is expressed in THESE
/// units, so mixing them is meaningful.
const average_test_weight: u64 = 1;

/// Tests whose runtime is orders of magnitude above that median, so a
/// name-count-balanced split would still leave one shard holding all the
/// wall clock. Measured on a 16-core Linux box.
///
/// This table is a load-balancing hint, NOT a correctness input: a test
/// missing from it still runs, it just shares a shard. Re-measure and add an
/// entry whenever a new test starts dominating `zig build test`.
const slow_test_weights = [_]struct { name: []const u8, weight: u64 }{
    // ~60 s each: the two SSE keepalive soaks. They self-skip unless
    // KABELWEB_SOAK is set, so they only weigh on the full `test` step —
    // but that is exactly the step being parallelized, and 120 s of the
    // 402 s baseline is these two tests alone.
    .{ .name = "sse keepalive: server does NOT mis-remove a healthy client under 60s", .weight = 6_000 },
    .{ .name = "sse keepalive: server does NOT mis-remove 2 healthy clients under 60s", .weight = 6_000 },
    // ~10 s: 100 real sequential GETs against example.com over the network.
    .{ .name = "stress: 100 sequential successful GETs to example.com", .weight = 1_000 },
    // ~2 s each: real process spawns / real socket traffic.
    .{ .name = "stress: parse 1000 random-ish requests without crash", .weight = 200 },
    .{ .name = "stress: 50 sequential server init/destroy cycles", .weight = 200 },
    .{ .name = "stress: parse 10,000 small requests without leak", .weight = 200 },
    .{ .name = "stress: parse 100 large requests (1 MB body each) without leak", .weight = 200 },
    .{ .name = "stress: register and remove 1000 clients in mixed order", .weight = 200 },
    .{ .name = "stress: hash map with 1000 query params parses correctly", .weight = 200 },
    .{ .name = "stress: 500 sequential Address.init/destroy cycles", .weight = 200 },
    .{ .name = "sse: 1000 concurrent client registrations produce 1000 unique IDs", .weight = 200 },
    .{ .name = "integration: parse 100 sequential requests from socket pair", .weight = 200 },
};

fn testWeight(name: []const u8) u64 {
    for (slow_test_weights) |entry| {
        if (std.mem.eql(u8, name, entry.name)) return entry.weight;
    }
    return average_test_weight;
}

/// `haystack.contains(needle)`, but anchored on a SIMD `memchr` for the
/// needle's first byte.
///
/// `std.mem.indexOf` on two ~60-byte slices is a naive O(n·m) scan and costs
/// about a microsecond per call. The sharding passes below run millions of
/// them (one per candidate filter per test name), which put seconds into
/// every single `zig build` — including builds that never touch the test
/// suite. Jumping straight to the handful of positions where the first byte
/// occurs and comparing only those is the same answer for a tenth of the
/// time.
fn containsFast(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    // Stop early once too few bytes remain for the needle to fit — without
    // that, a hit on the needle's first byte near the end of the haystack
    // slices past it.
    const last_start = haystack.len - needle.len;
    var offset: usize = 0;
    while (std.mem.indexOfScalarPos(u8, haystack[0 .. last_start + 1], offset, needle[0])) |pos| {
        if (std.mem.eql(u8, haystack[pos..][0..needle.len], needle)) return true;
        offset = pos + 1;
    }
    return false;
}

/// An inverted index from 2-byte sequence to the test names containing it.
///
/// Sharding has to answer "which test names contain this filter?" a few
/// million times. Doing that by scanning every name for every filter is a
/// naive O(n·m) substring search, ~1 µs a pop, which put seconds into EVERY
/// `zig build` — including builds that never touch the test suite.
///
/// Inverting it makes the common answer free. A filter is looked up by ONE
/// of its 2-byte sequences; a specific pair occurs in roughly one name in a
/// thousand, so the candidate list is a name or two and the exact compare
/// runs that many times instead of 791.
///
/// The index is only ever a CANDIDATE FILTER: `candidates()` may return names
/// that do not contain the filter, and the caller must confirm with
/// `std.mem.indexOf`. That direction is safe — it costs a little time and can
/// never drop a name. The reverse mistake is what silently re-runs tests in
/// the wrong shard, so the exact compare stays at every call site.
const PairIndex = struct {
    const pair_count = 1 << 16;
    const none = std.math.maxInt(u32);

    /// Counting sort of every (2-byte sequence, name index) occurrence, so a
    /// sequence's occurrences are the contiguous run `items[starts[p]..starts[p + 1]]`.
    starts: []u32,
    items: []u32,
    allocator: std.mem.Allocator,

    fn init(alloc: std.mem.Allocator, names: []const []const u8) !PairIndex {
        // One slot per (name, adjacent byte pair).
        var total: usize = 0;
        for (names) |name| {
            if (name.len >= 2) total += name.len - 1;
        }

        const counts = try alloc.alloc(u32, pair_count);
        defer alloc.free(counts);
        @memset(counts, 0);

        const cursor = try alloc.alloc(u32, pair_count);
        defer alloc.free(cursor);

        for (names) |name| {
            var i: usize = 0;
            while (i + 2 <= name.len) : (i += 1) {
                counts[pairOf(name, i)] += 1;
            }
        }

        const starts = try alloc.alloc(u32, pair_count + 1);
        var running: u32 = 0;
        for (0..pair_count) |p| {
            starts[p] = running;
            running += counts[p];
            cursor[p] = starts[p];
        }
        starts[pair_count] = running;

        const items = try alloc.alloc(u32, total);
        for (names, 0..) |name, name_index| {
            var i: usize = 0;
            while (i + 2 <= name.len) : (i += 1) {
                const p = pairOf(name, i);
                items[cursor[p]] = @intCast(name_index);
                cursor[p] += 1;
            }
        }

        return .{ .starts = starts, .items = items, .allocator = alloc };
    }

    fn deinit(self: *PairIndex) void {
        self.allocator.free(self.starts);
        self.allocator.free(self.items);
    }

    fn pairOf(name: []const u8, i: usize) usize {
        return (@as(usize, name[i]) << 8) | name[i + 1];
    }

    /// The needle's 2-byte sequence with the shortest candidate list, i.e.
    /// the one that will send the fewest names to the exact compare.
    fn bestPair(self: *const PairIndex, needle: []const u8) u32 {
        var best: u32 = 0;
        var best_len: u32 = std.math.maxInt(u32);
        var i: usize = 0;
        while (i + 2 <= needle.len) : (i += 1) {
            const p: u32 = @intCast(pairOf(needle, i));
            const len = self.starts[p + 1] - self.starts[p];
            if (len < best_len) {
                best_len = len;
                best = p;
            }
        }
        return best;
    }

    fn candidates(self: *const PairIndex, pair: u32) []const u32 {
        return self.items[self.starts[pair]..self.starts[pair + 1]];
    }
};

/// Exactly how many of `all_names` contain `needle`, found by asking the
/// index for candidates and confirming each one. Never derived from a
/// cheaper approximation — this number decides which side of a name survives,
/// and an undercount silently drags sibling tests into a second shard.
fn countNamesContaining(all_names: []const []const u8, needle: []const u8, index: *const PairIndex) usize {
    if (needle.len == 0) return all_names.len;
    if (needle.len < 2) {
        // No 2-byte sequence to index on. Rare, and answering 0 here instead
        // of the truth is exactly how a one-character filter slipped past the
        // fan-out guard below while re-running the entire suite.
        var hits: usize = 0;
        for (all_names) |name| {
            if (std.mem.indexOf(u8, name, needle) != null) hits += 1;
        }
        return hits;
    }
    var hits: usize = 0;
    for (index.candidates(index.bestPair(needle))) |name_index| {
        if (std.mem.indexOf(u8, all_names[name_index], needle) != null) hits += 1;
    }
    return hits;
}

/// Report an unrecoverable build-configuration problem and stop.
///
/// Zig 0.16's `std.Build` has no `b.fatal`, and the rest of this file
/// signals unrecoverable build problems with `@panic` — match that, but
/// print the reason first, because a bare panic buries it in a stack trace.
fn fatalConfig(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ fmt ++ "\n", args);
    @panic("build configuration error");
}

/// Characters that cannot survive Zig's `@args-file` round trip.
///
/// Zig writes each `zig test` argument into a generated args file and quotes
/// it. It escapes a double quote but writes `'` as `\'` and leaves a bare
/// backslash alone — and the reader on the other side does not understand
/// `\'`, so the quoted token ends early and the parser then tries to read the
/// remainder as a filename ("unrecognized file extension of parameter ...").
/// A control character breaks the file the same way. 16 of this repo's 791
/// test names contain at least one of them, so every name goes through here
/// before it can become a filter.
fn isUnsafeFilterByte(c: u8) bool {
    return c == '\"' or c == '\'' or c == '\\' or c < 0x20;
}

/// The `--test-filter` shapes a test name can safely be reduced to.
///
/// `whole` is non-null when the name has no byte the args file cannot
/// carry, and is then always the right answer. Otherwise the name had to be
/// cut, and `head`/`tail` are the two maximal safe pieces of it — a
/// `--test-filter` is a SUBSTRING match, so either one still matches its own
/// test. Which one is chosen is settled later by `pickLeastOverlappingFilter`,
/// because the shorter we cut a name the more siblings it drags along.
const TestFilterCandidates = struct {
    whole: ?[]const u8,
    head: []const u8,
    tail: []const u8,
};

/// Reduce a test name to the `--test-filter` shapes that survive the args
/// file. See `TestFilterCandidates`.
fn safeTestFilter(name: []const u8) TestFilterCandidates {
    for (name) |c| {
        if (isUnsafeFilterByte(c)) break;
    } else return .{ .whole = name, .head = name, .tail = name };

    const first = blk: {
        for (name, 0..) |c, i| {
            if (isUnsafeFilterByte(c)) break :blk i;
        }
        break :blk name.len;
    };
    const last = blk: {
        var i = name.len;
        while (i > 0) {
            i -= 1;
            if (isUnsafeFilterByte(name[i])) break :blk i;
        }
        break :blk 0;
    };
    const head = std.mem.trim(u8, name[0..first], " \t");
    const tail = std.mem.trim(u8, name[last + 1 ..], " \t");

    // Both sides empty means the whole name is unsafe bytes — almost
    // certainly a machine-generated name. Fail loudly: silently dropping it
    // would leave a test that never runs, which is the exact failure this
    // whole sharding scheme has to rule out.
    if (head.len == 0 and tail.len == 0) {
        fatalConfig(
            "test name has no substring free of \" ' \\ or control bytes, so it " ++
                "cannot be turned into a --test-filter and would silently stop " ++
                "running under the sharded `test` step. Rename the test.\n" ++
                "  offending name: {s}",
            .{name},
        );
    }
    return .{ .whole = null, .head = head, .tail = tail };
}

/// Choose between a test's candidate filters by picking the one that is a
/// substring of the FEWEST other test names.
///
/// This is not cosmetic. A `--test-filter` is a substring match, so an
/// over-broad filter does not merely waste time — it makes a sibling test
/// match a shard it was not assigned to, and that test then runs in two
/// shards AT THE SAME TIME. The suite used to be one sequential process, so
/// tests sharing a fixture path were safe; running two copies concurrently
/// is not. Every name is known at configure time, so measure the overlap
/// instead of guessing.
fn pickLeastOverlappingFilter(
    candidates: TestFilterCandidates,
    all_names: []const []const u8,
    index: *const PairIndex,
) []const u8 {
    if (candidates.whole) |whole| return whole;

    const head_hits = countNamesContaining(all_names, candidates.head, index);
    const tail_hits = countNamesContaining(all_names, candidates.tail, index);
    // Ties go to the longer filter: a longer substring matches fewer names in
    // practice, and if it does not help it cannot hurt either.
    if (head_hits < tail_hits) return candidates.head;
    if (tail_hits < head_hits) return candidates.tail;
    return if (candidates.head.len >= candidates.tail.len) candidates.head else candidates.tail;
}

/// Decode the body of a Zig string literal (without the quotes) into `out`.
fn decodeZigStringBody(
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
    body: []const u8,
) !void {
    var i: usize = 0;
    while (i < body.len) {
        const c = body[i];
        if (c != '\\' or i + 1 >= body.len) {
            try out.append(alloc, c);
            i += 1;
            continue;
        }
        i += 1;
        const esc = body[i];
        i += 1;
        switch (esc) {
            'n' => try out.append(alloc, '\n'),
            'r' => try out.append(alloc, '\r'),
            't' => try out.append(alloc, '\t'),
            '\\' => try out.append(alloc, '\\'),
            '\"' => try out.append(alloc, '\"'),
            '\'' => try out.append(alloc, '\''),
            'x' => {
                const n = std.fmt.parseUnsigned(u16, body[i..][0..2], 16) catch {
                    try out.append(alloc, esc);
                    continue;
                };
                try out.append(alloc, @intCast(n & 0x7f));
                i += 2;
            },
            'u' => {
                const close = std.mem.indexOfScalar(u8, body[i..], '}') orelse {
                    try out.append(alloc, esc);
                    continue;
                };
                const cp = std.fmt.parseUnsigned(u21, body[i..][0..close], 16) catch {
                    try out.append(alloc, esc);
                    continue;
                };
                var buf: [4]u8 = undefined;
                const n = std.unicode.utf8Encode(@intCast(cp & 0x10ffff), &buf) catch {
                    try out.append(alloc, esc);
                    continue;
                };
                try out.appendSlice(alloc, buf[0..n]);
                i += close + 1;
            },
            else => try out.append(alloc, esc),
        }
    }
}

/// Collect one test name from the text starting at the `test` keyword's
/// argument. Handles both `test "name" {` and `test ident {`. Returns null
/// for `test {` (an unnamed discovery block) and `test(...)` (fuzz targets),
/// which no filter can select and which Zig therefore runs unfiltered.
fn parseTestName(
    alloc: std.mem.Allocator,
    arg: []const u8,
) !?[]const u8 {
    const trimmed = std.mem.trimStart(u8, arg, " \t");
    if (trimmed.len == 0) return null;
    if (trimmed[0] == '{') return null;
    if (trimmed[0] == '(') return null;
    if (trimmed[0] == '\"') {
        // Scan to the closing quote, honouring `\` escapes.
        var i: usize = 1;
        while (i < trimmed.len) : (i += 1) {
            if (trimmed[i] == '\\') {
                i += 1;
                continue;
            }
            if (trimmed[i] == '\"') break;
        }
        if (i >= trimmed.len) return null; // unterminated — not a test name
        var name: std.ArrayList(u8) = .empty;
        defer name.deinit(alloc);
        try decodeZigStringBody(alloc, &name, trimmed[1..i]);
        return try alloc.dupe(u8, name.items);
    }
    if (std.ascii.isAlphabetic(trimmed[0]) or trimmed[0] == '_') {
        var i: usize = 0;
        while (i < trimmed.len and (std.ascii.isAlphanumeric(trimmed[i]) or trimmed[i] == '_')) i += 1;
        if (i == 0) return null;
        return try alloc.dupe(u8, trimmed[0..i]);
    }
    return null;
}

/// Walk `src/`, collect every named `test` decl, and return the de-duplicated
/// set of filters to shard across.
///
/// Scanning is deliberately permissive — a `test "..."` inside a comment or a
/// multi-line string becomes a filter that matches nothing, which is inert.
/// It is the misses that matter, and a `test` decl always starts its own line
/// in this codebase (enforced by `zig fmt`), so line-initial matching cannot
/// miss one.
fn collectTestShardEntries(b: *std.Build) []const TestShardEntry {
    const alloc = b.allocator;
    var seen: std.StringHashMap(void) = .init(alloc);
    defer seen.deinit();
    var entries: std.ArrayList(TestShardEntry) = .empty;
    errdefer entries.deinit(alloc);

    var src_dir = std.Io.Dir.cwd().openDir(
        b.graph.io,
        "src",
        .{ .iterate = true },
    ) catch |err| {
        fatalConfig("cannot open src/ to shard the test suite: {s}", .{@errorName(err)});
    };
    defer src_dir.close(b.graph.io);

    var walker = src_dir.walk(alloc) catch |err| {
        fatalConfig("cannot walk src/ to shard the test suite: {s}", .{@errorName(err)});
    };
    defer walker.deinit();

    while (walker.next(b.graph.io) catch |err| {
        fatalConfig("cannot walk src/ to shard the test suite: {s}", .{@errorName(err)});
    }) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;

        // `entry.dir` + `entry.basename`, not cwd + `entry.path`: the
        // walker's paths are relative to the directory it was opened on
        // (`src`), so `entry.path` alone does not resolve from cwd.
        const bytes = entry.dir.readFileAlloc(
            b.graph.io,
            entry.basename,
            alloc,
            .unlimited,
        ) catch continue; // generated / unreadable: nothing to shard from

        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trimStart(u8, raw_line, " \t\r");
            if (!std.mem.startsWith(u8, line, "test")) continue;
            if (line.len == 4) continue; // bare `test`
            if (!std.ascii.isWhitespace(line[4])) continue; // `testing.foo` etc.
            const name = parseTestName(alloc, line[4..]) catch continue orelse continue;
            if (name.len == 0) {
                alloc.free(name);
                continue;
            }
            if (seen.contains(name)) {
                alloc.free(name);
                continue;
            }
            // On success the hash map OWNS `name`, so it must not be freed
            // here — freeing it left a dangling key and the next `put`
            // aborted inside the map.
            seen.put(name, {}) catch {
                alloc.free(name);
                continue;
            };
            const candidates = safeTestFilter(name);
            entries.append(alloc, .{
                // Refined below, once every name is known.
                .filter = candidates.whole orelse candidates.head,
                .weight = testWeight(name),
                .name = name,
                .candidates = candidates,
            }) catch continue;
        }
    }

    const collected = entries.toOwnedSlice(alloc) catch return &.{};

    // Second pass: now that every test name is known, narrow each truncated
    // filter to the side that overlaps the fewest siblings. See
    // `pickLeastOverlappingFilter` for why an over-broad filter is a
    // correctness problem and not just a slow one.
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(alloc);
    for (collected) |entry| names.append(alloc, entry.name) catch return &.{};

    var index = PairIndex.init(alloc, names.items) catch return &.{};
    defer index.deinit();

    for (collected) |*entry| {
        entry.filter = pickLeastOverlappingFilter(entry.candidates, names.items, &index);
    }

    // Guard the thing that actually goes wrong: a filter SO broad that its
    // shard runs a slice of the whole suite.
    //
    // The filter for a name is normally the name. It is shortened only when
    // the name carries a byte the args file cannot carry, and then only to the
    // safe piece before or after it — which can be one character long. A
    // one-character filter is a substring of essentially every test name, so
    // its shard silently re-runs the ENTIRE suite: this exact failure turned
    // a 26 s build into 74 s while staying green, and nothing in the summary
    // said which shard had gone wrong.
    //
    // `head` vs `tail` is chosen by fan-out, but when BOTH sides are that
    // vague there is no better answer to pick, so the only honest response is
    // to stop and name the test. Renaming it to something unique fixes it.
    const max_filter_fanout = 64;
    for (collected) |entry| {
        const fanout = countNamesContaining(names.items, entry.filter, &index);
        if (fanout <= max_filter_fanout) continue;
        fatalConfig(
            "test name {s} reduces to the --test-filter {s}, which is a substring of " ++
                "{d} other test names. That shard would re-run {d} tests it does not " ++
                "own, roughly doubling the suite. Rename the test so that no quoted " ++
                "piece of its name is this short.\n" ++
                "  (guard: max_filter_fanout = {d})",
            .{ entry.name, entry.filter, fanout - 1, fanout - 1, max_filter_fanout },
        );
    }

    // Invariant, checked before anything is scheduled: a test's filter must
    // BE a substring of its own name. `--test-filter` is a substring match,
    // so this single property is what guarantees the test still runs once
    // the suite is split. Asserting it here turns the one failure mode that
    // matters — a test that quietly stops running because someone narrowed
    // the wrong side of a name — into a loud configure-time error naming the
    // test, instead of a green CI run with a hole in it.
    for (collected) |entry| {
        if (std.mem.indexOf(u8, entry.name, entry.filter) != null) continue;
        fatalConfig(
            "internal error: --test-filter {s} is not a substring of test name {s}, " ++
                "so that test would never run under the sharded `test` step.",
            .{ entry.filter, entry.name },
        );
    }

    return collected;
}

/// Group tests whose `--test-filter` would otherwise drag each other into
/// two shards, then longest-processing-time-first across the groups.
///
/// The grouping is what keeps the split safe. A filter is a substring match,
/// so if name A is a substring of name B, then whichever shard holds A's
/// filter also runs B. Assign A and B to different shards and B executes
/// TWICE, CONCURRENTLY — and this suite used to be one sequential process,
/// where two tests sharing a fixture path were safe. Union-find over those
/// containment edges puts both names in the same shard, where the duplicate
/// collapses back into a single run.
fn balanceTestShards(
    b: *std.Build,
    entries: []const TestShardEntry,
    shard_count: usize,
) [][]const []const u8 {
    const alloc = b.allocator;

    const parent: []usize = alloc.alloc(usize, entries.len) catch @panic("OOM");
    defer alloc.free(parent);
    for (parent, 0..) |*slot, i| slot.* = i;

    const find = struct {
        fn f(p: []usize, start: usize) usize {
            var root = start;
            while (p[root] != root) root = p[root];
            // Path compression, so repeated finds stay near-flat.
            var walk = start;
            while (p[walk] != root) {
                const next = p[walk];
                p[walk] = root;
                walk = next;
            }
            return root;
        }
    };
    const merge = struct {
        fn f(p: []usize, a: usize, b_: usize) void {
            const ra = find.f(p, a);
            const rb = find.f(p, b_);
            if (ra == rb) return;
            // Deterministic: the lower index always wins, so two checkouts
            // produce the same grouping.
            if (ra < rb) p[rb] = ra else p[ra] = rb;
        }
    };

    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(alloc);
    for (entries) |entry| names.append(alloc, entry.name) catch @panic("OOM");
    var index = PairIndex.init(alloc, names.items) catch @panic("OOM");
    defer index.deinit();

    // No length cap and no O(filters x names) loop: the inverted index
    // answers "which names could contain this filter" directly, and the exact
    // compare confirms.
    for (entries, 0..) |entry, i| {
        if (entry.filter.len < 2) continue;
        for (index.candidates(index.bestPair(entry.filter))) |name_index| {
            if (name_index == i) continue;
            if (entries[name_index].name.len <= entry.filter.len) continue;
            if (std.mem.indexOf(u8, entries[name_index].name, entry.filter) == null) continue;
            merge.f(parent, i, name_index);
        }
    }

    // Collapse each group into one scheduling unit carrying the sum of its
    // members' weights and all of their filters.
    var group_weight = alloc.alloc(u64, entries.len) catch @panic("OOM");
    defer alloc.free(group_weight);
    @memset(group_weight, 0);
    var group_seen = alloc.alloc(bool, entries.len) catch @panic("OOM");
    defer alloc.free(group_seen);
    @memset(group_seen, false);

    var shards: std.ArrayList(std.ArrayList([]const u8)) = .empty;
    var loads = alloc.alloc(u64, shard_count) catch @panic("OOM");
    defer alloc.free(loads);
    @memset(loads, 0);
    var shard_sizes = alloc.alloc(usize, shard_count) catch @panic("OOM");
    defer alloc.free(shard_sizes);
    @memset(shard_sizes, 0);
    for (0..shard_count) |_| shards.append(alloc, .empty) catch @panic("OOM");

    var roots: std.ArrayList(usize) = .empty;
    defer roots.deinit(alloc);
    for (entries, 0..) |entry, i| {
        group_weight[find.f(parent, i)] += entry.weight;
    }
    for (entries, 0..) |_, i| {
        const root = find.f(parent, i);
        if (group_seen[root]) continue;
        group_seen[root] = true;
        roots.append(alloc, root) catch @panic("OOM");
    }

    // Heaviest group first; the group's first filter name breaks ties so the
    // result is stable even when every weight is the default 1.
    const Ctx = struct {
        entries: []const TestShardEntry,
        group_weight: []const u64,
        fn lessThan(ctx: @This(), a: usize, b_: usize) bool {
            if (ctx.group_weight[a] != ctx.group_weight[b_]) {
                return ctx.group_weight[a] > ctx.group_weight[b_];
            }
            return std.mem.lessThan(u8, ctx.entries[a].filter, ctx.entries[b_].filter);
        }
    };
    std.mem.sort(
        usize,
        roots.items,
        Ctx{ .entries = entries, .group_weight = group_weight },
        Ctx.lessThan,
    );

    for (roots.items) |root| {
        // Lightest by predicted time; ties broken by FEWEST FILTERS so equal
        // -load shards still spread evenly. Picking the first minimum on a
        // tie hands every tie to the lowest index and skews the split.
        var lightest: usize = 0;
        for (loads, shard_sizes, 0..) |load, size, i| {
            if (load > loads[lightest]) continue;
            if (load < loads[lightest]) {
                lightest = i;
                continue;
            }
            if (size < shard_sizes[lightest]) lightest = i;
        }
        loads[lightest] += group_weight[root];
        // `&shards.items[...]`, NOT `shards.items[...]`: std.ArrayList is
        // unmanaged in Zig 0.16, so indexing yields a COPY of the struct and
        // an append through it grows a buffer nobody ever reads back. That
        // silently produced shards of 1, 459 and 1457 filters instead of 8
        // equal ones, while still "working" (green) because the union of the
        // filters never changed.
        const shard = &shards.items[lightest];
        // Every member's filter goes into the group's shard. The group's
        // tests all match at least the filter that created the edge, but
        // keeping each member's own filter means a group can never lose a
        // test if the containment relationship is ever refined away.
        for (entries, 0..) |entry, i| {
            if (find.f(parent, i) != root) continue;
            shard.append(alloc, entry.filter) catch @panic("OOM");
            shard_sizes[lightest] += 1;
        }
    }

    const out: [][]const []const u8 = alloc.alloc([]const []const u8, shard_count) catch @panic("OOM");
    for (shards.items, out) |shard, *slot| slot.* = shard.items;
    return out;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Path to the vendored curl directory, relative to this
    // package's build.zig. Default is `vendor/curl/` co-located with
    // this build.zig (the package owns its own vendor dir — the
    // build script at scripts/build-vendor-curl.sh populates it).
    // Override with `-Dvendor-dir=...` if you move it elsewhere.
    const vendor_dir = b.option(
        []const u8,
        "vendor-dir",
        "Path to vendor/curl/ (relative to this package, default 'vendor/curl')",
    ) orelse "vendor/curl";

    // Force-use vendor (skip the system probe). Useful for CI runners
    // that have system libs but want a hermetic build, or for testing
    // the vendored path. Default: false (probe decides).
    const force_vendor = b.option(
        bool,
        "force-vendor",
        "Skip the system probe and always use the vendored libcurl archive",
    ) orelse false;

    // Test filter (substring match on the test name). Zig 0.16's test
    // runner no longer parses `--test-filter` on its own command line
    // (it only accepts `--listen=-` / `--seed=` / `--cache-dir=`), so the
    // old `zig build test -- --test-filter=...` passthrough below aborts
    // the runner with "unrecognized command line argument". The build
    // step applies the filter over the `--listen=-` protocol instead:
    //   zig build test -Dtest-filter=hijacks
    const test_filter: []const u8 = b.option(
        []const u8,
        "test-filter",
        "Only run tests whose name contains this substring (localizes a hang)",
    ) orelse "";
    const test_filters: []const []const u8 = if (test_filter.len > 0)
        &.{test_filter}
    else
        &.{};

    // Debian/Ubuntu multiarch: headers AND libs can live under
    // /usr/include/<triplet>/ + /usr/lib/<triplet>/ instead of the
    // plain dirs. Resolve the triplet present on this host (at most
    // one will be) so the link/include wiring below can add it.
    // Gated on existence — passing a nonexistent -L dir is a hard
    // error, not a no-op.
    const multiarch_triplet: ?[]const u8 = if (fileExists("/usr/lib/x86_64-linux-gnu/libcurl.so") or
        fileExists("/usr/include/x86_64-linux-gnu/curl/curl.h"))
        "x86_64-linux-gnu"
    else if (fileExists("/usr/lib/aarch64-linux-gnu/libcurl.so") or
        fileExists("/usr/include/aarch64-linux-gnu/curl/curl.h"))
        "aarch64-linux-gnu"
    else
        null;
    const multiarch_lib_dir: ?[]const u8 = if (multiarch_triplet) |t|
        b.fmt("/usr/lib/{s}", .{t})
    else
        null;
    const multiarch_include_dir: ?[]const u8 = if (multiarch_triplet) |t|
        b.fmt("/usr/include/{s}", .{t})
    else
        null;

    const mod = b.addModule("kabelweb", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Tests are colocated with the implementation: every `src/**/*.zig`
    // file carries its own `test { ... }` blocks (the former `*_test.zig`
    // files were merged into them and deleted), and `src/root.zig` imports
    // each test-owning file in its `test {}` block so the runner can reach
    // them.
    //
    // All four test steps compile that same root and differ only in the
    // test-name filter + environment (see the step wiring below):
    //   test        → everything, incl. the 2×60 s SSE soaks (KABELWEB_SOAK=1)
    //   test-fast   → everything except the soaks (they self-skip)
    //   test-server → `server.` prefixed test names only
    //   test-client → `client.` prefixed test names only
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.linkSystemLibrary("c", .{});
    test_mod.link_libc = true;

    const fast_test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    fast_test_mod.linkSystemLibrary("c", .{});
    fast_test_mod.link_libc = true;

    const server_test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_test_mod.linkSystemLibrary("c", .{});
    server_test_mod.link_libc = true;
    const client_test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_test_mod.linkSystemLibrary("c", .{});
    client_test_mod.link_libc = true;

    // The server demo is an executable root that consumes the lib through
    // `@import("kabelweb")`, so the lib test root cannot pull its tests in
    // (a named self-import would be a module cycle) — it gets its own test
    // module + `test-demo` wiring below. Its tests are the static-contract
    // checks on the landing page HTML.
    const demo_test_mod = b.createModule(.{
        .root_source_file = b.path("src/examples/server_demo.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "kabelweb", .module = mod },
        },
    });
    demo_test_mod.linkSystemLibrary("c", .{});
    demo_test_mod.link_libc = true;

    // Example binaries (living docs — see src/examples/). The server
    // demo serves the landing page + SSE/WS/template routes; the client
    // smoke CLI fires one request. Both consume the lib via
    // `@import("kabelweb")` (same as any external user) and join the
    // link wiring loop below.
    const server_demo_exe = b.addExecutable(.{
        .name = "kabelweb-server-demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/examples/server_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "kabelweb", .module = mod },
            },
        }),
    });
    server_demo_exe.root_module.link_libc = true;
    b.installArtifact(server_demo_exe);
    const client_smoke_exe = b.addExecutable(.{
        .name = "kabelweb-client-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/examples/client_smoke.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "kabelweb", .module = mod },
            },
        }),
    });
    client_smoke_exe.root_module.link_libc = true;
    b.installArtifact(client_smoke_exe);

    const run_step = b.step("run", "Run the kabelweb server demo");
    const run_cmd = b.addRunArtifact(server_demo_exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Universal: libc is required by every libcurl binding + cimport.
    mod.linkSystemLibrary("c", .{});
    mod.link_libc = true;

    // Probe host system for libcurl + openssl. When the probe finds
    // usable system libs (typical Arch / Debian / Fedora dev hosts),
    // link the system libs and skip the vendored archive entirely.
    // Otherwise fall back to the vendored fat archive (curl + ssl +
    // crypto merged into one .a).
    const sys = if (force_vendor) SystemLibs{
        .use_system = false,
        .found_curl = false,
        .found_ssl = false,
        .found_crypto = false,
    } else probeSystemLibs(b, target);

    // Lib wiring applies to ALL modules (lib + both test modules +
    // both example exes). The test binaries compile the same server +
    // client sources, so they need the same include paths + link line;
    // the exes need it too.
    // Second iteration skips the Windows stub generation via the
    // fileExists check (first iteration already wrote the archive).
    for ([_]*std.Build.Module{ mod, test_mod, fast_test_mod, server_test_mod, client_test_mod, demo_test_mod, server_demo_exe.root_module, client_smoke_exe.root_module }) |m| {
        if (sys.use_system) {
            // System libs path. `linkSystemLibrary("curl")` does NOT auto-
            // pull libssl/libcrypto (no pkg-config Requires honour), so we
            // link them explicitly. The cimport for `curl/curl.h` needs
            // `/usr/include` on the include path on Linux (Debian/Ubuntu
            // put curl.h at `/usr/include/curl/curl.h` and the cimport does
            // `#include <curl/curl.h>`, so /usr/include must be on the
            // search path). Most distros add /usr/include by default, but
            // some configurations (e.g. cross-compile toolchains) don't —
            // add it explicitly so the cimport works everywhere.
            //
            // On macOS, the probe only returns `use_system=true` when both
            // /opt/homebrew/opt/curl/include/curl/curl.h AND
            // /opt/homebrew/opt/openssl@3/include/openssl/ssl.h exist.
            // We mirror those paths here so the cimport resolves
            // <curl/curl.h> and <openssl/ssl.h> regardless of which
            // include-path probe happens to win the search.
            switch (target.result.os.tag) {
                .linux => {
                    m.addIncludePath(.{ .cwd_relative = "/usr/include" });
                    // Library search path. Without this, Zig 0.16's
                    // `linkSystemLibrary("curl"/"ssl"/"crypto")` calls
                    // below fail with
                    //   "unable to find dynamic system library 'curl'
                    //    using strategy 'paths_first'.
                    //    searched paths: none"
                    // because the glibc 2.38+ default target's link search
                    // path doesn't include /usr/lib for some Compile steps
                    // (cli tests, package tests) — even though it works for
                    // the main exe via the root build.zig's
                    // `linkPlatformDeps`. Mirrors the macOS branch below.
                    // The multiarch dirs cover Debian/Ubuntu, whose
                    // headers + linker symlinks live under
                    // /usr/<include|lib>/<triplet>/ (resolved above; null
                    // elsewhere).
                    m.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
                    if (multiarch_lib_dir) |dir| {
                        m.addLibraryPath(.{ .cwd_relative = dir });
                    }
                    if (multiarch_include_dir) |dir| {
                        m.addIncludePath(.{ .cwd_relative = dir });
                    }
                },
                .macos => {
                    // Probe uses an OR-of-paths predicate, but link only
                    // succeeds against the path that actually has the .dylib.
                    // /opt/homebrew/opt/curl/include and
                    // /opt/homebrew/opt/openssl@3/include are the canonical
                    // keg-only Homebrew paths on Apple Silicon.
                    m.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/curl/include" });
                    m.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
                    // Library search paths so linkSystemLibrary can find
                    // the .dylib (it's keg-only — not on the default search
                    // path). The /usr/lib fallback covers system-wide installs.
                    m.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/curl/lib" });
                    m.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
                    m.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
                },
                .windows => {
                    // vcpkg at `C:/vcpkg/installed/x64-windows/`. Both the
                    // include and lib subdirs are added explicitly because
                    // the cimport in src/curl.zig resolves <curl/curl.h>
                    // and the linker needs to find the .lib files at link
                    // time. The `\` → `/` translation is fine on Windows
                    // since the NTFS layer accepts both separators — Zig's
                    // path-handler routes them through the same kernel
                    // APIs.
                    //
                    // Use addObjectFile (not linkSystemLibrary) to bypass
                    // the GNU-vs-MSVC lib-name convention mismatch: the
                    // build target is `x86_64-windows-gnu` (GNU toolchain
                    // conventions — `libcurl.a`), but vcpkg ships
                    // `libcurl.lib` (MSVC-style extension, GCC-style name).
                    // Explicit object-file links work with either naming
                    // — the linker doesn't try to translate `-lcurl` →
                    // `libcurl.{a,lib}` it just adds the file the build.zig
                    // hands it.
                    m.addIncludePath(.{ .cwd_relative = "C:/vcpkg/installed/x64-windows/include" });
                    m.addObjectFile(.{ .cwd_relative = "C:/vcpkg/installed/x64-windows/lib/libcurl.lib" });
                    m.addObjectFile(.{ .cwd_relative = "C:/vcpkg/installed/x64-windows/lib/libssl.lib" });
                    m.addObjectFile(.{ .cwd_relative = "C:/vcpkg/installed/x64-windows/lib/libcrypto.lib" });
                },
                else => {
                    m.addIncludePath(.{ .cwd_relative = "/usr/include" });
                },
            }
            // addObjectFile above replaces these linkSystemLibrary calls
            // on Windows (where the vcpkg lib-file naming doesn't match
            // the GNU `libfoo.a` convention). On Linux + macOS the
            // linkSystemLibrary calls below work because the system libs
            // are at `/usr/lib/libfoo.so.<n>` / `/opt/homebrew/opt/...`/
            // `libfoo.dylib`, which IS the convention `linkSystemLibrary`
            // looks for on those platforms.
            if (target.result.os.tag != .windows) {
                m.linkSystemLibrary("curl", .{});
                m.linkSystemLibrary("ssl", .{});
                m.linkSystemLibrary("crypto", .{});
            }
        } else {
            // Vendored path. Add the per-target include path + embed the
            // prebuilt archive as an object file.
            const target_subdir = switch (target.result.os.tag) {
                .linux => b.fmt("linux-{s}", .{switch (target.result.cpu.arch) {
                    .x86_64 => "x86_64",
                    .aarch64 => "aarch64",
                    else => @panic("vendored curl: unsupported Linux arch"),
                }}),
                .macos => switch (target.result.cpu.arch) {
                    .aarch64 => "macos-arm64",
                    .x86_64 => "macos-x86_64",
                    else => @panic("vendored curl: unsupported macOS arch"),
                },
                .windows => "windows-amd64", // script doesn't build yet — see note
                else => @panic("vendored curl: unsupported OS"),
            };
            const target_dir = b.fmt("{s}/{s}", .{ vendor_dir, target_subdir });

            // Header path — needed by `@cImport(@cInclude("curl/curl.h"))`
            // inside src/curl.zig. The header is portable C, so the same
            // vendored copy works for every host (Zig's cimport uses the
            // HOST C compiler, not the cross-target compiler).
            m.addIncludePath(b.path(b.fmt("{s}/include", .{target_dir})));

            // Link the prebuilt vendored archive directly into every consumer.
            // addObjectFile embeds the .a symbols in the consumer's link line
            // (no separate -L/-l needed — Zig's linker resolves the archive's
            // undefined symbols at consumer link time).
            //
            // The archive is a FAT build: curl + libssl + libcrypto objects
            // merged in one .a (see scripts/build-vendor-curl.sh). So we
            // do NOT also link ssl/crypto — they're already in the archive.
            const libcurl_a = b.path(b.fmt("{s}/lib/libcurl.a", .{target_dir}));

            // WINDOWS-DEV-BOX STUB PATH:
            //
            // `build-vendor-curl.sh` intentionally never builds a Windows
            // archive (it only cross-compiles Linux + macOS targets; the
            // Windows script section is a no-op with an informative message
            // — see the script's `case "$(uname -s)"` Windows-host arm).
            // On a Windows host without vcpkg libcurl + openssl installed,
            // there's no `vendor/curl/windows-amd64/lib/libcurl.a` AND no
            // header at `vendor/curl/windows-amd64/include/curl/curl.h`,
            // which causes two failures during `zig build test`:
            //
            //   1. `src/modules/agent/Agent.zig` transitively pulls in
            //      kabelweb (via the test runner imports), so
            //      the test compile includes kabelweb's client sources.
            //      kabelweb `src/client/curl.zig` does
            //      `@cImport(@cInclude("curl/curl.h"))` — without the
            //      header, the cimport fails with "file not found".
            //   2. The test compile's link line references the missing
            //      `libcurl.a` via `addObjectFile`, which fails with
            //      "file not found" at link-line construction time.
            //
            // The fix: when the vendored archive is missing on Windows,
            // generate a STUB archive + STUB header from the sources in
            // `scripts/stub_libcurl.{h,c}`. The stub functions are empty
            // no-ops (curl_easy_init returns NULL, curl_easy_perform
            // returns CURLE_FAILED_INIT) — enough to satisfy the linker +
            // cimport without providing real network capability. Tests that
            // merely construct a kabelweb `Client` and never fire
            // a request pass; tests that actually call .get/.post/.stream
            // fail at runtime with a clear InitFailed error from the stub
            // (visible in `zig build test` output).
            //
            // This stub path is Windows-only (Linux + macOS still require
            // the real archive or system libcurl). To get a real libcurl
            // on Windows: install vcpkg (`vcpkg install curl:x64-windows
            // openssl:x64-windows`) — the system probe above takes over
            // and the stub is bypassed entirely.
            if (target.result.os.tag == .windows and !fileExists(b.fmt("{s}/lib/libcurl.a", .{target_dir}))) {
                generateStubLibcurlWindows(b, target_dir);
                // After the stub is generated, addObjectFile points at
                // the now-existing file. (The compile step's file existence
                // check is lazy — addObjectFile records the path; the actual
                // check happens at link-line construction time.)
            }
            m.addObjectFile(libcurl_a);
        }
    }

    // === Tests for the package itself ===
    // `b.addTest({ .root_module = test_mod })` runs the full entry
    // (src/root.zig): fast suites + the 60 s SSE soaks. Both test
    // modules carry link_libc + (system or vendored) curl/ssl/crypto
    // (wired above), so the TLS + in-process-server suites link and
    // resolve cleanly. On
    // Linux the system libssl/libcrypto live in /usr/lib, which Zig does
    // not add by default for some Compile steps.
    for ([_]*std.Build.Module{ test_mod, fast_test_mod, server_test_mod, client_test_mod, demo_test_mod }) |tm| {
        if (target.result.os.tag == .linux and sys.use_system) {
            tm.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
            if (multiarch_lib_dir) |dir| {
                tm.addLibraryPath(.{ .cwd_relative = dir });
            }
            if (multiarch_include_dir) |dir| {
                tm.addIncludePath(.{ .cwd_relative = dir });
            }
        }
    }

    // ── Sharded `test` step ────────────────────────────────────────────
    //
    // The full `test` step was 402 s on a 16-core box: ~8 s of compile and
    // ~390 s of ONE test binary running its 791 tests strictly in sequence
    // inside a single process. No amount of `-j` touches that 390 s — the
    // parallelism has to come from SEPARATE test binaries.
    //
    // So the same test set is split at CONFIGURE time into N shards, each
    // its own `b.addTest` compile carrying a `--test-filter` subset, and
    // `zig build`'s own step scheduler compiles and runs them concurrently.
    // See the "Sharded test execution" block above for why filters (not
    // separate modules) and why the shard membership is scanned from the
    // sources rather than hand-listed.
    //
    // Default is half the core count, capped at 8: each shard is its own
    // `zig test` compile peaking around 500 MB RSS, so an unconstrained
    // `-j` on a big workstation would OOM rather than get faster. Pass
    // `-Dtest-shards=1` for the old single-binary behaviour.
    //
    // An explicit `-Dtest-filter=…` disables sharding entirely: the user
    // asked for one specific subset, so it goes through one unfiltered
    // compile exactly as before.
    const host_cpus = std.Thread.getCpuCount() catch 4;
    const default_shards: usize = @max(1, @min(8, host_cpus / 2));
    const shard_count = b.option(
        usize,
        "test-shards",
        "Number of parallel shards for `zig build test` (default: min(8, cpus/2); 1 = single binary, legacy behaviour)",
    ) orelse default_shards;

    const shard_entries = if (test_filter.len > 0)
        &[_]TestShardEntry{}
    else
        collectTestShardEntries(b);
    // One shard means "no filters at all": pass the whole suite through a
    // single unfiltered compile, which is both faster (one compile) and the
    // exact legacy behaviour. Filtering by name would only slow it down.
    const use_filters = shard_count > 1 and shard_entries.len > 0;
    const shards = if (use_filters)
        balanceTestShards(b, shard_entries, shard_count)
    else
        &[_][]const []const u8{};

    if (shard_entries.len > 0) {
        std.debug.print(
            "[test] mod_tests split into {d} shard(s) from {d} scanned test names " ++
                "(`zig build test:shard:<i>` runs one)\n",
            .{ if (use_filters) shard_count else @as(usize, 1), shard_entries.len },
        );
    }

    const test_step = b.step("test", "Run kabelweb package tests (fast suites + 60s SSE soaks)");

    for (shards, 0..) |filters, i| {
        const shard_tests = b.addTest(.{
            .root_module = test_mod,
            .filters = filters,
        });
        const run_shard = b.addRunArtifact(shard_tests);
        // The 2×60 s SSE soaks live in `server/sse_manager.zig` and self-skip
        // (`error.SkipZigTest`) unless KABELWEB_SOAK is set — every shard of
        // the full `test` step gets it, so the soaks still run exactly once
        // (they are in the weight table, so the balancer gives them their own
        // shard rather than piling them onto one).
        run_shard.setEnvironmentVariable("KABELWEB_SOAK", "1");
        test_step.dependOn(&run_shard.step);
        // Per-shard step so a failure — or a re-measure for
        // `slow_test_weights` above — can be reproduced in isolation.
        const shard_label = b.fmt("test:shard:{d}", .{i});
        b.step(
            shard_label,
            b.fmt("Run shard {d}/{d} of the kabelweb test suite ({d} tests)", .{ i + 1, shards.len, filters.len }),
        ).dependOn(&run_shard.step);
    }

    if (!use_filters) {
        const mod_tests = b.addTest(.{ .root_module = test_mod, .filters = test_filters });
        const run_mod_tests = b.addRunArtifact(mod_tests);
        run_mod_tests.setEnvironmentVariable("KABELWEB_SOAK", "1");
        test_step.dependOn(&run_mod_tests.step);
    }
    test_step.dependOn(b.getInstallStep());

    // Fast suites only (no 60 s soaks) — what CI runs on every
    // platform. The soaks are timing-sensitive; they run in the
    // full `test` step (ubuntu job) instead of blocking mac/Windows.
    //
    // Sharded the same way as `test` above: the fast set was 174 s of one
    // sequential binary, and it is the step CI runs on every push.
    const fast_shards = if (test_filter.len > 0 or shard_count <= 1)
        &[_][]const []const u8{}
    else
        balanceTestShards(b, shard_entries, shard_count);
    const fast_use_filters = fast_shards.len > 1;

    const test_fast_step = b.step("test-fast", "Run kabelweb fast suites (no 60s SSE soaks)");
    for (fast_shards, 0..) |filters, i| {
        const shard_tests = b.addTest(.{
            .root_module = fast_test_mod,
            .filters = filters,
        });
        const run_shard = b.addRunArtifact(shard_tests);
        test_fast_step.dependOn(&run_shard.step);
        const shard_label = b.fmt("test-fast:shard:{d}", .{i});
        b.step(
            shard_label,
            b.fmt("Run shard {d}/{d} of the kabelweb fast suite ({d} tests)", .{ i + 1, fast_shards.len, filters.len }),
        ).dependOn(&run_shard.step);
    }
    if (!fast_use_filters) {
        const fast_tests = b.addTest(.{ .root_module = fast_test_mod, .filters = test_filters });
        const run_fast_tests = b.addRunArtifact(fast_tests);
        test_fast_step.dependOn(&run_fast_tests.step);
    }
    test_fast_step.dependOn(b.getInstallStep());

    // Split halves of the fast set (server-only / client-only) — CI runs
    // these separately so a hanging suite is localized to one half instead of
    // stalling the whole binary with zero output. The halves are selected by
    // test-name prefix: with the root module rooted at `src/root.zig`, a test
    // name starts with the module-relative file path (`server.…` /
    // `client.…`). An explicit `-Dtest-filter=…` still wins.
    const server_filters: []const []const u8 = if (test_filter.len > 0) test_filters else &.{"server."};
    const server_tests = b.addTest(.{ .root_module = server_test_mod, .filters = server_filters });
    const run_server_tests = b.addRunArtifact(server_tests);
    const test_server_step = b.step("test-server", "Run kabelweb server suites only (no soaks)");
    test_server_step.dependOn(&run_server_tests.step);
    test_server_step.dependOn(b.getInstallStep());
    const client_filters: []const []const u8 = if (test_filter.len > 0) test_filters else &.{"client."};
    const client_tests = b.addTest(.{ .root_module = client_test_mod, .filters = client_filters });
    const run_client_tests = b.addRunArtifact(client_tests);
    const test_client_step = b.step("test-client", "Run kabelweb client suites only");
    test_client_step.dependOn(&run_client_tests.step);
    test_client_step.dependOn(b.getInstallStep());

    // Demo (executable root) tests — the landing-page static-contract checks
    // that live in `src/examples/server_demo.zig`. They are fast file-grep
    // assertions, so they join both the full and the fast gates.
    const demo_tests = b.addTest(.{ .root_module = demo_test_mod, .filters = test_filters });
    const run_demo_tests = b.addRunArtifact(demo_tests);
    const test_demo_step = b.step("test-demo", "Run the server-demo (example) tests only");
    test_demo_step.dependOn(&run_demo_tests.step);
    test_demo_step.dependOn(b.getInstallStep());
    test_step.dependOn(&run_demo_tests.step);
    test_fast_step.dependOn(&run_demo_tests.step);
}
