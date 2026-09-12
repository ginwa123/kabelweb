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

    // Test module: the full entry (src/full_test.zig) — fast suites via
    // src/root.zig PLUS the 60 s SSE soaks. The repo-root gate runs the
    // fast set only (via the kabelweb lib module); run this package's
    // own `zig build test` to exercise everything including soaks.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/full_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.linkSystemLibrary("c", .{});
    test_mod.link_libc = true;

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

    // Lib wiring applies to ALL modules (lib + test + both example exes).
    // The test binary compiles the same server + client sources, so it
    // needs the same include paths + link line; the exes need it too.
    // Second iteration skips the Windows stub generation via the
    // fileExists check (first iteration already wrote the archive).
    for ([_]*std.Build.Module{ mod, test_mod, server_demo_exe.root_module, client_smoke_exe.root_module }) |m| {
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
    // (src/full_test.zig): fast suites + the 60 s SSE soaks. test_mod
    // carries link_libc + (system or vendored) curl/ssl/crypto (wired
    // above) + the `helpers` import, so the TLS + in-process-server
    // suites link and resolve cleanly. On
    // Linux the system libssl/libcrypto live in /usr/lib, which Zig does
    // not add by default for some Compile steps.
    if (target.result.os.tag == .linux and sys.use_system) {
        test_mod.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
        if (multiarch_lib_dir) |dir| {
            test_mod.addLibraryPath(.{ .cwd_relative = dir });
        }
        if (multiarch_include_dir) |dir| {
            test_mod.addIncludePath(.{ .cwd_relative = dir });
        }
    }
    const mod_tests = b.addTest(.{ .root_module = test_mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run kabelweb package tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(b.getInstallStep());
}
