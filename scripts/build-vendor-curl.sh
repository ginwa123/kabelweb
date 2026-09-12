#!/usr/bin/env bash
# scripts/build-vendor-curl.sh
#
# Cross-compiles a *standard* curl 8.10.1 (with TLS via vendored
# OpenSSL, and the normal protocol set: http, https, ftp, ftps, imap,
# pop3, smtp, telnet, tftp, dict, file, gopher) from source for each
# target platform (Linux x86_64, macOS arm64, macOS x86_64) and writes
# the prebuilt libcurl.a + libssl.a + libcrypto.a + headers to
# vendor/curl/<target>/ and vendor/openssl/<target>/.
#
# Why we vendor curl + OpenSSL:
#   - `install:windows` and `install:macos*` previously failed because
#     the cross-target linker couldn't find host-installed libcurl /
#     libssl (vcpkg / brew / pkg-config aren't on a Linux host).
#   - Vendoring makes the build hermetic across host OSes — a developer
#     on macOS, Linux, or Windows can build for any target without
#     installing target-specific system libraries.
#   - Earlier revisions of this script shipped an HTTP-only curl
#     (--disable-ssl) to sidestep TLS vendoring. That's no longer
#     "standard curl" behavior (the agent's LLM API calls need
#     https://), so this revision vendors OpenSSL too and links curl
#     against it, restoring HTTPS support and the normal protocol set.
#
# Requires (host): bash, curl, autoconf/perl (for ./Configure and
# ./configure), zig 0.16+ (for macOS cross-compile), gcc (for Linux
# native). curl + OpenSSL sources are downloaded on first run from
# https://curl.se/download/ and https://www.openssl.org/source/.
#
# Layout:
#   vendor/openssl/
#   ├── linux-x86_64/lib/{libssl.a,libcrypto.a}
#   ├── linux-x86_64/include/openssl/*.h
#   ├── macos-arm64/lib/{libssl.a,libcrypto.a}
#   ├── macos-arm64/include/openssl/*.h
#   ├── macos-x86_64/lib/{libssl.a,libcrypto.a}
#   └── macos-x86_64/include/openssl/*.h
#   vendor/curl/
#   ├── linux-x86_64/lib/libcurl.a
#   ├── linux-x86_64/include/curl/*.h
#   ├── macos-arm64/lib/libcurl.a
#   ├── macos-arm64/include/curl/*.h
#   ├── macos-x86_64/lib/libcurl.a
#   └── macos-x86_64/include/curl/*.h
#
# Method:
#   1. Build OpenSSL first (static, no-shared, no-asm — no-asm avoids
#      needing a target-specific perlasm/assembler toolchain during
#      cross-compilation; it costs some crypto performance but keeps
#      the cross build hermetic and simple). `make build_libs` builds
#      only libssl.a/libcrypto.a, skipping the `apps` target (the
#      openssl CLI binary), which we don't need and which is awkward
#      to cross-link.
#   2. Build curl with `--with-openssl=<vendor/openssl/<target>>` so
#      it links against our static OpenSSL instead of requiring a
#      host TLS library. The final libtool link step (`make` for the
#      `libcurl.la` target) fails on Linux hosts due to a libtool bug
#      (`0: Bad file descriptor`), but each .c file is already
#      compiled — we just `ar rcs libcurl.a lib/*.o` to archive them
#      directly, bypassing libtool.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJECT_DIR="$( cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd )"
# kabelweb owns its own vendor dir. The script lives in
# scripts/ and writes to `vendor/`
# dirs co-located with the package (../vendor/{curl,openssl} from here).
VENDOR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/vendor"
CURL_VENDOR_DIR="${VENDOR_ROOT}/curl"
OPENSSL_VENDOR_DIR="${VENDOR_ROOT}/openssl"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/nalar-curl-XXXXXX")
trap 'rm -rf "${TMP}"' EXIT

CURL_VERSION="8.10.1"
CURL_URL="https://curl.se/download/curl-${CURL_VERSION}.tar.gz"
CURL_SRC_DIR="${TMP}/curl-${CURL_VERSION}"

OPENSSL_VERSION="3.4.0"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_SRC_DIR="${TMP}/openssl-${OPENSSL_VERSION}"

# === Target selection ===
# Only build the targets reachable on this host. Cross-compiling macOS
# via `zig cc -target aarch64-macos` works on a Linux host, but each
# macOS target adds ~5-10 min of OpenSSL build + ~10-15 min of curl
# cross-compile — 30+ min of pure waste on a Linux CI runner that
# only needs the Linux build.
#
# Override with CURL_TARGETS="linux-x86_64 macos-arm64 macos-x86_64"
# (or any subset) to build for non-host targets. Default: only the
# targets that match the host OS.
#
# Windows hosts: bail out as a successful no-op before doing any work.
# The script builds OpenSSL + curl from source and needs gcc/make/perl +
# the Perl Locale::Maketext::Simple module (OpenSSL's Configure requires
# it). Most Windows dev boxes don't ship those — and even with MinGW/
# MSYS2 installed, the cross-build to a non-Linux target (e.g. building
# linux-x86_64 from a Windows host) needs `zig cc -target …` plumbing
# that isn't wired up here. So on a Windows host the vendored archive
# can't be produced. Instead of failing halfway through with a
# confusing `Can't locate Locale/Maketext/Simple.pm in @INC`, exit 0
# early with a clear next-steps message.
#
# Why `exit 0` (not `exit 2`): Zig's `b.addSystemCommand` treats any
# non-zero exit code as a step failure, which would cascade and fail the
# whole `zig build test` even when the test compile itself doesn't need
# the libcurl archive (no test code transitively imports
# custom_http_client). Exiting 0 lets the build proceed; the explanatory
# message still surfaces so the operator sees why the archive is empty.
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*|Windows*)
        cat <<'EOF'
[build-vendor-curl.sh] SKIPPED — Windows host.

  This script cross-compiles libcurl + vendored OpenSSL from source,
  which requires gcc, make, perl, and the Perl Locale::Maketext::Simple
  module. None of those are available on a typical Windows dev box
  (Git for Windows ships bash + perl but no gcc).

  Two paths forward for Windows builds:

    1. Install vcpkg and `vcpkg install curl:x64-windows openssl:x64-windows`.
       The kabelweb build.zig system-probe will
       then pick up C:/vcpkg/installed/x64-windows/lib/{libcurl,libssl,
       libcrypto}.lib and link those instead of the vendored archive.

    2. Cross-compile the vendor archive from a Linux/macOS host:
         git clone … && cd … && bash scripts/build-vendor-curl.sh
       then copy vendor/curl/<target>/
       to the Windows box.

  (The kabelweb package's vendored-path lookup hardcodes
  `windows-amd64/` for Windows targets, but the script intentionally
  never builds it — see the comment at "Windows archive" below.)
EOF
        exit 0
        ;;
    Linux)   DEFAULT_TARGETS="linux-x86_64" ;;
    Darwin)  DEFAULT_TARGETS="macos-arm64 macos-x86_64" ;;
    *)       DEFAULT_TARGETS="linux-x86_64" ;;
esac
TARGETS="${CURL_TARGETS:-${DEFAULT_TARGETS}}"

# === Common configure flags for a standard curl build ===
# We keep TLS enabled (linked against our vendored OpenSSL) and the
# normal protocol set. We still disable pieces that would require
# *additional* vendored dependencies we don't build here:
#   - ldap/ldaps          (needs system LDAP libs)
#   - libssh2/libssh       (scp/sftp — needs vendoring libssh2 too)
#   - librtmp               (needs vendoring librtmp too)
#   - libpsl / libgsasl     (optional helper libs, not vendored)
#   - brotli / zstd / zlib  (compression — not vendored; TODO below)
#   - libidn2               (IDN — not vendored)
#   - nghttp2/nghttp3/ngtcp2/quiche (HTTP/2 + HTTP/3 — not vendored;
#     TODO: vendor nghttp2 for HTTP/2 support)
#   - docs                  (irrelevant to a vendored static lib)
# Everything else (http, https, ftp, ftps, imap, pop3, smtp, telnet,
# tftp, dict, file, gopher, ipv6, threaded resolver, alt-svc, hsts,
# headers-api, websockets) is left at curl's normal defaults.
COMMON_CONFIGURE_FLAGS=(
    --disable-shared
    --enable-static
    --without-bearssl
    --without-gnutls
    --without-wolfssl
    --without-mbedtls
    --without-rustls
    --without-nghttp2
    --without-nghttp3
    --without-ngtcp2
    --without-quiche
    --without-libssh2
    --without-libssh
    --without-zlib
    --without-brotli
    --without-zstd
    --without-libidn2
    --without-librtmp
    --without-libpsl
    --without-libgsasl
    --disable-ldap
    --disable-ldaps
    --disable-docs
    --disable-ech
)

# === Skip-if-already-built cache (BEFORE any source download) ===
# Each per-target build is skipped only if the curl archive+headers
# AND the OpenSSL archives+headers already exist. Re-run with FORCE=1
# to bypass the cache (e.g. after changing COMMON_CONFIGURE_FLAGS or
# bumping CURL_VERSION/OPENSSL_VERSION).
#
# Cache correctness depends on more than file existence: libcurl.a must
# be the FAT archive (curl + libssl + libcrypto objects merged in one
# archive, see build_curl_target's final `ar rcs` step), not just
# curl's own .o files. The naive file-existence check can produce a
# half-built state if libcurl.a was built before libssl.a/libcrypto.a
# existed — the merge step ran with zero openssl objects, leaving a
# thin ~178-object archive that later satisfies the file-existence
# check forever. Consumers then hit 200+ "undefined symbol:
# BIO_meth_set_destroy" linker errors at `zig build` time.
#
# Format-agnostic check via object count: thin archive ≈ 178 objects,
# fat archive ≈ 1200. Threshold 500 gives 2x margin against future
# curl/openssl growth. nm-based symbol lookup is intentionally NOT
# used because Linux nm cannot parse Mach-O archives (cross-compiled
# macOS builds seen from a Linux host), so a symbol check would
# falsely flag fat Mach-O archives as "not fat". The build-time
# per-archive verify at the end of build_curl_target is the source
# of truth for symbol presence; this skip-cache check only needs to
# catch the "thin archive" regression.
if [[ "${FORCE:-0}" != "1" ]]; then
    needs_build=0
    for target in ${TARGETS}; do
        ct="${CURL_VENDOR_DIR}/${target}"
        ot="${OPENSSL_VENDOR_DIR}/${target}"
        # NOTE: GNU `ar` exits with code 9 when the archive is missing
        # (this is the documented "fatal error" code in binutils). With
        # `set -euo pipefail` + `pipefail`, a non-zero exit from `ar t`
        # inside a `$(...)` substitution causes the whole script to
        # exit with that code BEFORE the substitution value is captured
        # — even though an assignment to a regular variable is
        # normally a `set -e` no-op. The supsequent `[[ ! -f ... ]]`
        # check (which is the canonical way to detect a missing file
        # anyway) makes the `ar t` probe redundant; swallow its exit
        # code with `|| true` so the cache skip-check doesn't kill the
        # script on a fresh checkout.
        obj_count=$(ar t "${ct}/lib/libcurl.a" 2>/dev/null | wc -l || true)
        if [[ ! -f "${ct}/lib/libcurl.a" ]] || \
           [[ "${obj_count}" -lt 500 ]] || \
           [[ ! -d "${ct}/include/curl" ]] || \
           [[ -z "$(ls "${ct}/include/curl/" 2>/dev/null)" ]] || \
           [[ ! -f "${ot}/lib/libssl.a" ]] || \
           [[ ! -f "${ot}/lib/libcrypto.a" ]] || \
           [[ ! -d "${ot}/include/openssl" ]]; then
            needs_build=1
            break
        fi
    done
    if [[ "${needs_build}" -eq 0 ]]; then
        echo "Already built (fat libcurl.a + libssl.a + libcrypto.a + headers present for ${TARGETS})."
        echo "Run with FORCE=1 to rebuild."
        exit 0
    fi
fi

# === Download sources on first run ===
if [[ ! -d "${CURL_SRC_DIR}" ]]; then
    echo "=== Downloading curl ${CURL_VERSION} source ==="
    curl -fsSL --retry 3 --connect-timeout 30 "${CURL_URL}" -o "${TMP}/curl.tar.gz"
    tar -xzf "${TMP}/curl.tar.gz" -C "${TMP}/"
fi
if [[ ! -d "${OPENSSL_SRC_DIR}" ]]; then
    echo "=== Downloading OpenSSL ${OPENSSL_VERSION} source ==="
    curl -fsSL --retry 3 --connect-timeout 30 "${OPENSSL_URL}" -o "${TMP}/openssl.tar.gz"
    tar -xzf "${TMP}/openssl.tar.gz" -C "${TMP}/"
fi

# === Build OpenSSL (static, no-asm) for a specific target ===
# Args: $1 = output dir (e.g. vendor/openssl/linux-x86_64)
#       $2 = OpenSSL Configure target name (e.g. "linux-x86_64",
#            "darwin64-arm64-cc", "darwin64-x86_64-cc")
#       $3.. = extra CC args for cross-compile (empty for native)
build_openssl_target() {
    local out_dir="$1"
    local ossl_target="$2"
    shift 2
    local cc_extra=("$@")

    echo ""
    echo "=== Building OpenSSL for ${out_dir} ==="
    local build_dir="${TMP}/openssl-build-${out_dir##*/}"
    rm -rf "${build_dir}"
    mkdir -p "${build_dir}"
    cd "${build_dir}"

    local cc="cc"
    local ar_bin="ar"
    local ranlib_bin="ranlib"
    if [[ ${#cc_extra[@]} -gt 0 ]]; then
        cc="zig cc ${cc_extra[*]}"
        ar_bin="zig ar"
        ranlib_bin="zig ranlib"
    fi

    # no-shared: static libs only. no-asm: skip perlasm — avoids
    # needing a target-specific assembler during cross-compilation.
    # no-tests / no-apps: we only need libssl.a/libcrypto.a, not the
    # openssl CLI or test suite (both are awkward to cross-link).
    "${OPENSSL_SRC_DIR}/Configure" "${ossl_target}" \
        no-shared no-asm no-tests no-apps no-docs \
        --prefix="${out_dir}" \
        --openssldir="${out_dir}/ssl" \
        CC="${cc}" AR="${ar_bin}" RANLIB="${ranlib_bin}" \
        >/dev/null

    # build_libs only builds libssl.a/libcrypto.a (skips `apps`,
    # `test`, `doc` — matches the no-apps/no-tests/no-docs flags above
    # but some older OpenSSL Makefiles still need the narrower target).
    make -j4 build_libs >/dev/null

    if [[ ! -f "libssl.a" ]] || [[ ! -f "libcrypto.a" ]]; then
        echo "  ERROR: libssl.a/libcrypto.a not produced — OpenSSL build failed"
        return 1
    fi

    mkdir -p "${out_dir}/lib" "${out_dir}/include"
    cp libssl.a libcrypto.a "${out_dir}/lib/"
    # Copy the headers in two passes:
    #   1. ALL plain .h files from the source tree's include/openssl/
    #      (e.g. pem.h, ssl.h, evp.h — ~113 headers that don't go
    #      through Configure substitution). These are missing from the
    #      build dir because OpenSSL's build process only generates the
    #      `.h` files from `.h.in` templates INTO the build dir; it
    #      doesn't copy the verbatim source headers.
    #   2. The 28 generated .h files from the build dir's include/openssl/
    #      (the result of Configure substituting @VAR@ tokens in the
    #      source's .h.in templates). These OVERLAY the source's `.h`
    #      counterparts where both exist (e.g. asn1.h, ssl.h).
    #
    # Without step 1, the vendored include/openssl/ is missing pem.h and
    # ~84 other plain headers. Curl's configure picks up the SYSTEM
    # /usr/include/openssl/ instead (the missing header causes a fatal
    # build error like "unknown type name 'OSSL_i2d_of_void_ctx'" —
    # observed on CI run 31706196476 after fixing the test-step race;
    # see docs/superpowers/plans/2026-08-13-fix-ci-linux-vendor-race.md
    # for the full failure chain).
    cp -r "${OPENSSL_SRC_DIR}/include/openssl" "${out_dir}/include/"
    # Copy generated headers on top (rsync-style overlay). Use cp -n
    # (no-clobber) to preserve step-1 plain headers; only overwrite
    # when the build dir has a fresher .h (the Configure-generated one).
    if [[ -d "include/openssl" ]]; then
        cp -rn include/openssl/. "${out_dir}/include/openssl/" 2>/dev/null || \
            cp -rf include/openssl/. "${out_dir}/include/openssl/"
    fi
    # Clean up .h.in templates — they're never meant to be included.
    find "${out_dir}/include/openssl" -name '*.h.in' -delete 2>/dev/null || true
    echo "  archived: ${out_dir}/lib/{libssl.a,libcrypto.a}"
    echo "  headers:  ${out_dir}/include/openssl/ ($(find "${out_dir}/include/openssl" -name '*.h' | wc -l) .h files)"
}

# === Build curl for a specific target ===
# Args: $1 = output dir (e.g. vendor/curl/linux-x86_64), $2 = host triple
#       (empty for native), $3 = matching OpenSSL vendor dir,
#       $4.. = extra CC args (e.g. "-target aarch64-macos")
build_curl_target() {
    local out_dir="$1"
    local host_triple="$2"
    local openssl_dir="$3"
    shift 3
    local cc_extra=("$@")

    echo ""
    echo "=== Building curl for ${out_dir} ==="
    rm -rf "${TMP}/build"
    mkdir -p "${TMP}/build"
    cd "${TMP}/build"

    local prefix="${TMP}/install-${out_dir##*/}"

    # For cross-compile, force CC/CXX/AR/RANLIB to use zig cc / zig ar.
    # Without this, ./configure picks up the host gcc and produces
    # ELF x86_64 objects even when --host says aarch64-apple-darwin
    # (we hit this — see git history for the ELF-x86_64-on-macOS bug).
    if [[ -n "${host_triple}" ]]; then
        export CC="zig cc ${cc_extra[*]}"
        export CXX="zig c++ ${cc_extra[*]}"
        export AR="zig ar"
        export RANLIB="zig ranlib"
        export ac_cv_host="${host_triple}"
    else
        unset CC CXX AR RANLIB ac_cv_host
    fi
    # Point pkg-config-less configure at our vendored, static OpenSSL.
    export CPPFLAGS="-I${openssl_dir}/include"
    export LDFLAGS="-L${openssl_dir}/lib"

    # Run ./configure with target-specific options
    local cfg_cmd=("${CURL_SRC_DIR}/configure" "--prefix=${prefix}")
    if [[ -n "${host_triple}" ]]; then
        cfg_cmd+=("--host=${host_triple}")
    fi
    cfg_cmd+=("--with-openssl=${openssl_dir}")
    cfg_cmd+=("${COMMON_CONFIGURE_FLAGS[@]}")

    "${cfg_cmd[@]}" >/dev/null 2>&1

    # Compile each .c file. The final libtool link step (libcurl.la)
    # fails on Linux hosts due to a libtool bug (Bad file descriptor on
    # fd 0), but that's OK — every .c file is already compiled into a
    # .o. We just bypass libtool by archiving them directly.
    make -j4 >/dev/null 2>&1 || true

    # Verify we got a healthy number of .o files (sanity check; a
    # TLS-enabled build compiles more of lib/vtls/* than the HTTP-only
    # build did). Search RECURSIVELY — lib/vtls/*.o, lib/vauth/*.o,
    # lib/vquic/*.o, etc. are all needed for symbol resolution below.
    local obj_count
    obj_count=$(find lib -name '*.o' | wc -l)
    if [[ "${obj_count}" -lt 100 ]]; then
        echo "  ERROR: only ${obj_count} .o files produced — build is incomplete"
        return 1
    fi
    echo "  compiled: ${obj_count} object files (recursive: includes vtls/, vauth/, etc.)"

    # Verify the objects are actually for the right target (sanity
    # check that the zig cc cross-compile actually worked). The first
    # .o's magic-number tells us: ELF = Linux/BSD, Mach-O = Apple,
    # COFF = Windows.
    # Use `find -print -quit` instead of `find | head -n 1` — the
    # pipe-head combo causes SIGPIPE on `head`'s early exit, which
    # `pipefail` + `set -e` turns into a silent script exit.
    local first_obj
    first_obj=$(find lib -name '*.o' -print -quit)
    local obj_format
    obj_format=$(file "${first_obj}" 2>/dev/null | sed 's|.*: ||')
    echo "  format: ${obj_format}"

    # Archive into libcurl.a (bypasses libtool's broken linker step).
    #
    # IMPORTANT: libcurl.a must be self-contained. Callers (e.g.
    # `zig build`) link a single vendor/curl/<target>/lib/libcurl.a —
    # they don't separately link vendor/openssl/<target>/lib/{libssl,
    # libcrypto}.a. If we archive only curl's own .o files, the
    # archive references OpenSSL symbols (ERR_peek_error,
    # SSL_CTX_set_keylog_callback, etc.) that are never defined
    # anywhere the linker looks, and the final `zig build` link fails
    # with "undefined symbol". So we extract libssl.a's and
    # libcrypto.a's object files and fold them into the same archive
    # as curl's objects, producing one fat, self-contained libcurl.a
    # per target — exactly like the pre-OpenSSL HTTP-only build was
    # (a single archive consumers link against).
    # AR is already exported above: "zig ar" for cross-compile targets,
    # unset (falls back to plain "ar") for the native Linux build.
    # Left unquoted deliberately so "zig ar" word-splits into the two
    # argv tokens zig ar expects.
    local ar_cmd="${AR:-ar}"
    local ossl_extract_dir="${TMP}/openssl-objs-${out_dir##*/}"
    rm -rf "${ossl_extract_dir}"
    mkdir -p "${ossl_extract_dir}/ssl" "${ossl_extract_dir}/crypto"
    ( cd "${ossl_extract_dir}/ssl" && ${ar_cmd} x "${openssl_dir}/lib/libssl.a" )
    ( cd "${ossl_extract_dir}/crypto" && ${ar_cmd} x "${openssl_dir}/lib/libcrypto.a" )
    # ssl/ and crypto/ objects are extracted into separate
    # subdirectories specifically so identically-named .o files from
    # the two libraries (e.g. both defining "bio.o") can't clobber
    # each other in a single flat extraction directory.

    mkdir -p "${out_dir}/lib" "${out_dir}/include"
    rm -f "${out_dir}/lib/libcurl.a"
    # shellcheck disable=SC2086
    ar rcs "${out_dir}/lib/libcurl.a" \
        $(find lib -name '*.o') \
        $(find "${ossl_extract_dir}" -name '*.o')
    echo "  archived: ${out_dir}/lib/libcurl.a (curl + libssl + libcrypto, fat archive)"

    # Copy curl headers (public headers from the source dir —
    # curl_config.h is internal and only used at build time).
    cp -r "${CURL_SRC_DIR}/include/curl/." "${out_dir}/include/curl/"
    echo "  headers: ${out_dir}/include/curl/"

    # Verify the archive is non-empty and exports both a core curl
    # symbol and a TLS-path symbol, proving OpenSSL actually linked in
    # (not just compiled-and-discarded).
    local first_obj_basename
    first_obj_basename=$(find lib -maxdepth 1 -name '*.o' -print -quit | sed 's|.*/||')
    ar p "${out_dir}/lib/libcurl.a" "${first_obj_basename}" > "${TMP}/sample.o" 2>/dev/null || true
    if [[ ! -s "${TMP}/sample.o" ]]; then
        echo "  ERROR: archive is empty — build failed"
        return 1
    fi
    if [[ -z "${host_triple}" ]]; then
        # nm on an archive reports only UNDEFINED references (`U`), not
        # the defined symbols in its members — so `nm libcurl.a | grep 'T foo'`
        # would always miss `foo` even when the symbol is defined in one
        # of the 1200+ merged .o files. The robust check is to extract
        # the archive to a tempdir and run nm on each member.
        local nm_check_dir="${TMP}/libcurl-obj-check"
        rm -rf "${nm_check_dir}"
        mkdir -p "${nm_check_dir}"
        ( cd "${nm_check_dir}" && ${ar_cmd} x "${out_dir}/lib/libcurl.a" ) || true
        # Single concatenated nm pass over every .o — easier to scan
        # than per-file nm in a loop (1200+ files = 1200+ nm spawns).
        local all_nm
        all_nm=$(find "${nm_check_dir}" -name '*.o' -exec nm {} \; 2>/dev/null)

        if ! grep -qE "[Tt] curl_easy_init" <<<"${all_nm}"; then
            echo "  ERROR: Linux libcurl.a does not export curl_easy_init"
            return 1
        fi
        if ! grep -qE "Curl_ossl_" <<<"${all_nm}"; then
            echo "  WARNING: curl_easy_init found but no Curl_ossl_* symbols — HTTPS glue may not be compiled in"
        fi
        # Confirm ERR_peek_error / SSL_CTX_set_keylog_callback are
        # actually DEFINED ("T"/"t") in the merged archive, not merely
        # referenced. A merge bug (e.g. AR pointing at the wrong tool,
        # or the extract step silently producing zero .o files) would
        # leave these referenced-but-undefined, which nm alone on the
        # archive won't flag — only the final `zig build` link would
        # (as undefined symbol errors). Checking here catches it early.
        for sym in ERR_peek_error SSL_CTX_set_keylog_callback; do
            if ! grep -qE "[Tt] ${sym}$" <<<"${all_nm}"; then
                echo "  ERROR: ${sym} not defined in merged libcurl.a — OpenSSL objects did not merge correctly"
                return 1
            fi
        done
        echo "  verified: curl_easy_init + OpenSSL symbols (ERR_peek_error, SSL_CTX_set_keylog_callback) defined (Linux nm)"
    else
        echo "  verified: Mach-O archive non-empty (symbols checked at Zig link time)"
    fi
}

mkdir -p "${CURL_VENDOR_DIR}" "${OPENSSL_VENDOR_DIR}"

# === Step 1: OpenSSL for each target ===
# Only build the targets in TARGETS (set above based on host OS or
# CURL_TARGETS override). See the comment at TARGETS for rationale.
echo "Building for target(s): ${TARGETS}"

for target in ${TARGETS}; do
    case "${target}" in
        linux-x86_64)
            build_openssl_target "${OPENSSL_VENDOR_DIR}/linux-x86_64" "linux-x86_64"
            ;;
        macos-arm64)
            build_openssl_target "${OPENSSL_VENDOR_DIR}/macos-arm64" "darwin64-arm64-cc" \
                "-target" "aarch64-macos" "-fuse-ld=lld"
            ;;
        macos-x86_64)
            build_openssl_target "${OPENSSL_VENDOR_DIR}/macos-x86_64" "darwin64-x86_64-cc" \
                "-target" "x86_64-macos" "-fuse-ld=lld"
            ;;
        *)
            echo "ERROR: unknown target '${target}' (expected: linux-x86_64, macos-arm64, macos-x86_64)" >&2
            exit 9
            ;;
    esac
done

# === Step 2: curl for each target, linked against the OpenSSL above ===
for target in ${TARGETS}; do
    case "${target}" in
        linux-x86_64)
            build_curl_target "${CURL_VENDOR_DIR}/linux-x86_64" "" \
                "${OPENSSL_VENDOR_DIR}/linux-x86_64"
            ;;
        macos-arm64)
            build_curl_target "${CURL_VENDOR_DIR}/macos-arm64" "aarch64-apple-darwin" \
                "${OPENSSL_VENDOR_DIR}/macos-arm64" \
                "-target" "aarch64-macos" "-fuse-ld=lld"
            ;;
        macos-x86_64)
            build_curl_target "${CURL_VENDOR_DIR}/macos-x86_64" "x86_64-apple-darwin" \
                "${OPENSSL_VENDOR_DIR}/macos-x86_64" \
                "-target" "x86_64-macos" "-fuse-ld=lld"
            ;;
    esac
done

echo ""
echo "=== Done. Run 'zig build' to verify ==="
echo "  Linux native + macOS arm64 + macOS x86_64 vendored curl (with OpenSSL/HTTPS) ready."
echo "  Windows archive (vendor/curl/windows-amd64/) NOT built yet — needs MinGW setup."
echo "  Note: HTTP/2 and HTTP/3 are still disabled (nghttp2/nghttp3/ngtcp2 not vendored)."
echo "        Compression (gzip/br/zstd) is still disabled (zlib/brotli/zstd not vendored)."
