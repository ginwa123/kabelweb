#!/usr/bin/env bash
# Bench harness: event-loop serve shapes against each other.
#
#   ./scripts/bench-event-loop.sh [--quick] [--port 29590]
#
# Builds kabelweb-server-demo, serves it three ways, and loads /health +
# /hello/:name with a stdlib-only python3 concurrent loader (no wrk/oha
# needed). Prints a comparison table (rps + mean ms/req).
#
# Modes: direct (single loop) | pool (worker-pool dispatch) | loops-4.
# NOTE: SSE/WS routes work on all paths now (fd handoff) — the loader
# only hits plain routes, which is what the reactor serves inline.
set -u
PORT=29590
QUICK=0
for a in "$@"; do
  case "$a" in
    --quick) QUICK=1 ;;
    --port) shift ;;
    --port=*) PORT="${a#--port=}" ;;
  esac
done

cd "$(dirname "$0")/.." || exit 1

echo "[bench] building demo..."
timeout 300 zig build install --prefix zig-out >/dev/null 2>&1 || {
  echo "[bench] zig build failed"; exit 1
}
DEMO="$PWD/zig-out/bin/kabelweb-server-demo"
[ -x "$DEMO" ] || { echo "[bench] demo binary missing: $DEMO"; exit 1; }

if ! command -v python3 >/dev/null; then
  echo "[bench] python3 required for the loader"; exit 1
fi

# Loader tuning: --quick for CI smoke, full otherwise.
if [ "$QUICK" = "1" ]; then
  THREADS=8; REQS=25
else
  THREADS=32; REQS=100
fi

load() { # $1 = label
  python3 - "$PORT" "$THREADS" "$REQS" <<'EOF'
import sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
port, nthreads, reqs = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
paths = ["/health", "/hello/bench"]
def worker(_):
    # One HTTPConnection per thread (keep-alive reuse, like a real client).
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    ok, lat = 0, 0.0
    for i in range(reqs):
        t = time.perf_counter()
        try:
            c.request("GET", paths[i % 2])
            r = c.getresponse()
            r.read()
            if r.status == 200:
                ok += 1
        except Exception:
            pass
        lat += time.perf_counter() - t
    c.close()
    return ok, lat
t0 = time.perf_counter()
with ThreadPoolExecutor(max_workers=nthreads) as ex:
    res = list(ex.map(worker, range(nthreads)))
dt = time.perf_counter() - t0
ok = sum(r[0] for r in res)
lat = sum(r[1] for r in res)
total = nthreads * reqs
print(f"{ok}/{total} ok  {total/dt:.0f} rps  {lat/max(ok,1)*1000:.2f} ms/req")
EOF
}

run_mode() { # $1 = label, $2... = demo args
  label="$1"; shift
  echo "[bench] --- $label ---"
  "$DEMO" "$@" >/tmp/bench-demo.log 2>&1 &
  srv=$!
  # wait for /health (max ~10s)
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
    sleep 0.1
  done
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 || {
    echo "[bench] server never came up ($label)"; tail -n 5 /tmp/bench-demo.log
    kill "$srv" 2>/dev/null; return 1
  }
  printf "[bench] %-12s " "$label"
  load
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  sleep 0.5
}

echo "[bench] threads=$THREADS reqs/thread=$REQS port=$PORT"
run_mode "direct"
run_mode "pool" --pool
run_mode "loops-4" --loops 4
echo "[bench] done."
