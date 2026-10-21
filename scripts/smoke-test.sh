#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel and check that it
# actually protects traffic.
#
#   CRS_DIR=<coreruleset checkout> scripts/smoke-test.sh <agent-binary> <zentinel-binary>
#
# CRS_DIR is a checkout of the OWASP CRS (the workflows pin the commit
# zentinel-modsec's CI uses); the agent loads it unmodified, the way the docs
# deploy it.
#
# The release workflow runs this on every platform before it publishes any
# asset, and CI runs it on main. It exists because 0.3.0 shipped a binary that
# could not complete the v2 handshake with any current Zentinel, and every
# unit and integration test in this repository still passed (the CRS tests
# skip themselves when no CRS checkout is present).
#
# What it proves, in order:
#   1. A clean request is forwarded (200 from the upstream). The agent and the
#      filter are fail-closed, so this cannot pass unless the proxy completed
#      the v2 handshake with the agent and got an Allow back.
#   2. Each attack request is refused with 403 and never reaches the upstream.
#   3. With the agent stopped, the clean request is no longer served, which
#      shows the agent was on the request path rather than bypassed.
#
# Requirements: bash, curl, python3 (for the upstream fixture).

set -euo pipefail

AGENT_BIN=${1:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}
ZENTINEL_BIN=${2:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}
AGENT_BIN=$(cd "$(dirname "$AGENT_BIN")" && pwd)/$(basename "$AGENT_BIN")
ZENTINEL_BIN=$(cd "$(dirname "$ZENTINEL_BIN")" && pwd)/$(basename "$ZENTINEL_BIN")

# How long to wait for the agent to listen and the proxy to serve.
STARTUP_TIMEOUT=${SMOKE_STARTUP_TIMEOUT:-60}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/zentinel-smoke.XXXXXX")
# Unix socket paths are limited to ~104 bytes, and TMPDIR on macOS runners is
# long, so the socket gets its own short directory.
SOCKET_DIR=$(mktemp -d "${SMOKE_SOCKET_DIR:-/tmp}/zs.XXXXXX")
SOCKET="$SOCKET_DIR/agent.sock"
PIDS=()

# --- agent-specific part ------------------------------------------------------

AGENT_NAME="modsec"
AGENT_TYPE="waf"
CRS_DIR=${CRS_DIR:?set CRS_DIR to a checkout of the OWASP CRS}
CRS_DIR=$(cd "$CRS_DIR" && pwd)

start_agent() {
    # Stock CRS: the shipped example setup file, then every rule file.
    cp "$CRS_DIR/crs-setup.conf.example" "$WORK/crs-setup.conf"
    RUST_LOG=info "$AGENT_BIN" --socket "$SOCKET" \
        --rules "$WORK/crs-setup.conf,$CRS_DIR/rules/*.conf" >"$WORK/agent.log" 2>&1 &
    AGENT_PID=$!
    PIDS+=("$AGENT_PID")
}

# "description|path-and-query" -- each must be answered 403 by the agent.
ATTACKS=(
    "SQL injection in the query string|/search?id=1%27%20OR%20%271%27%3D%271"
    "SQL injection (UNION SELECT)|/search?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users"
    "XSS in the query string|/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
)

# --- generic part -------------------------------------------------------------

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null || true
    done
    if [ "${KEEP_WORK:-0}" != "1" ]; then
        rm -rf "$WORK"
    fi
    rm -rf "$SOCKET_DIR"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for f in agent zentinel upstream; do
        if [ -f "$WORK/$f.log" ]; then
            echo "----- $f log (last 60 lines) -----" >&2
            tail -n 60 "$WORK/$f.log" >&2
        fi
    done
    exit 1
}

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

UPSTREAM_PORT=$(free_port)
PROXY_PORT=$(free_port)
METRICS_PORT=$(free_port)

# Upstream fixture: answers every request with 200 "upstream-ok" and records
# the request line, so the test can tell whether an attack got through.
cat >"$WORK/upstream.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = open(sys.argv[2], "a", buffering=1)

class H(BaseHTTPRequestHandler):
    def _ok(self):
        log.write(self.requestline + "\n")
        body = b"upstream-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = _ok

    def log_message(self, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/upstream.py" "$UPSTREAM_PORT" "$WORK/upstream-requests.log" >"$WORK/upstream.log" 2>&1 &
PIDS+=("$!")

echo "agent:    $AGENT_BIN"
"$AGENT_BIN" --version || true
echo "zentinel: $ZENTINEL_BIN"
"$ZENTINEL_BIN" --version

start_agent
for _ in $(seq 1 "$STARTUP_TIMEOUT"); do
    [ -S "$SOCKET" ] && break
    kill -0 "$AGENT_PID" 2>/dev/null || fail "agent exited during startup"
    sleep 1
done
[ -S "$SOCKET" ] || fail "agent did not create $SOCKET within ${STARTUP_TIMEOUT}s"

cat >"$WORK/zentinel.kdl" <<KDL
system {
    worker-threads 1
    graceful-shutdown-timeout-secs 1
}

listeners {
    listener "http" {
        address "127.0.0.1:${PROXY_PORT}"
        protocol "http"
    }
}

routes {
    route "protected" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "${AGENT_NAME}"
        policies {
            failure-mode "closed"
        }
    }
}

agents {
    agent "${AGENT_NAME}" type="${AGENT_TYPE}" {
        unix-socket path="${SOCKET}"
        events "request_headers"
        timeout-ms 2000
        failure-mode "closed"
    }
}

filters {
    filter "${AGENT_NAME}" {
        type "agent"
        agent "${AGENT_NAME}"
        timeout-ms 2000
        failure-mode "closed"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:${UPSTREAM_PORT}"
    }
}

observability {
    metrics {
        address "127.0.0.1:${METRICS_PORT}"
        path "/metrics"
    }
}
KDL

"$ZENTINEL_BIN" test --config "$WORK/zentinel.kdl" >"$WORK/zentinel-test.log" 2>&1 \
    || { cat "$WORK/zentinel-test.log" >&2; fail "zentinel rejected the smoke-test config"; }

"$ZENTINEL_BIN" --config "$WORK/zentinel.kdl" >"$WORK/zentinel.log" 2>&1 &
PIDS+=("$!")
ZENTINEL_PID=$!

status_of() {
    curl -s -o "$WORK/body" -w '%{http_code}' --max-time 10 "http://127.0.0.1:${PROXY_PORT}$1" || true
}

# 1. Clean request. Retry until the proxy is up and the agent connection is
#    established; a handshake that never succeeds ends here as a failure.
CLEAN="/search?q=hello+world"
code=000
for _ in $(seq 1 "$STARTUP_TIMEOUT"); do
    kill -0 "$ZENTINEL_PID" 2>/dev/null || fail "zentinel exited during startup"
    code=$(status_of "$CLEAN")
    [ "$code" = "200" ] && break
    sleep 1
done
[ "$code" = "200" ] || fail "clean request: expected 200, got $code (handshake or allow decision failed)"
grep -q upstream-ok "$WORK/body" || fail "clean request: 200 but the body did not come from the upstream"
echo "ok   clean request forwarded (200)"

# 2. Attacks must be blocked by the agent and never reach the upstream.
for case in "${ATTACKS[@]}"; do
    desc=${case%%|*}
    path=${case#*|}
    seen_before=$(wc -l <"$WORK/upstream-requests.log")
    code=$(status_of "$path")
    [ "$code" = "403" ] || fail "$desc: expected 403, got $code for $path"
    seen_after=$(wc -l <"$WORK/upstream-requests.log")
    [ "$seen_before" = "$seen_after" ] || fail "$desc: the upstream received $path"
    echo "ok   $desc blocked (403)"
done

# The clean request must still pass after the attacks.
code=$(status_of "$CLEAN")
[ "$code" = "200" ] || fail "clean request after attacks: expected 200, got $code"

# 3. Stop the agent: under fail-closed the clean request must stop being
#    served. If it still returns 200, the agent was never on the path.
# The agent may keep draining the proxy's open connections after SIGTERM, so
# give it a moment and then make sure it is gone.
kill "$AGENT_PID" 2>/dev/null || true
for _ in 1 2 3 4 5; do
    kill -0 "$AGENT_PID" 2>/dev/null || break
    sleep 1
done
kill -9 "$AGENT_PID" 2>/dev/null || true
sleep 1
code=$(status_of "$CLEAN")
[ "$code" != "200" ] || fail "clean request with the agent stopped still returned 200: the agent was not on the request path"
echo "ok   with the agent stopped the request is refused ($code)"

echo "PASS: $AGENT_NAME agent smoke test"
