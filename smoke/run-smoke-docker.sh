#!/usr/bin/env bash
# ==========================================================================
# MirageProxy smoke test — Docker mode (mirrors a real VPS deployment)
#
# Builds the Docker image exactly like the README describes, runs the server
# + ssserver in the container, extracts the paired client binary from it, and
# runs the same integrity checks as run-smoke.sh.
#
# Topology:
#
#   curl ──socks5──▶ sslocal(:1080, host) ──SS──▶ mirageproxy_client(:30000, host)
#        ──HTTPS──▶ server(:30001, container) ──SS──▶ ssserver(:5080, container)
#        ──▶ testserver(:9000, host, via host.docker.internal)
#
# NOTE: requires sudo docker (you will be prompted for your password).
#
# Usage:
#   ./smoke/run-smoke-docker.sh
#   SMOKE_TS_PORT=9111 ./smoke/run-smoke-docker.sh
# ==========================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${SMOKE_WORKDIR:-/tmp/mirage-smoke-docker-$$}"
TS_PORT="${SMOKE_TS_PORT:-9000}"
SS_VERSION="v1.25.0"
IMG="mirageproxy-smoke"
CONT="mirageproxy-smoke"
# Resolved inside the container by ssserver (host-gateway via --add-host).
BASE="http://host.docker.internal:${TS_PORT}"
PROXY="socks5h://127.0.0.1:1080"

PASS=0
FAIL=0
WARN=0
PIDS=()

cleanup() {
	for pid in "${PIDS[@]:-}"; do
		kill "$pid" 2>/dev/null || true
	done
	sudo docker rm -f "$CONT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log()  { printf '\n\033[1m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
warn() { WARN=$((WARN + 1)); printf '  \033[33mWARN\033[0m  %s\n' "$1"; }

wait_port() {
	local port="$1" name="$2" i
	for i in $(seq 1 150); do
		if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
			return 0
		fi
		sleep 0.2
	done
	echo "ERROR: $name did not start listening on port $port" >&2
	return 1
}

want_hash() { curl -sS --max-time 15 "http://127.0.0.1:${TS_PORT}/hash?size=$1" | tr -d '[:space:]'; }
got_hash()  { sha256sum "$1" | awk '{print $1}'; }

# ------------------------------- preflight -------------------------------
for tool in go openssl curl tar sha256sum docker; do
	command -v "$tool" >/dev/null 2>&1 || { echo "Missing required tool: $tool" >&2; exit 1; }
done

if curl -s --max-time 2 "http://127.0.0.1:${TS_PORT}/health" >/dev/null 2>&1; then
	echo "Port ${TS_PORT} is already in use — set SMOKE_TS_PORT to another port" >&2
	exit 1
fi

mkdir -p "$WORK"

# ------------------------------- build image + extract client -------------------------------
log "Building the Docker image (same as a VPS deployment)"
sudo docker build --build-arg REMOTE_SERVER_URL="https://127.0.0.1:30001" -t "$IMG" "$ROOT"

log "Running the container (server :30001 + ssserver :5080 inside)"
sudo docker rm -f "$CONT" >/dev/null 2>&1 || true
sudo docker run -d --name "$CONT" \
	--add-host=host.docker.internal:host-gateway \
	-p "127.0.0.1:30001:30001" \
	"$IMG" >/dev/null

log "Extracting the paired client binary from the container"
# docker cp preserves the file's root ownership from inside the container,
# so chown it back to the invoking user before making it executable.
sudo docker cp "$CONT:/app/client" "$WORK/mirageproxy_client"
sudo chown "$(id -u):$(id -g)" "$WORK/mirageproxy_client"
chmod +x "$WORK/mirageproxy_client"

# ------------------------------- local binaries -------------------------------
go build -o "$WORK/testserver" "$ROOT/smoke/testserver.go"

SSLOCAL="$ROOT/sslocal"
if [ ! -x "$SSLOCAL" ]; then
	log "sslocal not found in repo — downloading"
	wget -q "https://github.com/shadowsocks/shadowsocks-rust/releases/download/${SS_VERSION}/shadowsocks-${SS_VERSION}.x86_64-unknown-linux-gnu.tar.xz" \
		-O "$WORK/ss-local.tar.xz"
	tar -xJf "$WORK/ss-local.tar.xz" -C "$WORK" sslocal
	SSLOCAL="$WORK/sslocal"
	rm -f "$WORK/ss-local.tar.xz"
	chmod +x "$SSLOCAL"
fi

# ------------------------------- start local processes -------------------------------
# The test server binds 0.0.0.0 so the container can reach it via host-gateway.
log "Starting testserver (0.0.0.0:${TS_PORT}), client and sslocal"
"$WORK/testserver" -addr "0.0.0.0:${TS_PORT}" >"$WORK/testserver.log" 2>&1 &
PIDS+=("$!")
"$WORK/mirageproxy_client" -insecure >"$WORK/client.log" 2>&1 &
PIDS+=("$!")
"$SSLOCAL" -c "$ROOT/sslocal-config.json" >"$WORK/sslocal.log" 2>&1 &
PIDS+=("$!")

wait_port "$TS_PORT" testserver
wait_port 30001 "container server (published)"
wait_port 30000 client
wait_port 1080 sslocal
log "Stack is up"

# ------------------------------- tests -------------------------------
log "Sanity: target answers directly (bypassing the tunnel)"
[ "$(curl -sS --max-time 15 "http://127.0.0.1:${TS_PORT}/health")" = "ok" ] &&
	pass "direct target reachable" || fail "direct target reachable"

log "T1: health through the full tunnel"
[ "$(curl -sS --max-time 30 -x "$PROXY" "${BASE}/health")" = "ok" ] &&
	pass "health via tunnel" || fail "health via tunnel"

log "T2: download integrity — 1 KiB"
curl -sS --max-time 30 -x "$PROXY" -o "$WORK/t2.bin" "${BASE}/download?size=1024"
[ "$(got_hash "$WORK/t2.bin")" = "$(want_hash 1024)" ] &&
	pass "1 KiB download" || fail "1 KiB download"

log "T3: download integrity — 4 MiB"
curl -sS --max-time 180 -x "$PROXY" -o "$WORK/t3.bin" "${BASE}/download?size=4194304"
[ "$(got_hash "$WORK/t3.bin")" = "$(want_hash 4194304)" ] &&
	pass "4 MiB download" || fail "4 MiB download"

log "T4: download integrity — 2 MiB chunked stream"
curl -sS --max-time 180 -x "$PROXY" -o "$WORK/t4.bin" "${BASE}/download?size=2097152&chunked=1"
[ "$(got_hash "$WORK/t4.bin")" = "$(want_hash 2097152)" ] &&
	pass "2 MiB chunked download" || fail "2 MiB chunked download"

log "T5: upload round-trip — 1 MiB POST echoed back"
head -c 1048576 /dev/urandom >"$WORK/up.bin"
curl -sS --max-time 180 -x "$PROXY" -o "$WORK/up.echo" \
	-H "Content-Type: application/octet-stream" \
	--data-binary "@${WORK}/up.bin" "${BASE}/echo"
[ "$(got_hash "$WORK/up.echo")" = "$(got_hash "$WORK/up.bin")" ] &&
	pass "1 MiB upload round-trip" || fail "1 MiB upload round-trip"

log "T6: parallel downloads — 2 × 1 MiB"
curl -sS --max-time 180 -x "$PROXY" -o "$WORK/p1.bin" "${BASE}/download?size=1048576" &
C1=$!
curl -sS --max-time 180 -x "$PROXY" -o "$WORK/p2.bin" "${BASE}/download?size=1048576" &
C2=$!
wait "$C1" 2>/dev/null || true
wait "$C2" 2>/dev/null || true
PH="$(want_hash 1048576)"
{ [ "$(got_hash "$WORK/p1.bin")" = "$PH" ] && [ "$(got_hash "$WORK/p2.bin")" = "$PH" ]; } &&
	pass "parallel downloads" || fail "parallel downloads"

log "T7: unauthenticated probes get the nginx 404 camouflage"
code_root="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -k "https://127.0.0.1:30001/")"
code_up="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -k "https://127.0.0.1:30001/upload?clientid=smokeprobe")"
srv="$(curl -sI --max-time 15 -k "https://127.0.0.1:30001/" | tr -d '\r' | awk 'tolower($1)=="server:"{print $2}')"
[ "$code_root" = "404" ] &&
	pass "GET / → HTTP $code_root" || fail "GET / expected 404, got $code_root"
[ "$code_up" = "404" ] &&
	pass "POST /upload (unsigned) → HTTP $code_up" || fail "POST /upload (unsigned) expected 404, got $code_up"
[ "$srv" = "nginx/1.31.7" ] &&
	pass "Server header: $srv" || fail "Server header: expected nginx/1.31.7, got '$srv'"

log "T8: real internet through the tunnel (informational)"
if curl -sS --max-time 25 -x "$PROXY" -o "$WORK/net.trace" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null &&
	grep -q '^ip=' "$WORK/net.trace"; then
	pass "internet reachable via tunnel (exit IP: $(grep '^ip=' "$WORK/net.trace" | cut -d= -f2))"
else
	warn "no internet through tunnel (offline environment?) — not counted as failure"
fi

# ------------------------------- summary -------------------------------
log "SMOKE RESULT: $PASS passed, $FAIL failed, $WARN warnings"
echo "Logs and artifacts: $WORK"
if [ "$FAIL" -gt 0 ]; then
	for f in client sslocal testserver; do
		echo "--- $f.log (tail) ---"
		tail -n 15 "$WORK/$f.log" 2>/dev/null || true
	done
	echo "--- container logs (tail) ---"
	sudo docker logs --tail 15 "$CONT" 2>&1 || true
	exit 1
fi
