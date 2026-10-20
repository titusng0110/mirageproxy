#!/usr/bin/env bash
# ==========================================================================
# MirageProxy smoke test — local mode (no Docker required)
#
# Builds the server and client from source with a fresh paired secret, then
# exercises the entire chain on localhost:
#
#   curl ──socks5──▶ sslocal(:1080) ──SS──▶ mirage client(:30000)
#        ──HTTPS──▶ mirage server(:30001) ──SS──▶ ssserver(:5080) ──▶ testserver(:9000)
#
# Checks:
#   T1  health check through the full tunnel
#   T2  download integrity — 1 KiB (sha256 vs deterministic generator)
#   T3  download integrity — 4 MiB
#   T4  download integrity — 2 MiB chunked streaming (no Content-Length)
#   T5  upload integrity — 1 MiB POST echoed back through the tunnel
#   T6  parallel downloads — 2 × 1 MiB (concurrent sessions)
#   T7  unauthenticated probes get the nginx/1.31.7 404 camouflage
#   T8  real internet through the tunnel (informational, offline-tolerant)
#
# Usage:
#   ./smoke/run-smoke.sh
#   SMOKE_TS_PORT=9111 ./smoke/run-smoke.sh     # different target port
#   SMOKE_WORKDIR=/tmp/x ./smoke/run-smoke.sh   # fixed work dir
# ==========================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${SMOKE_WORKDIR:-/tmp/mirage-smoke-$$}"
TS_PORT="${SMOKE_TS_PORT:-9000}"
SS_VERSION="v1.25.0"
BASE="http://127.0.0.1:${TS_PORT}"
PROXY="socks5h://127.0.0.1:1080"

PASS=0
FAIL=0
WARN=0
PIDS=()

cleanup() {
	for pid in "${PIDS[@]:-}"; do
		kill "$pid" 2>/dev/null || true
	done
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

# Hash of what /download?size=N produces, fetched DIRECTLY from the test
# server (not through the tunnel) so the comparison isolates the tunnel.
want_hash() { curl -sS --max-time 15 "http://127.0.0.1:${TS_PORT}/hash?size=$1" | tr -d '[:space:]'; }
got_hash()  { sha256sum "$1" | awk '{print $1}'; }

# ------------------------------- preflight -------------------------------
for tool in go openssl curl tar wget sha256sum; do
	command -v "$tool" >/dev/null 2>&1 || { echo "Missing required tool: $tool" >&2; exit 1; }
done

if curl -s --max-time 2 "http://127.0.0.1:${TS_PORT}/health" >/dev/null 2>&1; then
	echo "Port ${TS_PORT} is already in use — set SMOKE_TS_PORT to another port" >&2
	exit 1
fi

mkdir -p "$WORK"

# ------------------------------- build -------------------------------
log "Generating throwaway cert + fresh paired secret, building from source"
openssl req -x509 -newkey rsa:4096 -keyout "$WORK/server.key" \
	-out "$WORK/server.crt" -days 2 -nodes -subj "/CN=localhost" 2>/dev/null

SECRET="$(openssl rand -base64 32)"
go build -ldflags "-s -w -X main.ProxySecret=${SECRET}" \
	-o "$WORK/server_bin" "$ROOT/server"
go build -ldflags "-s -w -X main.ProxySecret=${SECRET} -X main.RemoteServerURL=https://127.0.0.1:30001" \
	-o "$WORK/client_bin" "$ROOT/client"
go build -o "$WORK/testserver" "$ROOT/smoke/testserver.go"

# ------------------------------- binaries -------------------------------
# ssserver is not in the repo (grab_sslocal.sh keeps only sslocal) — download
# the static musl build so the test runs on any distro.
if [ ! -x "$WORK/ssserver" ]; then
	log "Downloading ssserver ${SS_VERSION} (static musl build)"
	wget -q "https://github.com/shadowsocks/shadowsocks-rust/releases/download/${SS_VERSION}/shadowsocks-${SS_VERSION}.x86_64-unknown-linux-musl.tar.xz" \
		-O "$WORK/ss-server.tar.xz"
	tar -xJf "$WORK/ss-server.tar.xz" -C "$WORK" ssserver
	rm -f "$WORK/ss-server.tar.xz"
	chmod +x "$WORK/ssserver"
fi

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

# ------------------------------- start stack -------------------------------
log "Starting the stack: testserver → ssserver → server → client → sslocal"
"$WORK/testserver" -addr "127.0.0.1:${TS_PORT}" >"$WORK/testserver.log" 2>&1 &
PIDS+=("$!")
"$WORK/ssserver" -c "$ROOT/ssserver-config.json" >"$WORK/ssserver.log" 2>&1 &
PIDS+=("$!")
# The server loads server.crt/server.key from its working directory.
( cd "$WORK" && exec ./server_bin ) >"$WORK/server.log" 2>&1 &
PIDS+=("$!")
"$WORK/client_bin" -insecure >"$WORK/client.log" 2>&1 &
PIDS+=("$!")
"$SSLOCAL" -c "$ROOT/sslocal-config.json" >"$WORK/sslocal.log" 2>&1 &
PIDS+=("$!")

wait_port "$TS_PORT" testserver
wait_port 5080 ssserver
wait_port 30001 server
wait_port 30000 client
wait_port 1080 sslocal
log "All five processes are listening"

# ------------------------------- tests -------------------------------
log "Sanity: target answers directly (bypassing the tunnel)"
[ "$(curl -sS --max-time 15 "${BASE}/health")" = "ok" ] &&
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
	for f in server client ssserver sslocal testserver; do
		echo "--- $f.log (tail) ---"
		tail -n 15 "$WORK/$f.log" 2>/dev/null || true
	done
	exit 1
fi
