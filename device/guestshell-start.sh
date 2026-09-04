#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Launch aria2c inside Guest Shell as an RPC daemon for the IRIS agent.
# - runs as the guestshell user (NOT root): /flash is SELinux-labeled (Phase 0)
# - copies the binary off /flash to an exec-capable fs (chmod denied on /flash)
# - private swarm: DHT/PEX/LPD OFF; seeds completed files without re-hashing
# - RPC on so iris_agent.py can addTorrent; the agent adds torrents (none on argv)
# - idempotent: if the RPC already answers, do nothing
set -euo pipefail

STAGE_DIR="${STAGE_DIR:-/flash/guest-share/iris}"
EXEC_DIR="${EXEC_DIR:-/home/guestshell}"
ARIA2_SRC="${ARIA2_SRC:-$STAGE_DIR/aria2c}"
RPC_PORT="${RPC_PORT:-6800}"
RPC_SECRET_FILE="${RPC_SECRET_FILE:-$STAGE_DIR/rpc-secret}"
HOOK_SRC="${HOOK_SRC:-$STAGE_DIR/agent/peer-transfer-hook.sh}"
HOOK_DST="${HOOK_DST:-$EXEC_DIR/iris-peer-transfer-hook}"
LOG="${LOG:-$STAGE_DIR/aria2c.log}"
# Device-side logging is OFF by default: flash has finite write endurance,
# and aria2c's log is chatty and continuous for the whole life of a transfer
# (and, with --seed-ratio=0.0 below, a staged device seeds forever, so a log
# left on would never stop growing). Off means genuinely no recurring flash
# write from this source, not "a smaller file" -- with no --log= on the
# launch line below, aria2c's own daemon mode (-D/--daemon) already
# redirects its stdout/stderr to /dev/null itself (aria2 Next 2.5.6 --help,
# the -D entry), so nothing is opened on flash at all. Same fail-closed
# on/1/true/yes parsing telemetry_report.stream_enabled() uses; anything
# else, including garbage, stays off. This never touches error reporting:
# IOS syslog (emit(), via `send log`) and the heartbeat's stage_error field
# are unaffected either way -- only the continuous local aria2c.log file is
# optional.
IRIS_LOG="${IRIS_LOG:-off}"
MAX_PEERS="${MAX_PEERS:-10}"     # cap BT peer connections per torrent on a device
# Lift aria2's concurrency cap, which defaults to 5. A SEEDING torrent counts
# against that cap and never completes (--seed-ratio=0.0 below means seed
# forever, which is the point -- staged devices seed to their peers), so a
# device holding five staged images would queue the download for a sixth and
# never start it. A device may be assigned up to ten. The starvation is silent:
# aria2 reports the extra as `waiting`, not an error, so the device would report
# staging indefinitely with no fault recorded anywhere. Bandwidth is bounded by
# --bt-max-peers and transfer limits, never by this; using it as a throttle only
# starves. Same defect fixed on the origin in server/seed-launch.sh.
MAX_CONCURRENT="${MAX_CONCURRENT:-100}"
BT_LISTEN_PORT="${BT_LISTEN_PORT:-}"

if [ -n "$BT_LISTEN_PORT" ]; then
  [[ "$BT_LISTEN_PORT" =~ ^[0-9]+$ ]] && [ "$BT_LISTEN_PORT" -ge 1 ] \
    && [ "$BT_LISTEN_PORT" -le 65535 ] \
    || { echo "invalid BT_LISTEN_PORT: $BT_LISTEN_PORT" >&2; exit 1; }
  set -- "--listen-port=$BT_LISTEN_PORT"
else
  set --
fi

# The installer bakes rpc-secret EMPTY (the agent fetches the real value on
# its first token-refresh), and Aria2 Next rejects --rpc-secret= outright
# ("Empty string is not allowed"; aria2 1.37 accepted it — field incident
# 2026-08-20: aria2c never launched, bootstrap aborted before the agent, and
# every freshly onboarded Guest Shell device stayed silent). Launch with the
# same placeholder the IOx entrypoint uses; bootstrap's secret sync bounces
# aria2c onto the real secret right after that first refresh.
RPC_SECRET="$(tr -d '[:space:]' < "$RPC_SECRET_FILE" 2>/dev/null || true)"
RPC_SECRET="${RPC_SECRET:-iris}"

# The per-peer transfer-record hook (--on-bt-download-complete, appended below).
# aria2 execs the value directly -- execlp with no shell (util.cc:2328) -- so
# it must be a real file with the exec bit, exactly like aria2c itself. /flash
# denies chmod, which is why aria2c is copied to $EXEC_DIR; a hook left in the
# stage dir could never be made executable, so it takes the same route.
#
# This runs ABOVE the "already up?" exit on purpose. Dropping a new bundle.tgz
# IS how the agent is upgraded, and an aria2c that is already serving is NOT
# relaunched -- so this is the only moment a refreshed hook can reach the path
# the running daemon already holds. The path never changes, so the live daemon
# picks up the new content on its next fire.
#
# temp + mv, never `cp -f` onto the live file: copying onto an executing file
# returns ETXTBSY, the same failure already documented for the binary below.
HOOK=""
if [ -f "$HOOK_SRC" ]; then
  _hook_tmp="$HOOK_DST.new.$$"
  if cp -f "$HOOK_SRC" "$_hook_tmp" 2>/dev/null \
     && chmod +x "$_hook_tmp" 2>/dev/null \
     && mv -f "$_hook_tmp" "$HOOK_DST" 2>/dev/null; then
    HOOK="$HOOK_DST"
  else
    rm -f "$_hook_tmp" 2>/dev/null || true
    # Not fatal, and deliberately so: without the hook a transfer still
    # completes and the report simply omits the per-peer transfer records
    # ("not measured"). Aborting the launcher over telemetry would silence
    # the device, which is the 2026-08-20 failure mode.
    echo "cannot install the peer-transfer hook at $HOOK_DST; transfers will run without per-peer transfer records" >&2
  fi
  unset _hook_tmp
fi
if [ -n "$HOOK" ]; then
  # Appended as an argument rather than written into the exec list literally:
  # Aria2 Next rejects an empty option value outright ("Empty string is not
  # allowed"), so --on-bt-download-complete= with no hook would stop aria2c
  # from launching at all -- the exact shape of the 2026-08-20 incident.
  set -- "$@" "--on-bt-download-complete=$HOOK"
fi

# --log is added only when an operator explicitly opts in (IRIS_LOG=on).
# Left off the exec line entirely when not: see the IRIS_LOG comment above
# for why that -- not a smaller/rotated file -- is what "off" means here.
case "$(printf '%s' "$IRIS_LOG" | tr '[:upper:]' '[:lower:]')" in
  on|1|true|yes) set -- "$@" "--log=$LOG" ;;
esac

# What the hook needs, handed over by inheritance through aria2c's fork rather
# than re-read from disk. The rpc-secret FILE and the running daemon can
# disagree (that skew IS the 2026-08-20 incident), and an empty file
# legitimately means the daemon is on the "iris" placeholder resolved above --
# so the value in this variable is the only one guaranteed to be the one the
# daemon is actually using. No new exposure: it is already on aria2c's argv.
# (The hook needs no stage path: aria2 hands it the staged file as argv[3].)
export IRIS_RPC_PORT="$RPC_PORT"
export IRIS_RPC_SECRET="$RPC_SECRET"

# Health-probe bounds, in seconds -- the same two questions the container
# supervisors ask (device/iox/entrypoint.sh, device/xr/entrypoint.sh):
#   * --connect-timeout answers "is anything bound to the RPC port". On
#     loopback a daemon that is gone refuses the connection instantly (curl
#     exit 7); a daemon that is merely busy still owns its listen socket, so
#     the kernel completes the connection for it.
#   * --max-time bounds the wait for the ANSWER, and sits well above the
#     longest stall a HEALTHY aria2c can have. Built without c-ares, aria2c
#     resolves tracker hostnames with a blocking getaddrinfo() on its
#     event-loop thread: one announce against a slow resolver freezes the whole
#     daemon -- RPC replies included -- for as long as the resolver takes
#     (5.03 s measured; glibc's 5 s x 2 attempts is the ceiling to design for).
# Unbounded, as this probe used to be, a wedged daemon hangs the launcher (and
# the EEM applet that runs it) instead.
RPC_CONNECT_TIMEOUT="${RPC_CONNECT_TIMEOUT:-2}"
RPC_HEALTH_TIMEOUT="${RPC_HEALTH_TIMEOUT:-10}"

rpc_probe() {
  curl -s --connect-timeout "$RPC_CONNECT_TIMEOUT" --max-time "$RPC_HEALTH_TIMEOUT" \
    "http://127.0.0.1:$RPC_PORT/jsonrpc" \
    -d '{"jsonrpc":"2.0","id":"p","method":"aria2.getVersion","params":["token:'"$RPC_SECRET"'"]}' \
    >/dev/null 2>&1
}

rpc_up() {
  # A SLOW answer is not a dead daemon. Everything below this probe treats a
  # failure as "aria2c is not serving" and pkills it, so a probe that cannot
  # tell busy from dead kills healthy daemons and drops their in-flight
  # downloads. Connection refused means nothing is listening -- a verdict on
  # its own, and one that must stay immediate (the 2026-08-20 deadlock was a
  # stale daemon left alive). Any other failure is only a late answer, so
  # confirm it with a second probe: a resolver stall ends when the resolver
  # gives up, a wedged daemon fails the retry too.
  local rc=0
  rpc_probe || rc=$?
  case "$rc" in
    0) return 0 ;;
    7) return 1 ;;
  esac
  # A plain yes/no, never curl's own status: the caller asks "is it serving?".
  rpc_probe || return 1
}

# already up? (skip the probe in tests)
if [ "${SKIP_RPC_PROBE:-0}" != "1" ]; then
  if rpc_up; then
    echo "aria2c RPC already up on :$RPC_PORT"; exit 0
  fi
fi

# Reaching here means the RPC probe FAILED, so any surviving aria2c is alive
# but not serving. It must go before we relaunch: it still owns the RPC port
# (a new instance cannot bind) and `cp -f` over a running binary fails with
# ETXTBSY, so the stale build would keep running. Field incident 2026-08-20:
# leaving it alive deadlocked devices for ~42 minutes — the agent hit
# ECONNREFUSED every tick and never reached its first heartbeat.
if pgrep -f 'aria2c.*enable-rpc' >/dev/null 2>&1; then
  echo "aria2c is running but not answering RPC on :$RPC_PORT — replacing it" >&2
  pkill -f 'aria2c.*enable-rpc' 2>/dev/null || true
  _w=0
  while pgrep -f 'aria2c.*enable-rpc' >/dev/null 2>&1 && [ "$_w" -lt 10 ]; do
    sleep 1; _w=$((_w + 1))
  done
fi

# copy the binary to an exec-capable fs and run it
ARIA2="$EXEC_DIR/aria2c"
cp -f "$ARIA2_SRC" "$ARIA2" \
  || { echo "cannot install aria2c from $ARIA2_SRC to $ARIA2" >&2; exit 1; }
chmod +x "$ARIA2" \
  || { echo "cannot make $ARIA2 executable" >&2; exit 1; }

# --check-integrity=true is a RESUME guard. Without it aria2 trusts the piece
# map recorded in the .aria2 control file, so a completed piece that rotted on
# flash (bit-rot, a torn write during a power loss) survives the resume: the
# torrent reports complete and the staged image carries the wrong SHA-256. The
# agent's whole-image hash still catches that, but only after the whole
# remaining transfer, and the repair is then a full re-stage instead of one
# 1 MiB piece. It rides the launch line because in aria2's own code
# (RequestGroup.cc, createInitialCommand for BitTorrent) it already costs
# nothing on the two paths that are not a resume: with nothing on disk every
# piece read returns 0 bytes and the piece is marked missing at once, and on a
# COMPLETED file --bt-seed-unverified=true above marks every piece done and
# aria2 skips validation entirely -- so a device seeding its staged images
# never re-hashes them at launch.
exec "$ARIA2" \
  --daemon=true \
  --enable-rpc=true \
  --rpc-listen-all=false \
  --rpc-listen-port="$RPC_PORT" \
  --rpc-secret="$RPC_SECRET" \
  --enable-dht=false \
  --enable-peer-exchange=false \
  --bt-enable-lpd=false \
  --bt-max-peers="$MAX_PEERS" \
  --max-concurrent-downloads="$MAX_CONCURRENT" \
  "$@" \
  --bt-seed-unverified=true \
  --check-integrity=true \
  --seed-ratio=0.0 \
  --file-allocation=none \
  --dir="$STAGE_DIR" \
  --log-level=warn \
  --summary-interval=0
