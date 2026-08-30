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
MAX_PEERS="${MAX_PEERS:-10}"     # cap BT peer connections per torrent on a device
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

# What the hook needs, handed over by inheritance through aria2c's fork rather
# than re-read from disk. The rpc-secret FILE and the running daemon can
# disagree (that skew IS the 2026-08-20 incident), and an empty file
# legitimately means the daemon is on the "iris" placeholder resolved above --
# so the value in this variable is the only one guaranteed to be the one the
# daemon is actually using. No new exposure: it is already on aria2c's argv.
# (The hook needs no stage path: aria2 hands it the staged file as argv[3].)
export IRIS_RPC_PORT="$RPC_PORT"
export IRIS_RPC_SECRET="$RPC_SECRET"

# already up? (skip the probe in tests)
if [ "${SKIP_RPC_PROBE:-0}" != "1" ]; then
  if curl -s "http://127.0.0.1:$RPC_PORT/jsonrpc" \
       -d '{"jsonrpc":"2.0","id":"p","method":"aria2.getVersion","params":["token:'"$RPC_SECRET"'"]}' \
       >/dev/null 2>&1; then
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
  "$@" \
  --bt-seed-unverified=true \
  --seed-ratio=0.0 \
  --file-allocation=none \
  --dir="$STAGE_DIR" \
  --log="$LOG" \
  --log-level=warn \
  --summary-interval=0
