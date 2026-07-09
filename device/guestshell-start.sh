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
LOG="${LOG:-$STAGE_DIR/aria2c.log}"
MAX_PEERS="${MAX_PEERS:-10}"     # cap BT peer connections per torrent on a device

RPC_SECRET="$(cat "$RPC_SECRET_FILE" 2>/dev/null || echo iris)"

# already up? (skip the probe in tests)
if [ "${SKIP_RPC_PROBE:-0}" != "1" ]; then
  if curl -s "http://127.0.0.1:$RPC_PORT/jsonrpc" \
       -d '{"jsonrpc":"2.0","id":"p","method":"aria2.getVersion","params":["token:'"$RPC_SECRET"'"]}' \
       >/dev/null 2>&1; then
    echo "aria2c RPC already up on :$RPC_PORT"; exit 0
  fi
fi

# copy the binary to an exec-capable fs and run it
ARIA2="$EXEC_DIR/aria2c"
cp -f "$ARIA2_SRC" "$ARIA2" 2>/dev/null || true
chmod +x "$ARIA2" 2>/dev/null || true

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
  --bt-seed-unverified=true \
  --seed-ratio=0.0 \
  --file-allocation=none \
  --dir="$STAGE_DIR" \
  --log="$LOG" \
  --log-level=warn \
  --summary-interval=0
