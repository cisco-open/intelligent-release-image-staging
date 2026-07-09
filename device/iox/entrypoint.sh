#!/bin/sh

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# PID 1 for the IRIS aarch64 IOx Docker app on the IE-3400.
# Replaces the Guest Shell trio (EEM 60s timer + bootstrap.sh + guestshell-start.sh):
#   1. ensure the stage dir + a config file exist (generate conf from env on first
#      boot if the persistent mount has none — robust to ephemeral storage),
#   2. keep aria2c running as the BT RPC daemon, re-seeding its rpc-secret when the
#      agent rotates it (mirrors bootstrap.sh),
#   3. run the agent control plane once every tick (the existing --once path).
set -u

STAGE_DIR="${IRIS_STAGE_DIR:-/data/iris}"
CONF="${IRIS_AGENT_CONF:-$STAGE_DIR/iris-agent.conf}"
RPC_PORT="${IRIS_RPC_PORT:-6800}"
TICK="${IRIS_TICK_SECONDS:-60}"
MAX_PEERS="${IRIS_MAX_PEERS:-10}"
ARIA2="/opt/iris/bin/aria2c"
AGENT="/opt/iris/agent/iris_agent.py"

# IOx blocks bind-mounting sdflash: into the app, so the agent can't write the
# IOS-visible SD directly. It instead scp-PUSHES the staged image to
# sdflash:guest-share/iris via the device's SCP server (container -> device), then
# IOS `copy /verify`s it onto sdflash: — see iris_agent.build_deps copy_to_root.
mkdir -p "$STAGE_DIR"

# --- 1. config: use a dropped conf if present, else synthesize from env ---------
# A conf dropped onto a persistent mount wins (and the agent rewrites it in place
# on token refresh). With no conf (e.g. ephemeral storage / first boot) build one
# from the app-hosting --env knobs. SECRETS (catalog_token, device_ssh_pass) come
# from the environment at deploy time; they are never baked into the image.
if [ ! -f "$CONF" ]; then
  echo "IRIS-ENTRYPOINT: no conf at $CONF; generating from environment"
  {
    echo "catalog_url = ${IRIS_CATALOG_URL:-https://100.90.168.20:8443}"
    echo "catalog_token = ${IRIS_CATALOG_TOKEN:-}"
    echo "device_id = ${IRIS_DEVICE_ID:-}"
    echo "stage_dir = ${STAGE_DIR}"
    echo "rpc_secret = "
    echo "catalog_ca = ${IRIS_CATALOG_CA:-/opt/iris/iris-catalog.pem}"
    echo "token_expires_at = 0"
    echo "runtime_mode = container"
    echo "device_ssh_host = ${IRIS_DEVICE_SSH_HOST:-100.92.100.253}"
    echo "device_ssh_user = ${IRIS_DEVICE_SSH_USER:-dnac}"
    echo "device_ssh_pass = ${IRIS_DEVICE_SSH_PASS:-}"
    echo "device_ssh_enable = ${IRIS_DEVICE_SSH_ENABLE:-${IRIS_DEVICE_SSH_PASS:-}}"
    echo "max_peers = ${MAX_PEERS}"
    echo "telemetry = ${IRIS_TELEMETRY:-on}"
    echo "rpc_port = ${RPC_PORT}"
  } > "$CONF"
fi

# --- 2/3. aria2c supervisor + agent tick loop ----------------------------------
read_secret() {
  sed -n 's/^[[:space:]]*rpc_secret[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null \
    | tr -d '[:space:]'
}

start_aria2c() {
  secret="$1"
  pkill -f 'aria2c.*enable-rpc' 2>/dev/null || true
  sleep 1
  "$ARIA2" \
    --daemon=true --enable-rpc=true --rpc-listen-all=false \
    --rpc-listen-port="$RPC_PORT" --rpc-secret="$secret" \
    --enable-dht=false --enable-peer-exchange=false --bt-enable-lpd=false \
    --bt-max-peers="$MAX_PEERS" --bt-seed-unverified=true --seed-ratio=0.0 \
    --file-allocation=none --dir="$STAGE_DIR" \
    --log-level=warn --summary-interval=0 \
    && echo "IRIS-ENTRYPOINT: aria2c (re)started on :$RPC_PORT"
}

echo "IRIS-ENTRYPOINT: starting; stage=$STAGE_DIR conf=$CONF tick=${TICK}s"
cur=""
while true; do
  want="$(read_secret)"
  [ -z "$want" ] && want="iris"          # placeholder until the agent fetches the real secret
  if [ "$want" != "$cur" ] || ! pgrep -f 'aria2c.*enable-rpc' >/dev/null 2>&1; then
    start_aria2c "$want" && cur="$want"
  fi
  python3 "$AGENT" --once || echo "IRIS-ENTRYPOINT: agent tick returned non-zero"
  sleep "$TICK"
done
