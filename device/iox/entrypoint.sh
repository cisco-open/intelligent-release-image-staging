#!/bin/sh

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# PID 1 for the IRIS arm64/amd64 IOx Docker app.
# Replaces the Guest Shell trio (EEM 60s timer + bootstrap.sh + guestshell-start.sh):
#   1. ensure the stage dir + a config file exist (generate conf from env on first
#      boot if the persistent mount has none — robust to ephemeral storage),
#   2. keep aria2c running as the BT RPC daemon, re-seeding its rpc-secret when the
#      agent rotates it (mirrors bootstrap.sh),
#   3. run the agent control plane once every tick (the existing --once path).
set -eu
umask 077

PERSIST_ROOT="${CAF_APP_PERSISTENT_DIR:-/data}"
STAGE_DIR="${IRIS_STAGE_DIR:-$PERSIST_ROOT/iris}"
CONF="${IRIS_AGENT_CONF:-$STAGE_DIR/iris-agent.conf}"
STATE="${IRIS_AGENT_STATE:-$STAGE_DIR/iris-agent.state}"
RPC_PORT="${IRIS_RPC_PORT:-6800}"
TICK="${IRIS_TICK_SECONDS:-60}"
MAX_PEERS="${IRIS_MAX_PEERS:-10}"
TARGET_FS="${IRIS_TARGET_FS:-}"
ARIA2="/opt/iris/bin/aria2c"
AGENT="/opt/iris/agent/iris_agent.py"

export IRIS_STAGE_DIR="$STAGE_DIR"
export IRIS_AGENT_CONF="$CONF"
export IRIS_AGENT_STATE="$STATE"

# Image hand-off to IOS: on C9k the app-hosting SSD share is bind-mounted in
# (IRIS_SHARE_DIR, run-opts -v) and the agent lands its scratch there at disk
# speed for an IOS-internal `copy /verify`; without a share (IE-3x00) it
# scp-pushes the image to <target>guest-share/iris through the device's SCP
# server instead.
mkdir -p "$STAGE_DIR" "$(dirname "$CONF")" "$(dirname "$STATE")"

# --- 1. config: use a dropped conf if present, else synthesize from env ---------
# A conf dropped onto a persistent mount wins (and the agent rewrites it in place
# on token refresh). With no conf (e.g. ephemeral storage / first boot) build one
# from the app-hosting --env knobs. SECRETS (catalog_token, device_ssh_pass) come
# from the environment at deploy time; they are never baked into the image.
if [ ! -f "$CONF" ]; then
  : "${IRIS_CATALOG_URL:?set IRIS_CATALOG_URL to the reachable IRIS catalog URL}"
  : "${IRIS_CATALOG_TOKEN:?set IRIS_CATALOG_TOKEN to this device enrollment token}"
  : "${IRIS_DEVICE_ID:?set IRIS_DEVICE_ID to the catalog device id}"
  : "${IRIS_DEVICE_SSH_HOST:?set IRIS_DEVICE_SSH_HOST to the IOS SSH-to-self address}"
  : "${IRIS_DEVICE_SSH_USER:?set IRIS_DEVICE_SSH_USER to the IOS SSH user}"
  : "${IRIS_DEVICE_SSH_PASS:?set IRIS_DEVICE_SSH_PASS to the IOS SSH password}"
  echo "IRIS-ENTRYPOINT: no conf at $CONF; generating from environment"
  tmp="${CONF}.tmp.$$"
  {
    echo "catalog_url = ${IRIS_CATALOG_URL}"
    echo "catalog_token = ${IRIS_CATALOG_TOKEN}"
    echo "device_id = ${IRIS_DEVICE_ID}"
    echo "stage_dir = ${STAGE_DIR}"
    echo "target_fs = ${TARGET_FS}"
    echo "rpc_secret = "
    echo "catalog_ca = ${IRIS_CATALOG_CA:-/opt/iris/iris-catalog.pem}"
    echo "token_expires_at = 0"
    echo "runtime_mode = container"
    echo "device_ssh_host = ${IRIS_DEVICE_SSH_HOST}"
    echo "device_ssh_user = ${IRIS_DEVICE_SSH_USER}"
    echo "device_ssh_pass = ${IRIS_DEVICE_SSH_PASS}"
    echo "device_ssh_enable = ${IRIS_DEVICE_SSH_ENABLE:-${IRIS_DEVICE_SSH_PASS}}"
    echo "max_peers = ${MAX_PEERS}"
    echo "telemetry = ${IRIS_TELEMETRY:-on}"
    echo "rpc_port = ${RPC_PORT}"
    echo "share_dir = ${IRIS_SHARE_DIR:-}"
    echo "share_ios_path = ${IRIS_SHARE_IOS_PATH:-}"
    echo "agent_version = $(cat /opt/iris/agent/VERSION 2>/dev/null || echo unknown)"
  } > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$CONF"
fi
chmod 600 "$CONF" 2>/dev/null || true

# A persistent config normally wins, but an explicit deployment-time target is
# an operator intent and must also take effect after an app restart/redeploy.
if [ -n "$TARGET_FS" ]; then
  PYTHONPATH=/opt/iris/agent python3 - "$CONF" "$TARGET_FS" <<'PY'
import sys
import agent_config

path, target = sys.argv[1:]
cfg = agent_config.load(path)
agent_config.validate_target_fs(target)
if cfg.get("target_fs") != target:
    cfg["target_fs"] = target
    agent_config.write_conf(path, cfg)
PY
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

AGENT_PID=""
SLEEP_PID=""

stop_agent() {
  trap - TERM INT
  for pid in "$AGENT_PID" "$SLEEP_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  pkill -f 'aria2c.*enable-rpc' 2>/dev/null || true
  for pid in "$AGENT_PID" "$SLEEP_PID"; do
    [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
  done
  exit 0
}

trap stop_agent TERM INT

echo "IRIS-ENTRYPOINT: starting; stage=$STAGE_DIR conf=$CONF tick=${TICK}s"
cur=""
while true; do
  want="$(read_secret)"
  [ -z "$want" ] && want="iris"          # placeholder until the agent fetches the real secret
  if [ "$want" != "$cur" ] || ! pgrep -f 'aria2c.*enable-rpc' >/dev/null 2>&1; then
    start_aria2c "$want" && cur="$want"
  fi
  # Keep foreground work as tracked children. POSIX shells defer traps while a
  # foreground command runs; waiting on a background child lets PID 1 handle
  # TERM immediately instead of making the container wait for the full tick.
  python3 "$AGENT" --once &
  AGENT_PID=$!
  if ! wait "$AGENT_PID"; then
    echo "IRIS-ENTRYPOINT: agent tick returned non-zero"
  fi
  AGENT_PID=""

  sleep "$TICK" &
  SLEEP_PID=$!
  wait "$SLEEP_PID" || true
  SLEEP_PID=""
done
