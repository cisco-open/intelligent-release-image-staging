#!/bin/sh

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# PID 1 for the IRIS XR appmgr Docker app (Cisco 8000 series, IOS-XR).
# The container is activated with "--net=host -v /misc/disk1:/hostmount";
# that bind mount IS harddisk: (hardware-proven write-through, see
# agentinfo/xr-support/LAB-RESULTS-2026-08-27.md). There is no placement
# step: aria2c downloads an image straight to its final harddisk: location,
# and the agent hashes the same bytes it seeds. This entrypoint:
#   1. ensure the stage/work dirs + a config file exist (generate conf from
#      env on first boot if none is present -- a dropped conf wins, same
#      convention device/iox/entrypoint.sh uses for its persistent mount),
#   2. keep aria2c running as the BT RPC daemon, re-seeding its rpc-secret
#      when the agent rotates it,
#   3. run the agent control plane once every tick (the existing --once path).
set -eu
umask 077

# /hostmount is the bind-mounted harddisk: -- stage dir IS the final dir.
# iris-work/ holds IRIS's own control files (conf, state) so they never
# collide with operator-owned files at the harddisk root; images land
# directly in $STAGE_DIR under their catalog filename, with aria2's .aria2
# sidecar alongside (removed by aria2 on completion).
STAGE_DIR="${IRIS_STAGE_DIR:-/hostmount}"
WORK_DIR="${IRIS_WORK_DIR:-$STAGE_DIR/iris-work}"
CONF="${IRIS_AGENT_CONF:-/etc/iris/iris-agent.conf}"
STATE="${IRIS_AGENT_STATE:-$WORK_DIR/iris-agent.state}"
RPC_PORT="${IRIS_RPC_PORT:-6800}"
TICK="${IRIS_TICK_SECONDS:-60}"
MAX_PEERS="${IRIS_MAX_PEERS:-10}"
ARIA2="/opt/iris/bin/aria2c"
AGENT="/opt/iris/agent/iris_agent.py"
# --on-bt-download-complete: the per-peer receipt hook. Baked into the image
# by the Dockerfile (already executable). Checked once: an image built
# before this existed simply runs without it, and aria2c must not be handed
# an empty option value (Aria2 Next rejects those outright).
HOOK="/opt/iris/agent/peer-receipt-hook.sh"
[ -x "$HOOK" ] || HOOK=""

export IRIS_STAGE_DIR="$STAGE_DIR"
export IRIS_AGENT_CONF="$CONF"
export IRIS_AGENT_STATE="$STATE"
# The hook resolves its RPC endpoint from this; same netns, so 127.0.0.1.
export IRIS_RPC_PORT="$RPC_PORT"

mkdir -p "$STAGE_DIR" "$WORK_DIR" "$(dirname "$CONF")" "$(dirname "$STATE")"

# --- 1. config: use a dropped conf if present, else synthesize from env ---------
# A conf dropped at $CONF wins (and the agent rewrites it in place on token
# refresh). With no conf (first boot / a recreated container) build one from
# the appmgr docker-run-opts --env knobs. SECRETS (catalog_token) come from
# the environment at activation time; they are never baked into the image.
if [ ! -f "$CONF" ]; then
  : "${IRIS_CATALOG_URL:?set IRIS_CATALOG_URL to the reachable IRIS catalog URL}"
  : "${IRIS_CATALOG_TOKEN:?set IRIS_CATALOG_TOKEN to this device enrollment token}"
  : "${IRIS_DEVICE_ID:?set IRIS_DEVICE_ID to the catalog device id}"
  echo "IRIS-ENTRYPOINT: no conf at $CONF; generating from environment"
  # mktemp creates the file without following a pre-created symlink; keep it
  # beside CONF so rename is atomic on the same filesystem.
  tmp="$(mktemp "$(dirname "$CONF")/.iris-agent.conf.XXXXXX")"
  chmod 600 "$tmp"
  trap 'rm -f "$tmp"' EXIT HUP INT TERM
  {
    echo "catalog_url = ${IRIS_CATALOG_URL}"
    echo "catalog_token = ${IRIS_CATALOG_TOKEN}"
    echo "device_id = ${IRIS_DEVICE_ID}"
    # No CLI on this platform to ask show version for these (that's the whole
    # reason XR is a container, not a Guest Shell) -- xr_deps.py's
    # _conf_fact() reads them straight from the conf instead. Set by the
    # onboard flow (device/xr-install.sh: MODEL from the fleet row, VERSION
    # parsed from its own preflight "show version"); an empty value here
    # keeps xr_deps.py's honest model=None/version="unknown" default.
    echo "device_model = ${IRIS_MODEL:-}"
    echo "device_version = ${IRIS_VERSION:-}"
    echo "stage_dir = ${STAGE_DIR}"
    # Fixed for this platform: /hostmount IS harddisk: (the bind mount), and
    # there is no other writable target on an XR appmgr container.
    echo "target_fs = harddisk:"
    # Dispatch key: selects xr_deps.build_deps() over the IOS-XE build_deps().
    echo "mode = xr"
    echo "rpc_secret = "
    echo "catalog_ca = ${IRIS_CATALOG_CA:-/opt/iris/iris-catalog.pem}"
    echo "token_expires_at = 0"
    echo "max_peers = ${MAX_PEERS}"
    echo "telemetry = ${IRIS_TELEMETRY:-on}"
    echo "telemetry_stream = ${IRIS_TELEMETRY_STREAM:-off}"
    echo "rpc_port = ${RPC_PORT}"
    echo "agent_version = $(cat /opt/iris/agent/VERSION 2>/dev/null || echo unknown)"
  } > "$tmp"
  mv -f "$tmp" "$CONF"
  trap - EXIT HUP INT TERM
fi
chmod 600 "$CONF" 2>/dev/null || true

# A console redeploy that flips telemetry/streaming is operator intent and
# must take effect even on an existing conf (same rule
# device/iox/entrypoint.sh applies via its reconcile.sh). Kept inline here
# rather than sourced from device/iox/ -- this image is self-contained.
reconcile_conf_key() {
  key="$1"; val="$2"
  [ -n "$val" ] || return 0
  PYTHONPATH="${PYTHONPATH:-/opt/iris/agent}" python3 - "$CONF" "$key" "$val" <<'PY'
import sys
import agent_config

path, key, val = sys.argv[1:]
cfg = agent_config.load(path)
if cfg.get(key) != val:
    cfg[key] = val
    agent_config.write_conf(path, cfg)
PY
}
reconcile_conf_key telemetry "${IRIS_TELEMETRY:-}"
reconcile_conf_key telemetry_stream "${IRIS_TELEMETRY_STREAM:-}"
# agent_version is a fact about the IMAGE, not operator state: after a
# package upgrade a persistent conf still carries the previous build's
# number and every telemetry report mis-states what is actually running.
# The baked VERSION file wins on every start (same rule as IOx).
reconcile_conf_key agent_version \
  "$(cat /opt/iris/agent/VERSION 2>/dev/null || echo unknown)"
# target_fs/stage_dir are facts about THIS PLATFORM, not operator-tunable
# state (same rationale as agent_version, above) -- and they must be
# force-reconciled every boot for a different reason too: agent_config.py's
# DEFAULTS dict is tuned for IOx (stage_dir="/flash/guest-share/iris",
# target_fs="" = auto-detect), and agent_config.load() silently backfills
# any key missing from an on-disk conf with that IOx default, then the
# unconditional agent_version reconcile just above rewrites the WHOLE file
# via write_conf() -- persisting the backfilled IOx value to disk. A
# minimal dropped conf that omits target_fs/stage_dir (both documented
# "optional" by agent_config.py, and exactly the shape the dropped-conf-wins
# bats fixture below uses) would otherwise have its forced
# "target_fs = harddisk:" silently undone on the very next boot. Forcing
# both here, unconditionally, closes that loop the same way agent_version
# does.
reconcile_conf_key target_fs harddisk:
reconcile_conf_key stage_dir "$STAGE_DIR"

# --- 2/3. aria2c supervisor + agent tick loop ----------------------------------
read_secret() {
  sed -n 's/^[[:space:]]*rpc_secret[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null \
    | tr -d '[:space:]'
}

start_aria2c() {
  secret="$1"
  pkill -f 'aria2c.*enable-rpc' 2>/dev/null || true
  sleep 1
  # Hand the hook the secret this daemon is being started with, by
  # inheritance through aria2c's fork -- deliberately not re-read from
  # $CONF, which the agent rewrites on every token refresh (see the
  # matching comment in device/iox/entrypoint.sh for the incident this
  # avoids).
  IRIS_RPC_SECRET="$secret"; export IRIS_RPC_SECRET
  # Positional args carry the optional hook flag: aria2c must never be
  # handed --on-bt-download-complete= with an empty value.
  set --
  case "${HOOK:-}" in ?*) set -- "--on-bt-download-complete=$HOOK" ;; esac
  "$ARIA2" \
    --daemon=true --enable-rpc=true --rpc-listen-all=false \
    --rpc-listen-port="$RPC_PORT" --rpc-secret="$secret" \
    --enable-dht=false --enable-peer-exchange=false --bt-enable-lpd=false \
    --bt-max-peers="$MAX_PEERS" --bt-seed-unverified=true --seed-ratio=0.0 \
    "$@" \
    --file-allocation=none --dir="$STAGE_DIR" \
    --log-level=warn --summary-interval=0 \
    && echo "IRIS-ENTRYPOINT: aria2c (re)started on :$RPC_PORT"
}

rpc_healthy() {
  # Liveness is not health: an aria2c that is running but not answering RPC
  # blocks its own relaunch (field incident 2026-08-20, see IOx entrypoint).
  # Ask the RPC itself.
  curl -s --max-time 3 "http://127.0.0.1:$RPC_PORT/jsonrpc" \
    -d '{"jsonrpc":"2.0","id":"h","method":"aria2.getVersion","params":["token:'"$1"'"]}' \
    >/dev/null 2>&1
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
  if [ "$want" != "$cur" ] \
     || ! pgrep -f 'aria2c.*enable-rpc' >/dev/null 2>&1 \
     || ! rpc_healthy "$want"; then
    start_aria2c "$want" && cur="$want"
  fi
  # Keep foreground work as tracked children. POSIX shells defer traps while
  # a foreground command runs; waiting on a background child lets PID 1
  # handle TERM immediately instead of making the container wait for the
  # full tick.
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
