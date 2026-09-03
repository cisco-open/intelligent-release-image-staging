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
# --on-bt-download-complete: the per-peer transfer-record hook. Baked into the image by
# the Dockerfile (already executable), so unlike the Guest Shell launcher there
# is no copy-to-an-exec-capable-filesystem dance here. Checked once: an image
# built before this existed simply runs without it, and aria2c must not be
# handed an empty option value (Aria2 Next rejects those outright).
HOOK="/opt/iris/agent/peer-transfer-hook.sh"
[ -x "$HOOK" ] || HOOK=""

export IRIS_STAGE_DIR="$STAGE_DIR"
export IRIS_AGENT_CONF="$CONF"
export IRIS_AGENT_STATE="$STATE"
# The hook resolves its RPC endpoint from these; same netns, so 127.0.0.1.
export IRIS_RPC_PORT="$RPC_PORT"

# Image hand-off to IOS: on C9k the app-hosting SSD share is bind-mounted in
# (IRIS_SHARE_DIR, run-opts -v) and the agent lands its scratch there at disk
# speed for an IOS-internal plain `copy`; without a share (IE-3x00) it
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
  # mktemp creates the file without following a pre-created symlink; keep it
  # beside CONF so rename is atomic on the persistent filesystem.
  tmp="$(mktemp "$(dirname "$CONF")/.iris-agent.conf.XXXXXX")"
  chmod 600 "$tmp"
  trap 'rm -f "$tmp"' EXIT HUP INT TERM
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
    echo "telemetry_stream = ${IRIS_TELEMETRY_STREAM:-off}"
    echo "rpc_port = ${RPC_PORT}"
    echo "share_dir = ${IRIS_SHARE_DIR:-}"
    echo "share_ios_path = ${IRIS_SHARE_IOS_PATH:-}"
    echo "agent_version = $(cat /opt/iris/agent/VERSION 2>/dev/null || echo unknown)"
  } > "$tmp"
  mv -f "$tmp" "$CONF"
  trap - EXIT HUP INT TERM
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

# Same operator-intent rule for the telemetry toggles: a console redeploy that
# flips reports or streaming must take effect on a device with an existing
# conf (spec section 5.5) — both keys reconcile, deploy-time env wins.
. "$(dirname "$0")/reconcile.sh"
reconcile_conf_key telemetry "${IRIS_TELEMETRY:-}"
reconcile_conf_key telemetry_stream "${IRIS_TELEMETRY_STREAM:-}"
# agent_version is a fact about the IMAGE, not operator state: after a package
# upgrade a persistent conf still carries the previous build's number and every
# telemetry report mis-states what is actually running (field observation
# 2026-08-20: the 3400 kept reporting 2026.07.26 from a pre-release-cut
# package). The baked VERSION file wins on every start.
reconcile_conf_key agent_version \
  "$(cat /opt/iris/agent/VERSION 2>/dev/null || echo unknown)"

# --- 2/3. aria2c supervisor + agent tick loop ----------------------------------
read_secret() {
  sed -n 's/^[[:space:]]*rpc_secret[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null \
    | tr -d '[:space:]'
}

# aria2c is owned by exact PID, never by process-name matching: it runs as a
# tracked background child of this PID-1 shell (no --daemon=true, which would
# double-fork and setsid() it out of reach), and ARIA2_PID plus the child's
# /proc starttime are the identity everything below acts on. That is what lets
# the image drop procps (pgrep/pkill) altogether.
ARIA2_PID=""
ARIA2_START=""

proc_stat() {
  # Sets PROC_STATE / PROC_START (state letter, starttime -- /proc/<pid>/stat
  # fields 3 and 22); fails once the PID is gone. comm (field 2) may contain
  # spaces, so split after the LAST ") ". Builtins only: no fork, so the check
  # itself can never reap the zombie it is about to report.
  read -r _stat 2>/dev/null < "/proc/$1/stat" || return 1
  set -- ${_stat##*) }
  PROC_STATE="${1:-}"; PROC_START="${20:-}"
}

aria2_alive() {
  # Alive means: the recorded PID exists, is the process we started (same
  # starttime -- a recycled PID number belongs to somebody else and must never
  # be signalled), and has not exited. A zombie still passes kill -0, which is
  # why the state letter decides; stop_aria2c's wait is what reaps it.
  [ -n "$ARIA2_PID" ] || return 1
  proc_stat "$ARIA2_PID" || return 1
  [ "$PROC_START" = "$ARIA2_START" ] || return 1
  case "$PROC_STATE" in Z|X) return 1 ;; esac
}

stop_aria2c() {
  # TERM first -- aria2c saves its .aria2 control files on TERM, so an
  # interrupted download resumes on the next start -- then a bounded wait,
  # then KILL. CONT rides along because a stopped child cannot act on TERM.
  # wait(1) reaps the child, so PID 1 never leaves a zombie behind.
  if aria2_alive; then
    kill -TERM "$ARIA2_PID" 2>/dev/null || true
    kill -CONT "$ARIA2_PID" 2>/dev/null || true
    _w=0
    while aria2_alive && [ "$_w" -lt 5 ]; do
      sleep 1; _w=$((_w + 1))
    done
    if aria2_alive; then kill -KILL "$ARIA2_PID" 2>/dev/null || true; fi
  fi
  # Reap only our own child (already gone, or still ours by starttime): a
  # recycled PID number can be a running process re-parented to PID 1, and
  # wait(1) on that would block the supervisor for as long as it lives.
  [ -n "$ARIA2_PID" ] || return 0
  if ! proc_stat "$ARIA2_PID" || [ "$PROC_START" = "$ARIA2_START" ]; then
    wait "$ARIA2_PID" 2>/dev/null || true
  fi
  ARIA2_PID=""; ARIA2_START=""
}

start_aria2c() {
  secret="$1"
  stop_aria2c
  # Hand the hook the secret this daemon is being started with, by inheritance
  # through aria2c's fork. Deliberately not re-read from $CONF: the agent
  # rewrites that file on every token refresh, and a hook reading a secret the
  # running daemon has already moved off is precisely the file-vs-daemon skew
  # of the 2026-08-20 incident. This supervisor relaunches aria2c whenever the
  # secret changes, so the exported value tracks the daemon by construction.
  IRIS_RPC_SECRET="$secret"; export IRIS_RPC_SECRET
  # Positional args carry the optional hook flag: aria2c must never be handed
  # --on-bt-download-complete= with an empty value. "$secret" is already saved
  # above, so reusing $@ here is safe.
  set --
  case "${HOOK:-}" in ?*) set -- "--on-bt-download-complete=$HOOK" ;; esac
  # A tracked child with its stdio on /dev/null -- exactly what --daemon=true's
  # daemon(0,0) did, minus the double fork. The redirect is not optional:
  # aria2c writes a progress readout line every second, to a pipe as readily
  # as to a terminal, for as long as anything is downloading OR seeding, and a
  # staged device seeds indefinitely -- that would flood the app log. The
  # aria2c options themselves are unchanged.
  # --check-integrity=true is a RESUME guard. Without it aria2 trusts the piece
  # map recorded in the .aria2 control file, so a completed piece that rotted
  # on flash (bit-rot, a torn write during a power loss) survives the resume:
  # the torrent reports complete and the staged image carries the wrong
  # SHA-256. The agent's whole-image hash still catches that, but only after
  # the whole remaining transfer, and the repair is then a full re-stage
  # instead of one 1 MiB piece.
  #
  # It sits on the launch line rather than being plumbed per download because
  # in aria2's own code (RequestGroup.cc, createInitialCommand for BitTorrent)
  # the launch flag ALREADY costs nothing on the two paths that are not a
  # resume:
  #   * nothing on disk yet -- every piece read returns 0 bytes, throws, and
  #     the piece is marked missing at once; no I/O, no hashing.
  #   * a COMPLETED file being re-added to seed -- --bt-seed-unverified=true
  #     above marks every piece done, and aria2 then takes the
  #     onDownloadFinished branch, skipping validation entirely. A device
  #     seeding ten staged images does not re-hash them on a relaunch.
  # So the read-back is paid exactly where the corruption can hide: over the
  # bytes an interrupted transfer already put on flash.
  "$ARIA2" \
    --enable-rpc=true --rpc-listen-all=false \
    --rpc-listen-port="$RPC_PORT" --rpc-secret="$secret" \
    --enable-dht=false --enable-peer-exchange=false --bt-enable-lpd=false \
    --bt-max-peers="$MAX_PEERS" --bt-seed-unverified=true --seed-ratio=0.0 \
    --check-integrity=true \
    --max-concurrent-downloads="${IRIS_MAX_CONCURRENT:-100}" \
    "$@" \
    --file-allocation=none --dir="$STAGE_DIR" \
    --log-level=warn --summary-interval=0 \
    </dev/null >/dev/null 2>&1 &
  ARIA2_PID=$!
  # starttime is fixed at fork and survives the exec, so it can be read right
  # away; it is what makes this PID *ours* on every later check.
  ARIA2_START=""
  if proc_stat "$ARIA2_PID"; then ARIA2_START="$PROC_START"; fi
  echo "IRIS-ENTRYPOINT: aria2c (re)started on :$RPC_PORT (pid $ARIA2_PID)"
}

# Health-probe bounds, in seconds. They are two different questions and the
# split is the whole point of this probe:
#   * --connect-timeout answers "is anything bound to the RPC port". On
#     loopback that is decided instantly -- a daemon that is gone gets the
#     connection REFUSED (curl exit 7), a daemon that is merely busy still
#     owns its listen socket, so the kernel completes the connection for it.
#   * --max-time bounds the wait for the ANSWER, and must sit well above the
#     longest stall a HEALTHY aria2c can have. Built without c-ares, aria2c
#     resolves tracker hostnames with a blocking getaddrinfo() on its
#     event-loop thread: one announce against a slow or unresponsive resolver
#     freezes the entire daemon -- RPC replies included -- for as long as the
#     resolver takes. Measured at 5.03 s (a blackholed forwarder), and the
#     glibc default of 5 s x 2 attempts is the ceiling to design for.
RPC_CONNECT_TIMEOUT=2
RPC_HEALTH_TIMEOUT=10

rpc_probe() {
  # One probe; the caller reads curl's own exit status (0 answered, 7 nothing
  # listening, 28 connected but no answer inside the bound, anything else a
  # transport failure mid-request). Run as a tracked background child and
  # waited on, for the same reason the tick's sleep is: a POSIX shell defers
  # traps while a FOREGROUND command runs, and PID 1 must never make the
  # container wait out a probe before it can act on TERM.
  curl -s --connect-timeout "$RPC_CONNECT_TIMEOUT" --max-time "$RPC_HEALTH_TIMEOUT" \
    "http://127.0.0.1:$RPC_PORT/jsonrpc" \
    -d '{"jsonrpc":"2.0","id":"h","method":"aria2.getVersion","params":["token:'"$1"'"]}' \
    >/dev/null 2>&1 &
  _probe_pid=$!
  _probe_rc=0
  wait "$_probe_pid" || _probe_rc=$?
  return "$_probe_rc"
}

rpc_healthy() {
  # Liveness is not health: an aria2c that is running but not answering RPC
  # blocks its own relaunch, and the agent then fails every tick on
  # ECONNREFUSED without ever heartbeating (field incident 2026-08-20, Guest
  # Shell; this supervisor had the identical condition). Ask the RPC itself.
  #
  # But a SLOW answer is not a dead daemon, and one curl with a 3 s bound
  # could not tell those apart: any overrun read as "kill it", so a daemon
  # stalled in getaddrinfo (see the bounds above) was killed and relaunched
  # while perfectly healthy -- twice in 300 s under one measured DNS stall,
  # its in-flight download dropped from the daemon each time. Two things
  # separate busy from dead here:
  #   * WHERE the probe failed. Connection refused means nothing is listening;
  #     that is a verdict on its own and must relaunch AT ONCE, because
  #     waiting there is exactly the 2026-08-20 deadlock. Any other failure
  #     only says the answer was late, which is a suspicion, not a verdict.
  #   * A SECOND probe. A resolver stall ends when the resolver gives up, so
  #     the retry gets through; a genuinely wedged daemon fails it too.
  _rc=0
  rpc_probe "$1" || _rc=$?
  case "$_rc" in
    0) return 0 ;;
    7) return 1 ;;
  esac
  # Any verdict this function returns is a plain healthy/unhealthy, never
  # curl's own status: the supervisor loop asks a yes/no question.
  rpc_probe "$1" || return 1
}

AGENT_PID=""
SLEEP_PID=""

stop_agent() {
  trap - TERM INT
  for pid in "$AGENT_PID" "$SLEEP_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  stop_aria2c
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
     || ! aria2_alive \
     || ! rpc_healthy "$want"; then
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
