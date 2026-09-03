#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# IRIS bootstrap — run by the IRIS-AGENT EEM timer (60s) inside Guest Shell.
# Self-contained and idempotent; this is the ONLY thing the installer needs to start.
#
# The installer drops files (bundle.tgz, iris-agent.conf, rpc-secret, this script)
# at the guest-share ROOT via IOS copy. Directories created by IOS `mkdir` are
# root-owned and the guest user cannot write into them (SELinux mount), so THIS
# script — running as the guest user — creates the working dir itself and moves
# the dropped files in. Then:
#   1. a freshly dropped bundle.tgz is unpacked (SELinux-safe flags)
#      -> dropping a new bundle on the device IS the agent install/upgrade.
#   2. the aria2c RPC daemon is (re)launched if it isn't running.
#   3. the agent runs once (poll catalog -> download -> verify -> EEM copy-to-root).
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$SCRIPT_DIR" in
  */guest-share) DEFAULT_SRC="$SCRIPT_DIR" ;;
  *) DEFAULT_SRC="/flash/guest-share" ;;
esac
SRC="${SRC:-$DEFAULT_SRC}"
STAGE="${STAGE:-$SRC/iris}"
export STAGE_DIR="${STAGE_DIR:-$STAGE}"
export IRIS_AGENT_CONF="${IRIS_AGENT_CONF:-$STAGE/iris-agent.conf}"
export IRIS_AGENT_STATE="${IRIS_AGENT_STATE:-$STAGE/iris-agent.state}"

# --- cadence jitter + failure backoff (issue #59) -------------------------
# The EEM watchdog fires this script every 60s on IOS's own clock -- fixed,
# not ours to jitter -- so a fleet installed or reloaded together keeps every
# device's timer in the same phase indefinitely: that is what turns an
# ordinary tick into a fleet-wide burst of policy GETs, heartbeats, and
# tracker re-announces. Two independent, small guards:
#   * JITTER_MAX: a per-tick sleep (0..JITTER_MAX-1s, uniform) right before
#     step 5 spreads the ACTUAL catalog contact within the tick, so
#     simultaneous EEM fires do not turn into a simultaneous burst.
#   * BACKOFF_FILE: after the agent fails outright (catalog unreachable,
#     timed out, or a non-2xx status -- the same shape a saturated server
#     produces), step 5 is SKIPPED on some ticks, exponentially longer up to
#     BACKOFF_MAX, without the EEM timer's own cadence changing. Steps 0-4
#     (local bundle/aria2c/log upkeep) still run every tick regardless --
#     only catalog contact backs off. Bounded well inside the token's
#     multi-day refresh slack (iris_agent.py's needs_refresh docstring), so
#     a run of skipped ticks never strands the device.
JITTER_MAX="${IRIS_TICK_JITTER_MAX:-8}"
BACKOFF_MAX="${IRIS_TICK_BACKOFF_MAX:-600}"
BACKOFF_FILE="$STAGE/.iris-tick-backoff"

# rand_below N -- uniform 0..N-1. python3 is already a hard dependency of
# step 5 below.
rand_below() {
  python3 -c 'import random,sys; print(random.randrange(int(sys.argv[1])))' "$1"
}

# 0. collect freshly dropped files into OUR (guest-owned) working dir
mkdir -p "$STAGE" || { echo "IRIS-BOOTSTRAP: cannot create stage directory $STAGE" >&2; exit 1; }
for f in bundle.tgz iris-agent.conf rpc-secret iris-catalog.pem; do
  if [ -f "$SRC/$f" ]; then
    if ! mv -f "$SRC/$f" "$STAGE/$f"; then
      # IOS guest-share and the guest-owned stage can be separate filesystems.
      cp -f "$SRC/$f" "$STAGE/$f" \
        || { echo "IRIS-BOOTSTRAP: failed to copy $SRC/$f into $STAGE" >&2; exit 1; }
      rm -f "$SRC/$f" \
        || { echo "IRIS-BOOTSTRAP: copied $f but failed to remove its source" >&2; exit 1; }
    fi
  fi
done

# 1. unpack a newly dropped bundle, then remove it
bundle_updated=0
if [ -f "$STAGE/bundle.tgz" ]; then
  tar xzf "$STAGE/bundle.tgz" -C "$STAGE" --no-same-owner --no-same-permissions -m \
    || { echo "IRIS-BOOTSTRAP: failed to unpack $STAGE/bundle.tgz" >&2; exit 1; }
  rm -f "$STAGE/bundle.tgz"
  # The bundle ships a (possibly newer) bootstrap — do not hide a failed update.
  # $SRC/bootstrap.sh is THIS script, still being read by the running bash.
  # `cp -f` rewrites the same inode, so the interpreter would continue at its
  # old byte offset inside the NEW content and execute whatever token lands
  # there (reproduced: a comment fragment as a command, then a mid-file
  # re-run). Write beside it and rename over it instead: rename swaps the
  # directory entry to a new inode and this process keeps reading the old one
  # untouched. Same idiom guestshell-start.sh uses for the hook.
  if [ -f "$STAGE/bootstrap.sh" ]; then
    cp -f "$STAGE/bootstrap.sh" "$SRC/bootstrap.sh.new" \
      && mv -f "$SRC/bootstrap.sh.new" "$SRC/bootstrap.sh" \
      || { rm -f "$SRC/bootstrap.sh.new"
           echo "IRIS-BOOTSTRAP: failed to update $SRC/bootstrap.sh" >&2; exit 1; }
  fi
  bundle_updated=1
fi

# 2. reconcile aria2c's RPC secret with the one the agent uses.
# The installer bakes rpc-secret EMPTY; the agent fetches the real value on its
# first token-refresh and writes it into iris-agent.conf. guestshell-start.sh
# seeds aria2c from the rpc-secret FILE, so sync the file from the conf and
# bounce a stale aria2c — otherwise aria2c runs with the wrong secret and the
# agent's addTorrent is rejected (the device never joins the swarm).
if [ -f "$STAGE/iris-agent.conf" ]; then
  conf_sec="$(sed -n 's/^[[:space:]]*rpc_secret[[:space:]]*=[[:space:]]*//p' \
                "$STAGE/iris-agent.conf" | tr -d '[:space:]')"
  file_sec="$(tr -d '[:space:]' < "$STAGE/rpc-secret" 2>/dev/null || true)"
  if [ -n "$conf_sec" ] && [ "$conf_sec" != "$file_sec" ]; then
    printf '%s\n' "$conf_sec" > "$STAGE/rpc-secret"
    pkill -f 'aria2c.*enable-rpc' 2>/dev/null || true   # relaunched below with the new secret
    # wait for the dying process so pgrep in step 3 does not see it and skip the relaunch
    _w=0
    while pgrep -f 'aria2c.*enable-rpc' >/dev/null 2>&1 && [ "$_w" -lt 5 ]; do
      sleep 1; _w=$((_w + 1))
    done
    unset _w
  fi
fi

# 3. keep the BitTorrent daemon up.
# Delegate unconditionally: guestshell-start.sh is idempotent — it probes the
# RPC first and exits 0 when aria2c is already SERVING. Gating this on
# `pgrep aria2c` instead (process existence) deadlocked devices in the field
# (2026-08-20): an aria2c that was alive but not answering RPC blocked its own
# relaunch, so the agent hit ECONNREFUSED on every 60s tick and crashed before
# its first heartbeat — invisible until the stale process happened to die.
# Health, not liveness, is the thing worth checking.
# A FAILED launch must not abort bootstrap: the agent (step 5) is the device's
# only path back to the catalog, so exiting here turns any aria2c launch
# regression into a silent device (the 2026-08-20 empty-rpc-secret incident
# was invisible for exactly this reason). Record the failure and continue —
# the agent tolerates a down RPC and heartbeats stage_error instead.
if [ -f "$STAGE/guestshell-start.sh" ]; then
  if bash "$STAGE/guestshell-start.sh"; then
    rm -f "$STAGE/aria2c-launch-failed"
  else
    echo "IRIS-BOOTSTRAP: failed to launch aria2c; continuing so the agent still heartbeats" >&2
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "$STAGE/aria2c-launch-failed" 2>/dev/null || :
  fi
fi

# 4. trim the aria2c log so it never fills flash (Guest Shell mode)
# Rotation is ancillary maintenance: a permissions/mktemp/filesystem error
# here must not stop step 5 — the agent is the device's only path back to the
# catalog (same rationale as the daemon-launch handling above), so warn and
# keep going rather than silencing the device on every EEM tick.
if [ -f "$STAGE/rotate-logs.sh" ]; then
  bash "$STAGE/rotate-logs.sh" "$STAGE/aria2c.log" \
    || echo "IRIS-BOOTSTRAP: log rotation failed; continuing so the agent still heartbeats" >&2
fi

# 5. run the agent control plane once -- jittered, and skipped while backing
#    off from a recent failure (see the block near the top of this script).
if [ -f "$STAGE/agent/iris_agent.py" ]; then
  now="$(date +%s)"
  skip_until=0; streak=0
  if [ -f "$BACKOFF_FILE" ]; then
    read -r skip_until streak < "$BACKOFF_FILE" 2>/dev/null || { skip_until=0; streak=0; }
  fi
  case "$skip_until" in ''|*[!0-9]*) skip_until=0 ;; esac
  case "$streak" in ''|*[!0-9]*) streak=0 ;; esac
  if [ "$now" -lt "$skip_until" ]; then
    echo "IRIS-BOOTSTRAP: backing off catalog contact for $((skip_until - now))s more (failure streak $streak)"
    exit 0
  fi
  jitter="$(rand_below "$JITTER_MAX" 2>/dev/null || echo 0)"
  [ "$jitter" -le 0 ] || sleep "$jitter"
  # Not `exec`: this process needs the exit status back to update the
  # backoff file below, so it must remain a plain wait-able child call.
  python3 "$STAGE/agent/iris_agent.py" --once
  agent_status=$?
  if [ "$agent_status" -eq 0 ]; then
    rm -f "$BACKOFF_FILE"
  else
    streak=$((streak + 1))
    [ "$streak" -le 10 ] || streak=10   # 2**10 * 60s is already far past BACKOFF_MAX
    mult=1; i=0
    while [ "$i" -lt "$streak" ]; do mult=$((mult * 2)); i=$((i + 1)); done
    delay=$((60 * mult))
    [ "$delay" -le "$BACKOFF_MAX" ] || delay="$BACKOFF_MAX"
    printf '%s %s\n' "$(($(date +%s) + delay))" "$streak" > "$BACKOFF_FILE"
  fi
  exit "$agent_status"
fi
[ "$bundle_updated" -eq 0 ] || {
  echo "IRIS-BOOTSTRAP: unpacked bundle lacks $STAGE/agent/iris_agent.py" >&2
  exit 1
}
