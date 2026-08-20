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
  cp -f "$STAGE/bootstrap.sh" "$SRC/bootstrap.sh" \
    || { echo "IRIS-BOOTSTRAP: failed to update $SRC/bootstrap.sh" >&2; exit 1; }
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
if [ -f "$STAGE/guestshell-start.sh" ]; then
  bash "$STAGE/guestshell-start.sh" \
    || { echo "IRIS-BOOTSTRAP: failed to launch aria2c" >&2; exit 1; }
fi

# 4. trim the aria2c log so it never fills flash (Guest Shell mode)
if [ -f "$STAGE/rotate-logs.sh" ]; then
  bash "$STAGE/rotate-logs.sh" "$STAGE/aria2c.log" \
    || { echo "IRIS-BOOTSTRAP: log rotation failed" >&2; exit 1; }
fi

# 5. run the agent control plane once
if [ -f "$STAGE/agent/iris_agent.py" ]; then
  exec python3 "$STAGE/agent/iris_agent.py" --once
fi
[ "$bundle_updated" -eq 0 ] || {
  echo "IRIS-BOOTSTRAP: unpacked bundle lacks $STAGE/agent/iris_agent.py" >&2
  exit 1
}
