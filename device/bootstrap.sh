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
SRC="${SRC:-/flash/guest-share}"
STAGE="${STAGE:-$SRC/iris}"

# 0. collect freshly dropped files into OUR (guest-owned) working dir
mkdir -p "$STAGE" 2>/dev/null || true
for f in bundle.tgz iris-agent.conf rpc-secret iris-catalog.pem; do
  if [ -f "$SRC/$f" ]; then
    mv -f "$SRC/$f" "$STAGE/$f" 2>/dev/null \
      || { cp -f "$SRC/$f" "$STAGE/$f" && rm -f "$SRC/$f"; } 2>/dev/null || true
  fi
done

# 1. unpack a newly dropped bundle, then remove it
if [ -f "$STAGE/bundle.tgz" ]; then
  if tar xzf "$STAGE/bundle.tgz" -C "$STAGE" --no-same-owner --no-same-permissions -m; then
    rm -f "$STAGE/bundle.tgz"
    # the bundle ships a (possibly newer) bootstrap — self-update the live copy
    cp -f "$STAGE/bootstrap.sh" "$SRC/bootstrap.sh" 2>/dev/null || true
  fi
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

# 3. keep the BitTorrent daemon up
if [ -f "$STAGE/guestshell-start.sh" ]; then
  pgrep -f 'aria2c.*enable-rpc' >/dev/null 2>&1 || bash "$STAGE/guestshell-start.sh"
fi

# 4. trim the aria2c log so it never fills flash (Guest Shell mode)
[ -f "$STAGE/rotate-logs.sh" ] && bash "$STAGE/rotate-logs.sh" "$STAGE/aria2c.log" || true

# 5. run the agent control plane once
if [ -f "$STAGE/agent/iris_agent.py" ]; then
  exec python3 "$STAGE/agent/iris_agent.py" --once
fi
