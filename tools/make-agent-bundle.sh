#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Build the IRIS device-agent bundle (iris-agent.tgz) that each
# device downloads during install. Friendly + interactive; when it's not run from
# a terminal it just uses the defaults so it still works in scripts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEVICE="$REPO_ROOT/device"
ARIA2="$REPO_ROOT/bin/aria2c"

say() { printf '%s\n' "$*"; }
ask() {                      # ask "Question" "default"  ->  prints the answer
  local q="$1" def="$2" ans=""
  if [ -t 0 ]; then read -rp "$q [$def]: " ans || true; fi
  printf '%s' "${ans:-$def}"
}

say ""
say "================================================================"
say " IRIS — build the device agent bundle"
say "================================================================"
say " This packs the agent (Python + the aria2c program) into ONE"
say " file. You serve that file from a little web page, and each"
say " device grabs it during install with an IOS 'copy https://...'"
say " command. You only do this once per new agent version."
say ""

# ---- 1. make sure every piece is present ----------------------------------
missing=0
for f in "$DEVICE/agent/iris_agent.py" "$DEVICE/agent/catalog_client.py" \
         "$DEVICE/agent/flashcheck.py" "$DEVICE/agent/flash_target.py" \
         "$DEVICE/agent/agent_config.py" \
         "$DEVICE/verify_image.py" \
         "$DEVICE/bootstrap.sh" \
         "$DEVICE/guestshell-start.sh" "$DEVICE/rotate-logs.sh"; do
  [ -f "$f" ] || { say "  missing: $f"; missing=1; }
done
if [ ! -f "$ARIA2" ]; then
  # try to borrow the binary from the built server image first (no extra download)
  if command -v docker >/dev/null 2>&1 && docker image inspect iris:latest >/dev/null 2>&1; then
    say "  bin/aria2c missing — extracting it from the iris:latest image..."
    mkdir -p "$(dirname "$ARIA2")"
    cid="$(docker create iris:latest)"
    docker cp "$cid:/opt/iris/bin/aria2c" "$ARIA2" >/dev/null
    docker rm "$cid" >/dev/null
    chmod +x "$ARIA2"
    say "  got it."
  else
    say "  The aria2c program is not here yet (bin/aria2c), and no iris:latest"
    say "  docker image to borrow it from. Either build the server image first, or"
    say "  run  tools/get-aria2c.sh  — then start me again."
    missing=1
  fi
fi
if [ "$missing" -eq 1 ]; then
  say ""; say "Please fix the item(s) above and run me again."; exit 1
fi

# ---- 2. where to save it ---------------------------------------------------
# default: the artifacts/ dir — the server container serves it on :8000 automatically
DEFAULT_OUT="$REPO_ROOT/artifacts/iris-agent.tgz"
OUT="$(ask "Where should I save the finished bundle?" "$DEFAULT_OUT")"
mkdir -p "$(dirname "$OUT")"

# ---- 3. pack it (in the exact layout the device expects) -------------------
# Delegates to server/pack-agent-bundle.sh — the ONE packer, also used by the
# container's startup self-provisioning, so the served bundle never drifts.
say ""
say "Packing the bundle..."
"$REPO_ROOT/server/pack-agent-bundle.sh" "$DEVICE" "$ARIA2" "$OUT"

# also place the bootstrap next to it — the installer fetches both from :8000
cp "$DEVICE/bootstrap.sh" "$(dirname "$OUT")/bootstrap.sh"

SIZE="$(du -h "$OUT" | awk '{print $1}')"
HOST_IP="$( (hostname -I 2>/dev/null | awk '{print $1}') || ipconfig getifaddr en0 2>/dev/null || true )"
[ -z "${HOST_IP:-}" ] && HOST_IP="<this-host-ip>"
say "  Done:  $OUT  ($SIZE)"
say ""
say "The server container serves this directory on :8000 automatically — nothing"
say "to start. Devices will fetch it from:"
say "    https://$HOST_IP:8000/$(basename "$OUT")"
say ""
