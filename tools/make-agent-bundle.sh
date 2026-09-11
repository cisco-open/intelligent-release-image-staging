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
EXPECTED_ARIA2_ARCH="x86-64"
MANIFEST_ARCH="x86_64"
ARCH="amd64"
ARIA2_EXPLICIT=0
OUT=""
ROOTS="${IRIS_INSTRUCTION_ROOTS_DIR:-${IRIS_CONFIG:-/etc/iris}/instr/roots.d}"
usage() {
  echo "usage: $0 [--arch amd64|arm64] [--aria2 /path/to/aria2c] [--out output.tgz] [--instruction-roots-dir DIR]"
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --arch|--aria2|--out|--instruction-roots-dir)
      [ "$#" -ge 2 ] && [ -n "$2" ] || { usage >&2; exit 2; }
      case "$1" in
        --arch) ARCH="$2" ;;
        --aria2) ARIA2="$2"; ARIA2_EXPLICIT=1 ;;
        --out) OUT="$2" ;;
        --instruction-roots-dir) ROOTS="$2" ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
case "$ARCH" in
  amd64|x86_64) BUNDLE_NAME="iris-agent.tgz" ;;
  arm64|aarch64)
    EXPECTED_ARIA2_ARCH="aarch64"
    MANIFEST_ARCH="aarch64"
    BUNDLE_NAME="iris-agent-arm.tgz"
    [ "$ARIA2_EXPLICIT" -eq 1 ] || {
      echo "arm64 requires --aria2 /path/to/the/pinned/aarch64/aria2c" >&2; exit 2;
    } ;;
  *) usage >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }
ask() {                      # ask "Question" "default"  ->  prints the answer
  local q="$1" def="$2" ans=""
  if [ -t 0 ]; then read -rp "$q [$def]: " ans || true; fi
  printf '%s' "${ans:-$def}"
}

verify_aria2() {
  local description="$1" file_out expected actual sums
  command -v file >/dev/null 2>&1 \
    || { say "  cannot verify $description: 'file' is required"; return 1; }
  file_out="$(file -b "$ARIA2")"
  [[ "$file_out" == *"ELF 64-bit"* && "$file_out" == *"$EXPECTED_ARIA2_ARCH"* \
     && "$file_out" == *"statically linked"* ]] \
    || { say "  $description is not an $EXPECTED_ARIA2_ARCH ELF binary: $file_out"; return 1; }
  # The manifest is the pin, not the architecture: a stale or substituted
  # x86-64 static binary passes the `file` check, so compare against the
  # selected architecture entry in tools/aria2c.sha256 and fail closed on a mismatch —
  # the same guarantee get-aria2c.sh and the IOx build path enforce.
  sums="$REPO_ROOT/tools/aria2c.sha256"
  expected="$(awk -v arch="$MANIFEST_ARCH" '$2 == arch {print $1}' "$sums" 2>/dev/null || true)"
  [ -n "$expected" ] \
    || { say "  cannot verify $description: no $MANIFEST_ARCH entry in $sums"; return 1; }
  actual="$( (shasum -a 256 "$ARIA2" 2>/dev/null || sha256sum "$ARIA2") | awk '{print $1}')"
  [ "$actual" = "$expected" ] \
    || { say "  $description sha256 $actual does not match the $MANIFEST_ARCH entry in tools/aria2c.sha256 ($expected)"
         say "  run  tools/get-aria2c.sh  to install the pinned handed-in binary"; return 1; }
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

# Staleness guard (issue #119, same mechanism device/iox/build.sh and
# tools/build-xr-package.sh guard against -- see issue #72): this bundler
# packs device/agent (and the installer scripts it ships alongside) AS THEY
# SIT IN THIS CHECKOUT ($REPO_ROOT) -- a worktree that has fallen behind main
# under those paths ships an older Guest Shell agent with nothing in the
# built iris-agent.tgz saying so. See tools/agent-source-freshness.sh.
# Sourcing is ITSELF best-effort -- a checkout old enough to predate this
# guard has no tools/agent-source-freshness.sh to source, and that must
# degrade to "the check is skipped," never to a raw "No such file or
# directory" abort that masks every error after it.
if [ -r "$REPO_ROOT/tools/agent-source-freshness.sh" ]; then
  # shellcheck source=tools/agent-source-freshness.sh
  . "$REPO_ROOT/tools/agent-source-freshness.sh"
  iris_check_agent_freshness "$REPO_ROOT" \
    "device/agent device/verify_image.py device/bootstrap.sh device/guestshell-start.sh device/rotate-logs.sh" \
    || exit 1
fi

# ---- 1. make sure every piece is present ----------------------------------
missing=0
for f in "$DEVICE/agent/iris_agent.py" "$DEVICE/agent/catalog_client.py" \
         "$DEVICE/agent/flashcheck.py" "$DEVICE/agent/flash_target.py" \
         "$DEVICE/agent/agent_config.py" \
         "$DEVICE/agent/peer-transfer-hook.sh" \
         "$DEVICE/verify_image.py" \
         "$DEVICE/bootstrap.sh" \
         "$DEVICE/guestshell-start.sh" "$DEVICE/rotate-logs.sh"; do
  [ -f "$f" ] || { say "  missing: $f"; missing=1; }
done
if [ ! -f "$ARIA2" ]; then
  # Require an immutable image reference rather than silently using a stale
  # local tag. The extracted binary is verified below before it is bundled.
  IRIS_IMAGE="${IRIS_IMAGE:-}"
  if [ "$ARIA2_EXPLICIT" -eq 0 ] && command -v docker >/dev/null 2>&1 && [[ "$IRIS_IMAGE" == *@sha256:* ]] \
      && docker image inspect "$IRIS_IMAGE" >/dev/null 2>&1; then
    say "  bin/aria2c missing — extracting it from $IRIS_IMAGE..."
    mkdir -p "$(dirname "$ARIA2")"
    cid="$(docker create --platform linux/amd64 "$IRIS_IMAGE")"
    docker cp "$cid:/opt/iris/bin/aria2c" "$ARIA2" >/dev/null
    docker rm "$cid" >/dev/null
    chmod +x "$ARIA2"
    say "  got it."
  else
    say "  The aria2c program is not here yet ($ARIA2), and no immutable IRIS_IMAGE"
    say "  image reference is available. Set IRIS_IMAGE=name@sha256:<digest>, or"
    say "  run  tools/get-aria2c.sh  — then start me again."
    missing=1
  fi
fi
if [ -f "$ARIA2" ] && ! verify_aria2 "$ARIA2"; then
  missing=1
fi
if [ "$missing" -eq 1 ]; then
  say ""; say "Please fix the item(s) above and run me again."; exit 1
fi

# ---- 2. where to save it ---------------------------------------------------
# default: the artifacts/ dir — the server container serves it on :8000 automatically
DEFAULT_OUT="$REPO_ROOT/artifacts/$BUNDLE_NAME"
[ -n "$OUT" ] || OUT="$(ask "Where should I save the finished bundle?" "$DEFAULT_OUT")"
mkdir -p "$(dirname "$OUT")"

# ---- 3. pack it (in the exact layout the device expects) -------------------
# Delegates to server/pack-agent-bundle.sh — the ONE packer, also used by the
# container's startup self-provisioning, so the served bundle never drifts.
say ""
say "Packing the bundle..."
"$REPO_ROOT/server/pack-agent-bundle.sh" "$DEVICE" "$ARIA2" "$OUT" \
  --instruction-roots-dir "$ROOTS"

# The one packer owns this adjacent evidence. Refuse to report success if a
# substituted wrapper failed to produce the exact raw digest contract.
EXPECTED="$( (shasum -a 256 "$OUT" 2>/dev/null || sha256sum "$OUT") \
  | awk '{print $1}')"
[ -f "$OUT.sha256" ] \
  && [ "$(wc -c < "$OUT.sha256" | tr -d ' ')" -eq 65 ] \
  && [ "$(cat "$OUT.sha256")" = "$EXPECTED" ] || {
    echo "bundle digest sidecar is missing or invalid: $OUT.sha256" >&2
    exit 1
  }

# also place the bootstrap next to it — the installer fetches both from :8000
cp "$DEVICE/bootstrap.sh" "$(dirname "$OUT")/bootstrap.sh"

SIZE="$(du -h "$OUT" | awk '{print $1}')"
# hostname -I is Linux-only; on macOS the failing pipeline must not kill the
# script under pipefail — the ipconfig fallback below handles the empty value
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
[ -n "$HOST_IP" ] || HOST_IP="$(ipconfig getifaddr en0 2>/dev/null || true)"
[ -z "${HOST_IP:-}" ] && HOST_IP="<this-host-ip>"
say "  Done:  $OUT  ($SIZE)"
say ""
say "The server container serves this directory on :8000 automatically — nothing"
say "to start. Devices will fetch it from:"
say "    https://$HOST_IP:8000/$(basename "$OUT")"
say ""
