#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Pack the IRIS Guest Shell device-agent bundle (iris-agent.tgz) in the exact
# layout the on-device bootstrap expects. This is the ONE packer: both the
# operator CLI (tools/make-agent-bundle.sh) and the container's startup
# self-provisioning (server/docker-entrypoint.sh) call it, so the served bundle
# can never drift from the deployed agent code.
#
#   pack-agent-bundle.sh <device-dir> <aria2c-path> <output.tgz>
#       [--instruction-roots-dir DIR]
#
# <device-dir>   the repo's device/ (holds agent/*.py, verify_image.py,
#                bootstrap.sh, guestshell-start.sh, rotate-logs.sh)
# <aria2c-path>  the static aria2c binary to embed (x86_64 for the C9300)
# <output.tgz>   where to write the bundle and adjacent .sha256 evidence
set -euo pipefail

DEVICE="${1:?usage: pack-agent-bundle.sh <device-dir> <aria2c-path> <output.tgz>}"
ARIA2="${2:?usage: pack-agent-bundle.sh <device-dir> <aria2c-path> <output.tgz>}"
OUT="${3:?usage: pack-agent-bundle.sh <device-dir> <aria2c-path> <output.tgz>}"
shift 3
ROOTS="${IRIS_INSTRUCTION_ROOTS_DIR:-}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --instruction-roots-dir)
      [ "$#" -ge 2 ] && [ -n "$2" ] \
        || { echo "pack-agent-bundle: --instruction-roots-dir needs a value" >&2; exit 2; }
      ROOTS="$2"; shift 2 ;;
    *) echo "pack-agent-bundle: unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -d "$DEVICE/agent" ] || { echo "pack-agent-bundle: no agent/ under $DEVICE" >&2; exit 1; }
[ -f "$ARIA2" ] || { echo "pack-agent-bundle: aria2c not found: $ARIA2" >&2; exit 1; }
[ -n "$ROOTS" ] || {
  echo "pack-agent-bundle: --instruction-roots-dir or IRIS_INSTRUCTION_ROOTS_DIR is required" >&2
  exit 1
}

STAGE="$(mktemp -d)"
mkdir -p "$STAGE/agent" "$(dirname "$OUT")"
TMP_BUNDLE="$(mktemp "$(dirname "$OUT")/.$(basename "$OUT").XXXXXX")"
TMP_SIDECAR="$(mktemp "$(dirname "$OUT")/.$(basename "$OUT").sha256.XXXXXX")"
trap 'rm -rf "$STAGE"; rm -f "$TMP_BUNDLE" "$TMP_SIDECAR"' EXIT
cp "$DEVICE"/agent/*.py "$STAGE/agent/"        # iris_agent + catalog_client + flashcheck + agent_config
# The aria2 --on-bt-download-complete program. It rides the bundle because
# dropping a new bundle.tgz IS how a device is upgraded, and it lives beside
# the agent because the agent is the only thing that reads what it writes.
# guestshell-start.sh copies it out of here onto an exec-capable filesystem at
# launch -- /flash denies chmod, so the staged copy can never be executable.
cp "$DEVICE/agent/peer-transfer-hook.sh" "$STAGE/agent/"
cp "$DEVICE/verify_image.py" "$STAGE/agent/"    # so the agent's "import verify_image" works
cp "$DEVICE/bootstrap.sh" "$DEVICE/guestshell-start.sh" "$DEVICE/rotate-logs.sh" "$STAGE/"
cp "$ARIA2" "$STAGE/aria2c"
PYTHONPATH="$(cd "$(dirname "$0")" && pwd)${PYTHONPATH:+:$PYTHONPATH}" \
  python3 - "$ROOTS" "$STAGE" <<'PYTHON'
import sys
from instruction_keys import InstructionKeyError, render_device_trust

try:
    render_device_trust(sys.argv[1], sys.argv[2])
except InstructionKeyError as exc:
    print("pack-agent-bundle: instruction trust unavailable: " + str(exc),
          file=sys.stderr)
    raise SystemExit(1)
PYTHON
chmod +x "$STAGE/aria2c" "$STAGE/bootstrap.sh" "$STAGE/guestshell-start.sh" \
         "$STAGE/rotate-logs.sh" "$STAGE/agent/peer-transfer-hook.sh" 2>/dev/null || true
# Tar an explicit file list (NOT '.') so there's no './' top-dir entry. On the
# device, guest-share is SELinux-labeled and denies chmod/utime even to the
# owner, so extracting a './' entry fails. Extract on-box with:
#   tar xzf bundle.tgz -C <dir> --no-same-owner --no-same-permissions -m
tar czf "$TMP_BUNDLE" -C "$STAGE" agent bootstrap.sh guestshell-start.sh \
  rotate-logs.sh aria2c iris-signers.allowed_signers iris-root.allowed_signers
DIGEST="$( (shasum -a 256 "$TMP_BUNDLE" 2>/dev/null \
  || sha256sum "$TMP_BUNDLE") | awk '{print $1}')"
case "$DIGEST" in
  *[!0-9a-f]*|'') echo "pack-agent-bundle: cannot digest bundle" >&2; exit 1 ;;
esac
printf '%s\n' "$DIGEST" > "$TMP_SIDECAR"
[ "$(wc -c < "$TMP_SIDECAR" | tr -d ' ')" -eq 65 ] \
  || { echo "pack-agent-bundle: invalid digest sidecar" >&2; exit 1; }
chmod 0644 "$TMP_BUNDLE" "$TMP_SIDECAR"
# Publish the archive first and its evidence second. A reader in between fails
# closed on a missing/mismatched sidecar; neither final path is ever partial.
mv -f "$TMP_BUNDLE" "$OUT"
mv -f "$TMP_SIDECAR" "$OUT.sha256"
