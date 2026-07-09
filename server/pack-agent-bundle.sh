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
#
# <device-dir>   the repo's device/ (holds agent/*.py, verify_image.py,
#                bootstrap.sh, guestshell-start.sh, rotate-logs.sh)
# <aria2c-path>  the static aria2c binary to embed (x86_64 for the C9300)
# <output.tgz>   where to write the bundle
set -euo pipefail

DEVICE="${1:?usage: pack-agent-bundle.sh <device-dir> <aria2c-path> <output.tgz>}"
ARIA2="${2:?usage: pack-agent-bundle.sh <device-dir> <aria2c-path> <output.tgz>}"
OUT="${3:?usage: pack-agent-bundle.sh <device-dir> <aria2c-path> <output.tgz>}"

[ -d "$DEVICE/agent" ] || { echo "pack-agent-bundle: no agent/ under $DEVICE" >&2; exit 1; }
[ -f "$ARIA2" ] || { echo "pack-agent-bundle: aria2c not found: $ARIA2" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/agent" "$(dirname "$OUT")"
cp "$DEVICE"/agent/*.py "$STAGE/agent/"        # iris_agent + catalog_client + flashcheck + agent_config
cp "$DEVICE/verify_image.py" "$STAGE/agent/"    # so the agent's "import verify_image" works
cp "$DEVICE/bootstrap.sh" "$DEVICE/guestshell-start.sh" "$DEVICE/rotate-logs.sh" "$STAGE/"
cp "$ARIA2" "$STAGE/aria2c"
chmod +x "$STAGE/aria2c" "$STAGE/bootstrap.sh" "$STAGE/guestshell-start.sh" "$STAGE/rotate-logs.sh" 2>/dev/null || true
# Tar an explicit file list (NOT '.') so there's no './' top-dir entry. On the
# device, guest-share is SELinux-labeled and denies chmod/utime even to the
# owner, so extracting a './' entry fails. Extract on-box with:
#   tar xzf bundle.tgz -C <dir> --no-same-owner --no-same-permissions -m
tar czf "$OUT" -C "$STAGE" agent bootstrap.sh guestshell-start.sh rotate-logs.sh aria2c
