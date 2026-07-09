#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Stage the DERIVABLE served artifacts into the artifacts dir at container
# startup, so a fresh deploy no longer fails onboarding on missing files. The
# three files a device downloads that the container can produce itself:
#   iris-agent.tgz    the Guest Shell agent bundle (rebuilt every start from the
#                     bind-mounted device/ sources, so it always matches the
#                     deployed agent code)
#   bootstrap.sh      the on-device launcher (device/bootstrap.sh)
#   iris-catalog.pem  the pinned CA the agent trusts = the server's PUBLIC cert
# The one served artifact this CANNOT produce is iris.tar (the aarch64 IOx
# package — needs device/iox/build.sh); it just notes when that is absent.
#
# BEST-EFFORT by design: it logs and returns 0 even when it can't stage (e.g. a
# read-only artifacts mount, or the cert not minted yet) so it NEVER blocks the
# server from starting.
#
#   provision-served.sh [artifacts-dir]
set -uo pipefail

ART="${1:-${IRIS_ARTIFACTS_DIR:-/srv/artifacts}}"
DEVICE="${IRIS_DEVICE_DIR:-/opt/iris/device}"
ARIA2="${IRIS_ARIA2:-/opt/iris/bin/aria2c}"
CRT="${IRIS_CRT_SRC:-${IRIS_CONFIG:-/etc/iris}/tls/crt.pem}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! mkdir -p "$ART/staging" 2>/dev/null || [ ! -w "$ART" ]; then
  echo "provision-served: artifacts dir $ART not writable — cannot self-provision;" \
       "onboarding will need the bundle staged manually (mount ../artifacts read-write)" >&2
  exit 0
fi

# All writes onto SERVED paths are atomic: build under a temp name in the same
# directory, then mv into place. A device fetching mid-restart reads either the
# old file or the new one — never a truncated/torn copy — and an interrupted
# pack (SIGTERM/disk-full) leaves the previous good file being served.
stage_atomic() {  # stage_atomic <tmp-file> <final-name>
  mv -f "$1" "$ART/$2"
}

# Guest Shell bundle — rebuilt every start so the served bundle can never drift
# from the deployed agent code (device/ is bind-mounted from the same checkout).
if [ -d "$DEVICE/agent" ] && [ -f "$ARIA2" ]; then
  if "$HERE/pack-agent-bundle.sh" "$DEVICE" "$ARIA2" "$ART/.iris-agent.tgz.tmp"; then
    stage_atomic "$ART/.iris-agent.tgz.tmp" iris-agent.tgz
    cp "$DEVICE/bootstrap.sh" "$ART/.bootstrap.sh.tmp" \
      && stage_atomic "$ART/.bootstrap.sh.tmp" bootstrap.sh
    echo "provision-served: staged iris-agent.tgz + bootstrap.sh (Guest Shell agent)"
  else
    rm -f "$ART/.iris-agent.tgz.tmp"
    echo "provision-served: bundle pack FAILED — previous iris-agent.tgz (if any) left as served" >&2
  fi
else
  echo "provision-served: device sources or aria2c missing" \
       "(device=$DEVICE aria2c=$ARIA2) — Guest Shell bundle not staged" >&2
fi

# Pinned CA the devices download = the server's PUBLIC cert (plaintext on the
# config volume, no decrypt needed). Refresh every start so a rotated cert
# propagates to what onboarding serves.
if [ -f "$CRT" ]; then
  cp "$CRT" "$ART/.iris-catalog.pem.tmp" \
    && stage_atomic "$ART/.iris-catalog.pem.tmp" iris-catalog.pem
  echo "provision-served: staged iris-catalog.pem (server cert)"
else
  echo "provision-served: server cert $CRT not found — run iris-bootstrap first" >&2
fi

# The IOx package is the one served artifact we cannot build here (aarch64 +
# ioxclient). Note its absence so an operator onboarding IE-3400s knows.
if [ ! -f "$ART/iris.tar" ]; then
  echo "provision-served: note — iris.tar (IE-3400 IOx agent) not staged;" \
       "build device/iox/build.sh to onboard IE-3400s (Guest Shell C9300s are ready)"
fi
exit 0
