#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Installs the aria2c client that was HANDED IN to this repository.
#
#   tools/get-aria2c.sh              # host architecture
#   tools/get-aria2c.sh amd64        # x86_64  (Catalyst / server)
#   tools/get-aria2c.sh arm64        # aarch64 (IE-3400, Cortex-A53)
#
# IRIS does not download and does not build aria2c. The binary is produced
# elsewhere, by the aria2-next-static project, and delivered here as an
# artifact. That project owns the source pin, the patch set, the build flags
# and the validation; this repository is purely the consumer.
#
# Why not download it: the previous implementation fetched a prebuilt binary
# from a third party (abcfy2/aria2-static-build). That published x86_64 only,
# while device/iox/package.yaml targets aarch64 for the IE-3x00 Guest Shell,
# and an opaque zip can be checksummed but never audited or patched.
#
# Why not build it here: the build carries local patches. Keeping a second copy
# of them in this repository guarantees they drift, and a stale copy silently
# ships a client missing fixes. There is exactly one producer.
#
# The delivered binary is verified against tools/aria2c.sha256 and this script
# FAILS CLOSED on a mismatch, so an out-of-date client cannot be installed by
# accident.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/bin"
SUMS="$REPO_ROOT/tools/aria2c.sha256"

case "${1:-}" in
  amd64|x86_64)  ARCH=x86_64 ;;
  arm64|aarch64) ARCH=aarch64 ;;
  "")
    case "$(uname -m)" in
      x86_64)        ARCH=x86_64 ;;
      arm64|aarch64) ARCH=aarch64 ;;
      *) echo "Unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
    esac
    ;;
  *) echo "usage: $0 [amd64|arm64]" >&2; exit 2 ;;
esac

# Where the deliverable is collected from, in order: an explicit
# ARIA2C_DELIVERABLE; the repository's own handed-in copy under
# deliverables/aria2c-<cpu> (the same place tools/build-device-image.sh and
# tools/start-compose-server.sh resolve the per-architecture binaries from,
# so one drop serves the server image AND every device package); else the
# producer checkout beside the repository. Every candidate is verified
# against tools/aria2c.sha256 below, so a stale copy fails closed either way.
if [ -n "${ARIA2C_DELIVERABLE:-}" ]; then
  DELIVERABLE="$ARIA2C_DELIVERABLE"
elif [ -f "$REPO_ROOT/deliverables/aria2c-$ARCH" ]; then
  DELIVERABLE="$REPO_ROOT/deliverables/aria2c-$ARCH"
else
  DELIVERABLE="$REPO_ROOT/../aria2-next-static/out/$ARCH/aria2c"
fi

[ -f "$SUMS" ] || { echo "missing $SUMS - cannot verify the deliverable" >&2; exit 1; }

expected="$(awk -v a="$ARCH" '$2 == a { print $1 }' "$SUMS")"
[ -n "$expected" ] || { echo "no checksum recorded for $ARCH in $SUMS" >&2; exit 1; }

if [ ! -f "$DELIVERABLE" ]; then
  cat >&2 <<EOF
No aria2c deliverable for $ARCH at:
  $DELIVERABLE

This repository does not build aria2c. Either drop the handed-in binary at
deliverables/aria2c-$ARCH, set ARIA2C_DELIVERABLE to it, or build one from source:
the upstream fork pinned in tools/aria2c.sha256 plus the patches in
tools/aria2c-patches/ (see the README there for the recipe). Maintainers
with the producer checkout can instead run:

  cd ../aria2-next-static && ./build.sh $ARCH
EOF
  exit 1
fi

actual="$( (shasum -a 256 "$DELIVERABLE" 2>/dev/null || sha256sum "$DELIVERABLE") | awk '{print $1}')"
if [ "$actual" != "$expected" ]; then
  cat >&2 <<EOF
CHECKSUM MISMATCH for $ARCH — refusing to install.
  expected: $expected   (tools/aria2c.sha256)
  actual:   $actual     ($DELIVERABLE)
EOF
  # A deliverable that hashes to ANOTHER entry in the manifest is not stale at
  # all, it is the wrong architecture -- the usual result of collecting from the
  # producer's other out/ directory. Say which, rather than leaving the operator
  # to compare two hashes by eye.
  wrong_arch="$(awk -v h="$actual" '$1 == h { print $2 }' "$SUMS")"
  if [ -n "$wrong_arch" ]; then
    cat >&2 <<EOF

That is the $wrong_arch entry in tools/aria2c.sha256: this deliverable is the
wrong architecture, not a stale build. Point ARIA2C_DELIVERABLE at the $ARCH
binary instead.
EOF
  else
    cat >&2 <<EOF

The deliverable is stale (produced before the currently pinned build), or a
newer client was produced and tools/aria2c.sha256 has not been updated to adopt
it. Do not "fix" this by editing the checksum unless you intend to adopt that
exact binary.
EOF
  fi
  exit 1
fi

mkdir -p "$OUT_DIR"
install -m 0755 "$DELIVERABLE" "$OUT_DIR/aria2c"

echo "Installed: $OUT_DIR/aria2c"
echo "  arch:   $ARCH"
echo "  sha256: $actual (verified against tools/aria2c.sha256)"
echo "  size:   $(wc -c < "$OUT_DIR/aria2c") bytes"
