#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Installs the aria2c client that is COMMITTED to this repository.
#
#   tools/get-aria2c.sh                    # host architecture
#   tools/get-aria2c.sh amd64              # x86_64  (Catalyst / server)
#   tools/get-aria2c.sh arm64              # aarch64 (IE-3400, Cortex-A53)
#   tools/get-aria2c.sh --no-install arm64 # deliverables/ only, keep bin/
#   tools/get-aria2c.sh --for-platforms linux/amd64,linux/arm64
#                                          # every client that list needs, in
#                                          # one run: amd64 into bin/, every
#                                          # other architecture into
#                                          # deliverables/. The list takes the
#                                          # same form as IRIS_DEVICE_PLATFORMS
#                                          # and defaults to it (else
#                                          # linux/amd64) when left off.
#
# IRIS does not build aria2c. The binary is produced elsewhere, by the
# aria2-next-static project, and delivered here as an artifact. That project
# owns the source pin, the patch set, the build flags and the validation; this
# repository is purely the consumer.
#
# The tested clients for both architectures are COMMITTED here --
# bin/aria2c and deliverables/aria2c-x86_64 (the same bytes) plus
# deliverables/aria2c-aarch64 -- so a fresh clone is already complete and
# offline-capable. Normally this script only re-verifies those committed
# files against tools/aria2c.sha256; it fetches solely when one of them is
# missing, for instance because it was deleted from a working tree.
#
# Resolution order: an explicit ARIA2C_DELIVERABLE, the repository's own
# committed deliverables/aria2c-<cpu>, a producer checkout beside the
# repository, and finally this project's own published release asset. Every
# one of them is verified against tools/aria2c.sha256 below.
#
# On downloading: an earlier implementation fetched a prebuilt binary from a
# third party (abcfy2/aria2-static-build), which published x86_64 only while
# device/iox/package.yaml targets aarch64 for the IE-3x00 Guest Shell, and
# shipped an opaque zip that could be checksummed but never audited or patched.
# The release asset this script falls back to is different in every one of
# those respects: it is published by this project, for both architectures,
# from the pinned source and patch set in tools/aria2c-patches/ with the build
# scripts in tools/aria2c-build/, and it is refused unless it matches the
# checksum recorded here. Set ARIA2C_NO_DOWNLOAD=1 to forbid the fetch
# entirely and require a local deliverable.
#
# Why not build it here: the build carries local patches. Keeping a second copy
# of them in this repository guarantees they drift, and a stale copy silently
# ships a client missing fixes. There is exactly one producer.
#
# Whichever candidate is used -- committed, handed in, or fetched -- it is
# verified against tools/aria2c.sha256 and this script FAILS CLOSED on a
# mismatch, so an out-of-date client cannot be installed by accident.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/bin"
SUMS="$REPO_ROOT/tools/aria2c.sha256"

# --for-platforms installs every client one deployment needs in a single run,
# from the same comma-separated list tools/build-device-image.sh reads out of
# IRIS_DEVICE_PLATFORMS. The amd64 client goes into bin/aria2c (what
# server/Dockerfile COPYs); every other architecture is collected into
# deliverables/ with bin/ left alone, because the device builders read there.
# Each client is installed by re-entering this same script one architecture at
# a time, so every one of them is verified against tools/aria2c.sha256 and
# fails closed exactly as a single-architecture run does -- there is no second
# implementation of the checks to keep in step. Per-client output is one line;
# a failing client's full diagnostic is passed through and stops the run.
if [ "${1:-}" = "--for-platforms" ]; then
  shift
  PLATFORMS="${1:-${IRIS_DEVICE_PLATFORMS:-linux/amd64}}"
  [ "$#" -eq 0 ] || shift
  if [ "$#" -gt 0 ]; then
    echo "usage: $0 --for-platforms linux/amd64,linux/arm64" >&2
    exit 2
  fi
  for platform in ${PLATFORMS//,/ }; do
    case "$platform" in
      linux/amd64|amd64|linux/x86_64|x86_64)   arch=amd64; cpu=x86_64 ;;
      linux/arm64|arm64|linux/aarch64|aarch64) arch=arm64; cpu=aarch64 ;;
      *) echo "unsupported platform in --for-platforms: $platform" >&2; exit 2 ;;
    esac
    if [ "$arch" = amd64 ]; then
      run_args=("$arch"); dest="bin/aria2c"; verb="Installed"
    else
      run_args=(--no-install "$arch"); dest="deliverables/aria2c-$cpu"; verb="Collected"
    fi
    rc=0
    out="$(bash "$0" "${run_args[@]}" 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ]; then
      printf '%s\n' "$out" >&2
      echo "!! no verified aria2c client for $platform; nothing further was installed" >&2
      exit "$rc"
    fi
    # A client verified somewhere this repository's builders never read (a
    # producer checkout, an ARIA2C_DELIVERABLE elsewhere) is not collected.
    # Say so here rather than let the device build fail closed later.
    if [ ! -f "$REPO_ROOT/$dest" ]; then
      printf '%s\n' "$out" >&2
      echo "!! the $cpu client verified, but $dest was not written; hand it in there" >&2
      exit 1
    fi
    echo "$verb: $dest — $cpu, sha256 matched tools/aria2c.sha256"
  done
  exit 0
fi

# --no-install collects and verifies the deliverable without touching
# bin/aria2c. bin/ holds ONE client, the x86_64 one the server image copies
# (server/Dockerfile) and tools/make-agent-bundle.sh defaults to, so fetching
# aarch64 for a device package must not replace it. The device builders read
# deliverables/, which this still populates.
INSTALL_BIN=1
if [ "${1:-}" = "--no-install" ]; then
  INSTALL_BIN=0
  shift
fi

# Parse the whole invocation before resolving or installing any deliverable.
# In particular, never silently ignore a trailing --no-install and replace
# the server's amd64 binary with an ARM client (#319).
if [ "$#" -gt 1 ]; then
  echo "usage: $0 [--no-install] [amd64|arm64] (put --no-install first)" >&2
  exit 2
fi

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
  *) echo "usage: $0 [--no-install] [amd64|arm64]" >&2; exit 2 ;;
esac

# Where the deliverable is collected from, in order: an explicit
# ARIA2C_DELIVERABLE (an operator pointing at a hand-in elsewhere on purpose);
# the repository's own COMMITTED copy under deliverables/aria2c-<cpu> (the
# same place tools/build-device-image.sh and tools/start-compose-server.sh
# resolve the per-architecture binaries from, so the one committed client
# serves the server image AND every device package); else a producer checkout
# beside the repository. The committed copy comes before the producer
# checkout deliberately: what this repository ships is what was tested, and a
# half-built producer tree must not take its place. Every candidate is
# verified against tools/aria2c.sha256 below, so a stale copy fails closed
# either way.
# The published deliverables live on a release of their own, tagged by the
# aria2-next version and patch count rather than by an IRIS CalVer release:
# the binary changes only when the build does.
ARIA2C_RELEASE_TAG="${ARIA2C_RELEASE_TAG:-aria2c-2.5.6-p7}"
ARIA2C_RELEASE_URL="${ARIA2C_RELEASE_URL:-https://github.com/cisco-open/intelligent-release-image-staging/releases/download/$ARIA2C_RELEASE_TAG/aria2c-$ARCH}"

DOWNLOADED=""
if [ -n "${ARIA2C_DELIVERABLE:-}" ]; then
  DELIVERABLE="$ARIA2C_DELIVERABLE"
elif [ -f "$REPO_ROOT/deliverables/aria2c-$ARCH" ]; then
  DELIVERABLE="$REPO_ROOT/deliverables/aria2c-$ARCH"
elif [ -f "$REPO_ROOT/../aria2-next-static/out/$ARCH/aria2c" ]; then
  DELIVERABLE="$REPO_ROOT/../aria2-next-static/out/$ARCH/aria2c"
elif [ -n "${ARIA2C_NO_DOWNLOAD:-}" ]; then
  DELIVERABLE="$REPO_ROOT/deliverables/aria2c-$ARCH"
else
  DOWNLOADED="$(mktemp)"
  trap 'rm -f "$DOWNLOADED"' EXIT
  echo ">> fetching the published aria2c deliverable for $ARCH"
  echo "   $ARIA2C_RELEASE_URL"
  if curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error \
       "$ARIA2C_RELEASE_URL" -o "$DOWNLOADED"; then
    DELIVERABLE="$DOWNLOADED"
  else
    echo "!! could not fetch it; falling back to a local deliverable" >&2
    DELIVERABLE="$REPO_ROOT/deliverables/aria2c-$ARCH"
  fi
fi

[ -f "$SUMS" ] || { echo "missing $SUMS - cannot verify the deliverable" >&2; exit 1; }

expected="$(awk -v a="$ARCH" '$2 == a { print $1 }' "$SUMS")"
[ -n "$expected" ] || { echo "no checksum recorded for $ARCH in $SUMS" >&2; exit 1; }

if [ ! -f "$DELIVERABLE" ]; then
  cat >&2 <<EOF
No aria2c deliverable for $ARCH at:
  $DELIVERABLE

This repository does not build aria2c. The published deliverable could not be
fetched from

  $ARIA2C_RELEASE_URL

so either that release is unreachable from this host or it does not carry this
architecture. This repository commits the tested client at
deliverables/aria2c-$ARCH, so in a clone the first thing to try is restoring it:

  git checkout -- deliverables/aria2c-$ARCH

Otherwise drop the handed-in binary there, set ARIA2C_DELIVERABLE to it, or
build one from source:
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
  if [ -n "$DOWNLOADED" ]; then
    cat >&2 <<EOF

That came from the published release asset, which means the asset does not
match the checksum this checkout pins. It has been discarded, not installed.
Either the release carries a different build than tools/aria2c.sha256 records,
or the download was tampered with. Do not adopt it; hand in a binary you trust
or build one from the pinned source.
EOF
  fi
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

# A verified download is kept in deliverables/ as well as installed into bin/.
# tools/build-device-image.sh resolves each architecture's client from there,
# so keeping it means the IOx and XR package builds need no second fetch, and
# a later run of this script finds it locally. This restores the copy the
# repository commits: the bytes match tools/aria2c.sha256, so the restored
# file is identical to the tracked one and leaves no diff behind.
if [ -n "$DOWNLOADED" ]; then
  mkdir -p "$REPO_ROOT/deliverables"
  # 0755, the mode the committed deliverable carries, so restoring a deleted
  # one leaves git seeing no change at all -- not even a mode change.
  install -m 0755 "$DELIVERABLE" "$REPO_ROOT/deliverables/aria2c-$ARCH"
  echo "Kept:      deliverables/aria2c-$ARCH"
fi

if [ "$INSTALL_BIN" -eq 0 ]; then
  echo "Verified:  $ARCH deliverable (bin/aria2c left as it was)"
  echo "  sha256: $actual (verified against tools/aria2c.sha256)"
  exit 0
fi

mkdir -p "$OUT_DIR"
install -m 0755 "$DELIVERABLE" "$OUT_DIR/aria2c"

echo "Installed: $OUT_DIR/aria2c"
echo "  arch:   $ARCH"
echo "  sha256: $actual (verified against tools/aria2c.sha256)"
echo "  size:   $(wc -c < "$OUT_DIR/aria2c") bytes"
