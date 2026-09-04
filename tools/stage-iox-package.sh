#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Build the deployment-neutral IRIS IOx package and PLACE it in the artifacts dir
# so Console onboarding can serve it. This is a SERVER/HOST-side helper only:
# it builds a tar and copies it into the artifacts directory. It NEVER installs,
# activates, reloads, or otherwise touches a device (stage-only invariant).
#
#   tools/stage-iox-package.sh [--arch amd64|arm64] [--artifacts-dir DIR]
#
# Defaults:
#   --arch amd64            the Catalyst-9300 IOx case this targets (produces
#                           iris-amd64.tar); arm64 is supported for symmetry
#                           (produces iris-arm64.tar for IE-3x00/IR).
#   --artifacts-dir         resolved artifacts dir. Default: the docker-compose
#                           host bind mount ${IRIS_ARTIFACTS_HOST_DIR:-../artifacts}
#                           relative to server/ (i.e. <repo>/artifacts).
#
# IOXCLIENT passes through the environment.
# BINFMT_IMAGE_DIGEST is required only when arm64 emulation must be installed;
# set it to the audited sha256 digest for tonistiigi/binfmt (without an image tag).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/device/iox/build.sh"
IOXCLIENT="${IOXCLIENT:-$REPO/tools/bin/ioxclient}"
IRIS_CONTAINER="${IRIS_CONTAINER:-iris}"

ARCH=amd64
ARTIFACTS_DIR=""
ARTIFACTS_DIR_EXPLICIT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --arch) ARCH="${2:?--arch needs a value}"; shift 2 ;;
    --artifacts-dir) ARTIFACTS_DIR="${2:?--artifacts-dir needs a value}"; ARTIFACTS_DIR_EXPLICIT=1; shift 2 ;;
    -h|--help)
      echo "usage: $0 [--arch amd64|arm64] [--artifacts-dir DIR]"
      exit 0
      ;;
    *) echo "!! unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$ARCH" in
  amd64) PKG_NAME=iris-amd64.tar ;;
  arm64) PKG_NAME=iris-arm64.tar ;;
  *) echo "!! --arch must be amd64 or arm64 (got $ARCH)" >&2; exit 2 ;;
esac

# Is arm64 emulation already registered? Ask the kernel first
# (/proc/sys/fs/binfmt_misc/qemu-aarch64 exists and is enabled) -- that needs
# no network and pulls nothing. Only when binfmt_misc is not readable at all
# (non-Linux Docker hosts, a restricted /proc) fall back to the floating-tag
# container probe, which is a network fetch of an unpinned image.
arm64_emulation_ready() {
  local reg=/proc/sys/fs/binfmt_misc/qemu-aarch64
  if [ -d /proc/sys/fs/binfmt_misc ]; then
    [ -r "$reg" ] && grep -q '^enabled' "$reg"
    return
  fi
  docker run --rm --platform linux/arm64 alpine:3.20 true >/dev/null 2>&1
}
if [ "$ARCH" = arm64 ] && ! arm64_emulation_ready; then
  echo ">> enabling Docker arm64 emulation for the arm64 IOx package build"
  : "${BINFMT_IMAGE_DIGEST:?set BINFMT_IMAGE_DIGEST to an audited tonistiigi/binfmt sha256 digest}"
  [[ "$BINFMT_IMAGE_DIGEST" =~ ^sha256:[0-9a-fA-F]{64}$ ]] \
    || { echo "!! BINFMT_IMAGE_DIGEST must be a sha256 digest" >&2; exit 1; }
  docker run --privileged --rm "tonistiigi/binfmt@$BINFMT_IMAGE_DIGEST" --install arm64
fi

# Resolve the artifacts dir: explicit flag wins; else the Compose host bind
# mount default, resolved relative to server/ exactly as docker-compose.yml
# reads ${IRIS_ARTIFACTS_HOST_DIR:-../artifacts}.
if [ -z "$ARTIFACTS_DIR" ]; then
  ART_REL="${IRIS_ARTIFACTS_HOST_DIR:-../artifacts}"
  case "$ART_REL" in
    /*) ARTIFACTS_DIR="$ART_REL" ;;
    *)  ARTIFACTS_DIR="$REPO/server/$ART_REL" ;;
  esac
fi

# Validate inputs BEFORE building so we never produce a mis-placed/mis-named tar.
[ -x "$BUILD" ] || { echo "!! build script not found/executable: $BUILD" >&2; exit 1; }

# A Compose container may create the bind mount as root. In that common case,
# docker cp places the completed package in the served directory without
# requiring operators to change host ownership. Explicit --artifacts-dir paths
# remain direct host writes only.
PLACE_WITH_DOCKER=0
if [ ! -d "$ARTIFACTS_DIR" ] || [ ! -w "$ARTIFACTS_DIR" ]; then
  if [ "$ARTIFACTS_DIR_EXPLICIT" -eq 0 ] \
      && docker inspect "$IRIS_CONTAINER" >/dev/null 2>&1; then
    PLACE_WITH_DOCKER=1
  else
    echo "!! artifacts dir not writable: $ARTIFACTS_DIR" >&2
    exit 1
  fi
fi
if [ ! -x "$IOXCLIENT" ]; then
  "$REPO/tools/get-ioxclient.sh" "$(dirname "$IOXCLIENT")"
fi

echo ">> building IOx package (arch=$ARCH -> $PKG_NAME)"
BUILD_OUT="$(mktemp -d)"
trap 'rm -rf "$BUILD_OUT"' EXIT
IOX_ARCH="$ARCH" PACKAGE_NAME="$PKG_NAME" IOXCLIENT="$IOXCLIENT" \
  bash "$BUILD" "$BUILD_OUT"

SRC="$BUILD_OUT/$PKG_NAME"
MANIFEST_SRC="$SRC.manifest"
[ -f "$SRC" ] && [ -f "$MANIFEST_SRC" ] \
  || { echo "!! build did not produce $SRC and its provenance manifest" >&2; exit 1; }

if [ "$PLACE_WITH_DOCKER" -eq 1 ]; then
  # Same atomic discipline as the host branch below: a device fetching the
  # package mid-copy must read the old file or the new one, never a torn one.
  docker cp "$SRC" "$IRIS_CONTAINER:/srv/artifacts/.$PKG_NAME.tmp"
  docker cp "$MANIFEST_SRC" "$IRIS_CONTAINER:/srv/artifacts/.$PKG_NAME.manifest.tmp"
  docker exec "$IRIS_CONTAINER" rm -f "/srv/artifacts/$PKG_NAME.manifest"
  docker exec "$IRIS_CONTAINER" mv -f "/srv/artifacts/.$PKG_NAME.tmp" "/srv/artifacts/$PKG_NAME"
  docker exec "$IRIS_CONTAINER" mv -f "/srv/artifacts/.$PKG_NAME.manifest.tmp" "/srv/artifacts/$PKG_NAME.manifest"
  echo ">> staged $PKG_NAME -> $IRIS_CONTAINER:/srv/artifacts/$PKG_NAME"
  docker exec "$IRIS_CONTAINER" ls -la "/srv/artifacts/$PKG_NAME" "/srv/artifacts/$PKG_NAME.manifest"
else
  # Atomic-friendly placement: copy to a temp name in the destination dir, then
  # rename into the served path (mirrors provision-served.sh staging discipline).
  DEST="$ARTIFACTS_DIR/$PKG_NAME"
  TMP_DEST="$ARTIFACTS_DIR/.$PKG_NAME.tmp"
  MANIFEST_DEST="$DEST.manifest"
  MANIFEST_TMP_DEST="$ARTIFACTS_DIR/.$PKG_NAME.manifest.tmp"
  cp "$SRC" "$TMP_DEST"
  cp "$MANIFEST_SRC" "$MANIFEST_TMP_DEST"
  rm -f "$MANIFEST_DEST"
  mv -f "$TMP_DEST" "$DEST"
  mv -f "$MANIFEST_TMP_DEST" "$MANIFEST_DEST"
  echo ">> staged $PKG_NAME -> $DEST"
  ls -la "$DEST" "$MANIFEST_DEST"
fi
