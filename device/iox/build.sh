#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Wrap the canonical IRIS device image as a classic IOx package.
#
#   device/iox/build.sh [--image-only] [--amd64|--arm64] [OUTPUT_DIR]
#
# Image inputs (ARIA2C_BIN_AMD64, ARIA2C_BIN_ARM64, CATALOG_PEM,
# CATALOG_PEM_URL and fingerprint) are validated by the shared builder. This
# wrapper owns only the IOx descriptor/classic-archive envelope; IOS-XR
# packages the same amd64 manifest.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PACKAGE=1
OUT="$HERE/out"
ARCH_FLAG=""
for arg in "$@"; do
  case "$arg" in
    --image-only) PACKAGE=0 ;;
    --amd64) ARCH_FLAG=amd64 ;;
    --arm64) ARCH_FLAG=arm64 ;;
    -h|--help)
      echo "usage: $0 [--image-only] [--amd64|--arm64] [OUTPUT_DIR]"
      exit 0
      ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *) OUT="$arg" ;;
  esac
done

IOX_ARCH="${ARCH_FLAG:-${IOX_ARCH:-arm64}}"
case "$IOX_ARCH" in
  arm64|aarch64)
    IOX_ARCH=arm64
    DEFAULT_PACKAGE_DESCRIPTOR="$HERE/package.yaml"
    DEFAULT_PACKAGE_NAME=iris-arm64.tar
    ;;
  amd64|x86_64)
    IOX_ARCH=amd64
    DEFAULT_PACKAGE_DESCRIPTOR="$HERE/package-amd64.yaml"
    DEFAULT_PACKAGE_NAME=iris-amd64.tar
    ;;
  *) echo "!! IOX_ARCH must be arm64 or amd64 (got $IOX_ARCH)" >&2; exit 2 ;;
esac

PACKAGE_NAME="${PACKAGE_NAME:-$DEFAULT_PACKAGE_NAME}"
PACKAGE_DESCRIPTOR="${PACKAGE_DESCRIPTOR:-$DEFAULT_PACKAGE_DESCRIPTOR}"
IOXCLIENT="${IOXCLIENT:-ioxclient}"
[ -r "$PACKAGE_DESCRIPTOR" ] \
  || { echo "!! package descriptor not readable: $PACKAGE_DESCRIPTOR" >&2; exit 1; }

# Keep wrapper metadata in the issue-72 freshness boundary as well as the
# common image-source check performed by build-device-image.sh.
if [ -r "$REPO/tools/agent-source-freshness.sh" ]; then
  # shellcheck source=tools/agent-source-freshness.sh
  . "$REPO/tools/agent-source-freshness.sh"
  iris_check_agent_freshness "$REPO" \
    "device/agent device/container device/verify_image.py device/iox tools/build-device-image.sh" \
    || exit 1
fi

CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
mkdir -p "$OUT"

"$REPO/tools/build-device-image.sh" --context "$CTX"
OCI_ARCHIVE="$(cat "$CTX/iris-device-oci-path")"
OCI_INDEX="$(sed -n 's/^index_digest=//p' "$CTX/iris-device-oci.manifest")"
OCI_ARCHIVE_SHA="$(sed -n 's/^archive_sha256=//p' "$CTX/iris-device-oci.manifest")"
OCI_SOURCE_SHA="$(sed -n 's/^source_sha256=//p' "$CTX/iris-device-oci.manifest")"
[ -n "$OCI_INDEX" ] && [ -n "$OCI_ARCHIVE_SHA" ] && [ -n "$OCI_SOURCE_SHA" ] \
  || { echo "!! canonical OCI provenance manifest is incomplete" >&2; exit 1; }

if [ "$PACKAGE" -eq 0 ]; then
  echo ">> canonical image-only build complete: $OCI_ARCHIVE ($OCI_INDEX)"
  exit 0
fi

# CAF on the older IOx targets accepts the classic Docker archive layout, not
# the OCI/containerd archive emitted by modern Docker save/buildx flows.
command -v skopeo >/dev/null 2>&1 \
  || { echo "!! skopeo is required to package for IOx" >&2; exit 1; }
echo ">> selecting linux/$IOX_ARCH from canonical OCI $OCI_INDEX"
skopeo copy --override-os linux --override-arch "$IOX_ARCH" \
  "oci-archive:$OCI_ARCHIVE" \
  "docker-archive:$CTX/rootfs.tar:iris-device:$IOX_ARCH"
tar tf "$CTX/rootfs.tar" | grep -qx manifest.json \
  || { echo "!! selected image has no classic manifest.json" >&2; exit 1; }
if tar tf "$CTX/rootfs.tar" | grep -qx index.json \
   || tar xOf "$CTX/rootfs.tar" manifest.json 2>/dev/null | grep -q attestation-manifest; then
  echo "!! selected image is not a CAF-compatible classic Docker archive" >&2
  exit 1
fi

# ioxclient packages its entire working directory. Keep it deliberately small:
# rootfs, descriptor, and the public pinned-cert probe used by freshness checks.
PKG="$CTX/pkg"
mkdir -p "$PKG"
mv "$CTX/rootfs.tar" "$PKG/rootfs.tar"
cp "$PACKAGE_DESCRIPTOR" "$PKG/package.yaml"
cp "$CTX/iris-catalog.pem" "$PKG/iris-catalog.pem"
( cd "$PKG" && "$IOXCLIENT" package . )
artifact_tmp="$(mktemp "$OUT/.${PACKAGE_NAME}.XXXXXX")"
manifest_tmp="$(mktemp "$OUT/.${PACKAGE_NAME}.manifest.XXXXXX")"
trap 'rm -rf "$CTX"; rm -f "$artifact_tmp" "$manifest_tmp"' EXIT
cp "$PKG/package.tar" "$artifact_tmp"
WRAPPER_SHA="$(sha256sum "$artifact_tmp" | awk '{print $1}')"
{
  echo 'format=iris-device-wrapper-v1'
  echo 'wrapper_kind=iox'
  echo "wrapper_file=$PACKAGE_NAME"
  echo "wrapper_sha256=$WRAPPER_SHA"
  echo "platform=linux/$IOX_ARCH"
  echo "canonical_index_digest=$OCI_INDEX"
  echo "canonical_archive_sha256=$OCI_ARCHIVE_SHA"
  echo "canonical_source_sha256=$OCI_SOURCE_SHA"
} > "$manifest_tmp"
chmod 444 "$artifact_tmp" "$manifest_tmp"
# Never expose a new wrapper beside stale provenance. Each published file is
# a rename within OUT; readers either see no manifest or one complete sidecar.
rm -f "$OUT/$PACKAGE_NAME.manifest"
mv -f "$artifact_tmp" "$OUT/$PACKAGE_NAME"
mv -f "$manifest_tmp" "$OUT/$PACKAGE_NAME.manifest"
echo ">> done: $OUT/$PACKAGE_NAME"
ls -la "$OUT/$PACKAGE_NAME" "$OUT/$PACKAGE_NAME.manifest"
