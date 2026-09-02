#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Build an IRIS IOx Docker app for arm64 IE-3x00/IR devices or amd64
# Catalyst 9000 devices.
#
#   ./build.sh [--image-only] [--amd64|--arm64] [OUTPUT_DIR]
#
# Assembles a build context (the agent python + an architecture-matched aria2c +
# the pinned catalog cert), builds the selected platform image, and packages it
# with ioxclient into <OUTPUT_DIR>/$PACKAGE_NAME.
#
# Inputs (env overridable):
#   IOX_ARCH       arm64 (default) or amd64.
#   PACKAGE_NAME   output filename (default iris-arm64.tar). Use architecture-specific
#                  names when serving both packages, such as iris-amd64.tar.
#   PACKAGE_DESCRIPTOR  package.yaml override for custom platform metadata.
#   ARIA2C_BIN     architecture-matched aria2c. Default: use the matching local
#                  agent bundle when present (its aria2c is still checksum-
#                  verified), otherwise deliverables/aria2c-<arch>, verified
#                  against tools/aria2c.sha256. This build does NOT download
#                  aria2c -- see tools/get-aria2c.sh for how the deliverable
#                  is produced and verified.
#   CATALOG_PEM    pinned server cert. Default: fetched from $CATALOG_PEM_URL.
#   CATALOG_PEM_URL  required when CATALOG_PEM is not supplied.
#   CATALOG_PEM_FINGERPRINT  expected SHA-256 fingerprint of the catalog cert
#                  (format: "SHA256:AA:BB:...").  Required when CATALOG_PEM is
#                  not supplied (i.e. when the cert is fetched over the network).
#                  The build aborts if the fetched cert's fingerprint does not
#                  match, preventing a MITM from baking a rogue cert into the
#                  fleet image.  Obtain it once with:
#                    openssl x509 -noout -fingerprint -sha256 -in iris-catalog.pem
#   IOXCLIENT      path to ioxclient (must be configured once via its wizard).
#   IMAGE_TAG      docker tag (default iris-iox:<IOX_ARCH>).
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
    DOCKER_PLATFORM=linux/arm64
    IOX_CPUARCH=aarch64
    ARIA2_FILE_PATTERN="ARM aarch64"
    DEFAULT_IMAGE_TAG=iris-iox:arm64
    DEFAULT_PACKAGE_DESCRIPTOR="$HERE/package.yaml"
    LOCAL_BUNDLE="$REPO/artifacts/iris-agent-arm.tgz"
    DEFAULT_PACKAGE_NAME=iris-arm64.tar
    ;;
  amd64|x86_64)
    IOX_ARCH=amd64
    DOCKER_PLATFORM=linux/amd64
    IOX_CPUARCH=x86_64
    ARIA2_FILE_PATTERN="x86-64"
    DEFAULT_IMAGE_TAG=iris-iox:amd64
    DEFAULT_PACKAGE_DESCRIPTOR="$HERE/package-amd64.yaml"
    LOCAL_BUNDLE="$REPO/artifacts/iris-agent.tgz"
    DEFAULT_PACKAGE_NAME=iris-amd64.tar
    ;;
  *)
    echo "!! IOX_ARCH must be arm64 or amd64 (got $IOX_ARCH)" >&2
    exit 2
    ;;
esac

IMAGE_TAG="${IMAGE_TAG:-$DEFAULT_IMAGE_TAG}"
PACKAGE_NAME="${PACKAGE_NAME:-$DEFAULT_PACKAGE_NAME}"
PACKAGE_DESCRIPTOR="${PACKAGE_DESCRIPTOR:-$DEFAULT_PACKAGE_DESCRIPTOR}"
CATALOG_PEM_URL="${CATALOG_PEM_URL:-}"
IOXCLIENT="${IOXCLIENT:-ioxclient}"
[ -r "$PACKAGE_DESCRIPTOR" ] \
  || { echo "!! package descriptor not readable: $PACKAGE_DESCRIPTOR" >&2; exit 1; }

CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
mkdir -p "$CTX/agent" "$CTX/agent_bin" "$OUT"

echo ">> staging agent python (incl. cli_ssh.py, verify_image.py)"
cp "$REPO"/device/agent/*.py "$CTX/agent/"
# the aria2 completion hook: not *.py, and the Dockerfile COPYs it by name,
# so a missing line here fails the build on a missing COPY source.
cp "$REPO/device/agent/peer-transfer-hook.sh" "$CTX/agent/" \
  || { echo "!! missing device/agent/peer-transfer-hook.sh (the aria2"
       echo "   --on-bt-download-complete program the Dockerfile COPYs)"; exit 1; } >&2
cp "$REPO"/device/verify_image.py "$CTX/agent/verify_image.py"   # lives in device/, agent imports it
cp "$REPO/VERSION" "$CTX/agent/VERSION"   # telemetry reports the packaged release

echo ">> staging $IOX_CPUARCH aria2c"
# This build does NOT download aria2c. The only sources are an explicit
# ARIA2C_BIN override, a local agent bundle (its aria2c is still checksum-
# verified below, since a bundle's provenance is not otherwise pinned), or
# the handed-in deliverables/aria2c-<arch> verified against
# tools/aria2c.sha256 -- see tools/get-aria2c.sh for the same idiom.
SUMS="$REPO/tools/aria2c.sha256"
DELIVERABLE="$REPO/deliverables/aria2c-$IOX_CPUARCH"

verify_aria2_checksum() {
  # $1 = candidate binary path, $2 = description for error output
  local candidate="$1" desc="$2" expected actual
  [ -f "$SUMS" ] || { echo "!! missing $SUMS -- cannot verify $desc" >&2; exit 1; }
  expected="$(awk -v a="$IOX_CPUARCH" '$2 == a { print $1 }' "$SUMS")"
  [ -n "$expected" ] \
    || { echo "!! no checksum recorded for $IOX_CPUARCH in $SUMS" >&2; exit 1; }
  actual="$( (shasum -a 256 "$candidate" 2>/dev/null || sha256sum "$candidate") | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    cat >&2 <<EOF
!! CHECKSUM MISMATCH for $desc ($IOX_CPUARCH) -- refusing to build.
   expected: $expected   (tools/aria2c.sha256)
   actual:   $actual     ($candidate)

This usually means the deliverable is stale, or a newer client was produced
and tools/aria2c.sha256 has not been updated to adopt it. Do not "fix" this
by editing the checksum unless you intend to adopt that exact binary.
EOF
    exit 1
  fi
}

if [ -n "${ARIA2C_BIN:-}" ]; then
  cp "$ARIA2C_BIN" "$CTX/agent_bin/aria2c"
elif [ -f "$LOCAL_BUNDLE" ]; then
  tar xzf "$LOCAL_BUNDLE" -C "$CTX/agent_bin" aria2c
  verify_aria2_checksum "$CTX/agent_bin/aria2c" "$LOCAL_BUNDLE (extracted aria2c)"
elif [ -f "$DELIVERABLE" ]; then
  verify_aria2_checksum "$DELIVERABLE" "$DELIVERABLE"
  cp "$DELIVERABLE" "$CTX/agent_bin/aria2c"
else
  cat >&2 <<EOF
!! no aria2c available for $IOX_CPUARCH.

This build does not download aria2c. Provide one of:
  1. ARIA2C_BIN=/path/to/aria2c-$IOX_CPUARCH  (architecture-matched binary)
  2. $DELIVERABLE
     (handed in and verified against tools/aria2c.sha256 -- see
     tools/get-aria2c.sh $([ "$IOX_CPUARCH" = "aarch64" ] && echo arm64 || echo amd64))
EOF
  exit 1
fi
file "$CTX/agent_bin/aria2c" | grep -q "$ARIA2_FILE_PATTERN" \
  || { echo "!! aria2c does not match $IOX_CPUARCH -- set ARIA2C_BIN"; exit 1; }

echo ">> staging pinned catalog cert"
if [ -n "${CATALOG_PEM:-}" ]; then
  cp "$CATALOG_PEM" "$CTX/iris-catalog.pem"
else
  # Fetch with --insecure (-k) because the catalog server is self-signed and
  # cannot be verified by a public CA.  The fingerprint pin below is the sole
  # trust mechanism: we compare the downloaded cert's SHA-256 fingerprint to
  # CATALOG_PEM_FINGERPRINT, aborting if they differ.
  : "${CATALOG_PEM_URL:?set CATALOG_PEM_URL or provide CATALOG_PEM}"
  : "${CATALOG_PEM_FINGERPRINT:?set CATALOG_PEM_FINGERPRINT to the expected SHA256 fingerprint of the catalog cert (openssl x509 -noout -fingerprint -sha256 -in iris-catalog.pem)}"
  curl -fsS --insecure "$CATALOG_PEM_URL" -o "$CTX/iris-catalog.pem"
  grep -q "BEGIN CERTIFICATE" "$CTX/iris-catalog.pem" || { echo "!! bad cert from $CATALOG_PEM_URL"; exit 1; }
  # openssl emits:  "SHA256 Fingerprint=AA:BB:..."
  # Operators may supply the documented format "SHA256:AA:BB:..." or the raw
  # bare hex "AA:BB:...".  Normalise both sides to uppercase bare hex before
  # comparing so any of these forms compare equal.
  got="$(openssl x509 -noout -fingerprint -sha256 -in "$CTX/iris-catalog.pem" \
         | sed 's/.*Fingerprint=//' | tr -d ' \r' | tr '[:lower:]' '[:upper:]')"
  want="$(echo "$CATALOG_PEM_FINGERPRINT" \
          | sed 's/^[Ss][Hh][Aa]256[: ]*[Ff][Ii][Nn][Gg][Ee][Rr][Pp][Rr][Ii][Nn][Tt]=//
                 s/^[Ss][Hh][Aa]256://' \
          | tr -d ' \r' | tr '[:lower:]' '[:upper:]')"
  if [ "$got" != "$want" ]; then
    echo "!! catalog cert fingerprint mismatch" >&2
    echo "   expected: $CATALOG_PEM_FINGERPRINT" >&2
    echo "   got:      $got" >&2
    exit 1
  fi
  echo ">> cert fingerprint verified: $got"
fi
grep -q "BEGIN CERTIFICATE" "$CTX/iris-catalog.pem" || { echo "!! bad cert"; exit 1; }

cp "$HERE/Dockerfile" "$HERE/entrypoint.sh" "$HERE/reconcile.sh" "$CTX/"
cp "$PACKAGE_DESCRIPTOR" "$CTX/package.yaml"

echo ">> docker build ($DOCKER_PLATFORM)"
docker build --platform "$DOCKER_PLATFORM" -t "$IMAGE_TAG" "$CTX"

if [ "$PACKAGE" -eq 0 ]; then
  echo ">> image ready: $IMAGE_TAG (IOx packaging skipped)"
  exit 0
fi

# IOx CAF ships a legacy docker runtime (dockerd 19.03 on IE3x00) that only
# loads CLASSIC docker-save archives (manifest.json + uncompressed layer
# tars). Modern engines break this two ways: containerd-store `docker save`
# emits a nested OCI index with buildx attestation manifests (app installs
# and activates but never starts), and `docker buildx --output type=docker`
# emits gzip layers without the legacy layout (activation fails with "Image
# blobs/... cannot be loaded"). skopeo's docker-archive transport writes the
# classic layout from any engine — lab-verified on IE-3400 (IOS-XE 17.15).
echo ">> exporting classic docker-archive rootfs.tar via skopeo (CAF cannot load modern save layouts)"
command -v skopeo >/dev/null 2>&1 \
  || { echo "!! skopeo is required to package for IOx (apt-get/brew install skopeo)" >&2; exit 1; }
rm -f "$CTX/rootfs.tar"
skopeo copy "docker-daemon:$IMAGE_TAG" "docker-archive:$CTX/rootfs.tar:$IMAGE_TAG"
tar tf "$CTX/rootfs.tar" | grep -q "manifest.json" \
  || { echo "!! rootfs.tar has no manifest.json — not a docker-archive" >&2; exit 1; }
if tar tf "$CTX/rootfs.tar" | grep -qx "index.json"; then
  echo "!! rootfs.tar carries an OCI index — not the classic layout IE3x00 CAF can load" >&2
  exit 1
fi
if tar xOf "$CTX/rootfs.tar" manifest.json 2>/dev/null | grep -q "attestation-manifest"; then
  echo "!! rootfs.tar carries buildx attestation manifests — IE3x00 CAF cannot start such images" >&2
  exit 1
fi

echo ">> ioxclient package -> $PACKAGE_NAME"
# Package from a directory holding ONLY the descriptor and rootfs.tar.
# `ioxclient package` tars its whole working directory into artifacts.tar.gz,
# and the descriptor references nothing but rootfs.tar -- packaging the docker
# build context itself shipped a second copy of aria2c, the agent sources,
# the Dockerfile and the cert as dead weight (~3.3 MB, 5.6% of every IOx tar;
# measured 2026-09-02, scrubber #75).
PKG="$CTX/pkg"
mkdir -p "$PKG"
mv "$CTX/rootfs.tar" "$PKG/rootfs.tar"
cp "$PACKAGE_DESCRIPTOR" "$PKG/package.yaml"
( cd "$PKG" && "$IOXCLIENT" package . )
cp "$PKG/package.tar" "$OUT/$PACKAGE_NAME"
echo ">> done: $OUT/$PACKAGE_NAME"
ls -la "$OUT/$PACKAGE_NAME"
