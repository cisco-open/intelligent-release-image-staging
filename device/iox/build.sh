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
#                  agent bundle when present, otherwise download the pinned build.
#   ARIA2_VERSION / ARIA2_SHA256 / ARIA2_URL  pinned download overrides.
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
    DEFAULT_ARIA2_SHA256=0c681a89a40e0f82d1f5137608e86257eb0af201459c002941ea098f2b8c26b6
    DEFAULT_ARIA2_ASSET=aria2-aarch64-linux-musl_static.zip
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
    DEFAULT_ARIA2_SHA256=e0a09b12ef67f35f8a8e4fdddbec851d235b7c31da549d0578bff459032b499a
    DEFAULT_ARIA2_ASSET=aria2-x86_64-linux-musl_static.zip
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
ARIA2_VERSION="${ARIA2_VERSION:-1.37.0}"
ARIA2_SHA256="${ARIA2_SHA256:-$DEFAULT_ARIA2_SHA256}"
ARIA2_URL="${ARIA2_URL:-https://github.com/abcfy2/aria2-static-build/releases/download/${ARIA2_VERSION}/${DEFAULT_ARIA2_ASSET}}"
[ -r "$PACKAGE_DESCRIPTOR" ] \
  || { echo "!! package descriptor not readable: $PACKAGE_DESCRIPTOR" >&2; exit 1; }

CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
mkdir -p "$CTX/agent" "$CTX/agent_bin" "$OUT"

echo ">> staging agent python (incl. cli_ssh.py, verify_image.py)"
cp "$REPO"/device/agent/*.py "$CTX/agent/"
cp "$REPO"/device/verify_image.py "$CTX/agent/verify_image.py"   # lives in device/, agent imports it

echo ">> staging $IOX_CPUARCH aria2c"
if [ -n "${ARIA2C_BIN:-}" ]; then
  cp "$ARIA2C_BIN" "$CTX/agent_bin/aria2c"
elif [ -f "$LOCAL_BUNDLE" ]; then
  tar xzf "$LOCAL_BUNDLE" -C "$CTX/agent_bin" aria2c
else
  echo ">> no local $IOX_ARCH bundle; downloading pinned aria2c"
  curl -fsSL "$ARIA2_URL" -o "$CTX/aria2.zip"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "$ARIA2_SHA256  $CTX/aria2.zip" | sha256sum -c -
  else
    got="$(shasum -a 256 "$CTX/aria2.zip" | awk '{print $1}')"
    [ "$got" = "$ARIA2_SHA256" ] \
      || { echo "!! aria2 checksum mismatch: expected $ARIA2_SHA256, got $got" >&2; exit 1; }
  fi
  unzip -q "$CTX/aria2.zip" -d "$CTX/agent_bin"
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

cp "$HERE/Dockerfile" "$HERE/entrypoint.sh" "$CTX/"
cp "$PACKAGE_DESCRIPTOR" "$CTX/package.yaml"

echo ">> docker build ($DOCKER_PLATFORM)"
docker build --platform "$DOCKER_PLATFORM" -t "$IMAGE_TAG" "$CTX"

if [ "$PACKAGE" -eq 0 ]; then
  echo ">> image ready: $IMAGE_TAG (IOx packaging skipped)"
  exit 0
fi

echo ">> ioxclient docker package -> $PACKAGE_NAME"
( cd "$CTX" && "$IOXCLIENT" docker package "$IMAGE_TAG" . )
cp "$CTX/package.tar" "$OUT/$PACKAGE_NAME"
echo ">> done: $OUT/$PACKAGE_NAME"
ls -la "$OUT/$PACKAGE_NAME"
