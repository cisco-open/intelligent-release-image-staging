#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Build the aarch64 IRIS IOx Docker app (iris.tar) for the IE-3x00.
#
#   ./build.sh [OUTPUT_DIR]
#
# Assembles a build context (the agent python + an aarch64 aria2c + the pinned
# catalog cert), builds the linux/arm64 image (native on Apple silicon), and
# packages it with ioxclient into <OUTPUT_DIR>/iris.tar.
#
# Inputs (env overridable):
#   ARIA2C_BIN     aarch64 aria2c. Default: extracted from artifacts/iris-agent-arm.tgz.
#   CATALOG_PEM    pinned server cert. Default: fetched from $CATALOG_PEM_URL.
#   CATALOG_PEM_URL  default https://100.90.168.20:8000/iris-catalog.pem
#   CATALOG_PEM_FINGERPRINT  expected SHA-256 fingerprint of the catalog cert
#                  (format: "SHA256:AA:BB:...").  Required when CATALOG_PEM is
#                  not supplied (i.e. when the cert is fetched over the network).
#                  The build aborts if the fetched cert's fingerprint does not
#                  match, preventing a MITM from baking a rogue cert into the
#                  fleet image.  Obtain it once with:
#                    openssl x509 -noout -fingerprint -sha256 -in iris-catalog.pem
#   IOXCLIENT      path to ioxclient (must be configured once via its wizard).
#   IMAGE_TAG      docker tag (default iris-iox:arm64).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${1:-$HERE/out}"
IMAGE_TAG="${IMAGE_TAG:-iris-iox:arm64}"
CATALOG_PEM_URL="${CATALOG_PEM_URL:-https://100.90.168.20:8000/iris-catalog.pem}"
IOXCLIENT="${IOXCLIENT:-ioxclient}"

CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
mkdir -p "$CTX/agent" "$CTX/agent_bin" "$OUT"

echo ">> staging agent python (incl. cli_ssh.py, verify_image.py)"
cp "$REPO"/device/agent/*.py "$CTX/agent/"
cp "$REPO"/device/verify_image.py "$CTX/agent/verify_image.py"   # lives in device/, agent imports it

echo ">> staging aarch64 aria2c"
if [ -n "${ARIA2C_BIN:-}" ]; then
  cp "$ARIA2C_BIN" "$CTX/agent_bin/aria2c"
else
  tar xzf "$REPO/artifacts/iris-agent-arm.tgz" -C "$CTX/agent_bin" aria2c
fi
file "$CTX/agent_bin/aria2c" | grep -q "ARM aarch64" \
  || { echo "!! aria2c is not aarch64 -- set ARIA2C_BIN"; exit 1; }

echo ">> staging pinned catalog cert"
if [ -n "${CATALOG_PEM:-}" ]; then
  cp "$CATALOG_PEM" "$CTX/iris-catalog.pem"
else
  # Fetch with --insecure (-k) because the catalog server is self-signed and
  # cannot be verified by a public CA.  The fingerprint pin below is the sole
  # trust mechanism: we compare the downloaded cert's SHA-256 fingerprint to
  # CATALOG_PEM_FINGERPRINT, aborting if they differ.
  : "${CATALOG_PEM_FINGERPRINT:?set CATALOG_PEM_FINGERPRINT to the expected SHA256 fingerprint of the catalog cert (openssl x509 -noout -fingerprint -sha256 -in iris-catalog.pem)}"
  curl -s --insecure "$CATALOG_PEM_URL" -o "$CTX/iris-catalog.pem"
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

cp "$HERE/Dockerfile" "$HERE/entrypoint.sh" "$HERE/package.yaml" "$CTX/"

echo ">> docker build (linux/arm64)"
docker build --platform linux/arm64 -t "$IMAGE_TAG" "$CTX"

echo ">> ioxclient docker package -> iris.tar"
( cd "$CTX" && "$IOXCLIENT" docker package "$IMAGE_TAG" . )
cp "$CTX/package.tar" "$OUT/iris.tar"
echo ">> done: $OUT/iris.tar"
ls -la "$OUT/iris.tar"
