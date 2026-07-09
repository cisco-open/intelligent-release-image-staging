#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Downloads a fully-static (musl) aria2c for linux-amd64 and verifies its checksum.
# Source: abcfy2/aria2-static-build (musl static releases). Pin a known version.
set -euo pipefail

VERSION="${ARIA2_VERSION:-1.37.0}"
ASSET="aria2-x86_64-linux-musl_static.zip"
URL="https://github.com/abcfy2/aria2-static-build/releases/download/${VERSION}/${ASSET}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/bin"
TMP="$(mktemp -d)"

echo "Downloading aria2 ${VERSION} static (musl) ..."
curl -fsSL "$URL" -o "$TMP/${ASSET}"

# Record the checksum you observed on first download, then enforce it on every run.
EXPECTED_SHA256="${ARIA2_SHA256:-e0a09b12ef67f35f8a8e4fdddbec851d235b7c31da549d0578bff459032b499a}"
ACTUAL_SHA256="$(shasum -a 256 "$TMP/${ASSET}" | awk '{print $1}')"
echo "Downloaded sha256: ${ACTUAL_SHA256}"
if [[ -n "$EXPECTED_SHA256" && "$EXPECTED_SHA256" != "$ACTUAL_SHA256" ]]; then
  echo "CHECKSUM MISMATCH: expected $EXPECTED_SHA256 got $ACTUAL_SHA256" >&2
  exit 1
fi

unzip -o "$TMP/${ASSET}" -d "$TMP" >/dev/null
BIN_PATH="$(find "$TMP" -name aria2c -type f | head -n1)"
install -m 0755 "$BIN_PATH" "$OUT_DIR/aria2c"
rm -rf "$TMP"
echo "Installed: $OUT_DIR/aria2c"
