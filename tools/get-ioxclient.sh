#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Download Cisco's IOx package CLI for Linux amd64. Cisco's download page does
# not publish a checksum or detached signature for this artifact; update the
# pinned version deliberately and inspect the installed version after download.
#
# Usage: tools/get-ioxclient.sh [INSTALL_DIR]
set -euo pipefail

VERSION=1.18.0.0
URL="https://pubhub.devnetcloud.com/media/iox/docs/artifacts/ioxclient/ioxclient-v${VERSION}/ioxclient_${VERSION}_linux_amd64.tar.gz"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DIR="${1:-$REPO/tools/bin}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64|Linux-amd64) ;;
  *) echo "!! this helper supports Linux amd64 only; install Cisco ioxclient separately and set IOXCLIENT" >&2; exit 2 ;;
esac

mkdir -p "$DEST_DIR"
if [ -x "$DEST_DIR/ioxclient" ]; then
  echo ">> ioxclient already present: $DEST_DIR/ioxclient"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo ">> downloading Cisco ioxclient ${VERSION}"
curl --fail --location --proto '=https' --tlsv1.2 "$URL" -o "$TMP/ioxclient.tar.gz"
tar -xzf "$TMP/ioxclient.tar.gz" -C "$TMP"
BIN="$(find "$TMP" -type f -name ioxclient -perm -u+x -print -quit)"
[ -n "$BIN" ] || { echo "!! download did not contain an executable ioxclient" >&2; exit 1; }
install -m 0755 "$BIN" "$DEST_DIR/ioxclient"
echo ">> installed $DEST_DIR/ioxclient"
