#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Download Cisco's IOx package CLI for Linux amd64. Cisco's download page does
# not publish a checksum or detached signature for this artifact, and
# ioxclient SIGNS every IOx package devices install, so this helper pins the
# binary itself: the first-seen sha256 of the extracted `ioxclient` executable
# is recorded in tools/ioxclient.sha256
# (format: "<sha256>  <version>", one line per pinned version, like
# tools/aria2c.sha256) and the download is refused on a mismatch. A version
# with no recorded checksum is refused too, unless IOXCLIENT_SKIP_VERIFY=1 is
# set explicitly for the one-off run that records it:
#
#   IOXCLIENT_SKIP_VERIFY=1 tools/get-ioxclient.sh   # prints the sha256 to pin
#
# Usage: tools/get-ioxclient.sh [INSTALL_DIR]
set -euo pipefail

VERSION="${IOXCLIENT_VERSION:-1.18.0.0}"
URL="${IOXCLIENT_URL:-https://pubhub.devnetcloud.com/media/iox/docs/artifacts/ioxclient/ioxclient-v${VERSION}/ioxclient_${VERSION}_linux_amd64.tar.gz}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DIR="${1:-$REPO/tools/bin}"
SUMS="${IOXCLIENT_SHA256_FILE:-$REPO/tools/ioxclient.sha256}"

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

# The pin is on the extracted BINARY (the thing that runs and signs
# packages), not the tarball wrapper.
actual="$( (sha256sum "$BIN" 2>/dev/null || shasum -a 256 "$BIN") | awk '{print $1}')"
expected=""
[ -f "$SUMS" ] && expected="$(awk -v v="$VERSION" '$2 == v { print $1 }' "$SUMS")"
if [ -z "$expected" ]; then
  if [ "${IOXCLIENT_SKIP_VERIFY:-0}" = "1" ]; then
    echo "!! WARNING: no checksum recorded for ioxclient $VERSION in $SUMS -- installing UNVERIFIED (IOXCLIENT_SKIP_VERIFY=1)" >&2
    echo "   record it to pin this download:  echo '$actual  $VERSION' >> ${SUMS#$REPO/}" >&2
  else
    cat >&2 <<EOF
!! no checksum recorded for ioxclient $VERSION in $SUMS -- refusing to install.
   ioxclient signs every IOx package devices install, so an unpinned download
   is a supply-chain hole. Downloaded binary sha256: $actual
   Inspect the download, then pin it:
     echo '$actual  $VERSION' >> ${SUMS#$REPO/}
   or, for a deliberate one-off unverified install, set IOXCLIENT_SKIP_VERIFY=1.
EOF
    exit 1
  fi
elif [ "$actual" != "$expected" ]; then
  cat >&2 <<EOF
!! CHECKSUM MISMATCH for ioxclient $VERSION -- refusing to install.
   expected: $expected   ($SUMS)
   actual:   $actual     ($URL)

Cisco may have republished the artifact, or the download was tampered with.
Do not "fix" this by editing the checksum unless you have inspected the new
tarball and intend to adopt it.
EOF
  exit 1
else
  echo ">> ioxclient $VERSION sha256 verified against $SUMS"
fi
install -m 0755 "$BIN" "$DEST_DIR/ioxclient"
echo ">> installed $DEST_DIR/ioxclient"
