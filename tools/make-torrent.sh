#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Create a PRIVATE .torrent (no DHT/PEX) for a file, pointing at the IRIS
# tracker. The normal publishing path is `iris-publish` (server/publish.py),
# which mints the torrent AND registers the image in the catalog; this helper
# exists for hand-built torrents only.
#
# The IRIS tracker refuses every announce that carries no credential
# (server/tracker.py -> auth.resolve_announce_principal answers 403), so the
# announce URL embedded here MUST carry one. Supply either:
#   ANNOUNCE_TOKEN=<token>   the seeder announce token (from the server's
#                            secrets store; iris-publish uses the same one),
#                            embedded as /announce?announce_token=<token>
#   ANNOUNCE_URL=<url>       a complete announce URL, used verbatim -- it
#                            must still carry a non-empty announce_token=
#                            (or legacy key=) query parameter
#
# Usage: ANNOUNCE_TOKEN=... tools/make-torrent.sh <file> <tracker-host>
set -euo pipefail
usage="usage: ANNOUNCE_TOKEN=<token> make-torrent.sh <file> <tracker-host>   (or ANNOUNCE_URL=<full announce url>)"
FILE="${1:?$usage}"
TRACKER_HOST="${2:?$usage}"
[ -f "$FILE" ] || { echo "ERROR: no such file: $FILE" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

valid_https_announce() {
  # Feed the possibly credential-bearing URL on stdin, never as Python argv.
  # tracker_announce validates the token-free origin/path shared by every
  # server-side producer; this wrapper separately rejects fragments/control
  # bytes before removing the query for that check.
  printf '%s' "$1" | PYTHONPATH="$SCRIPT_DIR/../server" python3 -c '
import sys
from urllib.parse import urlsplit, urlunsplit
import tracker_announce
try:
    raw = sys.stdin.read()
    if any(ord(c) <= 0x20 or ord(c) == 0x7f for c in raw):
        raise ValueError
    parts = urlsplit(raw)
    if parts.fragment:
        raise ValueError
    tracker_announce.validate(urlunsplit(
        (parts.scheme, parts.netloc, parts.path, "", "")))
except Exception:
    raise SystemExit(1)
'
}

if [ -n "${ANNOUNCE_URL:-}" ]; then
  # Verbatim, but it must still carry a credential the tracker honours
  # (announce_token=, or the legacy key=) with a non-empty value -- otherwise
  # this escape hatch recreates exactly the unusable torrent refused below.
  cred_re='[?&](announce_token|key)=[^&[:space:]]+'
  [[ "$ANNOUNCE_URL" =~ $cred_re ]] \
    || { echo "ERROR: ANNOUNCE_URL carries no announce credential (needs a non-empty announce_token= or key= query parameter); the tracker would answer 403" >&2; exit 1; }
  valid_https_announce "$ANNOUNCE_URL" \
    || { echo "ERROR: ANNOUNCE_URL must use the configured HTTPS tracker /announce endpoint" >&2; exit 1; }
  ANNOUNCE="$ANNOUNCE_URL"
elif [ -n "${ANNOUNCE_TOKEN:-}" ]; then
  [[ "$ANNOUNCE_TOKEN" =~ ^[A-Za-z0-9._~-]+$ ]] \
    || { echo "ERROR: ANNOUNCE_TOKEN must be URL-safe (letters, digits, . _ ~ -)" >&2; exit 1; }
  ANNOUNCE="https://${TRACKER_HOST}:6969/announce?announce_token=${ANNOUNCE_TOKEN}"
  valid_https_announce "$ANNOUNCE" \
    || { echo "ERROR: tracker host does not form a usable HTTPS announce endpoint" >&2; exit 1; }
else
  cat >&2 <<EOF
ERROR: no announce credential. The IRIS tracker rejects a credential-less
announce with 403, so a torrent made without one can never seed or download.
Set ANNOUNCE_TOKEN=<seeder announce token> (or ANNOUNCE_URL=<full announce
URL>) and re-run -- or publish through iris-publish, which does this for you.
EOF
  exit 1
fi

OUT="${FILE##*/}.torrent"
# -p sets the private flag (disables DHT/PEX in compliant clients incl. aria2)
mktorrent -p -a "$ANNOUNCE" -o "$OUT" "$FILE"
echo "Created $OUT (announce: https://${TRACKER_HOST}:6969/announce?announce_token=<redacted>)"
