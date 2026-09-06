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
#                            must carry one unambiguous, non-empty credential
#                            query value (announce_token= or key=)
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
  # server-side producer; this wrapper checks the query using the tracker
  # parser rules. Return 1 for an invalid endpoint, 2 for invalid credentials.
  printf '%s' "$1" | PYTHONPATH="$SCRIPT_DIR/../server" python3 -c '
import sys
from urllib.parse import parse_qsl, urlsplit, urlunsplit
import tracker_announce
try:
    raw = sys.stdin.read()
    if "#" in raw or any(ord(c) <= 0x20 or ord(c) == 0x7f for c in raw):
        raise ValueError
    parts = urlsplit(raw)
    if parts.path != tracker_announce.ANNOUNCE_PATH:
        raise ValueError
    tracker_announce.validate(urlunsplit(
        (parts.scheme, parts.netloc, parts.path, "", "")))
except Exception:
    raise SystemExit(1)

# Match auth.resolve_announce_principal: preserve blank occurrences, reject
# duplicate dedicated parameters, and prefer a nonempty dedicated value.
pairs = parse_qsl(parts.query, keep_blank_values=True)
dedicated = [value for name, value in pairs if name == "announce_token"]
if len(dedicated) > 1:
    raise SystemExit(2)
if dedicated and dedicated[0]:
    credential = dedicated[0]
else:
    keys = {value for name, value in pairs if name == "key" and value}
    # This helper cannot check the remote secret store, so multiple distinct
    # fallback keys are potentially ambiguous. Repeated identical keys are OK.
    if len(keys) != 1:
        raise SystemExit(2)
    credential = keys.pop()
if any(not 33 <= ord(c) <= 126 for c in credential):
    raise SystemExit(2)
'
}

if [ -n "${ANNOUNCE_URL:-}" ]; then
  if valid_https_announce "$ANNOUNCE_URL"; then
    ANNOUNCE="$ANNOUNCE_URL"
  else
    validation_status=$?
    if [ "$validation_status" -eq 2 ]; then
      echo "ERROR: ANNOUNCE_URL has no announce credential or an ambiguous/invalid credential query" >&2
    else
      echo "ERROR: ANNOUNCE_URL must use the configured HTTPS tracker /announce endpoint" >&2
    fi
    exit 1
  fi
elif [ -n "${ANNOUNCE_TOKEN:-}" ]; then
  announce_query="$(printf '%s' "$ANNOUNCE_TOKEN" | python3 -c '
import sys
from urllib.parse import urlencode
token = sys.stdin.read()
if not token or any(not 33 <= ord(c) <= 126 for c in token):
    raise SystemExit(1)
print(urlencode({"announce_token": token}))
')" || { echo "ERROR: ANNOUNCE_TOKEN must contain printable ASCII without whitespace" >&2; exit 1; }
  ANNOUNCE="https://${TRACKER_HOST}:6969/announce?${announce_query}"
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
