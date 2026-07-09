#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Create a PRIVATE .torrent (no DHT/PEX) for a file, pointing at the lab tracker.
set -euo pipefail
FILE="${1:?usage: make-torrent.sh <file> <tracker-host>}"
TRACKER_HOST="${2:?usage: make-torrent.sh <file> <tracker-host>}"
OUT="${FILE##*/}.torrent"
# -p sets the private flag (disables DHT/PEX in compliant clients incl. aria2)
mktorrent -p -a "http://${TRACKER_HOST}:6969/announce" -o "$OUT" "$FILE"
echo "Created $OUT"
