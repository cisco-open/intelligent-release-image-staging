#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Truncate IRIS logs that exceed a size cap (keep the tail). Called on the
# EEM monitor cadence so aria2c.log never fills flash. Pure shell; no rotation
# history kept (flash is precious) — we keep the last MAX_BYTES of each file.
set -euo pipefail
MAX_BYTES="${MAX_BYTES:-52428800}"     # 50 MB default
tmp=""
cleanup() { [ -z "$tmp" ] || rm -f -- "$tmp"; }
trap cleanup EXIT HUP INT TERM
for f in "$@"; do
  [ -f "$f" ] || continue
  size="$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)"
  if [ "$size" -gt "$MAX_BYTES" ]; then
    mode="$(stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f")"
    # A same-directory temporary file makes the replacement atomic and avoids
    # following an attacker-controlled "$f.tmp" symlink.
    tmp="$(mktemp "$(dirname "$f")/.$(basename "$f").XXXXXX")"
    tail -c "$MAX_BYTES" "$f" > "$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$f"
    tmp=""
  fi
done
