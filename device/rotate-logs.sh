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
    # A same-directory temporary file (fresh, 0600) avoids following an
    # attacker-controlled "$f.tmp" symlink.
    tmp="$(mktemp "$(dirname "$f")/.$(basename "$f").XXXXXX")"
    tail -c "$MAX_BYTES" "$f" > "$tmp"
    # Copy-truncate, never rename. aria2c holds the log open for its whole
    # life and has no reopen signal: renaming a new inode over the path left
    # the daemon writing to the old, now-unlinked inode -- invisible to `dir`,
    # never trimmed again, growing until the daemon exited -- while the
    # visible file froze at the moment of rotation. Truncating in place and
    # appending the tail keeps aria2c's O_APPEND descriptor on the one file
    # this script can see; the only loss is whatever landed between the copy
    # and the truncate.
    : > "$f"
    cat "$tmp" >> "$f"
    rm -f -- "$tmp"
    tmp=""
  fi
done
