#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Apply image assignments from fleet/assignments.csv (device_id,image_id).
# Run on the server machine. Each device picks up its assignment within ~60s;
# a device whose image CHANGED cleans up the old one automatically first.
#
# Usage: tools/apply-assignments.sh [csv]
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CSV="${1:-$REPO/fleet/assignments.csv}"
[ -f "$CSV" ] || { echo "no assignments file: $CSV (copy fleet/assignments.csv.example)" >&2; exit 1; }

assign() {
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx iris; then
    docker exec iris iris-assign "$1" "$2"
  else
    python3 "$REPO/server/iris-assign" "$1" "$2"          # bare-metal
  fi
}

# ── Pass 1: validate every data row before touching any device ────────────────
# Aborting mid-apply leaves a partially-configured fleet.  Collect all errors
# first; only proceed when every row is well-formed.
errors=0
while IFS=, read -r device_id image_id _rest || [ -n "$device_id" ]; do
  device_id="$(echo "$device_id" | tr -d ' \r')"
  image_id="$(echo "$image_id"  | tr -d ' \r')"
  [ -z "$device_id" ] && continue
  [ "$device_id" = "device_id" ] && continue
  case "$device_id" in \#*) continue;; esac
  if [ -z "$image_id" ]; then
    echo "ERROR: empty image_id for device '$device_id'" >&2
    errors=$((errors + 1))
  fi
done < "$CSV"
if [ "$errors" -gt 0 ]; then
  echo "Aborting: $errors validation error(s) — no assignments applied." >&2
  exit 1
fi

# ── Pass 2: apply assignments (all rows are valid) ────────────────────────────
n=0
while IFS=, read -r device_id image_id _rest || [ -n "$device_id" ]; do
  device_id="$(echo "$device_id" | tr -d ' \r')"
  image_id="$(echo "$image_id"  | tr -d ' \r')"
  [ -z "$device_id" ] && continue
  [ "$device_id" = "device_id" ] && continue
  case "$device_id" in \#*) continue;; esac
  assign "$device_id" "$image_id"
  n=$((n + 1))
done < "$CSV"
echo "applied $n assignment(s)"
