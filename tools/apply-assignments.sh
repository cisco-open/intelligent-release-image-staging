#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Apply image assignments from fleet/assignments.csv (device_id,image_id).
# Run on the server machine. Each device picks up its assignment within ~60s;
# a device whose image CHANGED cleans up the old one automatically first.
#
# Usage: tools/apply-assignments.sh [--dry-run] [csv]
#
# The whole CSV is validated BEFORE the first assignment is written -- row
# shape, identifier format, duplicate device ids, and every image_id against
# the server's published image list -- so a typo on row 40 cannot leave rows
# 1-39 applied and the rest not. Errors that only the server can raise at
# apply time (an image quarantined between validation and apply) are reported
# per row, and the summary then names exactly which rows were and were not
# applied rather than claiming the fleet is consistent.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; shift; fi
CSV="${1:-$REPO/fleet/assignments.csv}"
[ -f "$CSV" ] || { echo "no assignments file: $CSV (copy fleet/assignments.csv.example)" >&2; exit 1; }
IRIS_CONTAINER="${IRIS_CONTAINER:-iris}"
docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$IRIS_CONTAINER" || {
  echo "ERROR: the '$IRIS_CONTAINER' container is not running. Start it with tools/start-compose-server.sh, or set IRIS_CONTAINER=<name>." >&2
  exit 1
}

assign() {
  docker exec "$IRIS_CONTAINER" iris-assign "$1" "$2"
}

# Same identifier grammar tools/gen-device-installers.sh accepts for device
# ids; catalog image ids (e.g. cat9k_iosxe.26.01.01) fit the same shape.
ID_RE='^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'

# ── Pass 1: parse + validate every data row; nothing is applied yet ──────────
# The published image set is fetched ONCE from the server so every image_id
# is checked before any row is written.
published="$(docker exec "$IRIS_CONTAINER" iris-assign 2>/dev/null \
  | awk '/^published images:/ { p = 1; next } /^assignments:/ { p = 0 } p && $1 != "(none" { print $1 }')" || published=""

DEVICE_IDS=()
IMAGE_IDS=()
errors=0
lineno=0
err() { echo "ERROR: line $lineno: $*" >&2; errors=$((errors + 1)); }
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno + 1))
  line="${line%$'\r'}"
  [ -z "${line// /}" ] && continue
  case "$line" in \#*) continue ;; esac
  IFS=, read -r device_id image_id rest <<< "$line"
  device_id="$(echo "$device_id" | tr -d ' \r')"
  image_id="$(echo "${image_id:-}" | tr -d ' \r')"
  rest="$(echo "${rest:-}" | tr -d ' \r')"
  [ -z "$device_id" ] && continue
  [ "$device_id" = "device_id" ] && continue
  if [ -n "$rest" ]; then err "expected 2 columns (device_id,image_id), got more: '$line'"; continue; fi
  if [ -z "$image_id" ]; then err "empty image_id for device '$device_id'"; continue; fi
  [[ "$device_id" =~ $ID_RE ]] || { err "device_id '$device_id' has an invalid format"; continue; }
  [[ "$image_id" =~ $ID_RE ]] || { err "image_id '$image_id' has an invalid format"; continue; }
  for seen in ${DEVICE_IDS[@]+"${DEVICE_IDS[@]}"}; do
    if [ "$seen" = "$device_id" ]; then err "duplicate device_id '$device_id'"; continue 2; fi
  done
  if [ -n "$published" ] && ! printf '%s\n' "$published" | grep -qxF "$image_id"; then
    err "image '$image_id' (device '$device_id') is not published on the server"
    continue
  fi
  DEVICE_IDS+=("$device_id")
  IMAGE_IDS+=("$image_id")
done < "$CSV"
if [ -z "$published" ]; then
  echo "WARNING: could not read the published image list from '$IRIS_CONTAINER'; image ids are not pre-validated" >&2
fi
if [ "$errors" -gt 0 ]; then
  echo "Aborting: $errors validation error(s) -- no assignments applied." >&2
  exit 1
fi
if [ "${#DEVICE_IDS[@]}" -eq 0 ]; then
  echo "no assignment rows in $CSV -- nothing to apply"
  exit 0
fi
if [ "$DRY_RUN" -eq 1 ]; then
  echo "dry-run: ${#DEVICE_IDS[@]} assignment(s) validated, none applied:"
  for i in "${!DEVICE_IDS[@]}"; do echo "  ${DEVICE_IDS[$i]} -> ${IMAGE_IDS[$i]}"; done
  exit 0
fi

# ── Pass 2: apply (every row passed validation) ───────────────────────────────
applied=0
failed=()
for i in "${!DEVICE_IDS[@]}"; do
  if assign "${DEVICE_IDS[$i]}" "${IMAGE_IDS[$i]}"; then
    applied=$((applied + 1))
  else
    failed+=("${DEVICE_IDS[$i]} -> ${IMAGE_IDS[$i]}")
  fi
done
if [ "${#failed[@]}" -gt 0 ]; then
  echo "applied $applied of ${#DEVICE_IDS[@]} assignment(s); ${#failed[@]} FAILED at apply time:" >&2
  for f in "${failed[@]}"; do echo "  $f" >&2; done
  echo "The applied rows are live; fix the failed rows and re-run (re-applying an unchanged row is harmless)." >&2
  exit 1
fi
echo "applied $applied assignment(s)"
