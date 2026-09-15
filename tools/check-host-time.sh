#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Run ON EACH Docker host / eligible Kubernetes node, not inside a container.
# Read-only. No NTP server is selected and no host settings are changed.
set -euo pipefail
export LC_ALL=C
if command -v chronyc >/dev/null 2>&1; then
  status="$(timeout 10 chronyc tracking 2>/dev/null)" || status=""
  if printf '%s\n' "$status" | grep -Eq '^Leap status[[:space:]]*:[[:space:]]*Normal$' \
      && printf '%s\n' "$status" | grep -Eq '^Stratum[[:space:]]*:[[:space:]]*([1-9]|1[0-5])$' \
      && printf '%s\n' "$status" | grep -Eq '^Reference ID[[:space:]]*:[[:space:]]*[[:xdigit:]]{8}([[:space:]]|$)' \
      && ! printf '%s\n' "$status" | grep -Eqi '^Reference ID[[:space:]]*:[[:space:]]*(7F7F|00000000|.*\(LOCAL\))'; then
    echo "Host time preflight passed (chrony synchronized)."
    exit 0
  fi
elif command -v timedatectl >/dev/null 2>&1; then
  status="$(timeout 10 timedatectl show -p NTPSynchronized --value 2>/dev/null)" || status=""
  enabled="$(timeout 10 timedatectl show -p NTP --value 2>/dev/null)" || enabled=""
  if [ "$status" = yes ] && [ "$enabled" = yes ]; then
    echo "Host time preflight passed (system clock synchronized)."
    exit 0
  fi
fi
echo "ERROR: host time synchronization is absent or unverified. Configure the host's approved time source, verify its selected peer, then retry. Check every Docker host and every eligible Kubernetes node; containers inherit the node clock." >&2
exit 1
