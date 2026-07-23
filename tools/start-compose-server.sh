#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Bring up the Compose seed server and prepare both IOx packages. This is a
# host-side deployment command; it builds/stages artifacts only and never
# connects to or changes a device.
#
# Usage: tools/start-compose-server.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$REPO/server/docker-compose.yml")

"${COMPOSE[@]}" build
"${COMPOSE[@]}" run --rm iris iris-bootstrap
"${COMPOSE[@]}" up -d

for _ in $(seq 1 24); do
  health="$(docker inspect -f '{{.State.Health.Status}}' iris 2>/dev/null || true)"
  [ "$health" = healthy ] && break
  [ "$health" = unhealthy ] && {
    "${COMPOSE[@]}" logs --tail=100 iris >&2
    exit 1
  }
  sleep 5
done
[ "$health" = healthy ] || { echo "!! iris did not become healthy" >&2; exit 1; }

"$REPO/tools/provision-iox-packages.sh"
