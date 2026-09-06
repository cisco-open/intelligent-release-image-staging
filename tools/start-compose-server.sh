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

# --pull: server/Dockerfile's base is a floating tag; without it a rebuild
# silently reuses the host's cached python:3.12-slim-trixie and misses
# Debian security updates already on the tag (issue #13; measured 2026-09-02).
"${COMPOSE[@]}" build --pull
"${COMPOSE[@]}" run --rm iris iris-bootstrap
"${COMPOSE[@]}" up -d

# Resolve the container this compose project just started rather than trusting
# the literal name "iris". On a host that already runs a live IRIS, the literal
# reaches the PRODUCTION container -- the health poll below would report the
# stack healthy because production is, and the XR freshness check further down
# would compare against production's catalog certificate. IRIS_CONTAINER is the
# same override the rest of tools/ honours (and names the container in
# server/docker-compose.yml), so an explicit setting wins; otherwise the id
# comes from compose itself.
IRIS_CONTAINER="${IRIS_CONTAINER:-$("${COMPOSE[@]}" ps -q iris 2>/dev/null | head -n 1 || true)}"
[ -n "$IRIS_CONTAINER" ] || { echo "!! could not resolve the iris container for this compose project" >&2; exit 1; }

for _ in $(seq 1 24); do
  health="$(docker inspect -f '{{.State.Health.Status}}' "$IRIS_CONTAINER" 2>/dev/null || true)"
  [ "$health" = healthy ] && break
  [ "$health" = unhealthy ] && {
    "${COMPOSE[@]}" logs --tail=100 iris >&2
    exit 1
  }
  sleep 5
done
[ "$health" = healthy ] || { echo "!! iris did not become healthy" >&2; exit 1; }

[ -x "$REPO/tools/provision-iox-packages.sh" ] || { echo ">> IOx packaging tools not present; skipping IOx package staging" >&2; exit 0; }
"$REPO/tools/provision-iox-packages.sh"

# The XR RPM is optional and built separately. If one is already staged, check
# its byte/provenance binding; certificate rotation is intentionally irrelevant
# because onboarding now supplies the current public certificate at runtime.
XR_RPM="$REPO/artifacts/iris-xr.rpm"
if [ -f "$XR_RPM" ]; then
  XR_STATE="$(PYTHONPATH="$REPO/server${PYTHONPATH:+:$PYTHONPATH}" python3 - \
      "$XR_RPM" <<'PY'
import sys
import setup_status

item = setup_status.package_readiness(
    sys.argv[1], "iris-xr.rpm", "xr-appmgr", "linux/amd64",
    "tools/build-xr-package.sh --out artifacts/")
print(item["state"])
PY
)"
  if [ "$XR_STATE" != ok ]; then
    echo "WARNING: artifacts/iris-xr.rpm does not match its canonical-image provenance ($XR_STATE)." >&2
    echo "  Rebuild it: tools/build-xr-package.sh --out artifacts/" >&2
  fi
fi
