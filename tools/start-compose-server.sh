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

# server/Dockerfile COPYs bin/aria2c, the handed-in seeder client. That binary
# is git-ignored on purpose -- only its checksum and provenance live in the
# repository (tools/aria2c.sha256) -- so a fresh clone has none and the COPY
# fails inside BuildKit with a cache-key error naming no remedy (issue #203).
# Name the remedy here, before anything is built. The pin itself is still
# enforced in the image build; this check is only about the file being present.
if [ ! -f "$REPO/bin/aria2c" ]; then
  cat >&2 <<EOF
!! missing $REPO/bin/aria2c — server/Dockerfile cannot be built without it.

The seeder client is HANDED IN: produced by the aria2-next-static project,
never downloaded and never built here, and deliberately not committed. Install
the pinned binary, then start me again:

  tools/get-aria2c.sh amd64

It verifies the binary against tools/aria2c.sha256 and fails closed on a
mismatch. Set ARIA2C_DELIVERABLE to point at a handed-in binary elsewhere.
EOF
  exit 1
fi

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
