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

# XR RPM freshness (Cisco 8000 series, IOS-XR): this bring-up only stages
# the two IOx tars above -- the XR RPM is built separately and out of band
# (tools/build-xr-package.sh) and is entirely optional (a server with no
# Cisco 8000 devices in scope never needs one). An ABSENT RPM is therefore
# silent, same "absent = neutral" rule tools/check-package-freshness.sh
# uses for it. A PRESENT RPM that predates the certificate this bring-up
# just (re)provisioned is different: docker-entrypoint.sh mints iris-
# catalog.pem fresh on every start, so a prebuilt RPM naturally cannot pin
# a certificate that did not exist yet. Warn with the exact remedy rather
# than rebuilding automatically -- building the RPM needs docker context
# decisions (base image, CATALOG_PEM, ...) this deploy script does not own.
# The baseline is the certificate's OWN notBefore, never the mtime of
# /srv/artifacts/iris-catalog.pem. That file is a staged COPY rewritten at every
# bring-up, so its mtime records the last staging rather than the certificate,
# and comparing against it warned about a current RPM purely because this script
# had just re-copied the pem -- measured 2026-08-31, where the RPM was built
# eleven minutes AFTER the very certificate it was accused of predating.
XR_RPM="$REPO/artifacts/iris-xr.rpm"
if [ -f "$XR_RPM" ]; then
  CERT_NB="$(docker exec "$IRIS_CONTAINER" openssl x509 -in /srv/artifacts/iris-catalog.pem \
               -noout -startdate 2>/dev/null | sed 's/^notBefore=//' || true)"
  CERT_EPOCH=""
  if [ -n "$CERT_NB" ]; then
    CERT_EPOCH="$(date -u -d "$CERT_NB" '+%s' 2>/dev/null \
      || date -u -j -f '%b %e %H:%M:%S %Y %Z' "$CERT_NB" '+%s' 2>/dev/null || true)"
  fi
  RPM_EPOCH="$(date -r "$XR_RPM" '+%s' 2>/dev/null || true)"
  if [ -n "$CERT_EPOCH" ] && [ -n "$RPM_EPOCH" ] && [ "$RPM_EPOCH" -lt "$CERT_EPOCH" ]; then
    echo "WARNING: artifacts/iris-xr.rpm predates the live catalog certificate (build time only -- contents not inspected)." >&2
    echo "  Rebuild it: tools/build-xr-package.sh --out artifacts/   (CATALOG_PEM: the live certificate, certificate block only)" >&2
  fi
fi
