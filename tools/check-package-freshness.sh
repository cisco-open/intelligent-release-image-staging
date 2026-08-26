#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Detect served artifacts whose PINNED catalog certificate no longer matches the
# certificate the catalog actually serves.
#
# Why this exists: the IOx packages bake iris-catalog.pem in at BUILD time, so
# any catalog cert change (bootstrap on a fresh volume, a deliberate rotation, a
# rebuilt lab) silently invalidates every previously built package. The device
# still installs and the IOx app still reports RUNNING -- it just can never
# authenticate, and the only evidence is a TOKEN-REFRESH-FAIL line in the
# DEVICE's syslog. Nothing server-side distinguishes "never onboarded" from
# "onboarded but rejecting our certificate". This makes that drift visible.
#
# Read-only by default. It never touches a device.
#
#   tools/check-package-freshness.sh              # report; exit 1 if any drift
#   tools/check-package-freshness.sh --rebuild    # report, then rebuild if stale
#
# Env:
#   IRIS_CONTAINER   running server container (default: iris)
#   ARTIFACTS_DIR    served artifacts dir (default: <repo>/artifacts)
#   CATALOG_HOSTPORT host:port of the catalog to probe (default: from IRIS_HOST_IP:8443)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
IRIS_CONTAINER="${IRIS_CONTAINER:-iris}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$REPO/artifacts}"
REBUILD=0
[ "${1:-}" = "--rebuild" ] && REBUILD=1

fingerprint() {  # <pem file> -> bare sha256 fingerprint, or empty
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/.*Fingerprint=//' || true
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. The certificate the catalog ACTUALLY serves -- the ground truth every
#    device is measured against.
SERVED=""
HOSTPORT="${CATALOG_HOSTPORT:-}"
if [ -z "$HOSTPORT" ]; then
  HOST_IP="$(grep -sE '^IRIS_HOST_IP=' "$REPO/server/.env" | cut -d= -f2- || true)"
  [ -n "$HOST_IP" ] && HOSTPORT="$HOST_IP:8443"
fi
if [ -n "$HOSTPORT" ]; then
  if echo | openssl s_client -connect "$HOSTPORT" 2>/dev/null \
       | openssl x509 -outform pem > "$TMP/served.pem" 2>/dev/null; then
    SERVED="$(fingerprint "$TMP/served.pem")"
  fi
fi

# 2. The certificate handed to GUEST SHELL devices at onboard time. This one is
#    re-staged per onboard, which is exactly why guestshell platforms self-heal
#    across a cert change while the IOx packages do not.
DISTRIBUTED=""
if docker inspect "$IRIS_CONTAINER" >/dev/null 2>&1 \
   && docker cp "$IRIS_CONTAINER:/srv/artifacts/iris-catalog.pem" "$TMP/dist.pem" 2>/dev/null; then
  DISTRIBUTED="$(fingerprint "$TMP/dist.pem")"
fi

echo "catalog certificate in use"
echo "  served by catalog   : ${SERVED:-<unreachable>}${HOSTPORT:+  ($HOSTPORT)}"
echo "  handed to devices   : ${DISTRIBUTED:-<unavailable>}"
REFERENCE="${SERVED:-$DISTRIBUTED}"
CATALOG_DRIFT=0
if [ -z "$REFERENCE" ]; then
  echo "!! cannot determine the live catalog certificate; is the server running?" >&2
  exit 2
fi
if [ -n "$SERVED" ] && [ -n "$DISTRIBUTED" ] && [ "$SERVED" != "$DISTRIBUTED" ]; then
  CATALOG_DRIFT=1
  echo "  !! MISMATCH: the served cert differs from the one devices are told to trust."
  echo "     Every NEW onboard will fail too, not just the pre-built packages."
fi

# 3. Each IOx package pins a copy at build time -- compare it to the reference.
STALE=()
echo
echo "pinned certificate per served package"
for PKG in iris-amd64.tar iris-arm64.tar; do
  P="$ARTIFACTS_DIR/$PKG"
  if [ ! -f "$P" ]; then
    printf '  %-18s %s\n' "$PKG" "absent"
    continue
  fi
  BUILT="$(date -r "$P" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')"
  rm -rf "$TMP/pk"; mkdir -p "$TMP/pk"
  ( cd "$TMP/pk" && tar xf "$P" artifacts.tar.gz 2>/dev/null ) || true
  FP=""
  if [ -f "$TMP/pk/artifacts.tar.gz" ]; then
    C="$(tar tzf "$TMP/pk/artifacts.tar.gz" 2>/dev/null | grep -i 'catalog\.pem' | head -1 || true)"
    if [ -n "$C" ]; then
      ( cd "$TMP/pk" && tar xzf artifacts.tar.gz "$C" 2>/dev/null ) || true
      FP="$(fingerprint "$TMP/pk/$C")"
    fi
  fi
  if [ -z "$FP" ]; then
    printf '  %-18s built %s  %s\n' "$PKG" "$BUILT" "NO PINNED CERT FOUND"
    STALE+=("$PKG")
  elif [ "$FP" = "$REFERENCE" ]; then
    printf '  %-18s built %s  OK\n' "$PKG" "$BUILT"
  else
    printf '  %-18s built %s  STALE -> pins %s\n' "$PKG" "$BUILT" "$FP"
    STALE+=("$PKG")
  fi
done

echo
if [ ${#STALE[@]} -eq 0 ] && [ "$CATALOG_DRIFT" -eq 0 ]; then
  echo "all served packages pin the live catalog certificate."
  exit 0
fi

if [ ${#STALE[@]} -gt 0 ]; then
  echo "STALE: ${STALE[*]}"
  echo "Devices deployed from these packages will install and report RUNNING, then"
  echo "fail every catalog call with CERTIFICATE_VERIFY_FAILED and never heartbeat."
fi
if [ "$CATALOG_DRIFT" -eq 1 ]; then
  echo "Fix the served/distributed catalog certificate mismatch, then rerun this check."
  echo "Package rebuilding cannot repair the certificate handed to Guest Shell devices."
  exit 1
fi
if [ "$REBUILD" -eq 1 ]; then
  echo
  echo ">> rebuilding all IOx packages"
  "$HERE/provision-iox-packages.sh"
  echo
  echo ">> re-checking"
  exec "$0"
fi
echo "Fix: tools/provision-iox-packages.sh   (or re-run this with --rebuild)"
exit 1
