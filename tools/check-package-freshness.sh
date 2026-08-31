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

# <pem file> -> the certificate's OWN creation time as epoch seconds, or empty.
#
# This exists because a certificate's notBefore is the only baseline that
# survives being copied. The obvious alternative -- the mtime of the pem file
# on disk -- is wrong in a way that bites: /srv/artifacts/iris-catalog.pem is a
# STAGED COPY, re-written on every bring-up, so its mtime records the last
# staging operation and says nothing about when the certificate came into
# existence. Baselining the XR RPM against it reported "Needs rebuild" for an
# RPM built ELEVEN MINUTES AFTER the very certificate it was accused of
# predating (operator report 2026-08-31), purely because a later bring-up
# re-copied the pem. A false "rebuild me" is not harmless: it teaches the
# operator to ignore the one signal that catches a real rotation.
#
# Both date dialects are tried because this runs on the Linux server (GNU date,
# -d) and under the bats suite on Darwin (BSD date, -j -f).
cert_notbefore_epoch() {  # <pem file> -> epoch seconds, or empty
  local nb
  nb="$(openssl x509 -in "$1" -noout -startdate 2>/dev/null \
        | sed 's/^notBefore=//')" || true
  [ -n "$nb" ] || return 0
  date -u -d "$nb" '+%s' 2>/dev/null \
    || date -u -j -f '%b %e %H:%M:%S %Y %Z' "$nb" '+%s' 2>/dev/null \
    || true
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
# The pem file backing $REFERENCE, so the XR check below can read that same
# certificate's notBefore. Prefer what the catalog actually serves.
REFERENCE_PEM=""
if [ -n "$SERVED" ]; then
  REFERENCE_PEM="$TMP/served.pem"
elif [ -n "$DISTRIBUTED" ]; then
  REFERENCE_PEM="$TMP/dist.pem"
fi
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

# 4. The XR RPM (Cisco 8000 series) has no filesystem shape this stdlib-only
#    (openssl/tar) reader can unpack the way the two tars' inner
#    artifacts.tar.gz is unpacked above -- see server/setup_status.py's
#    _xr_package_item docstring for the same constraint on the console's
#    setup-status card, which this mirrors. So this can never say "this RPM
#    pins certificate X" the way the tar rows above do. What it CAN honestly
#    check is the RPM's build time against the live catalog certificate's
#    OWN mtime (the same container-side iris-catalog.pem already docker cp'd
#    above for its fingerprint -- read here via `stat` instead): built
#    at/after that mtime is the best available evidence the RPM was produced
#    with the live cert (REMEDY_XR's CATALOG_PEM argument is how a real
#    build ties the two together); built before it is evidence the RPM
#    predates a rotation and may still pin the old one. Contents are never
#    inspected either way -- the printed state says so plainly.
XR_PKG="iris-xr.rpm"
XR_PATH="$ARTIFACTS_DIR/$XR_PKG"
XR_REMEDY="tools/build-xr-package.sh --out artifacts/   (CATALOG_PEM: the live certificate, certificate block only)"
XR_STATE="absent"
echo
echo "XR RPM freshness (build time only -- contents not inspected)"
if [ ! -f "$XR_PATH" ]; then
  printf '  %-18s %s\n' "$XR_PKG" "absent"
else
  XR_BUILT_EPOCH="$(date -r "$XR_PATH" '+%s' 2>/dev/null || true)"
  XR_BUILT="$(date -r "$XR_PATH" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')"
  CERT_EPOCH=""
  [ -n "$REFERENCE_PEM" ] && CERT_EPOCH="$(cert_notbefore_epoch "$REFERENCE_PEM")"
  if [ -z "$XR_BUILT_EPOCH" ]; then
    printf '  %-18s build time unreadable -- contents not inspected regardless\n' "$XR_PKG"
    XR_STATE="unknown"
  elif [ -z "$CERT_EPOCH" ]; then
    printf '  %-18s built %s  UNKNOWN (certificate creation time unavailable; contents not inspected)\n' "$XR_PKG" "$XR_BUILT"
    XR_STATE="unknown"
  elif [ "$XR_BUILT_EPOCH" -ge "$CERT_EPOCH" ]; then
    printf '  %-18s built %s  OK-BY-MTIME (built after the certificate was created; contents not inspected)\n' "$XR_PKG" "$XR_BUILT"
    XR_STATE="ok"
  else
    printf '  %-18s built %s  STALE-BY-MTIME (built before the certificate was created; contents not inspected)\n' "$XR_PKG" "$XR_BUILT"
    XR_STATE="stale"
  fi
fi

echo
if [ ${#STALE[@]} -eq 0 ] && [ "$CATALOG_DRIFT" -eq 0 ] && [ "$XR_STATE" != "stale" ]; then
  echo "verified: both IOx tars pin the live catalog certificate (contents inspected)."
  case "$XR_STATE" in
    ok) echo "verified: the XR RPM was built after that certificate -- by build time only, contents not inspected." ;;
    unknown) echo "unverified: the XR RPM's build time could not be compared against the live certificate." ;;
    absent) echo "no XR RPM is staged; nothing to check for that package type." ;;
  esac
  exit 0
fi

if [ ${#STALE[@]} -gt 0 ]; then
  echo "STALE: ${STALE[*]}"
  echo "Devices deployed from these packages will install and report RUNNING, then"
  echo "fail every catalog call with CERTIFICATE_VERIFY_FAILED and never heartbeat."
fi
if [ "$XR_STATE" = "stale" ]; then
  echo "STALE (by mtime): $XR_PKG"
  echo "Built before the certificate was created; only build time was compared, never contents --"
  echo "a router onboarded from it may be pinning a certificate that has since rotated out."
  echo "Fix: $XR_REMEDY"
fi
if [ "$CATALOG_DRIFT" -eq 1 ]; then
  echo "Fix the served/distributed catalog certificate mismatch, then rerun this check."
  echo "Package rebuilding cannot repair the certificate handed to Guest Shell devices."
  exit 1
fi
if [ "$REBUILD" -eq 1 ] && [ ${#STALE[@]} -gt 0 ]; then
  echo
  echo ">> rebuilding all IOx packages"
  "$HERE/provision-iox-packages.sh"
  echo
  echo ">> re-checking"
  exec "$0"
fi
if [ ${#STALE[@]} -gt 0 ]; then
  echo "Fix: tools/provision-iox-packages.sh   (or re-run this with --rebuild)"
fi
exit 1
