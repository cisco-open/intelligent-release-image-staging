#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Report whether served device packages are readable and match their adjacent
# canonical-image provenance manifests. Device packages contain no deployment
# certificate, so certificate rotation is deliberately outside their freshness
# boundary. The separate live-vs-distributed certificate comparison remains:
# runtime onboarding still hands that public certificate to every device.
#
# Read-only by default. It never touches a device.
#
#   tools/check-package-freshness.sh
#   tools/check-package-freshness.sh --rebuild
#
# Env:
#   IRIS_CONTAINER   running server container (default: iris)
#   ARTIFACTS_DIR    served artifacts dir (default: <repo>/artifacts)
#   CATALOG_HOSTPORT host:port of the catalog to probe (default: IRIS_HOST_IP:8443)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
IRIS_CONTAINER="${IRIS_CONTAINER:-iris}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$REPO/artifacts}"
# Relative overrides belong to the caller's working directory. Preserve that
# location when passing it to a helper which otherwise resolves paths from
# server/ like Compose does.
case "$ARTIFACTS_DIR" in /*) ;; *) ARTIFACTS_DIR="$PWD/$ARTIFACTS_DIR" ;; esac
REBUILD=0
case "${1:-}" in
  '') ;;
  --rebuild) REBUILD=1 ;;
  -h|--help)
    echo "usage: $0 [--rebuild]"
    exit 0
    ;;
  *) echo "!! unknown argument: $1" >&2; exit 2 ;;
esac

fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/.*Fingerprint=//' || true
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

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

DISTRIBUTED=""
if docker inspect "$IRIS_CONTAINER" >/dev/null 2>&1 \
   && docker cp "$IRIS_CONTAINER:/srv/artifacts/iris-catalog.pem" "$TMP/dist.pem" 2>/dev/null; then
  DISTRIBUTED="$(fingerprint "$TMP/dist.pem")"
fi

echo "runtime onboarding certificate"
echo "  served by catalog   : ${SERVED:-<unreachable>}${HOSTPORT:+  ($HOSTPORT)}"
echo "  handed to devices   : ${DISTRIBUTED:-<unavailable>}"
TRUST_FAILURE=0
if [ -z "$SERVED" ] || [ -z "$DISTRIBUTED" ]; then
  TRUST_FAILURE=1
  echo "  !! cannot verify that the served and distributed certificates agree"
elif [ "$SERVED" != "$DISTRIBUTED" ]; then
  TRUST_FAILURE=1
  echo "  !! MISMATCH: the served cert differs from the one devices are told to trust"
fi

readiness() {
  PYTHONPATH="$REPO/server${PYTHONPATH:+:$PYTHONPATH}" \
    python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import sys
import setup_status

item = setup_status.package_readiness(*sys.argv[1:])
print(item["state"])
print(item.get("reason", ""))
print(item.get("detail", ""))
PY
}

BROKEN=()
IOX_NEEDS_BUILD=0
XR_NEEDS_BUILD=0
echo
echo "deployment-neutral package readiness"
while IFS='|' read -r NAME KIND PLATFORM REQUIRED REMEDY; do
  PATHNAME="$ARTIFACTS_DIR/$NAME"
  RESULT="$(readiness "$PATHNAME" "$NAME" "$KIND" "$PLATFORM" "$REMEDY")"
  STATE="$(printf '%s\n' "$RESULT" | sed -n '1p')"
  REASON="$(printf '%s\n' "$RESULT" | sed -n '2p')"
  DETAIL="$(printf '%s\n' "$RESULT" | sed -n '3p')"
  case "$STATE" in
    ok)
      printf '  %-18s READY  %s\n' "$NAME" "$DETAIL"
      ;;
    absent)
      printf '  %-18s absent\n' "$NAME"
      if [ "$REQUIRED" = required ]; then
        BROKEN+=("$NAME")
        [ "$KIND" = iox ] && IOX_NEEDS_BUILD=1
      fi
      ;;
    stale|unknown)
      STATE_LABEL="$(printf '%s' "$STATE" | tr '[:lower:]' '[:upper:]')"
      printf '  %-18s %s (%s)\n' "$NAME" "$STATE_LABEL" "${REASON:-unverified}"
      BROKEN+=("$NAME")
      if [ "$KIND" = iox ]; then IOX_NEEDS_BUILD=1; else XR_NEEDS_BUILD=1; fi
      ;;
    *)
      printf '  %-18s UNKNOWN (invalid readiness state)\n' "$NAME"
      BROKEN+=("$NAME")
      if [ "$KIND" = iox ]; then IOX_NEEDS_BUILD=1; else XR_NEEDS_BUILD=1; fi
      ;;
  esac
done <<EOF
iris-amd64.tar|iox|linux/amd64|required|tools/provision-iox-packages.sh
iris-arm64.tar|iox|linux/arm64|required|tools/provision-iox-packages.sh
iris-xr.rpm|xr-appmgr|linux/amd64|optional|tools/build-xr-package.sh --out artifacts/
EOF

if [ "$TRUST_FAILURE" -eq 0 ] && [ ${#BROKEN[@]} -eq 0 ]; then
  echo
  echo "verified: required package bytes are readable and match their provenance manifests"
  echo "verified: the served and distributed onboarding certificates match"
  exit 0
fi

echo
if [ ${#BROKEN[@]} -gt 0 ]; then
  echo "NOT READY: ${BROKEN[*]}"
  echo "A READY result verifies wrapper bytes against adjacent canonical-image provenance."
  echo "It does not inspect package contents or validate a native package signature."
fi
if [ "$TRUST_FAILURE" -eq 1 ]; then
  echo "Fix the served/distributed onboarding certificate state, then rerun this check."
  echo "Package rebuilding cannot repair that runtime trust mismatch."
fi

if [ "$REBUILD" -eq 1 ] && [ "$TRUST_FAILURE" -eq 0 ]; then
  if [ "$IOX_NEEDS_BUILD" -eq 1 ]; then
    echo
    echo ">> rebuilding all IOx packages"
    # Check and repair the same artifact tree, including an explicit
    # ARTIFACTS_DIR override. The staging helper resolves this host path
    # through IRIS_ARTIFACTS_HOST_DIR, not ARTIFACTS_DIR.
    IRIS_ARTIFACTS_HOST_DIR="$ARTIFACTS_DIR" "$HERE/provision-iox-packages.sh"
  fi
  if [ "$XR_NEEDS_BUILD" -eq 1 ]; then
    echo
    echo ">> rebuilding the IOS-XR package"
    "$HERE/build-xr-package.sh" --out "$ARTIFACTS_DIR"
  fi
  if [ "$IOX_NEEDS_BUILD" -eq 1 ] || [ "$XR_NEEDS_BUILD" -eq 1 ]; then
    echo
    echo ">> re-checking"
    exec "$0"
  fi
fi

if [ "$IOX_NEEDS_BUILD" -eq 1 ]; then
  echo "Fix IOx: tools/provision-iox-packages.sh"
fi
if [ "$XR_NEEDS_BUILD" -eq 1 ]; then
  echo "Fix IOS-XR: tools/build-xr-package.sh --out artifacts/"
fi
exit 1
