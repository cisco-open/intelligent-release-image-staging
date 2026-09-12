#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Wrap the canonical amd64 IRIS device manifest as an IOS-XR appmgr RPM.
# device/iox/build.sh selects from the same signable multi-platform OCI index.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
XR_DIR="$REPO/device/xr"

OUT="$XR_DIR/out"
DRY_RUN=0
ROOTS="${IRIS_INSTRUCTION_ROOTS_DIR:-${IRIS_CONFIG:-/etc/iris}/instr/roots.d}"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:?--out needs a value}"; shift 2 ;;
    --instruction-roots-dir)
      ROOTS="${2:?--instruction-roots-dir needs a value}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      echo "usage: $0 [--out DIR] [--instruction-roots-dir DIR] [--dry-run]"
      exit 0 ;;
    -*) echo "!! unknown option: $1" >&2; exit 2 ;;
    *) echo "!! unexpected argument: $1" >&2; exit 2 ;;
  esac
done

RPM_NAME="${RPM_NAME:-iris-xr}"
APPMGR_RELEASE="${APPMGR_RELEASE:-ThinXR_7.3.15}"
APPMGR_BUILD_REPO_URL="${APPMGR_BUILD_REPO_URL:-https://github.com/ios-xr/xr-appmgr-build.git}"
APPMGR_BUILD_COMMIT="${APPMGR_BUILD_COMMIT:-37d79607}"
APPMGR_BUILD_DIR="${APPMGR_BUILD_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/iris/xr-appmgr-build}"
APPMGR_BUILD_CMD="${APPMGR_BUILD_CMD:-./appmgr_build}"
PKG_VERSION="$(cat "$REPO/VERSION" 2>/dev/null || echo 0.0.0)"
IMAGE_TAR_NAME="${RPM_NAME}.tar.gz"
case "$APPMGR_BUILD_DIR" in
  /*) ;;
  *) echo "!! APPMGR_BUILD_DIR must be an absolute path" >&2; exit 2 ;;
esac

if [ -r "$REPO/tools/agent-source-freshness.sh" ]; then
  # shellcheck source=tools/agent-source-freshness.sh
  . "$REPO/tools/agent-source-freshness.sh"
  iris_check_agent_freshness "$REPO" \
    "device/agent device/container device/verify_image.py device/xr tools/build-device-image.sh tools/build-xr-package.sh" \
    || exit 1
fi

[ -x "$REPO/tools/build-device-image.sh" ] \
  || { echo "!! missing tools/build-device-image.sh" >&2; exit 1; }

if [ "$DRY_RUN" -eq 1 ]; then
  cat <<PLAN
>> [dry-run] would build or verify one canonical amd64+arm64 OCI archive via:
   tools/build-device-image.sh --context <temporary-dir> --instruction-roots-dir $ROOTS
>> [dry-run] would select linux/amd64 from that immutable OCI index into
   $APPMGR_BUILD_DIR/iris-src/$IMAGE_TAR_NAME
>> [dry-run] would reuse or safely clone $APPMGR_BUILD_REPO_URL @ $APPMGR_BUILD_COMMIT
>> [dry-run] would write the hardware-proven appmgr build.yaml, run
   $APPMGR_BUILD_CMD -b build.yaml, verify a new RPM exists, and atomically
   publish $OUT/iris-xr.rpm
PLAN
  exit 0
fi

CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
mkdir -p "$OUT"
"$REPO/tools/build-device-image.sh" --context "$CTX" --instruction-roots-dir "$ROOTS"
OCI_ARCHIVE="$(cat "$CTX/iris-device-oci-path")"
OCI_INDEX="$(sed -n 's/^index_digest=//p' "$CTX/iris-device-oci.manifest")"
OCI_ARCHIVE_SHA="$(sed -n 's/^archive_sha256=//p' "$CTX/iris-device-oci.manifest")"
OCI_SOURCE_SHA="$(sed -n 's/^source_sha256=//p' "$CTX/iris-device-oci.manifest")"
[ -n "$OCI_INDEX" ] && [ -n "$OCI_ARCHIVE_SHA" ] && [ -n "$OCI_SOURCE_SHA" ] \
  || { echo "!! canonical OCI provenance manifest is incomplete" >&2; exit 1; }

echo ">> resolving ios-xr/xr-appmgr-build"
mkdir -p "$(dirname "$APPMGR_BUILD_DIR")"
if [ ! -x "$APPMGR_BUILD_DIR/appmgr_build" ]; then
  # An operator-overridden path is never deleted or cloned over when nonempty.
  if [ -e "$APPMGR_BUILD_DIR" ]; then
    if [ ! -d "$APPMGR_BUILD_DIR" ] \
      || [ -n "$(ls -A "$APPMGR_BUILD_DIR" 2>/dev/null)" ]; then
      cat >&2 <<EOF
!! APPMGR_BUILD_DIR=$APPMGR_BUILD_DIR exists but has no executable appmgr_build
   and is not empty. Refusing to clone over it; choose a fresh path.
EOF
      exit 1
    fi
  fi
  git clone "$APPMGR_BUILD_REPO_URL" "$APPMGR_BUILD_DIR"
  git -C "$APPMGR_BUILD_DIR" checkout "$APPMGR_BUILD_COMMIT"
else
  echo ">> reusing existing xr-appmgr-build tool at $APPMGR_BUILD_DIR"
  if [ -d "$APPMGR_BUILD_DIR/.git" ]; then
    head="$(git -C "$APPMGR_BUILD_DIR" rev-parse HEAD 2>/dev/null || echo '')"
    case "$head" in
      "$APPMGR_BUILD_COMMIT"*|'') ;;
      *) echo "!! warning: appmgr builder is at $head, expected $APPMGR_BUILD_COMMIT" >&2 ;;
    esac
  fi
fi

command -v skopeo >/dev/null 2>&1 \
  || { echo "!! skopeo is required to select the XR image from the canonical OCI" >&2; exit 1; }
# appmgr_build assembles the RPM with the host's rpmbuild. Without it the build
# fails deep inside the vendored builder's log rather than here, so say it
# plainly before anything is fetched or written. Debian and Ubuntu ship it in
# the "rpm" package.
command -v rpmbuild >/dev/null 2>&1 \
  || { echo "!! rpmbuild is required to build the XR appmgr RPM — install the 'rpm' package" >&2; exit 1; }
echo ">> selecting linux/amd64 from canonical OCI $OCI_INDEX"
# iris-src is this wrapper's fixed, builder-owned input tree. A reused appmgr
# checkout may carry inputs from an older run; clear this exact child before
# populating it so an untracked cached file cannot enter a provenance-bound
# wrapper. Never sweep the checkout or an operator-selected parent directory.
IRIS_SRC="$APPMGR_BUILD_DIR/iris-src"
rm -rf -- "$IRIS_SRC"
mkdir -p "$IRIS_SRC/config" "$IRIS_SRC/data"
skopeo copy --override-os linux --override-arch amd64 \
  "oci-archive:$OCI_ARCHIVE" \
  "docker-archive:$CTX/iris-xr.tar:iris-device:amd64"
gzip -n -c "$CTX/iris-xr.tar" > "$IRIS_SRC/$IMAGE_TAR_NAME"

BUILD_YAML="$APPMGR_BUILD_DIR/build.yaml"
cat > "$BUILD_YAML" <<EOF
# Generated by tools/build-xr-package.sh. The schema and ThinXR release are
# hardware-proven; do not alter without another hardware validation.
packages:
- name: "$RPM_NAME"
  release: "$APPMGR_RELEASE"
  target-release: "$APPMGR_RELEASE"
  version: "$PKG_VERSION"
  sources:
    - name: $RPM_NAME
      file: iris-src/$IMAGE_TAR_NAME
  config-dir:
    - dir: iris-src/config
  data-dir:
    - dir: iris-src/data
  copy_hostname: false
  copy_ems_cert: false
EOF

# appmgr_build can print success and return zero after an internal failure.
# Remove only its explicit RPMS output directory, then trust only a new RPM.
rm -rf "$APPMGR_BUILD_DIR/RPMS"
mkdir -p "$APPMGR_BUILD_DIR/RPMS"
LOG="$APPMGR_BUILD_DIR/.iris-appmgr-build.log"
( cd "$APPMGR_BUILD_DIR" && $APPMGR_BUILD_CMD -b build.yaml ) >"$LOG" 2>&1 || true
cat "$LOG"

RPM_FILE="$(find "$APPMGR_BUILD_DIR/RPMS" -type f -name '*.rpm' 2>/dev/null | sort | tail -n1)"
if [ -z "$RPM_FILE" ] || [ ! -f "$RPM_FILE" ]; then
  echo "!! xr-appmgr-build did not produce an RPM; last output follows" >&2
  echo "   a zero exit or 'Done building' message is not proof of success" >&2
  tail -n 40 "$LOG" >&2
  exit 1
fi

artifact_tmp="$(mktemp "$OUT/.iris-xr.rpm.XXXXXX")"
manifest_tmp="$(mktemp "$OUT/.iris-xr.rpm.manifest.XXXXXX")"
trap 'rm -rf "$CTX"; rm -f "$artifact_tmp" "$manifest_tmp"' EXIT
cp "$RPM_FILE" "$artifact_tmp"
WRAPPER_SHA="$(sha256sum "$artifact_tmp" | awk '{print $1}')"
{
  echo 'format=iris-device-wrapper-v1'
  echo 'wrapper_kind=xr-appmgr'
  echo 'wrapper_file=iris-xr.rpm'
  echo "wrapper_sha256=$WRAPPER_SHA"
  echo 'platform=linux/amd64'
  echo "canonical_index_digest=$OCI_INDEX"
  echo "canonical_archive_sha256=$OCI_ARCHIVE_SHA"
  echo "canonical_source_sha256=$OCI_SOURCE_SHA"
} > "$manifest_tmp"
chmod 444 "$artifact_tmp" "$manifest_tmp"
rm -f "$OUT/iris-xr.rpm.manifest"
mv -f "$artifact_tmp" "$OUT/iris-xr.rpm"
mv -f "$manifest_tmp" "$OUT/iris-xr.rpm.manifest"
echo ">> done: $OUT/iris-xr.rpm"
