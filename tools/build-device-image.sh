#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Build the ONE signable IRIS device image artifact: a persisted OCI archive
# whose index contains linux/amd64 and linux/arm64 manifests. IOx and IOS-XR
# wrappers select from this exact archive; neither independently rebuilds an
# image. The sidecar manifest binds the archive and OCI index digests to every
# source byte copied into the images.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
CONTAINER_DIR="$REPO/device/container"
VERSION="$(cat "$REPO/VERSION" 2>/dev/null || echo 0.0.0)"

CONTEXT_DIR=""
OCI_ARCHIVE="${IRIS_DEVICE_IMAGE_OCI:-$REPO/artifacts/iris-device-$VERSION.oci.tar}"
while [ $# -gt 0 ]; do
  case "$1" in
    --context) CONTEXT_DIR="${2:?--context needs a directory}"; shift 2 ;;
    --output) OCI_ARCHIVE="${2:?--output needs a path}"; shift 2 ;;
    -h|--help)
      echo "usage: $0 --context DIR [--output iris-device.oci.tar]"
      exit 0 ;;
    *) echo "!! unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$CONTEXT_DIR" ] || { echo "!! --context is required" >&2; exit 2; }
[ -d "$CONTEXT_DIR" ] || { echo "!! context directory does not exist: $CONTEXT_DIR" >&2; exit 1; }
# This script owns these paths and computes SOURCE_SHA256 from them. Refuse a
# pre-populated owned path so stale/untracked bytes cannot be silently folded
# into a supposedly source-exact build context. Wrappers always pass a private
# mktemp directory; direct callers get the same clean-context guarantee.
for owned in agent agent_bin Dockerfile entrypoint.sh reconcile.sh \
  iris-catalog.pem iris-catalog.pem.cert-only \
  iris-device-oci-path iris-device-oci.manifest; do
  { [ ! -e "$CONTEXT_DIR/$owned" ] && [ ! -L "$CONTEXT_DIR/$owned" ]; } || {
    echo "!! context contains pre-existing builder-owned path: $CONTEXT_DIR/$owned" >&2
    echo "   pass a clean private --context directory" >&2
    exit 1
  }
done
for input in Dockerfile entrypoint.sh reconcile.sh; do
  [ -r "$CONTAINER_DIR/$input" ] \
    || { echo "!! missing unified device/container/$input" >&2; exit 1; }
done

# Issue #72: never build a current wrapper around stale agent/container source.
if [ -r "$REPO/tools/agent-source-freshness.sh" ]; then
  # shellcheck source=tools/agent-source-freshness.sh
  . "$REPO/tools/agent-source-freshness.sh"
  iris_check_agent_freshness "$REPO" \
    "device/agent device/verify_image.py device/container" || exit 1
fi

mkdir -p "$CONTEXT_DIR/agent" "$CONTEXT_DIR/agent_bin"
cp "$REPO"/device/agent/*.py "$CONTEXT_DIR/agent/"
cp "$REPO/device/agent/peer-transfer-hook.sh" "$CONTEXT_DIR/agent/" \
  || { echo "!! missing device/agent/peer-transfer-hook.sh" >&2; exit 1; }
cp "$REPO/device/verify_image.py" "$CONTEXT_DIR/agent/verify_image.py"
cp "$REPO/VERSION" "$CONTEXT_DIR/agent/VERSION"
cp "$CONTAINER_DIR/Dockerfile" "$CONTAINER_DIR/entrypoint.sh" \
  "$CONTAINER_DIR/reconcile.sh" "$CONTEXT_DIR/"

SUMS="$REPO/tools/aria2c.sha256"
verify_aria2_checksum() {
  local candidate="$1" cpuarch="$2" desc="$3" expected actual pattern
  [ -f "$SUMS" ] || { echo "!! missing $SUMS -- cannot verify $desc" >&2; exit 1; }
  expected="$(awk -v a="$cpuarch" '$2 == a { print $1 }' "$SUMS")"
  [ -n "$expected" ] || { echo "!! no checksum recorded for $cpuarch in $SUMS" >&2; exit 1; }
  actual="$( (shasum -a 256 "$candidate" 2>/dev/null || sha256sum "$candidate") | awk '{print $1}')"
  [ "$actual" = "$expected" ] || {
    echo "!! CHECKSUM MISMATCH for $desc ($cpuarch) -- refusing to build" >&2
    echo "   expected: $expected" >&2
    echo "   actual:   $actual" >&2
    exit 1
  }
  case "$cpuarch" in x86_64) pattern=x86-64 ;; aarch64) pattern='ARM aarch64' ;; esac
  file "$candidate" | grep -q "$pattern" \
    || { echo "!! aria2c does not match $cpuarch" >&2; exit 1; }
}

# A multi-platform build always contains both manifests and therefore always
# verifies both transfer engines. Per-architecture override names avoid the
# ambiguous former ARIA2C_BIN knob.
for tuple in "amd64:x86_64:iris-agent.tgz" "arm64:aarch64:iris-agent-arm.tgz"; do
  arch="${tuple%%:*}"; rest="${tuple#*:}"; cpuarch="${rest%%:*}"; bundle="${rest#*:}"
  override_var="ARIA2C_BIN_$(printf '%s' "$arch" | tr '[:lower:]' '[:upper:]')"
  override="${!override_var:-}"
  dest="$CONTEXT_DIR/agent_bin/aria2c-$arch"
  if [ -n "$override" ]; then
    cp "$override" "$dest"
    verify_aria2_checksum "$dest" "$cpuarch" "$override"
  elif [ -f "$REPO/artifacts/$bundle" ]; then
    tar xOf "$REPO/artifacts/$bundle" aria2c > "$dest"
    verify_aria2_checksum "$dest" "$cpuarch" "$bundle (aria2c)"
  elif [ -f "$REPO/deliverables/aria2c-$cpuarch" ]; then
    cp "$REPO/deliverables/aria2c-$cpuarch" "$dest"
    verify_aria2_checksum "$dest" "$cpuarch" "deliverables/aria2c-$cpuarch"
  else
    echo "!! no checksum-pinned aria2c available for $cpuarch" >&2
    exit 1
  fi
  chmod +x "$dest"
done

if [ -n "${CATALOG_PEM:-}" ]; then
  cp "$CATALOG_PEM" "$CONTEXT_DIR/iris-catalog.pem"
else
  : "${CATALOG_PEM_URL:?set CATALOG_PEM_URL or provide CATALOG_PEM}"
  : "${CATALOG_PEM_FINGERPRINT:?set CATALOG_PEM_FINGERPRINT for fetched catalog cert}"
  curl -fsS --insecure "$CATALOG_PEM_URL" -o "$CONTEXT_DIR/iris-catalog.pem"
  got="$(openssl x509 -noout -fingerprint -sha256 -in "$CONTEXT_DIR/iris-catalog.pem" \
    | sed 's/.*Fingerprint=//' | tr -d ' \r' | tr '[:lower:]' '[:upper:]')"
  want="$(printf '%s' "$CATALOG_PEM_FINGERPRINT" \
    | sed 's/^[Ss][Hh][Aa]256[: ]*[Ff][Ii][Nn][Gg][Ee][Rr][Pp][Rr][Ii][Nn][Tt]=//; s/^[Ss][Hh][Aa]256://' \
    | tr -d ' \r' | tr '[:lower:]' '[:upper:]')"
  [ "$got" = "$want" ] || { echo "!! catalog cert fingerprint mismatch" >&2; exit 1; }
fi
grep -q 'BEGIN CERTIFICATE' "$CONTEXT_DIR/iris-catalog.pem" \
  || { echo "!! bad cert: no certificate block found" >&2; exit 1; }
if grep -q 'BEGIN.*PRIVATE KEY' "$CONTEXT_DIR/iris-catalog.pem"; then
  echo "!! CATALOG_PEM contains a PRIVATE KEY block -- refusing to build" >&2
  echo "   extract only the public certificate, for example: openssl x509 -in $(basename "${CATALOG_PEM:-input.pem}") -out iris-catalog.pem" >&2
  exit 1
fi
sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/p' \
  "$CONTEXT_DIR/iris-catalog.pem" > "$CONTEXT_DIR/iris-catalog.pem.cert-only"
mv "$CONTEXT_DIR/iris-catalog.pem.cert-only" "$CONTEXT_DIR/iris-catalog.pem"
grep -q 'BEGIN CERTIFICATE' "$CONTEXT_DIR/iris-catalog.pem" \
  || { echo "!! cert normalization produced no certificate" >&2; exit 1; }

SOURCE_SHA256="$(cd "$CONTEXT_DIR" && {
  find agent agent_bin -type f -print
  printf '%s\n' Dockerfile entrypoint.sh reconcile.sh iris-catalog.pem
} | LC_ALL=C sort | while read -r path; do
  printf '%s  %s\n' "$(sha256sum "$path" | awk '{print $1}')" "$path"
done | sha256sum | awk '{print $1}')"

MANIFEST="$OCI_ARCHIVE.manifest"
manifest_value() { sed -n "s/^$1=//p" "$MANIFEST" 2>/dev/null | tail -n 1; }
oci_identity() {
  # BuildKit's OCI archive has a layout index whose tagged descriptor points
  # at the actual multi-platform image index. Record/verify the latter: that
  # digest is the portable object a registry signer addresses. Also accept a
  # direct untagged index, which is valid OCI output from other builders.
  python3 - "$1" <<'PY'
import hashlib
import json
import sys
import tarfile

with tarfile.open(sys.argv[1]) as archive:
    root_raw = archive.extractfile("index.json").read()
    root = json.loads(root_raw)
    descriptors = root.get("manifests", [])
    if descriptors and all(d.get("platform") for d in descriptors):
        index_raw = root_raw
        index = root
        digest = "sha256:" + hashlib.sha256(index_raw).hexdigest()
    elif len(descriptors) == 1 and descriptors[0].get("mediaType", "").endswith("image.index.v1+json"):
        descriptor = descriptors[0]
        algorithm, hexdigest = descriptor["digest"].split(":", 1)
        if algorithm != "sha256":
            raise SystemExit("unsupported OCI index digest algorithm")
        index_raw = archive.extractfile("blobs/sha256/" + hexdigest).read()
        if hashlib.sha256(index_raw).hexdigest() != hexdigest:
            raise SystemExit("OCI image index digest mismatch")
        index = json.loads(index_raw)
        digest = descriptor["digest"]
    else:
        raise SystemExit("OCI layout does not identify one multi-platform index")

    platforms = sorted("%s/%s" % (
        d.get("platform", {}).get("os", ""),
        d.get("platform", {}).get("architecture", ""))
        for d in index.get("manifests", []))
    if platforms != ["linux/amd64", "linux/arm64"]:
        raise SystemExit("unexpected OCI platforms: %r" % platforms)
    for descriptor in index["manifests"]:
        algorithm, hexdigest = descriptor["digest"].split(":", 1)
        if algorithm != "sha256":
            raise SystemExit("unsupported image-manifest digest algorithm")
        payload = archive.extractfile("blobs/sha256/" + hexdigest).read()
        if hashlib.sha256(payload).hexdigest() != hexdigest:
            raise SystemExit("OCI image-manifest digest mismatch")
    print(digest, ",".join(platforms))
PY
}
archive_valid=0
if [ -r "$OCI_ARCHIVE" ] && [ -r "$MANIFEST" ] \
   && [ "$(manifest_value format)" = iris-device-oci-v1 ] \
   && [ "$(manifest_value source_sha256)" = "$SOURCE_SHA256" ]; then
  actual_archive="$(sha256sum "$OCI_ARCHIVE" | awk '{print $1}')"
  identity="$(oci_identity "$OCI_ARCHIVE" 2>/dev/null || true)"
  actual_index="${identity%% *}"
  actual_platforms="${identity#* }"
  if [ "$actual_archive" = "$(manifest_value archive_sha256)" ] \
     && [ "$actual_index" = "$(manifest_value index_digest)" ] \
     && [ "$actual_platforms" = linux/amd64,linux/arm64 ] \
     && [ "$(manifest_value platforms)" = "$actual_platforms" ]; then
    archive_valid=1
  fi
fi

if [ "$archive_valid" -eq 1 ]; then
  echo ">> reusing canonical device OCI $(manifest_value index_digest)"
else
  if [ -e "$OCI_ARCHIVE" ] || [ -e "$MANIFEST" ]; then
    [ "${IRIS_FORCE_DEVICE_IMAGE_BUILD:-0}" = 1 ] || {
      echo "!! existing canonical OCI does not match current source; refusing to overwrite it" >&2
      echo "   choose --output for a new artifact or set IRIS_FORCE_DEVICE_IMAGE_BUILD=1" >&2
      exit 1
    }
  fi
  command -v docker >/dev/null 2>&1 || { echo "!! docker is required to build the canonical OCI" >&2; exit 1; }
  docker buildx version >/dev/null 2>&1 || { echo "!! docker buildx is required" >&2; exit 1; }
  mkdir -p "$(dirname "$OCI_ARCHIVE")"
  tmp_dir="$(mktemp -d "$(dirname "$OCI_ARCHIVE")/.iris-device-oci.XXXXXX")"
  tmp_archive="$tmp_dir/image.oci.tar"
  tmp_manifest="$tmp_dir/image.oci.tar.manifest"
  trap 'rm -f "$tmp_archive" "$tmp_manifest"; rmdir "$tmp_dir" 2>/dev/null || true' EXIT
  pull_flag=--pull
  [ -z "${IRIS_NO_PULL:-}" ] || pull_flag=--pull=false
  echo ">> building canonical linux/amd64,linux/arm64 OCI artifact"
  docker buildx build "$pull_flag" \
    --platform linux/amd64,linux/arm64 --provenance=false --sbom=false \
    -t "iris-device:$VERSION" --output "type=oci,dest=$tmp_archive" "$CONTEXT_DIR"
  archive_sha="$(sha256sum "$tmp_archive" | awk '{print $1}')"
  identity="$(oci_identity "$tmp_archive")"
  index_digest="${identity%% *}"
  platforms="${identity#* }"
  {
    echo 'format=iris-device-oci-v1'
    echo "source_sha256=$SOURCE_SHA256"
    echo "index_digest=$index_digest"
    echo "archive_sha256=$archive_sha"
    echo "platforms=$platforms"
  } > "$tmp_manifest"
  chmod 444 "$tmp_archive" "$tmp_manifest"
  # Do not leave old provenance next to a newly replaced archive, even for
  # the short interval between the two same-directory renames.
  rm -f "$MANIFEST"
  mv -f "$tmp_archive" "$OCI_ARCHIVE"
  mv -f "$tmp_manifest" "$MANIFEST"
  rmdir "$tmp_dir"
  trap - EXIT
fi

printf '%s\n' "$OCI_ARCHIVE" > "$CONTEXT_DIR/iris-device-oci-path"
cp "$MANIFEST" "$CONTEXT_DIR/iris-device-oci.manifest"
echo ">> canonical index: $(manifest_value index_digest)"
echo ">> signable archive: $OCI_ARCHIVE ($(manifest_value archive_sha256))"
