#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Bring up the Compose seed server and prepare every device package it serves:
# the Guest Shell bundle and catalog certificate (self-provisioned by the
# server), both IOx tars, and the XR RPM. This is a host-side deployment
# command; it builds/stages artifacts only and never connects to or changes a
# device.
#
# Everything a fresh clone is missing is checked BEFORE anything is built, and
# reported as one list, so an install never fails ten minutes into a package
# build on the next absent hand-in. The one input this script will never
# create is the instruction trust roots: those come from the custody ceremony
# in docs/zensical/operations.md, and only their public halves are read here.
#
# Usage: IRIS_INSTRUCTION_ROOTS_DIR=<dir with exactly two .pub> tools/start-compose-server.sh
#        (the directory defaults to <repo>/instr-roots)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$REPO/server/docker-compose.yml")
IRIS_RUNTIME_UID=10001
missing=()

# server/Dockerfile COPYs bin/aria2c, the handed-in seeder client. That binary
# is git-ignored on purpose -- only its checksum and provenance live in the
# repository (tools/aria2c.sha256) -- so a fresh clone has none and the COPY
# fails inside BuildKit with a cache-key error naming no remedy (issue #203).
# Name the remedy here, before anything is built. The pin itself is still
# enforced in the image build; this check is only about the file being present.
if [ ! -f "$REPO/bin/aria2c" ]; then
  missing+=("bin/aria2c (server seeder client) — run: tools/get-aria2c.sh amd64   [verifies against tools/aria2c.sha256; ARIA2C_DELIVERABLE points at a hand-in elsewhere]")
fi

# The instruction trust roots. Every device package embeds them, and the build
# fails closed without exactly two distinct public roots -- so check them
# first, and NEVER create them: the private halves belong to two custodians at
# separate sites (docs/zensical/operations.md, "Instruction-root ceremony").
# A disposable root is not a substitute for production trust. Only the .pub
# halves are read, from a reviewed directory the operator points at.
ROOTS="${IRIS_INSTRUCTION_ROOTS_DIR:-$REPO/instr-roots}"
pub_count=0
if [ -d "$ROOTS" ]; then
  pub_count="$(find "$ROOTS" -maxdepth 1 -type f -name '*.pub' | wc -l)"
fi
if [ "$pub_count" -ne 2 ]; then
  missing+=("instruction trust roots — $ROOTS must hold exactly two public roots (*.pub), found $pub_count. Create them with the custody ceremony (docs/zensical/operations.md#instruction-root-ceremony-and-recovery), keep the private halves off this host, and point IRIS_INSTRUCTION_ROOTS_DIR at the directory holding only the two .pub files.")
fi
export IRIS_INSTRUCTION_ROOTS_DIR="$ROOTS"

# Hand-in inputs the device-package builders need. Checked only when the IOx
# tooling is present, because a Guest Shell-only deployment does not build
# native packages at all.
if [ -x "$REPO/tools/provision-iox-packages.sh" ]; then
  IOXCLIENT="${IOXCLIENT:-$REPO/tools/bin/ioxclient}"
  [ -x "$IOXCLIENT" ] || missing+=("ioxclient at $IOXCLIENT — run: tools/get-ioxclient.sh   [or set IOXCLIENT]")
  # tools/build-device-image.sh resolves each architecture's aria2c from, in
  # order, ARIA2C_BIN_<ARCH>, the already-staged agent bundle, or
  # deliverables/aria2c-<cpu>; report the architecture when none resolves.
  for tuple in "amd64:x86_64:iris-agent.tgz" "arm64:aarch64:iris-agent-arm.tgz"; do
    arch="${tuple%%:*}"; rest="${tuple#*:}"; cpu="${rest%%:*}"; bundle="${rest#*:}"
    override_var="ARIA2C_BIN_$(printf '%s' "$arch" | tr '[:lower:]' '[:upper:]')"
    if [ -z "${!override_var:-}" ] && [ ! -f "$REPO/artifacts/$bundle" ] \
        && [ ! -f "$REPO/deliverables/aria2c-$cpu" ]; then
      missing+=("pinned aria2c for $arch — provide deliverables/aria2c-$cpu (hand-in from aria2-next-static, verified against tools/aria2c.sha256) or set $override_var")
    fi
  done
fi

if [ "${#missing[@]}" -gt 0 ]; then
  {
    echo "!! this install is missing ${#missing[@]} input(s); nothing was built or started:"
    for item in "${missing[@]}"; do echo "   - $item"; done
    echo
    echo "These are handed in, never downloaded or generated here. Supply every"
    echo "item above, then start me again."
  } >&2
  exit 1
fi

# The server and Console run as the fixed uid 10001 with all capabilities
# dropped, and the image cannot chown host paths. artifacts/ crosses that
# boundary, and unlike the age identity -- whose absence fails the entrypoint
# closed and loudly -- an unwritable artifacts/ lets the server start and then
# SILENTLY skip self-provisioning: no Guest Shell bundle, no staged
# iris-catalog.pem, and a Console package-readiness screen reporting everything
# absent with no way to fix it from a container that has no Docker socket.
# Grant it here instead of leaving that to be discovered after an onboarding
# fails (issue #204).
# Two writers share artifacts/: the server (uid 10001) self-provisions the
# bundle and certificate, and the host-side device-image builder writes the
# canonical OCI archive and its manifest there as the OPERATOR. Owner 10001
# plus the operator's group with group-write serves both; 10001:10001 -- what
# the docs used to say -- silently breaks the second writer.
mkdir -p "$REPO/artifacts"
OPERATOR_GID="$(id -g)"
artifacts_uid="$(stat -c %u "$REPO/artifacts" 2>/dev/null || echo -1)"
artifacts_gid="$(stat -c %g "$REPO/artifacts" 2>/dev/null || echo -1)"
if [ "$artifacts_uid" != "$IRIS_RUNTIME_UID" ] || [ "$artifacts_gid" != "$OPERATOR_GID" ] || [ ! -w "$REPO/artifacts" ]; then
  if sudo -n chown -R "$IRIS_RUNTIME_UID:$OPERATOR_GID" "$REPO/artifacts" 2>/dev/null \
      && sudo -n chmod -R g+w "$REPO/artifacts" 2>/dev/null; then
    echo ">> granted uid $IRIS_RUNTIME_UID and group $OPERATOR_GID write access to $REPO/artifacts"
  else
    cat >&2 <<EOF
!! $REPO/artifacts is owned by $artifacts_uid:$artifacts_gid, but it needs owner
   uid $IRIS_RUNTIME_UID (the server, which cannot chown a host path from inside
   the image) and group $OPERATOR_GID with write access (you, for the device-image
   builder).

Left as it is, either the server cannot self-provision its bundle and
certificate, or the package builders cannot write the canonical device image.

Grant it, then start me again:

  sudo chown -R $IRIS_RUNTIME_UID:$OPERATOR_GID "$REPO/artifacts" && sudo chmod -R g+w "$REPO/artifacts"
EOF
    exit 1
  fi
fi

# --pull: server/Dockerfile's base is a floating tag; without it a rebuild
# silently reuses the host's cached python:3.12-slim-trixie and misses
# Debian security updates already on the tag (issue #13; measured 2026-09-02).
"${COMPOSE[@]}" build --pull
"${COMPOSE[@]}" run --rm iris iris-bootstrap

# Install the two PUBLIC roots into the config volume so the server can
# self-provision a trust-bound Guest Shell bundle on this very start. It runs
# inside the server image as the runtime uid, so ownership is right without a
# privileged helper, and only the .pub files are mounted -- read-only, and
# from the same reviewed directory the builders use. Idempotent: re-running
# with the same roots changes nothing.
"${COMPOSE[@]}" run --rm -v "$ROOTS:/pub:ro" --entrypoint sh iris -c \
  'install -d -m 0755 "$IRIS_CONFIG/instr" "$IRIS_CONFIG/instr/roots.d" && install -m 0644 /pub/*.pub "$IRIS_CONFIG/instr/roots.d/"'

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

# The XR RPM. Built here so a fresh install serves every package the Console's
# readiness screen lists, rather than leaving XR as a separate step nobody
# remembers. The builder writes into a private temporary directory and the
# result is placed through the running container -- the same route
# stage-iox-package.sh uses -- so artifacts/ stays owned by the runtime uid as
# the docs prescribe and the operator never needs write access to it.
# Set IRIS_SKIP_XR=1 on a deployment with no XR devices and no build inputs.
XR_RPM="$REPO/artifacts/iris-xr.rpm"
if [ -n "${IRIS_SKIP_XR:-}" ]; then
  echo ">> IRIS_SKIP_XR is set; not building the XR RPM"
elif [ -x "$REPO/tools/build-xr-package.sh" ]; then
  XR_TMP="$(mktemp -d)"
  trap 'rm -rf "$XR_TMP"' EXIT
  "$REPO/tools/build-xr-package.sh" --instruction-roots-dir "$ROOTS" --out "$XR_TMP"
  docker cp "$XR_TMP/iris-xr.rpm" "$IRIS_CONTAINER:/srv/artifacts/.iris-xr.rpm.tmp"
  docker cp "$XR_TMP/iris-xr.rpm.manifest" "$IRIS_CONTAINER:/srv/artifacts/.iris-xr.rpm.manifest.tmp"
  docker exec "$IRIS_CONTAINER" mv -f /srv/artifacts/.iris-xr.rpm.tmp /srv/artifacts/iris-xr.rpm
  docker exec "$IRIS_CONTAINER" mv -f /srv/artifacts/.iris-xr.rpm.manifest.tmp /srv/artifacts/iris-xr.rpm.manifest
  echo ">> XR package is staged: iris-xr.rpm"
else
  echo ">> XR packaging tool not present; skipping the XR RPM" >&2
fi
# Whatever produced it, check the staged RPM's byte/provenance binding;
# certificate rotation is intentionally irrelevant because onboarding supplies
# the current public certificate at runtime.
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
