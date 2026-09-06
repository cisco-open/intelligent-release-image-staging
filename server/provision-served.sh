#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Stage the DERIVABLE served artifacts into the artifacts dir at container
# startup, so a fresh deploy no longer fails onboarding on missing files. The
# three files a device downloads that the container can produce itself:
#   iris-agent.tgz    the Guest Shell agent bundle (rebuilt every start from the
#                     image-baked device/ sources, so it always matches the
#                     deployed agent code)
#   bootstrap.sh      the on-device launcher (device/bootstrap.sh)
#   iris-catalog.pem  the pinned CA the agent trusts = the server's PUBLIC cert
# The served artifacts this CANNOT produce are the IOx packages iris-arm64.tar
# (aarch64, IE-3x00/IR) and iris-amd64.tar (x86_64, Catalyst 9300) — both need
# device/iox/build.sh; it just notes when they are absent.
#
# Bundle failures return non-zero and publish a runtime setup-status record.
# The entrypoint keeps existing services running; onboarding readiness stays
# non-ok until a verified bundle and bootstrap have been published.
#
#   provision-served.sh [artifacts-dir]
set -uo pipefail

ART="${1:-${IRIS_ARTIFACTS_DIR:-/srv/artifacts}}"
DEVICE="${IRIS_DEVICE_DIR:-/opt/iris/device}"
ARIA2="${IRIS_ARIA2:-/opt/iris/bin/aria2c}"
CRT="${IRIS_CRT_SRC:-${IRIS_CONFIG:-/etc/iris}/tls/crt.pem}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SUMS="${IRIS_ARIA2_SUMS:-/opt/iris/tools/aria2c.sha256}"
STATUS="${IRIS_RUN:-/run/iris}/served-bundle.json"
FAILED=0

# Runtime status remains writable even when the artifacts mount is read-only.
# Record an attempt before packing so an interrupted run cannot leave an old
# success record. Bind success to both published files, not just their names.
write_status() {
  python3 - "$STATUS" "$ART" "$1" "$2" <<'PYTHON'
import hashlib, json, os, sys, tempfile
path, artifacts, state, reason = sys.argv[1:]
record = {"format": "iris-served-bundle-v1", "state": state, "reason": reason}
if state == "ok":
    for name in ("iris-agent.tgz", "bootstrap.sh"):
        digest = hashlib.sha256()
        with open(os.path.join(artifacts, name), "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        record[name] = digest.hexdigest()
os.makedirs(os.path.dirname(path), exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
try:
    with os.fdopen(fd, "w") as handle:
        json.dump(record, handle)
        handle.write("\n")
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PYTHON
}
bundle_failed() {
  FAILED=1
  echo "provision-served: Guest Shell bundle not ready ($1); see setup status" >&2
  write_status failed "$1" || echo "provision-served: cannot write bundle readiness" >&2
}
write_status pending provisioning || {
  echo "provision-served: cannot initialize bundle readiness" >&2
  exit 1
}

verify_aria2() {
  python3 - "$ARIA2" "$SUMS" <<'PYTHON'
import hashlib, pathlib, sys
binary, manifest = sys.argv[1:]
try:
    entries = [line.split()[0] for line in pathlib.Path(manifest).read_text().splitlines()
               if len(line.split()) == 2 and line.split()[1] == "x86_64"]
    if len(entries) != 1 or len(entries[0]) != 64:
        raise ValueError("missing or invalid x86_64 checksum pin")
    with open(binary, "rb") as handle:
        header = handle.read(20)
        if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
            raise ValueError("aria2c is not an x86_64 ELF binary")
        digest = hashlib.sha256(header)
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != entries[0]:
        raise ValueError("aria2c checksum does not match the x86_64 pin")
except (OSError, UnicodeError, ValueError) as exc:
    print("provision-served: aria2c verification failed: " + str(exc), file=sys.stderr)
    sys.exit(1)
PYTHON
}

if ! mkdir -p "$ART/staging" 2>/dev/null || [ ! -w "$ART" ]; then
  echo "provision-served: artifacts dir $ART not writable — cannot self-provision;" \
       "onboarding will need the bundle staged manually (mount ../artifacts read-write)" >&2
  bundle_failed artifacts-unwritable
  exit 1
fi

# All writes onto SERVED paths are atomic: build under a temp name in the same
# directory, then mv into place. A device fetching mid-restart reads either the
# old file or the new one — never a truncated/torn copy — and an interrupted
# pack (SIGTERM/disk-full) leaves the previous good file being served.
stage_atomic() {  # stage_atomic <tmp-file> <final-name>
  mv -f "$1" "$ART/$2"
}

# Guest Shell bundle — rebuilt every start from the image-baked device/ sources
# (server/Dockerfile COPYs device/ into /opt/iris/device; there is no bind
# mount, so a host-side edit under device/ reaches the served bundle only
# after an image rebuild), so the served bundle can never drift from the
# agent code this image carries.
if [ ! -d "$DEVICE/agent" ] || [ ! -f "$ARIA2" ]; then
  bundle_failed inputs-missing
elif ! verify_aria2; then
  bundle_failed verification-failed
elif "$HERE/pack-agent-bundle.sh" "$DEVICE" "$ARIA2" "$ART/.iris-agent.tgz.tmp" \
    && cp "$DEVICE/bootstrap.sh" "$ART/.bootstrap.sh.tmp" \
    && stage_atomic "$ART/.iris-agent.tgz.tmp" iris-agent.tgz \
    && stage_atomic "$ART/.bootstrap.sh.tmp" bootstrap.sh; then
  if write_status ok ready; then
    echo "provision-served: staged iris-agent.tgz + bootstrap.sh (Guest Shell agent)"
  else
    bundle_failed status-write-failed
  fi
else
  rm -f "$ART/.iris-agent.tgz.tmp" "$ART/.bootstrap.sh.tmp"
  bundle_failed publication-failed
fi

# Pinned CA the devices download = the server's PUBLIC cert (plaintext on the
# config volume, no decrypt needed). Refresh every start so a rotated cert
# propagates to what onboarding serves.
if [ -f "$CRT" ]; then
  # Public certificate only: keep it host-readable so direct CLI onboarding
  # can deliver artifacts/iris-catalog.pem even when the container's private
  # umask is 077. The corresponding key remains only
  # in encrypted config/tmpfs and is never copied here.
  cp "$CRT" "$ART/.iris-catalog.pem.tmp" \
    && chmod 0644 "$ART/.iris-catalog.pem.tmp" \
    && stage_atomic "$ART/.iris-catalog.pem.tmp" iris-catalog.pem
  echo "provision-served: staged iris-catalog.pem (server cert)"
else
  echo "provision-served: server cert $CRT not found — run iris-bootstrap first" >&2
fi

# The IOx packages are the served artifacts we cannot build here (need
# ioxclient + a docker builder). Note absence so an operator knows what to
# stage. A Catalyst 9300 can onboard as Guest Shell today OR as an amd64 IOx
# Docker app once iris-amd64.tar is staged.
if [ ! -f "$ART/iris-arm64.tar" ]; then
  echo "provision-served: note — iris-arm64.tar (arm64 IOx agent for IE-3x00/IR) not" \
       "staged; build device/iox/build.sh to onboard IE-3x00/IR"
fi
if [ ! -f "$ART/iris-amd64.tar" ]; then
  echo "provision-served: note — iris-amd64.tar (amd64 IOx agent for Catalyst" \
       "9300) not staged; run tools/stage-iox-package.sh --arch amd64 to onboard" \
       "a 9300 as an IOx app (a 9300 can also onboard as Guest Shell without it)"
fi
exit "$FAILED"
