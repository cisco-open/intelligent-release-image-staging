#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Stage the DERIVABLE served artifacts into the artifacts dir at container
# startup, so a fresh deploy no longer fails onboarding on missing files. The
# files a Guest Shell device downloads that the container can produce itself:
#   iris-agent.tgz    the Guest Shell agent bundle (rebuilt every start from the
#                     image-baked device/ sources, so it always matches the
#                     deployed agent code)
#   iris-agent.tgz.sha256  the exact raw digest evidence for that archive
#   bootstrap.sh      the on-device launcher (device/bootstrap.sh)
#   iris-catalog.pem  the pinned CA the agent trusts = the server's PUBLIC cert
#   iris-signers.pem  the two offline instruction roots in CA signer form
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
ROOTS="${IRIS_INSTRUCTION_ROOTS_DIR:-${IRIS_CONFIG:-/etc/iris}/instr/roots.d}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SUMS="${IRIS_ARIA2_SUMS:-/opt/iris/tools/aria2c.sha256}"
STATUS="${IRIS_RUN:-/run/iris}/served-bundle.json"
FAILED=0

# Runtime status remains writable even when the artifacts mount is read-only.
# Record an attempt before packing so an interrupted run cannot leave an old
# success record. Bind success to every published and embedded trust input.
write_status() {
  python3 - "$STATUS" "$ART" "$1" "$2" <<'PYTHON'
import hashlib, json, os, stat, sys, tarfile, tempfile
path, artifacts, state, reason = sys.argv[1:]
record = {"format": "iris-served-bundle-v1", "state": state, "reason": reason}
if state == "ok":
    contents = {}
    embedded = {}
    identities = {}
    for name in ("iris-agent.tgz", "iris-agent.tgz.sha256", "bootstrap.sh",
                 "iris-signers.pem"):
        target = os.path.join(artifacts, name)
        info = os.lstat(target)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SystemExit("served publication contains a non-regular file")
        digest = hashlib.sha256()
        with open(target, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or \
                    (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                raise SystemExit("served publication changed while opening")
            if name == "iris-agent.tgz.sha256" and opened.st_size != 65:
                raise SystemExit("served bundle digest sidecar is invalid")
            if name == "iris-signers.pem" and opened.st_size > 128 * 1024:
                raise SystemExit("served signer trust is too large")
            identity = (opened.st_dev, opened.st_ino, opened.st_size,
                        opened.st_mtime_ns, opened.st_ctime_ns)
            data = bytearray()
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                if name in ("iris-agent.tgz.sha256", "iris-signers.pem"):
                    limit = 65 if name == "iris-agent.tgz.sha256" else 128 * 1024
                    if len(data) + len(chunk) > limit:
                        raise SystemExit("served publication grew while being read")
                    data.extend(chunk)
            if name == "iris-agent.tgz":
                handle.seek(0)
                with tarfile.open(fileobj=handle, mode="r:gz") as archive:
                    archive_members = archive.getmembers()
                    if len(archive_members) > 1024:
                        raise SystemExit("served bundle contains too many members")
                    for trust_name in (
                            "iris-signers.allowed_signers",
                            "iris-root.allowed_signers"):
                        members = [member for member in archive_members
                                   if member.name == trust_name]
                        if len(members) != 1 or not members[0].isfile() \
                                or not 0 < members[0].size <= 128 * 1024:
                            raise SystemExit(
                                "served bundle trust member is invalid")
                        member_handle = archive.extractfile(members[0])
                        trust_data = member_handle.read(128 * 1024 + 1) \
                            if member_handle is not None else b""
                        if not trust_data \
                                or len(trust_data) != members[0].size:
                            raise SystemExit(
                                "served bundle trust member is invalid")
                        embedded[trust_name] = trust_data
                        record[trust_name] = hashlib.sha256(
                            trust_data).hexdigest()
            after = os.fstat(handle.fileno())
            if (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns) != identity:
                raise SystemExit("served publication changed while being read")
        record[name] = digest.hexdigest()
        contents[name] = bytes(data)
        identities[name] = identity
    bundle_digest = record["iris-agent.tgz"]
    sidecar = contents["iris-agent.tgz.sha256"]
    if len(sidecar) != 65 or sidecar != (bundle_digest + "\n").encode("ascii"):
        raise SystemExit("served bundle digest sidecar is invalid")
    if embedded["iris-signers.allowed_signers"] != \
            contents["iris-signers.pem"]:
        raise SystemExit("public and bundled signer trust differ")
    for name, identity in identities.items():
        current = os.lstat(os.path.join(artifacts, name))
        if (current.st_dev, current.st_ino, current.st_size,
            current.st_mtime_ns, current.st_ctime_ns) != identity:
            raise SystemExit("served publication changed during readiness")
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

render_trust() {  # render_trust <output-directory>
  PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}" \
    python3 - "$ROOTS" "$1" <<'PYTHON'
import sys
from instruction_keys import InstructionKeyError, render_device_trust

try:
    render_device_trust(sys.argv[1], sys.argv[2])
except InstructionKeyError as exc:
    print("provision-served: instruction trust unavailable: " + str(exc),
          file=sys.stderr)
    raise SystemExit(1)
PYTHON
}

# Guest Shell bundle — rebuilt every start from the image-baked device/ sources
# (server/Dockerfile COPYs device/ into /opt/iris/device; there is no bind
# mount, so a host-side edit under device/ reaches the served bundle only
# after an image rebuild), so the served bundle can never drift from the
# agent code this image carries.
TX="$(mktemp -d "$ART/.served-bundle.XXXXXX")" || {
  bundle_failed artifacts-unwritable
  exit 1
}
trap 'rm -rf "$TX"' EXIT
if [ ! -d "$DEVICE/agent" ] || [ ! -f "$ARIA2" ]; then
  bundle_failed inputs-missing
elif ! verify_aria2; then
  bundle_failed verification-failed
elif ! render_trust "$TX/trust"; then
  bundle_failed instruction-roots-unavailable
elif "$HERE/pack-agent-bundle.sh" "$DEVICE" "$ARIA2" "$TX/iris-agent.tgz" \
      --instruction-roots-dir "$ROOTS" \
    && cp "$DEVICE/bootstrap.sh" "$TX/bootstrap.sh" \
    && cp "$TX/trust/iris-signers.allowed_signers" "$TX/iris-signers.pem" \
    && chmod 0644 "$TX/bootstrap.sh" "$TX/iris-signers.pem" \
    && stage_atomic "$TX/iris-signers.pem" iris-signers.pem \
    && stage_atomic "$TX/bootstrap.sh" bootstrap.sh \
    && stage_atomic "$TX/iris-agent.tgz" iris-agent.tgz \
    && stage_atomic "$TX/iris-agent.tgz.sha256" iris-agent.tgz.sha256; then
  if write_status ok ready; then
    echo "provision-served: staged digest- and trust-bound Guest Shell bundle"
  else
    bundle_failed status-write-failed
  fi
else
  bundle_failed publication-failed
fi
rm -rf "$TX"
trap - EXIT

# Pinned CA the devices download = the server's PUBLIC cert (plaintext on the
# config volume, no decrypt needed). Refresh every start so a rotated cert
# propagates to what onboarding serves.
if [ -f "$CRT" ]; then
  # Public certificate only: keep it host-readable so direct CLI onboarding
  # can deliver artifacts/iris-catalog.pem even when the container's private
  # umask is 077. The corresponding key remains only
  # in encrypted config/tmpfs and is never copied here.
  if cp "$CRT" "$ART/.iris-catalog.pem.tmp" \
    && chmod 0644 "$ART/.iris-catalog.pem.tmp" \
    && stage_atomic "$ART/.iris-catalog.pem.tmp" iris-catalog.pem; then
    echo "provision-served: staged iris-catalog.pem (server cert)"
  else
    FAILED=1
    rm -f "$ART/.iris-catalog.pem.tmp"
    echo "provision-served: cannot stage iris-catalog.pem (server cert)" >&2
  fi
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
