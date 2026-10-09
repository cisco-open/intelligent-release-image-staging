#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  DEVICE="$REPO/device"
  ENTRYPOINT="${IRIS_ENTRYPOINT_UNDER_TEST:-$DEVICE/container/entrypoint.sh}"
  CONF="$BATS_TEST_TMPDIR/iris-agent.conf"
  STAGE="$BATS_TEST_TMPDIR/stage"
  mkdir -p "$STAGE"
}

_base() {
  env -i PATH="$PATH" IRIS_CONTAINER_TESTING=1 \
    IRIS_AGENT_CONF="$CONF" IRIS_STAGE_DIR="$STAGE" \
    IRIS_CATALOG_URL=https://192.0.2.1:8443 IRIS_CATALOG_TOKEN=test-token \
    IRIS_DEVICE_ID=device-1 "$@" bash "$ENTRYPOINT"
}

_iox() {
  _base IRIS_DEVICE_PLATFORM=iox IRIS_DEVICE_SSH_HOST=192.0.2.2 \
    IRIS_DEVICE_SSH_USER=test IRIS_DEVICE_SSH_PASS=test "$@"
}

_xr() {
  _base IRIS_DEVICE_PLATFORM=xr-appmgr IRIS_TEST_SKIP_MOUNT_CHECK=1 "$@"
}

_placement_from_conf() {
  env -i PATH="$PATH" PYTHONPATH="$DEVICE/agent:$DEVICE" \
    python3 - "$CONF" "$1" <<'PY'
import sys
import agent_config
import iris_agent

cfg = agent_config.load(sys.argv[1])
share_dir, share_ios = iris_agent._share_settings(cfg)
seen = []

def shared():
    seen.append("share")
    return True

def push(name, prefix):
    seen.append(("scp", name, prefix))

def direct():
    seen.append("place")
    return True

def emit(mnemonic, message):
    raise AssertionError("unexpected placement failure: " + mnemonic)

assert iris_agent._iox_place_impl(
    "image.bin", cfg["target_fs"], share_dir, share_ios,
    shared, push, direct, emit) is True
if sys.argv[2] == "scp":
    assert (share_dir, share_ios) == ("", "")
    assert seen == [("scp", "image.bin", cfg["target_fs"]), "place"]
else:
    assert share_dir and share_ios
    assert seen == ["share"]
PY
}

@test "one Dockerfile and entrypoint replace both legacy definitions" {
  [ -f "$DEVICE/container/Dockerfile" ]
  [ -f "$ENTRYPOINT" ]
  [ -f "$DEVICE/container/reconcile.sh" ]
  [ ! -e "$DEVICE/iox/Dockerfile" ]
  [ ! -e "$DEVICE/iox/entrypoint.sh" ]
  [ ! -e "$DEVICE/xr/Dockerfile" ]
  [ ! -e "$DEVICE/xr/entrypoint.sh" ]
}

@test "canonical image embeds the reconcile path and selects aria2 by TARGETARCH" {
  grep -q '^COPY reconcile.sh /reconcile.sh$' "$DEVICE/container/Dockerfile"
  grep -q '^ARG TARGETARCH$' "$DEVICE/container/Dockerfile"
  grep -q '^COPY agent_bin/aria2c-${TARGETARCH} /opt/iris/bin/aria2c$' \
    "$DEVICE/container/Dockerfile"
}

@test "canonical image embeds rendered instruction trust and explicit verifier tooling" {
  dockerfile="$DEVICE/container/Dockerfile"
  grep -Eq 'apk add .*openssh-keygen' "$dockerfile"
  grep -q '^COPY agent/iris-signers.allowed_signers /opt/iris/agent/iris-signers.allowed_signers$' \
    "$dockerfile"
  grep -q '^COPY agent/iris-root.allowed_signers /opt/iris/agent/iris-root.allowed_signers$' \
    "$dockerfile"
  grep -Eq 'chmod 0444 .*iris-signers.allowed_signers' "$dockerfile"
  ! grep -q 'IRIS_MAX_PEERS=' "$dockerfile"
  ! grep -q 'IRIS_MAX_CONCURRENT=' "$dockerfile"
}

@test "all container package builders forward one root directory to the common renderer" {
  common="$REPO/tools/build-device-image.sh"
  iox="$DEVICE/iox/build.sh"
  xr="$REPO/tools/build-xr-package.sh"
  grep -q -- '--instruction-roots-dir' "$common"
  grep -q 'render_device_trust' "$common"
  grep -q 'iris-signers.allowed_signers' "$common"
  grep -q 'iris-root.allowed_signers' "$common"
  grep -Eq 'build-device-image\.sh.*--instruction-roots-dir' "$iox"
  grep -Eq 'build-device-image\.sh.*--instruction-roots-dir' "$xr"
}

_neutral_archive() {
  python3 - "$1" "${2:-0}" <<'PY'
import gzip, hashlib, io, json, sys, tarfile
from pathlib import Path
def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def tar(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            if data is None:
                member.type, member.mode = tarfile.DIRTYPE, 0o755
            else:
                member.size = len(data)
            archive.addfile(member, None if data is None else io.BytesIO(data))
    return buffer.getvalue()
blobs = {}
def blob(data, media, **extra):
    key = hashlib.sha256(data).hexdigest()
    blobs['blobs/sha256/' + key] = data
    return dict(mediaType=media, digest='sha256:' + key, size=len(data), **extra)
kind = 'application/vnd.oci.image.'
descriptors = []
for arch in ('amd64', 'arm64'):
    entries = [(name, None) for name in ('opt', 'opt/iris', 'opt/iris/agent')]
    entries.append(('opt/iris/agent/runtime.py', arch.encode()))
    if sys.argv[2] == '1':
        entries.append(('opt/iris/agent/iris-root.allowed_signers', b'active public trust'))
    layer = tar(entries)
    config = dict(os='linux', architecture=arch, rootfs=dict(type='layers',
        diff_ids=['sha256:' + hashlib.sha256(layer).hexdigest()]))
    manifest = dict(schemaVersion=2, mediaType=kind+'manifest.v1+json',
        config=blob(encoded(config), kind+'config.v1+json'),
        layers=[blob(gzip.compress(layer, mtime=0), kind+'layer.v1.tar+gzip')])
    descriptors.append(blob(encoded(manifest), kind+'manifest.v1+json',
        platform=dict(os='linux', architecture=arch)))
index = dict(schemaVersion=2, mediaType=kind+'index.v1+json', manifests=descriptors)
Path(sys.argv[1]).write_bytes(tar([('oci-layout', encoded(dict(imageLayoutVersion='1.0.0'))),
    ('index.json', encoded(index)), *sorted(blobs.items())]))
PY
}

_neutral_fixture() {
  BUILD_REPO="$BATS_TEST_TMPDIR/build-repo"
  MOCK_BIN="$BATS_TEST_TMPDIR/mock-bin"
  MOCK_OCI="$BATS_TEST_TMPDIR/neutral.oci.tar"
  MOCK_DOCKER_LOG="$BATS_TEST_TMPDIR/docker.log"
  MOCK_RENDER_TRACE="$BATS_TEST_TMPDIR/render.log"
  mkdir -p "$BUILD_REPO"/{tools/iris_installer,tools/licenses,device/container,device/agent,deliverables,server,artifacts} "$MOCK_BIN"
  cp "$REPO/tools/build-device-image.sh" "$BUILD_REPO/tools/"
  cp "$DEVICE/container/"{Dockerfile,entrypoint.sh,reconcile.sh,rebuild-xml.py} "$BUILD_REPO/device/container/"
  cp "$REPO/tools/"{iris-aead.c,build-instruction-crypto-inner.sh} "$BUILD_REPO/tools/"
  cp "$REPO/tools/licenses/musl-COPYRIGHT" "$BUILD_REPO/tools/licenses/"
  cp "$REPO/tools/iris_installer/"{__init__.py,state.py,custody.py,key_setup.py,device_finalize.py} "$BUILD_REPO/tools/iris_installer/"
  printf 'fixture-version\n' > "$BUILD_REPO/VERSION"
  printf '# fixture\n' > "$BUILD_REPO/device/agent/runtime.py"
  printf '# fixture\n' > "$BUILD_REPO/device/agent/peer-transfer-hook.sh"
  printf '# fixture\n' > "$BUILD_REPO/device/verify_image.py"
  for arch in x86_64 aarch64; do
    printf 'synthetic %s\n' "$arch" > "$BUILD_REPO/deliverables/aria2c-$arch"
    printf '%s %s\n' "$(sha256sum "$BUILD_REPO/deliverables/aria2c-$arch" | cut -d' ' -f1)" "$arch" >> "$BUILD_REPO/tools/aria2c.sha256"
  done
  cat > "$BUILD_REPO/server/instruction_keys.py" <<'PY'
import os
from pathlib import Path
class InstructionKeyError(Exception): pass
def render_device_trust(roots, output):
    Path(os.environ['MOCK_RENDER_TRACE']).write_text('called')
    for name in ('iris-signers.allowed_signers', 'iris-root.allowed_signers'):
        (Path(output) / name).write_text('synthetic rooted-mode context')
PY
  cat > "$MOCK_BIN/file" <<'SH'
#!/bin/sh
case "$1" in *amd64) echo 'ELF x86-64';; *arm64) echo 'ELF ARM aarch64';; *) exit 1;; esac
SH
  cat > "$MOCK_BIN/docker" <<'SH'
#!/bin/bash
printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"
if [ "$*" = 'buildx version' ]; then exit 0; fi
[ "$1 $2" = 'buildx build' ] || exit 91
for value in "$@"; do
  case "$value" in type=oci,dest=*) cp "$MOCK_OCI" "${value#type=oci,dest=}";; esac
done
SH
  chmod +x "$MOCK_BIN/docker" "$MOCK_BIN/file"
  _neutral_archive "$MOCK_OCI"
}

_device_builder() {
  local overrides=()
  while [[ "${1:-}" == *=* ]]; do overrides+=("$1"); shift; done
  env -i PATH="$MOCK_BIN:$PATH" MOCK_OCI="$MOCK_OCI" \
    MOCK_DOCKER_LOG="$MOCK_DOCKER_LOG" MOCK_RENDER_TRACE="$MOCK_RENDER_TRACE" \
    "${overrides[@]}" bash "$BUILD_REPO/tools/build-device-image.sh" "$@"
}

@test "neutral device build has explicit separate identity and no root rendering" {
  _neutral_fixture
  mkdir "$BATS_TEST_TMPDIR/context"
  run _device_builder --context "$BATS_TEST_TMPDIR/context" --neutral-trust
  [ "$status" -eq 0 ]
  archive="$BUILD_REPO/artifacts/iris-device-fixture-version-neutral.oci.tar"
  [ -f "$archive" ]
  grep -qx 'format=iris-device-neutral-oci-v1' "$archive.manifest"
  grep -qx 'trust_mode=neutral' "$archive.manifest"
  grep -Eq '^source_sha256=[0-9a-f]{64}$' "$archive.manifest"
  grep -q -- '--build-arg IRIS_NEUTRAL_TRUST=1' "$MOCK_DOCKER_LOG"
  [ ! -e "$MOCK_RENDER_TRACE" ]
  [ ! -s "$BATS_TEST_TMPDIR/context/agent/iris-signers.allowed_signers" ]
  [ ! -s "$BATS_TEST_TMPDIR/context/agent/iris-root.allowed_signers" ]
  mkdir "$BATS_TEST_TMPDIR/reuse-context"
  run _device_builder --context "$BATS_TEST_TMPDIR/reuse-context" --neutral-trust
  [ "$status" -eq 0 ]
  [[ "$output" == *"reusing canonical device OCI"* ]]
  [ "$(grep -c '^buildx build ' "$MOCK_DOCKER_LOG")" -eq 1 ]
}

@test "ordinary device build retains root rendering and rooted provenance" {
  _neutral_fixture
  mkdir "$BATS_TEST_TMPDIR/context"
  run _device_builder --context "$BATS_TEST_TMPDIR/context"
  [ "$status" -eq 0 ]
  archive="$BUILD_REPO/artifacts/iris-device-fixture-version.oci.tar"
  grep -qx 'format=iris-device-oci-v1' "$archive.manifest"
  grep -qx 'trust_mode=rooted' "$archive.manifest"
  [ -s "$MOCK_RENDER_TRACE" ]
  [ -s "$BATS_TEST_TMPDIR/context/agent/iris-root.allowed_signers" ]
  grep -q -- '--build-arg IRIS_NEUTRAL_TRUST=0' "$MOCK_DOCKER_LOG"
}

@test "neutral build refuses explicit roots and missing architecture before work" {
  _neutral_fixture
  mkdir "$BATS_TEST_TMPDIR/context"
  run _device_builder --context "$BATS_TEST_TMPDIR/context" --neutral-trust --instruction-roots-dir /not-opened
  [ "$status" -eq 2 ]
  [[ "$output" == *"cannot use instruction roots"* ]]
  run _device_builder IRIS_INSTRUCTION_ROOTS_DIR=/not-opened --context "$BATS_TEST_TMPDIR/context" --neutral-trust
  [ "$status" -eq 2 ]
  run _device_builder IRIS_DEVICE_PLATFORMS=linux/amd64 --context "$BATS_TEST_TMPDIR/context" --neutral-trust
  [ "$status" -eq 2 ]
  [[ "$output" == *"requires both"* ]]
  [ ! -e "$MOCK_DOCKER_LOG" ]
  [ ! -e "$MOCK_RENDER_TRACE" ]
  [ -z "$(ls -A "$BATS_TEST_TMPDIR/context")" ]
}

@test "forced rebuild cannot mix neutral and rooted caches" {
  _neutral_fixture
  for first in neutral rooted; do
    output_path="$BATS_TEST_TMPDIR/built-$first.oci.tar"
    mkdir "$BATS_TEST_TMPDIR/$first-context" "$BATS_TEST_TMPDIR/$first-second"
    args=()
    [ "$first" != neutral ] || args=(--neutral-trust)
    run _device_builder --context "$BATS_TEST_TMPDIR/$first-context" --output "$output_path" "${args[@]}"
    [ "$status" -eq 0 ]
    before="$(sha256sum "$output_path" "$output_path.manifest")"
    args=()
    [ "$first" != rooted ] || args=(--neutral-trust)
    run _device_builder IRIS_FORCE_DEVICE_IMAGE_BUILD=1 --context "$BATS_TEST_TMPDIR/$first-second" --output "$output_path" "${args[@]}"
    [ "$status" -eq 1 ]
    [[ "$output" == *"different trust mode"* ]]
    [ "$(sha256sum "$output_path" "$output_path.manifest")" = "$before" ]
  done
  [ "$(grep -c '^buildx build ' "$MOCK_DOCKER_LOG")" -eq 2 ]
}

@test "neutral builder refuses an emitted runtime containing active roots" {
  _neutral_fixture
  _neutral_archive "$MOCK_OCI" 1
  mkdir "$BATS_TEST_TMPDIR/context"
  run _device_builder --context "$BATS_TEST_TMPDIR/context" --neutral-trust
  [ "$status" -ne 0 ]
  [[ "$output" == *"already contains active trust"* ]]
  [ -z "$(ls -A "$BUILD_REPO/artifacts")" ]
}

@test "neutral Dockerfile removes only empty placeholders before one flattened export" {
  dockerfile="$DEVICE/container/Dockerfile"
  grep -qx 'ARG IRIS_NEUTRAL_TRUST=0' "$dockerfile"
  grep -q '0) test -s /opt/iris/agent/iris-signers.allowed_signers' "$dockerfile"
  grep -q '1) test ! -s /opt/iris/agent/iris-signers.allowed_signers' "$dockerfile"
  grep -q 'rm /opt/iris/agent/iris-signers.allowed_signers /opt/iris/agent/iris-root.allowed_signers' "$dockerfile"
  [ "$(grep -c '^FROM scratch$' "$dockerfile")" -eq 1 ]
  grep -qx 'COPY --from=runtime-files / /' "$dockerfile"
  # BuildKit creates a second (empty) layer for WORKDIR, even if COPY already
  # supplied the directory. CAF and offline trust finalization require one.
  ! sed -n '/^FROM scratch$/,$p' "$dockerfile" | grep -Eq '^(WORKDIR|RUN|ADD) '
  [ "$(sed -n '/^FROM scratch$/,$p' "$dockerfile" | grep -c '^COPY ')" -eq 1 ]
  grep -qx '  cd /opt/iris || fatal "cannot enter the device runtime directory"' "$ENTRYPOINT"
}

@test "missing and unknown platform values fail before any config write" {
  run _base
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS_DEVICE_PLATFORM is required"* ]]
  [ ! -e "$CONF" ]
  run _base IRIS_DEVICE_PLATFORM=ios
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown IRIS_DEVICE_PLATFORM"* ]]
  [ ! -e "$CONF" ]
}

@test "catalog URL credentials are refused before config creation" {
  run _base IRIS_DEVICE_PLATFORM=iox \
    IRIS_DEVICE_SSH_HOST=192.0.2.2 IRIS_DEVICE_SSH_USER=test \
    IRIS_DEVICE_SSH_PASS=test \
    IRIS_CATALOG_URL=https://user:literal-secret@192.0.2.1:8443
  [ "$status" -ne 0 ]
  [[ "$output" == *"without credentials"* ]]
  [[ "$output" != *"literal-secret"* ]]
  [ ! -e "$CONF" ]
}

@test "container refuses a missing or malformed tracker certificate before launch" {
  missing="$BATS_TEST_TMPDIR/missing.pem"
  run env -i PATH="$PATH" PYTHONPATH="$DEVICE/agent" \
    IRIS_CONTAINER_TESTING=1 IRIS_DEVICE_PLATFORM=iox \
    IRIS_AGENT_CONF="$CONF" IRIS_STAGE_DIR="$STAGE" \
    IRIS_CATALOG_URL=https://192.0.2.1:8443 IRIS_CATALOG_TOKEN=test-token \
    IRIS_DEVICE_ID=device-1 IRIS_DEVICE_SSH_HOST=192.0.2.2 \
    IRIS_DEVICE_SSH_USER=test IRIS_DEVICE_SSH_PASS=test \
    IRIS_CATALOG_CA="$missing" bash "$ENTRYPOINT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"catalog_ca is not a readable certificate file"* ]]

  printf '%s\n' 'not a certificate' > "$BATS_TEST_TMPDIR/bad.pem"
  CONF="$BATS_TEST_TMPDIR/bad-agent.conf"
  run env -i PATH="$PATH" PYTHONPATH="$DEVICE/agent" \
    IRIS_CONTAINER_TESTING=1 IRIS_DEVICE_PLATFORM=iox \
    IRIS_AGENT_CONF="$CONF" IRIS_STAGE_DIR="$STAGE" \
    IRIS_CATALOG_URL=https://192.0.2.1:8443 IRIS_CATALOG_TOKEN=test-token \
    IRIS_DEVICE_ID=device-1 IRIS_DEVICE_SSH_HOST=192.0.2.2 \
    IRIS_DEVICE_SSH_USER=test IRIS_DEVICE_SSH_PASS=test \
    IRIS_CATALOG_CA="$BATS_TEST_TMPDIR/bad.pem" bash "$ENTRYPOINT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"catalog_ca is not a valid certificate bundle"* ]]
}

@test "runtime-delivered catalog certificate path is platform-derived" {
  run _iox
  [ -f "$CONF" ]
  grep -qF "catalog_ca = $STAGE/iris-catalog.pem" "$CONF"

  rm -f "$CONF"
  run _xr
  [ -f "$CONF" ]
  grep -qF "catalog_ca = $STAGE/iris-catalog.pem" "$CONF"
}

@test "fixed IOx and XR bootstrap candidates import privately into persistent work" {
  appdata="$BATS_TEST_TMPDIR/appdata"
  mkdir -p "$appdata"
  printf '%s' 'iox-private-envelope' > "$appdata/iris-instructions.bootstrap"
  chmod 600 "$appdata/iris-instructions.bootstrap"
  run _iox CAF_APP_APPDATA_DIR="$appdata"
  [ -f "$STAGE/iris-instructions.bootstrap" ]
  [ "$(stat -c %a "$STAGE/iris-instructions.bootstrap")" = 600 ]
  [ "$(cat "$STAGE/iris-instructions.bootstrap")" = iox-private-envelope ]
  [ ! -e "$appdata/iris-instructions.bootstrap" ]
  [ ! -e "$STAGE/iris-instructions.lkg" ]

  rm -rf "$STAGE" "$CONF"
  mkdir -p "$STAGE"
  printf '%s' 'xr-private-envelope' > "$STAGE/iris-instructions.bootstrap"
  chmod 600 "$STAGE/iris-instructions.bootstrap"
  run _xr
  [ -f "$STAGE/iris-work/iris-instructions.bootstrap" ]
  [ "$(stat -c %a "$STAGE/iris-work/iris-instructions.bootstrap")" = 600 ]
  [ "$(cat "$STAGE/iris-work/iris-instructions.bootstrap")" = xr-private-envelope ]
  [ ! -e "$STAGE/iris-instructions.bootstrap" ]
  [ ! -e "$STAGE/iris-work/iris-instructions.lkg" ]
}

@test "invalid bootstrap candidate cannot replace an existing pending envelope" {
  mkdir -p "$STAGE/iris-work"
  printf '%s' 'existing-pending-envelope' > \
    "$STAGE/iris-work/iris-instructions.bootstrap"
  target="$BATS_TEST_TMPDIR/symlink-target"
  printf '%s' 'replacement-envelope' > "$target"
  ln -s "$target" "$STAGE/iris-instructions.bootstrap"
  run _xr
  [ "$status" -ne 0 ]
  [[ "$output" == *"instruction bootstrap candidate is invalid"* ]]
  [ "$(cat "$STAGE/iris-work/iris-instructions.bootstrap")" = \
    existing-pending-envelope ]
  [ -L "$STAGE/iris-instructions.bootstrap" ]
}

@test "production IOx requires CAF app-data and refuses a catalog path override" {
  run env -i PATH="$PATH" IRIS_DEVICE_PLATFORM=iox \
    IRIS_CATALOG_URL=https://192.0.2.1:8443 IRIS_CATALOG_TOKEN=test-token \
    IRIS_DEVICE_ID=device-1 IRIS_DEVICE_SSH_HOST=192.0.2.2 \
    IRIS_DEVICE_SSH_USER=test IRIS_DEVICE_SSH_PASS=test \
    bash "$ENTRYPOINT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"CAF_APP_APPDATA_DIR is required"* ]]

  run env -i PATH="$PATH" IRIS_DEVICE_PLATFORM=iox \
    CAF_APP_APPDATA_DIR=/data/appdata IRIS_CATALOG_CA=/tmp/redirected.pem \
    bash "$ENTRYPOINT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS_CATALOG_CA is test-only"* ]]
}

@test "IOx gets its profile and retains a validated explicit target override" {
  run _iox IRIS_TARGET_FS=sdflash:
  [ -f "$CONF" ]
  grep -q '^device_platform = iox$' "$CONF"
  grep -q '^target_fs = sdflash:$' "$CONF"
  grep -q '^runtime_mode = container$' "$CONF"
  grep -q '^share_dir = $' "$CONF"
  grep -q '^share_ios_path = $' "$CONF"
}

@test "IOx without a configured share selects SCP from the generated config" {
  for target in bootflash: sdflash:; do
    run _iox IRIS_TARGET_FS="$target" PYTHONPATH="$DEVICE/agent"
    [[ "$output" == *"catalog_ca is not a readable certificate file"* ]]
    run _placement_from_conf scp
    [ "$status" -eq 0 ]
  done
}

@test "IOx clears stale fabricated share defaults before placement selection" {
  run _iox IRIS_TARGET_FS=bootflash: PYTHONPATH="$DEVICE/agent" \
    IRIS_SHARE_DIR=/mnt/share IRIS_SHARE_IOS_PATH=usbflash1:iox_host_data_share
  grep -q '^share_dir = /mnt/share$' "$CONF"
  grep -q '^share_ios_path = usbflash1:iox_host_data_share$' "$CONF"

  run _iox PYTHONPATH="$DEVICE/agent"
  [[ "$output" == *"catalog_ca is not a readable certificate file"* ]]
  grep -q '^share_dir = $' "$CONF"
  grep -q '^share_ios_path = $' "$CONF"
  run _placement_from_conf scp
  [ "$status" -eq 0 ]
}

@test "partial IOx share options fail before config creation" {
  for setting in IRIS_SHARE_DIR=/mnt/share \
      IRIS_SHARE_IOS_PATH=usbflash1:iox_host_data_share; do
    run _iox "$setting"
    [ "$status" -ne 0 ]
    [[ "$output" == *"IRIS_SHARE_DIR and IRIS_SHARE_IOS_PATH must be set together"* ]]
    [ ! -e "$CONF" ]
  done
}

@test "unsafe IOx target and share paths fail closed" {
  run _iox IRIS_TARGET_FS='flash:;reload'
  [ "$status" -ne 0 ]
  [[ "$output" == *"safe IOS filesystem prefix"* ]]
  run _iox IRIS_SHARE_DIR=/mnt/share IRIS_SHARE_IOS_PATH='flash:x/../escape'
  [ "$status" -ne 0 ]
  [[ "$output" == *"must not contain '..'"* ]]
  run _iox IRIS_SHARE_DIR=/mnt/../escape IRIS_SHARE_IOS_PATH=usbflash1:iris
  [ "$status" -ne 0 ]
  [[ "$output" == *"must not contain '..'"* ]]
  [ ! -e "$CONF" ]
}

@test "IOx accepts and persists a validated alternate mounted-share pair" {
  run _iox IRIS_TARGET_FS=flash: IRIS_SHARE_DIR=/mnt/alternate \
    IRIS_SHARE_IOS_PATH=usbflash2:iris-alt
  [ -f "$CONF" ]
  grep -q '^share_dir = /mnt/alternate$' "$CONF"
  grep -q '^share_ios_path = usbflash2:iris-alt$' "$CONF"
  run _placement_from_conf share
  [ "$status" -eq 0 ]
}

@test "XR fixes harddisk storage and rejects IOx target, share and SSH surfaces" {
  run _xr IRIS_TARGET_FS=flash:
  [ "$status" -ne 0 ]
  [[ "$output" == *"forbids IRIS_TARGET_FS"* ]]
  run _xr IRIS_SHARE_DIR=/mnt/share
  [ "$status" -ne 0 ]
  [[ "$output" == *"forbids IRIS_SHARE_DIR"* ]]
  run _xr IRIS_DEVICE_SSH_HOST=192.0.2.2
  [ "$status" -ne 0 ]
  [[ "$output" == *"forbids IRIS_DEVICE_SSH_"* ]]
}

@test "XR default config is persistent and harddisk-bound" {
  run _xr
  [ -f "$CONF" ]
  grep -q '^device_platform = xr-appmgr$' "$CONF"
  grep -q '^target_fs = harddisk:$' "$CONF"
  grep -q '^mode = xr$' "$CONF"
}

@test "IRIS_MAX_CONCURRENT is bounded before reaching aria2" {
  for bad in 0 1001 nope; do
    rm -f "$CONF"
    run _iox IRIS_MAX_CONCURRENT="$bad"
    [ "$status" -ne 0 ] || return 1
    [[ "$output" == *"IRIS_MAX_CONCURRENT"* ]] || return 1
    [ ! -e "$CONF" ] || return 1
  done
}

@test "reconciled env is validated even when a persistent conf already exists" {
  cat > "$CONF" <<'EOF'
catalog_url = https://sentinel.example:8443
catalog_token = sentinel-token
device_id = device-1
device_platform = iox
device_ssh_host = 192.0.2.2
device_ssh_user = test
device_ssh_pass = test
telemetry = on
EOF
  before="$(sha256sum "$CONF" | awk '{print $1}')"
  run _iox IRIS_TELEMETRY=$'on\r\nagent_version = forged'
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS_TELEMETRY must be a single line"* ]]
  [ "$(sha256sum "$CONF" | awk '{print $1}')" = "$before" ]
}

@test "invalid telemetry and XR facts in an existing conf fail before reconcile" {
  cat > "$CONF" <<'EOF'
catalog_url = https://sentinel.example:8443
catalog_token = sentinel-token
device_id = device-1
device_platform = xr-appmgr
mode = xr
target_fs = harddisk:
telemetry_stream = maybe
device_model = 8201
EOF
  before="$(sha256sum "$CONF" | awk '{print $1}')"
  run _xr
  [ "$status" -ne 0 ]
  [[ "$output" == *"telemetry_stream has an invalid boolean value"* ]]
  [ "$(sha256sum "$CONF" | awk '{print $1}')" = "$before" ]

  sed -i 's/telemetry_stream = maybe/telemetry_stream = off/; s/device_model = 8201/device_model = 8201;reload/' "$CONF"
  before="$(sha256sum "$CONF" | awk '{print $1}')"
  run _xr
  [ "$status" -ne 0 ]
  [[ "$output" == *"device_model contains unsafe characters"* ]]
  [ "$(sha256sum "$CONF" | awk '{print $1}')" = "$before" ]
}

@test "XR test-only mount bypass cannot be enabled in production" {
  run env -i PATH="$PATH" IRIS_DEVICE_PLATFORM=xr-appmgr \
    IRIS_TEST_SKIP_MOUNT_CHECK=1 IRIS_CATALOG_URL=https://192.0.2.1:8443 \
    IRIS_CATALOG_TOKEN=t IRIS_DEVICE_ID=d bash "$ENTRYPOINT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not a mounted filesystem"* ]]
}
