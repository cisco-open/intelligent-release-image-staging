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
  grep -Eq '^RUN apk add .*openssh-keygen' "$dockerfile"
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
  grep -q '^share_ios_path = usbflash1:iox_host_data_share$' "$CONF"
}

@test "unsafe IOx target and share paths fail closed" {
  run _iox IRIS_TARGET_FS='flash:;reload'
  [ "$status" -ne 0 ]
  [[ "$output" == *"safe IOS filesystem prefix"* ]]
  run _iox IRIS_SHARE_IOS_PATH='flash:x/../escape'
  [ "$status" -ne 0 ]
  [[ "$output" == *"must not contain '..'"* ]]
}

@test "IOx accepts and persists a validated alternate mounted-share pair" {
  run _iox IRIS_SHARE_DIR=/mnt/alternate \
    IRIS_SHARE_IOS_PATH=usbflash2:iris-alt
  [ -f "$CONF" ]
  grep -q '^share_dir = /mnt/alternate$' "$CONF"
  grep -q '^share_ios_path = usbflash2:iris-alt$' "$CONF"
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
