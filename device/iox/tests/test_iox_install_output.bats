#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

@test "install waits for IOx readiness and reports meaningful app state" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'waiting for IOx app-hosting service (CAF/Dockerd)' "$install"
  [ "$status" -eq 0 ]
  run grep -F "app-hosting has not reported '\$APPID' yet" "$install"
  [ "$status" -eq 0 ]
}

@test "install reports IOS lifecycle output and removes a partial app config" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'install_out=' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'clear_partial_app_config' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'partial app-hosting configuration has been removed' "$install"
  [ "$status" -eq 0 ]
}

@test "install limits lifecycle output to meaningful IOS messages" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F "grep -E 'Installing package|Failed to install|%IOX|%APP'" "$install"
  [ "$status" -eq 0 ]
}

@test "install persists a successful IOx app lifecycle" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'copy running-config startup-config' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'startup-config saved' "$install"
  [ "$status" -eq 0 ]
}

# --- inband IOx (dry-run structural safety) ---
setup() {
  export DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 STAGE_HOST=192.0.2.2 \
         DEVICE_SSH_PASS=x
  INSTALL="$BATS_TEST_DIRNAME/../install.sh"
}

@test "inband dry-run creates no VLAN/SVI and never replaces the AppGig allowed list" {
  NETWORK_ATTACHMENT=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\nvlan '* ]] && \
  [[ "$output" != *"interface Vlan"* ]] && \
  ! grep -Eq 'switchport trunk allowed vlan [0-9]' <<<"$output" && \
  [[ "$output" != *"ip address 192.0.2"* ]]
}

@test "inband dry-run trunks the AppGig additively (allowed vlan add)" {
  NETWORK_ATTACHMENT=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [[ "$output" == *"interface AppGigabitEthernet1/1"* ]] && \
  [[ "$output" == *"switchport mode trunk"* ]] && \
  [[ "$output" == *"switchport trunk allowed vlan add 120"* ]]
}

@test "inband dry-run points the app SSH-to-IOS at the existing management SVI" {
  NETWORK_ATTACHMENT=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [[ "$output" == *"IRIS_DEVICE_SSH_HOST=192.0.2.1"* ]] && \
  [[ "$output" == *"vlan 120 guest-interface 0"* ]]
}

@test "inband real run requires IOS_SSH_HOST" {
  NETWORK_ATTACHMENT=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IRIS_CRT_FILE=/dev/null run bash "$INSTALL"
  [ "$status" -ne 0 ] && [[ "$output" == *"IOS_SSH_HOST"* ]]
}

@test "routed dry-run still creates the IRIS VLAN and SVI" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [[ "$output" == *"vlan 666"* ]] && [[ "$output" == *"interface Vlan666"* ]]
}

# --- C9k share-mount transfer (Route B): the app-hosting SSD share is bind-
# mounted into the container so the agent lands its scratch at disk speed and
# placement is an IOS-internal copy — no scp, no punt path, no CoPP cap. ---

@test "share dry-run renders the bind-mount run-opts and the share env" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    SHARE_IOS_PATH=usbflash1:iox_host_data_share \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'-v /vol/usb1/iox_host_data_share:/mnt/share'* ]] && \
  [[ "$output" == *'-e IRIS_SHARE_DIR=/mnt/share'* ]] && \
  [[ "$output" == *'-e IRIS_SHARE_IOS_PATH=usbflash1:iox_host_data_share'* ]] && \
  [[ "$output" == *"mkdir usbflash1:iox_host_data_share"* ]]
}

@test "share run-opts render INSIDE the app-hosting docker block (before end)" {
  # app-hosting silently ignores run-opts rendered after the block's `end`,
  # so the mount would vanish while every substring gate still passed —
  # assert the line that immediately follows run-opts 12 is `end`.
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    SHARE_IOS_PATH=usbflash1:iox_host_data_share \
    run bash "$INSTALL" --dry-run
  after="$(printf '%s\n' "$output" | grep -A1 'run-opts 12' | tail -1)"
  [ "$after" = "end" ]
}

@test "without SHARE env no bind-mount is rendered (IE-3x00 default unchanged)" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [[ "$output" != *'-v /vol/'* ]] && \
  [[ "$output" != *'IRIS_SHARE_DIR'* ]]
}

@test "SHARE env is all-or-nothing" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] && [[ "$output" == *"SHARE_IOS_PATH"* ]]
}

@test "IOx install retries app-hosting verification disable until it succeeds" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'app-hosting verification disable' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'disabled successfully' "$install"
  [ "$status" -eq 0 ]
}

# --- operator-facing PREREQ checks (2026-08-20 incident: an IE-3400 lost `ip
# routing` on re-image; onboarding "succeeded" while the app's VLAN traffic had
# no L3 path out — silent, invisible, hours to diagnose). Static assertions
# prove the PREREQ lines and commands are present and land before step [2/9];
# the stub-backed tests below prove the pass/fail/warn behavior itself. ---

@test "install checks ip routing before applying any config (PREREQ, routed only)" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'show running-config | include ^ip routing' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'PREREQ: ip routing is disabled on this switch' "$install"
  [ "$status" -eq 0 ]
}

@test "install checks for an IOx SD partition (PREREQ, IE3x00)" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'show sdflash: filesys' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'PREREQ: no IOx partition on the SD card' "$install"
  [ "$status" -eq 0 ]
}

@test "install warns (not fails) on a stale device clock (PREREQ)" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'PREREQ WARNING: device clock is' "$install"
  [ "$status" -eq 0 ]
}

@test "PREREQ checks land before step [2/9] applies IOx networking" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  pre_line="$(grep -n '^echo "\[pre\] prerequisite checks' "$install" | head -1 | cut -d: -f1)"
  step2_line="$(grep -n '^echo "\[2/9\]' "$install" | head -1 | cut -d: -f1)"
  [ -n "$pre_line" ] && [ -n "$step2_line" ] && [ "$pre_line" -lt "$step2_line" ]
}

# --- behavioral PREREQ tests: stub lab/device-run.sh so install.sh's RUN
# helper talks to a fake device transcript instead of a real one. Mirrors the
# STUBDIR pattern in device/tests/test_device_install.bats (HERE resolves off
# a symlinked install.sh, so lab/device-run.sh must live two dirs up from it).
# FAKE_* env vars steer the fake device's answers per check. ---

_iox_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device/iox"
  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
case "$cmds" in
  *"show running-config"*)
    [ "${FAKE_IP_ROUTING:-yes}" = "yes" ] && echo "ip routing"
    ;;
esac
case "$cmds" in
  *"show sdflash: filesys"*)
    if [ "${FAKE_IOX_PARTITION:-yes}" = "yes" ]; then
      echo "IOx Partition Exists"
    else
      echo "Filesystem: sdflash: (no IOx partition present)"
    fi
    ;;
esac
case "$cmds" in
  *"show clock"*)
    echo "${FAKE_CLOCK_LINE:-14:23:07.512 UTC Thu Aug 20 2026}"
    ;;
esac
case "$cmds" in
  *"show iox"*)
    echo "IOx service (CAF)        : Running"
    echo "Dockerd                  : Running"
    ;;
esac
case "$cmds" in
  *"app-hosting verification disable"*)
    echo "App hosting verification disabled successfully"
    ;;
esac
exit 0
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"
  ln -s "$BATS_TEST_DIRNAME/../install.sh" "$STUBDIR/device/iox/install.sh"
  CRTFILE="$BATS_TEST_TMPDIR/crt.pem"
  echo "-----BEGIN CERTIFICATE-----fake-----END CERTIFICATE-----" > "$CRTFILE"
}

# same portable timeout wrapper as device/tests/test_device_install.bats: the
# real (non-dry) flow reaches long device-wait loops past the PREREQ step, so
# "did it proceed" tests bound the run and inspect partial captured output.
_iox_run_with_timeout_impl() {
  local secs="$1"; shift
  local outfile
  outfile="$(mktemp)"
  ("$@" > "$outfile" 2>&1) &
  local pid=$!
  local waited=0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$secs" ]; do
    sleep 1; waited=$((waited + 1))
  done
  local rc
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    rc=124
  else
    wait "$pid"; rc=$?
  fi
  cat "$outfile"
  rm -f "$outfile"
  return "$rc"
}

iox_run_with_timeout() {
  run _iox_run_with_timeout_impl "$@"
}

_iox_env() {
  env DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 STAGE_HOST=192.0.2.2 \
    DEVICE_SSH_PASS=x VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 \
    GUEST_IP=192.0.2.10 IRIS_CRT_FILE="$CRTFILE" "$@"
}

@test "ip routing missing: real run exits non-zero with the PREREQ line" {
  _iox_stub_setup
  run _iox_env FAKE_IP_ROUTING=no bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"PREREQ: ip routing is disabled on this switch"* ]]
}

@test "ip routing present: real run proceeds past the check to step [2/9]" {
  _iox_stub_setup
  iox_run_with_timeout 12 env DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 \
    STAGE_HOST=192.0.2.2 DEVICE_SSH_PASS=x VLAN=666 SVI_IP=192.0.2.9 \
    SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 IRIS_CRT_FILE="$CRTFILE" \
    FAKE_IP_ROUTING=yes bash "$STUBDIR/device/iox/install.sh"
  [[ "$output" != *"PREREQ: ip routing is disabled"* ]]
  [[ "$output" == *"[2/9]"* ]]
}

@test "no IOx partition: real run exits non-zero with the PREREQ line" {
  _iox_stub_setup
  run _iox_env FAKE_IP_ROUTING=yes FAKE_IOX_PARTITION=no \
    bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"PREREQ: no IOx partition on the SD card"* ]]
}

@test "old device clock: real run warns but continues past the check" {
  _iox_stub_setup
  iox_run_with_timeout 12 env DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 \
    STAGE_HOST=192.0.2.2 DEVICE_SSH_PASS=x VLAN=666 SVI_IP=192.0.2.9 \
    SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 IRIS_CRT_FILE="$CRTFILE" \
    FAKE_IP_ROUTING=yes FAKE_IOX_PARTITION=yes \
    FAKE_CLOCK_LINE="14:23:07.512 UTC Thu Aug 20 2018" \
    bash "$STUBDIR/device/iox/install.sh"
  [[ "$output" == *"PREREQ WARNING: device clock is 2018"* ]]
  [[ "$output" == *"[2/9]"* ]]
}
