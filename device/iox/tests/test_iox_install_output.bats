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
  # assert the line that immediately follows run-opts 11 is `end`.
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    SHARE_IOS_PATH=usbflash1:iox_host_data_share \
    run bash "$INSTALL" --dry-run
  after="$(printf '%s\n' "$output" | grep -A1 'run-opts 11' | tail -1)"
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
