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

@test "inband dry-run emits no VLAN/SVI/AppGig-trunk mutation" {
  NETWORK_ATTACHMENT=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\nvlan '* ]] && \
  [[ "$output" != *"interface Vlan"* ]] && \
  [[ "$output" != *"switchport trunk allowed vlan"* ]] && \
  [[ "$output" != *"ip address 192.0.2"* ]]
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
