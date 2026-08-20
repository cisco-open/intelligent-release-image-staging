#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  INSTALL="$BATS_TEST_DIRNAME/../router-install.sh"
  export MODEL=C8000V DEVICE_IP=192.0.2.10 DEVICE_ID=router-1 \
    CATALOG_URL=https://192.0.2.20:8443 CATALOG_TOKEN=deadbeef \
    STAGE_HOST=192.0.2.20 NETWORK_ATTACHMENT=router-routed VPG_NUMBER=10 \
    APP_IP=10.8.0.2 APP_MASK=255.255.255.252 APP_GATEWAY=10.8.0.1
}

@test "router-routed renders a VPG Guest Shell attachment" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"interface VirtualPortGroup10"* ]]
  [[ "$output" == *"ip address 10.8.0.1 255.255.255.252"* ]]
  [[ "$output" == *"app-vnic gateway0 virtualportgroup 10 guest-interface 0"* ]]
  [[ "$output" == *"guest-ipaddress 10.8.0.2 netmask 255.255.255.252"* ]]
}

@test "router-routed emits no NAT configuration" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"ip nat inside"* ]]
  [[ "$output" != *"IRIS-NAT-"* ]]
}

@test "router-nat renders overload and deterministic inbound swarm PAT" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"interface GigabitEthernet1"* ]]
  [[ "$output" == *"ip nat outside"* ]]
  [[ "$output" == *"ip access-list standard IRIS-NAT-10"* ]]
  [[ "$output" == *"permit 10.8.0.0 0.0.0.3"* ]]
  [[ "$output" == *"ip nat inside source list IRIS-NAT-10 interface GigabitEthernet1 overload"* ]]
  [[ "$output" == *"ip nat inside source static tcp 10.8.0.2 6881 interface GigabitEthernet1 6881"* ]]
  [[ "$output" == *"BT_LISTEN_PORT=6881"* ]]
}

@test "router renderer never emits switch network primitives" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  ! grep -Eq '(^|[[:space:]])vlan [0-9]|interface Vlan|switchport|ip router isis|vrf definition|AppGigabitEthernet' <<<"$output"
}

@test "router config and copies use bootflash explicitly" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"stage_dir = /bootflash/guest-share/iris"* ]]
  [[ "$output" == *"target_fs = bootflash:"* ]]
  [[ "$output" == *"catalog_ca = /bootflash/guest-share/iris/iris-catalog.pem"* ]]
  [[ "$output" == *"bootflash:guest-share/bootstrap.sh"* ]]
  [[ "$output" != *"target_fs = flash:"* ]]
}

@test "router dry-run uses one capability for both credential filenames" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  conf_cap="$(printf '%s\n' "$output" | sed -nE 's#.*staging/iris-agent-router-1-([0-9a-f]{32})\.conf.*#\1#p' | head -1)"
  rpc_cap="$(printf '%s\n' "$output" | sed -nE 's#.*staging/rpc-secret-([0-9a-f]{32}).*#\1#p' | head -1)"
  [ -n "$conf_cap" ]
  [ "$conf_cap" = "$rpc_cap" ]
}

@test "router installer refuses a non-Catalyst-8000 model" {
  MODEL=ISR4451 run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"Catalyst 8000-family models only"* ]]
}

@test "router installer rejects a non-contiguous mask" {
  APP_MASK=255.0.255.0 run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid APP_IP, APP_MASK, or APP_GATEWAY"* ]]
}

@test "router installer rejects a gateway outside the app subnet" {
  APP_GATEWAY=10.9.0.1 run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"must differ and share a subnet"* ]]
}

@test "real router install structurally live-checks model and processor-board identity" {
  grep -qF 'EXPECTED_DEVICE_IDENTITY' "$INSTALL"
  grep -qF 'rocessor board ID' "$INSTALL"
  grep -qF 'device identity mismatch' "$INSTALL"
}

@test "real router install has a post-apply readback gate before persistence" {
  grep -qF 'verify applied config and persist' "$INSTALL"
  grep -qF 'show running-config' "$INSTALL"
  grep -qF 'config_block "VirtualPortGroup$VPG_NUMBER"' "$INSTALL"
  grep -qF 'router configuration is incomplete' "$INSTALL"
}

@test "re-onboard destroys a pre-existing guestshell before applying config" {
  # 2026-08-20 incident (iris8kv-1/-2): a re-onboard over a guestshell that was
  # already RUNNING left it on its OLD networking — step [4/7] saw RUNNING and
  # never re-enabled, so the freshly applied app-hosting gateway never reached
  # the guest and the agent had no egress. The installer must destroy any
  # pre-existing guestshell BEFORE applying config so enable always builds the
  # guest from the current networking.
  run grep -n 'guestshell destroy' "$INSTALL"
  [ "$status" -eq 0 ]
  destroy_line="$(grep -n 'guestshell destroy' "$INSTALL" | head -1 | cut -d: -f1)"
  config_line="$(grep -n '^echo "\[3/7\] apply IOS config' "$INSTALL" | head -1 | cut -d: -f1)"
  enable_line="$(grep -n '^echo "\[4/7\] guestshell enable' "$INSTALL" | head -1 | cut -d: -f1)"
  [ -n "$destroy_line" ] && [ -n "$config_line" ] && [ -n "$enable_line" ]
  [ "$destroy_line" -lt "$config_line" ]
  [ "$config_line" -lt "$enable_line" ]
  # the destroy must wait for the guest to actually be gone, not fire-and-forget
  run grep -A8 'guestshell destroy' "$INSTALL"
  [[ "$output" == *"DESTROYED"* || "$output" == *"still present"* ]]
}
