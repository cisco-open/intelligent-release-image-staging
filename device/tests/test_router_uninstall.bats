#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  UNINSTALL="$BATS_TEST_DIRNAME/../router-uninstall.sh"
  export MODEL=C8000V NETWORK_ATTACHMENT=router-routed VPG_NUMBER=10 \
    APP_IP=10.8.0.2
}

@test "router-routed teardown removes only the VPG app footprint" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no interface VirtualPortGroup10"* ]]
  [[ "$output" == *"no app-hosting appid guestshell"* ]]
  [[ "$output" == *"delete /force /recursive bootflash:guest-share/iris"* ]]
  [[ "$output" == *"delete /force bootflash:guest-share/bootstrap.sh"* ]]
  [[ "$output" != *"delete /force /recursive bootflash:guest-share"$'\n'* ]]
  [[ "$output" != *"IRIS-NAT-"* ]]
}

@test "router NAT teardown removes receipt-owned NAT rules" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no ip nat inside source static tcp 10.8.0.2 6881 interface GigabitEthernet1 6881"* ]]
  [[ "$output" == *"no ip nat inside source list IRIS-NAT-10 interface GigabitEthernet1 overload"* ]]
  [[ "$output" == *"no ip access-list standard IRIS-NAT-10"* ]]
}

@test "NAT teardown clears only receipt-owned translations before the mapping" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"clear ip nat translation inside <IRIS-inside-global> 10.8.0.2 forced"* ]]
  [[ "$output" != *"clear ip nat translation *"* ]]
  # IOS refuses the overload no-form while translations reference the mapping;
  # targeted clearing must happen before the rule and its ACL are removed.
  clear_at="${output%%clear ip nat translation inside*}"
  rule_at="${output%%no ip nat inside source list*}"
  [ "${#clear_at}" -lt "${#rule_at}" ]
}

@test "router teardown never contains a device-wide NAT clear" {
  ! grep -qF 'clear ip nat translation *' "$UNINSTALL"
}

@test "routed teardown does not flush NAT translations" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"clear ip nat translation"* ]]
}

@test "pre-existing outside marking is preserved" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 NAT_OUTSIDE_OWNED=0 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"no ip nat outside"* ]]
}

@test "IRIS-created outside marking is removed" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 NAT_OUTSIDE_OWNED=1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"interface GigabitEthernet1"* ]]
  [[ "$output" == *"no ip nat outside"* ]]
}

@test "router teardown never emits switch network primitives" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 NAT_OUTSIDE_OWNED=1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  ! grep -Eq '(^|[[:space:]])vlan [0-9]|interface Vlan|switchport|ip router isis|vrf definition|AppGigabitEthernet' <<<"$output"
}

@test "router uninstaller refuses a non-Catalyst-8000 model" {
  MODEL=ISR4451 run bash "$UNINSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"Catalyst 8000-family models only"* ]]
}

@test "real router undeploy without credentials fails through the friendly guard" {
  # A real run must hit the DEVICE_IP guard before anything dereferences it,
  # so the operator sees the guard message rather than a raw set -u abort.
  run env -u DEVICE_IP -u DEVICE_USER -u DEVICE_PASS bash "$UNINSTALL"
  [ "$status" -ne 0 ]
  [[ "$output" == *"set DEVICE_IP"* ]]
  [[ "$output" != *"unbound variable"* ]]
}

@test "real router undeploy requires receipt ownership and processor-board identity" {
  grep -qF 'ROUTER_RESOURCES_OWNED' "$UNINSTALL"
  grep -qF 'EXPECTED_DEVICE_IDENTITY' "$UNINSTALL"
  grep -qF 'rocessor board ID' "$UNINSTALL"
  grep -qF 'device identity mismatch' "$UNINSTALL"
}

@test "real router undeploy verifies every removable resource before success" {
  grep -qF 'show running-config' "$UNINSTALL"
  grep -qF 'ip nat inside source static tcp' "$UNINSTALL"
  grep -qF 'logging discriminator IRISQ' "$UNINSTALL"
  grep -qF 'crypto pki trustpoint IRIS' "$UNINSTALL"
  grep -qF 'artifacts still present after undeploy' "$UNINSTALL"
}
