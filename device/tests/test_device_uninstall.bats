#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  export DEVICE_IP=100.92.9.3 DEVICE_USER=u DEVICE_PASS=p VLAN=666
  UNINSTALL="$BATS_TEST_DIRNAME/../device-uninstall.sh"
}

# One assertion per @test (same rationale as test_device_install.bats: only
# the LAST command in a bats body sets the exit code).

@test "dry-run exits 0" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "dry-run removes both EEM applets" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no event manager applet IRIS-AGENT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]]
}

@test "dry-run also removes the on-demand reclaim applets" {
  # the agent creates IRIS-RECLAIM / IRIS-RECLAIM-BUNDLE under disk pressure
  # and never self-removes them — undeploy must clear them too
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no event manager applet IRIS-RECLAIM"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-RECLAIM-BUNDLE"* ]]
}

@test "dry-run removes the applets BEFORE the guestshell teardown" {
  run bash "$UNINSTALL" --dry-run
  applets_at="${output%%no event manager applet IRIS-AGENT*}"
  destroy_at="${output%%guestshell destroy*}"
  [ "${#applets_at}" -lt "${#destroy_at}" ]
}

@test "dry-run removes vlan and SVI" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan666"* ]] && [[ "$output" == *"no vlan 666"* ]]
}

@test "dry-run detaches IRISQ with EXPLICIT-name no-forms" {
  # bare 'no logging buffered discriminator' is rejected by IOS with
  # '% Incomplete command' — hardware-learned 2026-07-04
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no logging buffered discriminator IRISQ"* ]] && \
  [[ "$output" == *"no logging console discriminator IRISQ"* ]] && \
  [[ "$output" == *"no logging monitor discriminator IRISQ"* ]] && \
  [[ "$output" == *"no logging discriminator IRISQ"* ]]
}

@test "dry-run removes the PKI trustpoint (with its yes confirm) and http client binding" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no ip http client secure-trustpoint IRIS"* ]] && \
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]] && \
  [[ "$output" == *$'no crypto pki trustpoint IRIS\nyes'* ]]
}

@test "dry-run deletes guest-share" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete /force /recursive flash:guest-share"* ]]
}

@test "dry-run documents what is deliberately left in place" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"LEFT IN PLACE"* ]] && [[ "$output" == *"iox"* ]]
}

@test "dry-run persists successful Guest Shell cleanup" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"copy running-config startup-config"* ]]
}

@test "custom VLAN flows into the removal lines" {
  VLAN=42 run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan42"* ]] && [[ "$output" == *"no vlan 42"* ]]
}

@test "real run refuses to start without DEVICE_PASS" {
  unset DEVICE_PASS
  run bash "$UNINSTALL"
  [ "$status" -ne 0 ]
}

@test "real run refuses an empty VLAN instead of guessing 666" {
  # OnboardService exports VLAN='' when the fleet row has no vlan; tearing
  # down a guessed 666 could hit the wrong SVI and then falsely verify clean
  VLAN='' run bash "$UNINSTALL"
  [ "$status" -ne 0 ] && [[ "$output" == *"VLAN not set"* ]]
}
