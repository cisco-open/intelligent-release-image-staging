#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  export DEVICE_IP=100.90.168.99 DEVICE_USER=u DEVICE_PASS=p VLAN=666
  UNINSTALL="$BATS_TEST_DIRNAME/../uninstall.sh"
}

# One assertion per @test (only the LAST command in a bats body sets status).

@test "dry-run exits 0" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "dry-run tears the app down stop -> deactivate -> uninstall" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"app-hosting stop appid iris"* ]] && \
  [[ "$output" == *"app-hosting deactivate appid iris"* ]] && \
  [[ "$output" == *"app-hosting uninstall appid iris"* ]]
}

@test "dry-run removes the app-hosting appid config" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no app-hosting appid iris"* ]]
}

@test "dry-run removes the IRIS VLAN and SVI" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan666"* ]] && [[ "$output" == *"no vlan 666"* ]]
}

@test "dry-run removes any runtime EEM applets (no-op if absent)" {
  # the shared agent may leave IRIS-COPYROOT and the on-demand low-space
  # reclaim applets (IRIS-RECLAIM / IRIS-RECLAIM-BUNDLE) in running-config
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-AGENT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-RECLAIM"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-RECLAIM-BUNDLE"* ]]
}

@test "dry-run removes the PKI trustpoint with its yes confirm" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no ip http client secure-trustpoint IRIS"* ]] && \
  [[ "$output" == *$'no crypto pki trustpoint IRIS\nyes'* ]]
}

@test "dry-run deletes the staged app package" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete flash:iris.tar"* ]]
}

@test "dry-run leaves generic config and the sdflash image in place" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"LEFT IN PLACE"* ]] && \
  [[ "$output" == *"ip scp server"* ]] && \
  [[ "$output" == *"sdflash image"* ]]
}

@test "custom VLAN and PKG_FS flow into the removal" {
  VLAN=42 PKG_FS=sdflash: run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan42"* ]] && \
  [[ "$output" == *"delete sdflash:iris.tar"* ]]
}

@test "real run refuses to start without DEVICE_PASS" {
  unset DEVICE_PASS
  run bash "$UNINSTALL"
  [ "$status" -ne 0 ]
}

@test "real run refuses an empty VLAN instead of guessing 666" {
  VLAN='' run bash "$UNINSTALL"
  [ "$status" -ne 0 ] && [[ "$output" == *"VLAN not set"* ]]
}
