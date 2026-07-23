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
