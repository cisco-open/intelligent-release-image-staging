#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# pack-agent-bundle.sh is the ONE packer for the Guest Shell agent bundle,
# shared by tools/make-agent-bundle.sh and server/docker-entrypoint.sh so the
# two can never drift. It packs a fixed member list in the exact on-device
# layout.

setup() {
  PACK="$BATS_TEST_DIRNAME/../pack-agent-bundle.sh"
  DEVICE="$BATS_TEST_DIRNAME/../../device"
  TMP="$(mktemp -d)"
  printf '#!/bin/sh\necho fake-aria2c\n' > "$TMP/aria2c"; chmod +x "$TMP/aria2c"
  OUT="$TMP/iris-agent.tgz"
}
teardown() { rm -rf "$TMP"; }

@test "packs a bundle from the device sources + aria2c" {
  run bash "$PACK" "$DEVICE" "$TMP/aria2c" "$OUT"
  [ "$status" -eq 0 ]
  [ -f "$OUT" ]
}

@test "bundle has the exact member list the device expects (no './' top entry)" {
  bash "$PACK" "$DEVICE" "$TMP/aria2c" "$OUT"
  run tar tzf "$OUT"
  # top-level members
  [[ "$output" == *"bootstrap.sh"* ]]
  [[ "$output" == *"guestshell-start.sh"* ]]
  [[ "$output" == *"rotate-logs.sh"* ]]
  [[ "$output" == *"aria2c"* ]]
  [[ "$output" == *"agent/iris_agent.py"* ]]
  [[ "$output" == *"agent/verify_image.py"* ]]
  # NO './' top-dir entry (guest-share denies chmod/utime on it)
  ! grep -qE '^\./$' <<< "$output"
}

@test "aria2c is packed executable" {
  bash "$PACK" "$DEVICE" "$TMP/aria2c" "$OUT"
  run tar tzvf "$OUT"
  # the aria2c line carries an executable bit
  echo "$output" | grep -E '(-rwx|x).* aria2c$'
}

@test "fails clearly when a required arg is missing" {
  run bash "$PACK" "$DEVICE" "$TMP/aria2c"
  [ "$status" -ne 0 ]
}
