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
  ROOTS="$TMP/roots.d"; mkdir "$ROOTS"
  for name in root-b root-a; do
    ssh-keygen -q -t ed25519 -N '' -C test-only -f "$TMP/$name"
    cp "$TMP/$name.pub" "$ROOTS/$name.pub"
  done
}
teardown() { rm -rf "$TMP"; }

pack() {
  bash "$PACK" "$DEVICE" "$TMP/aria2c" "$OUT" \
    --instruction-roots-dir "$ROOTS"
}

@test "packs a bundle from the device sources + aria2c" {
  run pack
  [ "$status" -eq 0 ]
  [ -f "$OUT" ]
  [ -f "$OUT.sha256" ]
  [ "$(wc -c < "$OUT.sha256" | tr -d ' ')" -eq 65 ]
  [ "$(cat "$OUT.sha256")" = "$(sha256sum "$OUT" | awk '{print $1}')" ]
}

@test "bundle has the exact member list the device expects (no './' top entry)" {
  pack
  run tar tzf "$OUT"
  printf '%s\n' "$output" | grep -qx 'iris-signers.allowed_signers'
  printf '%s\n' "$output" | grep -qx 'iris-root.allowed_signers'
  [ "$(printf '%s\n' "$output" | grep -c '^iris-.*allowed_signers$')" -eq 2 ]
  printf '%s\n' "$output" | grep -qx 'bootstrap.sh'
  printf '%s\n' "$output" | grep -qx 'guestshell-start.sh'
  printf '%s\n' "$output" | grep -qx 'rotate-logs.sh'
  printf '%s\n' "$output" | grep -qx 'aria2c'
  printf '%s\n' "$output" | grep -qx 'agent/iris_agent.py'
  printf '%s\n' "$output" | grep -qx 'agent/verify_image.py'
  # NO './' top-dir entry (guest-share denies chmod/utime on it)
  ! grep -qE '^\./$' <<< "$output"
}

@test "aria2c is packed executable" {
  pack
  run tar tzvf "$OUT"
  # the aria2c line carries an executable bit
  echo "$output" | grep -E '(-rwx|x).* aria2c$'
}

@test "fails clearly when a required arg is missing" {
  run bash "$PACK" "$DEVICE" "$TMP/aria2c"
  [ "$status" -ne 0 ]
}

@test "fails closed without exactly two real roots and preserves prior output" {
  printf 'prior bundle\n' > "$OUT"
  printf '%064d\n' 0 > "$OUT.sha256"
  rm "$ROOTS/root-b.pub"
  run pack
  [ "$status" -ne 0 ]
  [ "$(cat "$OUT")" = "prior bundle" ]
  [ "$(cat "$OUT.sha256")" = "$(printf '%064d' 0)" ]
}
