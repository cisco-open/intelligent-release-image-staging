#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# pack-agent-bundle.sh is the ONE packer for the Guest Shell agent bundle,
# shared by tools/make-agent-bundle.sh and server/docker-entrypoint.sh so the
# two can never drift. It packs a fixed member list in the exact on-device
# layout.

# Packaging only inspects headers; these fixtures are never executed.
_elf_fixture() {
  python3 - "$1" "$2" <<'PYTHON'
import struct, sys
header = bytearray(64)
header[:7] = b"\x7fELF\x02\x01\x01"
struct.pack_into('<HHI', header, 16, 2, int(sys.argv[2]), 1)
struct.pack_into('<H', header, 52, 64)
with open(sys.argv[1], 'wb') as target:
    target.write(header)
PYTHON
}

setup() {
  PACK="$BATS_TEST_DIRNAME/../pack-agent-bundle.sh"
  DEVICE="$BATS_TEST_DIRNAME/../../device"
  TMP="$(mktemp -d)"
  export IRIS_SSH_KEYGEN="$TMP/ssh-keygen"
  _elf_fixture "$IRIS_SSH_KEYGEN" 62
  printf "license fixture\n" > "$TMP/ssh-keygen.LICENCE"
  export IRIS_AEAD_HELPER="$TMP/iris-aead"
  _elf_fixture "$IRIS_AEAD_HELPER" 62
  printf "license fixture\n" > "$TMP/iris-aead.LICENCE"
  _elf_fixture "$TMP/aria2c" 62
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
  printf '%s\n' "$output" | grep -qx 'agent/ssh-keygen'
  printf '%s\n' "$output" | grep -qx 'agent/ssh-keygen.LICENCE'
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


@test "verifier is packed executable with its matching license" {
  pack
  run tar tzvf "$OUT"
  echo "$output" | grep -E '(-rwx|x).* agent/ssh-keygen$'
  tar xOf "$OUT" agent/ssh-keygen.LICENCE > "$TMP/packed-license"
  cmp "$TMP/ssh-keygen.LICENCE" "$TMP/packed-license"
}

@test "missing or empty verifier fails without replacing prior bundle" {
  for state in missing empty; do
    printf 'prior bundle\n' > "$OUT"
    printf 'prior digest\n' > "$OUT.sha256"
    rm -f "$IRIS_SSH_KEYGEN"
    if [ "$state" = empty ]; then : > "$IRIS_SSH_KEYGEN"; fi
    run pack
    [ "$status" -ne 0 ]
    [[ "$output" == *"missing static verifier"* ]]
    [ "$(cat "$OUT")" = "prior bundle" ]
    [ "$(cat "$OUT.sha256")" = "prior digest" ]
  done
}

@test "missing or empty verifier license fails closed" {
  for state in missing empty; do
    rm -f "$TMP/ssh-keygen.LICENCE"
    if [ "$state" = empty ]; then : > "$TMP/ssh-keygen.LICENCE"; fi
    run pack
    [ "$status" -ne 0 ]
    [[ "$output" == *"missing ssh-keygen.LICENCE"* ]]
    [ ! -e "$OUT" ]
    [ ! -e "$OUT.sha256" ]
  done
}

@test "explicit verifier override cannot bypass architecture validation" {
  _elf_fixture "$IRIS_SSH_KEYGEN" 183
  run pack
  [ "$status" -ne 0 ]
  [[ "$output" == *"verifier architecture does not match aria2c"* ]]
  [ ! -e "$OUT" ]
  # Check the opposite mismatch and the command-line override too.
  _elf_fixture "$TMP/aria2c" 183
  _elf_fixture "$IRIS_SSH_KEYGEN" 62
  run bash "$PACK" "$DEVICE" "$TMP/aria2c" "$OUT" \
      --ssh-keygen "$IRIS_SSH_KEYGEN" --instruction-roots-dir "$ROOTS"
  [ "$status" -ne 0 ]
  [[ "$output" == *"verifier architecture does not match aria2c"* ]]
}

@test "matching ARM binaries are packed without executing on builder" {
  _elf_fixture "$TMP/aria2c" 183
  _elf_fixture "$IRIS_SSH_KEYGEN" 183
  _elf_fixture "$IRIS_AEAD_HELPER" 183
  run pack
  [ "$status" -eq 0 ]
  tar xOf "$OUT" agent/ssh-keygen > "$TMP/packed-verifier"
  cmp "$IRIS_SSH_KEYGEN" "$TMP/packed-verifier"
}

@test "AEAD helper and license are packed executable and byte-exact" {
  pack
  run tar tzvf "$OUT"
  echo "$output" | grep -E '(-rwx|x).* agent/iris-aead$'
  tar xOf "$OUT" agent/iris-aead > "$TMP/packed-aead"
  tar xOf "$OUT" agent/iris-aead.LICENCE > "$TMP/packed-aead-license"
  cmp "$IRIS_AEAD_HELPER" "$TMP/packed-aead"
  cmp "$TMP/iris-aead.LICENCE" "$TMP/packed-aead-license"
}

@test "missing AEAD helper or license cannot replace a prior bundle" {
  printf 'prior bundle\n' > "$OUT"
  printf 'prior digest\n' > "$OUT.sha256"
  rm "$IRIS_AEAD_HELPER"
  run pack
  [ "$status" -ne 0 ]
  [[ "$output" == *"AEAD helper"* ]]
  _elf_fixture "$IRIS_AEAD_HELPER" 62
  rm "$TMP/iris-aead.LICENCE"
  run pack
  [ "$status" -ne 0 ]
  [[ "$output" == *"iris-aead.LICENCE"* ]]
  [ "$(cat "$OUT")" = "prior bundle" ]
  [ "$(cat "$OUT.sha256")" = "prior digest" ]
}

@test "wrong-architecture AEAD helper is rejected before packaging" {
  _elf_fixture "$IRIS_AEAD_HELPER" 183
  run pack
  [ "$status" -ne 0 ]
  [[ "$output" == *"wrong-architecture AEAD helper"* ]]
}

@test "malformed binaries cannot bypass ELF checks through explicit verifier" {
  printf 'not ELF' > "$IRIS_SSH_KEYGEN"
  run pack
  [ "$status" -ne 0 ]
  [[ "$output" == *"unsupported ELF"* ]]
  _elf_fixture "$IRIS_SSH_KEYGEN" 62
  printf 'not ELF' > "$TMP/aria2c"
  run pack
  [ "$status" -ne 0 ]
  [[ "$output" == *"unsupported ELF"* ]]
  [ ! -e "$OUT" ]
}
