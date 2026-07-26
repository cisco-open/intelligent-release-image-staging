#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

@test "guestshell-start builds an RPC aria2c daemon with private-swarm flags" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  # RPC probe skipped so the launcher proceeds to launch the stub
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  out="$(cat "$tmp/launched.txt")"
  [[ "$out" == *"--enable-rpc=true"* ]]
  [[ "$out" == *"--rpc-secret=rpcsecret"* ]]
  [[ "$out" == *"--enable-dht=false"* ]]
  [[ "$out" == *"--bt-seed-unverified=true"* ]]
  [[ "$out" == *"--bt-max-peers=10"* ]]
  [[ "$out" == *"--dir=$tmp/stage"* ]]
  [[ "$out" != *"--listen-port="* ]]
}

@test "guestshell-start pins the BitTorrent port only when requested" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 BT_LISTEN_PORT=6881 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [[ "$(cat "$tmp/launched.txt")" == *"--listen-port=6881"* ]]
}
