#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

@test "seed-launch builds the expected aria2c command line" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/state/torrents" "$tmp/config" "$tmp/log" "$tmp/images"
  echo "secretval" > "$tmp/config/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@"\n' > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"

  run env IRIS_STATE="$tmp/state" IRIS_CONFIG="$tmp/config" IRIS_LOG="$tmp/log" \
      IMAGES_DIR="$tmp/images" ARIA2="$tmp/aria2c-stub" \
      bash "$BATS_TEST_DIRNAME/../seed-launch.sh"

  [ "$status" -eq 0 ]
  [[ "$output" == *"--enable-rpc=true"* ]]
  [[ "$output" == *"--rpc-secret=secretval"* ]]
  [[ "$output" == *"--enable-dht=false"* ]]
  [[ "$output" == *"--enable-peer-exchange=false"* ]]
  [[ "$output" == *"--seed-ratio=0.0"* ]]
  [[ "$output" == *"--dir=$tmp/images"* ]]
}

@test "seed-launch exits non-zero with an error when the rpc-secret file is missing" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/state/torrents" "$tmp/config" "$tmp/log" "$tmp/images"
  # NO rpc-secret file written — the file is absent
  printf '#!/usr/bin/env bash\necho "$@"\n' > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"

  run env IRIS_STATE="$tmp/state" IRIS_CONFIG="$tmp/config" IRIS_LOG="$tmp/log" \
      IMAGES_DIR="$tmp/images" ARIA2="$tmp/aria2c-stub" \
      bash "$BATS_TEST_DIRNAME/../seed-launch.sh"

  [ "$status" -ne 0 ]
  [[ "$output" == *"FATAL"* ]] || [[ "$output" == *"rpc-secret"* ]]
  rm -rf "$tmp"
}

@test "seed-launch exits non-zero with an error when the rpc-secret file is empty" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/state/torrents" "$tmp/config" "$tmp/log" "$tmp/images"
  # Empty rpc-secret file
  printf '' > "$tmp/config/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@"\n' > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"

  run env IRIS_STATE="$tmp/state" IRIS_CONFIG="$tmp/config" IRIS_LOG="$tmp/log" \
      IMAGES_DIR="$tmp/images" ARIA2="$tmp/aria2c-stub" \
      bash "$BATS_TEST_DIRNAME/../seed-launch.sh"

  [ "$status" -ne 0 ]
  [[ "$output" == *"FATAL"* ]] || [[ "$output" == *"rpc-secret"* ]]
  rm -rf "$tmp"
}

@test "seed-launch seeds an image in a model subdir with the correct per-torrent dir" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/state/torrents" "$tmp/config" "$tmp/log" "$tmp/images/IE3400" "$tmp/run"
  echo "secretval" > "$tmp/config/rpc-secret"
  : > "$tmp/state/torrents/ie3x00-universalk9.17.18.03.torrent"
  printf '{"images":{"ie3x00-universalk9.17.18.03":{"filename":"ie3x00.bin"}}}' > "$tmp/state/catalog.json"
  : > "$tmp/images/IE3400/ie3x00.bin"
  printf '#!/usr/bin/env bash\necho "$@"\n' > "$tmp/aria2c-stub"; chmod +x "$tmp/aria2c-stub"

  run env IRIS_STATE="$tmp/state" IRIS_CONFIG="$tmp/config" IRIS_LOG="$tmp/log" \
      IRIS_RUN="$tmp/run" IMAGES_DIR="$tmp/images/iosxe/c9300" IMAGES_ROOT="$tmp/images" \
      ARIA2="$tmp/aria2c-stub" \
      bash "$BATS_TEST_DIRNAME/../seed-launch.sh"

  [ "$status" -eq 0 ]
  # the seeder is driven by a generated per-torrent input file...
  echo "$output" | grep -q -- "--input-file=$tmp/run/seeder.input"
  # ...which pairs the IE torrent with its ACTUAL image dir (the model subdir),
  # not the global --dir (which would error "Failed to open file").
  grep -q -- "$tmp/state/torrents/ie3x00-universalk9.17.18.03.torrent" "$tmp/run/seeder.input"
  grep -q -- "dir=$tmp/images/IE3400" "$tmp/run/seeder.input"
  rm -rf "$tmp"
}
