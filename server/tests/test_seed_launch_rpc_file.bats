#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

@test "seed-launch reads the rpc-secret from IRIS_RPC_SECRET_FILE (tmpfs)" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/state/torrents" "$tmp/config" "$tmp/log" "$tmp/images" "$tmp/run"
  echo "tmpfssecret" > "$tmp/run/rpc-secret"
  # an old plaintext on the volume must NOT be used when the env var is set
  echo "stalesecret" > "$tmp/config/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@"\n' > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"

  run env IRIS_STATE="$tmp/state" IRIS_CONFIG="$tmp/config" IRIS_LOG="$tmp/log" \
      IMAGES_DIR="$tmp/images" ARIA2="$tmp/aria2c-stub" \
      IRIS_RPC_SECRET_FILE="$tmp/run/rpc-secret" \
      bash "$BATS_TEST_DIRNAME/../seed-launch.sh"

  [ "$status" -eq 0 ]
  # Use grep for reliable substring matching after run (bats [[ ]] does not
  # enforce failures when -e is disabled by run's set+eET).
  # The secret never appears in the argv (IRIS-13-016); it is written to the
  # 0600 conf file aria2c is pointed at, and the stale on-volume value is
  # not what lands there.
  argv="$output"
  run grep -q -- "--rpc-secret=" <<<"$argv"
  [ "$status" -ne 0 ]
  grep -q -- "--conf-path=$tmp/state/seeder.aria2.conf" <<<"$argv"
  grep -qx "rpc-secret=tmpfssecret" "$tmp/state/seeder.aria2.conf"
  run grep -q "stalesecret" "$tmp/state/seeder.aria2.conf"
  [ "$status" -ne 0 ]
  rm -rf "$tmp"
}
