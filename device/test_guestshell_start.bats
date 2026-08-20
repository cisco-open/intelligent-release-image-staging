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

@test "an empty baked rpc-secret launches aria2c with the placeholder secret" {
  # Field incident 2026-08-20: every Guest Shell device fell silent after
  # redeploy. The installer bakes rpc-secret EMPTY by design (the agent
  # fetches the real value on its first token-refresh), and Aria2 Next 2.5.6
  # rejects --rpc-secret= outright ("Empty string is not allowed") where
  # aria2 1.37 accepted it. aria2c then never launched, bootstrap aborted
  # before ever running the agent, and the device never sent its first
  # heartbeat. Launch with the same "iris" placeholder the IOx entrypoint
  # uses; bootstrap's secret sync bounces aria2c onto the real secret right
  # after that first refresh.
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  printf '\n' > "$tmp/stage/rpc-secret"   # baked empty (installer default)
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  out="$(cat "$tmp/launched.txt")"
  [[ "$out" == *"--rpc-secret=iris "* ]]
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

@test "an unresponsive aria2c is killed before relaunch (stale-process deadlock)" {
  # 2026-08-20 incident: reaching this point means the RPC probe already
  # FAILED, so any surviving aria2c is not serving. Leaving it alive makes the
  # relaunch useless — it still owns :6800 (new instance cannot bind) and
  # `cp -f` over a running binary fails with ETXTBSY, so the stale build keeps
  # running. Clear it first, then copy and launch.
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home" "$tmp/bin"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  # a stale aria2c IS present; record that the launcher clears it
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/pkill.log"\n' "$tmp" > "$tmp/bin/pkill"
  chmod +x "$tmp/bin/pgrep" "$tmp/bin/pkill"
  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      SKIP_RPC_PROBE=1 bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [ -f "$tmp/pkill.log" ]                      # stale process cleared
  [[ "$(cat "$tmp/pkill.log")" == *"aria2c"* ]]
  [ -f "$tmp/launched.txt" ]                   # and the relaunch still happened
}

@test "a failed binary copy is reported, not silently ignored" {
  # cp/chmod failures were swallowed with `|| true`, so a device could exec a
  # stale binary (or nothing) with no diagnostic anywhere.
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/does-not-exist" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      SKIP_RPC_PROBE=1 bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"aria2c"* ]]
}
