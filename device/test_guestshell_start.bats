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

# ---------------------------------------------------------------------------
# --on-bt-download-complete: the per-peer receipt hook
#
# aria2 execs the option value directly (execlp, no shell), so the value must
# be a real executable FILE. /flash denies chmod, which is why the launcher
# copies the hook to $EXEC_DIR exactly as it does aria2c. The option is
# launch-time only -- OptionHandlerFactory.cc never marks it initial/changeable,
# so an addTorrent option dict would be silently dropped -- which is why these
# assertions live against the launcher and not the agent.
# ---------------------------------------------------------------------------

_gs_fixture() {           # $1 = tmpdir; stages a hook unless $2 = "nohook"
  mkdir -p "$1/stage/agent" "$1/home"
  echo "rpcsecret" > "$1/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\nenv > "%s/env.txt"\n' \
    "$1" "$1" > "$1/aria2c-stub"
  chmod +x "$1/aria2c-stub"
  if [ "${2:-}" != "nohook" ]; then
    printf '#!/bin/sh\nexit 0\n' > "$1/stage/agent/peer-receipt-hook.sh"
  fi
}

@test "a staged hook is wired in as --on-bt-download-complete" {
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [[ "$(cat "$tmp/launched.txt")" == *"--on-bt-download-complete=$tmp/home/iris-peer-receipt-hook"* ]]
}

@test "the hook is installed on an exec-capable fs with the exec bit" {
  # A hook left in the stage dir could never be chmod'd (/flash is
  # SELinux-labeled), and execlp needs the bit -- so the copy is the mechanism,
  # not an optimisation.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [ -x "$tmp/home/iris-peer-receipt-hook" ]
}

@test "no staged hook means NO --on-bt-download-complete flag at all" {
  # Never an empty option value: Aria2 Next rejects those outright ("Empty
  # string is not allowed"), which is exactly how --rpc-secret= stopped aria2c
  # from launching at all in the 2026-08-20 incident. An agent bundle that
  # predates the hook must still launch a daemon.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp" nohook
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [ -f "$tmp/launched.txt" ]
  [[ "$(cat "$tmp/launched.txt")" != *"--on-bt-download-complete"* ]]
}

@test "a hook that cannot be installed is reported but never blocks the launch" {
  # Telemetry must not be able to silence a device. Without the hook the report
  # simply omits the receipts ("not measured") and the transfer is unaffected.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  # an undeliverable destination: the copy fails, nothing else does
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      HOOK_DST="$tmp/no-such-dir/iris-peer-receipt-hook" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"peer-receipt hook"* ]]
  [ -f "$tmp/launched.txt" ]
  [[ "$(cat "$tmp/launched.txt")" != *"--on-bt-download-complete"* ]]
}

@test "a refreshed hook is installed even when aria2c is already serving" {
  # Dropping a new bundle.tgz IS the agent upgrade path, and a serving aria2c
  # is deliberately NOT relaunched -- so the install must sit ABOVE the
  # 'already up?' early exit or an upgraded hook could never reach the path the
  # running daemon already holds.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  printf '#!/bin/sh\n# v2\nexit 0\n' > "$tmp/stage/agent/peer-receipt-hook.sh"
  mkdir -p "$tmp/bin"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/curl"     # RPC answers: already up
  chmod +x "$tmp/bin/curl"
  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already up"* ]]        # took the early exit
  [ ! -f "$tmp/launched.txt" ]             # and did NOT relaunch aria2c
  grep -q "v2" "$tmp/home/iris-peer-receipt-hook"
}

@test "the hook inherits the secret the daemon is actually launched with" {
  # Never re-read from the rpc-secret FILE: the file and the running daemon can
  # disagree, and that skew is the 2026-08-20 incident. Inheritance through
  # aria2c's fork is the only channel that cannot drift.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 RPC_PORT=6899 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  grep -qx "IRIS_RPC_SECRET=rpcsecret" "$tmp/env.txt"
  grep -qx "IRIS_RPC_PORT=6899" "$tmp/env.txt"
  [[ "$(cat "$tmp/launched.txt")" == *"--rpc-secret=rpcsecret"* ]]
}

@test "an empty baked secret exports the same placeholder aria2c is launched with" {
  # The empty file legitimately means the daemon is on the "iris" placeholder;
  # the hook must be told that, not left to guess from the file.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  printf '\n' > "$tmp/stage/rpc-secret"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  grep -qx "IRIS_RPC_SECRET=iris" "$tmp/env.txt"
}
