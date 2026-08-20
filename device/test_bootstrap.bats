#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# bootstrap.sh must reconcile aria2c's RPC secret with the one the agent fetched
# on its first token-refresh. The installer bakes rpc-secret EMPTY; the agent
# writes the real value into iris-agent.conf. If bootstrap does not sync the
# rpc-secret file from the conf (and bounce a stale aria2c), aria2c runs with the
# wrong secret and the agent's addTorrent fails — the device never downloads.

setup() {
  TMP="$(mktemp -d)"
  SRC="$TMP/guest-share"; STAGE="$SRC/iris"
  mkdir -p "$STAGE"
  # stub guestshell-start so bootstrap never launches a real aria2c
  printf '#!/usr/bin/env bash\necho started >> "%s/gss.log"\n' "$TMP" > "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  # stub pgrep (aria2c "not running") + pkill (record the bounce) on PATH
  BIN="$TMP/bin"; mkdir -p "$BIN"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$BIN/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/pkill.log"\n' "$TMP" > "$BIN/pkill"
  chmod +x "$BIN/pgrep" "$BIN/pkill"
}

teardown() { rm -rf "$TMP"; }

@test "bootstrap syncs rpc-secret from conf and bounces aria2c when it changed" {
  printf 'rpc_secret = REALSECRET123\nrpc_port = 6800\n' > "$STAGE/iris-agent.conf"
  printf '\n' > "$STAGE/rpc-secret"   # baked empty
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  # the file aria2c reads now holds the agent's real secret
  [ "$(tr -d '[:space:]' < "$STAGE/rpc-secret")" = "REALSECRET123" ]
  # aria2c was bounced so it relaunches with the new secret
  [ -f "$TMP/pkill.log" ]
}

@test "bootstrap does NOT bounce aria2c when rpc-secret already matches the conf" {
  printf 'rpc_secret = REALSECRET123\n' > "$STAGE/iris-agent.conf"
  printf 'REALSECRET123\n' > "$STAGE/rpc-secret"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ ! -f "$TMP/pkill.log" ]
}

@test "a live-but-unresponsive aria2c is relaunched, not skipped" {
  # 2026-08-20 incident (iris8kv-2/-3/-4 + C9300 .129, ~42min silent): step 3
  # gated the launch on `pgrep aria2c` — process EXISTENCE, not RPC HEALTH. An
  # aria2c that is alive but not serving RPC therefore blocked its own
  # relaunch forever: the agent hit ECONNREFUSED on 127.0.0.1:6800 every tick,
  # crashed before its first heartbeat, and the device never appeared. It only
  # recovered when the stale process happened to die. guestshell-start.sh is
  # ALREADY idempotent (it probes the RPC and exits 0 when healthy), so
  # bootstrap must delegate to it unconditionally.
  printf 'rpc_secret = SAME\nrpc_port = 6800\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"      # in sync: no bounce path taken
  # pgrep SUCCEEDS: a process is alive (the deadlock precondition)
  printf '#!/usr/bin/env bash\nexit 0\n' > "$BIN/pgrep"
  chmod +x "$BIN/pgrep"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  # the launcher MUST still have been consulted despite the live process
  [ -f "$TMP/gss.log" ]
}
