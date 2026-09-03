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

@test "a failed aria2c launch is recorded but does NOT block the agent" {
  # Sibling of the 2026-08-20 incident class: bootstrap used to `exit 1` when
  # guestshell-start.sh failed, so the agent (step 5) never ran and the device
  # never heartbeated — an aria2c LAUNCH regression (e.g. the empty rpc-secret
  # bug) was indistinguishable from a dead device. The agent is the device's
  # only line back to the catalog: it must run even when the swarm daemon is
  # down, and report the breakage instead of vanishing.
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  # the failure is surfaced and recorded for forensics...
  [[ "$output" == *"failed to launch aria2c"* ]]
  [ -f "$STAGE/aria2c-launch-failed" ]
  # ...but the agent STILL ran, so the device still heartbeats
  [ -f "$TMP/agent-invoked" ]
}

@test "a failed log rotation warns but does NOT block the agent" {
  # Rotation is ancillary maintenance. A permissions/mktemp/filesystem error
  # in step 4 must not exit before step 5 — the agent is the device's only
  # path back to the catalog, so a fatal rotation error would permanently
  # silence the device on every EEM tick (same class as the aria2c-launch
  # failure above).
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$STAGE/rotate-logs.sh"
  chmod +x "$STAGE/rotate-logs.sh"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"log rotation failed"* ]]
  [ -f "$TMP/agent-invoked" ]
}

@test "a healthy aria2c launch clears a stale launch-failure marker" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  printf 'stale\n' > "$STAGE/aria2c-launch-failed"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ ! -f "$STAGE/aria2c-launch-failed" ]
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

@test "a bundle upgrade replaces bootstrap.sh by rename so the running tick still reaches the agent" {
  # bootstrap.sh runs FROM $SRC/bootstrap.sh (the EEM applet's path) and, on
  # a bundle drop, replaces that very file. `cp -f` rewrote the same inode,
  # so the bash still executing it resumed at its old byte offset inside the
  # NEW content -- executing whatever token landed there. The upgrade tick
  # must finish on the OLD script's logic (step 5 runs the agent) and leave
  # the new bootstrap in place for the next tick. The bundled replacement
  # here is pure `exit 99` lines, so an in-place overwrite fails loudly.
  cp "$BATS_TEST_DIRNAME/bootstrap.sh" "$SRC/bootstrap.sh"
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  BUNDLE="$TMP/bundle-src"; mkdir -p "$BUNDLE/agent"
  { printf '#!/usr/bin/env bash\n'
    for _ in $(seq 1 400); do printf 'exit 99 # upgraded-bootstrap padding line\n'; done
  } > "$BUNDLE/bootstrap.sh"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$BUNDLE/agent/iris_agent.py"
  tar czf "$SRC/bundle.tgz" -C "$BUNDLE" bootstrap.sh agent
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$SRC/bootstrap.sh"
  [ "$status" -eq 0 ]
  # the tick that performed the upgrade still ran the agent...
  [ -f "$TMP/agent-invoked" ]
  # ...and the next tick will read the bundled bootstrap
  cmp -s "$SRC/bootstrap.sh" "$BUNDLE/bootstrap.sh"
  [ ! -e "$SRC/bootstrap.sh.new" ]
}
