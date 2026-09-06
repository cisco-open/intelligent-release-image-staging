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
  cp "$BATS_TEST_DIRNAME/../server/certs/cisco_bulkhash_verify.pem" \
    "$STAGE/iris-catalog.pem"
  # stub guestshell-start so bootstrap never launches a real aria2c
  printf '#!/usr/bin/env bash\necho started >> "%s/gss.log"\n' "$TMP" > "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  # stub pgrep (aria2c "not running") + pkill (record the bounce) on PATH
  BIN="$TMP/bin"; mkdir -p "$BIN"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$BIN/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/pkill.log"\n' "$TMP" > "$BIN/pkill"
  chmod +x "$BIN/pgrep" "$BIN/pkill"
  # tests above this line are not about cadence jitter/backoff (issue #59):
  # keep them fast and deterministic by disabling the pre-agent jitter sleep.
  # The jitter/backoff tests below override this explicitly.
  export IRIS_TICK_JITTER_MAX=0
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

# ---------------------------------------------------------------------------
# Persisted aria2c launch overrides from iris-agent.conf (issue #122):
# guestshell-start.sh only reads its own live process environment, refreshed
# on each 60s EEM tick, so an operator has no way to make IRIS_LOG (or
# RPC_PORT/MAX_PEERS, which had the identical gap) stick without this. These
# tests run the REAL guestshell-start.sh (not a stub) against a stub aria2c
# so the launch line it actually builds can be inspected end to end.
# ---------------------------------------------------------------------------

@test "bootstrap propagates iris_log=on from iris-agent.conf to aria2c's real launch line" {
  printf 'rpc_secret = SAME\niris_log = on\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$(cat "$TMP/launched.txt")" == *"--log=$STAGE/aria2c.log"* ]]
}

@test "bootstrap leaves aria2c's default OFF logging alone when iris-agent.conf has no iris_log key" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$(cat "$TMP/launched.txt")" != *"--log="* ]]
}

@test "bootstrap rejects a hostile iris_log value instead of exporting it, and stays off" {
  # The value rides straight from the conf file into an exported env var,
  # never through eval/exec, so there is no shell-injection path regardless
  # -- but this proves it two ways: the shell metacharacters in the value
  # never run (no $TMP/pwned file appears), and the malformed value is
  # rejected rather than silently coerced to "on".
  printf 'rpc_secret = SAME\niris_log = on; touch %s/pwned #\n' "$TMP" \
    > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"ignoring invalid iris_log"* ]]
  [ ! -f "$TMP/pwned" ]
  [[ "$(cat "$TMP/launched.txt")" != *"--log="* ]]
}

@test "bootstrap propagates rpc_port and max_peers from iris-agent.conf to aria2c's real launch line" {
  printf 'rpc_secret = SAME\nrpc_port = 6900\nmax_peers = 25\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  out="$(cat "$TMP/launched.txt")"
  [[ "$out" == *"--rpc-listen-port=6900"* ]]
  [[ "$out" == *"--bt-max-peers=25"* ]]
}

@test "bootstrap ignores an invalid rpc_port/max_peers in iris-agent.conf and keeps the builtin defaults" {
  printf 'rpc_secret = SAME\nrpc_port = not-a-port\nmax_peers = 999999\n' \
    > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"ignoring invalid rpc_port"* ]]
  [[ "$output" == *"ignoring out-of-range max_peers"* ]]
  out="$(cat "$TMP/launched.txt")"
  [[ "$out" == *"--rpc-listen-port=6800"* ]]   # builtin default, unchanged
  [[ "$out" == *"--bt-max-peers=10"* ]]        # builtin default, unchanged
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

# ---------------------------------------------------------------------------
# Cadence jitter + failure backoff (issue #59)
#
# The EEM watchdog fires this script on IOS's own fixed 60s clock, so a fleet
# installed or reloaded together keeps every device's timer in the same
# phase indefinitely -- amplifying every tick into a fleet-wide burst of
# policy GETs, heartbeats, and tracker re-announces. bootstrap.sh (a) sleeps
# a small per-device jitter before the actual catalog contact, and (b) skips
# that contact for a while after the agent fails outright, easing off an
# overloaded or unreachable server without the EEM timer's own cadence
# changing (steps 0-4, local upkeep, still run every tick).
# ---------------------------------------------------------------------------

@test "bootstrap sleeps a bounded per-tick jitter before invoking the agent" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  # record the jitter sleep's argument instead of actually waiting
  printf '#!/usr/bin/env bash\necho "$1" >> "%s/sleep.log"\n' "$TMP" > "$BIN/sleep"
  chmod +x "$BIN/sleep"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=8 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/agent-invoked" ]
  [ -f "$TMP/sleep.log" ]
  jitter="$(cat "$TMP/sleep.log")"
  [ "$jitter" -ge 0 ] && [ "$jitter" -lt 8 ]
}

@test "IRIS_TICK_JITTER_MAX=0 skips the jitter sleep entirely" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  printf '#!/usr/bin/env bash\necho "$1" >> "%s/sleep.log"\n' "$TMP" > "$BIN/sleep"
  chmod +x "$BIN/sleep"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=0 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/agent-invoked" ]
  [ ! -f "$TMP/sleep.log" ]
}

@test "a failed agent tick opens a backoff window that skips the NEXT tick's catalog contact" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  mkdir -p "$STAGE/agent"
  # counts real invocations, then always fails -- like an unreachable/overloaded catalog
  printf 'import sys\nwith open(r"%s/agent-invocations", "a") as f: f.write("x")\nsys.exit(1)\n' \
    "$TMP" > "$STAGE/agent/iris_agent.py"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=0 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 1 ]
  [ "$(wc -c < "$TMP/agent-invocations")" -eq 1 ]
  [ -f "$STAGE/.iris-tick-backoff" ]
  read -r skip_until streak < "$STAGE/.iris-tick-backoff"
  [ "$streak" -eq 1 ]
  [ "$skip_until" -gt "$(date +%s)" ]

  # the NEXT tick (EEM fires again 60s later, well inside the backoff window)
  # must skip catalog contact -- no second agent invocation -- and say so.
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=0 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"backing off catalog contact"* ]]
  [ "$(wc -c < "$TMP/agent-invocations")" -eq 1 ]
}

@test "a successful agent tick clears a stale backoff window" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  # a backoff window that already expired, from a streak of 3 prior failures
  printf '%s %s\n' "$(( $(date +%s) - 5 ))" 3 > "$STAGE/.iris-tick-backoff"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=0 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/agent-invoked" ]
  [ ! -f "$STAGE/.iris-tick-backoff" ]
}
