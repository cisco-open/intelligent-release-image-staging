#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Cadence jitter + failure backoff (issue #59): the unified device container
# drives the agent on a fixed tick. A fleet of
# containers that starts or restarts together keeps every device's timer in
# the same phase indefinitely -- turning an ordinary tick into a fleet-wide
# burst of policy GETs, heartbeats, and tracker re-announces. Both
# entrypoint now (a) dithers every ordinary tick +/-JITTER_PCT% of TICK, (b)
# spread the FIRST tick across the whole TICK window once at startup, and
# (c) back off exponentially, capped, after the agent tick fails outright.

setup() {
  DEVICE="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  REPO="$(cd "$DEVICE/.." && pwd)"
  ENTRYPOINTS="$DEVICE/container/entrypoint.sh"
  TMP="$(mktemp -d)"
}

teardown() { rm -rf "$TMP"; }

# --- pure function: next_tick_sleep bounds --------------------------------

_extract_jitter_funcs() {   # $1 = entrypoint
  awk '/^rand_below\(\)/,/^}/' "$1"
  awk '/^next_tick_sleep\(\)/,/^}/' "$1"
}

@test "next_tick_sleep: steady state (streak 0) stays within +/-JITTER_PCT% of TICK" {
  for ep in $ENTRYPOINTS; do
    src="$(_extract_jitter_funcs "$ep")"
    for _ in 1 2 3 4 5 6 7 8; do
      out="$(eval "$src"; TICK=60 JITTER_PCT=10 BACKOFF_MAX=600 next_tick_sleep 0)"
      [ "$out" -ge 54 ] || { echo "$ep: $out < 54"; return 1; }
      [ "$out" -le 66 ] || { echo "$ep: $out > 66"; return 1; }
    done
  done
}

@test "next_tick_sleep: a failure streak backs off well past the steady-state range" {
  for ep in $ENTRYPOINTS; do
    src="$(_extract_jitter_funcs "$ep")"
    out="$(eval "$src"; TICK=60 JITTER_PCT=10 BACKOFF_MAX=600 next_tick_sleep 1)"
    # streak=1 -> base 120s +/-10%: strictly above the streak-0 ceiling (66)
    [ "$out" -gt 66 ] || { echo "$ep: streak=1 gave $out, not > 66"; return 1; }
    [ "$out" -ge 108 ] && [ "$out" -le 132 ] || { echo "$ep: streak=1 out of [108,132]: $out"; return 1; }
  done
}

@test "next_tick_sleep: backoff is capped at BACKOFF_MAX regardless of streak" {
  for ep in $ENTRYPOINTS; do
    src="$(_extract_jitter_funcs "$ep")"
    for streak in 5 8 10 15; do
      out="$(eval "$src"; TICK=60 JITTER_PCT=10 BACKOFF_MAX=600 next_tick_sleep "$streak")"
      # capped base (600) +/-10% jitter -> [540, 660]
      [ "$out" -ge 540 ] && [ "$out" -le 660 ] || {
        echo "$ep: streak=$streak gave $out, expected [540,660]"; return 1; }
    done
  done
}

@test "rand_below N is always in [0, N)" {
  for ep in $ENTRYPOINTS; do
    src="$(awk '/^rand_below\(\)/,/^}/' "$ep")"
    for _ in 1 2 3 4 5; do
      out="$(eval "$src"; rand_below 7)"
      [ "$out" -ge 0 ] && [ "$out" -le 6 ] || { echo "$ep: rand_below(7) gave $out"; return 1; }
    done
  done
}

# --- wiring: the tick loop actually uses these functions ------------------

@test "the tick loop increments FAIL_STREAK on failure and resets it on success" {
  for ep in $ENTRYPOINTS; do
    body="$(awk '/^while true; do$/,/^done$/' "$ep")"
    [[ "$body" == *'FAIL_STREAK=$((FAIL_STREAK + 1))'* ]] \
      || { echo "$ep: no failure-path increment"; return 1; }
    [[ "$body" == *'FAIL_STREAK=0'* ]] \
      || { echo "$ep: no success-path reset"; return 1; }
    [[ "$body" == *'next_tick_sleep "$FAIL_STREAK"'* ]] \
      || { echo "$ep: sleep is not driven by next_tick_sleep"; return 1; }
  done
}

@test "startup jitter is skipped when IRIS_STARTUP_JITTER=0" {
  for ep in $ENTRYPOINTS; do
    grep -qF 'IRIS_STARTUP_JITTER' "$ep" || { echo "$ep: no startup jitter guard"; return 1; }
  done
}

# --- real end-to-end: failure backoff escalates across ticks --------------
#
# Same bounded/kill idiom device/iox/tests/test_iox_install_output.bats and
# device/xr/tests/test_xr_image.bats already use for a script whose loop
# legitimately keeps running past the point under test. AGENT is the
# container-baked path (/opt/iris/agent/iris_agent.py), which does not exist
# on this host -- python3 fails every tick with a deterministic, immediate
# "No such file or directory", so the agent tick fails on every iteration
# and the backoff streak must climb tick over tick.

_run_bounded() {   # $1 = seconds, $2.. = command
  local secs="$1"; shift
  local outfile pid waited=0 rc
  outfile="$(mktemp)"
  ("$@" >"$outfile" 2>&1) &
  pid=$!
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$secs" ]; do
    sleep 1; waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    rc=124
  else
    wait "$pid"; rc=$?
  fi
  cat "$outfile"
  rm -f "$outfile"
  return "$rc"
}

@test "iox entrypoint: repeated agent failures escalate the backoff streak" {
  CONF="$TMP/iox-agent.conf"
  cat > "$CONF" <<'EOF'
catalog_url = https://198.51.100.1:8443
catalog_token = t
device_id = d1
device_platform = iox
device_ssh_host = 192.0.2.1
device_ssh_user = test
device_ssh_pass = test
EOF
  run _run_bounded 12 env PATH="$PATH" PYTHONPATH="$REPO/device/agent" \
      IRIS_DEVICE_PLATFORM=iox IRIS_CONTAINER_TESTING=1 \
      IRIS_CATALOG_CA="$REPO/server/certs/cisco_bulkhash_verify.pem" \
      IRIS_AGENT_CONF="$CONF" IRIS_STAGE_DIR="$TMP/stage" IRIS_TICK_SECONDS=1 \
      IRIS_STARTUP_JITTER=0 \
      bash "$DEVICE/container/entrypoint.sh"
  [ "$status" -eq 124 ]   # killed at the bound -- the tick loop is infinite by design
  [[ "$output" == *"agent tick returned non-zero"* ]] || { echo "$output"; return 1; }
  [[ "$output" == *"failure streak 1)"* ]] || { echo "$output"; return 1; }
  [[ "$output" == *"failure streak 2)"* ]] || { echo "$output"; return 1; }
}

@test "xr entrypoint: repeated agent failures escalate the backoff streak" {
  CONF="$TMP/xr-agent.conf"
  cat > "$CONF" <<'EOF'
catalog_url = https://198.51.100.1:8443
catalog_token = t
device_id = d1
mode = xr
device_platform = xr-appmgr
target_fs = harddisk:
EOF
  run _run_bounded 12 env PATH="$PATH" PYTHONPATH="$REPO/device/agent" \
      IRIS_DEVICE_PLATFORM=xr-appmgr IRIS_CONTAINER_TESTING=1 \
      IRIS_CATALOG_CA="$REPO/server/certs/cisco_bulkhash_verify.pem" \
      IRIS_TEST_SKIP_MOUNT_CHECK=1 IRIS_AGENT_CONF="$CONF" IRIS_STAGE_DIR="$TMP/stage" \
      IRIS_TICK_SECONDS=1 IRIS_STARTUP_JITTER=0 \
      bash "$DEVICE/container/entrypoint.sh"
  [ "$status" -eq 124 ]   # killed at the bound -- the tick loop is infinite by design
  [[ "$output" == *"agent tick returned non-zero"* ]] || { echo "$output"; return 1; }
  [[ "$output" == *"failure streak 1)"* ]] || { echo "$output"; return 1; }
  [[ "$output" == *"failure streak 2)"* ]] || { echo "$output"; return 1; }
}
