#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for lab/xr-run.sh's session bound (agentinfo/plans/2026-08-29-xr-teardown-hardening.md,
# Task 1). Live incident 2026-08-29: an XR router wedged mid-teardown --
# SSH accepted the TCP handshake but never presented a banner -- and because
# ConnectTimeout only bounds the handshake, the undeploy job ran unbounded
# (28+ minutes, no rc) until a container restart killed it. These tests stub
# `sshpass`/`sleep` on PATH and drive lab/xr-run.sh directly (not through a
# stubbed xr-run.sh) so the transport itself is under test.
#
# `|| return 1` is load-bearing: under bash 3.2 a bare failing `[[ ]]` mid-body
# does NOT fail a bats test unless it is the test function's final command.

setup() {
  RUN="$BATS_TEST_DIRNAME/../../lab/xr-run.sh"
  STUB="$BATS_TEST_TMPDIR/bin"; mkdir -p "$STUB"
  ARGV_LOG="$BATS_TEST_TMPDIR/argv.log"; : > "$ARGV_LOG"
  SLEEP_LOG="$BATS_TEST_TMPDIR/sleep.log"; : > "$SLEEP_LOG"
  export ARGV_LOG SLEEP_LOG
  export TMPDIR="$BATS_TEST_TMPDIR"
  export DEVICE_USER=admin DEVICE_PASS=zzsecretzz

  # Fake sshpass: logs the argv it was invoked with, drains stdin (as the
  # real ssh session would), optionally sleeps to simulate a wedged router
  # (FAKE_SLEEP), then emits FAKE_OUTPUT and exits FAKE_SSHPASS_STATUS.
  cat > "$STUB/sshpass" <<'STUBEOF'
#!/usr/bin/env bash
if [ -n "${ARGV_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$ARGV_LOG"
fi
cat > /dev/null
if [ -n "${FAKE_SLEEP:-}" ]; then
  /bin/sleep "$FAKE_SLEEP"
fi
printf '%s\n' "${FAKE_OUTPUT:-sw1#ok}"
exit "${FAKE_SSHPASS_STATUS:-0}"
STUBEOF
  chmod +x "$STUB/sshpass"

  # Fake sleep: logs every invocation's argument (so the tests can pin
  # whether xr-run.sh's watchdog ever armed) and then really sleeps, via
  # the absolute path -- calling plain `sleep` here would re-enter this
  # same stub through PATH and recurse forever.
  cat > "$STUB/sleep" <<'STUBEOF'
#!/usr/bin/env bash
if [ -n "${SLEEP_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$SLEEP_LOG"
fi
exec /bin/sleep "$@"
STUBEOF
  chmod +x "$STUB/sleep"

  export PATH="$STUB:$PATH"
}

@test "fast path is unchanged: rc 0, stub output flows through, password still redacted" {
  run env bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ]
  [[ "$output" == *"sw1#ok"* ]] || return 1
  [[ "$output" != *"zzsecretzz"* ]]
}

@test "ServerAlive options are present in the ssh invocation" {
  run env bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ]
  grep -q -- '-o ServerAliveInterval=15' "$ARGV_LOG" || return 1
  grep -q -- '-o ServerAliveCountMax=4' "$ARGV_LOG"
}

@test "a wedged session is killed at the bound: rc 124, well inside the sleep it was killed out of" {
  start="$(date +%s)"
  run env FAKE_SLEEP=30 IRIS_XR_SESSION_TIMEOUT=1 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  elapsed=$(( $(date +%s) - start ))
  [ "$status" -eq 124 ] || return 1
  [ "$elapsed" -lt 15 ]
}

@test "redaction still applies to whatever partial output a killed session produced" {
  # The fake ssh writes its (secret-bearing) banner before it wedges, same
  # as a real device would emit a login banner before going silent.
  run env FAKE_SLEEP=30 FAKE_OUTPUT="login as: admin, password: zzsecretzz" \
    IRIS_XR_SESSION_TIMEOUT=1 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 124 ] || return 1
  [[ "$output" != *"zzsecretzz"* ]]
}

@test "IRIS_XR_SESSION_TIMEOUT=0 disables the bound: no watchdog sleep is ever scheduled" {
  run env IRIS_XR_SESSION_TIMEOUT=0 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [ ! -s "$SLEEP_LOG" ]
}

@test "a nonzero IRIS_XR_SESSION_TIMEOUT arms the watchdog even on the fast path" {
  # FAKE_SLEEP=1 keeps this well clear of a startup race: the assertion is
  # about which code path xr-run.sh takes (watchdog armed vs. skipped), not
  # about winning a fork/exec footrace against a near-instant stub -- a
  # truly instant "fast path" could in principle complete and reap the
  # watchdog before the watchdog subshell is even scheduled to log its call.
  run env FAKE_SLEEP=1 IRIS_XR_SESSION_TIMEOUT=37 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  grep -q '^37$' "$SLEEP_LOG"
}
