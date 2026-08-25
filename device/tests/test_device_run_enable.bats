#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# lab/device-run.sh must not send the enable password to a device that is
# already in enable mode.
#
# Measured on a lab C8000v: an identical session costs 3.13 s without the
# enable+password lines and 43.32 s with them. The device lands at `#`, so
# `enable` is a no-op and the password line is then executed as an EXEC
# command; IOS tries to resolve it as a hostname and — where that lookup
# black-holes rather than failing fast — blocks for ~40 s. router-uninstall.sh
# opens 17 sessions, so this alone accounted for ~11 minutes of a teardown.
#
# `|| return 1` is load-bearing: under bash 3.2 a bare failing `[[ ]]` mid-body
# does NOT fail a bats test.

setup() {
  RUN="$BATS_TEST_DIRNAME/../../lab/device-run.sh"
  STUB="$BATS_TEST_TMPDIR/bin"; mkdir -p "$STUB"
  LOG="$BATS_TEST_TMPDIR/sent.log"
  export TMPDIR="$BATS_TEST_TMPDIR"          # keep the privilege cache local
  export DEVICE_USER=u DEVICE_PASS=zzsecretzz
  # The stub records what was piped in, and replays a transcript whose prompt
  # marker is controlled by FAKE_PROMPT (# = already enabled, > = user mode).
  cat > "$STUB/sshpass" <<STUBEOF
#!/usr/bin/env bash
cat > "$LOG"
p="\${FAKE_PROMPT:-#}"
# Model the real prompt: the \`enable\` echo carries the PRE-enable marker, and
# everything after a successful enable carries '#'. With no enable sent, the
# prompt simply stays as it was -- which is the signal that the cached
# "already privileged" belief has gone stale.
if grep -q '^enable\$' "$LOG"; then
  echo "sw1\${p}enable"
  after="#"
else
  after="\$p"
fi
echo "sw1\${after}terminal length 0"
echo "sw1\${after}show clock"
echo "10:00:00.000 UTC Tue Aug 25 2026"
STUBEOF
  chmod +x "$STUB/sshpass"
  export PATH="$STUB:$PATH"
}

@test "the first call still sends enable, since privilege is not yet known" {
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  grep -q '^enable$' "$LOG" || return 1
  grep -q '^zzsecretzz$' "$LOG"
}

@test "an already-enabled device is remembered, and the next call sends neither" {
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  : > "$LOG"
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  ! grep -q '^enable$' "$LOG" || return 1
  ! grep -q '^zzsecretzz$' "$LOG" || return 1
  # the real work still goes
  grep -q '^show clock$' "$LOG"
}

@test "a device that genuinely needs enable keeps getting it" {
  FAKE_PROMPT='>' bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10" >/dev/null 2>&1
  : > "$LOG"
  FAKE_PROMPT='>' bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10" >/dev/null 2>&1
  grep -q '^enable$' "$LOG" || return 1
  grep -q '^zzsecretzz$' "$LOG"
}

@test "a cached device that starts asking for enable again recovers" {
  # learn "already enabled"...
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  # ...then the device comes back in user mode (reload, config change)
  FAKE_PROMPT='>' bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10" >/dev/null 2>&1
  : > "$LOG"
  FAKE_PROMPT='>' bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10" >/dev/null 2>&1
  grep -q '^enable$' "$LOG" || return 1
  grep -q '^zzsecretzz$' "$LOG"
}

@test "the escape hatch forces the old unconditional behaviour" {
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  : > "$LOG"
  IRIS_DEVICE_ENABLE_ALWAYS=1 bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10" >/dev/null 2>&1
  grep -q '^enable$' "$LOG" || return 1
  grep -q '^zzsecretzz$' "$LOG"
}
