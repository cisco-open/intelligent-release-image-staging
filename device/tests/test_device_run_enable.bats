#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# lab/device-run.sh must never write a line into an IOS session that is not a
# valid command in the mode it is actually in.
#
# The login lands at `#` on every box in the fleet, so `enable` is a no-op and
# the password line after it is executed as an EXEC command; IOS then tries to
# resolve it as a hostname. Measured 2026-09-01 on identical sessions, with no
# DNS configuration difference between the two boxes:
#
#     192.0.2.114     3.06 s clean / 3.19 s with the pair   (+0.13 s)
#     203.0.113.101   3.41 s clean / 51.79 s with the pair   (+48.4 s)
#
# (RFC 5737 documentation stand-ins for the two lab segments; only the split
# between them matters.)
#
# The first segment is merely lucky -- something there answers the default
# 255.255.255.255 broadcast. So the contract is the DEFAULT: send neither line,
# and escalate only for a device that has shown it runs us at user EXEC, where
# `enable` really does raise the prompt the secret then answers.
#
# `|| return 1` is load-bearing: under bash 3.2 a bare failing `[[ ]]` mid-body
# does NOT fail a bats test.

setup() {
  RUN="$BATS_TEST_DIRNAME/../../lab/device-run.sh"
  STUB="$BATS_TEST_TMPDIR/bin"; mkdir -p "$STUB"
  LOG="$BATS_TEST_TMPDIR/sent.log"
  export TMPDIR="$BATS_TEST_TMPDIR"
  export IRIS_STATE="$BATS_TEST_TMPDIR/state"  # keep known_hosts + the escalation marker local
  export DEVICE_USER=u DEVICE_PASS=zzsecretzz
  # The stub records what was piped in, and replays a transcript whose prompt
  # marker is controlled by FAKE_PROMPT (# = already enabled, > = user mode).
  cat > "$STUB/sshpass" <<STUBEOF
#!/usr/bin/env bash
cat > "$LOG"
p="\${FAKE_PROMPT:-#}"
# Model the real prompt: the \`enable\` echo carries the PRE-enable marker, and
# everything after a successful enable carries '#'. With no enable sent, the
# prompt simply stays as it was -- which is the signal the device wanted it.
if grep -q '^enable\$' "$LOG"; then
  echo "sw1\${p}enable"
  after="#"
else
  after="\$p"
fi
echo "sw1\${after}terminal length 0"
echo "sw1\${after}show clock"
echo "10:00:00.000 UTC Tue Aug 25 2026"
exit "\${FAKE_SSH_STATUS:-0}"
STUBEOF
  chmod +x "$STUB/sshpass"
  export PATH="$STUB:$PATH"
}

@test "the first call to an unknown device sends neither enable nor the secret" {
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  ! grep -q '^enable$' "$LOG" || return 1
  ! grep -q '^zzsecretzz$' "$LOG" || return 1
  # the real work still goes
  grep -q '^show clock$' "$LOG"
}

@test "an already-enabled device never gets the pair, on any call" {
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  : > "$LOG"
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  ! grep -q '^enable$' "$LOG" || return 1
  ! grep -q '^zzsecretzz$' "$LOG"
}

@test "a device that runs us at user EXEC is escalated on the next call" {
  # first contact learns it from the '>' prompt the device itself emitted
  FAKE_PROMPT='>' bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10" >/dev/null 2>&1
  : > "$LOG"
  FAKE_PROMPT='>' bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10" >/dev/null 2>&1
  grep -q '^enable$' "$LOG" || return 1
  grep -q '^zzsecretzz$' "$LOG"
}

@test "a device that stops needing enable stops being sent the pair" {
  # learn "needs enable"...
  FAKE_PROMPT='>' bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10" >/dev/null 2>&1
  # ...then it comes back already privileged (reload, config change): that call
  # still sends the pair, sees 'sw1#enable', and unlearns it
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  : > "$LOG"
  printf 'show clock\n' | bash "$RUN" 192.0.2.10 >/dev/null 2>&1
  ! grep -q '^enable$' "$LOG" || return 1
  ! grep -q '^zzsecretzz$' "$LOG"
}

@test "the escape hatch forces the old unconditional behaviour" {
  IRIS_DEVICE_ENABLE_ALWAYS=1 bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10" >/dev/null 2>&1
  grep -q '^enable$' "$LOG" || return 1
  grep -q '^zzsecretzz$' "$LOG"
}

@test "a stray-token stall is reported on stderr, not swallowed" {
  cat > "$STUB/sshpass" <<'STUBEOF'
#!/usr/bin/env bash
cat > /dev/null
echo "sw1#terminal length 0"
echo "Translating \"zzsecretzz\"...domain server (255.255.255.255)"
echo "% Bad IP address or host name"
STUBEOF
  chmod +x "$STUB/sshpass"
  run bash -c "printf 'show clock\n' | bash '$RUN' 192.0.2.10 2>&1 >/dev/null"
  [[ "$output" == *"resolved one of our lines as a hostname"* ]]
}

@test "SSH failure survives the escalation bookkeeping" {
  run env FAKE_SSH_STATUS=23 bash -c \
    "printf 'show clock\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 23 ]
}
