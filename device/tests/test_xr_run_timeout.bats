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
  STDIN_LOG="$BATS_TEST_TMPDIR/stdin.log"; : > "$STDIN_LOG"
  export ARGV_LOG SLEEP_LOG STDIN_LOG
  export TMPDIR="$BATS_TEST_TMPDIR"
  export IRIS_STATE="$BATS_TEST_TMPDIR/state"   # persistent known_hosts stays local
  export DEVICE_USER=admin DEVICE_PASS=zzsecretzz

  # The peer emits prompts without newlines and reads one command at a time.
  # Its run child can consume queued stdin, reproducing why pipelined exit
  # disappears on hardware even after complete command output was returned.
  cat > "$STUB/sshpass" <<'STUBEOF'
#!/usr/bin/env python3
import os
import select
import signal
import sys
import time

with open(os.environ['ARGV_LOG'], 'a') as log:
    log.write(' '.join(sys.argv[1:]) + '\n')

def emit(text):
    os.write(1, text.encode())

def line():
    data = b''
    while not data.endswith(b'\n'):
        part = os.read(0, 1)
        if not part:
            return None
        data += part
    text = data.decode().rstrip('\r\n')
    with open(os.environ['STDIN_LOG'], 'a') as log:
        log.write(text + '\n')
    return text

emit(os.environ.get('FAKE_OUTPUT', 'sw1#ok') + '\n')
if os.environ.get('FAKE_SLEEP'):
    time.sleep(float(os.environ['FAKE_SLEEP']))
if os.environ.get('FAKE_EOF') == 'login':
    sys.exit(int(os.environ.get('FAKE_SSHPASS_STATUS', '0')))
prefix = 'RP/0/RP0/CPU0:router'
prompt = prefix + '#'
emit(prompt)
while True:
    command = line()
    if command is None:
        # A real SSH PTY stays open if exit was swallowed by the run child.
        if os.environ.get('FAKE_CONSUME_RUN_INPUT'):
            time.sleep(30)
        break
    emit(command + '\r\n')
    if command == 'exit':
        if os.environ.get('FAKE_EXIT_SLEEP'):
            time.sleep(30)
        break
    if os.environ.get('FAKE_EOF') == 'command':
        break
    if command.startswith('run '):
        emit('SAFE_RUN_OUTPUT\n')
        if os.environ.get('FAKE_CONSUME_RUN_INPUT'):
            while select.select([0], [], [], 0.1)[0]:
                pending = os.read(0, 4096)
                if not pending:
                    break
                emit('RUN_CHILD_CONSUMED_INPUT\n')
        if os.environ.get('FAKE_MISLEADING_PROMPT'):
            emit('RP/0/RP0/CPU0:other-router#')
            if select.select([0], [], [], 0.1)[0]:
                emit('WRONG_PROMPT_RELEASED_INPUT\n')
                sys.exit(9)
            emit('\n')
        if os.environ.get('FAKE_SPLIT_PROMPT'):
            emit(prefix + '(config')
            if select.select([0], [], [], 0.1)[0]:
                emit('PARTIAL_PROMPT_RELEASED_INPUT\n')
                sys.exit(9)
            emit(')#')
            continue
    if command == 'configure':
        prompt = prefix + '(config)#'
    elif command == 'abort':
        prompt = prefix + '#'
    emit(prompt)
if os.environ.get('FAKE_SIGNAL'):
    os.kill(os.getpid(), signal.SIGTERM)
sys.exit(int(os.environ.get('FAKE_SSHPASS_STATUS', '0')))
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
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"sw1#ok"* ]] || return 1
  [[ "$output" != *"zzsecretzz"* ]]
}

@test "ServerAlive options are present in the ssh invocation" {
  run env bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  grep -q -- '-o ServerAliveInterval=15' "$ARGV_LOG" || return 1
  grep -q -- '-o ServerAliveCountMax=4' "$ARGV_LOG"
}

# ---------------------------------------------------------------------------
# CRITICAL: the bounded path must actually deliver the request. `xr_run_ssh
# &` is an asynchronous command; per POSIX/bash, an asynchronous command
# with no explicit stdin redirection of its own has its stdin redirected
# from /dev/null when job control is not the interactive default -- so
# without an explicit `<&0` on that background launch, every bounded
# session logs in and sends nothing at all. These pin the exact request
# text (terminal length 0 / commands / commit guard / exit), in order, on
# BOTH the default (bounded) path and the IRIS_XR_SESSION_TIMEOUT=0 path.
# ---------------------------------------------------------------------------

_assert_full_request_delivered() {
  local tl0 cfg host commit failed abort exitline
  tl0="$(grep -n '^terminal length 0$' "$STDIN_LOG" | head -1 | cut -d: -f1)"
  cfg="$(grep -n '^configure$' "$STDIN_LOG" | head -1 | cut -d: -f1)"
  host="$(grep -n '^hostname foo$' "$STDIN_LOG" | head -1 | cut -d: -f1)"
  commit="$(grep -n '^commit$' "$STDIN_LOG" | head -1 | cut -d: -f1)"
  failed="$(grep -n '^show configuration failed$' "$STDIN_LOG" | head -1 | cut -d: -f1)"
  abort="$(grep -n '^abort$' "$STDIN_LOG" | head -1 | cut -d: -f1)"
  exitline="$(grep -n '^exit$' "$STDIN_LOG" | head -1 | cut -d: -f1)"
  [ -n "$tl0" ] && [ -n "$cfg" ] && [ -n "$host" ] && [ -n "$commit" ] \
    && [ -n "$failed" ] && [ -n "$abort" ] && [ -n "$exitline" ] || return 1
  [ "$tl0" -lt "$cfg" ] || return 1
  [ "$cfg" -lt "$host" ] || return 1
  [ "$host" -lt "$commit" ] || return 1
  [ "$commit" -lt "$failed" ] || return 1
  [ "$failed" -lt "$abort" ] || return 1
  [ "$abort" -lt "$exitline" ]
}

@test "the default bounded path delivers the full request to ssh (terminal length 0 / commands / commit guard / exit)" {
  run env bash -c "printf 'configure\nhostname foo\ncommit\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  _assert_full_request_delivered
}

@test "IRIS_XR_SESSION_TIMEOUT=0 also delivers the full request to ssh" {
  run env IRIS_XR_SESSION_TIMEOUT=0 \
    bash -c "printf 'configure\nhostname foo\ncommit\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  _assert_full_request_delivered
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

# ---------------------------------------------------------------------------
# IMPORTANT: a garbage IRIS_XR_SESSION_TIMEOUT must never turn into an
# instant kill (`sleep abc`/`sleep -5` fail immediately, and a naive
# watchdog would read that as "the bound already elapsed" and fire rc 124
# at t=0 for every session) or into a silently-unbounded session. Invalid
# values fall back to the 150s default with one stderr warning; empty/unset
# stays exactly as before (150s default, no warning).
# ---------------------------------------------------------------------------

@test "IRIS_XR_SESSION_TIMEOUT=abc falls back to the 150s default with a warning, not an instant kill" {
  run env IRIS_XR_SESSION_TIMEOUT=abc FAKE_SLEEP=1 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"IRIS_XR_SESSION_TIMEOUT"* ]] || return 1
  grep -q '^150$' "$SLEEP_LOG"
}

@test "IRIS_XR_SESSION_TIMEOUT=-5 falls back to the 150s default with a warning, not an instant kill" {
  run env IRIS_XR_SESSION_TIMEOUT=-5 FAKE_SLEEP=1 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"IRIS_XR_SESSION_TIMEOUT"* ]] || return 1
  grep -q '^150$' "$SLEEP_LOG"
}

@test "IRIS_XR_SESSION_TIMEOUT with embedded whitespace falls back to the 150s default with a warning" {
  run env IRIS_XR_SESSION_TIMEOUT=" 5 " FAKE_SLEEP=1 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"IRIS_XR_SESSION_TIMEOUT"* ]] || return 1
  grep -q '^150$' "$SLEEP_LOG"
}

@test "empty IRIS_XR_SESSION_TIMEOUT behaves exactly like unset: 150s default, no warning" {
  run env IRIS_XR_SESSION_TIMEOUT= FAKE_SLEEP=1 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" != *"IRIS_XR_SESSION_TIMEOUT"* ]] || return 1
  grep -q '^150$' "$SLEEP_LOG"
}

@test "unset IRIS_XR_SESSION_TIMEOUT behaves as the 150s default, no warning" {
  run env FAKE_SLEEP=1 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" != *"IRIS_XR_SESSION_TIMEOUT"* ]] || return 1
  grep -q '^150$' "$SLEEP_LOG"
}

@test "IRIS_XR_SESSION_TIMEOUT=0 stays valid: no warning, bound disabled" {
  run env IRIS_XR_SESSION_TIMEOUT=0 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" != *"IRIS_XR_SESSION_TIMEOUT"* ]] || return 1
  [ ! -s "$SLEEP_LOG" ]
}

# Live-reproduced 2026-08-31 on 8010-R4 (203.0.113.84), byte dump in
# agentinfo/xr-support/: the router does not only terminate lines with the
# `\r\n` a pty is expected to produce -- it also emits a bare CR at the START
# of an output line (the `\n\r` sequence, a column reset before printing).
# The sanitizer below used to be `s/\r$//`, which strips a CR only where it
# sits immediately before the newline, so a LEADING CR sailed straight
# through into every consumer of this transport. That was not cosmetic:
# device/xr-uninstall.sh's [5/5] emptiness check drops the `dir` timestamp
# line with a `^(Mon|Tue|...)` anchor, `\rMon Aug 31 ... UTC` does not match
# that anchor, so the line survived every filter and a provably EMPTY
# iris-work directory was reported as still holding artifacts -- undeploy
# exited 1 on a clean device across seven live runs. Stripping CR everywhere
# repairs every `^`-anchored parser downstream of this transport at once,
# which is why the fix belongs here and not in any one parser.
@test "a carriage return is stripped anywhere in the line, not just before the newline" {
  run env FAKE_OUTPUT="$(printf 'RP/0/RP0/CPU0:8010-R4#dir harddisk:/iris-work\r\n\rMon Aug 31 14:19:11.430 UTC\r')" \
    bash -c "printf 'dir harddisk:/iris-work\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  # The text itself must survive intact -- this strips CR, it does not drop lines.
  [[ "$output" == *"Mon Aug 31 14:19:11.430 UTC"* ]] || return 1
  [[ "$output" == *"dir harddisk:/iris-work"* ]] || return 1
  # And the leading CR that defeated the anchor must be gone.
  [[ "$output" != *$'\r'* ]]
}

@test "a failing mktemp is refused loudly, not silently run unbounded" {
  cat > "$STUB/mktemp" <<'STUBEOF'
#!/usr/bin/env bash
exit 1
STUBEOF
  chmod +x "$STUB/mktemp"
  run env bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"mktemp"* ]]
}

@test "run child cannot consume the next command or final exit before returning its prompt" {
  run env FAKE_CONSUME_RUN_INPUT=1 IRIS_XR_SESSION_TIMEOUT=2 \
    bash -c "printf 'run harmless-read\nshow version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"SAFE_RUN_OUTPUT"* ]] || return 1
  [[ "$output" != *"RUN_CHILD_CONSUMED_INPUT"* ]] || return 1
  grep -q '^show version$' "$STDIN_LOG" || return 1
  grep -q '^exit$' "$STDIN_LOG"
}

@test "only the authenticated XR prompt releases the next command" {
  run env FAKE_MISLEADING_PROMPT=1 IRIS_XR_SESSION_TIMEOUT=2 \
    bash -c "printf 'run harmless-read\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" != *"WRONG_PROMPT_RELEASED_INPUT"* ]] || return 1
  grep -q '^exit$' "$STDIN_LOG"
}

@test "a split configuration prompt waits for its closing delimiter" {
  run env FAKE_SPLIT_PROMPT=1 IRIS_XR_SESSION_TIMEOUT=2 \
    bash -c "printf 'run harmless-read\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" != *"PARTIAL_PROMPT_RELEASED_INPUT"* ]] || return 1
  grep -q '^exit$' "$STDIN_LOG"
}

@test "clean SSH EOF before login or before all commands is a transport failure" {
  for phase in login command; do
    run env FAKE_EOF="$phase" IRIS_XR_SESSION_TIMEOUT=2 \
      bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
    [ "$status" -ne 0 ] || return 1
    [[ "$output" == *"before all commands"* ]] || return 1
  done
}

@test "SSH failure status survives prompt framing" {
  run env FAKE_EOF=login FAKE_SSHPASS_STATUS=23 IRIS_XR_SESSION_TIMEOUT=2 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 23 ]
}

@test "the hard deadline still bounds EOF after the final exit" {
  run env FAKE_EXIT_SLEEP=1 IRIS_XR_SESSION_TIMEOUT=1 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 124 ] || return 1
  grep -q '^exit$' "$STDIN_LOG"
}

@test "SSH termination by signal is preserved instead of reported as a timeout" {
  run env FAKE_SIGNAL=1 IRIS_XR_SESSION_TIMEOUT=2 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 143 ]
}

@test "a failed read after exit was delivered cannot report success" {
  # Inject EIO at the syscall boundary after the healthy fake peer echoes
  # exit. SSH itself still exits zero, so only a transport read failure can
  # account for the nonzero result.
  cat > "$STUB/IrisReadFailure.pm" <<'PERLEOF'
package IrisReadFailure;
use Errno qw(EIO);
BEGIN {
    my $after_exit = 0;
    *CORE::GLOBAL::sysread = sub (*\$$;$) {
        if ($after_exit) { $! = EIO; return undef }
        my ($handle, $buffer, $length, $offset) = @_;
        my $count = @_ == 4
            ? CORE::sysread($handle, $$buffer, $length, $offset)
            : CORE::sysread($handle, $$buffer, $length);
        $after_exit = 1 if defined($count) && $$buffer =~ /(?:^|\n)exit\r?\n/;
        return $count;
    };
}
1;
PERLEOF
  run env PERL5LIB="$STUB" PERL5OPT=-MIrisReadFailure IRIS_XR_SESSION_TIMEOUT=2 \
    bash -c "printf 'show version\n' | bash '$RUN' 192.0.2.10"
  [ "$status" -eq 1 ] || return 1
  [[ "$output" == *"cannot read SSH dialogue"* ]] || return 1
  grep -q '^exit$' "$STDIN_LOG"
}
