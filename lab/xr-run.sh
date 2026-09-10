#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Run IOS-XR commands on a Cisco 8000-series router over SSH -- the XR
# transport twin of lab/device-run.sh. Two hardware-proven differences from
# the IOS-XE transport (agentinfo/xr-support/LAB-RESULTS-2026-08-27.md):
#
#   1. NO enable dance. The XR admin login lands directly at the privileged
#      prompt ("RP/0/RP0/CPU0:<host>#"); there is no separate "enable" step
#      and nothing to send a password for. Unlike device-run.sh, this script
#      never sends "enable" -- doing so on XR is not a harmless no-op the way
#      it is on IOS-XE (there is no "already privileged" prompt-echo idiom to
#      detect), it is simply not part of the login flow at all.
#
#   2. Config sessions are two-stage (configure/commit) and a FAILED commit
#      leaves the session dirty: the pending edit set is still open and the
#      next command run against it inherits that stuck state (the lab-proven
#      trap). Every literal "commit" line in the input is therefore followed
#      by "show configuration failed" then "abort". This is harmless when
#      nothing failed -- commit already applied the change, so "show
#      configuration failed" reports nothing and "abort" just closes config
#      mode with no pending edits left to discard (the same net effect an
#      "end" would have) -- and it is the only documented way out of a
#      dirty session when something did fail.
#
# Usage:  echo "show version" | lab/xr-run.sh <device-ip>
#         lab/xr-run.sh <device-ip> <<'EOF'
#         configure
#         hostname foo
#         commit
#         EOF
# Commands are read from stdin. `terminal length 0` is prepended automatically.
# User/password from $DEVICE_USER/$DEVICE_PASS (required -- export them or
# 'source' creds/). XR's own login is 'admin' (never the IOS-XE 'dnac'
# default some lab creds files carry) -- this script has no default of its
# own either; the caller supplies whichever user the box actually needs.
#
# Session bound: a wedged router can accept the TCP handshake and then never
# present a banner or respond further -- ConnectTimeout only bounds the
# handshake, not the rest of the session (lab incident 2026-08-29: an XR
# undeploy job hung 28+ minutes with no rc until the container was
# restarted). ServerAliveInterval/ServerAliveCountMax make ssh itself notice
# a dead peer, and the whole session additionally runs under a hard
# wall-clock bound of IRIS_XR_SESSION_TIMEOUT seconds (default 150),
# env-overridable; set it to 0 to disable the bound entirely (lab debugging
# escape hatch). The 150s default is the top of the recon-derived 120-150s
# band (agentinfo/xr-support/teardown-speed-recon.md section 1.4): every
# healthy session recovered or inferred from live .20 job logs runs ~15-20s,
# so 150s carries 6-10x headroom over that ceiling for both install and
# teardown (the install Up-poll is 30 short client-looped sessions, not one
# long one -- same memo, section 1.3 -- so no separate install knob is
# needed), while still capping a worst-case two-stall teardown (Task 2's
# at-most-two-bounded-sessions composite, device/xr-uninstall.sh) at 300s
# total, well under the old default's 1800s. GNU coreutils `timeout` is not assumed present: this repo's
# bats suite runs on Darwin, which ships neither `timeout` nor `gtimeout` by
# default, and nothing else in this tree depends on it -- so the bound below
# is a small portable watchdog (background + kill) instead of a `timeout`
# invocation. On timeout it reports rc 124, matching GNU timeout's
# convention, so callers that already treat a nonzero rc as step failure
# need no changes.
#
# Host identity: the peer is verified per lab/iris-ssh-policy.sh (same policy
# and env knobs as device-run.sh: IRIS_SSH_HOST_KEY / IRIS_SSH_KNOWN_HOSTS /
# persistent accept-new; IRIS_SSH_LEGACY=1 for legacy algorithms). ssh's own
# diagnostics are forwarded (redacted) on stderr, never discarded.
set -uo pipefail
HOST="${1:?usage: xr-run.sh <device-ip>  (commands on stdin)}"
DEVICE_USER="${DEVICE_USER:?set DEVICE_USER (device login user; export it or 'source' creds/)}"
export SSHPASS="${DEVICE_PASS:?set DEVICE_PASS (export it or 'source' your gitignored creds file)}"
LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lab/iris-ssh-policy.sh
. "$LAB_DIR/iris-ssh-policy.sh" || { echo "xr-run.sh: cannot load $LAB_DIR/iris-ssh-policy.sh" >&2; exit 1; }
iris_ssh_policy "$HOST" || exit 1
ERR_COPY="$(mktemp "${TMPDIR:-/tmp}/iris-xr-run-err.XXXXXX")" \
  || { echo "xr-run.sh: mktemp failed creating the ssh diagnostics capture -- refusing to run with ssh errors discarded" >&2; exit 1; }
SESSION_TIMEOUT="${IRIS_XR_SESSION_TIMEOUT:-150}"
# A garbage value here must fall back to the default, never turn into an
# instant kill: `sleep abc` or `sleep -5` fails immediately, and a naive
# watchdog would read that failed sleep as "the bound already elapsed" and
# fire rc 124 on every single session at t=0. Empty/unset already became
# "150" via the ${:-150} default above and is intentionally silent; only a
# genuinely-set-but-invalid value (non-digits, a leading '-', embedded
# whitespace) warns and falls back.
case "$SESSION_TIMEOUT" in
  *[!0-9]*)
    echo "xr-run.sh: IRIS_XR_SESSION_TIMEOUT='$SESSION_TIMEOUT' is not a non-negative integer -- using the 150s default instead" >&2
    SESSION_TIMEOUT=150
    ;;
esac

CMDS="$(cat)"
# Insert the recovery pair after every literal "commit" line (own line, no
# trailing config keywords such as "commit replace" -- those are not this
# script's concern and are passed through untouched).
GUARDED_CMDS="$(printf '%s\n' "$CMDS" | awk '
  { print }
  /^[[:space:]]*commit[[:space:]]*$/ {
    print "show configuration failed"
    print "abort"
  }
')"

xr_run_ssh() {
  # XR's `run` child can consume already-buffered CLI commands, including
  # exit. Send each line only after the previous command returns its prompt.
  perl "$LAB_DIR/xr-dialogue.pl" sshpass -e ssh -tt -o ConnectTimeout=15 "${IRIS_SSH_OPTS[@]}" \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
    "${DEVICE_USER}@${HOST}" 2>>"$ERR_COPY"
}

# Portable stand-in for `timeout "$timeout_secs" xr_run_ssh`: background the
# session, race it against a watchdog subshell, and kill whichever loses.
# A marker file (not the process's exit status) records whether the
# watchdog actually fired, since a signal-related exit code from a genuine
# ssh/network failure must not be misreported as a timeout.
# IRIS_XR_SESSION_TIMEOUT=0 skips the wrapper entirely and runs unbounded.
run_bounded_ssh() {
  local timeout_secs="$1"

  if [ "$timeout_secs" = "0" ]; then
    xr_run_ssh
    return $?
  fi

  # Deliberately NOT `local`: this function is the entire content of a
  # pipe stage, so bash runs it in its own subshell and that subshell
  # exits right when the function returns -- which is exactly when the
  # EXIT trap below fires, i.e. after the `local` scope that declared this
  # variable has already ended. Under `set -u` that turned into a stray
  # "unbound variable" on every single normal run (caught by actually
  # running it, not by inspection).
  fired_marker="$(mktemp "${TMPDIR:-/tmp}/iris-xr-run-timeout.XXXXXX")" || {
    echo "xr-run.sh: mktemp failed creating the session-timeout marker -- refusing to run without the bound in place" >&2
    return 1
  }
  # The explicit `rm -f "$fired_marker"` at the end of this function
  # removes it on the paths this script controls directly: normal
  # completion and the watchdog killing a wedged ssh once the bound fires
  # both return through the end of this function and hit that line before
  # any trap needs to run. TERM and INT are also trapped, and that matters:
  # re-measured directly against this exact subshell (identified as the
  # pipe stage that is a direct child of xr-run.sh's own process, sibling
  # to the `perl` stage below), sent a bare TERM while it was blocked in
  # the `wait` below, on the bash 3.2 this repo's bats suite runs under --
  # an explicit `exit` from within the TERM/INT trap DOES re-fire the EXIT
  # trap on this shell, three separate runs, each cleaning up the marker
  # within milliseconds. That is standard bash behavior (an `exit` called
  # from a non-EXIT trap re-triggers the EXIT trap) and is why TERM/INT are
  # trapped explicitly here instead of left to their default (immediately
  # fatal, no trap at all) disposition. The one signal this can't cover is
  # SIGKILL, which bypasses every trap by definition and would leave the
  # marker behind -- harmless, since `mktemp` gives every run its own
  # uniquely named file, so a leaked one is a few bytes in TMPDIR, not a
  # collision with the next run. Scope, also verified directly: this
  # function's `trap` calls only apply to the specific process running it,
  # and this is a non-last pipe stage, so bash runs it in its own forked
  # subshell, distinct from xr-run.sh's top-level process -- a kill of only
  # the single outermost PID a caller happens to have captured (xr-run.sh's
  # own process, not this subshell) does NOT reach this subshell at all,
  # and the marker is left behind exactly as if SIGKILL had been used.
  trap 'rm -f "$fired_marker" 2>/dev/null' EXIT
  trap 'exit 143' TERM
  trap 'exit 130' INT
  printf '0' > "$fired_marker"

  # `sshpass` wraps `ssh`, feeding it the password over a pty it allocates
  # and holds open as the pty master. `set -m` for this one background
  # launch puts sshpass into its own process group, and the negative-PID
  # kill below correctly reaches sshpass itself plus any child that does
  # NOT detach into a session of its own -- but sshpass's `ssh` child does:
  # sshpass calls setsid() on it, so `ssh` actually ends up OUTSIDE this
  # process group (measured), and the group-kill does not reach it
  # directly. What kills `ssh` in practice is the pty master closing once
  # sshpass dies: `ssh` holds the pty slave as its controlling terminal and
  # gets a hangup once nothing holds the master open any more. That is
  # reliable in the cases this task cares about, but it is a step removed
  # from the signal delivery itself -- a `ssh` that is somehow blocked
  # where it would not observe the hangup promptly is a residual case the
  # group-kill alone does not cover. Job control is switched back off
  # immediately after so it doesn't affect anything else in the script.
  set -m
  xr_run_ssh <&0 &
  local ssh_pid=$!
  set +m

  # The watchdog's own stdio must NOT be the real ssh/perl pipe, for the
  # same reason: this script runs with job control off for itself, so if
  # the watchdog subshell below is killed while blocked in its own `sleep`,
  # that sleep is orphaned rather than reaped, and an orphan still holding
  # the pipe's write end open would leave perl blocked on EOF forever.
  # Detaching stdio here means that orphan holds /dev/null open instead --
  # and, same as above, it gets its own process group so the fast (common)
  # path of cancelling it below reaps its `sleep` cleanly instead of
  # leaving it to run out the clock as a harmless but sloppy orphan.
  set -m
  (
    sleep "$timeout_secs"
    if kill -0 "$ssh_pid" 2>/dev/null; then
      printf '1' > "$fired_marker"
      kill -TERM -"$ssh_pid" 2>/dev/null
      sleep 1
      kill -KILL -"$ssh_pid" 2>/dev/null
    fi
  ) </dev/null >/dev/null 2>&1 &
  local watchdog_pid=$!
  set +m

  # 2>/dev/null here (and below) swallows bash's own job-control
  # "Terminated: 15  xr_run_ssh" notice for the job we just killed -- pure
  # cosmetic noise on this script's stderr, not a masked error, since $?
  # is captured from `wait` itself regardless of its stderr.
  wait "$ssh_pid" 2>/dev/null
  local ssh_rc=$?

  kill -TERM -"$watchdog_pid" 2>/dev/null
  wait "$watchdog_pid" 2>/dev/null

  if [ "$(cat "$fired_marker" 2>/dev/null)" = "1" ]; then
    ssh_rc=124
  fi
  rm -f "$fired_marker"
  return "$ssh_rc"
}

{
  printf 'terminal length 0\n'
  printf '%s\n' "$GUARDED_CMDS"
  printf 'exit\n'
} | run_bounded_ssh "$SESSION_TIMEOUT" \
  | perl -pe '
      # Strip CR ANYWHERE in the line, not just the `\r` before the newline.
      # This router does not only send the `\r\n` terminator a pty is
      # expected to produce: it also emits a bare CR at the START of an
      # output line -- an `\n\r` sequence, a column reset before printing --
      # measured byte-exact on 8010-R4 (203.0.113.84) 2026-08-31. The old
      # `s/\r$//` anchored form left every one of those leading CRs in place,
      # and a leading CR silently defeats every `^`-anchored parser
      # downstream: device/xr-uninstall.sh:s [5/5] emptiness check drops the
      # `dir` timestamp line with `^(Mon|Tue|...)`, `\rMon Aug 31 ... UTC`
      # never matched it, that one line survived all six filters, and a
      # provably EMPTY iris-work directory was reported as still holding
      # artifacts (undeploy exited 1 against a clean device, seven live
      # runs). Sanitizing here rather than in any one parser is deliberate:
      # CR is never meaningful content in XR CLI output, and one strip at the
      # transport repairs every current and future consumer at once.
      s/\r//g;
      for my $secret (grep { defined && length } $ENV{DEVICE_PASS}) {
        s/\Q$secret\E/[REDACTED]/g;
      }
    '
RUN_STATUS=$?
iris_ssh_cleanup
# ssh's own diagnostics, redacted, on OUR stderr -- never discarded.
if [ -s "$ERR_COPY" ]; then
  perl -pe '
      s/\r//g;
      for my $secret (grep { defined && length } $ENV{DEVICE_PASS}) {
        s/\Q$secret\E/[REDACTED]/g;
      }
    ' "$ERR_COPY" | sed 's/^/ssh: /' >&2
  iris_ssh_explain "$ERR_COPY" "$HOST"
fi
rm -f "$ERR_COPY"
exit "$RUN_STATUS"
