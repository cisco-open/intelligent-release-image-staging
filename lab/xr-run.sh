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
# wall-clock bound of IRIS_XR_SESSION_TIMEOUT seconds (default 900),
# env-overridable; set it to 0 to disable the bound entirely (lab debugging
# escape hatch). GNU coreutils `timeout` is not assumed present: this repo's
# bats suite runs on Darwin, which ships neither `timeout` nor `gtimeout` by
# default, and nothing else in this tree depends on it -- so the bound below
# is a small portable watchdog (background + kill) instead of a `timeout`
# invocation. On timeout it reports rc 124, matching GNU timeout's
# convention, so callers that already treat a nonzero rc as step failure
# need no changes.
set -uo pipefail
HOST="${1:?usage: xr-run.sh <device-ip>  (commands on stdin)}"
DEVICE_USER="${DEVICE_USER:?set DEVICE_USER (device login user; export it or 'source' creds/)}"
export SSHPASS="${DEVICE_PASS:?set DEVICE_PASS (export it or 'source' your gitignored creds file)}"
SESSION_TIMEOUT="${IRIS_XR_SESSION_TIMEOUT:-900}"

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
  sshpass -e ssh -tt \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
    "${DEVICE_USER}@${HOST}" 2>/dev/null
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

  local fired_marker
  fired_marker="$(mktemp "${TMPDIR:-/tmp}/iris-xr-run-timeout.XXXXXX")"
  printf '0' > "$fired_marker"

  # `sshpass` wraps `ssh` (a child process of its own, feeding it the
  # password over a pty); a plain `kill $ssh_pid` on timeout would only
  # reach sshpass itself, and if sshpass has no SIGTERM handler of its own
  # (typical for a small wrapper) the kernel terminates it immediately even
  # mid-syscall, orphaning the ssh child rather than killing it. An orphan
  # holding the router's still-open socket -- and this pipeline's stdout --
  # would recreate the exact unbounded hang this task exists to close.
  # `set -m` for just this one background launch puts the whole sshpass+ssh
  # job in its own process group, so a negative-PID kill below reaches every
  # descendant, not only the direct child; job control is switched back off
  # immediately after so it doesn't affect anything else in the script.
  set -m
  xr_run_ssh &
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

  wait "$ssh_pid"
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
      s/\r$//;
      for my $secret (grep { defined && length } $ENV{DEVICE_PASS}) {
        s/\Q$secret\E/[REDACTED]/g;
      }
    '
