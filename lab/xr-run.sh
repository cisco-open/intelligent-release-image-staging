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
set -uo pipefail
HOST="${1:?usage: xr-run.sh <device-ip>  (commands on stdin)}"
DEVICE_USER="${DEVICE_USER:?set DEVICE_USER (device login user; export it or 'source' creds/)}"
export SSHPASS="${DEVICE_PASS:?set DEVICE_PASS (export it or 'source' your gitignored creds file)}"

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

{
  printf 'terminal length 0\n'
  printf '%s\n' "$GUARDED_CMDS"
  printf 'exit\n'
} | sshpass -e ssh -tt \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
      "${DEVICE_USER}@${HOST}" 2>/dev/null \
  | perl -pe '
      s/\r$//;
      for my $secret (grep { defined && length } $ENV{DEVICE_PASS}) {
        s/\Q$secret\E/[REDACTED]/g;
      }
    '
