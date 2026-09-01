#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Run IOS-XE commands on a Catalyst 9300 over SSH.
# Usage:  echo "show version" | lab/device-run.sh <device-ip>
#         lab/device-run.sh <device-ip> <<'EOF'
#         show clock
#         show app-hosting list
#         EOF
# Commands are read from stdin. `terminal length 0` is prepended automatically.
# Password from $DEVICE_PASS (required — export it or 'source' creds/); user from $DEVICE_USER (required; export it or 'source' creds/).
set -uo pipefail
HOST="${1:?usage: device-run.sh <device-ip>  (commands on stdin)}"
DEVICE_USER="${DEVICE_USER:?set DEVICE_USER (device login user; export it or 'source' creds/)}"
export SSHPASS="${DEVICE_PASS:?set DEVICE_PASS (export it or 'source' your gitignored creds file)}"

CMDS="$(cat)"
DEVICE_ENABLE="${DEVICE_ENABLE:-$DEVICE_PASS}"

# Never write a line into an IOS session that is not a valid command in the
# mode we are actually in. A login that lands at `#` is already privileged, so
# `enable` is a no-op and the password line after it is executed as an EXEC
# command; IOS then tries to resolve it as a hostname, and where that lookup
# black-holes instead of failing fast it blocks for ~45 s. Measured 2026-09-01
# on the lab fleet, identical sessions, no config difference between the boxes:
#
#     100.90.168.114   3.06 s clean / 3.19 s with the pair   (+0.13 s)
#     100.90.170.101   3.41 s clean / 51.79 s with the pair   (+48.4 s)
#
# The .168 segment is fast only because something there answers the default
# 255.255.255.255 broadcast; NEITHER box has `no ip domain lookup`, and adding
# it would only hide this. So the fix is to stop typing the wrong line.
#
# Default: send NOTHING. `enable` goes out only for a device already known to
# need it, and then the password IS a valid answer to the prompt `enable` is
# about to raise -- correct by construction rather than by luck of the segment.
#
# This inverts the previous cache, which defaulted to sending and learned to
# stop: that still paid one full stall per device on first contact, and being
# in /tmp it re-armed on every container restart (measured: all 32 devices of
# the 2026-09-01 06:49 wave paid it, because the container had restarted at
# 06:27). The marker filename changed with the meaning so a stale file from the
# old scheme can never be read as its opposite.
#
# The learning step reads the prompt IOS itself emitted, never our own echo --
# a `>` before our first command means we ran at user EXEC and this device does
# need enable. It self-corrects in both directions, so a device that gains or
# loses an enable requirement is picked up on the next call. A device that
# genuinely needs enable fails its first session LOUDLY (its commands ran
# unprivileged) and succeeds on the retry -- fail-closed, and no stray token
# either way. IRIS_DEVICE_ENABLE_ALWAYS=1 forces the old unconditional pair.
NEEDS_ENABLE="${TMPDIR:-/tmp}/iris-needsenable-$(id -u)-${DEVICE_USER}-${HOST}"
SEND_ENABLE=0
if [ "${IRIS_DEVICE_ENABLE_ALWAYS:-0}" = "1" ] || [ -f "$NEEDS_ENABLE" ]; then
  SEND_ENABLE=1
fi
OUT_COPY="$(mktemp "${TMPDIR:-/tmp}/iris-run.XXXXXX")"

{
  if [ "$SEND_ENABLE" = "1" ]; then
    printf 'enable\n'
    printf '%s\n' "$DEVICE_ENABLE"
  fi
  printf 'terminal length 0\n'
  printf '%s\n' "$CMDS"
  printf 'exit\n'
} | sshpass -e ssh -tt \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
      -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 \
      -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
      -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc \
      "${DEVICE_USER}@${HOST}" 2>/dev/null \
  | perl -pe '
      s/\r$//;
      for my $secret (grep { defined && length } @ENV{qw(DEVICE_PASS DEVICE_ENABLE)}) {
        s/\Q$secret\E/[REDACTED]/g;
      }
    ' \
  | tee "$OUT_COPY"
RUN_STATUS=$?

# Learn from the prompt IOS echoed alongside our own commands. `tee` keeps the
# caller's output streaming; only this bookkeeping reads the copy.
if [ "$SEND_ENABLE" = "0" ]; then
  # "sw1>terminal length 0" -- we ran at USER exec, so this device really does
  # need enable. Remember it; the next call sends the pair, and there the
  # password is answering a prompt that will actually appear.
  grep -qE '>[[:space:]]*terminal length 0' "$OUT_COPY" && : > "$NEEDS_ENABLE"
else
  # "sw1#enable" -- already privileged after all, so stop sending the pair.
  grep -qE '#[[:space:]]*enable[[:space:]]*$' "$OUT_COPY" && rm -f "$NEEDS_ENABLE"
fi

# Guard, not a test: this is the fingerprint IOS leaves when we typed something
# that was not a command in the current mode, and it is the only direct
# evidence of the whole bug class. Warn rather than fail -- one known site
# remains (the bare `y` after `guestshell destroy`, which can only be fixed by
# reading the prompt in-session) and a hard failure there would break
# re-onboard. Several callers redirect stderr, so this is a floor, not a net.
if grep -qE '% (Bad IP address or host name|Unknown command or computer name)' \
     "$OUT_COPY"; then
  echo "  WARNING: $HOST resolved one of our lines as a hostname -- a line was" \
       "sent that is not a valid command in the current mode (this costs ~45 s" \
       "per occurrence on a segment where DNS black-holes)" >&2
fi
rm -f "$OUT_COPY"
exit "$RUN_STATUS"
