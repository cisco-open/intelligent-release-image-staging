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
#
# Host identity: the peer is verified per lab/iris-ssh-policy.sh --
# IRIS_SSH_HOST_KEY (pin one key), IRIS_SSH_KNOWN_HOSTS (strict against a
# file), or by default accept-new against a persistent known_hosts under
# $IRIS_SSH_STATE_DIR (default $IRIS_STATE/ssh). Legacy SHA-1/CBC/ssh-rsa
# algorithms are opt-in with IRIS_SSH_LEGACY=1. ssh's own diagnostics are
# forwarded (redacted) on stderr so a caller can tell "connection refused"
# from "no matching KEX" from "host key changed".
set -uo pipefail
HOST="${1:?usage: device-run.sh <device-ip>  (commands on stdin)}"
DEVICE_USER="${DEVICE_USER:?set DEVICE_USER (device login user; export it or 'source' creds/)}"
export SSHPASS="${DEVICE_PASS:?set DEVICE_PASS (export it or 'source' your gitignored creds file)}"
LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lab/iris-ssh-policy.sh
. "$LAB_DIR/iris-ssh-policy.sh" || { echo "device-run.sh: cannot load $LAB_DIR/iris-ssh-policy.sh" >&2; exit 1; }
iris_ssh_policy "$HOST" || exit 1

CMDS="$(cat)"

# Refuse the interactive install-subsystem commands. They print a file list
# and wait on a "[y/n]" prompt, and this transport cannot answer one: commands
# arrive on stdin ahead of the prompt, so the reply lands nowhere, the session
# tears down while the operation is still open, and the switch then refuses
# every later attempt with "cannot start new install operation, some operation
# is already running" -- with NO entry in `show install log` to explain it.
# Recovery is a reload. stk03-fiab2 sat wedged that way from 2026-08-28 until
# 2026-09-03, and the signature reproduced on the next scripted attempt.
#
# IRIS itself never does this: device/agent/iris_agent.py's reclaim() drives
# `install remove inactive` from an EEM applet with `pattern "[y/n]"` and a
# following "y", precisely because a raw prompt cannot be answered from here.
# Use that idiom, or a real terminal, and read `show install ...` instead when
# you only need to look.
if printf '%s' "$CMDS" | grep -qiE '^[[:space:]]*(do[[:space:]]+)?install[[:space:]]+(remove|add|activate|deactivate|commit|abort|rollback)\b'; then
  echo "device-run.sh: refusing an interactive install-subsystem command." >&2
  echo "  This transport feeds stdin ahead of the [y/n] prompt, so the answer" >&2
  echo "  is lost and the session drops holding the install lock. The switch" >&2
  echo "  then refuses every later install operation until it is reloaded." >&2
  echo "  Read-only 'show install ...' commands are fine and are not blocked." >&2
  echo "  To actually run one, drive it from an EEM applet with" >&2
  echo "  pattern \"[y/n]\" (see reclaim() in device/agent/iris_agent.py)," >&2
  echo "  or run it at a real terminal." >&2
  exit 2
fi
DEVICE_ENABLE="${DEVICE_ENABLE:-$DEVICE_PASS}"

# Never write a line into an IOS session that is not a valid command in the
# mode we are actually in. A login that lands at `#` is already privileged, so
# `enable` is a no-op and the password line after it is executed as an EXEC
# command; IOS then tries to resolve it as a hostname, and where that lookup
# black-holes instead of failing fast it blocks for ~45 s. Measured 2026-09-01
# on the lab fleet, identical sessions, no config difference between the boxes:
#
#     192.0.2.114     3.06 s clean / 3.19 s with the pair   (+0.13 s)
#     203.0.113.101   3.41 s clean / 51.79 s with the pair   (+48.4 s)
#
# (Addresses here and below are RFC 5737 documentation stand-ins for the two
# lab segments; only the split between them matters.)
#
# The first segment is fast only because something there answers the default
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
#
# The marker lives beside the persistent known_hosts (a 0700 directory owned
# by us), not under a world-writable /tmp name any local user could pre-create
# to make the next session type the enable secret as an EXEC command -- and
# so that a container restart no longer forgets which devices need it.
NEEDS_ENABLE_DIR="$(dirname "$IRIS_SSH_KNOWN_HOSTS_FILE")/needs-enable"
mkdir -p "$NEEDS_ENABLE_DIR" 2>/dev/null && chmod 700 "$NEEDS_ENABLE_DIR" 2>/dev/null
NEEDS_ENABLE="$NEEDS_ENABLE_DIR/${DEVICE_USER}@${HOST}"
SEND_ENABLE=0
if [ "${IRIS_DEVICE_ENABLE_ALWAYS:-0}" = "1" ] || [ -f "$NEEDS_ENABLE" ]; then
  SEND_ENABLE=1
fi
OUT_COPY="$(mktemp "${TMPDIR:-/tmp}/iris-run.XXXXXX")" \
  || { echo "device-run.sh: mktemp failed creating the transcript copy" >&2; exit 1; }
ERR_COPY="$(mktemp "${TMPDIR:-/tmp}/iris-run-err.XXXXXX")" \
  || { rm -f "$OUT_COPY"; echo "device-run.sh: mktemp failed creating the ssh diagnostics capture -- refusing to run with ssh errors discarded" >&2; exit 1; }

{
  if [ "$SEND_ENABLE" = "1" ]; then
    printf 'enable\n'
    printf '%s\n' "$DEVICE_ENABLE"
  fi
  printf 'terminal length 0\n'
  printf '%s\n' "$CMDS"
  printf 'exit\n'
} | sshpass -e ssh -tt -o ConnectTimeout=15 "${IRIS_SSH_OPTS[@]}" \
      "${DEVICE_USER}@${HOST}" 2>"$ERR_COPY" \
  | perl -pe '
      s/\r$//;
      for my $secret (grep { defined && length } @ENV{qw(DEVICE_PASS DEVICE_ENABLE)}) {
        s/\Q$secret\E/[REDACTED]/g;
      }
    ' \
  | tee "$OUT_COPY"
RUN_STATUS=$?
iris_ssh_cleanup

# ssh's own diagnostics, redacted, on OUR stderr -- never discarded. This is
# the only place "connection refused", "no matching key exchange method",
# "permission denied" and "host key changed" can be told apart.
if [ -s "$ERR_COPY" ]; then
  perl -pe '
      s/\r$//;
      for my $secret (grep { defined && length } @ENV{qw(DEVICE_PASS DEVICE_ENABLE)}) {
        s/\Q$secret\E/[REDACTED]/g;
      }
    ' "$ERR_COPY" | sed 's/^/ssh: /' >&2
  iris_ssh_explain "$ERR_COPY" "$HOST"
fi
rm -f "$ERR_COPY"

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
