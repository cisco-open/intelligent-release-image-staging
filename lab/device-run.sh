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

# Do not send the enable password to a device that is already in enable mode.
# These logins land at `#`, so `enable` is a no-op and the password line that
# follows is executed as an EXEC command. IOS then tries to resolve it as a
# hostname, and where that lookup black-holes instead of failing fast it blocks
# for ~40 s: measured on a lab C8000v, an identical session cost 3.13 s without
# these two lines and 43.32 s with them. router-uninstall.sh opens 17 sessions,
# so this alone was ~11 minutes of a teardown -- and it is why installs
# outlived the artifact server's staging TTL.
#
# Privilege is learned from the prompt IOS echoes back and cached per
# user+device: the first call still sends enable (nothing is known yet), later
# calls skip it. The cache self-corrects in both directions, so a device that
# starts requiring enable again -- after a reload or a config change -- is
# picked up on the next call. IRIS_DEVICE_ENABLE_ALWAYS=1 restores the old
# unconditional behaviour.
PRIV_CACHE="${TMPDIR:-/tmp}/iris-priv-$(id -u)-${DEVICE_USER}-${HOST}"
SEND_ENABLE=1
if [ "${IRIS_DEVICE_ENABLE_ALWAYS:-0}" != "1" ] && [ -f "$PRIV_CACHE" ]; then
  SEND_ENABLE=0
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

# Learn from the prompt IOS echoed alongside our own commands. `tee` keeps the
# caller's output streaming; only this bookkeeping reads the copy.
if [ "$SEND_ENABLE" = "1" ]; then
  # "sw1#enable" -- the device was ALREADY privileged, so stop paying for it.
  grep -qE '#[[:space:]]*enable[[:space:]]*$' "$OUT_COPY" && : > "$PRIV_CACHE"
else
  # "sw1>terminal length 0" -- it wants enable after all; forget what we cached.
  grep -qE '>[[:space:]]*terminal length 0' "$OUT_COPY" && rm -f "$PRIV_CACHE"
fi
rm -f "$OUT_COPY"
