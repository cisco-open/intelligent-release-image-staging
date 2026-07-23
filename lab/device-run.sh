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
{
  printf 'enable\n'
  printf '%s\n' "$DEVICE_ENABLE"
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
    '
