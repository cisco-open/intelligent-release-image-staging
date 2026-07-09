#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Reliably `copy <url> flash:<dst>` on a device, answering IOS's prompts.
# Usage: lab/device-copy.sh <device-ip> <http-url> <flash-dest-path>
# Handles both new files (one "Destination filename?" prompt) and existing files
# (adds an "over write? [confirm]" prompt) by waiting for each prompt via expect.
set -uo pipefail
export HOST="${1:?usage: device-copy.sh <ip> <url> <flash-dest>}"
export URL="${2:?usage: device-copy.sh <ip> <url> <flash-dest>}"
export DST="${3:?usage: device-copy.sh <ip> <url> <flash-dest>}"
export DEVICE_USER="${DEVICE_USER:?set DEVICE_USER (device login user)}"
export DEVICE_PASS="${DEVICE_PASS:?set DEVICE_PASS (export it or 'source' your gitignored creds file)}"
export DEVICE_ENABLE="${DEVICE_ENABLE:-$DEVICE_PASS}"
export GS_TIMEOUT="${GS_TIMEOUT:-120}"

expect <<'EOF'
set timeout $env(GS_TIMEOUT)
log_user 1
spawn sshpass -p $env(DEVICE_PASS) ssh -tt \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
  -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 \
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
  -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc $env(DEVICE_USER)@$env(HOST)
set prompt ""
expect {
  -re {[Pp]assword:}            { send "$env(DEVICE_ENABLE)\r"; exp_continue }
  -re {>\s*$}                   { send "enable\r"; exp_continue }
  -re {([A-Za-z0-9_.\-]+)#\s*$} { set prompt $expect_out(1,string) }
  timeout                       { puts "\nTIMEOUT_LOGIN"; exit 2 }
}
send "terminal length 0\r"
expect -re "$prompt#"
send -- "copy $env(URL) flash:$env(DST)\r"
expect {
  -re {Destination filename}    { send "\r"; exp_continue }
  -re {[Oo]ver ?write\?}        { send "\r"; exp_continue }
  -re {bytes copied}            { }
  -re {Error|%Error|No such}    { puts "\nCOPY_ERROR"; exit 3 }
  timeout                       { puts "\nTIMEOUT_COPY"; exit 4 }
}
expect -re "$prompt#"
send "exit\r"
expect eof
EOF
