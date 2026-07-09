#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Run ONE program inside Guest Shell on a device and capture its output.
# Usage: lab/gsrun.sh <device-ip> '<program> <args...>'
#
# Hardware-learned constraints:
#  * guestshell run needs a live PTY -> drive it with expect (not piped SSH).
#  * IOS strips quotes, so `bash -c "a; b"` is broken -> pass a SINGLE program
#    invocation only (e.g. 'aria2c --version', 'chmod +x /flash/../x',
#    'ip -4 addr show dev eth0', '/flash/..//guestshell-start.sh').
#    For multi-step logic, stage a script file and run `bash /flash/..//x.sh`.
#  * NEVER include '?' — IOS intercepts it as context-help.
# Output framing: capture between the command echo and the returned IOS prompt.
set -uo pipefail
export HOST="${1:?usage: gsrun.sh <device-ip> '<program> <args>'}"
export IRISCMD="${2:?usage: gsrun.sh <device-ip> '<program> <args>'}"
export DEVICE_USER="${DEVICE_USER:?set DEVICE_USER (device login user)}"
export DEVICE_PASS="${DEVICE_PASS:?set DEVICE_PASS (export it or 'source' your gitignored creds file)}"
export DEVICE_ENABLE="${DEVICE_ENABLE:-$DEVICE_PASS}"
export GS_TIMEOUT="${GS_TIMEOUT:-200}"

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
  -re {[Pp]assword:}               { send "$env(DEVICE_ENABLE)\r"; exp_continue }
  -re {>\s*$}                      { send "enable\r"; exp_continue }
  -re {([A-Za-z0-9_.\-]+)#\s*$}    { set prompt $expect_out(1,string) }
  timeout                          { puts "\nTIMEOUT_LOGIN"; exit 2 }
}
send "terminal length 0\r"
expect -re "$prompt#"
send -- "guestshell run $env(IRISCMD)\r"
expect -re {guestshell run}        ;# consume the echoed command line
expect {
  -re "$prompt#" { }
  timeout        { puts "\nTIMEOUT_CMD" }
}
send "exit\r"
expect eof
EOF
