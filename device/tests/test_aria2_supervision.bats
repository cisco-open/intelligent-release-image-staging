#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# The container supervisors (device/iox/entrypoint.sh for IE3x00/C9k app
# hosting, device/xr/entrypoint.sh for the Cisco 8000 appmgr container) own
# aria2c by the exact PID of the child they launched: no pgrep, no pkill, no
# process-name matching anywhere. That is what lets both images ship without
# procps. Static shape checks here, plus a functional pass that drives the
# REAL supervisor functions (extracted from each script) with a stub aria2c
# under /bin/sh -- dash on Debian, the container's own /bin/sh.

setup() {
  DEVICE="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  ENTRYPOINTS="$DEVICE/iox/entrypoint.sh $DEVICE/xr/entrypoint.sh"
  DOCKERFILES="$DEVICE/iox/Dockerfile $DEVICE/xr/Dockerfile"
  PROBE="$BATS_TEST_DIRNAME/aria2_supervision_probe.sh"
}

# The script with its comments stripped: the comments are allowed to explain
# what pgrep/pkill and --daemon used to do; the code is not allowed to use them.
_code() { sed 's/[[:space:]]*#.*$//' "$1"; }

@test "neither container entrypoint matches processes by name" {
  for ep in $ENTRYPOINTS; do
    if _code "$ep" | grep -qE 'pgrep|pkill|killall|pidof'; then
      echo "process-name matching in $ep:"; _code "$ep" | grep -nE 'pgrep|pkill|killall|pidof'
      return 1
    fi
  done
}

@test "neither container image installs procps" {
  for df in $DOCKERFILES; do
    # the package-install line: apt on the Debian IOx image, apk on the Alpine XR image
    run grep -E 'apt-get install|^RUN apk add' "$df"
    [ "$status" -eq 0 ] || return 1
    [[ "$output" != *procps* ]] || { echo "procps still installed by $df"; return 1; }
    # the comment that once justified it must not survive either
    ! grep -q 'procps: pkill/pgrep' "$df" || return 1
  done
}

@test "aria2c runs as a tracked child of PID 1 with daemon-equivalent stdio" {
  # No --daemon=true (a double fork + setsid would put aria2c out of reach);
  # the PID is recorded from $!; stdio goes to /dev/null exactly as daemon
  # mode's daemon(0,0) did -- aria2c prints a readout line per second to a
  # pipe as readily as to a terminal while anything downloads OR seeds.
  for ep in $ENTRYPOINTS; do
    ! _code "$ep" | grep -q -- '--daemon' || return 1
    grep -q 'ARIA2_PID=\$!' "$ep" || return 1
    grep -q '</dev/null >/dev/null 2>&1 &' "$ep" || return 1
    grep -q '^stop_aria2c()' "$ep" || return 1
    grep -q 'wait "\$ARIA2_PID"' "$ep" || return 1
  done
}

@test "the supervisor loop keys on aria2_alive AND rpc_healthy" {
  for ep in $ENTRYPOINTS; do
    cond="$(awk '/^  if \[ "\$want" != "\$cur" \]/{found=1} found{print; if(/; then/) exit}' "$ep")"
    [ -n "$cond" ] || { echo "loop condition not found in $ep"; return 1; }
    [[ "$cond" == *'! aria2_alive'* ]] || return 1
    [[ "$cond" == *'! rpc_healthy'* ]] || return 1
  done
}

@test "stop_agent tears the aria2c child down before exiting" {
  for ep in $ENTRYPOINTS; do
    awk '/^stop_agent\(\)/,/^}/' "$ep" | grep -q 'stop_aria2c' || return 1
  done
}

@test "both entrypoints parse under dash (the container /bin/sh)" {
  command -v dash >/dev/null 2>&1 || skip "dash not installed"
  for ep in $ENTRYPOINTS; do
    run dash -n "$ep"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  done
}

@test "supervisor functions: crash, stop, TERM, recycled PID, missing binary (real functions, stub aria2c)" {
  # See aria2_supervision_probe.sh for the individual checks: a kill -9'd
  # child reads dead and is reaped; a STOPped child is replaced via TERM+CONT
  # inside the KILL bound; a live process with a different starttime is never
  # signalled; a launch with no binary neither hangs nor aborts the caller.
  for ep in $ENTRYPOINTS; do
    run sh "$PROBE" "$ep" "$BATS_TEST_TMPDIR"
    echo "$output"
    [ "$status" -eq 0 ] || return 1
    [[ "$output" == *"PROBE OK"* ]] || return 1
  done
}
