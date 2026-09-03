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

# ---------------------------------------------------------------------------
# Resume integrity (#66): a resumed transfer must re-hash what is on flash
#
# Without --check-integrity aria2 trusts the piece map in the .aria2 control
# file, so a completed piece that rotted on disk survives the resume, the
# torrent reports complete, and the staged image carries the wrong SHA-256 --
# caught by the agent's whole-image hash only after the entire remaining
# transfer, and repaired only by re-staging the whole image. Reproduced on the
# real binaries: 128 MiB torrent, one 256-byte corruption inside completed
# piece 0, resume without the flag -> "complete" + sha256 mismatch; with it ->
# 1 MiB dropped, re-fetched, sha256 match.
# ---------------------------------------------------------------------------

# Launch aria2c through the entrypoint's REAL start_aria2c with a stub binary
# that records its argv, then tear it down through the real stop_aria2c.
_recorded_launch_argv() {           # $1 = entrypoint, $2 = file to record into
  local ep="$1" argv="$2" d="$BATS_TEST_TMPDIR/launch"
  rm -rf "$d"; mkdir -p "$d"
  cat > "$d/aria2c-stub" <<'STUB'
#!/bin/sh
# Write atomically: the harness polls for a non-empty file.
printf '%s\n' "$@" > "$ARGV_FILE.part" && mv "$ARGV_FILE.part" "$ARGV_FILE"
exec sleep 30
STUB
  cat > "$d/harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
eval "$(awk '/^(proc_stat|aria2_alive|stop_aria2c|start_aria2c)\(\)/,/^}/' "$1")"
ARIA2="$2"; RPC_PORT=6800; MAX_PEERS=10; STAGE_DIR="$3"; HOOK=""
ARIA2_PID=""; ARIA2_START=""
start_aria2c s1 >/dev/null
i=0
while [ ! -s "$ARGV_FILE" ] && [ "$i" -lt 200 ]; do sleep 0.05; i=$((i + 1)); done
stop_aria2c
[ -s "$ARGV_FILE" ]
HARNESS
  chmod +x "$d/aria2c-stub" "$d/harness.sh"
  ARGV_FILE="$argv" sh "$d/harness.sh" "$ep" "$d/aria2c-stub" "$d"
}

@test "both container launches re-verify the bytes already on disk (--check-integrity)" {
  for ep in $ENTRYPOINTS; do
    argv="$BATS_TEST_TMPDIR/argv.txt"
    rm -f "$argv"
    run _recorded_launch_argv "$ep" "$argv"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    run grep -qx -- '--check-integrity=true' "$argv"
    [ "$status" -eq 0 ] || { echo "no --check-integrity in $ep launch:"; cat "$argv"; return 1; }
    # ...and the completed-file case stays free: --bt-seed-unverified marks a
    # finished download done and aria2 skips validation for it, so a device
    # seeding its staged images does not re-hash them on every relaunch.
    run grep -qx -- '--bt-seed-unverified=true' "$argv"
    [ "$status" -eq 0 ] || { echo "--bt-seed-unverified lost in $ep"; cat "$argv"; return 1; }
  done
}

# ---------------------------------------------------------------------------
# Health, not just an answer (#77): rpc_healthy must tell BUSY from DEAD
#
# aria2c built without c-ares resolves tracker hostnames with a blocking
# getaddrinfo() on its event-loop thread, so one announce against a slow
# resolver freezes the daemon -- RPC included -- for as long as the resolver
# takes (5.03 s measured). Against a single 3 s probe that read as "dead" and
# this supervisor killed and relaunched a healthy daemon twice in 300 s,
# dropping its in-flight download each time.
# ---------------------------------------------------------------------------

# Drive the entrypoint's REAL rpc_probe/rpc_healthy (and its real timeout
# values) with a stub curl that hands out a scripted sequence of exit codes.
# Prints the number of probes made; exits with rpc_healthy's own verdict.
_health_verdict() {                 # $1 = entrypoint, $2.. = curl exit codes
  local ep="$1"; shift
  local d="$BATS_TEST_TMPDIR/health"
  rm -rf "$d"; mkdir -p "$d/bin"
  printf '%s\n' "$@" > "$d/codes"
  cat > "$d/bin/curl" <<'CURL'
#!/bin/sh
n=$(cat "$CURL_STATE" 2>/dev/null || echo 0)
n=$((n + 1)); echo "$n" > "$CURL_STATE"
printf '%s\n' "$*" >> "$CURL_LOG"
rc="$(sed -n "${n}p" "$CURL_CODES")"
exit "${rc:-0}"
CURL
  cat > "$d/harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
# The functions AND the real timeout values, so a regression back to an
# inline --max-time 3 fails here rather than silently testing nothing.
eval "$(awk '/^(rpc_probe|rpc_healthy)\(\)/,/^}/' "$1")"
eval "$(awk '/^RPC_CONNECT_TIMEOUT=|^RPC_HEALTH_TIMEOUT=/' "$1")"
RPC_PORT=6800
rc=0
rpc_healthy sekrit || rc=$?
wc -l < "$CURL_LOG" | tr -d ' '
exit "$rc"
HARNESS
  chmod +x "$d/bin/curl" "$d/harness.sh"
  : > "$d/log"
  PATH="$d/bin:$PATH" CURL_STATE="$d/state" CURL_LOG="$d/log" CURL_CODES="$d/codes" \
    sh "$d/harness.sh" "$ep"
}

@test "a daemon that answers late is NOT condemned on the strength of one late probe" {
  # curl 28 (no answer inside the bound) then 0: a resolver stall that ended.
  for ep in $ENTRYPOINTS; do
    run _health_verdict "$ep" 28 0
    [ "$status" -eq 0 ] || { echo "$ep condemned a healthy daemon: $output"; return 1; }
    [ "$output" -eq 2 ] || { echo "$ep made $output probes, expected 2"; return 1; }
  done
}

@test "a refused connection is condemned at once -- nothing is listening" {
  # curl 7 on loopback means no listener: a verdict, not a suspicion. The
  # 2026-08-20 deadlock was a stale daemon left alive, so this must not wait
  # for a confirming probe.
  for ep in $ENTRYPOINTS; do
    run _health_verdict "$ep" 7 0
    [ "$status" -eq 1 ] || { echo "$ep did not condemn a refused port: $output"; return 1; }
    [ "$output" -eq 1 ] || { echo "$ep made $output probes for a refused port, expected 1"; return 1; }
  done
}

@test "a daemon that fails the confirming probe too is condemned" {
  for ep in $ENTRYPOINTS; do
    run _health_verdict "$ep" 28 28
    [ "$status" -eq 1 ] || { echo "$ep left a wedged daemon running: $output"; return 1; }
    [ "$output" -eq 2 ] || { echo "$ep made $output probes, expected 2"; return 1; }
  done
}

@test "the health probe waits longer than the worst measured resolver stall" {
  # 5.03 s measured with a blackholed forwarder; glibc's default 5 s x 2
  # attempts is the ceiling to design for. Anything at or below 5 s makes a
  # healthy-but-resolving daemon look dead again.
  for ep in $ENTRYPOINTS; do
    t="$(sed -n 's/^RPC_HEALTH_TIMEOUT=//p' "$ep")"
    [ -n "$t" ] || { echo "$ep has no RPC_HEALTH_TIMEOUT"; return 1; }
    [ "$t" -gt 5 ] || { echo "$ep health timeout is ${t}s, too short for a 5 s resolver stall"; return 1; }
    # and the "is anything listening" question is asked separately
    grep -q -- '--connect-timeout "\$RPC_CONNECT_TIMEOUT"' "$ep" || return 1
  done
}
