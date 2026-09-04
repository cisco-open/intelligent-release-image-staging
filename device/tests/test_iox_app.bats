#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for the shared container entrypoint plus device/iox/{install.sh,build.sh}
# Findings addressed:
#   #1 (CRITICAL)  install.sh run-opts must pass IRIS_DEVICE_SSH_HOST / IRIS_DEVICE_SSH_USER
#   #2 (IMPORTANT) entrypoint.sh supervisor must restart a crashed aria2c
#   #3 (IMPORTANT) the canonical build must be deployment-neutral
#   #4 (RE-VERIFY) secret-rotation ordering in entrypoint.sh — verdict documented below

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
setup() {
  IOX_DIR="$BATS_TEST_DIRNAME/../iox"
  INSTALL="$IOX_DIR/install.sh"
  ENTRYPOINT="$BATS_TEST_DIRNAME/../container/entrypoint.sh"
  BUILD="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)/tools/build-device-image.sh"

  export DEVICE_IP=192.0.2.1 VLAN=100 \
    SVI_IP=192.0.2.253 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.254 \
    GW_IP=192.0.2.253 \
    CATALOG_TOKEN=tok123 DEVICE_ID=switch-01 \
    STAGE_HOST=198.51.100.1 DEVICE_SSH_PASS=p4ss \
    DEVICE_SSH_USER=iosadmin \
    CATALOG_URL=https://198.51.100.1:8443 TARGET_FS=sdflash:
}

# Extract and evaluate only the variable defaults + appid_block function from
# install.sh, without triggering the imperative install steps.  This is the
# cleanest way to unit-test the IOS config block without a live device.
_appid_block_output() {
  local svi="${1:-$SVI_IP}" user="${2:-$DEVICE_SSH_USER}" target="${3:-$TARGET_FS}"
  # Re-export with overrides so the heredoc substitutions inside appid_block pick
  # them up correctly. For routed the app SSH host is the IRIS SVI, so
  # IOS_SSH_HOST mirrors SVI_IP (the routed default set in install.sh's case block).
  SVI_IP="$svi" IOS_SSH_HOST="$svi" DEVICE_SSH_USER="$user" TARGET_FS="$target" \
  bash -c '
    # Source only the variable defaults (lines that assign defaults not the
    # mandatory parameter checks) and the appid_block() function body.
    eval "$(awk "/^CATALOG_URL=|^APP_INTF=|^GW_IP=|^CPU=|^MEM=|^DISK=|^PKG=|^DEVICE_SSH_USER=|^TARGET_FS=|^IRIS_TELEMETRY=|^APPID=/" "'"$INSTALL"'")"
    eval "$(awk "/^appid_block\(\)/,/^\}/" "'"$INSTALL"'")"
    appid_block
  '
}

# ---------------------------------------------------------------------------
# Finding #1 — install.sh run-opts must carry IRIS_DEVICE_SSH_HOST / USER
# ---------------------------------------------------------------------------

@test "install.sh run-opts include IRIS_DEVICE_SSH_HOST set to SVI_IP" {
  run _appid_block_output "$SVI_IP" "$DEVICE_SSH_USER"
  [ "$status" -eq 0 ]
  [[ "$output" == *"-e IRIS_DEVICE_SSH_HOST=$SVI_IP"* ]]
}

@test "install.sh run-opts include IRIS_DEVICE_SSH_USER" {
  run _appid_block_output "$SVI_IP" "$DEVICE_SSH_USER"
  [ "$status" -eq 0 ]
  [[ "$output" == *"-e IRIS_DEVICE_SSH_USER=$DEVICE_SSH_USER"* ]]
}

@test "install.sh run-opts IRIS_DEVICE_SSH_HOST tracks SVI_IP not a hardcoded literal" {
  # Use a distinct SVI_IP to prove the value isn't hardcoded
  run _appid_block_output "10.20.30.40" "iosadmin"
  [ "$status" -eq 0 ]
  [[ "$output" == *"-e IRIS_DEVICE_SSH_HOST=10.20.30.40"* ]]
  [[ "$output" != *"198.51.100.253"* ]]
}

@test "install.sh passes the selected IOS target filesystem to the app" {
  run _appid_block_output "$SVI_IP" "$DEVICE_SSH_USER" "bootflash:"
  [ "$status" -eq 0 ]
  [[ "$output" == *"-e IRIS_TARGET_FS=bootflash:"* ]]
}

@test "install.sh uses one numbered run-opts line per environment variable" {
  run _appid_block_output
  [ "$status" -eq 0 ]
  [ "$(printf '%s\n' "$output" | grep -c '^  run-opts ' | tr -d ' ')" -eq 11 ]
  ! printf '%s\n' "$output" | grep -Eq 'run-opts.* -e .* -e '
}

@test "install.sh explicitly passes the telemetry setting" {
  run _appid_block_output
  [ "$status" -eq 0 ]
  [[ "$output" == *'run-opts 9 "-e IRIS_TELEMETRY=on"'* ]]
}

# ---------------------------------------------------------------------------
# Finding #2 — entrypoint.sh: supervisor must restart a crashed aria2c
# ---------------------------------------------------------------------------

# Run ONE iteration of entrypoint.sh's actual supervisor condition (the real
# if-expression, not a re-implementation) with the real read_secret, proc_stat
# and aria2_alive sourced from the script, start_aria2c stubbed to a call log,
# and $1 evaluated first to set the scenario up (ARIA2_PID / ARIA2_START and a
# rpc_healthy stub). cur already equals the conf's secret, so only the
# scenario can trigger a call. Prints the number of start_aria2c calls.
_loop_cond_calls() {
  local scenario="$1" tmpd conf log cond
  tmpd="$(mktemp -d)"
  conf="$tmpd/iris-agent.conf"; log="$tmpd/calls"
  echo "rpc_secret = mysecret" > "$conf"
  touch "$log"
  # If entrypoint.sh's condition regresses (drops the liveness or the health
  # clause), the tests below fail on the real text. Anchored on the secret
  # comparison so no other `if [` earlier in the script can be picked up.
  cond="$(awk '/^  if \[ "\$want" != "\$cur" \]/{found=1} found{print; if(/; then/) exit}' "$ENTRYPOINT")"
  [ -n "$cond" ] || { echo "loop condition not found in $ENTRYPOINT" >&2; return 1; }
  bash -c '
    set -u
    CONF="'"$conf"'"
    CALL_LOG_FILE="'"$log"'"
    eval "$(awk "/^(read_secret|proc_stat|aria2_alive)\(\)/,/^}/" "'"$ENTRYPOINT"'")"
    # Stub start_aria2c so it logs the call without launching a real daemon.
    start_aria2c() { echo "started:$1" >> "$CALL_LOG_FILE"; }
    ARIA2_PID=""; ARIA2_START=""
    '"$scenario"'
    cur=mysecret
    want="$(read_secret)"
    [ -z "$want" ] && want="iris"
    '"$cond"'
      start_aria2c "$want" && cur="$want"
    fi
  '
  wc -l < "$log" | tr -d ' '
  rm -rf "$tmpd"
}

# The supervisor's own liveness scenario: this very shell stands in for a live
# aria2c child, with its starttime recorded through the real proc_stat.
_ALIVE='ARIA2_PID=$$; proc_stat "$$"; ARIA2_START="$PROC_START"'

@test "entrypoint.sh calls start_aria2c when aria2c is absent even if secret unchanged" {
  # No child recorded -- the state after a crash has been reaped, or before
  # the first launch. Health answers yes, so liveness alone must relaunch.
  run _loop_cond_calls 'rpc_healthy() { return 0; }'
  [ "$status" -eq 0 ]
  [ "$output" -ge 1 ]
}

@test "entrypoint.sh calls start_aria2c when the recorded aria2c has exited" {
  # A child that exited and was reaped: /proc/<pid> is gone, so the recorded
  # PID must read as dead even though the secret is unchanged and health is
  # not consulted.
  run _loop_cond_calls 'sleep 0 & ARIA2_PID=$!; proc_stat "$ARIA2_PID" && ARIA2_START="$PROC_START"; wait "$ARIA2_PID"; rpc_healthy() { return 0; }'
  [ "$status" -eq 0 ]
  [ "$output" -ge 1 ]
}

@test "entrypoint.sh calls start_aria2c when aria2c is alive but not answering RPC" {
  # Liveness alone deadlocked Guest Shell devices in the field (2026-08-20):
  # an aria2c that was running but not serving blocked its own relaunch, so
  # the agent hit ECONNREFUSED on every tick and never reached its first
  # heartbeat. The IOx supervisor had the identical latent fault.
  run _loop_cond_calls "$_ALIVE"'; rpc_healthy() { return 1; }'
  [ "$status" -eq 0 ]
  [ "$output" -ge 1 ]
}

@test "entrypoint.sh leaves a live, healthy aria2c with an unchanged secret alone" {
  # The inverse guard: a healthy daemon must not be bounced every tick.
  run _loop_cond_calls "$_ALIVE"'; rpc_healthy() { return 0; }'
  [ "$status" -eq 0 ]
  [ "$output" -eq 0 ]
}

@test "entrypoint.sh supervisor checks aria2c HEALTH, not just liveness" {
  # Static analysis: the loop body must restart the daemon when it is dead
  # (aria2_alive -- the exact PID it launched, never a process-name match)
  # AND when it is alive but not answering RPC (rpc_healthy).
  grep -q 'aria2_alive' "$ENTRYPOINT"
  grep -q 'rpc_healthy\|jsonrpc' "$ENTRYPOINT"
}

@test "entrypoint.sh tracks agent and sleep children for prompt TERM handling" {
  grep -q 'python3 "\$AGENT" --once &' "$ENTRYPOINT"
  grep -q 'AGENT_PID=\$!' "$ENTRYPOINT"
  # sleep_for (issue #59) replaces a bare "$TICK": every ordinary tick is
  # jittered, and a failed tick backs off -- see next_tick_sleep -- but the
  # tracked-child TERM-handling shape this test guards is unchanged.
  grep -q 'sleep "\$sleep_for" &' "$ENTRYPOINT"
  grep -q 'SLEEP_PID=\$!' "$ENTRYPOINT"
  grep -q 'kill "\$pid"' "$ENTRYPOINT"
  grep -q 'wait "\$pid"' "$ENTRYPOINT"
}

# ---------------------------------------------------------------------------
# Finding #3 / #136 — catalog trust is runtime material, never a build input
# ---------------------------------------------------------------------------

@test "canonical builder has no catalog certificate fetch or fingerprint input" {
  run grep -E 'CATALOG_PEM|iris-catalog\.pem|openssl x509.*fingerprint|curl .*insecure' "$BUILD"
  [ "$status" -ne 0 ]
}

@test "unified image does not copy or default a deployment certificate" {
  dockerfile="$BATS_TEST_DIRNAME/../container/Dockerfile"
  run grep -E '^COPY .*iris-catalog\.pem|IRIS_CATALOG_CA=' "$dockerfile"
  [ "$status" -ne 0 ]
}

@test "build.sh supports arm64 and amd64 IOx images" {
  grep -q 'amd64:x86_64:iris-agent.tgz' "$BUILD"
  grep -q 'arm64:aarch64:iris-agent-arm.tgz' "$BUILD"
  grep -q -- '--platform linux/amd64,linux/arm64' "$BUILD"
}

@test "amd64 package descriptor declares x86_64" {
  grep -q '^  cpuarch: x86_64$' "$IOX_DIR/package-amd64.yaml"
}

@test "unified Dockerfile uses a digest-pinned multi-architecture Python base" {
  # The app is built for BOTH aarch64 (IE3x00) and x86_64 (Catalyst 9000)
  # from one Dockerfile, so the base must be an official multi-arch
  # Alpine keeps both manifests small and the index digest pins the base.
  dockerfile="$BATS_TEST_DIRNAME/../container/Dockerfile"
  grep -qE '^FROM python:3\.12-alpine[0-9.]+@sha256:[0-9a-f]{64}$' "$dockerfile"
  ! grep -qE '^FROM (arm64v8|amd64|i386|arm32v7)/' "$dockerfile"
}

# ---------------------------------------------------------------------------
# IRIS-12-005 -- values that ride inside the quoted run-opts lines are
# validated before anything touches the device (the XR installer already did
# this; the IOx one pasted them blind, IOS dropped the malformed line, and
# the app died on its entrypoint's required-env guard AFTER [1/9] had torn
# down the working app).
# ---------------------------------------------------------------------------

@test "install.sh rejects a DEVICE_SSH_PASS containing a double quote" {
  DEVICE_SSH_PASS='pa"ss' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"DEVICE_SSH_PASS must not contain a double quote, CR, or LF"* ]]
}

@test "install.sh rejects a DEVICE_SSH_PASS containing a newline" {
  DEVICE_SSH_PASS=$'pa\nss' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"DEVICE_SSH_PASS must not contain a double quote, CR, or LF"* ]]
}

@test "install.sh allows whitespace inside DEVICE_SSH_PASS (it stays quoted)" {
  DEVICE_SSH_PASS='pass with spaces' run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "install.sh rejects a CATALOG_TOKEN with a double quote, and whitespace" {
  CATALOG_TOKEN='to"k' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"CATALOG_TOKEN must not contain"* ]] || return 1
  CATALOG_TOKEN='to k' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"CATALOG_TOKEN contains whitespace"* ]]
}

@test "install.sh rejects CATALOG_URL, DEVICE_ID and DEVICE_SSH_USER that would break the run-opts quoting" {
  CATALOG_URL='https://x:8443/"' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"CATALOG_URL"* ]] || return 1
  DEVICE_ID='sw "1"' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"DEVICE_ID"* ]] || return 1
  DEVICE_SSH_USER=$'dn\nac' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"DEVICE_SSH_USER"* ]]
}

# ---------------------------------------------------------------------------
# #123/#124 -- IRIS_LOG must actually reach the container (previously neither
# installer passed it, so the documented opt-in was unreachable on exactly
# the platforms whose entrypoints implement it), validated the same way every
# other value riding inside the quoted run-opts lines already is.
# ---------------------------------------------------------------------------

@test "install.sh defaults IRIS_LOG to off and forwards it in the run-opts" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'run-opts 11 "-e IRIS_LOG=off"'* ]]
}

@test "install.sh forwards an operator's IRIS_LOG=on opt-in in the run-opts" {
  IRIS_LOG=on run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'run-opts 11 "-e IRIS_LOG=on"'* ]]
}

@test "install.sh rejects an IRIS_LOG value that would break the run-opts quoting, and whitespace" {
  IRIS_LOG='on"' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"IRIS_LOG has an invalid boolean value"* ]] || return 1
  IRIS_LOG='on off' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"IRIS_LOG has an invalid boolean value"* ]]
}

@test "install.sh's quoting guard runs before the first device session" {
  # structural: the guard precedes the [1/9] teardown AND the identity probe
  guard="$(grep -n '^_no_quotes_or_newlines DEVICE_SSH_PASS' "$INSTALL" | cut -d: -f1)"
  probe="$(grep -n "printf 'show version" "$INSTALL" | head -1 | cut -d: -f1)"
  step1="$(grep -n '\[1/9\] teardown' "$INSTALL" | head -1 | cut -d: -f1)"
  [ -n "$guard" ] && [ -n "$probe" ] && [ -n "$step1" ]
  [ "$guard" -lt "$probe" ] && [ "$guard" -lt "$step1" ]
}
