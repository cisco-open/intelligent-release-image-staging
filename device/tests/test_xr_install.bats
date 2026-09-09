#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for device/xr-install.sh (agentinfo/plans/2026-08-28-xr-agent.md,
# Task 3): the appmgr onboard recipe for a Cisco 8000-series IOS-XR router.

setup() {
  INSTALL="$BATS_TEST_DIRNAME/../xr-install.sh"
  export DEVICE_IP=192.0.2.10 DEVICE_ID=8010-r1 \
    CATALOG_URL=https://192.0.2.20:8443 CATALOG_TOKEN=deadbeefcafe
}

# ---------------------------------------------------------------------------
# Dry-run text pins
# ---------------------------------------------------------------------------

@test "dry-run renders the hardware-proven activate line with its secret redacted" {
  # Rewritten (was pinned to the pre-#123/#124 opts string) to also cover the
  # bounded container-log driver and the IRIS_LOG env now on the line.
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'appmgr application iris activate type docker source iris-xr docker-run-opts "-td --net=host -v /misc/disk1:/hostmount --log-driver json-file --log-opt max-size=1m --log-opt max-file=3 --env IRIS_DEVICE_PLATFORM=xr-appmgr --env IRIS_CATALOG_URL=https://192.0.2.20:8443 --env IRIS_CATALOG_TOKEN=<redacted> --env IRIS_DEVICE_ID=8010-r1 --env IRIS_MODEL= --env IRIS_VERSION= --env IRIS_TELEMETRY=on --env IRIS_TELEMETRY_STREAM=off --env IRIS_LOG=off"'* ]]
  [[ "$output" != *'deadbeefcafe'* ]]
}

# ---------------------------------------------------------------------------
# #123 -- the container log must be bounded (never --log-driver=none: XR has
# no syslog path for %IRIS lines, see xr_deps.py's deviation note), and #124
# -- IRIS_LOG must actually reach the container so the documented opt-in is
# reachable on this platform.
# ---------------------------------------------------------------------------

@test "dry-run bounds the container log with a rotated json-file driver, never --log-driver=none" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'--log-driver json-file --log-opt max-size=1m --log-opt max-file=3'* ]]
  [[ "$output" != *'--log-driver none'* ]]
}

@test "dry-run defaults IRIS_LOG to off and forwards it to the container" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'--env IRIS_LOG=off'* ]]
}

@test "dry-run forwards an operator's IRIS_LOG=on opt-in to the container" {
  IRIS_LOG=on run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'--env IRIS_LOG=on'* ]]
}

@test "installer refuses an IRIS_LOG value that would break out of the docker-run-opts quoting" {
  IRIS_LOG='on"; no shutdown' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS_LOG must not contain a double quote"* ]]
}

@test "dry-run forwards MODEL from the caller's env contract (fleet row) as IRIS_MODEL" {
  # No live probe in --dry-run, so IRIS_VERSION stays empty here -- it's
  # parsed from the real preflight "show version" in the live path below.
  MODEL=8201 run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"--env IRIS_MODEL=8201 --env IRIS_VERSION="* ]]
}

@test "installer refuses a MODEL value that would break out of the docker-run-opts quoting" {
  MODEL='bad"value' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"MODEL must not contain a double quote"* ]]
}

@test "dry-run never emits --name" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"--name"* ]]
}

@test "dry-run wraps the activate line in configure/commit" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  configure_line="$(printf '%s\n' "$output" | grep -n '^configure$' | head -1 | cut -d: -f1)"
  activate_line="$(printf '%s\n' "$output" | grep -n 'appmgr application iris activate' | head -1 | cut -d: -f1)"
  commit_line="$(printf '%s\n' "$output" | grep -n '^commit$' | head -1 | cut -d: -f1)"
  [ -n "$configure_line" ] && [ -n "$activate_line" ] && [ -n "$commit_line" ]
  [ "$configure_line" -lt "$activate_line" ]
  [ "$activate_line" -lt "$commit_line" ]
}

@test "dry-run pushes the rpm straight to harddisk: root" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'/harddisk:/iris-xr.rpm'* ]]
  [[ "$output" == *"appmgr package install rpm /harddisk:/iris-xr.rpm"* ]]
  [[ "$output" == *"scp -O <public-certificate> <user>@192.0.2.10:/harddisk:/iris-catalog.pem"* ]]
  [[ "$output" == *"scp -O <instruction-envelope> <user>@192.0.2.10:/harddisk:/iris-instructions.bootstrap"* ]]
}

@test "dry-run never emits a startup-config persist step" {
  # XR commit IS the persisted state -- there is no running/startup split.
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  if printf '%s\n' "$output" | grep -qE '^copy running-config startup-config$'; then
    return 1
  fi
}

@test "dry-run respects APPID and SOURCE_NAME overrides" {
  APPID=probe SOURCE_NAME=probe-xr run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"appmgr application probe activate type docker source probe-xr"* ]]
  [[ "$output" == *"/harddisk:/probe-xr.rpm"* ]]
}

@test "dry-run reports the free-space floor and lets it be raised" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"2147483648 bytes"* ]]
  XR_MIN_FREE_BYTES=9999999999 run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"9999999999 bytes"* ]]
}

@test "installer refuses a value that would break out of the docker-run-opts quoting" {
  CATALOG_TOKEN='bad"value' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"CATALOG_TOKEN must not contain a double quote"* ]]
}

@test "dry-run rejects appmgr/config injection across XR supplied fields" {
  local name value
  while IFS='|' read -r name value; do
    run env "$name=$value" bash "$INSTALL" --dry-run
    [ "$status" -ne 0 ] || { echo "$name unexpectedly accepted"; return 1; }
    [[ "$output" != *$'\ncommit\nreload\n'* ]] || return 1
  done <<'EOF'
APPID|iris;commit
SOURCE_NAME|iris-xr;commit
DEVICE_IP|192.0.2.10;reload
DEVICE_ID|8010-r1;reload
MODEL|8201;reload
IRIS_TELEMETRY|on;reload
IRIS_TELEMETRY_STREAM|off;reload
IRIS_LOG|on;reload
XR_MIN_FREE_BYTES|2147483648;reload
ACTIVATE_TIMEOUT|300;reload
ACTIVATE_POLL|10;reload
EOF
}

@test "dry-run rejects CR/LF without echoing the catalog credential" {
  CATALOG_TOKEN=$'literal-secret\r\ncommit' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" != *'literal-secret'* ]]
  [[ "$output" != *$'\ncommit\n'* ]]
}

@test "dry-run rejects catalog URL userinfo without printing it" {
  CATALOG_URL=https://user:literal-secret@192.0.2.20:8443 \
    run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"without credentials"* ]]
  [[ "$output" != *"literal-secret"* ]]
}

@test "dry-run rejects unsafe package paths before printing an scp command" {
  XR_RPM_FILE=$'/tmp/iris-xr.rpm\nreload' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" != *'scp push'* ]]
}

@test "real install without credentials fails through the friendly guard, not an unbound variable" {
  run env -u DEVICE_USER -u DEVICE_PASS bash "$INSTALL"
  [ "$status" -ne 0 ]
  [[ "$output" == *"set DEVICE_USER"* ]]
  [[ "$output" != *"unbound variable"* ]]
}

@test "real install requires a readable XR_RPM_FILE before touching the device" {
  run env DEVICE_USER=admin DEVICE_PASS=pw XR_RPM_FILE=/nonexistent/iris-xr.rpm bash "$INSTALL"
  [ "$status" -ne 0 ]
  [[ "$output" == *"XR_RPM_FILE=/nonexistent/iris-xr.rpm is not readable"* ]]
  [[ "$output" == *"tools/build-xr-package.sh"* ]]
}

@test "real install requires a valid public catalog certificate before touching the device" {
  rpm="$BATS_TEST_TMPDIR/iris-xr.rpm"
  cert="$BATS_TEST_TMPDIR/not-a-cert.pem"
  printf '%s\n' rpm > "$rpm"
  printf '%s\n' 'not a certificate' > "$cert"
  run env DEVICE_USER=admin DEVICE_PASS=pw XR_RPM_FILE="$rpm" \
    IRIS_CRT_FILE="$cert" bash "$INSTALL"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not a valid PEM certificate"* ]]
  [[ "$output" != *"[1/5]"* ]]
}

# ---------------------------------------------------------------------------
# The commit-failure guard: every commit this script sends must ride
# lab/xr-run.sh (which appends the show-configuration-failed/abort recovery),
# never a direct ssh call of its own.
# ---------------------------------------------------------------------------

@test "the installer opens no SSH session of its own other than the three scp pushes" {
  # The pushes carry the RPM, runtime certificate, and bootstrap envelope. Every
  # other device interaction goes through RUN(), which wraps lab/xr-run.sh.
  count="$(grep -c 'sshpass' "$INSTALL")"
  [ "$count" -eq 3 ]
  grep -q 'sshpass -e scp' "$INSTALL"
}

@test "activation (config + commit) is piped through RUN, not sent directly" {
  run grep -A3 '^activate_line$' "$INSTALL"
  # the actual call site: a brace group ending "} | RUN"
  block="$(sed -n '/^{$/,/| RUN/p' "$INSTALL" | grep -A5 'activate_line')"
  [[ "$block" == *"commit"* ]]
  [[ "$block" == *"| RUN"* || "$(grep -A1 -F 'activate_line' "$INSTALL" | tail -5)" == *"RUN"* ]]
}

@test "lab/xr-run.sh (the shared XR transport) carries the commit-failure recovery" {
  XR_RUN="$BATS_TEST_DIRNAME/../../lab/xr-run.sh"
  [ -e "$XR_RUN" ]
  grep -q 'show configuration failed' "$XR_RUN"
  grep -q '"abort"' "$XR_RUN"
}

# ---------------------------------------------------------------------------
# Live path against a stubbed lab/xr-run.sh -- mirrors
# test_router_install.bats's _router_install_stub_setup.
# ---------------------------------------------------------------------------

_xr_install_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device" "$STUBDIR/bin"
  FAKE_STATE_DIR="$BATS_TEST_TMPDIR/state"
  mkdir -p "$FAKE_STATE_DIR"
  FAKE_COMMAND_LOG="$BATS_TEST_TMPDIR/xr-commands.log"
  : > "$FAKE_COMMAND_LOG"
  export FAKE_STATE_DIR FAKE_COMMAND_LOG

  cat > "$STUBDIR/lab/xr-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
if [ -n "${FAKE_COMMAND_LOG:-}" ]; then
  { echo "=== CALL START ==="; printf '%s\n' "$cmds"; echo "=== CALL END ==="; } >> "$FAKE_COMMAND_LOG"
fi
case "$cmds" in
  *"show version"*)
    printf '%s\n' "${FAKE_VERSION_BANNER-Cisco IOS XR Software, Version 25.4.2 LNT}"
    ;;
  *"dir harddisk: | include bytes free"*)
    printf '%s\n' "${FAKE_DIR_BYTES_FREE-39929724928 bytes total (39883231232 bytes free)}"
    ;;
  *"show appmgr source-table"*)
    printf '%s\n' "${FAKE_SOURCE_TABLE-iris-xr  0.1.0  ThinXR_7.3.15  app_manager}"
    ;;
  *"show appmgr application-table"*)
    n=$(( $(cat "$FAKE_STATE_DIR/apptable_n" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$FAKE_STATE_DIR/apptable_n"
    up_after="${FAKE_APP_UP_AFTER:-1}"
    if [ -n "${FAKE_APP_NEVER_UP:-}" ] || [ "$n" -lt "$up_after" ]; then
      printf '%s\n' "${FAKE_APP_TABLE_NOT_UP-iris  docker  iris-xr  Activating  app_manager}"
    else
      printf '%s\n' "${FAKE_APP_TABLE_UP-iris  docker  iris-xr  Up  app_manager}"
    fi
    ;;
  *"appmgr package install rpm"*)
    echo "Installing package: ok"
    ;;
  *)
    echo "ok"
    ;;
esac
STUB
  chmod +x "$STUBDIR/lab/xr-run.sh"
  # The scp push sources the real trust policy from the tree it runs in.
  cp "$BATS_TEST_DIRNAME/../../lab/iris-ssh-policy.sh" "$STUBDIR/lab/iris-ssh-policy.sh"
  export IRIS_STATE="$BATS_TEST_TMPDIR/state"   # persistent known_hosts stays local

  cat > "$STUBDIR/bin/sshpass" <<'STUB'
#!/usr/bin/env bash
if [ -n "${FAKE_COMMAND_LOG:-}" ]; then
  echo "=== SCP: $* ===" >> "$FAKE_COMMAND_LOG"
fi
case "$*" in
  *"${FAKE_SCP_FAIL_MATCH:-__no_match__}"*) exit 1 ;;
esac
exit "${FAKE_SCP_STATUS:-0}"
STUB
  chmod +x "$STUBDIR/bin/sshpass"

  ln -sf "$INSTALL" "$STUBDIR/device/xr-install.sh"

  RPMFILE="$BATS_TEST_TMPDIR/iris-xr.rpm"
  echo "fake rpm bytes" > "$RPMFILE"
  CRTFILE="$BATS_TEST_TMPDIR/iris-catalog.pem"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$BATS_TEST_TMPDIR/catalog.key" -out "$CRTFILE" \
    -days 1 -subj '/CN=iris-test' >/dev/null 2>&1
  INSTRUCTION_FILE="$BATS_TEST_TMPDIR/iris-instructions.envelope"
  printf '%s' 'private-bootstrap-ciphertext' > "$INSTRUCTION_FILE"
  chmod 600 "$INSTRUCTION_FILE"
}

_xr_install_run_live() {
  env PATH="$STUBDIR/bin:$PATH" DEVICE_USER=admin DEVICE_PASS=pw \
    XR_RPM_FILE="$RPMFILE" IRIS_CRT_FILE="$CRTFILE" \
    IRIS_INSTRUCTION_BOOTSTRAP_FILE="$INSTRUCTION_FILE" \
    ACTIVATE_TIMEOUT="${ACTIVATE_TIMEOUT:-30}" \
    ACTIVATE_POLL="${ACTIVATE_POLL:-1}" \
    bash "$STUBDIR/device/xr-install.sh"
}

@test "live: succeeds end to end against a well-behaved device" {
  _xr_install_stub_setup
  run _xr_install_run_live
  [ "$status" -eq 0 ]
  [[ "${lines[${#lines[@]}-1]}" = "onboard complete: 192.0.2.10" ]]
}

@test "live: pushes the current certificate to the fixed harddisk path before activation" {
  _xr_install_stub_setup
  run _xr_install_run_live
  [ "$status" -eq 0 ] || return 1
  grep -q "${CRTFILE} admin@192.0.2.10:/harddisk:/iris-catalog.pem" "$FAKE_COMMAND_LOG"
  cert_line="$(grep -n '/harddisk:/iris-catalog.pem' "$FAKE_COMMAND_LOG" | head -1 | cut -d: -f1)"
  activate_line="$(grep -n 'appmgr application iris activate' "$FAKE_COMMAND_LOG" | head -1 | cut -d: -f1)"
  [ -n "$cert_line" ] && [ -n "$activate_line" ]
  [ "$cert_line" -lt "$activate_line" ]
}

@test "live: uploads package certificate and bootstrap before registration" {
  _xr_install_stub_setup
  run _xr_install_run_live
  [ "$status" -eq 0 ] || return 1
  rpm_line="$(grep -n '/harddisk:/iris-xr.rpm' "$FAKE_COMMAND_LOG" | head -1 | cut -d: -f1)"
  cert_line="$(grep -n '/harddisk:/iris-catalog.pem' "$FAKE_COMMAND_LOG" | head -1 | cut -d: -f1)"
  instruction_line="$(grep -n '/harddisk:/iris-instructions.bootstrap' "$FAKE_COMMAND_LOG" | head -1 | cut -d: -f1)"
  register_line="$(grep -n 'appmgr package install rpm' "$FAKE_COMMAND_LOG" | head -1 | cut -d: -f1)"
  [ -n "$rpm_line" ] && [ -n "$cert_line" ] && \
    [ -n "$instruction_line" ] && [ -n "$register_line" ]
  [ "$rpm_line" -lt "$cert_line" ]
  [ "$cert_line" -lt "$instruction_line" ]
  [ "$instruction_line" -lt "$register_line" ]
  ! grep -q 'private-bootstrap-ciphertext' "$FAKE_COMMAND_LOG"
}

@test "real install validates the bootstrap snapshot before device contact" {
  _xr_install_stub_setup
  for shape in missing empty symlink oversized; do
    : > "$FAKE_COMMAND_LOG"
    candidate="$BATS_TEST_TMPDIR/bootstrap-$shape"
    rm -f "$candidate"
    case "$shape" in
      missing) ;;
      empty) : > "$candidate" ;;
      symlink) ln -s "$INSTRUCTION_FILE" "$candidate" ;;
      oversized) dd if=/dev/zero of="$candidate" bs=262145 count=1 status=none ;;
    esac
    chmod 600 "$candidate" 2>/dev/null || true
    IRIS_INSTRUCTION_BOOTSTRAP_FILE="$candidate" run _xr_install_run_live
    [ "$status" -ne 0 ] || { echo "$shape unexpectedly accepted"; return 1; }
    [[ "$output" == *"instruction bootstrap snapshot is invalid"* ]] || return 1
    [ ! -s "$FAKE_COMMAND_LOG" ] || return 1
  done
}

@test "live: bootstrap upload failure prevents package registration and activation" {
  _xr_install_stub_setup
  FAKE_SCP_FAIL_MATCH=iris-instructions.bootstrap run _xr_install_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"XR package/catalog/bootstrap upload failed"* ]]
  ! grep -q 'appmgr package install rpm' "$FAKE_COMMAND_LOG"
  ! grep -q 'appmgr application iris activate' "$FAKE_COMMAND_LOG"
}

@test "live: parses the running version out of its own preflight show version" {
  # No env for this -- unlike MODEL (the fleet row), there is nowhere else on
  # this CLI-less platform to learn it, so the installer must extract it
  # itself from the same probe that already classifies the box as IOS-XR.
  _xr_install_stub_setup
  run _xr_install_run_live
  [ "$status" -eq 0 ] || return 1
  # First token only: "25.4.2 LNT" carries a space, and a space inside the
  # quoted docker-run-opts splits the opts -- the validator rejects the stray
  # token and the WHOLE pseudo-atomic commit fails (hardware-reproduced on
  # 8010-R1). The delimiter grep pins the token boundary.
  grep -q -- '--env IRIS_VERSION=25.4.2 --env' "$FAKE_COMMAND_LOG" || return 1
  ! grep -q -- 'IRIS_VERSION=25.4.2 LNT' "$FAKE_COMMAND_LOG"
}

@test "live: forwards MODEL through to the activate line sent to the device" {
  _xr_install_stub_setup
  MODEL=8201 run _xr_install_run_live
  [ "$status" -eq 0 ]
  grep -q -- '--env IRIS_MODEL=8201' "$FAKE_COMMAND_LOG"
}

@test "live: forwards IRIS_LOG through to the activate line sent to the device" {
  _xr_install_stub_setup
  IRIS_LOG=on run _xr_install_run_live
  [ "$status" -eq 0 ]
  grep -q -- '--env IRIS_LOG=on' "$FAKE_COMMAND_LOG"
}

@test "live: IRIS_LOG defaults to off on the activate line sent to the device" {
  _xr_install_stub_setup
  run _xr_install_run_live
  [ "$status" -eq 0 ]
  grep -q -- '--env IRIS_LOG=off' "$FAKE_COMMAND_LOG"
}

@test "live: refuses a device whose show version is not IOS-XR" {
  _xr_install_stub_setup
  FAKE_VERSION_BANNER="Cisco IOS XE Software, Version 17.18.03" run _xr_install_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"does not report an IOS-XR banner"* ]]
  # must refuse BEFORE ever pushing the rpm
  ! grep -q "SCP:" "$FAKE_COMMAND_LOG"
}

@test "live: refuses when harddisk: free space is under the floor" {
  _xr_install_stub_setup
  FAKE_DIR_BYTES_FREE="1000000 bytes total (500000 bytes free)" run _xr_install_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"only 500000 bytes free"* ]]
  ! grep -q "SCP:" "$FAKE_COMMAND_LOG"
}

@test "live: fails when the package never appears in show appmgr source-table" {
  _xr_install_stub_setup
  FAKE_SOURCE_TABLE="" run _xr_install_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"does not appear in 'show appmgr source-table'"* ]]
}

@test "live: fails, with the table output, when the app never reaches Up" {
  _xr_install_stub_setup
  FAKE_APP_NEVER_UP=1 ACTIVATE_TIMEOUT=2 ACTIVATE_POLL=1 run _xr_install_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"did not reach Up within"* ]]
  [[ "$output" == *"Activating"* ]]
}

@test "live: a device that comes up on a later poll still succeeds" {
  _xr_install_stub_setup
  FAKE_APP_UP_AFTER=3 ACTIVATE_TIMEOUT=30 ACTIVATE_POLL=1 run _xr_install_run_live
  [ "$status" -eq 0 ]
  [[ "${lines[${#lines[@]}-1]}" = "onboard complete: 192.0.2.10" ]]
}

@test "live: the RPM scp verifies the router's host key (never /dev/null known_hosts)" {
  _xr_install_stub_setup
  FAKE_COMMAND_LOG="$BATS_TEST_TMPDIR/cmd.log"; : > "$FAKE_COMMAND_LOG"; export FAKE_COMMAND_LOG
  run _xr_install_run_live
  [ "$status" -eq 0 ] || return 1
  scp_line="$(grep '=== SCP:' "$FAKE_COMMAND_LOG")"
  [[ "$scp_line" != *"UserKnownHostsFile=/dev/null"* ]] || return 1
  [[ "$scp_line" != *"StrictHostKeyChecking=no"* ]] || return 1
  [[ "$scp_line" == *"StrictHostKeyChecking=accept-new"* ]] || return 1
  [[ "$scp_line" == *"UserKnownHostsFile=$IRIS_STATE/ssh/known_hosts"* ]]
}
