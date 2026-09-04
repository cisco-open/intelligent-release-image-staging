#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

@test "install waits for IOx readiness and reports meaningful app state" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'waiting for IOx app-hosting service (CAF/Dockerd)' "$install"
  [ "$status" -eq 0 ]
  run grep -F "app-hosting has not reported '\$APPID' yet" "$install"
  [ "$status" -eq 0 ]
}

@test "install reports IOS lifecycle output and removes a partial app config" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'install_out=' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'clear_partial_app_config' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'partial app-hosting configuration has been removed' "$install"
  [ "$status" -eq 0 ]
}

@test "install limits lifecycle output to meaningful IOS messages" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F "grep -E 'Installing package|Failed to install|%IOX|%APP'" "$install"
  [ "$status" -eq 0 ]
}

@test "install persists a successful IOx app lifecycle" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'copy running-config startup-config' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'startup-config saved' "$install"
  [ "$status" -eq 0 ]
}

# --- inband IOx (dry-run structural safety) ---
setup() {
  export DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 STAGE_HOST=192.0.2.2 \
         DEVICE_SSH_PASS=x
  INSTALL="$BATS_TEST_DIRNAME/../install.sh"
}

@test "stale NETWORK_ATTACHMENT without MANAGEMENT_TYPE aborts; a normal env is unaffected" {
  NETWORK_ATTACHMENT=inband run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE"* ]] || return 1
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "inband dry-run creates no VLAN/SVI and never replaces the AppGig allowed list" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\nvlan '* ]] && \
  [[ "$output" != *"interface Vlan"* ]] && \
  ! grep -Eq 'switchport trunk allowed vlan [0-9]' <<<"$output" && \
  [[ "$output" != *"ip address 192.0.2"* ]]
}

@test "inband dry-run trunks the AppGig additively (allowed vlan add)" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [[ "$output" == *"interface AppGigabitEthernet1/1"* ]] && \
  [[ "$output" == *"switchport mode trunk"* ]] && \
  [[ "$output" == *"switchport trunk allowed vlan add 120"* ]]
}

@test "inband dry-run points the app SSH-to-IOS at the existing management SVI" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [[ "$output" == *"IRIS_DEVICE_SSH_HOST=192.0.2.1"* ]] && \
  [[ "$output" == *"vlan 120 guest-interface 0"* ]]
}

@test "inband real run requires IOS_SSH_HOST" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IRIS_CRT_FILE=/dev/null run bash "$INSTALL"
  [ "$status" -ne 0 ] && [[ "$output" == *"IOS_SSH_HOST"* ]]
}

@test "routed dry-run still creates the IRIS VLAN and SVI" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [[ "$output" == *"vlan 666"* ]] && [[ "$output" == *"interface Vlan666"* ]]
}

# --- C9k share-mount transfer (Route B): the app-hosting SSD share is bind-
# mounted into the container so the agent lands its scratch at disk speed and
# placement is an IOS-internal copy — no scp, no punt path, no CoPP cap. ---

@test "share dry-run renders the bind-mount run-opts and the share env" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    SHARE_IOS_PATH=usbflash1:iox_host_data_share \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'-v /vol/usb1/iox_host_data_share:/mnt/share'* ]] && \
  [[ "$output" == *'-e IRIS_SHARE_DIR=/mnt/share'* ]] && \
  [[ "$output" == *'-e IRIS_SHARE_IOS_PATH=usbflash1:iox_host_data_share'* ]] && \
  [[ "$output" == *"mkdir usbflash1:iox_host_data_share"* ]]
}

@test "share run-opts render INSIDE the app-hosting docker block (before end)" {
  # app-hosting silently ignores run-opts rendered after the block's `end`,
  # so the mount would vanish while every substring gate still passed —
  # assert the line that immediately follows run-opts 13 (the last one,
  # renumbered from 12 when run-opts 10 "-e IRIS_LOG=..." was added ahead of
  # the SHARE block) is `end`.
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    SHARE_IOS_PATH=usbflash1:iox_host_data_share \
    run bash "$INSTALL" --dry-run
  after="$(printf '%s\n' "$output" | grep -A1 'run-opts 13' | tail -1)"
  [ "$after" = "end" ]
}

@test "without SHARE env no bind-mount is rendered (IE-3x00 default unchanged)" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [[ "$output" != *'-v /vol/'* ]] && \
  [[ "$output" != *'IRIS_SHARE_DIR'* ]]
}

@test "SHARE env is all-or-nothing" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] && [[ "$output" == *"SHARE_IOS_PATH"* ]]
}

@test "IOx install retries app-hosting verification disable until it succeeds" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'app-hosting verification disable' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'disabled successfully' "$install"
  [ "$status" -eq 0 ]
}

# --- operator-facing PREREQ checks (2026-08-20 incident: an IE-3400 lost `ip
# routing` on re-image; onboarding "succeeded" while the app's VLAN traffic had
# no L3 path out — silent, invisible, hours to diagnose). Static assertions
# prove the PREREQ lines and commands are present and land before step [2/9];
# the stub-backed tests below prove the pass/fail/warn behavior itself. ---

@test "install checks ip routing before applying any config (PREREQ, routed only)" {
  # semantic detection: explicit `no ip routing` / host-mode route table —
  # NOT a grep for the positive `ip routing` line, which is absent when
  # routing is the platform default (IE3x00 false-positive, 2026-08-20)
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'show running-config | include no ip routing' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'PREREQ: ip routing is disabled on this switch' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'PREREQ: could not verify ip routing' "$install"
  [ "$status" -eq 0 ]
}

@test "install checks for an IOx SD partition (PREREQ, IE3x00)" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'show sdflash: filesys' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'PREREQ: no IOx partition on the SD card' "$install"
  [ "$status" -eq 0 ]
}

@test "install warns (not fails) on a stale device clock (PREREQ)" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'PREREQ WARNING: device clock is' "$install"
  [ "$status" -eq 0 ]
}

@test "PREREQ checks land before step [2/9] applies IOx networking" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  pre_line="$(grep -n '^echo "\[pre\] prerequisite checks' "$install" | head -1 | cut -d: -f1)"
  step2_line="$(grep -n '^echo "\[2/9\]' "$install" | head -1 | cut -d: -f1)"
  [ -n "$pre_line" ] && [ -n "$step2_line" ] && [ "$pre_line" -lt "$step2_line" ]
}

# --- behavioral PREREQ tests: stub lab/device-run.sh so install.sh's RUN
# helper talks to a fake device transcript instead of a real one. Mirrors the
# STUBDIR pattern in device/tests/test_device_install.bats (HERE resolves off
# a symlinked install.sh, so lab/device-run.sh must live two dirs up from it).
# FAKE_* env vars steer the fake device's answers per check. ---

_iox_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device/iox"
  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
[ -z "${FAKE_COMMAND_LOG:-}" ] || printf '%s\n' "$cmds" >> "$FAKE_COMMAND_LOG"
case "$cmds" in
  *"show version"*)
    echo "cisco ${FAKE_MODEL:-IE-3400-8T2S} (ARMv8) processor"
    echo "Processor board ID ${FAKE_DEVICE_IDENTITY:-FOC1234TEST}"
    ;;
esac
case "$cmds" in
  *"show running-config"*)
    # Real sessions echo the commands back; the installer's transport check
    # keys on that echo. FAKE_DEVICE_DOWN=yes simulates a dead session.
    [ "${FAKE_DEVICE_DOWN:-no}" = "yes" ] && exit 0
    echo "show running-config | include no ip routing"
    if [ "${FAKE_IP_ROUTING:-yes}" = "yes" ]; then
      echo "Gateway of last resort is 100.90.168.1 to network 0.0.0.0"
    else
      echo "no ip routing"
      echo "Default gateway is not set"
    fi
    ;;
esac
case "$cmds" in
  *"show sdflash: filesys"*)
    if [ "${FAKE_IOX_PARTITION:-yes}" = "yes" ]; then
      echo "IOx Partition Exists"
    else
      echo "Filesystem: sdflash: (no IOx partition present)"
    fi
    ;;
esac
case "$cmds" in
  *"show clock"*)
    echo "${FAKE_CLOCK_LINE:-14:23:07.512 UTC Thu Aug 20 2026}"
    ;;
esac
case "$cmds" in
  *"show iox"*)
    echo "IOx service (CAF)        : Running"
    echo "Dockerd                  : Running"
    ;;
esac
case "$cmds" in
  *"app-hosting verification disable"*)
    echo "App hosting verification disabled successfully"
    ;;
esac
case "$cmds" in
  *"show app-hosting list"*)
    echo "App id                                   State"
    echo "---------------------------------------------------------"
    # unset FAKE_APP_STATE == no app installed (the default for every test
    # that never gets as far as the lifecycle)
    if [ -n "${FAKE_APP_STATE:-}" ]; then
      echo "iris                                     ${FAKE_APP_STATE}"
    else
      echo "No App found"
    fi
    ;;
esac
case "$cmds" in
  *"copy https://"*)
    echo "${FAKE_COPY_RESULT:-11223344 bytes copied in 12.345 secs}"
    ;;
esac
case "$cmds" in
  *"app-hosting install appid"*)
    echo "Installing package 'flash:iris-arm64.tar' for 'iris'. Use 'show app-hosting list' for progress."
    ;;
esac
case "$cmds" in
  *"app-hosting activate appid"*)
    # The second line is deliberately one the success-path grep filter drops,
    # so a test can tell an unfiltered dump from a filtered one.
    echo "sw1#app-hosting activate appid iris"
    echo "${FAKE_ACTIVATE_DETAIL:-% Error: activation is still loading the app image}"
    ;;
esac
exit 0
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"
  ln -s "$BATS_TEST_DIRNAME/../install.sh" "$STUBDIR/device/iox/install.sh"
  CRTFILE="$BATS_TEST_TMPDIR/crt.pem"
  echo "-----BEGIN CERTIFICATE-----fake-----END CERTIFICATE-----" > "$CRTFILE"
}

# same portable timeout wrapper as device/tests/test_device_install.bats: the
# real (non-dry) flow reaches long device-wait loops past the PREREQ step, so
# "did it proceed" tests bound the run and inspect partial captured output.
_iox_run_with_timeout_impl() {
  local secs="$1"; shift
  local outfile
  outfile="$(mktemp)"
  ("$@" > "$outfile" 2>&1) &
  local pid=$!
  local waited=0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$secs" ]; do
    sleep 1; waited=$((waited + 1))
  done
  local rc
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    rc=124
  else
    wait "$pid"; rc=$?
  fi
  cat "$outfile"
  rm -f "$outfile"
  return "$rc"
}

iox_run_with_timeout() {
  run _iox_run_with_timeout_impl "$@"
}

_iox_env() {
  env DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 STAGE_HOST=192.0.2.2 \
    DEVICE_SSH_PASS=x VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 \
    GUEST_IP=192.0.2.10 IRIS_CRT_FILE="$CRTFILE" MODEL=IE-3400-8T2S \
    EXPECTED_DEVICE_IDENTITY=FOC1234TEST "$@"
}

@test "ip routing missing: real run exits non-zero with the PREREQ line" {
  _iox_stub_setup
  run _iox_env FAKE_IP_ROUTING=no bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"PREREQ: ip routing is disabled on this switch"* ]]
}

@test "dead device session: PREREQ says transport, not routing" {
  # a session that produces no output must not masquerade as a routing
  # problem (the old check conflated the two)
  _iox_stub_setup
  run _iox_env FAKE_DEVICE_DOWN=yes bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"PREREQ: could not verify ip routing"* ]]
  [[ "$output" != *"PREREQ: ip routing is disabled"* ]]
}

@test "ip routing present: real run proceeds past the check to step [2/9]" {
  _iox_stub_setup
  iox_run_with_timeout 12 env DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 \
    STAGE_HOST=192.0.2.2 DEVICE_SSH_PASS=x VLAN=666 SVI_IP=192.0.2.9 \
    SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 IRIS_CRT_FILE="$CRTFILE" \
    MODEL=IE-3400-8T2S EXPECTED_DEVICE_IDENTITY=FOC1234TEST FAKE_IP_ROUTING=yes \
    bash "$STUBDIR/device/iox/install.sh"
  [[ "$output" != *"PREREQ: ip routing is disabled"* ]]
  [[ "$output" == *"[2/9]"* ]]
}

@test "no IOx partition: real run exits non-zero with the PREREQ line" {
  _iox_stub_setup
  run _iox_env FAKE_IP_ROUTING=yes FAKE_IOX_PARTITION=no \
    bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"PREREQ: no IOx partition on the SD card"* ]]
}

@test "old device clock: real run warns but continues past the check" {
  _iox_stub_setup
  iox_run_with_timeout 12 env DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 \
    STAGE_HOST=192.0.2.2 DEVICE_SSH_PASS=x VLAN=666 SVI_IP=192.0.2.9 \
    SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 IRIS_CRT_FILE="$CRTFILE" \
    MODEL=IE-3400-8T2S EXPECTED_DEVICE_IDENTITY=FOC1234TEST FAKE_IP_ROUTING=yes FAKE_IOX_PARTITION=yes \
    FAKE_CLOCK_LINE="14:23:07.512 UTC Thu Aug 20 2018" \
    bash "$STUBDIR/device/iox/install.sh"
  [[ "$output" == *"PREREQ WARNING: device clock is 2018"* ]]
  [[ "$output" == *"[2/9]"* ]]
}

@test "unparseable device clock: the optional probe must not abort the install" {
  # No four-digit year in the probe output must leave clock_year empty and
  # skip the warning — under `set -euo pipefail` a bare failing grep here
  # used to kill the installer at a check documented as optional.
  _iox_stub_setup
  iox_run_with_timeout 12 env DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 \
    STAGE_HOST=192.0.2.2 DEVICE_SSH_PASS=x VLAN=666 SVI_IP=192.0.2.9 \
    SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 IRIS_CRT_FILE="$CRTFILE" \
    MODEL=IE-3400-8T2S EXPECTED_DEVICE_IDENTITY=FOC1234TEST FAKE_IP_ROUTING=yes FAKE_IOX_PARTITION=yes \
    FAKE_CLOCK_LINE="% Clock is not set" \
    bash "$STUBDIR/device/iox/install.sh"
  [[ "$output" != *"PREREQ WARNING"* ]]
  [[ "$output" == *"[2/9]"* ]]
}

@test "failing PREREQ aborts before the existing app is torn down" {
  # The prerequisite checks are read-only; when one fails on a re-onboard the
  # working app must still be running. Tearing down first turns a routing or
  # storage complaint into a destroyed deployment with no replacement.
  _iox_stub_setup
  COMMAND_LOG="$BATS_TEST_TMPDIR/device-commands.log"
  run _iox_env FAKE_COMMAND_LOG="$COMMAND_LOG" FAKE_IP_ROUTING=no \
    bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"PREREQ: ip routing is disabled"* ]]
  ! grep -qE 'app-hosting (stop|deactivate|uninstall) appid iris|no app-hosting appid iris' "$COMMAND_LOG"
}

@test "mismatched device identity aborts before destructive app commands" {
  _iox_stub_setup
  COMMAND_LOG="$BATS_TEST_TMPDIR/device-commands.log"
  run _iox_env FAKE_COMMAND_LOG="$COMMAND_LOG" EXPECTED_DEVICE_IDENTITY=WRONG-ID \
    bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"ERROR: device identity mismatch"* ]]
  ! grep -qE 'app-hosting (stop|deactivate|uninstall) appid iris|no app-hosting appid iris' "$COMMAND_LOG"
}

# --- app-hosting lifecycle budgets (scrubber #78) --------------------------
# The first install of a NEW package version has to load its docker layers into
# the IOx image cache before the app can activate; a byte-identical package the
# box has run before activates in seconds. The old flat 90 s activate budget was
# shorter than that first-time load on an IE-3400, so the console onboard
# reported failure while the activation completed a minute or two later.

@test "the lifecycle budgets default to 300s and no wait is hardcoded" {
  install="$BATS_TEST_DIRNAME/../install.sh"
  run grep -F 'INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-300}"' "$install"
  [ "$status" -eq 0 ]
  # same knob name and same default as device/xr-install.sh
  run grep -F 'ACTIVATE_TIMEOUT="${ACTIVATE_TIMEOUT:-300}"' "$install"
  [ "$status" -eq 0 ]
  run grep -F 'START_TIMEOUT="${START_TIMEOUT:-300}"' "$install"
  [ "$status" -eq 0 ]
  run grep -nE 'wait_state [A-Z]+ [0-9]+' "$install"
  [ "$status" -ne 0 ]
}

@test "a non-numeric lifecycle budget is refused before the device is touched" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    ACTIVATE_TIMEOUT=abc run bash "$INSTALL" --dry-run
  [ "$status" -eq 2 ]
  [[ "$output" == *"ACTIVATE_TIMEOUT must be a whole number of seconds"* ]]
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    STATE_POLL=0 run bash "$INSTALL" --dry-run
  [ "$status" -eq 2 ]
  [[ "$output" == *"STATE_POLL must be greater than zero"* ]]
}

@test "activation timeout honours the budget, dumps the unfiltered IOS reply, and keeps the app for a resumable retry" {
  # The app never leaves DEPLOYED, which is exactly the observed failure: the
  # activation is still loading layers when the budget runs out.
  _iox_stub_setup
  run _iox_env FAKE_IP_ROUTING=yes FAKE_APP_STATE=DEPLOYED \
    ACTIVATE_TIMEOUT=2 STATE_POLL=1 bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -ne 0 ]
  # the budget is a knob, not a constant
  [[ "$output" == *"did not reach ACTIVATED within 2 seconds"* ]]
  # the activate reply is printed UNFILTERED: this line is dropped by the
  # success-path grep, so seeing it proves the swallowed output is now shown
  [[ "$output" == *"activation is still loading the app image"* ]]
  [[ "$output" == *"Last observed state: DEPLOYED"* ]]
  # and the operator is told the retry is possible without an undeploy
  [[ "$output" == *"LEFT IN PLACE"* ]]
  [[ "$output" == *"resumable retry"* ]]
}

@test "activation timeout leaves the app-hosting config on the device" {
  # clear_partial_app_config belongs to the DEPLOYED failure only: removing the
  # stanza here would abort an activation that is still in flight.
  _iox_stub_setup
  COMMAND_LOG="$BATS_TEST_TMPDIR/device-commands.log"
  run _iox_env FAKE_COMMAND_LOG="$COMMAND_LOG" FAKE_IP_ROUTING=yes \
    FAKE_APP_STATE=DEPLOYED ACTIVATE_TIMEOUT=2 STATE_POLL=1 \
    bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -ne 0 ]
  # the teardown in [1/9] is expected; a SECOND removal after the activate
  # wait is not, so count them
  run grep -c 'no app-hosting appid iris' "$COMMAND_LOG"
  [ "$status" -eq 0 ]
  [ "$output" -eq 1 ]
}

# --- iox_ready: one login per observation ----------------------------------
# Both readiness fields live in the SAME `show iox` output, so reading it twice
# paid a second ssh handshake for nothing -- and this runs on every iteration of
# a poll loop that can last minutes. The poll itself must still re-observe live
# state each iteration; only the duplicated read WITHIN one observation is gone.

_iox_ready_fn() {
  sed -n '/^iox_ready() {/,/^}/p' "$BATS_TEST_DIRNAME/../install.sh"
}

@test "iox_ready reads show iox exactly once per observation" {
  log="$BATS_TEST_TMPDIR/iox-reads"
  : > "$log"
  run bash -c "
    RUN() { cat >/dev/null; echo run >> '$log'
            printf 'IOx service (CAF)  : Running\nDockerd  : Running\n'; }
    $(_iox_ready_fn)
    iox_ready"
  [ "$status" -eq 0 ]
  [ "$(wc -l < "$log" | tr -d ' ')" -eq 1 ]
}

@test "iox_ready still fails when either field is not Running" {
  for missing in 'IOx service (CAF)  : Running' 'Dockerd  : Running'; do
    run bash -c "
      RUN() { cat >/dev/null; printf '%s\n' '$missing'; }
      $(_iox_ready_fn)
      iox_ready"
    [ "$status" -ne 0 ]
  done
}
