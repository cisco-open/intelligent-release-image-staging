#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  export DEVICE_IP=203.0.113.3 DEVICE_USER=u DEVICE_PASS=p VLAN=666
  UNINSTALL="$BATS_TEST_DIRNAME/../device-uninstall.sh"
}

# One assertion per @test (same rationale as test_device_install.bats: only
# the LAST command in a bats body sets the exit code).

@test "dry-run exits 0" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "stale NETWORK_ATTACHMENT without MANAGEMENT_TYPE aborts; a normal env is unaffected" {
  run env -u MANAGEMENT_TYPE NETWORK_ATTACHMENT=inband bash "$UNINSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE"* ]] || return 1
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "dry-run removes timer, copy, and interrupted hash applets" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no event manager applet IRIS-AGENT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-ROOT-HASH"* ]]
}

@test "dry-run also removes the on-demand reclaim applets" {
  # the agent creates IRIS-RECLAIM / IRIS-RECLAIM-BUNDLE under disk pressure
  # and never self-removes them — undeploy must clear them too
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no event manager applet IRIS-RECLAIM"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-RECLAIM-BUNDLE"* ]]
}

@test "dry-run removes the applets BEFORE the guestshell teardown" {
  run bash "$UNINSTALL" --dry-run
  applets_at="${output%%no event manager applet IRIS-AGENT*}"
  destroy_at="${output%%guestshell destroy*}"
  [ "${#applets_at}" -lt "${#destroy_at}" ]
}

@test "dry-run removes vlan and SVI" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan666"* ]] && [[ "$output" == *"no vlan 666"* ]]
}

@test "routed dry-run removes ONLY the IRIS VLAN from the AppGig allowed list" {
  # The installer only ever ADDS the IRIS VLAN to the trunk; teardown removes
  # exactly that (record-owned) VLAN and never the trunk or other apps' VLANs.
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *$'interface AppGigabitEthernet1/0/1\n switchport trunk allowed vlan remove 666'* ]] || return 1
  [[ "$output" != *"no switchport"* ]] || return 1
  [[ "$output" != *"switchport trunk allowed vlan none"* ]]
}

@test "the AppGig port follows the model (IE-3x00) or an explicit APP_INTF" {
  MODEL=IE-3400-8P2S run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"interface AppGigabitEthernet1/1"* ]] || return 1
  APP_INTF=AppGigabitEthernet2/0/1 run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"interface AppGigabitEthernet2/0/1"* ]]
}

@test "inband and force teardowns never touch the trunk's allowed list" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"allowed vlan"* ]] || return 1
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"allowed vlan"* ]]
}

@test "dry-run detaches IRISQ with EXPLICIT-name no-forms" {
  # bare 'no logging buffered discriminator' is rejected by IOS with
  # '% Incomplete command' — hardware-learned 2026-07-04
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no logging buffered discriminator IRISQ"* ]] && \
  [[ "$output" == *"no logging console discriminator IRISQ"* ]] && \
  [[ "$output" == *"no logging monitor discriminator IRISQ"* ]] && \
  [[ "$output" == *"no logging discriminator IRISQ"* ]]
}

@test "dry-run removes the PKI trustpoint (with its yes confirm) and http client binding" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no ip http client secure-trustpoint IRIS"* ]] && \
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]] && \
  [[ "$output" == *$'no crypto pki trustpoint IRIS\nyes'* ]]
}

@test "dry-run deletes guest-share" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete /force /recursive flash:guest-share"* ]]
}

@test "dry-run documents what is deliberately left in place" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"LEFT IN PLACE"* ]] && [[ "$output" == *"iox"* ]]
}

@test "dry-run persists successful Guest Shell cleanup" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"copy running-config startup-config"* ]]
}

@test "custom VLAN flows into the removal lines" {
  VLAN=42 run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan42"* ]] && [[ "$output" == *"no vlan 42"* ]]
}

@test "real run refuses to start without DEVICE_PASS" {
  unset DEVICE_PASS
  run bash "$UNINSTALL"
  [ "$status" -ne 0 ]
}

@test "real run refuses an empty VLAN instead of guessing 666" {
  # OnboardService exports VLAN='' when the fleet row has no vlan; tearing
  # down a guessed 666 could hit the wrong SVI and then falsely verify clean
  VLAN='' run bash "$UNINSTALL"
  [ "$status" -ne 0 ] && [[ "$output" == *"VLAN not set"* ]]
}

# --- IRIS_FORCE_AGENT_ONLY: record-less force undeploy ----------------------
# A device stranded WITHOUT a deployment record (onboard died after enabling
# Guest Shell but before its record was written) has no record proving IRIS
# created the VLAN/SVI. gui_server.py sets IRIS_FORCE_AGENT_ONLY=1 for exactly
# this case; force preserves that operator network while still removing every
# artifact carrying IRIS's own name.

@test "force dry-run keeps the operator VLAN but clears IRIS-named config" {
  # "Operator-owned" is the VLAN and its SVI -- network IRIS merely configured,
  # which no deployment record proves it created. The IRISQ discriminator and
  # the IRIS PKI trustpoint carry IRIS's own name, so a teardown clears them in every
  # mode: leaving them behind is what made a "clean" device refuse the next
  # onboard on an artifact we put there ourselves.
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"no interface Vlan"* ]] || return 1
  [[ "$output" != *"no vlan 666"* ]] || return 1
  [[ "$output" == *"no logging discriminator IRISQ"* ]] || return 1
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]] || return 1
  [[ "$output" == *"no ip http client secure-trustpoint IRIS"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "non-force dry-run DOES emit the operator-owned teardown commands" {
  # proves the gate actually gates: without IRIS_FORCE_AGENT_ONLY, the same
  # routed default undeploy still removes the VLAN/SVI, IRISQ, and trustpoint
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no interface Vlan666"* ]] && \
  [[ "$output" == *"no vlan 666"* ]] && \
  [[ "$output" == *"no logging discriminator IRISQ"* ]] && \
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]]
}

@test "force dry-run still removes the full IRIS agent footprint" {
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no event manager applet IRIS-AGENT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]] && \
  [[ "$output" == *"no app-hosting appid guestshell"* ]] && \
  [[ "$output" == *"guestshell disable"* ]] && \
  [[ "$output" == *"guestshell destroy"* ]] && \
  [[ "$output" == *"delete /force /recursive flash:guest-share"* ]]
}


# --- record-less force rescue: the VLAN guard must not gate it --------------
# Force mode never uses VLAN -- config_cleanup returns before any Vlan$VLAN
# line and the verify filter drops every VLAN term -- yet its absence aborted
# the rescue before the script reached the device.

_device_uninstall_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device"
  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
# Model the `ssh -tt` transcript: every typed line is echoed back behind the
# prompt (which is what carries the verify markers), then the response. No
# app-hosting entry, no matching config: the device reads as already clean,
# so both poll loops exit on their first pass and nothing sleeps.
req="$(cat)"
if [ -n "${FAKE_COMMAND_LOG:-}" ]; then
  printf '=== CALL ===\n%s\n' "$req" >> "$FAKE_COMMAND_LOG"
fi
case "$req" in
  *"show version"*)
    [ -n "${FAKE_VERSION_EMPTY:-}" ] && exit 0
    printf '%s\n' "sw1#show version" "cisco C9300-24T (X86) processor" \
      "Processor board ID ${FAKE_BOARD_ID:-FOC1234ABCD}"
    exit 0 ;;
esac
case "$req" in
  *"__IRIS_VERIFY_"*)
    if [ -n "${FAKE_VERIFY_TRUNCATED:-}" ]; then
      # session dropped before the FILES section came back
      printf '%s\n' "$req" | sed 's/^/sw1#/' | sed '/FILES__/,$d'
      exit 0
    fi
    printf '%s\n' "$req" | sed 's/^/sw1#/'
    exit "${FAKE_VERIFY_STATUS:-0}" ;;
esac
printf '%s\n' "$req" | sed 's/^/sw1#/'
echo "[OK]"
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"
  ln -sf "$UNINSTALL" "$STUBDIR/device/device-uninstall.sh"
  FAKE_COMMAND_LOG="$BATS_TEST_TMPDIR/commands.log"; : > "$FAKE_COMMAND_LOG"
  export FAKE_COMMAND_LOG
}

_device_uninstall_run_live() {
  env DEVICE_IP=192.0.2.10 DEVICE_USER=u DEVICE_PASS=p VLAN=666 \
    bash "$STUBDIR/device/device-uninstall.sh"
}

@test "forced teardown does not demand a VLAN it will never use" {
  # A bare legacy_routed fleet row carries no vlan at all, so this closed the
  # only exit a record-less device had: the force banner even says Vlan$VLAN
  # is NOT touched.
  _device_uninstall_stub_setup
  run env -u VLAN -u INBAND_VLAN DEVICE_IP=192.0.2.10 DEVICE_USER=u \
    DEVICE_PASS=p IRIS_FORCE_AGENT_ONLY=1 \
    bash "$STUBDIR/device/device-uninstall.sh"
  [[ "$output" != *"VLAN not set"* ]] || return 1
  [[ "$output" == *"Removing:"*"IRISQ"*"IRIS PKI"* ]] || return 1
  [[ "$output" == *"Preserving: operator VLAN/SVI"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "non-forced teardown still refuses to guess a missing VLAN" {
  # The guard is correct for a record-driven teardown -- it must keep firing there.
  _device_uninstall_stub_setup
  run env -u VLAN -u INBAND_VLAN DEVICE_IP=192.0.2.10 DEVICE_USER=u \
    DEVICE_PASS=p bash "$STUBDIR/device/device-uninstall.sh"
  [[ "$output" == *"VLAN not set"* ]] || return 1
  [ "$status" -ne 0 ]
}

# --- identity guard + fail-closed verify (IRIS-11-003 / IRIS-11-007) --------
# The Guest Shell teardown used to open with an unchecked config write and to
# read an empty verify response as "clean". It now opens with a read-only
# `show version` (which also lets device-run.sh learn the enable requirement
# before any config write), compares the board ID against
# EXPECTED_DEVICE_IDENTITY when the record supplies one, and refuses to
# declare the device clean unless every verify section came back.

@test "live: a record-driven teardown completes and persists against a clean device" {
  _device_uninstall_stub_setup
  run _device_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]]
}

@test "live: the FIRST device session is a read-only show version, before any config write" {
  _device_uninstall_stub_setup
  run _device_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  first="$(awk '/^=== CALL ===$/{n++} n==1' "$FAKE_COMMAND_LOG")"
  [[ "$first" == *"show version"* ]] || return 1
  [[ "$first" != *"configure terminal"* ]]
}

@test "live: EXPECTED_DEVICE_IDENTITY mismatch aborts before any destructive command" {
  _device_uninstall_stub_setup
  EXPECTED_DEVICE_IDENTITY=FOC9999ZZZZ run _device_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"device identity mismatch"* ]] || return 1
  [[ "$output" == *"FOC9999ZZZZ"*"FOC1234ABCD"* ]] || return 1
  ! grep -q "no event manager applet" "$FAKE_COMMAND_LOG" || return 1
  ! grep -q "guestshell" "$FAKE_COMMAND_LOG" || return 1
  ! grep -q "delete /force" "$FAKE_COMMAND_LOG"
}

@test "live: EXPECTED_DEVICE_IDENTITY match proceeds to the teardown" {
  _device_uninstall_stub_setup
  EXPECTED_DEVICE_IDENTITY=FOC1234ABCD run _device_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"identity verified"* ]] || return 1
  grep -q "no event manager applet IRIS-AGENT" "$FAKE_COMMAND_LOG"
}

@test "live: a truncated identity probe aborts before any destructive command" {
  _device_uninstall_stub_setup
  FAKE_VERSION_EMPTY=1 EXPECTED_DEVICE_IDENTITY=FOC1234ABCD run _device_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"returned nothing"* ]] || return 1
  ! grep -q "no event manager applet" "$FAKE_COMMAND_LOG"
}

@test "live: an empty verify response is NOT clean -- a missing section fails closed" {
  _device_uninstall_stub_setup
  FAKE_VERIFY_TRUNCATED=1 run _device_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"refusing to declare the device clean"* ]] || return 1
  [[ "$output" != *"undeploy complete"* ]] || return 1
  ! grep -q "copy running-config startup-config" "$FAKE_COMMAND_LOG"
}

@test "live: a failed verify session (ssh rc 255) is NOT clean" {
  _device_uninstall_stub_setup
  FAKE_VERIFY_STATUS=255 run _device_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"verify session"*"failed"* ]] || return 1
  ! grep -q "copy running-config startup-config" "$FAKE_COMMAND_LOG"
}
