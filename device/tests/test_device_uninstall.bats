#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  export DEVICE_IP=100.92.9.3 DEVICE_USER=u DEVICE_PASS=p VLAN=666
  UNINSTALL="$BATS_TEST_DIRNAME/../device-uninstall.sh"
}

# One assertion per @test (same rationale as test_device_install.bats: only
# the LAST command in a bats body sets the exit code).

@test "dry-run exits 0" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "dry-run removes both EEM applets" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no event manager applet IRIS-AGENT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]]
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

# --- IRIS_FORCE_AGENT_ONLY: receipt-less force undeploy ---------------------
# A device stranded WITHOUT a deployment receipt (onboard died after enabling
# Guest Shell but before its receipt was written) has no receipt proving IRIS
# created the VLAN/SVI. gui_server.py sets IRIS_FORCE_AGENT_ONLY=1 for exactly
# this case; force preserves that operator network while still removing every
# artifact carrying IRIS's own name.

@test "force dry-run keeps the operator VLAN but clears IRIS-named config" {
  # "Operator-owned" is the VLAN and its SVI -- network IRIS merely configured,
  # which no receipt proves it created. The IRISQ discriminator and the IRIS
  # PKI trustpoint carry IRIS's own name, so a teardown clears them in every
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


# --- receipt-less force rescue: the VLAN guard must not gate it -------------
# Force mode never uses VLAN -- config_cleanup returns before any Vlan$VLAN
# line and the verify filter drops every VLAN term -- yet its absence aborted
# the rescue before the script reached the device.

_device_uninstall_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device"
  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
cat > /dev/null
# No app-hosting entry, no matching config: the device reads as already clean,
# so both poll loops exit on their first pass and nothing sleeps.
echo "[OK]"
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"
  ln -sf "$UNINSTALL" "$STUBDIR/device/device-uninstall.sh"
}

@test "forced teardown does not demand a VLAN it will never use" {
  # A bare legacy_routed fleet row carries no vlan at all, so this closed the
  # only exit a receipt-less device had: the force banner even says Vlan$VLAN
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
  # The guard is correct for a receipted teardown -- it must keep firing there.
  _device_uninstall_stub_setup
  run env -u VLAN -u INBAND_VLAN DEVICE_IP=192.0.2.10 DEVICE_USER=u \
    DEVICE_PASS=p bash "$STUBDIR/device/device-uninstall.sh"
  [[ "$output" == *"VLAN not set"* ]] || return 1
  [ "$status" -ne 0 ]
}
