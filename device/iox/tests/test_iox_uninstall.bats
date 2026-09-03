#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  export DEVICE_IP=100.90.168.99 DEVICE_USER=u DEVICE_PASS=p VLAN=666
  UNINSTALL="$BATS_TEST_DIRNAME/../uninstall.sh"
}

# One assertion per @test (only the LAST command in a bats body sets status).

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

@test "dry-run tears the app down stop -> deactivate -> uninstall" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"app-hosting stop appid iris"* ]] && \
  [[ "$output" == *"app-hosting deactivate appid iris"* ]] && \
  [[ "$output" == *"app-hosting uninstall appid iris"* ]]
}

@test "dry-run removes the app-hosting appid config" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no app-hosting appid iris"* ]]
}

@test "dry-run removes the IRIS VLAN and SVI" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan666"* ]] && [[ "$output" == *"no vlan 666"* ]]
}

@test "dry-run removes any runtime EEM applets (no-op if absent)" {
  # the shared agent may leave IRIS-COPYROOT and the on-demand low-space
  # reclaim applets (IRIS-RECLAIM / IRIS-RECLAIM-BUNDLE) in running-config
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-AGENT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-RECLAIM"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-RECLAIM-BUNDLE"* ]]
}

@test "dry-run removes the PKI trustpoint with its yes confirm" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no ip http client secure-trustpoint IRIS"* ]] && \
  [[ "$output" == *$'no crypto pki trustpoint IRIS\nyes'* ]]
}

@test "dry-run deletes the staged app package" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete flash:iris-arm64.tar"* ]]
}

@test "dry-run leaves generic config and the sdflash image in place" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"LEFT IN PLACE"* ]] && \
  [[ "$output" == *"ip scp server"* ]] && \
  [[ "$output" == *"sdflash image"* ]]
}

@test "dry-run persists successful IOx cleanup" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"copy running-config startup-config"* ]]
}

@test "custom VLAN and PKG_FS flow into the removal" {
  VLAN=42 PKG_FS=sdflash: run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan42"* ]] && \
  [[ "$output" == *"delete sdflash:iris-arm64.tar"* ]]
}

@test "real run refuses to start without DEVICE_PASS" {
  unset DEVICE_PASS
  run bash "$UNINSTALL"
  [ "$status" -ne 0 ]
}

@test "real run refuses an empty VLAN instead of guessing 666" {
  VLAN='' run bash "$UNINSTALL"
  [ "$status" -ne 0 ] && [[ "$output" == *"VLAN not set"* ]]
}

@test "inband dry-run removes only the app footprint" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no app-hosting appid iris"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]]
}

@test "inband dry-run keeps the existing VLAN/SVI but clears IRIS-named config" {
  # "Operator-owned" is the VLAN and its SVI -- network IRIS merely configured,
  # which no deployment record proves it created. The IRISQ discriminator and
  # the IRIS PKI trustpoint carry IRIS's own name, so a teardown clears them
  # in every mode: leaving them behind is what made a "clean" device refuse
  # the next onboard on an artifact we put there ourselves.
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"no vlan "* ]] || return 1
  [[ "$output" != *"no interface Vlan"* ]] || return 1
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]] || return 1
  [[ "$output" == *"no logging discriminator IRISQ"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "dry-run with SHARE_IOS_PATH removes only iris-prefixed share files" {
  SHARE_IOS_PATH=usbflash1:iox_host_data_share run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete /force usbflash1:iox_host_data_share/iris-staged.bin"* ]] && \
  [[ "$output" == *"delete /force usbflash1:iox_host_data_share/iris-probe.txt"* ]] && \
  [[ "$output" == *"delete /force /recursive usbflash1:iox_host_data_share/iris"* ]] && \
  [[ "$output" != *"delete /force /recursive usbflash1:iox_host_data_share
"* ]]
}

@test "dry-run without SHARE_IOS_PATH never touches the CAF share" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"iox_host_data_share"* ]]
}

# --- guest-share/iris cleanup (IE-3400 scp-push staging dir) ---------------
# The agent SCP-pushes the image to <target_fs>guest-share/iris on IE-3400
# (and on any C9300 that falls back from the share mount). Undeploy left that
# directory behind: the app package and the SSD-share files were removed, this
# one never was. Mirrors the Guest Shell uninstaller, which has always cleaned
# its guest-share.

@test "dry-run removes the scp-push staging dir under guest-share" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete /force /recursive sdflash:guest-share/iris"* ]]
}

@test "dry-run honors TARGET_FS for the staging dir" {
  TARGET_FS=flash: run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete /force /recursive flash:guest-share/iris"* ]]
}

@test "dry-run never deletes the guest-share root itself" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"delete /force /recursive sdflash:guest-share"$'\n'* ]] && \
  [[ "$output" != *"delete /force sdflash:guest-share"$'\n'* ]]
}

@test "dry-run verification mentions the staging dir" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"guest-share/iris"* ]]
}

# --- IRIS_FORCE_AGENT_ONLY: record-less force undeploy ----------------------
# A device stranded WITHOUT a deployment record has no record to prove the
# VLAN/SVI is IRIS-owned. gui_server.py sets IRIS_FORCE_AGENT_ONLY=1 for exactly
# this case; force preserves that operator network while still removing every
# artifact carrying IRIS's own name.

@test "force dry-run keeps the operator VLAN but clears IRIS-named config" {
  # "Operator-owned" is the VLAN and its SVI -- network IRIS merely configured,
  # which no deployment record proves it created. The IRISQ discriminator and
  # the IRIS PKI trustpoint carry IRIS's own name, so a teardown clears them
  # in every mode: leaving them behind is what made a "clean" device refuse
  # the next onboard on an artifact we put there ourselves.
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"no interface Vlan"* ]] || return 1
  [[ "$output" != *"no vlan 666"* ]] || return 1
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]] || return 1
  [[ "$output" == *"no logging discriminator IRISQ"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "non-force dry-run DOES emit the operator-owned teardown commands" {
  # proves the gate actually gates: without IRIS_FORCE_AGENT_ONLY, the same
  # routed default undeploy still removes the VLAN/SVI and trustpoint
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no interface Vlan666"* ]] && \
  [[ "$output" == *"no vlan 666"* ]] && \
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]]
}

@test "force dry-run still removes the full IRIS agent footprint" {
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"app-hosting stop appid iris"* ]] && \
  [[ "$output" == *"app-hosting deactivate appid iris"* ]] && \
  [[ "$output" == *"app-hosting uninstall appid iris"* ]] && \
  [[ "$output" == *"no app-hosting appid iris"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]] && \
  [[ "$output" == *"delete flash:iris-arm64.tar"* ]] && \
  [[ "$output" == *"delete /force /recursive sdflash:guest-share/iris"* ]]
}


# --- record-less force rescue: the VLAN guard must not gate it --------------
# Force mode never uses VLAN -- config_cleanup returns before any Vlan$VLAN
# line and the verify filter drops every VLAN term -- yet its absence aborted
# the rescue before the script reached the device.

_iox_uninstall_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device/iox"
  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
cat > /dev/null
# No app-hosting entry, no matching config: the device reads as already clean,
# so both poll loops exit on their first pass and nothing sleeps.
echo "[OK]"
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"
  ln -sf "$UNINSTALL" "$STUBDIR/device/iox/uninstall.sh"
}

@test "forced teardown does not demand a VLAN it will never use" {
  # A bare legacy_routed fleet row carries no vlan at all, so this closed the
  # only exit a record-less device had: the force banner even says Vlan$VLAN
  # is NOT touched.
  _iox_uninstall_stub_setup
  run env -u VLAN -u INBAND_VLAN DEVICE_IP=192.0.2.10 DEVICE_USER=u \
    DEVICE_PASS=p IRIS_FORCE_AGENT_ONLY=1 \
    bash "$STUBDIR/device/iox/uninstall.sh"
  [[ "$output" != *"VLAN not set"* ]] || return 1
  [[ "$output" == *"Removing:"*"IRISQ"*"IRIS PKI"* ]] || return 1
  [[ "$output" == *"Preserving: operator VLAN/SVI"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "non-forced teardown still refuses to guess a missing VLAN" {
  # The guard is correct for a record-driven teardown -- it must keep firing there.
  _iox_uninstall_stub_setup
  run env -u VLAN -u INBAND_VLAN DEVICE_IP=192.0.2.10 DEVICE_USER=u \
    DEVICE_PASS=p bash "$STUBDIR/device/iox/uninstall.sh"
  [[ "$output" == *"VLAN not set"* ]] || return 1
  [ "$status" -ne 0 ]
}


# --- EXPECTED_DEVICE_IDENTITY: the record binds the teardown to one box ------
# The console passes the deployment record's processor board ID. The first
# device session is then a read-only `show version`, and no destructive
# command is sent unless the live board ID matches -- mirrors the router
# uninstaller and the IOx installer's own guard. Force mode (record-less
# rescue) has nothing to compare against and skips it.

_iox_identity_stub_setup() {
  # $1 = the board ID the stub device reports ("" = a truncated session that
  # never returns one). Every command the script sends is logged, so the
  # tests can prove nothing destructive went out before the abort.
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device/iox"
  export IRIS_STUB_LOG="$BATS_TEST_TMPDIR/sent.log" IRIS_STUB_BOARD_ID="$1"
  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
printf '%s\n' "$cmds" >> "$IRIS_STUB_LOG"
if printf '%s\n' "$cmds" | grep -q '^show version'; then
  echo "Cisco IOS XE Software, Version 17.15.01"
  echo "cisco IE-3400-8T2S (ARM) processor with 512K bytes of memory."
  [ -n "$IRIS_STUB_BOARD_ID" ] && echo "Processor board ID $IRIS_STUB_BOARD_ID"
  exit 0
fi
echo "[OK]"
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"
  ln -sf "$UNINSTALL" "$STUBDIR/device/iox/uninstall.sh"
}

_sent_destructive() {
  grep -E '^(app-hosting (stop|deactivate|uninstall)|no |configure terminal|delete |copy running-config)' \
    "$IRIS_STUB_LOG" || true
}

@test "identity mismatch aborts before any destructive command" {
  _iox_identity_stub_setup FCW9999LIVE
  run env DEVICE_IP=192.0.2.10 DEVICE_USER=u DEVICE_PASS=p VLAN=666 \
    EXPECTED_DEVICE_IDENTITY=FCW1234RECORD \
    bash "$STUBDIR/device/iox/uninstall.sh"
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"device identity mismatch"* ]] || return 1
  [[ "$output" == *"FCW1234RECORD"*"FCW9999LIVE"* ]] || return 1
  [[ "$output" == *"undeploy it again with Force"* ]] || return 1
  # the ONLY session was the read-only probe
  grep -q '^show version' "$IRIS_STUB_LOG" || return 1
  [ -z "$(_sent_destructive)" ]
}

@test "a session that returns no board ID aborts instead of proceeding" {
  # a dropped or unauthenticated session must never read as "identity ok"
  _iox_identity_stub_setup ""
  run env DEVICE_IP=192.0.2.10 DEVICE_USER=u DEVICE_PASS=p VLAN=666 \
    EXPECTED_DEVICE_IDENTITY=FCW1234RECORD \
    bash "$STUBDIR/device/iox/uninstall.sh"
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"could not read the processor board ID"* ]] || return 1
  [ -z "$(_sent_destructive)" ]
}

@test "matching identity proceeds with the teardown" {
  _iox_identity_stub_setup FCW1234RECORD
  run env DEVICE_IP=192.0.2.10 DEVICE_USER=u DEVICE_PASS=p VLAN=666 \
    EXPECTED_DEVICE_IDENTITY=FCW1234RECORD \
    bash "$STUBDIR/device/iox/uninstall.sh"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" != *"identity mismatch"* ]] || return 1
  # show version came FIRST, then the teardown
  first="$(grep -nE '^(show version|app-hosting stop)' "$IRIS_STUB_LOG" | head -1)"
  [[ "$first" == *"show version"* ]] || return 1
  grep -q '^app-hosting stop appid iris' "$IRIS_STUB_LOG"
}

@test "without EXPECTED_DEVICE_IDENTITY the teardown runs as before (no probe)" {
  _iox_identity_stub_setup FCW9999LIVE
  run env -u EXPECTED_DEVICE_IDENTITY DEVICE_IP=192.0.2.10 DEVICE_USER=u \
    DEVICE_PASS=p VLAN=666 bash "$STUBDIR/device/iox/uninstall.sh"
  [ "$status" -eq 0 ] || return 1
  ! grep -q '^show version' "$IRIS_STUB_LOG"
}

@test "force mode skips the identity check (record-less rescue)" {
  _iox_identity_stub_setup FCW9999LIVE
  run env -u VLAN -u INBAND_VLAN DEVICE_IP=192.0.2.10 DEVICE_USER=u DEVICE_PASS=p \
    IRIS_FORCE_AGENT_ONLY=1 EXPECTED_DEVICE_IDENTITY=FCW1234RECORD \
    bash "$STUBDIR/device/iox/uninstall.sh"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" != *"identity mismatch"* ]]
}

@test "the header documents EXPECTED_DEVICE_IDENTITY" {
  grep -q 'EXPECTED_DEVICE_IDENTITY' "$UNINSTALL"
  head -50 "$UNINSTALL" | grep -q 'EXPECTED_DEVICE_IDENTITY'
}
