#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for device/xr-uninstall.sh (agentinfo/plans/2026-08-28-xr-agent.md,
# Task 3): the receipt-driven inverse of device/xr-install.sh.

setup() {
  UNINSTALL="$BATS_TEST_DIRNAME/../xr-uninstall.sh"
}

# ---------------------------------------------------------------------------
# Dry-run text pins
# ---------------------------------------------------------------------------

@test "dry-run deactivates the app inside configure/commit" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  configure_line="$(printf '%s\n' "$output" | grep -n '^configure$' | head -1 | cut -d: -f1)"
  no_app_line="$(printf '%s\n' "$output" | grep -n '^no appmgr application iris$' | head -1 | cut -d: -f1)"
  commit_line="$(printf '%s\n' "$output" | grep -n '^commit$' | head -1 | cut -d: -f1)"
  [ -n "$configure_line" ] && [ -n "$no_app_line" ] && [ -n "$commit_line" ]
  [ "$configure_line" -lt "$no_app_line" ]
  [ "$no_app_line" -lt "$commit_line" ]
}

@test "dry-run uses the Cisco 8000 'source' uninstall form" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"appmgr package uninstall source iris-xr"* ]]
  [[ "$output" != *"appmgr package uninstall package"* ]]
}

@test "dry-run removes only the two IRIS-named files, via run rm" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"run rm -f /misc/disk1/iris-xr.rpm"* ]]
  [[ "$output" == *"run rm -rf /misc/disk1/iris-work"* ]]
}

@test "dry-run never emits a startup-config persist step" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  if printf '%s\n' "$output" | grep -qE '^copy running-config startup-config$'; then
    return 1
  fi
}

@test "dry-run respects APPID and SOURCE_NAME overrides" {
  APPID=probe SOURCE_NAME=probe-xr run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no appmgr application probe"* ]]
  [[ "$output" == *"appmgr package uninstall source probe-xr"* ]]
  [[ "$output" == *"run rm -f /misc/disk1/probe-xr.rpm"* ]]
}

@test "FORCE dry-run and receipted dry-run touch the identical IRIS-named footprint" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  plain="$output"
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  forced="$output"
  # every actual command line in the plain run also appears in the forced
  # run -- FORCE only prepends an explanatory banner, it does not change
  # what gets touched (see the script header: XR activation is --net=host
  # only, so nothing here is ever ambiguously operator-owned the way a
  # router's VirtualPortGroup/NAT can be).
  for line in "no appmgr application iris" "appmgr package uninstall source iris-xr" \
              "run rm -f /misc/disk1/iris-xr.rpm" "run rm -rf /misc/disk1/iris-work"; do
    [[ "$plain" == *"$line"* ]]
    [[ "$forced" == *"$line"* ]]
  done
}

@test "FORCE dry-run names only IRIS-marked artifacts, nothing switch/router-shaped" {
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"FORCE"* ]]
  # never a VLAN/VirtualPortGroup/NAT primitive -- XR activation never
  # creates any of these (host networking only).
  if printf '%s\n' "$output" | grep -Eq '(^|[[:space:]])vlan [0-9]|VirtualPortGroup|switchport|ip nat|ip access-list'; then
    return 1
  fi
}

@test "real teardown without credentials fails through the friendly guard, not an unbound variable" {
  run env -u DEVICE_IP -u DEVICE_USER -u DEVICE_PASS bash "$UNINSTALL"
  [ "$status" -ne 0 ]
  [[ "$output" == *"set DEVICE_IP"* ]]
  [[ "$output" != *"unbound variable"* ]]
}

# ---------------------------------------------------------------------------
# The commit-failure guard: the deactivate step's commit must ride
# lab/xr-run.sh, never a direct ssh call.
# ---------------------------------------------------------------------------

@test "the uninstaller opens no SSH session of its own" {
  count="$(grep -c 'sshpass' "$UNINSTALL" || true)"
  [ "$count" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Live path against a stubbed lab/xr-run.sh
# ---------------------------------------------------------------------------

_xr_uninstall_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device"
  FAKE_COMMAND_LOG="$BATS_TEST_TMPDIR/xr-commands.log"
  : > "$FAKE_COMMAND_LOG"
  export FAKE_COMMAND_LOG

  cat > "$STUBDIR/lab/xr-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
if [ -n "${FAKE_COMMAND_LOG:-}" ]; then
  { echo "=== CALL START ==="; printf '%s\n' "$cmds"; echo "=== CALL END ==="; } >> "$FAKE_COMMAND_LOG"
fi
case "$cmds" in
  *"__IRIS_XR_VERIFY_APPS__"*)
    echo "__IRIS_XR_VERIFY_APPS__"
    printf '%s\n' "${FAKE_APP_ROW-}"
    echo "__IRIS_XR_VERIFY_SOURCES__"
    printf '%s\n' "${FAKE_SOURCE_ROW-}"
    if [ "${FAKE_VERIFY_OMIT_FILES:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_FILES__"
      printf '%s\n' "${FAKE_DIR_HARDDISK-Directory of harddisk:/}"
    fi
    ;;
  *)
    echo "ok"
    ;;
esac
STUB
  chmod +x "$STUBDIR/lab/xr-run.sh"
  ln -sf "$UNINSTALL" "$STUBDIR/device/xr-uninstall.sh"
}

_xr_uninstall_run_live() {
  env DEVICE_IP=192.0.2.10 DEVICE_USER=admin DEVICE_PASS=pw \
    bash "$STUBDIR/device/xr-uninstall.sh"
}

@test "live: reports success once the app, source, and files are all gone" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ]
  [[ "$output" == *"undeploy complete"* ]]
}

@test "live: fails when the app is still listed after teardown" {
  _xr_uninstall_stub_setup
  FAKE_APP_ROW="iris  docker  iris-xr  Up  app_manager" run _xr_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"artifacts still present"* ]]
  [[ "$output" == *"appmgr application iris"* ]]
}

@test "live: fails when the source is still listed after teardown" {
  _xr_uninstall_stub_setup
  FAKE_SOURCE_ROW="iris-xr  0.1.0  ThinXR_7.3.15" run _xr_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"artifacts still present"* ]]
  [[ "$output" == *"appmgr source iris-xr"* ]]
}

@test "live: fails when the rpm or work dir is still listed on harddisk:" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 1024 Aug 27 12:00 iris-xr.rpm" run _xr_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"iris-xr.rpm"* ]]
}

@test "live: verify fails closed when a marker section never comes back" {
  _xr_uninstall_stub_setup
  FAKE_VERIFY_OMIT_FILES=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"did not return the harddisk: file check"* ]]
}

@test "live: FORCE mode sends the identical command sequence as receipted mode" {
  _xr_uninstall_stub_setup
  _xr_uninstall_run_live >/dev/null
  plain_log="$(cat "$FAKE_COMMAND_LOG")"
  : > "$FAKE_COMMAND_LOG"
  env DEVICE_IP=192.0.2.10 DEVICE_USER=admin DEVICE_PASS=pw IRIS_FORCE_AGENT_ONLY=1 \
    bash "$STUBDIR/device/xr-uninstall.sh" >/dev/null
  forced_log="$(cat "$FAKE_COMMAND_LOG")"
  [ "$plain_log" = "$forced_log" ]
}
