#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  export DEVICE_IP=100.92.9.3 VLAN=666 \
    SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 GUEST_IP=100.92.9.126 \
    CATALOG_URL=https://100.90.168.20:8443 CATALOG_TOKEN=deadbeef \
    DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 RPC_SECRET=s3cr3t \
    HOST_USER=testuser HOST_PASS=testpass
  INSTALL="$BATS_TEST_DIRNAME/../device-install.sh"
}

# NOTE: each config assertion is its OWN @test — in bats only the LAST command
# in a @test body sets the exit code, so multiple [[ ]] in one @test silently
# pass even when earlier ones fail. One assertion per @test so every regression
# fails the suite independently (especially the load-bearing file prompt quiet
# and authorization bypass lines — see finding #25 / test_eem_cfgs.bats note).

@test "dry-run exits 0" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "dry-run emits iox" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"iox"* ]]
}

@test "dry-run emits vlan 666" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"vlan 666"* ]]
}

@test "dry-run emits interface Vlan666" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"interface Vlan666"* ]]
}

@test "dry-run emits the SVI ip address" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"ip address 100.92.9.125 255.255.255.252"* ]]
}

@test "dry-run emits ip router isis" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"ip router isis"* ]]
}

@test "dry-run emits app-hosting appid guestshell" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"app-hosting appid guestshell"* ]]
}

@test "dry-run emits guest-ipaddress" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"guest-ipaddress 100.92.9.126"* ]]
}

@test "dry-run emits app-default-gateway" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"app-default-gateway 100.92.9.125"* ]]
}

@test "dry-run emits app-resource profile custom" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"app-resource profile custom"* ]]
}

@test "dry-run emits file prompt quiet (required for non-interactive EEM copy)" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"file prompt quiet"* ]]
}

@test "dry-run emits IRIS-AGENT authorization bypass (required on AAA nodes)" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"event manager applet IRIS-AGENT authorization bypass"* ]]
}

@test "dry-run does NOT define IRIS-COPYROOT (agent templates it at runtime)" {
  # the agent templates IRIS-COPYROOT at runtime; the installer must NOT define it
  run bash "$INSTALL" --dry-run
  [[ "$output" != *"event manager applet IRIS-COPYROOT"* ]]
}

@test "dry-run writes the agent config with catalog_url" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"catalog_url = https://100.90.168.20:8443"* ]]
}

@test "dry-run writes the agent config with catalog_token" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"catalog_token = deadbeef"* ]]
}

@test "dry-run writes the agent config with device_id" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"device_id = 100.92.9.3"* ]]
}

@test "dry-run agent config emits token_expires_at = 0 (refresh on first tick)" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"token_expires_at = 0"* ]]
}

@test "dry-run agent config emits an EMPTY rpc_secret line (agent fills it on refresh)" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"rpc_secret = "* ]]
}

@test "dry-run agent config does NOT bake a real rpc_secret value" {
  run bash "$INSTALL" --dry-run
  # setup() exports RPC_SECRET=s3cr3t; it must NOT land in the rendered conf
  [[ "$output" != *"rpc_secret = s3cr3t"* ]]
}

@test "refuses to run without required vars" {
  run env -u DEVICE_IP bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
}

# --- TLS trust: trustpoint push + verified-https copies + pinned cafile (#2) ---
# Each assertion is its OWN @test: in bats, only the LAST statement in a @test body
# sets the exit code, so consecutive [[ ]] lines hide earlier failures. One assertion
# per @test guarantees each one — ESPECIALLY the negative "no copy http://" — fails
# the suite independently if it regresses. setup() does NOT export IRIS_CRT_FILE, so
# these also prove --dry-run renders the secure flow with no cert file on disk.

@test "dry-run renders the PKI trustpoint block" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"crypto pki trustpoint IRIS"* ]]
}

@test "dry-run answers the trustpoint accept [yes/no] prompts (hardware-validated)" {
  run bash "$INSTALL" --dry-run
  # without the `yes` lines the CA never imports and copy https: fails on real IOS
  [[ "$output" == *"yes"* ]]
}

@test "dry-run selects the IRIS trustpoint as the http client secure-trustpoint" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"ip http client secure-trustpoint IRIS"* ]]
}

@test "dry-run renders the install copies over https" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"copy https://100.90.168.20:8000/"* ]]
}

@test "dry-run contains NO cleartext copy http:// (the #2 negative assertion)" {
  run bash "$INSTALL" --dry-run
  [[ "$output" != *"copy http://"* ]]
}

@test "dry-run agent config pins the catalog CA" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"catalog_ca = /flash/guest-share/iris/iris-catalog.pem"* ]]
}

# --- model-aware install: the install path must branch by device (#18) ---
# The default (no MODEL / a cat9k) MUST stay byte-for-byte the C9300 behavior so
# the live 9300 fleet is unaffected; an IE-3x00 selects its own app-hosting
# interface, the SD-card staging filesystem, and the ARM agent bundle. One
# discriminating assertion per @test (see the bats note above): the negatives
# that prove no cross-model leak must each fail the suite on their own.

@test "C9300 default keeps the 9300 app-hosting interface" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"interface AppGigabitEthernet1/0/1"* ]]
}

@test "C9300 default stages on flash: (no sdflash: leak)" {
  run bash "$INSTALL" --dry-run
  [[ "$output" != *"sdflash:"* ]]
}

@test "C9300 default ships the x86 bundle (no ARM bundle leak)" {
  run bash "$INSTALL" --dry-run
  [[ "$output" != *"iris-agent-arm.tgz"* ]]
}

@test "IE-3400 selects the IE app-hosting interface AppGigabitEthernet1/1" {
  run env MODEL=IE-3400-8T2S bash "$INSTALL" --dry-run
  [[ "$output" == *"interface AppGigabitEthernet1/1"* ]]
}

@test "IE-3400 does NOT emit the C9300 app-hosting interface" {
  run env MODEL=IE-3400-8T2S bash "$INSTALL" --dry-run
  [[ "$output" != *"AppGigabitEthernet1/0/1"* ]]
}

@test "IE-3400 stages on the SD card (sdflash:/guest-share)" {
  run env MODEL=IE-3400-8T2S bash "$INSTALL" --dry-run
  [[ "$output" == *"sdflash:/guest-share"* ]]
}

@test "IE-3400 ships the ARM agent bundle" {
  run env MODEL=IE-3400-8T2S bash "$INSTALL" --dry-run
  [[ "$output" == *"iris-agent-arm.tgz"* ]]
}

@test "explicit APP_INTF override beats model detection" {
  run env MODEL=IE-3400-8T2S APP_INTF=AppGigabitEthernet9/9 bash "$INSTALL" --dry-run
  [[ "$output" == *"interface AppGigabitEthernet9/9"* ]]
}

@test "explicit IOS_FS override beats model detection" {
  run env MODEL=IE-3400-8T2S IOS_FS=bootflash: bash "$INSTALL" --dry-run
  [[ "$output" == *"bootflash:/guest-share"* ]]
}

@test "real-run IOS_ROOT is derived from IOS_FS (not hardcoded flash:/guest-share)" {
  # Structural guard: the real-run path (DRY=0) must compute IOS_ROOT from
  # IOS_FS the same way the dry-run does, so an IE-3400 copies to sdflash:
  # instead of flash:. The hardcoded literal must not appear in the script.
  ! grep -qF 'IOS_ROOT="flash:/guest-share"' "$INSTALL"
}

@test "IE-3400 dry-run copy commands resolve to sdflash:/guest-share (behavioral IOS_ROOT check)" {
  # Behavioral companion to the structural guard above.  Runs the actual
  # dry-run with MODEL=IE-3400-8T2S and asserts the generated copy commands
  # contain 'sdflash:/guest-share' as the destination root.  This catches
  # regressions like IOS_ROOT='flash:/guest-share' (single-quote, evades grep)
  # or IOS_ROOT="${IOS_FS:-flash:}/guest-share" (wrong default).
  run env MODEL=IE-3400-8T2S bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  # The INSTALL COPIES section must use sdflash:/guest-share as the target FS.
  [[ "$output" == *"sdflash:/guest-share"* ]]
  # And must NOT use flash:/guest-share (the C9300 path).
  [[ "$output" != *" flash:/guest-share"* ]]
}

# --- co-located staging (#13): the console runs in the SAME container as the
# artifact server, so step [2/6] must be able to stage locally without ssh
# and without HOST_USER/HOST_PASS, honoring IRIS_ARTIFACTS_DIR for where the
# artifact server actually serves from (not a repo-relative path that doesn't
# exist in the container). See device-install.sh step [2/6].

setup_stage_local() {
  # a real (non-dry-run) invocation only needs to get PAST step [2/6]; stub
  # lab/device-run.sh so step [1/6]'s flash pre-check is a harmless no-op and
  # step [3/6]+ (which needs a real device) never gets reached because we
  # kill the script right after [2/6] finishes.
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab"
  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null   # drain stdin (the CLI commands piped to the "device")
echo "bytes free stub"
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"
  # device-install.sh resolves lab/device-run.sh as "$HERE/../lab/device-run.sh";
  # HERE is the dir containing device-install.sh itself, so symlink the real
  # script into a scratch tree that mirrors <root>/device and <root>/lab.
  mkdir -p "$STUBDIR/device"
  ln -s "$INSTALL" "$STUBDIR/device/device-install.sh"
  cp "$BATS_TEST_DIRNAME/../bootstrap.sh" "$STUBDIR/device/bootstrap.sh" 2>/dev/null || true

  ARTDIR="$BATS_TEST_TMPDIR/artifacts"
  mkdir -p "$ARTDIR"
  CRTFILE="$BATS_TEST_TMPDIR/crt.pem"
  echo "-----BEGIN CERTIFICATE-----fake-----END CERTIFICATE-----" > "$CRTFILE"
}

# Portable stand-in for GNU `timeout` (not present on macOS/BSD by default):
# backgrounds the command, waits up to $1 seconds, then kills it if still
# alive. Echoes captured stdout+stderr and `exit`s with its exit code (or 124
# on kill) so it composes with bats' own `run` (which captures $output/$status
# from THIS function's output/exit code, without letting a non-zero code fail
# the test the way calling it bare would).
_run_with_timeout_impl() {
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

run_with_timeout() {
  run _run_with_timeout_impl "$@"
}

@test "IRIS_STAGE_LOCAL=1 stages the per-device config without HOST_USER/HOST_PASS" {
  setup_stage_local
  unset HOST_USER HOST_PASS

  # step [4/6] (guestshell wait) polls up to ~7 minutes on a stub that never
  # reports RUNNING; bound the run and grep captured output -- we only care
  # that [2/6] succeeded (staged files + no HOST_USER fatal) before the
  # script moves on, not that later steps complete.
  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" \
    bash "$STUBDIR/device/device-install.sh"

  [[ "$output" != *"set HOST_USER"* ]]
  [ -f "$ARTDIR/staging/iris-agent-100.92.9.3.conf" ]
  [ -f "$ARTDIR/staging/rpc-secret" ]
}

@test "without IRIS_STAGE_LOCAL and a non-local STAGE_HOST, the remote ssh path still demands HOST_USER" {
  setup_stage_local
  unset HOST_USER HOST_PASS

  run_with_timeout 5 env IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" \
    bash "$STUBDIR/device/device-install.sh"

  [[ "$output" == *"set HOST_USER"* ]]
  [ ! -f "$ARTDIR/staging/iris-agent-100.92.9.3.conf" ]
}

# --- read-only served-tree regression (#13 follow-up): make-agent-bundle.sh
# already places bootstrap.sh + iris-catalog.pem at the artifacts ROOT before
# the container ever runs an install, and that root is a read-only mount in
# the co-located console/container case (only artifacts/staging is writable).
# device-install.sh must NOT try to re-copy those two already-provisioned
# files — it should skip them and still complete step [2/6] cleanly.
@test "IRIS_STAGE_LOCAL=1 with already-provisioned root files + read-only root: [2/6] succeeds, no re-copy attempted" {
  setup_stage_local
  unset HOST_USER HOST_PASS

  # pre-provision the two root files, exactly as make-agent-bundle.sh does
  echo "#!/usr/bin/env bash" > "$ARTDIR/bootstrap.sh"
  echo "-----BEGIN CERTIFICATE-----already-here-----END CERTIFICATE-----" > "$ARTDIR/iris-catalog.pem"
  BOOT_SUM_BEFORE="$(cat "$ARTDIR/bootstrap.sh")"
  CRT_SUM_BEFORE="$(cat "$ARTDIR/iris-catalog.pem")"
  # staging/ must pre-exist and stay writable — it's a separate sub-mount in
  # the real container layout, created ahead of time rather than by the
  # script's own `mkdir -p` (which would fail once the root below is r/o)
  mkdir -p "$ARTDIR/staging"

  # now make the artifacts ROOT read-only (staging/ underneath stays writable —
  # a separate sub-mount, mirroring the real container layout)
  chmod a-w "$ARTDIR"

  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" \
    bash "$STUBDIR/device/device-install.sh"

  chmod u+w "$ARTDIR"   # restore so bats can clean up BATS_TEST_TMPDIR

  [[ "$output" != *"Read-only file system"* ]]
  [ -f "$ARTDIR/staging/iris-agent-100.92.9.3.conf" ]
  [ -f "$ARTDIR/staging/rpc-secret" ]
  # untouched — the pre-existing content must survive (no re-copy happened)
  [ "$(cat "$ARTDIR/bootstrap.sh")" = "$BOOT_SUM_BEFORE" ]
  [ "$(cat "$ARTDIR/iris-catalog.pem")" = "$CRT_SUM_BEFORE" ]
}

@test "IRIS_STAGE_LOCAL=1 with ABSENT root files + writable root: they DO get copied (laptop path intact)" {
  setup_stage_local
  unset HOST_USER HOST_PASS

  # confirm the fixture starts clean (setup_stage_local doesn't pre-create these)
  [ ! -e "$ARTDIR/bootstrap.sh" ]
  [ ! -e "$ARTDIR/iris-catalog.pem" ]

  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" \
    bash "$STUBDIR/device/device-install.sh"

  [ -f "$ARTDIR/bootstrap.sh" ]
  [ -f "$ARTDIR/iris-catalog.pem" ]
}
