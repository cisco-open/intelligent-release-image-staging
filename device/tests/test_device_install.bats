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

@test "stale NETWORK_ATTACHMENT without MANAGEMENT_TYPE aborts; a normal env is unaffected" {
  run env -u MANAGEMENT_TYPE NETWORK_ATTACHMENT=inband bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE"* ]] || return 1
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

# IRIS-11-005: `ip router isis` used to be unconditional (this test asserted
# it). It is now opt-in per record via SVI_IGP=isis, so IRIS never injects its
# subnet into an IGP -- or creates a `router isis` process -- unasked.
@test "dry-run does NOT emit ip router isis unless SVI_IGP=isis" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ] || return 1
  [[ "$output" != *"ip router isis"* ]]
}

@test "dry-run emits ip router isis on the SVI when SVI_IGP=isis" {
  SVI_IGP=isis run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *$'ip address 100.92.9.125 255.255.255.252\n ip router isis'* ]]
}

@test "an unknown SVI_IGP is refused" {
  SVI_IGP=ospf run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"SVI_IGP must be"* ]]
}

@test "routed dry-run trunks the AppGig ADDITIVELY, never with the bare (replacing) form" {
  # The bare form replaces the allowed list on the switch's single app-hosting
  # uplink, dropping every other IOx app's VLAN.
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"switchport trunk allowed vlan add 666"* ]] || return 1
  ! grep -Eq 'switchport trunk allowed vlan [0-9]' <<<"$output"
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

@test "dry-run persists successful Guest Shell onboarding" {
  run bash "$INSTALL" --dry-run
  [[ "$output" == *"copy running-config startup-config"* ]]
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
# artifact server, so step [2/7] must be able to stage locally without ssh
# and without HOST_USER/HOST_PASS, honoring IRIS_ARTIFACTS_DIR for where the
# artifact server actually serves from (not a repo-relative path that doesn't
# exist in the container). See device-install.sh step [2/7].

setup_stage_local() {
  # a real (non-dry-run) invocation only needs to get PAST step [2/7]; stub
  # lab/device-run.sh so step [1/7]'s flash pre-check is a harmless no-op and
  # step [3/7]+ (which needs a real device) never gets reached because we
  # kill the script right after [2/7] finishes. The [pre] PREREQ step now
  # sits between [1/7] and [2/7] (routed by default), so the stub must also
  # answer the ip-routing / clock checks — FAKE_IP_ROUTING defaults "yes" and
  # FAKE_CLOCK_LINE defaults to a recent year so every pre-existing test below
  # still sails past [pre] unmodified; only the dedicated PREREQ tests further
  # down override those.
  #
  # [1/7]+[pre] now ride ONE combined SSH session (marker __IRIS_PRECHECK_)
  # instead of up to three — see device-install.sh. The stub recognizes that
  # single request by the marker prefix and answers all of its sections
  # (FLASH always, ROUTING only when the request actually asked for it, i.e.
  # MANAGEMENT_TYPE=routed, CLOCK always) in one reply. Real sessions echo
  # commands back; FAKE_DEVICE_DOWN=yes simulates a dead session that echoes
  # nothing at all — no markers either — which is exactly what a missing
  # section looks like to the installer's fail-closed ROUTING parse.
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab"
  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"   # drain stdin (the CLI commands piped to the "device")
case "$cmds" in
  *"__IRIS_PRECHECK_"*)
    [ "${FAKE_DEVICE_DOWN:-no}" = "yes" ] && exit 0
    echo "__IRIS_PRECHECK_FLASH__"
    echo "bytes free stub"
    case "$cmds" in
      *"__IRIS_PRECHECK_ROUTING__"*)
        echo "__IRIS_PRECHECK_ROUTING__"
        echo "show running-config | include no ip routing"
        if [ "${FAKE_IP_ROUTING:-yes}" = "yes" ]; then
          echo "Gateway of last resort is 100.90.168.1 to network 0.0.0.0"
        else
          echo "no ip routing"
          echo "Default gateway is not set"
        fi
        ;;
    esac
    echo "__IRIS_PRECHECK_CLOCK__"
    echo "${FAKE_CLOCK_LINE:-14:23:07.512 UTC Thu Aug 20 2026}"
    ;;
  *)
    echo "bytes free stub"
    ;;
esac
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

  # step [4/7] (guestshell wait) polls up to ~7 minutes on a stub that never
  # reports RUNNING; bound the run and grep captured output -- we only care
  # that [2/7] succeeded (staged files + no HOST_USER fatal) before the
  # script moves on, not that later steps complete.
  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" \
    bash "$STUBDIR/device/device-install.sh"

  [[ "$output" != *"set HOST_USER"* ]]
  [ "$(find "$ARTDIR/staging" -name 'iris-agent-100.92.9.3-*.conf' | wc -l)" -eq 1 ]
  [ "$(find "$ARTDIR/staging" -name 'rpc-secret-*' | wc -l)" -eq 1 ]
}

@test "without IRIS_STAGE_LOCAL and a non-local STAGE_HOST, the remote ssh path still demands HOST_USER" {
  setup_stage_local
  unset HOST_USER HOST_PASS

  # STAGE_HOST must be an address this machine CANNOT own: device-install.sh
  # decides locality with `ip -o addr | grep -qw "$STAGE_HOST"`, so a real lab
  # address makes the test take the local-staging branch (and silently stop
  # proving anything) on the very host that owns it. 192.0.2.10 is TEST-NET-1
  # (RFC 5737), reserved for documentation and never assigned to an interface.
  run_with_timeout 5 env IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=192.0.2.10 \
    IRIS_CRT_FILE="$CRTFILE" \
    bash "$STUBDIR/device/device-install.sh"

  [[ "$output" == *"set HOST_USER"* ]]
  [ "$(find "$ARTDIR" -name 'iris-agent-100.92.9.3-*.conf' | wc -l)" -eq 0 ]
}

# --- read-only served-tree regression (#13 follow-up): make-agent-bundle.sh
# already places bootstrap.sh + iris-catalog.pem at the artifacts ROOT before
# the container ever runs an install, and that root is a read-only mount in
# the co-located console/container case (only artifacts/staging is writable).
# device-install.sh must NOT try to re-copy those two already-provisioned
# files — it should skip them and still complete step [2/7] cleanly.
@test "IRIS_STAGE_LOCAL=1 with already-provisioned root files + read-only root: [2/7] succeeds, no re-copy attempted" {
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
  [ "$(find "$ARTDIR/staging" -name 'iris-agent-100.92.9.3-*.conf' | wc -l)" -eq 1 ]
  [ "$(find "$ARTDIR/staging" -name 'rpc-secret-*' | wc -l)" -eq 1 ]
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

# --- inband Guest Shell (network-preserving; must still enable iox) ---
_inband() {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=198.51.100.20 \
    APP_MASK=255.255.255.0 APP_GATEWAY=198.51.100.1 \
    bash "$INSTALL" --dry-run
}

@test "inband dry-run enables iox (app-hosting subsystem needed for guestshell)" {
  run _inband
  [ "$status" -eq 0 ] && [[ "$output" == *$'\niox\n'* ]]
}

@test "inband dry-run emits app-hosting appid guestshell" {
  run _inband
  [[ "$output" == *"app-hosting appid guestshell"* ]]
}

@test "inband dry-run preserves the existing network (no vlan/SVI/bare-trunk/isis)" {
  run _inband
  [[ "$output" != *$'\nvlan '* ]] && [[ "$output" != *"interface Vlan"* ]] && \
  ! grep -Eq 'switchport trunk allowed vlan [0-9]' <<<"$output" && \
  [[ "$output" != *"ip router isis"* ]]
}

@test "inband dry-run trunks the AppGig additively (mode trunk + allowed vlan add)" {
  run _inband
  [[ "$output" == *"interface AppGigabitEthernet1/0/1"* ]] && \
  [[ "$output" == *"switchport mode trunk"* ]] && \
  [[ "$output" == *"switchport trunk allowed vlan add 120"* ]]
}

@test "inband Guest Shell does NOT disable app signature verification (IOx/SSD only)" {
  run _inband
  [[ "$output" != *"verification disable"* ]]
}

# --- operator-facing PREREQ checks (2026-08-20 incident: an IE-3400 lost `ip
# routing` on re-image; onboarding "succeeded" while the app's VLAN traffic had
# no L3 path out — silent, invisible, hours to diagnose). Static assertions
# first, then stub-backed behavioral tests using setup_stage_local's fake
# lab/device-run.sh (extended above with FAKE_IP_ROUTING / FAKE_CLOCK_LINE). ---

@test "checks ip routing before applying any config (PREREQ, routed only)" {
  # semantic detection: explicit `no ip routing` / host-mode route table —
  # NOT a grep for the positive `ip routing` line, which is absent when
  # routing is the platform default (IE3x00 false-positive, 2026-08-20)
  run grep -F 'show running-config | include no ip routing' "$INSTALL"
  [ "$status" -eq 0 ]
  run grep -F 'PREREQ: ip routing is disabled on this switch' "$INSTALL"
  [ "$status" -eq 0 ]
  run grep -F 'PREREQ: could not verify ip routing' "$INSTALL"
  [ "$status" -eq 0 ]
}

@test "warns (not fails) on a stale device clock (PREREQ)" {
  run grep -F 'PREREQ WARNING: device clock is' "$INSTALL"
  [ "$status" -eq 0 ]
}

@test "PREREQ checks land before step [2/7] stages the agent config" {
  pre_line="$(grep -n '^echo "\[pre\] prerequisite checks' "$INSTALL" | head -1 | cut -d: -f1)"
  step2_line="$(grep -n '^echo "\[2/7\]' "$INSTALL" | head -1 | cut -d: -f1)"
  [ -n "$pre_line" ] && [ -n "$step2_line" ] && [ "$pre_line" -lt "$step2_line" ]
}

@test "does NOT check ip routing on the inband path (no IRIS-managed SVI)" {
  # inband rides the operator's own already-routed network; only routed
  # creates the IRIS-managed SVI this prerequisite protects.
  run _inband
  [[ "$output" != *"PREREQ: ip routing is disabled"* ]]
}

@test "ip routing missing: real run exits non-zero with the PREREQ line" {
  setup_stage_local
  unset HOST_USER HOST_PASS

  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" FAKE_IP_ROUTING=no \
    bash "$STUBDIR/device/device-install.sh"

  [ "$status" -ne 0 ]
  [[ "$output" == *"PREREQ: ip routing is disabled on this switch"* ]]
  # must fail BEFORE staging — [pre] sits ahead of [2/7]
  [ "$(find "$ARTDIR" -name 'iris-agent-100.92.9.3-*.conf' | wc -l)" -eq 0 ]
}

@test "dead device session: PREREQ says transport, not routing" {
  # a session that produces no output must not masquerade as a routing
  # problem (the old check conflated the two)
  setup_stage_local
  unset HOST_USER HOST_PASS

  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" FAKE_DEVICE_DOWN=yes \
    bash "$STUBDIR/device/device-install.sh"

  [ "$status" -ne 0 ]
  [[ "$output" == *"PREREQ: could not verify ip routing"* ]]
  [[ "$output" != *"PREREQ: ip routing is disabled"* ]]
}

@test "ip routing present: real run proceeds past the check to step [2/7]" {
  setup_stage_local
  unset HOST_USER HOST_PASS

  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" FAKE_IP_ROUTING=yes \
    bash "$STUBDIR/device/device-install.sh"

  [[ "$output" != *"PREREQ: ip routing is disabled"* ]]
  [ "$(find "$ARTDIR/staging" -name 'iris-agent-100.92.9.3-*.conf' | wc -l)" -eq 1 ]
}

@test "old device clock: real run warns but continues past the check" {
  setup_stage_local
  unset HOST_USER HOST_PASS

  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" FAKE_IP_ROUTING=yes \
    FAKE_CLOCK_LINE="14:23:07.512 UTC Thu Aug 20 2018" \
    bash "$STUBDIR/device/device-install.sh"

  [[ "$output" == *"PREREQ WARNING: device clock is 2018"* ]]
  [ "$(find "$ARTDIR/staging" -name 'iris-agent-100.92.9.3-*.conf' | wc -l)" -eq 1 ]
}

@test "unparseable device clock: the optional probe must not abort the install" {
  # `show clock` output with no four-digit year (odd platform format, or a
  # transport hiccup on just this probe) must leave clock_year empty and skip
  # the warning — under `set -euo pipefail` a bare failing grep here used to
  # kill the whole installer at a check that is documented as optional.
  setup_stage_local
  unset HOST_USER HOST_PASS

  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" FAKE_IP_ROUTING=yes \
    FAKE_CLOCK_LINE="% Clock is not set" \
    bash "$STUBDIR/device/device-install.sh"

  [[ "$output" != *"PREREQ WARNING"* ]]
  [ "$(find "$ARTDIR/staging" -name 'iris-agent-100.92.9.3-*.conf' | wc -l)" -eq 1 ]
}

@test "dry-run and real run use the same capability-bearing staged filenames" {
  setup_stage_local
  cap=0123456789abcdef0123456789abcdef
  mkdir -p "$STUBDIR/bin"
  cat > "$STUBDIR/bin/od" <<EOF
#!/usr/bin/env bash
printf ' %s\n' '$cap'
EOF
  cat > "$STUBDIR/bin/curl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$STUBDIR/bin/od" "$STUBDIR/bin/curl"
  cat > "$STUBDIR/lab/device-run.sh" <<EOF
#!/usr/bin/env bash
cmds="\$(cat)"
printf '%s\n' "\$cmds" >> '$BATS_TEST_TMPDIR/device-commands'
case "\$cmds" in
  *'__IRIS_PRECHECK_'*)
    # [1/7]+[pre] ride ONE combined session now (marker __IRIS_PRECHECK_) --
    # answer all three sections so the real run sails past the PREREQ gate.
    echo '__IRIS_PRECHECK_FLASH__'
    echo 'bytes free stub'
    echo '__IRIS_PRECHECK_ROUTING__'
    echo 'show running-config | include no ip routing'
    echo 'Gateway of last resort is 100.90.168.1 to network 0.0.0.0'
    echo '__IRIS_PRECHECK_CLOCK__'
    echo '14:23:07.512 UTC Thu Aug 20 2026' ;;
  *'show running-config | include ^ip routing'*) echo 'ip routing' ;;
  *'show clock'*) echo '14:23:07.512 UTC Thu Aug 20 2026' ;;
  *'show app-hosting list'*) echo 'guestshell RUNNING' ;;
  *'copy https://'*) echo '123 bytes copied' ;;
  *'copy running-config startup-config'*) echo '[OK]' ;;
  *'show running-config'*)
    echo 'show running-config | include no ip routing'
    echo 'Gateway of last resort is 100.90.168.1 to network 0.0.0.0' ;;
  *) echo 'bytes free stub' ;;
esac
EOF
  chmod +x "$STUBDIR/lab/device-run.sh"

  run env PATH="$STUBDIR/bin:$PATH" bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"staging/iris-agent-100.92.9.3-$cap.conf"* ]]
  [[ "$output" == *"staging/rpc-secret-$cap"* ]]

  run env PATH="$STUBDIR/bin:$PATH" IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    IRIS_CRT_FILE="$CRTFILE" bash "$STUBDIR/device/device-install.sh"
  [ "$status" -eq 0 ]
  [ -f "$ARTDIR/staging/iris-agent-100.92.9.3-$cap.conf" ]
  [ -f "$ARTDIR/staging/rpc-secret-$cap" ]
  grep -qF "staging/iris-agent-100.92.9.3-$cap.conf" "$BATS_TEST_TMPDIR/device-commands"
  grep -qF "staging/rpc-secret-$cap" "$BATS_TEST_TMPDIR/device-commands"
}

# --- SSH session consolidation ([1/7] flash pre-check + [pre] ip routing +
# [pre] device clock, formerly up to three separate lab/device-run.sh logins,
# now one combined session keyed by the __IRIS_PRECHECK_ marker -- same
# pattern as _default_router_preflight in server/gui_onboard.py). ---

@test "[1/7]+[pre] pre-checks issue exactly ONE device-run.sh session, not up to three" {
  setup_stage_local
  unset HOST_USER HOST_PASS
  CALLLOG="$BATS_TEST_TMPDIR/precheck-calls"
  : > "$CALLLOG"
  cat > "$STUBDIR/lab/device-run.sh" <<STUB
#!/usr/bin/env bash
cmds="\$(cat)"
case "\$cmds" in
  *"__IRIS_PRECHECK_"*) printf 'PRECHECK\n' >> '$CALLLOG' ;;
esac
case "\$cmds" in
  *"__IRIS_PRECHECK_"*)
    echo "__IRIS_PRECHECK_FLASH__"
    echo "bytes free stub"
    echo "__IRIS_PRECHECK_ROUTING__"
    echo "show running-config | include no ip routing"
    echo "Gateway of last resort is 100.90.168.1 to network 0.0.0.0"
    echo "__IRIS_PRECHECK_CLOCK__"
    echo "14:23:07.512 UTC Thu Aug 20 2026"
    ;;
  *"show app-hosting list"*) echo "guestshell RUNNING" ;;
  *) echo "bytes free stub" ;;
esac
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"

  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" \
    bash "$STUBDIR/device/device-install.sh"

  # got past [2/7] (staging succeeded), i.e. past the whole pre-check block
  [ "$(find "$ARTDIR/staging" -name 'iris-agent-100.92.9.3-*.conf' | wc -l)" -eq 1 ]
  # exactly one device-run.sh invocation carried the precheck marker -- were
  # this the old code, flash/routing/clock would show up as THREE
  [ "$(wc -l < "$CALLLOG" | tr -d ' ')" -eq 1 ]
}

@test "PRECHECK: a response missing the ROUTING marker section fails closed, not silently as empty/safe" {
  setup_stage_local
  unset HOST_USER HOST_PASS
  # Simulate a device that echoes FLASH and CLOCK back but, for whatever
  # reason (a truncated/garbled session), never echoes the ROUTING marker at
  # all. A correct fail-closed parser must treat that as "could not verify",
  # never as "no routing problem found" -- an empty ROUTING section would be
  # the wrong, unsafe reading (it could just as easily mean routing IS
  # disabled and the disabled-detecting lines were dropped in transit).
  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
case "$cmds" in
  *"__IRIS_PRECHECK_"*)
    echo "__IRIS_PRECHECK_FLASH__"
    echo "bytes free stub"
    echo "__IRIS_PRECHECK_CLOCK__"
    echo "14:23:07.512 UTC Thu Aug 20 2026"
    ;;
  *) echo "bytes free stub" ;;
esac
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"

  run_with_timeout 5 env IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 \
    CATALOG_TOKEN=deadbeef DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 \
    IRIS_CRT_FILE="$CRTFILE" \
    bash "$STUBDIR/device/device-install.sh"

  [ "$status" -ne 0 ]
  [[ "$output" == *"PREREQ: could not verify ip routing"* ]]
  [[ "$output" != *"PREREQ: ip routing is disabled"* ]]
  # must fail BEFORE staging -- [pre] sits ahead of [2/7]
  [ "$(find "$ARTDIR" -name 'iris-agent-100.92.9.3-*.conf' | wc -l)" -eq 0 ]
}

# --- artifact preflight: retry, and say WHICH fault it was ------------------
# One 5s attempt with no retry was the most fragile step in a fleet onboard --
# the artifact server's latency degrades under concurrent load, and this check
# runs at exactly that moment. A transient miss strands the device
# half-installed, because the trustpoint is pushed just before it.
#
# These drive the FUNCTION rather than the whole installer: the behaviour under
# test is entirely inside artifact_preflight, and running 700 lines of installer
# to reach it makes the test slow and couples it to every unrelated step.

_load_preflight() {   # $1 = curl exit script; extracts the function under test
  PFDIR="$BATS_TEST_TMPDIR/pf"; mkdir -p "$PFDIR/bin"
  sed -n '/^artifact_preflight()/,/^}/p' "$BATS_TEST_DIRNAME/../device-install.sh" \
    > "$PFDIR/fn.sh"
  [ -s "$PFDIR/fn.sh" ]          # the function must still exist to extract
  printf '%s\n' '#!/usr/bin/env bash' "$1" > "$PFDIR/bin/curl"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$PFDIR/bin/sleep"   # no real backoff
  chmod +x "$PFDIR/bin/curl" "$PFDIR/bin/sleep"
  cat > "$PFDIR/run.sh" <<'RUN'
set -uo pipefail
STAGE_HOST=stage.example; IRIS_CRT_FILE=/dev/null
. "$PFDIR/fn.sh"
artifact_preflight
RUN
}

@test "artifact preflight retries a transient failure instead of giving up at once" {
  _load_preflight 'n="$PFDIR/calls"; c=$(( $(cat "$n" 2>/dev/null || echo 0) + 1 )); echo "$c" > "$n"
[ "$c" -lt 3 ] && exit 28
exit 0'
  PFDIR="$PFDIR" PATH="$PFDIR/bin:$PATH" run bash "$PFDIR/run.sh"
  [ "$status" -eq 0 ]                          # third attempt succeeds
  [ "$(cat "$PFDIR/calls")" -eq 3 ]            # and it really did retry
  [[ "$output" == *"attempt 1 failed (curl rc=28)"* ]]
  [[ "$output" != *"ERROR: artifact preflight failed"* ]]
}

@test "artifact preflight names a TLS failure as TLS, not as unreachable" {
  _load_preflight 'exit 60'
  PFDIR="$PFDIR" PATH="$PFDIR/bin:$PATH" run bash "$PFDIR/run.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"TLS verification failed"* ]]
  # the old message blamed reachability AND trust for every fault, which sent a
  # real investigation chasing certificate drift while the certs were identical
  [[ "$output" != *"is not reachable / not trusted"* ]]
}

@test "artifact preflight names a connect failure as connect" {
  _load_preflight 'exit 7'
  PFDIR="$PFDIR" PATH="$PFDIR/bin:$PATH" run bash "$PFDIR/run.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"cannot connect"* ]]
}

@test "artifact preflight names a timeout as a timeout and points at fleet load" {
  _load_preflight 'exit 28'
  PFDIR="$PFDIR" PATH="$PFDIR/bin:$PATH" run bash "$PFDIR/run.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"timed out"* ]]
  [[ "$output" == *"fleet onboard"* ]]
}
