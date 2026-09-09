#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  INSTALL="$BATS_TEST_DIRNAME/../router-install.sh"
  export MODEL=C8000V DEVICE_IP=192.0.2.10 DEVICE_ID=router-1 \
    CATALOG_URL=https://192.0.2.20:8443 CATALOG_TOKEN=deadbeef \
    STAGE_HOST=192.0.2.20 MANAGEMENT_TYPE=router-routed VPG_NUMBER=10 \
    APP_IP=10.8.0.2 APP_MASK=255.255.255.252 APP_GATEWAY=10.8.0.1
}

@test "stale NETWORK_ATTACHMENT without MANAGEMENT_TYPE aborts; a normal env is unaffected" {
  run env -u MANAGEMENT_TYPE NETWORK_ATTACHMENT=router-routed bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE"* ]] || return 1
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "router-routed renders a VPG Guest Shell interface" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"interface VirtualPortGroup10"* ]]
  [[ "$output" == *"ip address 10.8.0.1 255.255.255.252"* ]]
  [[ "$output" == *"app-vnic gateway0 virtualportgroup 10 guest-interface 0"* ]]
  [[ "$output" == *"guest-ipaddress 10.8.0.2 netmask 255.255.255.252"* ]]
}

@test "router-routed emits no NAT configuration" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"ip nat inside"* ]]
  [[ "$output" != *"IRIS-NAT-"* ]]
}

@test "router-nat renders overload and deterministic inbound swarm PAT" {
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"interface GigabitEthernet1"* ]]
  [[ "$output" == *"ip nat outside"* ]]
  [[ "$output" == *"ip access-list standard IRIS-NAT-10"* ]]
  [[ "$output" == *"permit 10.8.0.0 0.0.0.3"* ]]
  [[ "$output" == *"ip nat inside source list IRIS-NAT-10 interface GigabitEthernet1 overload"* ]]
  [[ "$output" == *"ip nat inside source static tcp 10.8.0.2 6881 interface GigabitEthernet1 6881"* ]]
  [[ "$output" == *"BT_LISTEN_PORT=6881"* ]]
}

@test "router renderer never emits switch network primitives" {
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  ! grep -Eq '(^|[[:space:]])vlan [0-9]|interface Vlan|switchport|ip router isis|vrf definition|AppGigabitEthernet' <<<"$output"
}

@test "router config and copies use bootflash explicitly" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"stage_dir = /bootflash/guest-share/iris"* ]]
  [[ "$output" == *"target_fs = bootflash:"* ]]
  [[ "$output" == *"catalog_ca = /bootflash/guest-share/iris/iris-catalog.pem"* ]]
  [[ "$output" == *"bootflash:guest-share/bootstrap.sh"* ]]
  [[ "$output" != *"target_fs = flash:"* ]]
}

@test "router dry-run uses one capability for both credential filenames" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  conf_cap="$(printf '%s\n' "$output" | sed -nE 's#.*staging/iris-agent-router-1-([0-9a-f]{32})\.conf.*#\1#p' | head -1)"
  rpc_cap="$(printf '%s\n' "$output" | sed -nE 's#.*staging/rpc-secret-([0-9a-f]{32}).*#\1#p' | head -1)"
  [ -n "$conf_cap" ]
  [ "$conf_cap" = "$rpc_cap" ]
}

@test "a supplied router capability binds the exact fail-closed copy order" {
  cap=0123456789abcdef0123456789abcdef
  run env IRIS_STAGING_CAPABILITY="$cap" bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ] || return 1
  mapfile -t copies < <(printf '%s\n' "$output" | grep '^copy https://')
  [ "${#copies[@]}" -eq 8 ] || return 1
  [[ "${copies[0]}" == *"/bootstrap.sh bootflash:guest-share/bootstrap.sh" ]] || return 1
  [[ "${copies[1]}" == *"/staging/iris-agent-router-1-$cap.conf bootflash:guest-share/iris-agent.conf" ]] || return 1
  [[ "${copies[2]}" == *"/staging/rpc-secret-$cap bootflash:guest-share/rpc-secret" ]] || return 1
  [[ "${copies[3]}" == *"/iris-catalog.pem bootflash:guest-share/iris-catalog.pem" ]] || return 1
  [[ "${copies[4]}" == *"/iris-signers.pem bootflash:guest-share/iris-signers.allowed_signers" ]] || return 1
  [[ "${copies[5]}" == *"/staging/iris-instructions-router-1-$cap.envelope bootflash:guest-share/iris-instructions.bootstrap" ]] || return 1
  [[ "${copies[6]}" == *"/staging/bundle-sha256-$cap bootflash:guest-share/bundle.tgz.sha256" ]] || return 1
  [[ "${copies[7]}" == *"/iris-agent.tgz bootflash:guest-share/bundle.tgz" ]]
}

@test "router rejects an invalid supplied staging capability before rendering credentials" {
  run env IRIS_STAGING_CAPABILITY=0123456789abcdef0123456789abcdeG \
    bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"ERROR: IRIS_STAGING_CAPABILITY must be 32 lowercase hexadecimal characters"* ]] || return 1
  [[ "$output" != *"catalog_token = deadbeef"* ]]
}

@test "router installer never recursively removes the live Guest Shell stage" {
  ! grep -Eq 'delete /force /recursive .*IOS_STAGE|rm -rf .*STAGE' "$INSTALL"
}

@test "router installer refuses a non-Catalyst-8000 model" {
  MODEL=ISR4451 run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"Catalyst 8000-family models only"* ]]
}

@test "router installer rejects a non-contiguous mask" {
  APP_MASK=255.0.255.0 run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid APP_IP, APP_MASK, or APP_GATEWAY"* ]]
}

@test "router installer rejects a gateway outside the app subnet" {
  APP_GATEWAY=10.9.0.1 run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"must differ and share a subnet"* ]]
}

@test "real router install structurally live-checks model and processor-board identity" {
  grep -qF 'EXPECTED_DEVICE_IDENTITY' "$INSTALL"
  grep -qF 'rocessor board ID' "$INSTALL"
  grep -qF 'device identity mismatch' "$INSTALL"
}

@test "real router install has a post-apply readback gate before persistence" {
  grep -qF 'verify configuration and save startup-config' "$INSTALL"
  grep -qF 'show running-config' "$INSTALL"
  grep -qF 'config_block "VirtualPortGroup$VPG_NUMBER"' "$INSTALL"
  grep -qF 'router configuration is incomplete' "$INSTALL"
}

@test "re-onboard destroys a pre-existing guestshell before applying config" {
  # 2026-08-20 incident (iris8kv-1/-2): a re-onboard over a guestshell that was
  # already RUNNING left it on its OLD networking — step [4/6] saw RUNNING and
  # never re-enabled, so the freshly applied app-hosting gateway never reached
  # the guest and the agent had no egress. The installer must destroy any
  # pre-existing guestshell BEFORE applying config so enable always builds the
  # guest from the current networking.
  run grep -n 'guestshell destroy' "$INSTALL"
  [ "$status" -eq 0 ]
  destroy_line="$(grep -n 'guestshell destroy' "$INSTALL" | head -1 | cut -d: -f1)"
  config_line="$(grep -n '^echo "\[3/6\] configure IRIS' "$INSTALL" | head -1 | cut -d: -f1)"
  enable_line="$(grep -n '^echo "\[4/6\] start Guest Shell' "$INSTALL" | head -1 | cut -d: -f1)"
  [ -n "$destroy_line" ] && [ -n "$config_line" ] && [ -n "$enable_line" ]
  [ "$destroy_line" -lt "$config_line" ]
  [ "$config_line" -lt "$enable_line" ]
  # the destroy must wait for the guest to actually be gone, not fire-and-forget
  run grep -A8 'guestshell destroy' "$INSTALL"
  [[ "$output" == *"DESTROYED"* || "$output" == *"still present"* ]]
}

@test "guestshell destroy answers the confirmation prompt (cross-version)" {
  # Some IOS-XE versions prompt "Undeploy Guest Shell? [y/n]"; without the y
  # the destroy never runs, the poll loop burns its full two minutes, and the
  # install fails with the stale guest intact. Both uninstallers already send
  # the answer for exactly this reason — the installer's destroy must match.
  run grep -F "printf 'guestshell destroy\ny\n'" "$INSTALL"
  [ "$status" -eq 0 ]
}

# --- SSH session consolidation: step [6/6]'s three read-only verify checks
# (show running-config, show app-hosting list, dir bootflash:guest-share[/iris])
# now ride one lab/device-run.sh login using the same __IRIS_PREFLIGHT_-style
# markers as _default_router_preflight in server/gui_onboard.py, instead of
# paying a fresh SSH connection setup per check. FAKE_COMMAND_LOG records one
# "=== CALL START ===".."=== CALL END ===" block per device-run.sh invocation
# so tests can inspect exactly which commands landed in the same login.

_router_install_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device" "$STUBDIR/bin"
  FAKE_STATE_DIR="$BATS_TEST_TMPDIR/state"
  mkdir -p "$FAKE_STATE_DIR"
  FAKE_COMMAND_LOG="$BATS_TEST_TMPDIR/device-commands.log"
  : > "$FAKE_COMMAND_LOG"
  export FAKE_STATE_DIR FAKE_COMMAND_LOG

  cat > "$STUBDIR/lab/device-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
if [ -n "${FAKE_COMMAND_LOG:-}" ]; then
  {
    echo "=== CALL START ==="
    printf '%s\n' "$cmds"
    echo "=== CALL END ==="
  } >> "$FAKE_COMMAND_LOG"
fi

# Every "show app-hosting list" call (pre-existing-guestshell check, the
# destroy-wait poll, and the enable-wait poll) sends identical stdin, so a
# call counter is what lets this stub give each phase a different answer:
# call 1 is always the pre-existing check; with FAKE_EXISTING_GUESTSHELL=yes,
# the next FAKE_DESTROY_POLLS-1 calls stay present, the one after that clears,
# and everything after is the enable-wait poll (answered RUNNING at once).
apphost_reply() {
  local n
  n=$(( $(cat "$FAKE_STATE_DIR/apphost_n" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$FAKE_STATE_DIR/apphost_n"
  if [ "${FAKE_EXISTING_GUESTSHELL:-no}" = "yes" ]; then
    local polls="${FAKE_DESTROY_POLLS:-2}"
    if [ "$n" -eq 1 ]; then
      echo "guestshell RUNNING"
    elif [ "$n" -lt "$((1 + polls))" ]; then
      echo "guestshell UNDEPLOYING"
    elif [ "$n" -eq "$((1 + polls))" ]; then
      echo ""
    else
      echo "guestshell RUNNING"
    fi
  else
    if [ "$n" -eq 1 ]; then
      echo ""
    else
      echo "guestshell RUNNING"
    fi
  fi
}

case "$cmds" in
  *"__IRIS_VERIFY_RUNNING__"*)
    echo "terminal width 512"
    if [ "${FAKE_VERIFY_OMIT_RUNNING:-no}" != "yes" ]; then
      echo "__IRIS_VERIFY_RUNNING__"
      echo "interface VirtualPortGroup${VPG_NUMBER}"
      echo " ip address ${APP_GATEWAY} ${APP_MASK}"
      echo " no shutdown"
      echo "app-hosting appid guestshell"
      echo " app-vnic gateway0 virtualportgroup ${VPG_NUMBER} guest-interface 0"
      echo "  guest-ipaddress ${APP_IP} netmask ${APP_MASK}"
      echo "event manager applet IRIS-AGENT authorization bypass"
      echo "logging discriminator IRISQ mnemonics drops IOX_INST_WARN"
      echo "crypto pki trustpoint IRIS"
      echo "ip http client secure-trustpoint IRIS"
      echo "file prompt quiet"
    fi
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      echo "__IRIS_VERIFY_APPS__"
      echo "guestshell RUNNING"
    fi
    if [ "${FAKE_VERIFY_OMIT_FILES:-no}" != "yes" ]; then
      echo "__IRIS_VERIFY_FILES__"
      echo "bootstrap.sh"
      echo "iris-agent.conf"
    fi
    ;;
  *"show version"*)
    echo "cisco ${FAKE_MODEL:-C8000V} (x86) processor"
    echo "Processor board ID ${FAKE_DEVICE_IDENTITY:-FOC1234TEST}"
    ;;
  *"more "*"guest-share/iris/iris-agent.conf"*)
    [ -n "${FAKE_LKG_KEY:-}" ] && echo "lkg_key = $FAKE_LKG_KEY"
    ;;
  *"show app-hosting list"*)
    apphost_reply
    ;;
  *"copy https://"*)
    echo "123 bytes copied"
    ;;
  *"copy running-config startup-config"*)
    echo "[OK]"
    ;;
  *)
    echo "bytes free stub"
    ;;
esac
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"

  cat > "$STUBDIR/bin/curl" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  chmod +x "$STUBDIR/bin/curl"

  ln -sf "$INSTALL" "$STUBDIR/device/router-install.sh"
  cp "$BATS_TEST_DIRNAME/../bootstrap.sh" "$STUBDIR/device/bootstrap.sh"

  ARTDIR="$BATS_TEST_TMPDIR/artifacts"
  mkdir -p "$ARTDIR/staging"
  CRTFILE="$BATS_TEST_TMPDIR/crt.pem"
  echo "-----BEGIN CERTIFICATE-----fake-----END CERTIFICATE-----" > "$CRTFILE"
  TEST_CAP=0123456789abcdef0123456789abcdef
  export IRIS_STAGING_CAPABILITY="$TEST_CAP"
  printf 'bundle fixture\n' > "$ARTDIR/iris-agent.tgz"
  sha256sum "$ARTDIR/iris-agent.tgz" | awk '{print $1}' \
    > "$ARTDIR/iris-agent.tgz.sha256"
  printf 'iris-server cert-authority ssh-ed25519 fixture\n' \
    > "$ARTDIR/iris-signers.pem"
  printf 'sealed instruction fixture\n' \
    > "$ARTDIR/staging/iris-instructions-router-1-$TEST_CAP.envelope"
}

_router_install_run_live() {
  env PATH="$STUBDIR/bin:$PATH" IRIS_STAGE_LOCAL=1 IRIS_ARTIFACTS_DIR="$ARTDIR" \
    IRIS_CRT_FILE="$CRTFILE" EXPECTED_DEVICE_IDENTITY=FOC1234TEST \
    bash "$STUBDIR/device/router-install.sh"
}

@test "router local staging refuses a missing bundle sidecar before device mutation" {
  _router_install_stub_setup
  rm -f "$ARTDIR/iris-agent.tgz.sha256"
  run _router_install_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"ERROR: bundle digest evidence is missing or invalid"* ]] || return 1
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" 'configure terminal')" -eq 0 ]
}

@test "router re-onboarding preserves a valid device lkg_key" {
  _router_install_stub_setup
  key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  FAKE_LKG_KEY="$key" run _router_install_run_live
  [ "$status" -eq 0 ] || return 1
  grep -qx "lkg_key = $key" \
    "$ARTDIR/staging/iris-agent-router-1-$TEST_CAP.conf"
}

# Counts call blocks in a FAKE_COMMAND_LOG whose body contains every given
# substring -- used to prove commands landed in the SAME device-run.sh
# invocation (one login) rather than separate ones.
_calls_containing() {
  local log="$1"; shift
  python3 - "$log" "$@" <<'PY'
import sys
text = open(sys.argv[1]).read()
needles = sys.argv[2:]
blocks = text.split("=== CALL START ===\n")[1:]
count = sum(1 for b in blocks
            if all(n in b.split("=== CALL END ===\n")[0] for n in needles))
print(count)
PY
}

# Counts call blocks containing TARGET, restricted to blocks strictly after
# the first block containing START and strictly before the next block after
# that containing END -- lets a test isolate one phase's call count (e.g.
# the destroy-wait poll) from an unrelated later phase (e.g. the
# enable-wait poll) that also happens to send the same command text.
_calls_between_containing() {
  local log="$1" start="$2" end="$3" target="$4"
  python3 - "$log" "$start" "$end" "$target" <<'PY2'
import sys
log, start, end, target = sys.argv[1:5]
text = open(log).read()
blocks = [b.split("=== CALL END ===\n")[0]
          for b in text.split("=== CALL START ===\n")[1:]]
start_i = next((i for i, b in enumerate(blocks) if start in b), None)
if start_i is None:
    print(0); sys.exit()
end_i = next((i for i in range(start_i + 1, len(blocks)) if end in blocks[i]),
             len(blocks))
print(sum(1 for b in blocks[start_i + 1:end_i] if target in b))
PY2
}

@test "step [6/6] verify merges running-config, app-hosting state, and file listing into ONE call" {
  _router_install_stub_setup
  run _router_install_run_live
  [ "$status" -eq 0 ]
  merged="$(_calls_containing "$FAKE_COMMAND_LOG" '__IRIS_VERIFY_RUNNING__' \
    'show running-config' 'show app-hosting list' 'dir bootflash:guest-share')"
  [ "$merged" -eq 1 ]
  # and it must be the ONLY place "show running-config" is sent -- proving
  # the old separate call for it is gone, not just duplicated alongside a
  # new merged one.
  total_running="$(_calls_containing "$FAKE_COMMAND_LOG" 'show running-config')"
  [ "$total_running" -eq 1 ]
}

@test "step [6/6] verify fails closed when the RUNNING marker is missing from the response" {
  _router_install_stub_setup
  FAKE_VERIFY_OMIT_RUNNING=yes run _router_install_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"ERROR: router verify did not return running-config"* ]]
}

@test "step [6/6] verify fails closed when the FILES marker is missing from the response" {
  # A dropped/truncated section must never be read as "empty output" -- an
  # empty FILES section would otherwise sail through the require_text checks
  # incorrectly (an install that never actually verified the copied files).
  _router_install_stub_setup
  FAKE_VERIFY_OMIT_FILES=yes run _router_install_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"ERROR: router verify did not return guest-share file listing"* ]]
}

@test "pre-existing guestshell destroy-wait poll still issues separate calls, not merged" {
  # Deliberately isolated to the window between the destroy mutation and the
  # config-apply step -- counting "show app-hosting list" calls over the
  # WHOLE run would also pick up the (correctly separate) enable-wait poll
  # later on and mask a flattened destroy-wait loop.
  _router_install_stub_setup
  FAKE_EXISTING_GUESTSHELL=yes FAKE_DESTROY_POLLS=2 run _router_install_run_live
  [[ "$output" == *"guestshell DESTROYED"* ]]
  # destroy-wait poll: FAKE_DESTROY_POLLS=2 means "still there" once, then
  # "gone" -- 2 separate polls before config-apply starts.
  between="$(_calls_between_containing "$FAKE_COMMAND_LOG" \
    'guestshell destroy' 'configure terminal' 'show app-hosting list')"
  [ "$between" -ge 2 ]
}

@test "guestshell enable-wait poll is a loop of separate calls, not one call in source" {
  # Runtime-proving this without real 15s sleeps is impractically slow;
  # structurally confirm the poll call still lives inside the step [4/6] for
  # loop and was not folded into verify_request()/the step [6/6] merge.
  step4_line="$(grep -n '^echo "\[4/6\] start Guest Shell' "$INSTALL" | head -1 | cut -d: -f1)"
  step5_line="$(grep -n '^echo "\[5/6\] copy certificate' "$INSTALL" | head -1 | cut -d: -f1)"
  # The iteration count is a tunable (it moved when the flat 15s wait became a
  # ramp), so match the loop, not the number -- and search inside the step
  # [4/6] window so the earlier destroy-wait loop cannot be picked up instead.
  for_rel="$(sed -n "${step4_line},${step5_line}p" "$INSTALL" \
    | grep -n 'for i in \$(seq 1 [0-9][0-9]*); do' | head -1 | cut -d: -f1)"
  for_line=""
  [ -n "$for_rel" ] && for_line=$((step4_line + for_rel - 1))
  poll_call_line="$(sed -n "${step4_line},${step5_line}p" "$INSTALL" \
    | grep -n 'show app-hosting list' | head -1 | cut -d: -f1)"
  [ -n "$step4_line" ] && [ -n "$for_line" ] && [ -n "$poll_call_line" ]
  [ "$for_line" -gt "$step4_line" ]
  # the poll call's absolute line number must fall inside [step4_line, step5_line)
  poll_abs=$((step4_line + poll_call_line - 1))
  [ "$poll_abs" -gt "$for_line" ]
  [ "$poll_abs" -lt "$step5_line" ]
}
