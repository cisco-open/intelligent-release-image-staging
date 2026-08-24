#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  UNINSTALL="$BATS_TEST_DIRNAME/../router-uninstall.sh"
  export MODEL=C8000V NETWORK_ATTACHMENT=router-routed VPG_NUMBER=10 \
    APP_IP=10.8.0.2
}

@test "router-routed teardown removes only the VPG app footprint" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no interface VirtualPortGroup10"* ]]
  [[ "$output" == *"no app-hosting appid guestshell"* ]]
  [[ "$output" == *"delete /force /recursive bootflash:guest-share/iris"* ]]
  [[ "$output" == *"delete /force bootflash:guest-share/bootstrap.sh"* ]]
  [[ "$output" != *"delete /force /recursive bootflash:guest-share"$'\n'* ]]
  [[ "$output" != *"IRIS-NAT-"* ]]
}

@test "router NAT teardown removes receipt-owned NAT rules" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no ip nat inside source static tcp 10.8.0.2 6881 interface GigabitEthernet1 6881"* ]]
  [[ "$output" == *"no ip nat inside source list IRIS-NAT-10 interface GigabitEthernet1 overload"* ]]
  [[ "$output" == *"no ip access-list standard IRIS-NAT-10"* ]]
}

@test "NAT teardown clears only receipt-owned translations before the mapping" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"clear ip nat translation inside <IRIS-inside-global> 10.8.0.2 forced"* ]]
  [[ "$output" != *"clear ip nat translation *"* ]]
  # IOS refuses the overload no-form while translations reference the mapping;
  # targeted clearing must happen before the rule and its ACL are removed.
  clear_at="${output%%clear ip nat translation inside*}"
  rule_at="${output%%no ip nat inside source list*}"
  [ "${#clear_at}" -lt "${#rule_at}" ]
}

@test "router teardown never contains a device-wide NAT clear" {
  ! grep -qF 'clear ip nat translation *' "$UNINSTALL"
}

@test "routed teardown does not flush NAT translations" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"clear ip nat translation"* ]]
}

@test "pre-existing outside marking is preserved" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 NAT_OUTSIDE_OWNED=0 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"no ip nat outside"* ]]
}

@test "IRIS-created outside marking is removed" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 NAT_OUTSIDE_OWNED=1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"interface GigabitEthernet1"* ]]
  [[ "$output" == *"no ip nat outside"* ]]
}

@test "router teardown never emits switch network primitives" {
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 NAT_OUTSIDE_OWNED=1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  ! grep -Eq '(^|[[:space:]])vlan [0-9]|interface Vlan|switchport|ip router isis|vrf definition|AppGigabitEthernet' <<<"$output"
}

@test "router uninstaller refuses a non-Catalyst-8000 model" {
  MODEL=ISR4451 run bash "$UNINSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"Catalyst 8000-family models only"* ]]
}

@test "real router undeploy without credentials fails through the friendly guard" {
  # A real run must hit the DEVICE_IP guard before anything dereferences it,
  # so the operator sees the guard message rather than a raw set -u abort.
  run env -u DEVICE_IP -u DEVICE_USER -u DEVICE_PASS bash "$UNINSTALL"
  [ "$status" -ne 0 ]
  [[ "$output" == *"set DEVICE_IP"* ]]
  [[ "$output" != *"unbound variable"* ]]
}

@test "real router undeploy requires receipt ownership and processor-board identity" {
  grep -qF 'ROUTER_RESOURCES_OWNED' "$UNINSTALL"
  grep -qF 'EXPECTED_DEVICE_IDENTITY' "$UNINSTALL"
  grep -qF 'rocessor board ID' "$UNINSTALL"
  grep -qF 'device identity mismatch' "$UNINSTALL"
}

@test "real router undeploy verifies every removable resource before success" {
  grep -qF 'show running-config' "$UNINSTALL"
  grep -qF 'ip nat inside source static tcp' "$UNINSTALL"
  grep -qF 'logging discriminator IRISQ' "$UNINSTALL"
  grep -qF 'crypto pki trustpoint IRIS' "$UNINSTALL"
  grep -qF 'artifacts still present after undeploy' "$UNINSTALL"
}

# --- NAT overload teardown: settle + retry before declaring residue --------
# IOS refuses `no ip nat inside source list ... overload` while translations
# still reference the mapping. Clearing them is not instantaneous, so a single
# immediate re-check raced and reported residue on a router that was actually
# fine seconds later (observed on iris8kv-4: rule left configured, 0
# translations). Retry with a settle before failing, and make the failure text
# name the residue and the remedy instead of reading like a status note.

@test "NAT removal is retried with a settle rather than checked once" {
  run grep -cE "NAT_REMOVE_(ATTEMPTS|SETTLE)" "$UNINSTALL"
  [ "$output" -ge 2 ]
}

@test "the residue failure names the leftover rule and the remedy" {
  run grep -A12 "could not remove the IRIS NAT overload mapping" "$UNINSTALL"
  [[ "$output" == *"LEFT ON THE DEVICE"* ]] && \
  [[ "$output" == *"NAT_RULE"* ]] && \
  [[ "$output" == *"access-list standard IRIS-NAT"* ]] && \
  [[ "$output" == *"re-run this undeploy"* ]]
}

@test "force teardown removes the agent footprint but never the VPG or NAT" {
  # A router whose onboard died after enabling Guest Shell but before its
  # receipt was written cannot be undeployed (no receipt), cannot be adopted
  # (routers never can) and cannot be re-onboarded (preflight refuses an
  # existing Guest Shell). Force mode is the only way out -- and because no
  # receipt proves IRIS created the VPG/NAT, it must not touch them.
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  # agent footprint IS removed
  [[ "$output" == *"no event manager applet IRIS-AGENT"* ]]
  [[ "$output" == *"guestshell destroy"* ]] || [[ "$output" == *"guestshell disable"* ]]
  [[ "$output" == *"delete /force /recursive bootflash:guest-share/iris"* ]]
  # operator network is NOT touched
  [[ "$output" != *"no interface VirtualPortGroup"* ]]
  [[ "$output" != *"IRIS-NAT-"* ]]
  [[ "$output" != *"ip nat inside source"* ]]
  [[ "$output" == *"SKIPPED"* ]]
}

@test "force teardown does not require a receipt VPG number" {
  # Without a receipt there is no VPG number to validate; requiring one would
  # re-strand the device this mode exists to rescue.
  unset VPG_NUMBER
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"missing a valid VPG_NUMBER"* ]]
}

@test "non-force teardown still refuses without a valid VPG number" {
  unset VPG_NUMBER
  run bash "$UNINSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing a valid VPG_NUMBER"* ]]
}

# --- SSH session consolidation: the trailing verify block (show
# running-config, show app-hosting list, dir bootflash:guest-share[/iris])
# now rides one lab/device-run.sh login using the same __IRIS_PREFLIGHT_-style
# markers as _default_router_preflight in server/gui_onboard.py, instead of
# a fresh SSH connection per check. FAKE_COMMAND_LOG records one
# "=== CALL START ===".."=== CALL END ===" block per device-run.sh
# invocation so tests can inspect exactly which commands landed together.

_router_uninstall_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device"
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

# "show app-hosting list" is sent by both the disable-wait poll and the
# destroy-wait poll. A shared counter partitioned into two fixed windows
# (FAKE_DISABLE_POLLS calls, then FAKE_DESTROY_POLLS calls) lets the stub
# answer each phase distinctly without the phases bleeding into each other.
apphost_reply() {
  local n disable_polls destroy_polls k
  n=$(( $(cat "$FAKE_STATE_DIR/apphost_n" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$FAKE_STATE_DIR/apphost_n"
  disable_polls="${FAKE_DISABLE_POLLS:-1}"
  destroy_polls="${FAKE_DESTROY_POLLS:-1}"
  if [ "$n" -le "$disable_polls" ]; then
    [ "$n" -lt "$disable_polls" ] && echo "guestshell RUNNING" || echo ""
  elif [ "$n" -le "$((disable_polls + destroy_polls))" ]; then
    k=$((n - disable_polls))
    [ "$k" -lt "$destroy_polls" ] && echo "guestshell RUNNING" || echo ""
  else
    echo ""
  fi
}

# The NAT overload retry loop mutates ("no $NAT_RULE") then re-observes
# (plain "show running-config", no verify markers) before deciding whether
# to retry. FAKE_NAT_DRAIN_ROUNDS controls how many observes still show the
# rule present before it reports clean.
natcheck_reply() {
  local n rounds
  n=$(( $(cat "$FAKE_STATE_DIR/natcheck_n" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$FAKE_STATE_DIR/natcheck_n"
  rounds="${FAKE_NAT_DRAIN_ROUNDS:-1}"
  if [ "$n" -lt "$rounds" ]; then
    echo "ip nat inside source list IRIS-NAT-${VPG_NUMBER} interface ${NAT_INTERFACE} overload"
  else
    echo "! clean, no residue"
  fi
}

case "$cmds" in
  *"__IRIS_VERIFY_RUNNING__"*)
    echo "terminal width 512"
    if [ "${FAKE_VERIFY_OMIT_RUNNING:-no}" != "yes" ]; then
      echo "__IRIS_VERIFY_RUNNING__"
      if [ "${FAKE_UNINSTALL_LEAVE_RESIDUE:-no}" = "yes" ]; then
        echo "interface VirtualPortGroup${VPG_NUMBER}"
        echo "app-hosting appid guestshell"
      else
        echo "hostname iris8kv-1"
        echo "!"
        echo "end"
      fi
    fi
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      echo "__IRIS_VERIFY_APPS__"
      echo "No App found"
    fi
    if [ "${FAKE_VERIFY_OMIT_FILES:-no}" != "yes" ]; then
      echo "__IRIS_VERIFY_FILES__"
      echo "Directory of bootflash:/guest-share/"
      echo "No files in directory"
      echo "%Error opening bootflash:/guest-share/iris (No such file or directory)"
    fi
    ;;
  *"show version"*)
    echo "cisco ${FAKE_MODEL:-C8000V} (x86) processor"
    echo "Processor board ID ${FAKE_DEVICE_IDENTITY:-FOC1234TEST}"
    ;;
  *"show app-hosting list"*)
    apphost_reply
    ;;
  *"show ip nat translations"*)
    printf '%s\n' "${FAKE_NAT_TRANSLATIONS:-}"
    ;;
  *"show running-config"*)
    natcheck_reply
    ;;
  *"copy running-config startup-config"*)
    echo "[OK]"
    ;;
  *)
    echo "ok"
    ;;
esac
STUB
  chmod +x "$STUBDIR/lab/device-run.sh"

  ln -sf "$UNINSTALL" "$STUBDIR/device/router-uninstall.sh"
}

_router_uninstall_run_live() {
  env DEVICE_IP=192.0.2.10 DEVICE_USER=test DEVICE_PASS=test \
    EXPECTED_DEVICE_IDENTITY=FOC1234TEST ROUTER_RESOURCES_OWNED=1 \
    NAT_REMOVE_SETTLE=1 \
    bash "$STUBDIR/device/router-uninstall.sh"
}

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

@test "undeploy verify merges running-config, app-hosting state, and file listing into ONE call" {
  _router_uninstall_stub_setup
  run _router_uninstall_run_live
  [ "$status" -eq 0 ]
  [[ "$output" == *"is clean and persisted"* ]]
  merged="$(_calls_containing "$FAKE_COMMAND_LOG" '__IRIS_VERIFY_RUNNING__' \
    'show running-config' 'show app-hosting list' 'dir bootflash:guest-share')"
  [ "$merged" -eq 1 ]
}

@test "undeploy fails closed (never reports clean) when the FILES marker is missing" {
  # A dropped FILES section must never read as "nothing left" -- the
  # forbidden-artifact scan treats absence as proof of a clean teardown, so
  # a truncated response has to fail loudly instead of quietly passing.
  _router_uninstall_stub_setup
  FAKE_VERIFY_OMIT_FILES=yes run _router_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"ERROR: undeploy verify did not return guest-share file listing"* ]]
  [[ "$output" != *"is clean and persisted"* ]]
}

@test "undeploy fails closed (never reports clean) when the RUNNING marker is missing" {
  _router_uninstall_stub_setup
  FAKE_VERIFY_OMIT_RUNNING=yes run _router_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"ERROR: undeploy verify did not return running-config"* ]]
  [[ "$output" != *"is clean and persisted"* ]]
}

@test "undeploy verify does NOT falsely declare clean when residue is actually present" {
  # Sanity check that the merge didn't also weaken the forbidden-artifact
  # scan itself: real residue in a well-formed (marker-complete) response
  # must still be caught.
  _router_uninstall_stub_setup
  FAKE_UNINSTALL_LEAVE_RESIDUE=yes run _router_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"artifacts still present after undeploy"* ]]
}

@test "NAT overload retry loop still mutates, re-observes, and retries as separate calls" {
  # Must NOT be flattened: IOS refuses the overload no-form while
  # translations still reference it, so this has to stay mutate -> observe
  # -> retry across separate device-run.sh calls, never a single shot.
  _router_uninstall_stub_setup
  NETWORK_ATTACHMENT=router-nat NAT_INTERFACE=GigabitEthernet1 \
    FAKE_NAT_DRAIN_ROUNDS=2 run _router_uninstall_run_live
  [ "$status" -eq 0 ]
  mutates="$(_calls_between_containing "$FAKE_COMMAND_LOG" \
    'no ip nat inside source static tcp' 'no app-hosting appid guestshell' \
    'no ip nat inside source list IRIS-NAT-10 interface GigabitEthernet1 overload')"
  observes="$(_calls_between_containing "$FAKE_COMMAND_LOG" \
    'no ip nat inside source static tcp' 'no app-hosting appid guestshell' \
    'show running-config')"
  [ "$mutates" -ge 2 ]
  [ "$observes" -ge 2 ]
}

@test "guestshell disable-wait and destroy-wait polls remain separate calls, not merged" {
  _router_uninstall_stub_setup
  FAKE_DISABLE_POLLS=2 FAKE_DESTROY_POLLS=2 run _router_uninstall_run_live
  [ "$status" -eq 0 ]
  disable_calls="$(_calls_between_containing "$FAKE_COMMAND_LOG" \
    'guestshell disable' 'guestshell destroy' 'show app-hosting list')"
  destroy_calls="$(_calls_between_containing "$FAKE_COMMAND_LOG" \
    'guestshell destroy' 'no app-hosting appid guestshell' 'show app-hosting list')"
  [ "$disable_calls" -ge 2 ]
  [ "$destroy_calls" -ge 2 ]
}
