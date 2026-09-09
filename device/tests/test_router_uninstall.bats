#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  UNINSTALL="$BATS_TEST_DIRNAME/../router-uninstall.sh"
  export MODEL=C8000V MANAGEMENT_TYPE=router-routed VPG_NUMBER=10 \
    APP_IP=10.8.0.2
}

@test "stale NETWORK_ATTACHMENT without MANAGEMENT_TYPE aborts; a normal env is unaffected" {
  run env -u MANAGEMENT_TYPE NETWORK_ATTACHMENT=router-routed bash "$UNINSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE"* ]] || return 1
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "router-routed teardown removes only the VPG app footprint" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no interface VirtualPortGroup10"* ]]
  [[ "$output" == *"no app-hosting appid guestshell"* ]]
  [[ "$output" == *"no event manager applet IRIS-ROOT-HASH"* ]]
  [[ "$output" == *"delete /force /recursive bootflash:guest-share/iris"* ]]
  [[ "$output" == *"delete /force bootflash:guest-share/bootstrap.sh"* ]]
  [[ "$output" != *"delete /force /recursive bootflash:guest-share"$'\n'* ]]
  [[ "$output" != *"IRIS-NAT-"* ]]
}

@test "router teardown removes and verifies interrupted integrity-stage inputs" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"delete /force bootflash:guest-share/bundle.tgz.sha256"* ]] || return 1
  [[ "$output" == *"delete /force bootflash:guest-share/iris-instructions.bootstrap"* ]] || return 1
  [[ "$output" == *"delete /force bootflash:guest-share/iris-signers.allowed_signers"* ]]
}

@test "router NAT teardown removes record-owned NAT rules" {
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no ip nat inside source static tcp 10.8.0.2 6881 interface GigabitEthernet1 6881"* ]]
  [[ "$output" == *"no ip nat inside source list IRIS-NAT-10 interface GigabitEthernet1 overload"* ]]
  [[ "$output" == *"no ip access-list standard IRIS-NAT-10"* ]]
}

@test "NAT teardown clears only record-owned translations before the mapping" {
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 \
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
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 NAT_OUTSIDE_OWNED=0 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"no ip nat outside"* ]]
}

@test "IRIS-created outside marking is removed" {
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 NAT_OUTSIDE_OWNED=1 \
    run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"interface GigabitEthernet1"* ]]
  [[ "$output" == *"no ip nat outside"* ]]
}

@test "router teardown never emits switch network primitives" {
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 NAT_OUTSIDE_OWNED=1 \
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

@test "real router undeploy requires deployment record ownership and processor-board identity" {
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
  [[ "$output" == *"Retry after NAT translations drain"* ]]
}

@test "force teardown removes the agent footprint and reclaims only IRIS-marked network config" {
  # A router whose onboard died after enabling Guest Shell but before its
  # deployment record was written cannot be undeployed (no record), cannot be
  # adopted (routers never can) and cannot be re-onboarded (preflight refuses
  # an existing VirtualPortGroup and an existing Guest Shell). Force mode is
  # the only way out.
  #
  # It used to skip the VPG/NAT entirely, on the belief that without a record
  # nothing proves IRIS created them. That was wrong, and it stranded routers:
  # router-install.sh stamps every VPG it creates with a description, and the
  # NAT objects carry IRIS's own name. Ownership is provable ON THE DEVICE, so
  # force now reclaims exactly what carries IRIS's mark -- and nothing else.
  #
  # Dry-run cannot discover device state, so it still reports the reclaim as
  # device-driven; the live tests below pin the actual behaviour.
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no event manager applet IRIS-AGENT"* ]]
  [[ "$output" == *"guestshell destroy"* ]] || [[ "$output" == *"guestshell disable"* ]]
  [[ "$output" == *"delete /force /recursive bootflash:guest-share/iris"* ]]
  # Never a blind removal: force must not emit an unqualified VPG teardown.
  [[ "$output" != *"no interface VirtualPortGroup"$'\n'* ]]
}

@test "force teardown removes a VPG carrying IRIS's own description" {
  _router_uninstall_stub_setup
  FAKE_RUNNING_IRIS_VPG=yes _router_uninstall_run_live_forced
  # VirtualPortGroup7 is the one the stub marks with IRIS's description.
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no interface VirtualPortGroup7")" -ge 1 ]
}

@test "force teardown never removes a VPG that lacks IRIS's description" {
  # THE safety property: an operator's own VirtualPortGroup carries no IRIS
  # marker and must survive a force teardown untouched.
  _router_uninstall_stub_setup
  FAKE_RUNNING_OPERATOR_VPG=yes _router_uninstall_run_live_forced
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no interface VirtualPortGroup3")" -eq 0 ]
}

@test "force teardown reclaims the IRIS VPG while leaving the operator's alone" {
  _router_uninstall_stub_setup
  FAKE_RUNNING_IRIS_VPG=yes FAKE_RUNNING_OPERATOR_VPG=yes \
    _router_uninstall_run_live_forced
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no interface VirtualPortGroup7")" -ge 1 ]
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no interface VirtualPortGroup3")" -eq 0 ]
}

@test "force teardown removes IRIS-named NAT objects it finds on the device" {
  # ip access-list standard IRIS-NAT-5 / its overload rule carry IRIS's own
  # name, so they are provably IRIS's exactly like the marked VPG.
  _router_uninstall_stub_setup
  FAKE_RUNNING_NAT=yes _router_uninstall_run_live_forced
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no ip access-list standard IRIS-NAT-5")" -ge 1 ]
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no ip nat inside source list IRIS-NAT-5 interface GigabitEthernet1 overload")" -ge 1 ]
}

@test "force teardown removes a static NAT mapping inside the IRIS VPG subnet" {
  # gui_onboard router preflight also refuses when a leftover static mapping
  # collides with the swarm port. The mapping is not IRIS-named, but its
  # inside-local address lies inside the IRIS-marked VPG's own subnet, which
  # is the same ownership proof the VPG itself carries.
  _router_uninstall_stub_setup
  FAKE_RUNNING_IRIS_VPG=yes FAKE_RUNNING_NAT=yes _router_uninstall_run_live_forced
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no ip nat inside source static tcp 192.168.254.10 6881 interface GigabitEthernet1 6881")" -ge 1 ]
}

@test "force teardown leaves a static NAT mapping outside any IRIS subnet alone" {
  # Same shape of rule, but its inside-local is not in an IRIS VPG subnet --
  # it is the operator's, and must survive.
  _router_uninstall_stub_setup
  FAKE_RUNNING_NAT=yes _router_uninstall_run_live_forced
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no ip nat inside source static tcp 192.168.254.10")" -eq 0 ]
}

@test "force teardown on a clean router removes no network config at all" {
  _router_uninstall_stub_setup
  _router_uninstall_run_live_forced
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no interface VirtualPortGroup")" -eq 0 ]
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "IRIS-NAT-")" -eq 0 ]
}

@test "force teardown does not require a deployment record VPG number" {
  # Without a record there is no VPG number to validate; requiring one would
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

# Model removals: an object the script un-configures stops being reported by
# every later read (verify AND the retry loop's re-observe). The overload
# no-form is honoured only after FAKE_FORCE_NAT_DRAIN_ROUNDS attempts
# (default 1) -- IOS refuses it while translations still reference it -- and
# never when FAKE_FORCE_NAT_STUCK=yes.
case "$cmds" in
  *"no ip access-list standard IRIS-NAT-5"*) touch "$FAKE_STATE_DIR/acl5_removed" ;;
esac
case "$cmds" in
  *"no ip nat inside source list IRIS-NAT-5 interface GigabitEthernet1 overload"*)
    n=$(( $(cat "$FAKE_STATE_DIR/overload5_no_n" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$FAKE_STATE_DIR/overload5_no_n"
    if [ "${FAKE_FORCE_NAT_STUCK:-no}" != "yes" ] && [ "$n" -ge "${FAKE_FORCE_NAT_DRAIN_ROUNDS:-1}" ]; then
      touch "$FAKE_STATE_DIR/overload5_removed"
    fi ;;
esac
case "$cmds" in
  *"no ip nat inside source static tcp 192.168.254.10 6881"*) touch "$FAKE_STATE_DIR/static_removed" ;;
esac
case "$cmds" in
  *"no interface VirtualPortGroup7"*) touch "$FAKE_STATE_DIR/vpg7_removed" ;;
esac
case "$cmds" in
  *"clear ip nat translation inside"*)
    printf '%s\n' "$cmds" | grep 'clear ip nat translation' >> "$FAKE_STATE_DIR/cleared" ;;
esac

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
        if [ "${FAKE_RUNNING_OPERATOR_VPG:-no}" = "yes" ]; then
          echo "interface VirtualPortGroup3"
          echo " ip address 192.168.254.1 255.255.255.252"
          echo "!"
        fi
        # A VPG carrying the description router-install.sh writes into every
        # VPG IRIS creates -- on-device proof of IRIS ownership.
        if [ "${FAKE_RUNNING_IRIS_VPG:-no}" = "yes" ] && [ ! -e "$FAKE_STATE_DIR/vpg7_removed" ]; then
          echo "interface VirtualPortGroup7"
          echo " description IRIS Guest Shell VPG"
          echo " ip address 192.168.254.9 255.255.255.252"
          echo "!"
        fi
        # What router-install.sh leaves on EVERY router it onboards and only
        # config_cleanup removes -- which force mode skips by design.
        if [ "${FAKE_RUNNING_AGENT_CONFIG:-no}" = "yes" ]; then
          echo "logging discriminator IRISQ mnemonics drops IOX_INST_WARN"
          echo "logging buffered discriminator IRISQ"
          echo "logging console discriminator IRISQ"
          echo "logging monitor discriminator IRISQ"
          echo "crypto pki trustpoint IRIS"
          echo "ip http client secure-trustpoint IRIS"
        fi
        if [ "${FAKE_RUNNING_NAT:-no}" = "yes" ]; then
          [ -e "$FAKE_STATE_DIR/acl5_removed" ] || echo "ip access-list standard IRIS-NAT-5"
          [ -e "$FAKE_STATE_DIR/overload5_removed" ] || echo "ip nat inside source list IRIS-NAT-5 interface GigabitEthernet1 overload"
          [ -e "$FAKE_STATE_DIR/static_removed" ] || echo "ip nat inside source static tcp 192.168.254.10 6881 interface GigabitEthernet1 6881"
        fi
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
    # A real device returns the whole config here. The force path's ownership
    # scan reads it, so the stub must be faithful; the NAT-drain retry loop
    # only greps for its own rule, which natcheck_reply still supplies.
    echo "hostname iris8kv-1"
    if [ "${FAKE_RUNNING_OPERATOR_VPG:-no}" = "yes" ]; then
      echo "interface VirtualPortGroup3"
      echo " ip address 192.168.254.1 255.255.255.252"
      echo "!"
    fi
    if [ "${FAKE_RUNNING_IRIS_VPG:-no}" = "yes" ] && [ ! -e "$FAKE_STATE_DIR/vpg7_removed" ]; then
      echo "interface VirtualPortGroup7"
      echo " description IRIS Guest Shell VPG"
      echo " ip address 192.168.254.9 255.255.255.252"
      echo "!"
    fi
    if [ "${FAKE_RUNNING_NAT:-no}" = "yes" ]; then
      [ -e "$FAKE_STATE_DIR/acl5_removed" ] || echo "ip access-list standard IRIS-NAT-5"
      [ -e "$FAKE_STATE_DIR/overload5_removed" ] || echo "ip nat inside source list IRIS-NAT-5 interface GigabitEthernet1 overload"
      [ -e "$FAKE_STATE_DIR/static_removed" ] || echo "ip nat inside source static tcp 192.168.254.10 6881 interface GigabitEthernet1 6881"
    fi
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

_router_uninstall_run_live_forced() {
  # The record-less rescue path: no EXPECTED_DEVICE_IDENTITY, no proven
  # resource ownership and no VPG number, because there is no deployment
  # record to supply any of them. This is exactly what gui_server.py sets
  # when it forces a teardown.
  env -u EXPECTED_DEVICE_IDENTITY -u ROUTER_RESOURCES_OWNED -u VPG_NUMBER \
    DEVICE_IP=192.0.2.10 DEVICE_USER=test DEVICE_PASS=test \
    IRIS_FORCE_AGENT_ONLY=1 NAT_REMOVE_SETTLE=1 \
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
  [[ "$output" == *"undeploy complete:"* ]]
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
  [[ "$output" != *"undeploy complete:"* ]]
}

@test "undeploy fails closed (never reports clean) when the RUNNING marker is missing" {
  _router_uninstall_stub_setup
  FAKE_VERIFY_OMIT_RUNNING=yes run _router_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"ERROR: undeploy verify did not return running-config"* ]]
  [[ "$output" != *"undeploy complete:"* ]]
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
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 \
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

@test "forced live teardown does not demand an identity it cannot have" {
  # Force mode exists for a router with NO deployment record, so there is no
  # EXPECTED_DEVICE_IDENTITY to compare a live processor board ID against.
  # Comparing anyway fails every real forced undeploy before it touches the
  # device, stranding the exact router this mode exists to rescue.
  # NOTE: `|| return 1` is load-bearing -- under bash 3.2 a bare failing
  # `[[ ]]` mid-body does NOT fail a bats test.
  _router_uninstall_stub_setup
  run _router_uninstall_run_live_forced
  [[ "$output" != *"device identity mismatch"* ]] || return 1
  [[ "$output" == *"Force undeploy:"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "forced live teardown does not report the operator VirtualPortGroup as residue" {
  # Force preserves any VPG that does not carry IRIS's description -- this one
  # is the operator's. With no record VPG_NUMBER is empty, so scanning for a
  # bare "interface VirtualPortGroup" matches the operator's own group and
  # fails an undeploy that in fact succeeded.
  _router_uninstall_stub_setup
  FAKE_RUNNING_OPERATOR_VPG=yes run _router_uninstall_run_live_forced
  [[ "$output" != *"artifacts still present"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "forced live teardown still fails when the agent footprint really remains" {
  # The relaxed scan must not become a blanket pass: guestshell left behind is
  # still IRIS's own artifact and must still fail the undeploy.
  _router_uninstall_stub_setup
  FAKE_UNINSTALL_LEAVE_RESIDUE=yes run _router_uninstall_run_live_forced
  [[ "$output" == *"artifacts still present"* ]] || return 1
  [ "$status" -ne 0 ]
}

@test "forced teardown removes the IRIS config that blocks a re-onboard" {
  # Force mode exists so a stranded router can be recovered AND re-onboarded.
  # Router preflight (gui_onboard.py collisions) refuses on the IRISQ
  # discriminator, its bindings, and the IRIS PKI trustpoint -- all of which
  # only config_cleanup removed, and force skips config_cleanup. So a forced
  # teardown left behind precisely what stops the device being onboarded again,
  # which is the condition force exists to clear.
  #
  # These are IRIS-named artifacts, unambiguously ours -- the same argument
  # that applies to `app-hosting appid guestshell`. The VPG and NAT stay
  # untouched, because no deployment record proves IRIS created those.
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no logging discriminator IRISQ"* ]] || return 1
  [[ "$output" == *"no logging buffered discriminator IRISQ"* ]] || return 1
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]] || return 1
  [[ "$output" == *"no ip http client secure-trustpoint IRIS"* ]] || return 1
  # operator network still off limits
  [[ "$output" != *"no interface VirtualPortGroup"* ]] || return 1
  [ "$status" -eq 0 ]
}

# Rewritten for IRIS-11-004: this test used to assert that force mode IGNORED
# the IRIS-NAT objects in its verify. It now asserts the corrected contract:
# force reclaims the IRIS-named NAT objects (each in its own session, the
# overload no-form retried after clearing IRIS-subnet translations) and the
# verify fails closed when any of them survives.
@test "forced live teardown on router-nat reclaims the IRIS-named NAT objects and verifies they are gone" {
  _router_uninstall_stub_setup
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 APP_IP=10.8.0.2 \
    FAKE_RUNNING_NAT=yes FAKE_FORCE_NAT_DRAIN_ROUNDS=2 run _router_uninstall_run_live_forced
  [[ "$output" != *"artifacts still present"* ]] || return 1
  [ "$status" -eq 0 ] || return 1
  # the overload no-form was retried (first attempt refused while referenced)
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no ip nat inside source list IRIS-NAT-5 interface GigabitEthernet1 overload")" -ge 2 ] || return 1
  # and never shared a session with the ACL removal (a prompting IOS eats the next line)
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no ip nat inside source list IRIS-NAT-5" "no ip access-list standard")" -eq 0 ] || return 1
  # ACL removed only after the overload rule was observed gone
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "no ip access-list standard IRIS-NAT-5")" -eq 1 ]
}

@test "forced live teardown on router-nat fails closed when the overload rule cannot be removed" {
  # A router that was seeding seconds earlier still holds translations, so IOS
  # refuses the no-form. The old force path sent it once, skipped the NAT
  # scan, persisted the residue and reported clean -- and the next onboard was
  # refused on "IRIS-NAT-N already exists" with no record left to undeploy.
  _router_uninstall_stub_setup
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 APP_IP=10.8.0.2 \
    FAKE_RUNNING_NAT=yes FAKE_FORCE_NAT_STUCK=yes run _router_uninstall_run_live_forced
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"could not remove the IRIS NAT overload mapping"* ]] || return 1
  [[ "$output" != *"clean and persisted"* ]] || return 1
  [ "$(_calls_containing "$FAKE_COMMAND_LOG" "copy running-config startup-config")" -eq 0 ]
}

@test "forced live teardown clears only translations inside the IRIS VPG subnet before the overload no-form" {
  _router_uninstall_stub_setup
  MANAGEMENT_TYPE=router-nat NAT_INTERFACE=GigabitEthernet1 APP_IP=10.8.0.2 \
    FAKE_RUNNING_IRIS_VPG=yes FAKE_RUNNING_NAT=yes \
    FAKE_NAT_TRANSLATIONS="$(printf 'tcp 203.0.113.9:6881 192.168.254.10:6881 198.51.100.7:40001 198.51.100.7:40001\ntcp 203.0.113.9:5000 192.168.254.2:5000 198.51.100.8:443 198.51.100.8:443')" \
    run _router_uninstall_run_live_forced
  [ "$status" -eq 0 ] || return 1
  grep -q "clear ip nat translation inside 203.0.113.9 192.168.254.10 forced" "$FAKE_STATE_DIR/cleared" || return 1
  ! grep -q "192.168.254.2" "$FAKE_STATE_DIR/cleared" || return 1
  # cleared BEFORE the first overload no-form
  first_clear="$(grep -n 'clear ip nat translation inside 203.0.113.9' "$FAKE_COMMAND_LOG" | head -1 | cut -d: -f1)"
  first_no="$(grep -n 'no ip nat inside source list IRIS-NAT-5' "$FAKE_COMMAND_LOG" | head -1 | cut -d: -f1)"
  [ "$first_clear" -lt "$first_no" ]
}

@test "forced live teardown fails closed when a reclaimed IRIS VPG survives" {
  _router_uninstall_stub_setup
  # the stub honours the VPG no-form only when it sees it; make it deaf
  sed -i 's/no interface VirtualPortGroup7"\*) touch/no interface VirtualPortGroup7-NEVER"*) touch/' "$STUBDIR/lab/device-run.sh"
  FAKE_RUNNING_IRIS_VPG=yes run _router_uninstall_run_live_forced
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"artifacts still present"*"interface VirtualPortGroup7"* ]]
}

@test "forced teardown does not demand NAT values it will never use" {
  # router-nat comes from the inventory row, but force never touches NAT, so
  # requiring record-derived NAT values re-strands the device.
  unset NAT_INTERFACE APP_IP
  MANAGEMENT_TYPE=router-nat IRIS_FORCE_AGENT_ONLY=1 \
    run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"missing NAT_INTERFACE or APP_IP"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "forced teardown still removes the app-hosting stanza it owns" {
  # router-install.sh writes `app-hosting appid guestshell` on EVERY router
  # (line 121) and config_cleanup is the ONLY place the removal is emitted --
  # but force skips config_cleanup entirely. The block therefore survived a
  # forced teardown while the residue scan still flagged it, failing every
  # forced router undeploy after the destructive work and before the save.
  # It is IRIS's own artifact, identifiable by name, so force must remove it:
  # device-uninstall.sh's force branch does exactly this.
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no app-hosting appid guestshell"* ]] || return 1
  # ...and still must NOT touch the operator network it cannot prove it owns
  [[ "$output" != *"no interface VirtualPortGroup"* ]] || return 1
  [ "$status" -eq 0 ]
}
