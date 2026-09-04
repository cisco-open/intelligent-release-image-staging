#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Record-driven inverse of router-install.sh. Staged images at bootflash: root
# are deliberately preserved.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1
if [ -n "${NETWORK_ATTACHMENT:-}" ] && [ -z "${MANAGEMENT_TYPE:-}" ]; then
  echo "ERROR: NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE; refusing to fall back to the router-routed default" >&2
  exit 1
fi
MANAGEMENT_TYPE="${MANAGEMENT_TYPE:-router-routed}"
VPG_NUMBER="${VPG_NUMBER:-}"
NAT_INTERFACE="${NAT_INTERFACE:-}"
BT_LISTEN_PORT="${BT_LISTEN_PORT:-6881}"
NAT_OUTSIDE_OWNED="${NAT_OUTSIDE_OWNED:-0}"
ROUTER_RESOURCES_OWNED="${ROUTER_RESOURCES_OWNED:-0}"
# Force teardown for a device stranded WITHOUT a deployment record: an onboard
# that died after enabling Guest Shell but before its record was written
# leaves a router that cannot be undeployed (no record), cannot be adopted
# (routers never can) and cannot be re-onboarded (preflight refuses an
# existing Guest Shell).
# Force mode removes only the AGENT footprint, which is identifiable by name.
# It must never touch the VPG/NAT: with no record there is no proof IRIS
# created them, and removing an operator's network would be exactly the harm
# the record design exists to prevent.
FORCE_AGENT_ONLY="${IRIS_FORCE_AGENT_ONLY:-0}"
APP_IP="${APP_IP:-}"
IOS_ROOT="bootflash:guest-share"
# Everything under IRIS_DIR goes recursively; guest-share itself is a
# preserved platform directory where only the named files below are removed.
# The peer-transfer hook adds nothing to that root: its staged source lives at
# iris/agent/peer-transfer-hook.sh, its snapshots at iris/<image>.peers.json,
# and its exec-capable copy inside the guest at /home/guestshell (which goes
# with `guestshell destroy`). Keep it that way -- a stray name at this root is
# exactly what the collision preflight refuses on the next onboard.
IRIS_DIR="$IOS_ROOT/iris"

case "$MANAGEMENT_TYPE" in
  router-routed) ;;
  router-nat)
    # Force skips the NAT teardown entirely, so requiring record-derived NAT
    # values would re-strand the device this mode exists to rescue.
    if [ "${IRIS_FORCE_AGENT_ONLY:-0}" != "1" ]; then
      [ -n "$NAT_INTERFACE" ] && [ -n "$APP_IP" ] \
        || { echo "ERROR: router-nat deployment record is missing NAT_INTERFACE or APP_IP" >&2; exit 1; }
    fi ;;
  *) echo "ERROR: MANAGEMENT_TYPE must be router-routed or router-nat" >&2; exit 1 ;;
esac
if [ "$FORCE_AGENT_ONLY" != "1" ]; then
  [[ "$VPG_NUMBER" =~ ^[0-9]+$ ]] && [ "$VPG_NUMBER" -ge 0 ] \
    && [ "$VPG_NUMBER" -le 31 ] \
    || { echo "ERROR: deployment record is missing a valid VPG_NUMBER" >&2; exit 1; }
fi
if [ -n "$NAT_INTERFACE" ] && ! [[ "$NAT_INTERFACE" =~ ^[A-Za-z][A-Za-z0-9./_-]{0,63}$ ]]; then
  echo "ERROR: NAT_INTERFACE contains unsupported characters" >&2; exit 1
fi

MODEL="${MODEL:-}"
EXPECTED_DEVICE_IDENTITY="${EXPECTED_DEVICE_IDENTITY:-}"
if [ "$DRY" -eq 0 ]; then
  : "${DEVICE_IP:?set DEVICE_IP}"; : "${DEVICE_USER:?set DEVICE_USER}"
  : "${DEVICE_PASS:?set DEVICE_PASS}"
  if [ "$FORCE_AGENT_ONLY" = "1" ]; then
    echo "===== FORCE: agent-footprint-only teardown (no deployment record) ====="
    echo "  Removing: IRIS EEM applets, Guest Shell, and $IRIS_DIR."
    echo "  Reclaiming ONLY what carries IRIS's own mark: a VirtualPortGroup"
    echo "  with IRIS's description, and IRIS-NAT-* objects. Anything unmarked"
    echo "  is left exactly as it is."
  else
    : "${EXPECTED_DEVICE_IDENTITY:?set EXPECTED_DEVICE_IDENTITY from the deployment record}"
    [ "$ROUTER_RESOURCES_OWNED" = "1" ] \
      || { echo "ERROR: deployment record does not prove ownership of router resources" >&2; exit 1; }
  fi
  VERSION_OUT="$(printf 'show version\n' \
    | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null)"
  LIVE_MODEL="$(printf '%s\n' "$VERSION_OUT" \
    | sed -nE 's/^cisco[[:space:]]+([^[:space:]]+)[[:space:]]+\(.*/\1/p' | head -1)"
  LIVE_IDENTITY="$(printf '%s\n' "$VERSION_OUT" \
    | sed -nE 's/^[Pp]rocessor board ID[[:space:]]+([^[:space:]]+).*/\1/p' | head -1)"
  # Force mode is the record-less rescue path, so there is no expected
  # identity to compare a live board ID against. Demanding one anyway made
  # every forced undeploy abort here, which permanently stranded the routers
  # this mode exists to rescue. The operator named DEVICE_IP explicitly and
  # force only removes artifacts identifiable as IRIS's own by name.
  if [ "$FORCE_AGENT_ONLY" != "1" ]; then
    if [ -z "$LIVE_IDENTITY" ] || [ "$LIVE_IDENTITY" != "$EXPECTED_DEVICE_IDENTITY" ]; then
      # Name the way out. This fires whenever the box answering at DEVICE_IP is
      # not the one the record was written for -- overwhelmingly because it was
      # rebuilt or replaced, which keeps the address and the device id but gets
      # a fresh board ID. Refusing is right; refusing without saying what to do
      # next left the operator with an undeploy that would not run and an
      # onboard that told them to run it.
      echo "ERROR: device identity mismatch; refusing to modify $DEVICE_IP" >&2
      echo "  record expects board ID '$EXPECTED_DEVICE_IDENTITY', device reports '${LIVE_IDENTITY:-none}'" >&2
      echo "  If this device was rebuilt or replaced, undeploy it again with Force" >&2
      echo "  (removes the IRIS agent footprint only, leaving VirtualPortGroup and" >&2
      echo "  NAT untouched), or delete and re-add it in the Console." >&2
      exit 1
    fi
  fi
  MODEL="$LIVE_MODEL"
fi
case "$(printf '%s' "$MODEL" | tr 'a-z' 'A-Z')" in
  C8[0-9][0-9][0-9]*) ;;
  *) echo "ERROR: router recipe supports Catalyst 8000-family models only; detected '${MODEL:-unknown}'" >&2
     exit 1 ;;
esac

if [ "$MANAGEMENT_TYPE" = "router-nat" ] && [ "$FORCE_AGENT_ONLY" != "1" ]; then
  python3 - "$APP_IP" <<'PY'
import ipaddress
import sys
try:
    ipaddress.IPv4Address(sys.argv[1])
except ipaddress.AddressValueError as exc:
    raise SystemExit("ERROR: invalid APP_IP: %s" % exc)
PY
fi

config_teardown() {
cat <<EOF
no event manager applet IRIS-AGENT
no event manager applet IRIS-COPYROOT
no event manager applet IRIS-ROOT-HASH
no event manager applet IRIS-RECLAIM
no event manager applet IRIS-RECLAIM-BUNDLE
EOF
}

# Force mode skips config_cleanup, which owns the removal of everything IRIS
# configured. What it must NOT remove is the operator's network -- the
# VirtualPortGroup and the NAT rules -- because with no record there is no
# proof IRIS created those. Everything else here is IRIS-named and
# unambiguously ours, and router preflight refuses a re-onboard while ANY of
# it is present (see the collisions list in gui_onboard.py). Leaving it behind
# left the device exactly as stranded as before the teardown ran, which is the
# one thing force mode exists to prevent.
# The description router-install.sh writes into every VirtualPortGroup IRIS
# creates (see device/router-install.sh, "interface VirtualPortGroup" block).
# It is on-device proof of ownership that survives the loss of a record --
# which is what makes the force path able to reclaim its own network config
# without ever guessing about an operator's.
IRIS_VPG_DESCRIPTION="description IRIS Guest Shell VPG"

# Echo the VPG numbers whose interface block carries IRIS's description, and
# the IRIS-named NAT objects present, from ONE running-config read. Anything
# not carrying IRIS's own mark or name is never reported and never touched.
iris_owned_config() {
  printf 'terminal width 512\nshow running-config\n' \
    | "$RUN" "$DEVICE_IP" 2>/dev/null \
    | python3 -c '
import re, sys
marker = sys.argv[1]
text = sys.stdin.read()
# An IOS interface block runs to the next line that starts in column 0.
for m in re.finditer(r"(?ms)^interface VirtualPortGroup(\d+)\s*$\n(.*?)(?=^\S|\Z)", text):
    if marker in m.group(2):
        print("vpg %s" % m.group(1))
for acl in sorted(set(re.findall(r"(?m)^ip access-list standard (IRIS-NAT-\d+)\s*$", text))):
    print("acl %s" % acl)
for acl, iface in re.findall(
        r"(?m)^ip nat inside source list (IRIS-NAT-\d+) interface (\S+) overload\s*$", text):
    print("overload %s %s" % (acl, iface))
# A static mapping is not IRIS-named, but one whose inside-local address sits
# inside an IRIS-marked VPG subnet is ours by the same proof the VPG carries --
# and router preflight refuses to onboard while it collides with the swarm port.
import ipaddress
nets = []
for m in re.finditer(r"(?ms)^interface VirtualPortGroup(\d+)\s*$\n(.*?)(?=^\S|\Z)", text):
    if marker not in m.group(2):
        continue
    a = re.search(r"(?m)^\s*ip address\s+(\S+)\s+(\S+)\s*$", m.group(2))
    if a:
        try:
            nets.append(ipaddress.IPv4Network("%s/%s" % a.groups(), strict=False))
        except ValueError:
            pass
for line in re.findall(r"(?m)^ip nat inside source static tcp .*$", text):
    f = line.split()
    if len(f) < 8:
        continue
    try:
        ip = ipaddress.IPv4Address(f[6])
    except ValueError:
        continue
    if any(ip in n for n in nets):
        print("static %s" % line)
for n in nets:
    print("net %s" % n.with_prefixlen)
' "$IRIS_VPG_DESCRIPTION"
}

# Translations whose inside-local address sits in an IRIS VPG subnet, as
# "<inside-global> <inside-local>" pairs -- the record path clears by APP_IP,
# the force path (no record) clears by the subnet the IRIS-marked VPG owns.
iris_owned_translations() {   # $1 = newline-separated networks (CIDR)
  printf 'show ip nat translations\n' | "$RUN" "$DEVICE_IP" 2>/dev/null \
    | python3 -c '
import ipaddress, re, sys
nets = []
for line in sys.argv[1].splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        nets.append(ipaddress.IPv4Network(line, strict=False))
    except ValueError:
        pass
seen = set()
for line in sys.stdin:
    f = line.split()
    if len(f) < 3:
        continue
    g = re.match(r"^(\d+(?:\.\d+){3})(?::\d+)?$", f[1])
    l = re.match(r"^(\d+(?:\.\d+){3})(?::\d+)?$", f[2])
    if not (g and l):
        continue
    try:
        local = ipaddress.IPv4Address(l.group(1))
    except ValueError:
        continue
    if any(local in n for n in nets) and (g.group(1), str(local)) not in seen:
        seen.add((g.group(1), str(local)))
        print("%s %s" % (g.group(1), local))
' "$1"
}

config_cleanup_force() {
cat <<EOF
no app-hosting appid guestshell
no logging buffered discriminator IRISQ
no logging console discriminator IRISQ
no logging monitor discriminator IRISQ
no logging discriminator IRISQ
no ip http client secure-trustpoint IRIS
no crypto pki trustpoint IRIS
yes
EOF
}

config_cleanup() {
cat <<EOF
no app-hosting appid guestshell
EOF
if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
cat <<EOF
no ip access-list standard IRIS-NAT-$VPG_NUMBER
EOF
  if [ "$NAT_OUTSIDE_OWNED" = "1" ]; then
cat <<EOF
interface $NAT_INTERFACE
 no ip nat outside
exit
EOF
  fi
fi
cat <<EOF
no interface VirtualPortGroup$VPG_NUMBER
no logging buffered discriminator IRISQ
no logging console discriminator IRISQ
no logging monitor discriminator IRISQ
no logging discriminator IRISQ
no ip http client secure-trustpoint IRIS
no crypto pki trustpoint IRIS
yes
EOF
}

if [ "$DRY" -eq 1 ]; then
  echo "===== [1/5] EEM applets removed FIRST ====="; config_teardown
  echo "===== [2/5] guestshell disable  [3/5] guestshell destroy ====="
  if [ "$FORCE_AGENT_ONLY" = "1" ]; then
    echo "===== [4/5] FORCE: IRIS app-hosting stanza removed; VPG/NAT SKIPPED (force) - ownership unproven ====="
    config_cleanup_force
  else
  echo "===== [4/5] record-owned config removal ====="
  if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
    echo "no ip nat inside source static tcp $APP_IP $BT_LISTEN_PORT interface $NAT_INTERFACE $BT_LISTEN_PORT"
    echo "show ip nat translations | include $APP_IP"
    echo "clear ip nat translation inside <IRIS-inside-global> $APP_IP forced"
    echo "no ip nat inside source list IRIS-NAT-$VPG_NUMBER interface $NAT_INTERFACE overload"
    echo "verify overload mapping is absent before removing IRIS-NAT-$VPG_NUMBER"
  fi
  config_cleanup
  fi
  echo "===== [5/5] remove only IRIS files under $IOS_ROOT (preserve directory) ====="
  echo "delete /force /recursive $IRIS_DIR"
  for name in bootstrap.sh iris-agent.conf rpc-secret bundle.tgz iris-catalog.pem; do
    echo "delete /force $IOS_ROOT/$name"
  done
  echo "===== PERSIST: copy running-config startup-config ====="
  echo "===== LEFT IN PLACE: outside interface config not owned by IRIS, bootflash-root image ====="
  exit 0
fi

RUN="$HERE/../lab/device-run.sh"

echo "[1/5] remove EEM applets on $DEVICE_IP"
{ echo "configure terminal"; config_teardown; echo "end"; } | "$RUN" "$DEVICE_IP" >/dev/null

echo "[2/5] guestshell disable"
printf 'guestshell disable\n' | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
st="?"
for _ in $(seq 1 30); do
  st="$(printf 'show app-hosting list\n' | "$RUN" "$DEVICE_IP" | grep -i guestshell || true)"
  case "$st" in *RUNNING*|*STOPPING*) sleep 10 ;; *) break ;; esac
done

echo "[3/5] guestshell destroy"
printf 'guestshell destroy\ny\n' | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  st="$(printf 'show app-hosting list\n' | "$RUN" "$DEVICE_IP" | grep -i guestshell || true)"
  [ -z "$st" ] && break
  sleep 10
done
[ -z "$st" ] || { echo "ERROR: guestshell still present after destroy: $st" >&2; exit 1; }

OWNED=""
if [ "$FORCE_AGENT_ONLY" = "1" ]; then
  echo "[4/5] FORCE: remove the IRIS app-hosting stanza and reclaim IRIS-marked network config"
  { echo "configure terminal"; config_cleanup_force; echo "end"; } | "$RUN" "$DEVICE_IP" >/dev/null
  # Without a record the device itself is the evidence: a VirtualPortGroup
  # carrying IRIS's description, and NAT objects carrying IRIS's own name, are
  # provably ours. Reclaiming them is what lets a stranded router be onboarded
  # again -- router preflight refuses an existing VPG, its subnet, and the
  # IRIS-NAT ACL/overload rule. Anything unmarked is left exactly as it is.
  OWNED="$(iris_owned_config || true)"
  OWNED_NETS="$(printf '%s\n' "$OWNED" | sed -n 's/^net //p')"
  # Order matters, and so does SESSION SEPARATION: static mappings pin the
  # address, the overload rule references its ACL, and the VPG owns the
  # subnet -- unwind inwards out, one mutation per session. IOS refuses the
  # overload no-form while translations still reference it (see the record
  # path below), and on a prompting IOS the NEXT piped line is consumed as
  # the answer -- so a single combined session silently lost the ACL removal
  # too and the run still reported clean. That residue is exactly what
  # router preflight refuses on the next onboard.
  reclaimed_any=0
  while IFS= read -r line; do
    case "$line" in
      "static "*)
        rule="${line#static }"
        echo "  reclaiming static NAT mapping inside the IRIS VPG subnet"
        { echo "configure terminal"; echo "no $rule"; echo "end"; } \
          | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
        reclaimed_any=1 ;;
    esac
  done <<< "$OWNED"
  force_nat_stuck=""
  while IFS=' ' read -r kind a b; do
    [ "$kind" = "overload" ] || continue
    echo "  reclaiming NAT overload rule $a (interface $b)"
    reclaimed_any=1
    NAT_RULE="ip nat inside source list $a interface $b overload"
    NAT_REMOVE_ATTEMPTS="${NAT_REMOVE_ATTEMPTS:-4}"
    NAT_REMOVE_SETTLE="${NAT_REMOVE_SETTLE:-3}"
    nat_gone=0
    attempt=1
    while [ "$attempt" -le "$NAT_REMOVE_ATTEMPTS" ]; do
      # clear only translations inside the IRIS-marked VPG subnet(s) first
      if [ -n "$OWNED_NETS" ]; then
        while read -r global local; do
          [ -n "$global" ] && [ -n "$local" ] || continue
          printf 'clear ip nat translation inside %s %s forced\n' "$global" "$local" \
            | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
        done <<< "$(iris_owned_translations "$OWNED_NETS" || true)"
      fi
      { echo "configure terminal"; echo "no $NAT_RULE"; echo "end"; } \
        | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
      NAT_RUNNING="$(printf 'terminal width 512\nshow running-config\n' \
        | "$RUN" "$DEVICE_IP" | grep -v '#' || true)"
      case "$NAT_RUNNING" in
        *"$NAT_RULE"*) : ;;
        *) nat_gone=1; break ;;
      esac
      [ "$attempt" -lt "$NAT_REMOVE_ATTEMPTS" ] || break
      echo "  NAT mapping still referenced; clearing translations and retrying" \
           "($attempt/$NAT_REMOVE_ATTEMPTS)"
      sleep "$NAT_REMOVE_SETTLE"
      attempt=$((attempt + 1))
    done
    [ "$nat_gone" -eq 1 ] || force_nat_stuck="${force_nat_stuck}${force_nat_stuck:+, }$NAT_RULE"
  done <<< "$OWNED"
  if [ -n "$force_nat_stuck" ]; then
    {
      echo "ERROR: could not remove the IRIS NAT overload mapping after $NAT_REMOVE_ATTEMPTS attempts. LEFT ON THE DEVICE:"
      echo "         $force_nat_stuck"
      echo "       Its ACL is kept so the mapping stays valid for reconciliation rather than dangling."
      echo "       Cause is usually NAT translations still referencing the mapping; re-run the"
      echo "       forced undeploy once \`show ip nat translations\` has drained, or remove both by hand."
    } >&2
    exit 1
  fi
  while IFS=' ' read -r kind a b; do
    [ "$kind" = "acl" ] || continue
    echo "  reclaiming NAT ACL $a"
    reclaimed_any=1
    { echo "configure terminal"; echo "no ip access-list standard $a"; echo "end"; } \
      | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
  done <<< "$OWNED"
  while IFS=' ' read -r kind a b; do
    [ "$kind" = "vpg" ] || continue
    echo "  reclaiming VirtualPortGroup$a (carries IRIS's description)"
    reclaimed_any=1
    { echo "configure terminal"; echo "no interface VirtualPortGroup$a"; echo "end"; } \
      | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
  done <<< "$OWNED"
  if [ "$reclaimed_any" -eq 0 ]; then
    echo "  no IRIS-marked VirtualPortGroup or IRIS-named NAT object found;" \
         "operator network left untouched"
  fi
else
echo "[4/5] remove record-owned VPG and NAT footprint"
# IOS refuses to unconfigure a dynamic NAT mapping while translations still
# reference it. Remove the static rule, clear only translations whose inside
# local address belongs to this record, then remove and verify the overload
# rule before deleting its ACL. A failure leaves the ACL and unrelated device
# translations intact for safe operator reconciliation.
if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
  {
    echo "configure terminal"
    echo "no ip nat inside source static tcp $APP_IP $BT_LISTEN_PORT interface $NAT_INTERFACE $BT_LISTEN_PORT"
    echo "end"
  } | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true

  TRANSLATIONS="$(printf 'show ip nat translations | include %s\n' "$APP_IP" \
    | "$RUN" "$DEVICE_IP" 2>/dev/null || true)"
  GLOBALS="$(python3 -c 'import re, sys
local = sys.argv[1]
seen = set()
for line in sys.stdin:
    fields = line.split()
    if len(fields) < 3:
        continue
    match_global = re.match(r"^(\d+(?:\.\d+){3})(?::\d+)?$", fields[1])
    match_local = re.match(r"^(\d+(?:\.\d+){3})(?::\d+)?$", fields[2])
    if match_global and match_local and match_local.group(1) == local:
        address = match_global.group(1)
        if address not in seen:
            print(address)
            seen.add(address)' "$APP_IP" <<< "$TRANSLATIONS")"
  while IFS= read -r global; do
    [ -z "$global" ] && continue
    printf 'clear ip nat translation inside %s %s forced\n' "$global" "$APP_IP" \
      | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
  done <<< "$GLOBALS"

  # IOS refuses `no ip nat inside source list ... overload` while translations
  # still reference the mapping, and releasing them is not instantaneous. A
  # single immediate re-check therefore raced: it reported residue on routers
  # that were clean seconds later. Retry the removal (re-clearing translations
  # each pass) and only then decide.
  NAT_RULE="ip nat inside source list IRIS-NAT-$VPG_NUMBER interface $NAT_INTERFACE overload"
  NAT_REMOVE_ATTEMPTS="${NAT_REMOVE_ATTEMPTS:-4}"
  NAT_REMOVE_SETTLE="${NAT_REMOVE_SETTLE:-3}"
  nat_gone=0
  attempt=1
  while [ "$attempt" -le "$NAT_REMOVE_ATTEMPTS" ]; do
    {
      echo "configure terminal"
      echo "no $NAT_RULE"
      echo "end"
    } | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
    NAT_RUNNING="$(printf 'terminal width 512\nshow running-config\n' \
      | "$RUN" "$DEVICE_IP" | grep -v '#' || true)"
    case "$NAT_RUNNING" in
      *"$NAT_RULE"*) : ;;
      *) nat_gone=1; break ;;
    esac
    [ "$attempt" -lt "$NAT_REMOVE_ATTEMPTS" ] || break
    echo "  NAT mapping still referenced; clearing translations and retrying" \
         "($attempt/$NAT_REMOVE_ATTEMPTS)"
    sleep "$NAT_REMOVE_SETTLE"
    # re-clear: a translation created after the first sweep would hold the rule
    RETRY_TRANSLATIONS="$(printf 'show ip nat translations | include %s\n' "$APP_IP" \
      | "$RUN" "$DEVICE_IP" 2>/dev/null || true)"
    while IFS= read -r global; do
      [ -z "$global" ] && continue
      printf 'clear ip nat translation inside %s %s forced\n' "$global" "$APP_IP" \
        | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
    done <<< "$(printf '%s\n' "$RETRY_TRANSLATIONS" | awk 'NF>=3 && $2 ~ /^[0-9]+\./ {split($2,g,":"); print g[1]}' | sort -u)"
    attempt=$((attempt + 1))
  done
  if [ "$nat_gone" -ne 1 ]; then
    {
      echo "ERROR: could not remove the IRIS NAT overload mapping after" \
           "$NAT_REMOVE_ATTEMPTS attempts. LEFT ON THE DEVICE:"
      echo "         $NAT_RULE"
      echo "         ip access-list standard IRIS-NAT-$VPG_NUMBER  (preserved deliberately)"
      echo "       The ACL is kept so the mapping stays valid for reconciliation" \
           "rather than dangling."
      echo "       Cause is usually NAT translations still referencing the mapping."
      echo "       Fix: re-run this undeploy once translations have drained" \
           "(\`show ip nat translations\`), or remove both by hand:"
      echo "         configure terminal"
      echo "          no $NAT_RULE"
      echo "          no ip access-list standard IRIS-NAT-$VPG_NUMBER"
      echo "         end"
    } >&2
    exit 1
  fi
fi
{ echo "configure terminal"; config_cleanup; echo "end"; } | "$RUN" "$DEVICE_IP" >/dev/null

fi

echo "[5/5] remove IRIS files under $IOS_ROOT (preserve the platform directory)"
{
  printf 'delete /force /recursive %s\n' "$IRIS_DIR"
  for name in bootstrap.sh iris-agent.conf rpc-secret bundle.tgz iris-catalog.pem; do
    printf 'delete /force %s/%s\n' "$IOS_ROOT" "$name"
  done
} | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true

# One SSH login for all three read-only verify checks instead of three --
# same consolidation as _default_router_preflight in server/gui_onboard.py.
# IOS XE echoes these markers verbatim; a missing marker is a hard error,
# never treated as empty/safe output. Treating a dropped section as empty
# here would be actively dangerous: the forbidden-artifact scan below reads
# "nothing found" as "nothing left to remove," so a truncated response must
# fail the undeploy, not silently pass it as clean.
VERIFY_MARKER="__IRIS_VERIFY_"
verify_request() {
cat <<EOF
terminal width 512
echo ${VERIFY_MARKER}RUNNING__
show running-config
echo ${VERIFY_MARKER}APPS__
show app-hosting list
echo ${VERIFY_MARKER}FILES__
dir bootflash:guest-share
dir bootflash:guest-share/iris
EOF
}
verify_section() {
  python3 -c 'import re, sys
marker = "__IRIS_VERIFY_"
name = sys.argv[1]
text = sys.stdin.read()
start = marker + name + "__"
match = re.search(re.escape(start) + r"\r?\n?(.*?)(?=" + re.escape(marker) + r"[A-Z_]+__|\Z)", text, re.DOTALL)
if not match:
    sys.exit(1)
sys.stdout.write(match.group(1))' "$1"
}
VERIFY_OUT="$(verify_request | "$RUN" "$DEVICE_IP" || true)"
RUNNING_RAW="$(printf '%s' "$VERIFY_OUT" | verify_section RUNNING)" \
  || { echo "ERROR: undeploy verify did not return running-config; refusing to declare the device clean" >&2; exit 1; }
RUNNING="$(printf '%s' "$RUNNING_RAW" | grep -v '#' || true)"
config_block() {
  python3 -c 'import re,sys
name = re.escape(sys.argv[1])
text = sys.stdin.read()
match = re.search(r"(?ms)^interface %s\s*$\n(.*?)(?=^!\s*$|^interface |^end\s*$|\Z)" % name, text)
print(match.group(0) if match else "")' "$1"
}
APPS_RAW="$(printf '%s' "$VERIFY_OUT" | verify_section APPS)" \
  || { echo "ERROR: undeploy verify did not return app-hosting state; refusing to declare the device clean" >&2; exit 1; }
APP_STATE="$(printf '%s' "$APPS_RAW" | grep -v '#' || true)"
FILES_RAW="$(printf '%s' "$VERIFY_OUT" | verify_section FILES)" \
  || { echo "ERROR: undeploy verify did not return guest-share file listing; refusing to declare the device clean" >&2; exit 1; }
FILES="$(printf '%s' "$FILES_RAW" | grep -v '#' || true)"

forbidden=""
# Only a record proves IRIS created the VirtualPortGroup, and only a record
# supplies its number. Force mode deliberately preserves it, so scanning for a
# bare "interface VirtualPortGroup" prefix would flag the operator's own group
# and fail a teardown that actually succeeded.
if [ "$FORCE_AGENT_ONLY" != "1" ]; then
  case "$RUNNING" in
    *"interface VirtualPortGroup$VPG_NUMBER"*)
      forbidden="interface VirtualPortGroup$VPG_NUMBER" ;;
  esac
fi
# The agent footprint every teardown removes, forced or not.
for artifact in \
  "app-hosting appid guestshell" \
  "event manager applet IRIS-"; do
  case "$RUNNING" in *"$artifact"*) forbidden="${forbidden}${forbidden:+, }$artifact" ;; esac
done
# Scanned in BOTH modes: force removes these too, because preflight refuses a
# re-onboard while any of them is present and force exists to clear exactly
# that condition.
for artifact in \
  "logging discriminator IRISQ" \
  "logging buffered discriminator IRISQ" \
  "logging console discriminator IRISQ" \
  "logging monitor discriminator IRISQ" \
  "crypto pki trustpoint IRIS" \
  "ip http client secure-trustpoint IRIS"; do
  case "$RUNNING" in *"$artifact"*) forbidden="${forbidden}${forbidden:+, }$artifact" ;; esac
done
case "$APP_STATE" in *guestshell*) forbidden="${forbidden}${forbidden:+, }guestshell" ;; esac
case "$FILES" in
  *"Directory of bootflash:/guest-share/iris"*)
    forbidden="${forbidden}${forbidden:+, }bootflash:guest-share/iris" ;;
esac
for name in bootstrap.sh iris-agent.conf rpc-secret bundle.tgz iris-catalog.pem; do
  case "$FILES" in *"$name"*) forbidden="${forbidden}${forbidden:+, }$IOS_ROOT/$name" ;; esac
done

if [ "$MANAGEMENT_TYPE" = "router-nat" ] && [ "$FORCE_AGENT_ONLY" != "1" ]; then
  for artifact in \
    "ip access-list standard IRIS-NAT-$VPG_NUMBER" \
    "ip nat inside source list IRIS-NAT-$VPG_NUMBER interface $NAT_INTERFACE overload" \
    "ip nat inside source static tcp $APP_IP $BT_LISTEN_PORT interface $NAT_INTERFACE $BT_LISTEN_PORT"; do
    case "$RUNNING" in *"$artifact"*) forbidden="${forbidden}${forbidden:+, }$artifact" ;; esac
  done
  if [ "$NAT_OUTSIDE_OWNED" = "1" ]; then
    OUTSIDE_RUNNING="$(printf '%s\n' "$RUNNING" | config_block "$NAT_INTERFACE")"
    case "$OUTSIDE_RUNNING" in
      *"ip nat outside"*) forbidden="${forbidden}${forbidden:+, }$NAT_INTERFACE ip nat outside" ;;
    esac
  fi
fi

# Force mode: everything the reclaim step CHOSE to remove (because it carried
# IRIS's mark or name) must actually be gone. The scan used to skip every NAT
# artifact in force mode, so a refused overload no-form -- the normal state of
# a router that was seeding seconds earlier -- was persisted and recorded as
# clean, and the next onboard was refused on "IRIS-NAT-N already exists".
if [ "$FORCE_AGENT_ONLY" = "1" ] && [ -n "$OWNED" ]; then
  while IFS= read -r line; do
    set -- $line
    case "${1:-}" in
      acl)      artifact="ip access-list standard $2" ;;
      overload) artifact="ip nat inside source list $2 interface $3 overload" ;;
      vpg)      artifact="interface VirtualPortGroup$2" ;;
      static)   artifact="${line#static }" ;;
      *)        continue ;;
    esac
    case "$RUNNING" in *"$artifact"*) forbidden="${forbidden}${forbidden:+, }$artifact" ;; esac
  done <<< "$OWNED"
fi

[ -z "$forbidden" ] || {
  echo "ERROR: artifacts still present after undeploy: $forbidden" >&2
  exit 1
}

save_out="$(printf 'copy running-config startup-config\n' | "$RUN" "$DEVICE_IP" 2>&1 || true)"
case "$save_out" in
  *"[OK]"*|*"bytes copied"*) echo "undeploy complete: $DEVICE_IP is clean and persisted" ;;
  *) echo "ERROR: cleanup succeeded but saving startup-config failed:" >&2
     printf '%s\n' "$save_out" >&2; exit 1 ;;
esac
