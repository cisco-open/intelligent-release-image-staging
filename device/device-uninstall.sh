#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Undeploy IRIS from a Guest Shell device (Catalyst 9300 / ISR / ASR / CSR /
# C8000v): the exact inverse of device/device-install.sh, lab-validated on
# C9300 (2026-07-04). MANAGEMENT_TYPE selects the teardown scope:
#   routed (default) removes the full IRIS footprint:
#     - EEM applets IRIS-AGENT + IRIS-COPYROOT (FIRST, so the 60s timer can't
#       relaunch bootstrap mid-teardown)
#     - the guestshell instance (disable -> destroy) + its app-hosting config
#       (this is also what removes /home/guestshell/iris-peer-transfer-hook --
#        the exec-capable copy guestshell-start.sh makes because /flash
#        denies chmod. Nothing the hook installs sits outside these two.)
#     - interface Vlan$VLAN + vlan $VLAN
#     - the IRISQ logging discriminator + its buffered/console/monitor
#       attachments (EXPLICIT-name no-forms)
#     - crypto pki trustpoint IRIS + ip http client secure-trustpoint IRIS
#     - <fs>guest-share (agent, conf, bundle, staged seeding copy, and the
#       peer-transfer hook's staged source + its <image>.peers.json snapshots)
#   inband preserves the operator-owned VLAN/SVI/routes/VRF, which existed
#     before IRIS and which no deployment record proves IRIS created. It still
#     removes everything carrying IRIS's own name -- the EEM applets, guestshell/
#     app-hosting, guest-share, the IRISQ discriminator and its logging
#     bindings, and the IRIS PKI trustpoint / HTTP-client binding.
# IRIS_FORCE_AGENT_ONLY=1 applies that same reduction regardless of
#   MANAGEMENT_TYPE: a device stranded WITHOUT a deployment record (onboard
#   died after enabling Guest Shell but before its record was written) has no
#   record proving the VLAN/SVI is IRIS's, so the network is left exactly as
#   it is. What is identifiable by name as IRIS is still removed -- leaving it
#   would strand the device against its own next onboard, which preflight
#   refuses while any of it is present.
# Deliberately LEFT IN PLACE (both modes): `iox`, `file prompt quiet`, the
# AppGig trunk itself (`switchport mode trunk`; the installer re-applies it
# idempotently on the next onboard), any staged image at flash root (a
# delivered artifact, never IRIS machinery), and staged images at the
# filesystem root. A record-driven routed teardown does remove the IRIS VLAN
# from the trunk's allowed list (`switchport trunk allowed vlan remove`) --
# that VLAN is record-owned, and the installer only ever ADDED it, so other
# apps' VLANs on the same uplink are untouched in both directions. Successful
# cleanup is persisted to startup-config so a reload cannot restore IRIS
# configuration.
#
# Env (same contract as device-install.sh):
#   DEVICE_IP DEVICE_USER DEVICE_PASS [DEVICE_ENABLE] VLAN
#   APP_INTF (optional) -- the AppGigabitEthernet app-hosting port; derived from
#     the model (`show version`) like the installer does when unset.
#   EXPECTED_DEVICE_IDENTITY (optional) -- the processor board ID recorded at
#     onboard. When set, the FIRST device session is a read-only `show version`
#     and the teardown aborts before any destructive command unless the live
#     board ID matches (same guard as router-uninstall.sh: a rebuilt or
#     re-addressed box must never be torn down against another device's
#     record). When unset the probe still runs (it must succeed) but no
#     identity is compared.
#
# The first session is ALWAYS read-only: it lets lab/device-run.sh learn
# whether this device needs `enable` before any config write, so step 1 can
# no longer run silently unprivileged and leave the applets in place while
# the later, privileged steps destroy the guest.
#
# The verify is marker-gated and fails CLOSED: a dropped or truncated verify
# session is "could not verify", never "clean" -- treating an empty response
# as empty residue is what let a device be recorded clean with the applets,
# trustpoint and SVI still on it.
# Usage:  device-uninstall.sh [--dry-run]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

# VLAN_IN preserves whether a VLAN was actually supplied; the 666 default is
# ONLY for --dry-run rendering. A real run re-requires a non-empty VLAN below,
# because guessing 666 could tear down the wrong SVI/VLAN and then falsely
# verify clean (the verify greps for this exact VLAN). Platform selection is
# the CALLER's job now (OnboardService routes IOx to device/iox/uninstall.sh),
# so this script no longer refuses by model.
if [ -n "${NETWORK_ATTACHMENT:-}" ] && [ -z "${MANAGEMENT_TYPE:-}" ]; then
  echo "ERROR: NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE; refusing to fall back to the routed default" >&2
  exit 1
fi
MANAGEMENT_TYPE="${MANAGEMENT_TYPE:-routed}"
VLAN_IN="${VLAN:-${INBAND_VLAN:-}}"
VLAN="${VLAN_IN:-666}"
IOS_FS="${IOS_FS:-flash:}"
IOS_ROOT="${IOS_FS}guest-share"
# See header: force preserves only the operator's VLAN/SVI network. Everything
# carrying IRIS's own name is still removed regardless of MANAGEMENT_TYPE.
FORCE_AGENT_ONLY="${IRIS_FORCE_AGENT_ONLY:-0}"
# The app-hosting port, same model rule as device-install.sh (IE-3x00 vs 9300).
# APP_INTF_IN keeps an explicit override; a live run re-derives from the model
# the identity probe reads.
APP_INTF_IN="${APP_INTF:-}"
app_intf_for_model() {
  case "$(printf '%s' "${1:-}" | tr 'a-z' 'A-Z')" in
    IE-3*) echo "AppGigabitEthernet1/1" ;;
    *)     echo "AppGigabitEthernet1/0/1" ;;
  esac
}
APP_INTF="${APP_INTF_IN:-$(app_intf_for_model "${MODEL:-}")}"

config_teardown() {
# Every EEM applet the agent may have left in running-config: the 60s bootstrap
# timer (IRIS-AGENT), the copy-to-root applet (IRIS-COPYROOT), and the
# low-space reclaim applets the agent creates on demand and never self-removes
# (IRIS-RECLAIM / IRIS-RECLAIM-BUNDLE). All no-ops if absent.
cat <<EOF
no event manager applet IRIS-AGENT
no event manager applet IRIS-COPYROOT
no event manager applet IRIS-RECLAIM
no event manager applet IRIS-RECLAIM-BUNDLE
EOF
}

config_cleanup() {
# What a teardown may remove is decided by NAME, not by mode. Everything below
# carries IRIS's own name, so IRIS owns it and a teardown clears it in every
# mode -- otherwise a "clean" device still refuses the next onboard on an
# artifact we put there. What inband and force must NOT touch is the
# operator's network: the VLAN and its SVI, which IRIS merely configured and
# no deployment record proves it created.
if [ "$MANAGEMENT_TYPE" = "inband" ] || [ "$FORCE_AGENT_ONLY" = "1" ]; then
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
return
fi
cat <<EOF
no app-hosting appid guestshell
no interface Vlan$VLAN
no vlan $VLAN
interface $APP_INTF
 switchport trunk allowed vlan remove $VLAN
exit
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
  echo "===== [1/5] EEM applets removed FIRST (stops the 60s bootstrap timer) ====="
  config_teardown
  echo "===== [2/5] guestshell disable  [3/5] guestshell destroy (polled) ====="
  if [ "$MANAGEMENT_TYPE" = "inband" ] || [ "$FORCE_AGENT_ONLY" = "1" ]; then
    echo "===== [4/5] IRIS-named config removal (operator VLAN/SVI left in place) ====="
  else
    echo "===== [4/5] config footprint removal ====="
  fi
  config_cleanup
  echo "===== [5/5] delete /force /recursive $IOS_ROOT ====="
   echo "===== PERSIST: copy running-config startup-config (after successful cleanup) ====="
   echo "===== LEFT IN PLACE: iox, file prompt quiet, AppGig trunk mode (only the IRIS VLAN is removed from its allowed list in routed mode), flash-root image ====="
  exit 0
fi

: "${DEVICE_IP:?set DEVICE_IP}"; : "${DEVICE_USER:?set DEVICE_USER}"
: "${DEVICE_PASS:?set DEVICE_PASS}"
if [ "$FORCE_AGENT_ONLY" = "1" ]; then
  echo "===== FORCE: IRIS-named footprint teardown (no deployment record) ====="
  echo "  Removing: IRIS EEM applets, Guest Shell, $IOS_ROOT, IRISQ, and IRIS PKI."
  echo "  Preserving: operator VLAN/SVI network configuration, because no"
  echo "  deployment record proves IRIS created it."
else
  # Only a record-driven teardown removes Vlan$VLAN, so only it needs the number.
  # Demanding one in force mode re-strands the record-less device this mode
  # exists to rescue -- a bare fleet row carries no vlan at all.
  [ -n "$VLAN_IN" ] || { echo "ERROR: VLAN not set (the deployment record is" \
    "missing its vlan); refusing to guess — set the vlan on the device and retry" >&2; exit 1; }
fi
RUN="$HERE/../lab/device-run.sh"
EXPECTED_DEVICE_IDENTITY="${EXPECTED_DEVICE_IDENTITY:-}"

echo "[pre] read-only identity probe on $DEVICE_IP"
VERSION_OUT="$(printf 'show version\n' | "$RUN" "$DEVICE_IP")" \
  || { echo "ERROR: could not read 'show version' from $DEVICE_IP -- the device session failed; refusing to start the teardown" >&2; exit 1; }
[ -n "$(printf '%s' "$VERSION_OUT" | tr -d '[:space:]')" ] \
  || { echo "ERROR: 'show version' on $DEVICE_IP returned nothing (session cut short); refusing to start the teardown" >&2; exit 1; }
LIVE_IDENTITY="$(printf '%s\n' "$VERSION_OUT" \
  | sed -nE 's/^[Pp]rocessor board ID[[:space:]]+([^[:space:]]+).*/\1/p' | head -1)"
LIVE_MODEL="$(printf '%s\n' "$VERSION_OUT" \
  | sed -nE 's/^cisco[[:space:]]+([^[:space:]]+)[[:space:]]+\(.*/\1/p' | head -1)"
[ -n "$APP_INTF_IN" ] || APP_INTF="$(app_intf_for_model "${LIVE_MODEL:-${MODEL:-}}")"
if [ -n "$EXPECTED_DEVICE_IDENTITY" ]; then
  if [ -z "$LIVE_IDENTITY" ] || [ "$LIVE_IDENTITY" != "$EXPECTED_DEVICE_IDENTITY" ]; then
    echo "ERROR: device identity mismatch; refusing to modify $DEVICE_IP" >&2
    echo "  record expects board ID '$EXPECTED_DEVICE_IDENTITY', device reports '${LIVE_IDENTITY:-none}'" >&2
    echo "  If this device was rebuilt or replaced, undeploy it again with Force" >&2
    echo "  (removes the IRIS-named footprint only), or delete and re-add it in the Console." >&2
    exit 1
  fi
  echo "  identity verified: board ID $LIVE_IDENTITY"
fi

echo "[1/5] remove EEM applets on $DEVICE_IP (stops the 60s bootstrap timer)"
{ echo "configure terminal"; config_teardown; echo "end"; } | "$RUN" "$DEVICE_IP" >/dev/null \
  || { echo "ERROR: the applet-removal session on $DEVICE_IP failed; refusing to continue with the timer possibly still armed" >&2; exit 1; }

echo "[2/5] guestshell disable"
printf 'guestshell disable\n' | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
st="?"
for _ in $(seq 1 30); do
  st="$(printf 'show app-hosting list\n' | "$RUN" "$DEVICE_IP" | grep -i guestshell || true)"
  case "$st" in *RUNNING*|*STOPPING*) sleep 10 ;; *) break ;; esac
done
echo "  state after disable: ${st:-<no app-hosting entry>}"

echo "[3/5] guestshell destroy"
# The trailing 'y' answers the destroy confirmation on versions that prompt;
# where none appears it is swallowed as a harmless '% Invalid input'.
printf 'guestshell destroy\ny\n' | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  st="$(printf 'show app-hosting list\n' | "$RUN" "$DEVICE_IP" | grep -i guestshell || true)"
  [ -z "$st" ] && break
  sleep 10
done
if [ -n "$st" ]; then
  echo "ERROR: guestshell still present after destroy: $st" >&2; exit 1
fi
echo "  guestshell destroyed"

if [ "$MANAGEMENT_TYPE" = "inband" ] || [ "$FORCE_AGENT_ONLY" = "1" ]; then
  echo "[4/5] remove IRIS-named footprint (operator VLAN/SVI preserved)"
else
  echo "[4/5] remove config footprint (app-hosting block, Vlan$VLAN, IRISQ, PKI trustpoint)"
fi
{ echo "configure terminal"; config_cleanup; echo "end"; } | "$RUN" "$DEVICE_IP" >/dev/null

echo "[5/5] delete $IOS_ROOT (agent, conf, bundle, staged seeding copy)"
printf 'delete /force /recursive %s\n' "$IOS_ROOT" | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true

echo "verify: no app-hosting entry, no leftover config lines, no guest-share"
# terminal width 512 stops IOS wrapping the echoed command lines (wrap
# fragments would false-match the artifact greps below); lines carrying the
# prompt '#' are the command echoes themselves — excluded.
# Inband (and a record-less force undeploy) intentionally preserves the
# operator-owned network, discriminator, and trustpoint, so its verify only
# asserts the app footprint is gone.
if [ "$MANAGEMENT_TYPE" = "inband" ] || [ "$FORCE_AGENT_ONLY" = "1" ]; then
  # The VLAN/SVI is deliberately absent here -- it is preserved, so scanning
  # for it would fail a teardown that did exactly what it promised. The
  # IRIS-named artifacts ARE removed in this mode, so they are verified.
  verify_filter="applet IRIS-|crypto pki trustpoint IRIS|discriminator IRISQ"
  artifact_re="^guestshell|^event manager applet IRIS-|^crypto pki trustpoint IRIS *\$|IRISQ|guest-share"
else
  verify_filter="applet IRIS-|interface Vlan$VLAN|crypto pki trustpoint IRIS|discriminator IRISQ"
  artifact_re="^guestshell|^event manager applet IRIS-|^interface Vlan$VLAN|^crypto pki trustpoint IRIS *\$|IRISQ|guest-share"
fi
# Marker-gated, same as router-uninstall.sh: every section must come back or
# the undeploy fails closed -- an empty response is "could not verify".
VERIFY_MARKER="__IRIS_VERIFY_"
verify_request() {
cat <<EOF
terminal width 512
echo ${VERIFY_MARKER}APPS__
show app-hosting list
echo ${VERIFY_MARKER}RUNNING__
show running-config | include $verify_filter
echo ${VERIFY_MARKER}FILES__
dir $IOS_FS | include guest-share
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
verify_rc=0
VERIFY_OUT="$(verify_request | "$RUN" "$DEVICE_IP")" || verify_rc=$?
[ "$verify_rc" -eq 0 ] \
  || { echo "ERROR: the undeploy verify session on $DEVICE_IP failed (rc=$verify_rc); refusing to declare the device clean" >&2; exit 1; }
out=""
for section in APPS RUNNING FILES; do
  section_raw="$(printf '%s' "$VERIFY_OUT" | verify_section "$section")" \
    || { echo "ERROR: undeploy verify did not return its $section section (session cut short); refusing to declare the device clean" >&2; exit 1; }
  out="$out
$(printf '%s\n' "$section_raw" | grep -v "#" || true)"
done
left="$(printf '%s\n' "$out" | grep -E "$artifact_re" || true)"
if [ -n "$left" ]; then
  echo "ERROR: artifacts still present after undeploy:" >&2
  printf '%s\n' "$left" >&2
  exit 1
fi
echo "persist cleanup to startup-config"
save_out="$(printf 'copy running-config startup-config\n' | "$RUN" "$DEVICE_IP" 2>&1 || true)"
case "$save_out" in
  *"[OK]"*|*"bytes copied"*) echo "undeploy complete: $DEVICE_IP is clean and persisted" ;;
  *) echo "ERROR: cleanup succeeded but saving startup-config failed:" >&2
     printf '%s\n' "$save_out" >&2
     exit 1 ;;
esac
