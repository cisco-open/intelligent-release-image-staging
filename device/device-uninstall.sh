#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Undeploy IRIS from a Guest Shell device (Catalyst 9300 / ISR / ASR / CSR /
# C8000v): the exact inverse of device/device-install.sh, lab-validated on
# C9300 (2026-07-04). Removes ONLY the IRIS footprint:
#   - EEM applets IRIS-AGENT + IRIS-COPYROOT (FIRST, so the 60s timer can't
#     relaunch bootstrap mid-teardown)
#   - the guestshell instance (disable -> destroy) + its app-hosting config
#   - interface Vlan$VLAN + vlan $VLAN
#   - the IRISQ logging discriminator + its buffered/console/monitor
#     attachments (EXPLICIT-name no-forms — the bare forms are rejected with
#     "% Incomplete command")
#   - crypto pki trustpoint IRIS + ip http client secure-trustpoint IRIS
#   - <fs>guest-share (agent, conf, bundle, staged seeding copy)
# Deliberately LEFT IN PLACE: `iox`, `file prompt quiet`, the AppGig trunk
# (the installer re-applies all three idempotently on the next onboard), any
# staged image at flash root (a delivered artifact, never IRIS machinery),
# and staged images at the filesystem root. Successful cleanup is persisted to
# startup-config so a reload cannot restore IRIS configuration.
#
# Env (same contract as device-install.sh):
#   DEVICE_IP DEVICE_USER DEVICE_PASS [DEVICE_ENABLE] VLAN
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
VLAN_IN="${VLAN:-}"
VLAN="${VLAN:-666}"
IOS_FS="${IOS_FS:-flash:}"
IOS_ROOT="${IOS_FS}guest-share"

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
cat <<EOF
no app-hosting appid guestshell
no interface Vlan$VLAN
no vlan $VLAN
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
  echo "===== [4/5] config footprint removal ====="
  config_cleanup
  echo "===== [5/5] delete /force /recursive $IOS_ROOT ====="
   echo "===== PERSIST: copy running-config startup-config (after successful cleanup) ====="
   echo "===== LEFT IN PLACE: iox, file prompt quiet, AppGig trunk, flash-root image ====="
  exit 0
fi

: "${DEVICE_IP:?set DEVICE_IP}"; : "${DEVICE_USER:?set DEVICE_USER}"
: "${DEVICE_PASS:?set DEVICE_PASS}"
[ -n "$VLAN_IN" ] || { echo "ERROR: VLAN not set (the device's fleet row is" \
  "missing its vlan); refusing to guess — set the vlan on the device and retry" >&2; exit 1; }
RUN="$HERE/../lab/device-run.sh"

echo "[1/5] remove EEM applets on $DEVICE_IP (stops the 60s bootstrap timer)"
{ echo "configure terminal"; config_teardown; echo "end"; } | "$RUN" "$DEVICE_IP" >/dev/null

echo "[2/5] guestshell disable"
printf 'guestshell disable\n' | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
st="?"
for i in $(seq 1 30); do
  st="$(printf 'show app-hosting list\n' | "$RUN" "$DEVICE_IP" | grep -i guestshell || true)"
  case "$st" in *RUNNING*|*STOPPING*) sleep 10 ;; *) break ;; esac
done
echo "  state after disable: ${st:-<no app-hosting entry>}"

echo "[3/5] guestshell destroy"
# The trailing 'y' answers the destroy confirmation on versions that prompt;
# where none appears it is swallowed as a harmless '% Invalid input'.
printf 'guestshell destroy\ny\n' | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
for i in $(seq 1 30); do
  st="$(printf 'show app-hosting list\n' | "$RUN" "$DEVICE_IP" | grep -i guestshell || true)"
  [ -z "$st" ] && break
  sleep 10
done
if [ -n "$st" ]; then
  echo "ERROR: guestshell still present after destroy: $st" >&2; exit 1
fi
echo "  guestshell destroyed"

echo "[4/5] remove config footprint (app-hosting block, Vlan$VLAN, IRISQ, PKI trustpoint)"
{ echo "configure terminal"; config_cleanup; echo "end"; } | "$RUN" "$DEVICE_IP" >/dev/null

echo "[5/5] delete $IOS_ROOT (agent, conf, bundle, staged seeding copy)"
printf 'delete /force /recursive %s\n' "$IOS_ROOT" | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true

echo "verify: no app-hosting entry, no leftover config lines, no guest-share"
# terminal width 512 stops IOS wrapping the echoed command lines (wrap
# fragments would false-match the artifact greps below); lines carrying the
# prompt '#' are the command echoes themselves — excluded.
out="$(printf 'terminal width 512\nshow app-hosting list\nshow running-config | include applet IRIS-|interface Vlan%s|crypto pki trustpoint IRIS|discriminator IRISQ\ndir %s | include guest-share\n' \
        "$VLAN" "$IOS_FS" | "$RUN" "$DEVICE_IP" | grep -v "#" || true)"
left="$(printf '%s\n' "$out" | grep -E \
  "^guestshell|^event manager applet IRIS-|^interface Vlan$VLAN|^crypto pki trustpoint IRIS *$|IRISQ|guest-share" || true)"
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
