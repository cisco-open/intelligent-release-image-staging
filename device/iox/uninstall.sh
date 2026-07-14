#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Undeploy IRIS from a Cisco IOx app-hosting device — the inverse of
# device/iox/install.sh. IRIS runs there as an architecture-matched IOx Docker
# app (not Guest Shell), so teardown is app-hosting, not guestshell:
#   - stop -> deactivate -> uninstall the 'iris' app (frees its persist-disk)
#   - remove the app-hosting appid + the IRIS VLAN/SVI
#   - remove any IRIS-COPYROOT / IRIS-AGENT EEM applet the agent created at
#     runtime for its copy /verify (no-op if absent — IOx has no 60s timer)
#   - remove crypto pki trustpoint IRIS + ip http client secure-trustpoint IRIS
#   - delete the staged app package (<pkg-fs>iris.tar)
# Deliberately LEFT IN PLACE (the installer re-applies the first three
# idempotently; the last two are generic + a delivered artifact):
#   iox, file prompt quiet, the AppGigabitEthernet trunk, ip scp server enable,
#   the staged OS image on the selected IOS disk, and startup-config (never
#   written here).
#
# Env (subset of the installer's, supplied by OnboardService._build_env):
#   DEVICE_IP DEVICE_USER DEVICE_PASS [DEVICE_ENABLE] [VLAN=666]
#   [PKG=iris.tar] [PKG_FS=flash:]
# Usage:  iox/uninstall.sh [--dry-run]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

# VLAN_IN preserves whether a VLAN was actually supplied; the 666 default is
# ONLY for --dry-run text. A real run re-requires a non-empty VLAN below, so we
# never tear down the wrong SVI/VLAN and then falsely verify clean.
VLAN_IN="${VLAN:-}"
VLAN="${VLAN:-666}"
PKG="${PKG:-iris.tar}"; PKG_FS="${PKG_FS:-flash:}"
APPID=iris

config_cleanup() {
# Every EEM applet the SHARED agent may have created (the IOx agent runs the
# same reclaim/copy-root code as Guest Shell over its SSH-to-self CLI): the
# copy-to-root applet and the on-demand low-space reclaim applets, which the
# agent never self-removes. IRIS-AGENT won't exist on IOx (no 60s timer) but
# the no-op is harmless. All no-ops if absent.
cat <<EOF
no app-hosting appid $APPID
no event manager applet IRIS-AGENT
no event manager applet IRIS-COPYROOT
no event manager applet IRIS-RECLAIM
no event manager applet IRIS-RECLAIM-BUNDLE
no interface Vlan$VLAN
no vlan $VLAN
no ip http client secure-trustpoint IRIS
no crypto pki trustpoint IRIS
yes
EOF
}

if [ "$DRY" -eq 1 ]; then
  echo "===== [1/4] app-hosting stop -> deactivate -> uninstall '$APPID' ====="
  printf 'app-hosting stop appid %s\napp-hosting deactivate appid %s\napp-hosting uninstall appid %s\n' \
    "$APPID" "$APPID" "$APPID"
  echo "===== [2/4] remove config footprint (appid, VLAN$VLAN, applets, trustpoint) ====="
  config_cleanup
  echo "===== [3/4] delete ${PKG_FS}${PKG} ====="
  echo "===== [4/4] verify no '$APPID' app / config footprint remains ====="
  echo "===== LEFT IN PLACE: iox, file prompt quiet, AppGig trunk, ip scp server, sdflash image ====="
  exit 0
fi

: "${DEVICE_IP:?set DEVICE_IP}"; : "${DEVICE_USER:?set DEVICE_USER}"
: "${DEVICE_PASS:?set DEVICE_PASS}"
[ -n "$VLAN_IN" ] || { echo "ERROR: VLAN not set (the device's fleet row is" \
  "missing its vlan); refusing to guess — set the vlan on the device and retry" >&2; exit 1; }
RUN() { "$HERE/../../lab/device-run.sh" "$DEVICE_IP"; }
app_state() { printf 'show app-hosting list\n' | RUN 2>/dev/null | awk -v a="$APPID" '$1==a{print $2}'; }

echo "[1/4] app-hosting stop -> deactivate -> uninstall '$APPID' on $DEVICE_IP"
# Idempotent + order-tolerant: each step is a no-op (harmless error, swallowed)
# if the app is already past that state. uninstall frees the app's persist-disk.
printf 'app-hosting stop appid %s\n' "$APPID" | RUN >/dev/null 2>&1 || true
sleep 4
printf 'app-hosting deactivate appid %s\n' "$APPID" | RUN >/dev/null 2>&1 || true
sleep 4
printf 'app-hosting uninstall appid %s\n' "$APPID" | RUN >/dev/null 2>&1 || true
# Poll until the app-hosting entry is gone (uninstall is async).
for i in $(seq 1 24); do
  [ -z "$(app_state)" ] && break
  sleep 5
done
st="$(app_state)"
[ -z "$st" ] || echo "  WARN: '$APPID' still shows state '$st' after uninstall"

echo "[2/4] remove config footprint (appid, Vlan$VLAN, EEM applets, PKI trustpoint)"
{ echo "configure terminal"; config_cleanup; echo "end"; } | RUN >/dev/null

echo "[3/4] delete ${PKG_FS}${PKG} (the staged IOx app package)"
printf 'delete /force %s%s\n' "$PKG_FS" "$PKG" | RUN >/dev/null 2>&1 || true

echo "[4/4] verify no '$APPID' app and no config footprint remains"
out="$(printf 'terminal width 512\nshow app-hosting list\nshow running-config | include app-hosting appid %s|applet IRIS-|interface Vlan%s|crypto pki trustpoint IRIS\n' \
        "$APPID" "$VLAN" | RUN | grep -v "#" || true)"
left="$(printf '%s\n' "$out" | grep -E \
  "^$APPID |^app-hosting appid $APPID|^event manager applet IRIS-|^interface Vlan$VLAN|^crypto pki trustpoint IRIS *$" || true)"
if [ -n "$left" ]; then
  echo "ERROR: artifacts still present after undeploy:" >&2
  printf '%s\n' "$left" >&2
  exit 1
fi
echo "undeploy complete: $DEVICE_IP is clean (iox/scp/trunk/sdflash image left for the next onboard)"
