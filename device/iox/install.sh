#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Repeatable IRIS installer for the Catalyst IE-3x00, which CANNOT run Guest Shell
# (removed from IOS-XE >=17.9). It deploys the agent as an aarch64 IOx Docker app
# (iris.tar) instead of into Guest Shell, but uses the SAME transport as
# device/device-install.sh: push the IRIS PKI trustpoint over SSH FIRST, then
# `copy https://STAGE_HOST:8000/<pkg>` from the always-on container artifact
# server (no throwaway HTTP server). The agent then pulls its assigned image over
# the swarm and copies it to sdflash: (IOS-visible) via `copy /verify` — the
# IE3x00 analog of the C9300 placing its image on flash:. Distribute/stage ONLY;
# never install/activate/reload the IOS image.
#
# Idempotent: re-running tears down any existing iris app and redeploys (cert
# rotation, fresh package, fresh token) — safe to run repeatedly.
#
# Required env:
#   DEVICE_IP VLAN SVI_IP SVI_MASK GUEST_IP CATALOG_TOKEN DEVICE_ID STAGE_HOST
#   DEVICE_SSH_PASS  — the device login the container uses for its SSH-to-self CLI
#   IRIS_CRT_FILE    — local path to the server's BARE cert (crt.pem) for the
#                      trustpoint + the preflight --cacert (the generator supplies it)
#   DEVICE_USER (+ DEVICE_PASS) — for lab/device-run.sh; export or 'source' creds/
# Optional (defaults):
#   CATALOG_URL=https://STAGE_HOST:8443  APP_INTF=AppGigabitEthernet1/1
#   GW_IP=$SVI_IP  CPU=400  MEM=768  DISK=2048  PKG=iris.tar  PKG_FS=flash:
#   DEVICE_SSH_USER=dnac  PKG_FS=flash:
set -euo pipefail

: "${DEVICE_IP:?set DEVICE_IP}"; : "${VLAN:?set VLAN}"
: "${SVI_IP:?set SVI_IP}"; : "${SVI_MASK:?set SVI_MASK}"; : "${GUEST_IP:?set GUEST_IP}"
: "${CATALOG_TOKEN:?set CATALOG_TOKEN}"; : "${DEVICE_ID:?set DEVICE_ID}"
: "${STAGE_HOST:?set STAGE_HOST}"; : "${DEVICE_SSH_PASS:?set DEVICE_SSH_PASS}"
: "${IRIS_CRT_FILE:?set IRIS_CRT_FILE — local path to the bare server cert crt.pem}"
[ -r "$IRIS_CRT_FILE" ] || { echo "ERROR: IRIS_CRT_FILE=$IRIS_CRT_FILE not readable" >&2; exit 1; }

CATALOG_URL="${CATALOG_URL:-https://$STAGE_HOST:8443}"
APP_INTF="${APP_INTF:-AppGigabitEthernet1/1}"
GW_IP="${GW_IP:-$SVI_IP}"
CPU="${CPU:-400}"; MEM="${MEM:-768}"; DISK="${DISK:-2048}"
PKG="${PKG:-iris.tar}"; PKG_FS="${PKG_FS:-flash:}"
DEVICE_SSH_USER="${DEVICE_SSH_USER:-dnac}"
APPID=iris
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN() { "$HERE/../../lab/device-run.sh" "$DEVICE_IP"; }   # IOS cmds on stdin

# --- the PKI trustpoint that lets `copy https:` validate the self-signed cert ---
# (identical idiom to device/device-install.sh: no-then-re-add, paste the BARE
# crt.pem, answer the two yes/no prompts; non-circular — trust rides the SSH we
# already have, bulk transfer rides the HTTPS it authorizes.)
trustpoint_block() {
  echo "no crypto pki trustpoint IRIS"; echo "yes"
  echo "crypto pki trustpoint IRIS"
  echo " enrollment terminal"; echo " revocation-check none"; echo "exit"
  echo "crypto pki authenticate IRIS"
  cat "$IRIS_CRT_FILE"
  echo "quit"; echo "yes"
  echo "ip http client secure-trustpoint IRIS"
}

ios_net() {           # networking + IOx enable (idempotent)
cat <<EOF
iox
!
vlan $VLAN
!
interface $APP_INTF
 switchport mode trunk
 switchport trunk allowed vlan $VLAN
!
interface Vlan$VLAN
 description IRIS IOx app inline
 ip address $SVI_IP $SVI_MASK
 no shutdown
!
file prompt quiet
!
! SCP server: the IOx-app agent scp-pushes its downloaded scratch to sdflash:
! (it can't bind-mount sdflash: nor receive inbound), then copy /verify places it.
ip scp server enable
!
end
EOF
}

appid_block() {       # app-hosting appid (NO explicit exit lines — IOS auto-pops,
cat <<EOF
app-hosting appid $APPID
 app-vnic AppGigabitEthernet trunk
  vlan $VLAN guest-interface 0
   guest-ipaddress $GUEST_IP netmask $SVI_MASK
 app-default-gateway $GW_IP guest-interface 0
 app-resource profile custom
  cpu $CPU
  memory $MEM
  persist-disk $DISK
  vcpu 1
 app-resource docker
  run-opts 1 "-e IRIS_DEVICE_ID=$DEVICE_ID -e IRIS_DEVICE_SSH_PASS=$DEVICE_SSH_PASS -e IRIS_CATALOG_TOKEN=$CATALOG_TOKEN -e IRIS_CATALOG_URL=$CATALOG_URL -e IRIS_DEVICE_SSH_HOST=$SVI_IP -e IRIS_DEVICE_SSH_USER=$DEVICE_SSH_USER${IRIS_TELEMETRY:+ -e IRIS_TELEMETRY=$IRIS_TELEMETRY}"
end
EOF
}

app_state() { printf 'show app-hosting list\n' | RUN 2>/dev/null | awk -v a="$APPID" '$1==a{print $2}'; }
wait_state() {  # $1=target state, $2=timeout_s
  local t=0; while [ "$t" -lt "$2" ]; do sleep 5; t=$((t+5));
    local s; s="$(app_state)"; echo "    [$t s] $APPID=$s";
    [ "$s" = "$1" ] && return 0; done; return 1; }

echo "[1/8] teardown any existing '$APPID' app (idempotent re-install)"
printf 'app-hosting stop appid %s\napp-hosting deactivate appid %s\napp-hosting uninstall appid %s\n' \
  "$APPID" "$APPID" "$APPID" | RUN >/dev/null 2>&1 || true
sleep 6
printf 'configure terminal\nno app-hosting appid %s\nend\n' "$APPID" | RUN >/dev/null 2>&1 || true

echo "[2/8] apply IOx networking (IOx enable, VLAN $VLAN, $APP_INTF, Vlan$VLAN SVI)"
{ echo "configure terminal"; ios_net; } | RUN >/dev/null

echo "[3/8] disable app-hosting signature verification (EXEC)"
printf 'app-hosting verification disable\n' | RUN 2>/dev/null | grep -i 'signature' || true

echo "[4/8] push PKI trustpoint over SSH (so 'copy https:' validates the server cert)"
{ echo "configure terminal"; trustpoint_block; echo "end"; } | RUN >/dev/null

echo "[5/8] preflight: is https://$STAGE_HOST:8000/$PKG reachable? (HEAD, advisory)"
# HEAD only (-I) so we don't pull the whole package; -k because the DEVICE (not us)
# validates the cert against the trustpoint we just pasted. Advisory: a flaky
# operator->server link must not block a deploy the DEVICE can complete — the
# device copy below is the authoritative gate (with retries).
if curl -skf -I --max-time 8 "https://$STAGE_HOST:8000/$PKG" >/dev/null 2>&1; then
  echo "    reachable (HTTP HEAD ok)"
else
  echo "    WARN: preflight inconclusive from here; relying on the device copy"
fi

echo "[6/8] copy $PKG -> ${PKG_FS} over verified https (retry x3)"
printf 'delete /force %s%s\n' "$PKG_FS" "$PKG" | RUN >/dev/null 2>&1 || true
ok=0
for a in 1 2 3; do
  out="$(printf 'copy https://%s:8000/%s %s%s\n' "$STAGE_HOST" "$PKG" "$PKG_FS" "$PKG" | RUN 2>/dev/null || true)"
  case "$out" in *"bytes copied"*) ok=1; break ;; esac
  echo "    copy attempt $a/3 failed; retrying"; sleep 8
done
[ "$ok" -eq 1 ] || { echo "  ERROR: copy of $PKG failed after 3 attempts" >&2; exit 1; }

echo "[7/8] configure app-hosting appid $APPID + install/activate/start"
{ echo "configure terminal"; appid_block; } | RUN >/dev/null
printf 'app-hosting install appid %s package %s%s\n' "$APPID" "$PKG_FS" "$PKG" | RUN >/dev/null 2>&1
wait_state DEPLOYED 120 || { echo "  ERROR: install did not reach DEPLOYED" >&2; exit 1; }
sleep 8                                       # let the install op fully settle
printf 'app-hosting activate appid %s\n' "$APPID" | RUN >/dev/null 2>&1
wait_state ACTIVATED 90 || { echo "  ERROR: activate failed" >&2; exit 1; }
printf 'app-hosting start appid %s\n' "$APPID" | RUN >/dev/null 2>&1
wait_state RUNNING 90 || { echo "  ERROR: start did not reach RUNNING" >&2; exit 1; }

echo "[8/8] $APPID RUNNING. The agent refreshes its token, downloads $DEVICE_ID's"
echo "      assigned image over the swarm, and copies it to sdflash: via copy /verify."
echo "      Watch:  printf 'dir sdflash:\\n' | lab/device-run.sh $DEVICE_IP"
echo "      Swarm:  https://$STAGE_HOST:8080/  (Console -> Swarm tab)"
