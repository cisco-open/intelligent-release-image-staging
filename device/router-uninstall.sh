#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Receipt-driven inverse of router-install.sh. Staged images at bootflash: root
# are deliberately preserved.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1
NETWORK_ATTACHMENT="${NETWORK_ATTACHMENT:-router-routed}"
VPG_NUMBER="${VPG_NUMBER:-}"
NAT_INTERFACE="${NAT_INTERFACE:-}"
BT_LISTEN_PORT="${BT_LISTEN_PORT:-6881}"
NAT_OUTSIDE_OWNED="${NAT_OUTSIDE_OWNED:-0}"
ROUTER_RESOURCES_OWNED="${ROUTER_RESOURCES_OWNED:-0}"
APP_IP="${APP_IP:-}"
IOS_ROOT="bootflash:guest-share"
IRIS_DIR="$IOS_ROOT/iris"

case "$NETWORK_ATTACHMENT" in
  router-routed) ;;
  router-nat) [ -n "$NAT_INTERFACE" ] && [ -n "$APP_IP" ] \
    || { echo "ERROR: router-nat receipt is missing NAT_INTERFACE or APP_IP" >&2; exit 1; } ;;
  *) echo "ERROR: NETWORK_ATTACHMENT must be router-routed or router-nat" >&2; exit 1 ;;
esac
[[ "$VPG_NUMBER" =~ ^[0-9]+$ ]] && [ "$VPG_NUMBER" -ge 0 ] \
  && [ "$VPG_NUMBER" -le 31 ] \
  || { echo "ERROR: receipt is missing a valid VPG_NUMBER" >&2; exit 1; }
if [ -n "$NAT_INTERFACE" ] && ! [[ "$NAT_INTERFACE" =~ ^[A-Za-z][A-Za-z0-9./_-]{0,63}$ ]]; then
  echo "ERROR: NAT_INTERFACE contains unsupported characters" >&2; exit 1
fi

MODEL="${MODEL:-}"
EXPECTED_DEVICE_IDENTITY="${EXPECTED_DEVICE_IDENTITY:-}"
if [ "$DRY" -eq 0 ]; then
  : "${DEVICE_IP:?set DEVICE_IP}"; : "${DEVICE_USER:?set DEVICE_USER}"
  : "${DEVICE_PASS:?set DEVICE_PASS}"
  : "${EXPECTED_DEVICE_IDENTITY:?set EXPECTED_DEVICE_IDENTITY from the deployment receipt}"
  [ "$ROUTER_RESOURCES_OWNED" = "1" ] \
    || { echo "ERROR: receipt does not prove ownership of router resources" >&2; exit 1; }
  VERSION_OUT="$(printf 'show version\n' \
    | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null)"
  LIVE_MODEL="$(printf '%s\n' "$VERSION_OUT" \
    | sed -nE 's/^cisco[[:space:]]+([^[:space:]]+)[[:space:]]+\(.*/\1/p' | head -1)"
  LIVE_IDENTITY="$(printf '%s\n' "$VERSION_OUT" \
    | sed -nE 's/^[Pp]rocessor board ID[[:space:]]+([^[:space:]]+).*/\1/p' | head -1)"
  [ -n "$LIVE_IDENTITY" ] && [ "$LIVE_IDENTITY" = "$EXPECTED_DEVICE_IDENTITY" ] \
    || { echo "ERROR: device identity mismatch; refusing to modify $DEVICE_IP" >&2; exit 1; }
  MODEL="$LIVE_MODEL"
fi
case "$(printf '%s' "$MODEL" | tr 'a-z' 'A-Z')" in
  C8[0-9][0-9][0-9]*) ;;
  *) echo "ERROR: router recipe supports Catalyst 8000-family models only; detected '${MODEL:-unknown}'" >&2
     exit 1 ;;
esac

if [ "$NETWORK_ATTACHMENT" = "router-nat" ]; then
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
no event manager applet IRIS-RECLAIM
no event manager applet IRIS-RECLAIM-BUNDLE
EOF
}

config_cleanup() {
cat <<EOF
no app-hosting appid guestshell
EOF
if [ "$NETWORK_ATTACHMENT" = "router-nat" ]; then
cat <<EOF
no ip nat inside source static tcp $APP_IP $BT_LISTEN_PORT interface $NAT_INTERFACE $BT_LISTEN_PORT
no ip nat inside source list IRIS-NAT-$VPG_NUMBER interface $NAT_INTERFACE overload
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
  echo "===== [4/5] receipt-owned config removal ====="
  [ "$NETWORK_ATTACHMENT" = "router-nat" ] && echo "clear ip nat translation *"
  config_cleanup
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

echo "[4/5] remove receipt-owned VPG and NAT footprint"
# IOS refuses to unconfigure a dynamic NAT mapping while translations still
# reference it. config_cleanup drops IRIS-NAT-$VPG_NUMBER on the line after the
# overload no-form, so a refusal there would strip the ACL out from under a
# surviving rule and leave a dangling reference that the [5/5] verify then
# rejects. The app is destroyed by [3/5], so any remaining translations are
# stale and safe to flush.
if [ "$NETWORK_ATTACHMENT" = "router-nat" ]; then
  printf 'clear ip nat translation *\n' | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true
fi
{ echo "configure terminal"; config_cleanup; echo "end"; } | "$RUN" "$DEVICE_IP" >/dev/null

echo "[5/5] remove IRIS files under $IOS_ROOT (preserve the platform directory)"
{
  printf 'delete /force /recursive %s\n' "$IRIS_DIR"
  for name in bootstrap.sh iris-agent.conf rpc-secret bundle.tgz iris-catalog.pem; do
    printf 'delete /force %s/%s\n' "$IOS_ROOT" "$name"
  done
} | "$RUN" "$DEVICE_IP" >/dev/null 2>&1 || true

RUNNING="$(printf 'terminal width 512\nshow running-config\n' \
  | "$RUN" "$DEVICE_IP" | grep -v '#' || true)"
config_block() {
  python3 -c 'import re,sys
name = re.escape(sys.argv[1])
text = sys.stdin.read()
match = re.search(r"(?ms)^interface %s\s*$\n(.*?)(?=^!\s*$|^interface |^end\s*$|\Z)" % name, text)
print(match.group(0) if match else "")' "$1"
}
APP_STATE="$(printf 'show app-hosting list\n' \
  | "$RUN" "$DEVICE_IP" | grep -v '#' || true)"
FILES="$(printf 'dir bootflash:guest-share\ndir bootflash:guest-share/iris\n' \
  | "$RUN" "$DEVICE_IP" | grep -v '#' || true)"

forbidden=""
for artifact in \
  "interface VirtualPortGroup$VPG_NUMBER" \
  "app-hosting appid guestshell" \
  "event manager applet IRIS-" \
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

if [ "$NETWORK_ATTACHMENT" = "router-nat" ]; then
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
