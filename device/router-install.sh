#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Onboard a Catalyst 8000-family router through a VirtualPortGroup. IRIS stages
# images only; this script never installs, activates, reloads, or changes boot.
set -euo pipefail

: "${DEVICE_IP:?set DEVICE_IP}"
: "${CATALOG_URL:?set CATALOG_URL}"; : "${CATALOG_TOKEN:?set CATALOG_TOKEN}"
: "${DEVICE_ID:?set DEVICE_ID}"; : "${STAGE_HOST:?set STAGE_HOST}"
: "${VPG_NUMBER:?set VPG_NUMBER}"; : "${APP_IP:?set APP_IP}"
: "${APP_MASK:?set APP_MASK}"; : "${APP_GATEWAY:?set APP_GATEWAY}"

NETWORK_ATTACHMENT="${NETWORK_ATTACHMENT:-router-routed}"
case "$NETWORK_ATTACHMENT" in
  router-routed) NAT_INTERFACE="" ;;
  router-nat) : "${NAT_INTERFACE:?set NAT_INTERFACE}" ;;
  *) echo "ERROR: NETWORK_ATTACHMENT must be router-routed or router-nat" >&2; exit 1 ;;
esac
[[ "$VPG_NUMBER" =~ ^[0-9]+$ ]] && [ "$VPG_NUMBER" -ge 0 ] \
  && [ "$VPG_NUMBER" -le 31 ] \
  || { echo "ERROR: VPG_NUMBER must be between 0 and 31" >&2; exit 1; }
if [ -n "$NAT_INTERFACE" ] && ! [[ "$NAT_INTERFACE" =~ ^[A-Za-z][A-Za-z0-9./_-]{0,63}$ ]]; then
  echo "ERROR: NAT_INTERFACE contains unsupported characters" >&2; exit 1
fi

BT_LISTEN_PORT="${BT_LISTEN_PORT:-6881}"
[[ "$BT_LISTEN_PORT" =~ ^[0-9]+$ ]] && [ "$BT_LISTEN_PORT" -ge 1 ] \
  && [ "$BT_LISTEN_PORT" -le 65535 ] \
  || { echo "ERROR: BT_LISTEN_PORT must be between 1 and 65535" >&2; exit 1; }

RPC_SECRET=""
CPU="${CPU:-1110}"; MEM="${MEM:-512}"; PERSIST="${PERSIST:-256}"
HOST_USER="${HOST_USER:-}"; HOST_PASS="${HOST_PASS:-}"
BUNDLE="iris-agent.tgz"
IOS_ROOT="bootflash:guest-share"
IOS_STAGE="bootflash:guest-share/iris"
STAGE="/bootflash/guest-share/iris"
CATALOG_CA="$STAGE/iris-catalog.pem"
IRIS_CRT_FILE="${IRIS_CRT_FILE:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

MODEL="${MODEL:-}"
EXPECTED_DEVICE_IDENTITY="${EXPECTED_DEVICE_IDENTITY:-}"
if [ "$DRY" -eq 0 ]; then
  : "${EXPECTED_DEVICE_IDENTITY:?set EXPECTED_DEVICE_IDENTITY from the deployment receipt}"
  VERSION_OUT="$(printf 'show version\n' \
    | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null)"
  LIVE_MODEL="$(printf '%s\n' "$VERSION_OUT" \
    | sed -nE 's/^cisco[[:space:]]+([^[:space:]]+)[[:space:]]+\(.*/\1/p' | head -1)"
  LIVE_IDENTITY="$(printf '%s\n' "$VERSION_OUT" \
    | sed -nE 's/^[Pp]rocessor board ID[[:space:]]+([^[:space:]]+).*/\1/p' | head -1)"
  [ -n "$LIVE_IDENTITY" ] && [ "$LIVE_IDENTITY" = "$EXPECTED_DEVICE_IDENTITY" ] \
    || { echo "ERROR: device identity mismatch; refusing to configure $DEVICE_IP" >&2; exit 1; }
  MODEL="$LIVE_MODEL"
fi
case "$(printf '%s' "$MODEL" | tr 'a-z' 'A-Z')" in
  C8[0-9][0-9][0-9]*) ;;
  *) echo "ERROR: router recipe supports Catalyst 8000-family models only; detected '${MODEL:-unknown}'" >&2
     exit 1 ;;
esac

network_values="$(python3 - "$APP_IP" "$APP_MASK" "$APP_GATEWAY" <<'PY'
import ipaddress
import sys

try:
    app = ipaddress.IPv4Address(sys.argv[1])
    network = ipaddress.IPv4Network("%s/%s" % (app, sys.argv[2]), strict=False)
    gateway = ipaddress.IPv4Address(sys.argv[3])
except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
    raise SystemExit("ERROR: invalid APP_IP, APP_MASK, or APP_GATEWAY: %s" % exc)
if gateway not in network or app == gateway:
    raise SystemExit("ERROR: APP_IP and APP_GATEWAY must differ and share a subnet")
print(network.network_address)
print(network.hostmask)
PY
)"
APP_SUBNET="${network_values%%$'\n'*}"
APP_WILDCARD="${network_values##*$'\n'}"

ios_config() {
cat <<EOF
iox
!
interface VirtualPortGroup$VPG_NUMBER
 description IRIS Guest Shell VPG
 ip address $APP_GATEWAY $APP_MASK
EOF
if [ "$NETWORK_ATTACHMENT" = "router-nat" ]; then
cat <<EOF
 ip nat inside
EOF
fi
cat <<EOF
 no shutdown
!
EOF
if [ "$NETWORK_ATTACHMENT" = "router-nat" ]; then
cat <<EOF
interface $NAT_INTERFACE
 ip nat outside
!
ip access-list standard IRIS-NAT-$VPG_NUMBER
 permit $APP_SUBNET $APP_WILDCARD
!
ip nat inside source list IRIS-NAT-$VPG_NUMBER interface $NAT_INTERFACE overload
ip nat inside source static tcp $APP_IP $BT_LISTEN_PORT interface $NAT_INTERFACE $BT_LISTEN_PORT
!
EOF
fi
cat <<EOF
app-hosting appid guestshell
 app-vnic gateway0 virtualportgroup $VPG_NUMBER guest-interface 0
  guest-ipaddress $APP_IP netmask $APP_MASK
 app-default-gateway $APP_GATEWAY guest-interface 0
 app-resource profile custom
  cpu $CPU
  memory $MEM
  persist-disk $PERSIST
!
file prompt quiet
!
logging discriminator IRISQ mnemonics drops IOX_INST_WARN
logging buffered discriminator IRISQ
logging console discriminator IRISQ
logging monitor discriminator IRISQ
!
event manager applet IRIS-AGENT authorization bypass
 event timer watchdog time 60 maxrun 900
 action 100 cli command "enable"
 action 200 cli command "guestshell run env BT_LISTEN_PORT=$BT_LISTEN_PORT bash /bootflash/guest-share/bootstrap.sh"
!
end
EOF
}

agent_conf() {
cat <<EOF
catalog_url = $CATALOG_URL
catalog_token = $CATALOG_TOKEN
device_id = $DEVICE_ID
stage_dir = $STAGE
target_fs = bootflash:
rpc_secret = $RPC_SECRET
catalog_ca = $CATALOG_CA
telemetry = ${TELEMETRY:-on}
token_expires_at = 0
agent_version = $(cat "$HERE/../VERSION" 2>/dev/null || echo unknown)
EOF
}

trustpoint_block() {
  echo "no crypto pki trustpoint IRIS"
  echo "yes"
  echo "crypto pki trustpoint IRIS"
  echo " enrollment terminal"
  echo " revocation-check none"
  echo "exit"
  echo "crypto pki authenticate IRIS"
  if [ -n "$IRIS_CRT_FILE" ] && [ -r "$IRIS_CRT_FILE" ]; then
    cat "$IRIS_CRT_FILE"
  else
    echo "! <contents of \$IRIS_CRT_FILE inserted here at apply time>"
  fi
  echo "quit"
  echo "yes"
  echo "ip http client secure-trustpoint IRIS"
}

if [ "$DRY" -eq 1 ]; then
  echo "===== IOS CONFIG ====="; ios_config
  echo "===== PKI TRUSTPOINT ====="; trustpoint_block
  echo "===== AGENT CONFIG ====="; agent_conf
  echo "===== INSTALL COPIES ====="
  for pair in "bootstrap.sh:bootstrap.sh" "staging/iris-agent-$DEVICE_ID.conf:iris-agent.conf" \
              "staging/rpc-secret:rpc-secret" "$BUNDLE:bundle.tgz" \
              "iris-catalog.pem:iris-catalog.pem"; do
    src="${pair%%:*}"; dst="${pair##*:}"
    printf 'copy https://%s:8000/%s %s/%s\n' "$STAGE_HOST" "$src" "$IOS_ROOT" "$dst"
  done
  echo "===== guestshell enable ====="
  echo "===== PERSIST: copy running-config startup-config ====="
  exit 0
fi

ssh_host() {
  SSHPASS="$HOST_PASS" sshpass -e ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$HOST_USER@$STAGE_HOST" "$@"
}

echo "[1/7] bootflash pre-check on $DEVICE_IP"
printf 'dir bootflash: | include bytes free\n' | "$HERE/../lab/device-run.sh" "$DEVICE_IP" \
  | grep -i 'bytes free' || true

echo "[2/7] stage per-device agent config into artifacts/"
CONF="iris-agent-$DEVICE_ID.conf"
ART="${IRIS_ARTIFACTS_DIR:-$(cd "$HERE/.." && pwd)/artifacts}"
: "${IRIS_CRT_FILE:?set IRIS_CRT_FILE to the bare server cert crt.pem}"
[ -r "$IRIS_CRT_FILE" ] \
  || { echo "ERROR: IRIS_CRT_FILE=$IRIS_CRT_FILE is not readable" >&2; exit 1; }
if [ "${IRIS_STAGE_LOCAL:-0}" = "1" ] \
    || ip -o addr 2>/dev/null | grep -qw "$STAGE_HOST" \
    || [ "$STAGE_HOST" = "localhost" ]; then
  mkdir -p "$ART/staging"
  agent_conf > "$ART/staging/$CONF"
  printf '%s\n' "$RPC_SECRET" > "$ART/staging/rpc-secret"
  [ -e "$ART/bootstrap.sh" ] || cp "$HERE/bootstrap.sh" "$ART/bootstrap.sh"
  [ -e "$ART/iris-catalog.pem" ] || cp "$IRIS_CRT_FILE" "$ART/iris-catalog.pem"
else
  : "${HOST_USER:?set HOST_USER for remote STAGE_HOST $STAGE_HOST}"
  : "${HOST_PASS:?set HOST_PASS for remote STAGE_HOST $STAGE_HOST}"
  agent_conf | ssh_host "mkdir -p ~/iris/artifacts/staging && cat > ~/iris/artifacts/staging/$CONF && printf '%s\\n' '$RPC_SECRET' > ~/iris/artifacts/staging/rpc-secret"
  ssh_host "cat > ~/iris/artifacts/iris-catalog.pem" < "$IRIS_CRT_FILE"
fi

echo "[3/7] apply IOS config ($NETWORK_ATTACHMENT VirtualPortGroup)"
{ echo "configure terminal"; ios_config; } \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null
printf 'mkdir %s\n\n' "$IOS_ROOT" \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true

echo "[4/7] guestshell enable"
for i in $(seq 1 30); do
  state="$(printf 'show app-hosting list\n' \
    | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null \
    | grep -i guestshell || true)"
  case "$state" in *RUNNING*) echo "  guestshell RUNNING"; break ;; esac
  if [ $(((i - 1) % 5)) -eq 0 ]; then
    printf 'guestshell enable\n' \
      | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true
  fi
  [ "$i" -ne 30 ] \
    || { echo "ERROR: guestshell not RUNNING after ~7 minutes" >&2; exit 1; }
  sleep 15
done

echo "[5/7] install trustpoint and copy agent artifacts over verified HTTPS"
{ echo "configure terminal"; trustpoint_block; echo "end"; } \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null
if ! curl -sf -o /dev/null --max-time 5 --cacert "$IRIS_CRT_FILE" \
    "https://$STAGE_HOST:8000/bootstrap.sh"; then
  echo "ERROR: artifact server is unreachable or untrusted" >&2; exit 1
fi
printf 'delete /force /recursive %s\n' "$IOS_STAGE" \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true
for pair in "bootstrap.sh:bootstrap.sh" "staging/$CONF:iris-agent.conf" \
            "staging/rpc-secret:rpc-secret" "$BUNDLE:bundle.tgz" \
            "iris-catalog.pem:iris-catalog.pem"; do
  src="${pair%%:*}"; dst="${pair##*:}"; ok=0
  for attempt in 1 2 3; do
    out="$(printf 'copy https://%s:8000/%s %s/%s\n' \
      "$STAGE_HOST" "$src" "$IOS_ROOT" "$dst" \
      | "$HERE/../lab/device-run.sh" "$DEVICE_IP" || true)"
    case "$out" in *"bytes copied"*) ok=1; break ;; esac
    echo "  copy of $src failed (attempt $attempt/3), retrying..."; sleep 10
  done
  [ "$ok" -eq 1 ] \
    || { echo "ERROR: copy of $src failed after 3 attempts" >&2; exit 1; }
done

echo "[6/7] verify applied config and persist to startup-config"
RUN="$HERE/../lab/device-run.sh"
RUNNING="$(printf 'terminal width 512\nshow running-config\n' \
  | "$RUN" "$DEVICE_IP" | grep -v '#' || true)"
config_block() {
  python3 -c 'import re,sys
name = re.escape(sys.argv[1])
text = sys.stdin.read()
match = re.search(r"(?ms)^interface %s\s*$\n(.*?)(?=^!\s*$|^interface |^end\s*$|\Z)" % name, text)
print(match.group(0) if match else "")' "$1"
}
VPG_RUNNING="$(printf '%s\n' "$RUNNING" | config_block "VirtualPortGroup$VPG_NUMBER")"
APP_STATE="$(printf 'show app-hosting list\n' \
  | "$RUN" "$DEVICE_IP" | grep -v '#' || true)"
FILES="$(printf 'dir bootflash:guest-share\ndir bootflash:guest-share/iris\n' \
  | "$RUN" "$DEVICE_IP" | grep -v '#' || true)"

require_text() {
  local text="$1" expected="$2" description="$3"
  case "$text" in
    *"$expected"*) ;;
    *) echo "ERROR: applied-config verification missing $description" >&2; return 1 ;;
  esac
}

verify_failed=0
require_text "$VPG_RUNNING" "interface VirtualPortGroup$VPG_NUMBER" \
  "VirtualPortGroup$VPG_NUMBER" || verify_failed=1
require_text "$VPG_RUNNING" "ip address $APP_GATEWAY $APP_MASK" \
  "the VPG address" || verify_failed=1
require_text "$RUNNING" "app-hosting appid guestshell" \
  "Guest Shell app-hosting config" || verify_failed=1
require_text "$RUNNING" "app-vnic gateway0 virtualportgroup $VPG_NUMBER guest-interface 0" \
  "the VPG app-vnic" || verify_failed=1
require_text "$RUNNING" "guest-ipaddress $APP_IP netmask $APP_MASK" \
  "the Guest Shell address" || verify_failed=1
require_text "$RUNNING" "event manager applet IRIS-AGENT authorization bypass" \
  "the IRIS-AGENT applet" || verify_failed=1
require_text "$RUNNING" "logging discriminator IRISQ" \
  "the IRISQ logging discriminator" || verify_failed=1
require_text "$RUNNING" "crypto pki trustpoint IRIS" \
  "the IRIS trustpoint" || verify_failed=1
require_text "$RUNNING" "ip http client secure-trustpoint IRIS" \
  "the HTTP client trustpoint binding" || verify_failed=1
require_text "$RUNNING" "file prompt quiet" "file prompt quiet" || verify_failed=1
require_text "$APP_STATE" "guestshell" "the running Guest Shell instance" || verify_failed=1
require_text "$APP_STATE" "RUNNING" "Guest Shell RUNNING state" || verify_failed=1
require_text "$FILES" "bootstrap.sh" "bootflash:guest-share/bootstrap.sh" || verify_failed=1
require_text "$FILES" "iris-agent.conf" "the staged agent config" || verify_failed=1

if [ "$NETWORK_ATTACHMENT" = "router-nat" ]; then
  OUTSIDE_RUNNING="$(printf '%s\n' "$RUNNING" | config_block "$NAT_INTERFACE")"
  require_text "$VPG_RUNNING" "ip nat inside" "the VPG NAT-inside marking" \
    || verify_failed=1
  require_text "$OUTSIDE_RUNNING" "ip nat outside" "the NAT-outside marking" \
    || verify_failed=1
  require_text "$RUNNING" "ip access-list standard IRIS-NAT-$VPG_NUMBER" \
    "the IRIS NAT ACL" || verify_failed=1
  require_text "$RUNNING" "permit $APP_SUBNET $APP_WILDCARD" \
    "the IRIS NAT ACL permit" || verify_failed=1
  require_text "$RUNNING" \
    "ip nat inside source list IRIS-NAT-$VPG_NUMBER interface $NAT_INTERFACE overload" \
    "the NAT overload rule" || verify_failed=1
  require_text "$RUNNING" \
    "ip nat inside source static tcp $APP_IP $BT_LISTEN_PORT interface $NAT_INTERFACE $BT_LISTEN_PORT" \
    "the inbound swarm PAT" || verify_failed=1
fi
[ "$verify_failed" -eq 0 ] \
  || { echo "ERROR: router configuration is incomplete; refusing to mark onboarding successful" >&2; exit 1; }

save_out="$(printf 'copy running-config startup-config\n' \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>&1 || true)"
case "$save_out" in
  *"[OK]"*|*"bytes copied"*) echo "  startup-config saved" ;;
  *) echo "ERROR: failed to save startup-config after onboarding:" >&2
     printf '%s\n' "$save_out" >&2; exit 1 ;;
esac

echo "[7/7] done. The agent will stage its assigned image at bootflash: root."
