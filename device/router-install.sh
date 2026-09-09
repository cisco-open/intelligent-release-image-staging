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

if [ -n "${NETWORK_ATTACHMENT:-}" ] && [ -z "${MANAGEMENT_TYPE:-}" ]; then
  echo "ERROR: NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE; refusing to fall back to the router-routed default" >&2
  exit 1
fi
MANAGEMENT_TYPE="${MANAGEMENT_TYPE:-router-routed}"
case "$MANAGEMENT_TYPE" in
  router-routed) NAT_INTERFACE="" ;;
  router-nat) : "${NAT_INTERFACE:?set NAT_INTERFACE}" ;;
  *) echo "ERROR: MANAGEMENT_TYPE must be router-routed or router-nat" >&2; exit 1 ;;
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
if [ -n "${IRIS_STAGING_CAPABILITY:-}" ]; then
  CAP="$IRIS_STAGING_CAPABILITY"
else
  CAP="$(od -An -N16 -tx1 /dev/urandom | tr -d '[:space:]')"
fi
[[ "$CAP" =~ ^[0-9a-f]{32}$ ]] \
  || { echo "ERROR: IRIS_STAGING_CAPABILITY must be 32 lowercase hexadecimal characters" >&2; exit 1; }
[[ "$DEVICE_ID" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] \
  || { echo "ERROR: DEVICE_ID contains unsupported characters" >&2; exit 1; }
CONF="iris-agent-$DEVICE_ID-$CAP.conf"
RPC_SECRET_FILE="rpc-secret-$CAP"
INSTRUCTION_ENVELOPE="iris-instructions-$DEVICE_ID-$CAP.envelope"
BUNDLE_DIGEST_FILE="bundle-sha256-$CAP"

MODEL="${MODEL:-}"
EXPECTED_DEVICE_IDENTITY="${EXPECTED_DEVICE_IDENTITY:-}"
if [ "$DRY" -eq 0 ]; then
  : "${EXPECTED_DEVICE_IDENTITY:?set EXPECTED_DEVICE_IDENTITY from the deployment record}"
  # A failed session here used to trip errexit with ssh's status and NO
  # message (stderr was discarded too); name the fault instead.
  VERSION_OUT="$(printf 'show version\n' \
    | "$HERE/../lab/device-run.sh" "$DEVICE_IP")" \
    || { echo "ERROR: could not read 'show version' from $DEVICE_IP -- the device session failed (see the ssh diagnostics above: reachability, host key, credentials)" >&2; exit 1; }
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
if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
cat <<EOF
 ip nat inside
EOF
fi
cat <<EOF
 no shutdown
!
EOF
if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
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
telemetry_stream = ${TELEMETRY_STREAM:-off}
token_expires_at = 0
agent_version = $(cat "$HERE/../VERSION" 2>/dev/null || echo unknown)
EOF
[ -z "${PRESERVED_LKG_KEY:-}" ] || printf 'lkg_key = %s\n' "$PRESERVED_LKG_KEY"
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
  echo "===== IOS configuration ====="; ios_config
  echo "===== Certificate trust ====="; trustpoint_block
  echo "===== Agent configuration ====="; agent_conf
  echo "===== Copy agent files over HTTPS ====="
  echo "delete /force $IOS_ROOT/bundle.tgz"
  echo "delete /force $IOS_ROOT/bundle.tgz.sha256"
  for pair in "bootstrap.sh:bootstrap.sh" "staging/$CONF:iris-agent.conf" \
              "staging/$RPC_SECRET_FILE:rpc-secret" \
              "iris-catalog.pem:iris-catalog.pem" \
              "iris-signers.pem:iris-signers.allowed_signers" \
              "staging/$INSTRUCTION_ENVELOPE:iris-instructions.bootstrap" \
              "staging/$BUNDLE_DIGEST_FILE:bundle.tgz.sha256" \
              "$BUNDLE:bundle.tgz"; do
    src="${pair%%:*}"; dst="${pair##*:}"
    printf 'copy https://%s:8000/%s %s/%s\n' "$STAGE_HOST" "$src" "$IOS_ROOT" "$dst"
  done
  echo "===== Start Guest Shell ====="
  echo "guestshell enable"
  echo "===== Save startup-config ====="
  echo "copy running-config startup-config"
  exit 0
fi

ssh_host() {
  # Same trust policy as the device transport (lab/iris-ssh-policy.sh): the
  # stage host receives the per-device enrollment token, so it is verified.
  # shellcheck source=lab/iris-ssh-policy.sh
  . "$HERE/../lab/iris-ssh-policy.sh" || return 1
  iris_ssh_policy "$STAGE_HOST" || return 1
  local rc=0
  SSHPASS="$HOST_PASS" sshpass -e ssh "${IRIS_SSH_OPTS[@]}" \
    -o LogLevel=ERROR "$HOST_USER@$STAGE_HOST" "$@" || rc=$?
  iris_ssh_cleanup
  return "$rc"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

regular_bounded_file() {
  local _size
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  _size="$(wc -c < "$1" 2>/dev/null | tr -d '[:space:]')"
  case "$_size" in ''|*[!0-9]*) return 1 ;; esac
  [ "$_size" -gt 0 ] && [ "$_size" -le "$2" ]
}

validate_and_stage_local_artifacts() {
  local _bundle _sidecar _expected _actual _digest _tmp
  _bundle="$ART/$BUNDLE"
  _sidecar="$_bundle.sha256"
  regular_bounded_file "$_bundle" 33554432 \
    || { echo "ERROR: bundle digest evidence is missing or invalid" >&2; return 1; }
  [ -f "$_sidecar" ] && [ ! -L "$_sidecar" ] \
    && [ "$(wc -c < "$_sidecar" 2>/dev/null | tr -d '[:space:]')" = 65 ] \
    || { echo "ERROR: bundle digest evidence is missing or invalid" >&2; return 1; }
  IFS= read -r _expected < "$_sidecar" || true
  [[ "$_expected" =~ ^[0-9a-f]{64}$ ]] \
    || { echo "ERROR: bundle digest evidence is missing or invalid" >&2; return 1; }
  _actual="$(sha256_file "$_bundle" 2>/dev/null || true)"
  [ "$_actual" = "$_expected" ] \
    || { echo "ERROR: bundle digest evidence is missing or invalid" >&2; return 1; }
  regular_bounded_file "$ART/iris-signers.pem" 65536 \
    || { echo "ERROR: iris-signers.pem is missing or invalid" >&2; return 1; }
  regular_bounded_file "$ART/staging/$INSTRUCTION_ENVELOPE" 262144 \
    || { echo "ERROR: instruction bootstrap artifact is missing or invalid" >&2; return 1; }
  _digest="$ART/staging/$BUNDLE_DIGEST_FILE"
  _tmp="$ART/staging/.$BUNDLE_DIGEST_FILE.$$"
  (umask 077; printf '%s\n' "$_actual" > "$_tmp") \
    && mv -f "$_tmp" "$_digest" \
    || { rm -f "$_tmp" 2>/dev/null || true
         echo "ERROR: could not materialize bundle digest capability" >&2; return 1; }
}

validate_and_stage_remote_artifacts() {
  _remote_rc=0
  ssh_host "set -eu
base=\$HOME/iris/artifacts
bundle=\$base/$BUNDLE
sidecar=\$base/$BUNDLE.sha256
signers=\$base/iris-signers.pem
envelope=\$base/staging/$INSTRUCTION_ENVELOPE
[ -d \"\$base/staging\" ] && [ ! -L \"\$base/staging\" ] || exit 44
[ -f \"\$base/bootstrap.sh\" ] && [ ! -L \"\$base/bootstrap.sh\" ] || exit 44
[ -f \"\$bundle\" ] && [ ! -L \"\$bundle\" ] || exit 41
bundle_size=\$(wc -c < \"\$bundle\" | tr -d '[:space:]')
[ \"\$bundle_size\" -gt 0 ] && [ \"\$bundle_size\" -le 33554432 ] || exit 41
[ -f \"\$sidecar\" ] && [ ! -L \"\$sidecar\" ] || exit 41
[ \"\$(wc -c < \"\$sidecar\" | tr -d '[:space:]')\" = 65 ] || exit 41
expected=\$(cat \"\$sidecar\")
case \"\$expected\" in *[!0-9a-f]*|'') exit 41 ;; esac
[ \"\${#expected}\" -eq 64 ] || exit 41
actual=\$(sha256sum \"\$bundle\" | awk '{print \$1}')
[ \"\$actual\" = \"\$expected\" ] || exit 41
[ -f \"\$signers\" ] && [ ! -L \"\$signers\" ] || exit 42
signer_size=\$(wc -c < \"\$signers\" | tr -d '[:space:]')
[ \"\$signer_size\" -gt 0 ] && [ \"\$signer_size\" -le 65536 ] || exit 42
[ -f \"\$envelope\" ] && [ ! -L \"\$envelope\" ] || exit 43
envelope_size=\$(wc -c < \"\$envelope\" | tr -d '[:space:]')
[ \"\$envelope_size\" -gt 0 ] && [ \"\$envelope_size\" -le 262144 ] || exit 43
tmp=\$base/staging/.$BUNDLE_DIGEST_FILE.\$\$
trap 'rm -f \"\$tmp\"' EXIT HUP INT TERM
umask 077
printf '%s\\n' \"\$actual\" > \"\$tmp\"
mv -f \"\$tmp\" \"\$base/staging/$BUNDLE_DIGEST_FILE\"" >/dev/null 2>&1 \
    || _remote_rc=$?
  case "$_remote_rc" in
    0) return 0 ;;
    42) echo "ERROR: iris-signers.pem is missing or invalid" >&2 ;;
    43) echo "ERROR: instruction bootstrap artifact is missing or invalid" >&2 ;;
    44) echo "ERROR: required artifact staging inputs are missing or invalid" >&2 ;;
    *) echo "ERROR: bundle digest evidence is missing or invalid" >&2 ;;
  esac
  return 1
}

read_preserved_lkg_key() {
  local _existing _candidate
  _existing="$(printf 'more %s/iris-agent.conf\n' "$IOS_STAGE" \
    | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null || true)"
  _candidate="$(printf '%s\n' "$_existing" \
    | sed -n 's/^[[:space:]]*lkg_key[[:space:]]*=[[:space:]]*//p' \
    | tail -n1 | tr -d '\r' \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  if [[ "$_candidate" =~ ^[0-9a-f]{64}$ ]]; then
    PRESERVED_LKG_KEY="$_candidate"
  else
    PRESERVED_LKG_KEY=""
  fi
}

check_existing_stage_writable() {
  local _existing_app _probe
  _existing_app="$1"
  [ -n "$_existing_app" ] || return 0
  case "$_existing_app" in
    *RUNNING*) ;;
    *) echo "ERROR: existing Guest Shell is not running; start it and repair guest-share/iris ownership before re-onboarding" >&2
       return 1 ;;
  esac
  _probe="$(printf "guestshell run bash -c 'test -d %s && test -w %s && echo __IRIS_STAGE_WRITABLE__'\n" \
    "$STAGE" "$STAGE" | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null || true)"
  case "$_probe" in
    *__IRIS_STAGE_WRITABLE__*) return 0 ;;
    *) echo "ERROR: guest-share/iris is not writable by Guest Shell; repair its ownership before re-onboarding" >&2
       return 1 ;;
  esac
}

echo "[1/6] check storage on $DEVICE_IP"
printf 'dir bootflash: | include bytes free\n' | "$HERE/../lab/device-run.sh" "$DEVICE_IP" \
  | grep -i 'bytes free' || true

echo "[2/6] prepare agent configuration"
ART="${IRIS_ARTIFACTS_DIR:-$(cd "$HERE/.." && pwd)/artifacts}"
: "${IRIS_CRT_FILE:?set IRIS_CRT_FILE to the bare server cert crt.pem}"
[ -r "$IRIS_CRT_FILE" ] \
  || { echo "ERROR: IRIS_CRT_FILE=$IRIS_CRT_FILE is not readable" >&2; exit 1; }
STAGE_LOCAL=0
if [ "${IRIS_STAGE_LOCAL:-0}" = "1" ] \
    || ip -o addr 2>/dev/null | grep -qw "$STAGE_HOST" \
    || [ "$STAGE_HOST" = "localhost" ]; then
  STAGE_LOCAL=1
fi
if [ "$STAGE_LOCAL" -eq 1 ]; then
  mkdir -p "$ART/staging"
  [ -d "$ART/staging" ] && [ ! -L "$ART/staging" ] \
    || { echo "ERROR: artifact staging directory is invalid" >&2; exit 1; }
  validate_and_stage_local_artifacts || exit 1
else
  : "${HOST_USER:?set HOST_USER for remote STAGE_HOST $STAGE_HOST}"
  : "${HOST_PASS:?set HOST_PASS for remote STAGE_HOST $STAGE_HOST}"
  validate_and_stage_remote_artifacts || exit 1
fi

existing="$(printf 'show app-hosting list\n' \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null | grep -i guestshell || true)"
PRESERVED_LKG_KEY=""
read_preserved_lkg_key
check_existing_stage_writable "$existing" || exit 1

if [ "$STAGE_LOCAL" -eq 1 ]; then
  _conf_tmp="$ART/staging/.$CONF.$$"
  _rpc_tmp="$ART/staging/.$RPC_SECRET_FILE.$$"
  (umask 077
   agent_conf > "$_conf_tmp"
   printf '%s\n' "$RPC_SECRET" > "$_rpc_tmp") \
    && mv -f "$_conf_tmp" "$ART/staging/$CONF" \
    && mv -f "$_rpc_tmp" "$ART/staging/$RPC_SECRET_FILE" \
    || { rm -f "$_conf_tmp" "$_rpc_tmp" 2>/dev/null || true
         echo "ERROR: could not stage agent configuration" >&2; exit 1; }
  [ -e "$ART/bootstrap.sh" ] || cp "$HERE/bootstrap.sh" "$ART/bootstrap.sh"
  [ -e "$ART/iris-catalog.pem" ] || cp "$IRIS_CRT_FILE" "$ART/iris-catalog.pem"
else
  agent_conf | ssh_host "set -eu; umask 077; d=\$HOME/iris/artifacts/staging; c=\$d/.$CONF.\$\$; r=\$d/.$RPC_SECRET_FILE.\$\$; trap 'rm -f \"\$c\" \"\$r\"' EXIT HUP INT TERM; cat > \"\$c\"; printf '%s\\n' '$RPC_SECRET' > \"\$r\"; mv -f \"\$c\" \"\$d/$CONF\"; mv -f \"\$r\" \"\$d/$RPC_SECRET_FILE\""
  ssh_host "cat > ~/iris/artifacts/iris-catalog.pem" < "$IRIS_CRT_FILE"
fi

# 2026-08-20 incident (iris8kv-1/-2): a re-onboard over a guestshell that was
# already RUNNING leaves it on its OLD networking — the enable step below sees
# RUNNING and never re-enables, so the freshly applied app-hosting gateway
# never reaches the guest and the agent has no egress (silent: inbound ping
# still answers). Destroy any pre-existing guestshell FIRST so enable always
# builds the guest from the config this run applies. Agent state survives on
# bootflash:guest-share, so this costs only the ~60s guest rebuild.
if [ -n "$existing" ]; then
  echo "[3/6] remove existing Guest Shell"
  # some IOS-XE versions prompt "Undeploy Guest Shell? [y/n]" — answer it,
  # matching both uninstallers; without the y the destroy never runs and the
  # wait loop below times out with the stale guest intact
  printf 'guestshell destroy\ny\n' \
    | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true
  for i in $(seq 1 12); do
    still="$(printf 'show app-hosting list\n' \
      | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null | grep -i guestshell || true)"
    [ -z "$still" ] && { echo "  guestshell DESTROYED"; break; }
    [ "$i" -ne 12 ] || { echo "ERROR: pre-existing guestshell still present after destroy" >&2; exit 1; }
    sleep 10
  done
fi

echo "[3/6] configure IRIS ($MANAGEMENT_TYPE)"
{ echo "configure terminal"; ios_config; } \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null
printf 'mkdir %s\n\n' "$IOS_ROOT" \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true

echo "[4/6] start Guest Shell"
# Every iteration is its own login, deliberately: this is a state-gated poll,
# and collapsing repeated observations into one session is precisely what the
# 2026-08-29..31 fail-open wave was about (a marker proves what was typed,
# never what ran). What IS wrong here is the flat wait -- a guest that came up
# in 20 s still paid a full 15 s of overshoot, and the first observation was
# 15 s late for no reason. The sleep ramps 2,4,6..15 instead, which keeps the
# same overall budget (~431 s of sleep across 32 steps vs 450 s across 30)
# while finding a fast bring-up almost immediately.
for i in $(seq 1 32); do
  state="$(printf 'show app-hosting list\n' \
    | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null \
    | grep -i guestshell || true)"
  case "$state" in *RUNNING*) echo "  guestshell RUNNING"; break ;; esac
  if [ $(((i - 1) % 5)) -eq 0 ]; then
    printf 'guestshell enable\n' \
      | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true
  fi
  [ "$i" -ne 32 ] \
    || { echo "ERROR: guestshell not RUNNING after ~9 minutes" >&2; exit 1; }
  backoff=$((i * 2))
  [ "$backoff" -gt 15 ] && backoff=15
  sleep "$backoff"
done

echo "[5/6] copy certificate and agent files"
{ echo "configure terminal"; trustpoint_block; echo "end"; } \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null

# Preflight the artifact server before handing the device over to the automatic
# path. Retried, because one 5s attempt was the most fragile step in a fleet
# onboard: the artifact server's latency degrades under concurrent load (a 75x
# spike was measured with 30 simultaneous bundle fetches) and this check runs at
# exactly that moment. A transient miss strands the device half-installed -- the
# trustpoint above is already pushed -- which is a far worse outcome than waiting.
#
# The exit code is reported because "unreachable or untrusted" conflates three
# faults with three different fixes, and naming trust as a likely cause once sent
# an investigation chasing certificate drift while the certificates were identical.
artifact_preflight() {
  _url="https://$STAGE_HOST:8000/bootstrap.sh"
  _attempt=1
  while [ "$_attempt" -le 3 ]; do
    _rc=0
    _err="$(curl -sS -f -o /dev/null --max-time 5 --cacert "$IRIS_CRT_FILE" "$_url" 2>&1)" || _rc=$?
    [ "$_rc" -eq 0 ] && return 0
    if [ "$_attempt" -lt 3 ]; then
      echo "  artifact preflight attempt $_attempt failed (curl rc=$_rc); retrying in $((_attempt * 5))s" >&2
      sleep $((_attempt * 5))
    fi
    _attempt=$((_attempt + 1))
  done
  case "$_rc" in
    7)  _why="cannot connect -- is the artifact server up and :8000 reachable from here?" ;;
    22) _why="server returned an HTTP error -- is bootstrap.sh present in the artifacts dir?" ;;
    28) _why="timed out (5s x3) -- the server answers but is slow; a large fleet onboard can saturate it" ;;
    35|60) _why="TLS verification failed -- IRIS_CRT_FILE is not the cert this server presents" ;;
    *)  _why="curl exit $_rc" ;;
  esac
  echo "  ERROR: artifact preflight failed for $_url: $_why" >&2
  [ -n "$_err" ] && echo "  curl: $_err" >&2
  return 1
}

if ! artifact_preflight; then
  exit 1
fi
# Preserve the live work directory, its instruction state, and its last-known
# runnable agent. Only stale root-level incoming archive evidence is removed.
printf 'delete /force %s/bundle.tgz\ndelete /force %s/bundle.tgz.sha256\n' \
  "$IOS_ROOT" "$IOS_ROOT" \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true
for pair in "bootstrap.sh:bootstrap.sh" "staging/$CONF:iris-agent.conf" \
            "staging/$RPC_SECRET_FILE:rpc-secret" \
            "iris-catalog.pem:iris-catalog.pem" \
            "iris-signers.pem:iris-signers.allowed_signers" \
            "staging/$INSTRUCTION_ENVELOPE:iris-instructions.bootstrap" \
            "staging/$BUNDLE_DIGEST_FILE:bundle.tgz.sha256" \
            "$BUNDLE:bundle.tgz"; do
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

echo "[6/6] verify configuration and save startup-config"
RUN="$HERE/../lab/device-run.sh"
# One SSH login for all three read-only verify checks instead of three --
# same consolidation as _default_router_preflight in server/gui_onboard.py.
# IOS XE echoes these markers verbatim; a missing marker is a hard error,
# never treated as empty/safe output (an empty section here could otherwise
# read as "nothing to verify" instead of "the check didn't run").
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
  || { echo "ERROR: router verify did not return running-config" >&2; exit 1; }
RUNNING="$(printf '%s' "$RUNNING_RAW" | grep -v '#' || true)"
config_block() {
  python3 -c 'import re,sys
name = re.escape(sys.argv[1])
text = sys.stdin.read()
match = re.search(r"(?ms)^interface %s\s*$\n(.*?)(?=^!\s*$|^interface |^end\s*$|\Z)" % name, text)
print(match.group(0) if match else "")' "$1"
}
VPG_RUNNING="$(printf '%s\n' "$RUNNING" | config_block "VirtualPortGroup$VPG_NUMBER")"
APPS_RAW="$(printf '%s' "$VERIFY_OUT" | verify_section APPS)" \
  || { echo "ERROR: router verify did not return app-hosting state" >&2; exit 1; }
APP_STATE="$(printf '%s' "$APPS_RAW" | grep -v '#' || true)"
FILES_RAW="$(printf '%s' "$VERIFY_OUT" | verify_section FILES)" \
  || { echo "ERROR: router verify did not return guest-share file listing" >&2; exit 1; }
FILES="$(printf '%s' "$FILES_RAW" | grep -v '#' || true)"

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

if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
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

echo "onboard complete: $DEVICE_IP"
