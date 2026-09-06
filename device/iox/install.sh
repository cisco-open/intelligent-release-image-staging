#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Repeatable IRIS installer for Catalyst devices with IOx app hosting. It
# deploys the agent as an architecture-matched IOx Docker app (iris-arm64.tar) instead
# of into Guest Shell, but uses the SAME transport as
# device/device-install.sh: the onboarding host pushes the package over the
# already-authenticated IOS SCP service. The enrollment token therefore never
# enters a URL, an IOS HTTP-client configuration, or a process argument. The
# agent then pulls its assigned image over
# the swarm and copies it to an IOS-visible disk via a plain `copy`, such as
# sdflash: on IE-3x00 or usbflash1: on C9300. Distribute/stage
# ONLY; never install/activate/reload the IOS image.
#
# Idempotent: re-running tears down any existing iris app and redeploys (fresh
# runtime certificate, package, and token) — safe to run repeatedly.  The
# certificate is application data, not part of the signed package.
#
# Required env:
#   DEVICE_IP VLAN SVI_IP SVI_MASK GUEST_IP CATALOG_TOKEN DEVICE_ID STAGE_HOST
#   DEVICE_SSH_PASS  — the device login the container uses for its SSH-to-self CLI
#   DEVICE_USER (+ DEVICE_PASS) — for lab/device-run.sh; export or 'source' creds/
# Optional (defaults):
#   CATALOG_URL=https://STAGE_HOST:8443  APP_INTF=AppGigabitEthernet1/1
#   GW_IP=$SVI_IP  CPU=400  MEM=768  DISK=2048  PKG=iris-arm64.tar  PKG_FS=flash:
#   DEVICE_SSH_USER=dnac  TARGET_FS=sdflash:  IRIS_TELEMETRY=on
#   IRIS_CRT_FILE=$IRIS_ARTIFACTS_DIR/iris-catalog.pem (the public server cert)
#   IRIS_LOG=off -- device-side aria2c.log opt-in (see device/container/entrypoint.sh);
#     off by default for flash write endurance. Forwarded verbatim as an
#     -e run-opts value so the container actually sees an operator's opt-in --
#     previously this script dropped it silently and the entrypoint's own
#     default always won.
#   INSTALL_TIMEOUT=300  ACTIVATE_TIMEOUT=300  START_TIMEOUT=300  STATE_POLL=5
#     (seconds; the app-hosting lifecycle polls -- see the note by their
#     defaults below)
set -euo pipefail

DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

: "${DEVICE_IP:?set DEVICE_IP}"
: "${CATALOG_TOKEN:?set CATALOG_TOKEN}"; : "${DEVICE_ID:?set DEVICE_ID}"
: "${STAGE_HOST:?set STAGE_HOST}"; : "${DEVICE_SSH_PASS:?set DEVICE_SSH_PASS}"
# Management type model. routed: IRIS creates a dedicated VLAN/SVI and the app SSHes
# to that SVI. inband: the app attaches to an EXISTING operator-owned VLAN that
# IRIS never creates/changes/removes, and SSHes to the existing IOS management
# SVI (IOS_SSH_HOST) for its plain-copy placement. The AppGig trunk is the one inband
# touch: IRIS ADDs the inband VLAN to its allowed list (additive only, never
# replaced, never removed on uninstall).
if [ -n "${NETWORK_ATTACHMENT:-}" ] && [ -z "${MANAGEMENT_TYPE:-}" ]; then
  echo "ERROR: NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE; refusing to fall back to the routed default" >&2
  exit 1
fi
MANAGEMENT_TYPE="${MANAGEMENT_TYPE:-routed}"
case "$MANAGEMENT_TYPE" in
  routed)
    : "${VLAN:?set VLAN}"; : "${SVI_IP:?set SVI_IP}"; : "${SVI_MASK:?set SVI_MASK}"; : "${GUEST_IP:?set GUEST_IP}"
    GW_IP="${GW_IP:-$SVI_IP}"; IOS_SSH_HOST="${IOS_SSH_HOST:-$SVI_IP}" ;;
  inband)
    : "${INBAND_VLAN:?set INBAND_VLAN}"; : "${APP_IP:?set APP_IP}"; : "${APP_MASK:?set APP_MASK}"; : "${APP_GATEWAY:?set APP_GATEWAY}"
    : "${IOS_SSH_HOST:?set IOS_SSH_HOST — the existing IOS management SVI the app SSHes to}"
    VLAN="$INBAND_VLAN"; GUEST_IP="$APP_IP"; SVI_MASK="$APP_MASK"; GW_IP="$APP_GATEWAY" ;;
  *) echo "ERROR: MANAGEMENT_TYPE must be routed or inband" >&2; exit 1 ;;
esac

CATALOG_URL="${CATALOG_URL:-https://$STAGE_HOST:8443}"
APP_INTF="${APP_INTF:-AppGigabitEthernet1/1}"
# C9k share-mount transfer (Route B): bind-mount the app-hosting SSD share into
# the container so the agent lands its scratch at disk speed and IOS places it
# with an internal disk-to-disk copy — no scp, no CoPP-policed punt traffic.
# Both or neither: SHARE_HOST_PATH is the host-side dir (/vol/usb1/...),
# SHARE_IOS_PATH the same dir as IOS sees it (usbflash1:iox_host_data_share).
SHARE_HOST_PATH="${SHARE_HOST_PATH:-}"; SHARE_IOS_PATH="${SHARE_IOS_PATH:-}"
if [ -n "$SHARE_HOST_PATH$SHARE_IOS_PATH" ] && \
   { [ -z "$SHARE_HOST_PATH" ] || [ -z "$SHARE_IOS_PATH" ]; }; then
  echo "ERROR: SHARE_HOST_PATH and SHARE_IOS_PATH must be set together" >&2
  exit 2
fi
CPU="${CPU:-400}"; MEM="${MEM:-768}"; DISK="${DISK:-2048}"
PKG="${PKG:-iris-arm64.tar}"; PKG_FS="${PKG_FS:-flash:}"
DEVICE_SSH_USER="${DEVICE_SSH_USER:-dnac}"
TARGET_FS="${TARGET_FS:-sdflash:}"
IRIS_TELEMETRY="${IRIS_TELEMETRY:-on}"
IRIS_TELEMETRY_STREAM="${IRIS_TELEMETRY_STREAM:-off}"
# Same fail-closed default as device/container/entrypoint.sh's IRIS_LOG parsing
# -- this is only the plumbing that lets an operator's opt-in actually reach
# it; the default stays off either way.
IRIS_LOG="${IRIS_LOG:-off}"
# App-hosting lifecycle poll budgets, in seconds. The FIRST install of a new
# package version is far slower than a repeat install of the same one: the IOx
# runtime has to load the package's docker layers into its image cache before
# the app can activate, and a byte-identical package the box has run before
# activates in seconds because those layers are already cached. The old flat
# 90 s activate budget was shorter than that first-time load on an IE-3400, so
# a first install reported failure while the activation actually completed a
# minute or two later -- and the failed run left the app-hosting config behind,
# so the console's retry was refused by preflight. Same idiom and same 300 s
# default as device/xr-install.sh's ACTIVATE_TIMEOUT.
#
# Deliberately FLAT, not scaled by package size: every wait below returns as
# soon as the state is reached, so a generous ceiling costs a successful
# install nothing and only lengthens the already-failing case, while a
# size-derived budget would add a second failure mode (no size available, or a
# size read from an advisory HEAD that is allowed to fail) to a knob that only
# needs a ceiling. Override any of them per-device instead.
INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-300}"
ACTIVATE_TIMEOUT="${ACTIVATE_TIMEOUT:-300}"
START_TIMEOUT="${START_TIMEOUT:-300}"
STATE_POLL="${STATE_POLL:-5}"

_single_line() {
  case "$2" in *$'\n'*|*$'\r'*)
    echo "ERROR: $1 must be a single line" >&2; exit 2 ;;
  esac
}

_safe_word() {
  _single_line "$1" "$2"
  [[ "$2" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] \
    || { echo "ERROR: $1 contains unsafe characters" >&2; exit 2; }
}

_safe_host() {
  _single_line "$1" "$2"
  [[ "$2" =~ ^[A-Za-z0-9._:-]+$ ]] \
    || { echo "ERROR: $1 is not a safe host" >&2; exit 2; }
}

_uint_between() {
  local name="$1" value="$2" minimum="$3" maximum="$4"
  [[ "$value" =~ ^[0-9]+$ ]] && [ "${#value}" -le 9 ] \
    || { echo "ERROR: $name must be an integer from $minimum to $maximum" >&2; exit 2; }
  [ "$value" -ge "$minimum" ] && [ "$value" -le "$maximum" ] \
    || { echo "ERROR: $name must be an integer from $minimum to $maximum" >&2; exit 2; }
}

_ipv4() {
  local name="$1" value="$2" a b c d part
  _single_line "$name" "$value"
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] \
    || { echo "ERROR: $name must be an IPv4 address" >&2; exit 2; }
  IFS=. read -r a b c d <<<"$value"
  for part in "$a" "$b" "$c" "$d"; do
    [ "$((10#$part))" -le 255 ] \
      || { echo "ERROR: $name must be an IPv4 address" >&2; exit 2; }
  done
}

_netmask() {
  _ipv4 "$1" "$2"
  case "$2" in
    0.0.0.0|128.0.0.0|192.0.0.0|224.0.0.0|240.0.0.0|248.0.0.0|252.0.0.0|254.0.0.0|255.0.0.0|\
    255.128.0.0|255.192.0.0|255.224.0.0|255.240.0.0|255.248.0.0|255.252.0.0|255.254.0.0|255.255.0.0|\
    255.255.128.0|255.255.192.0|255.255.224.0|255.255.240.0|255.255.248.0|255.255.252.0|255.255.254.0|255.255.255.0|\
    255.255.255.128|255.255.255.192|255.255.255.224|255.255.255.240|255.255.255.248|255.255.255.252|255.255.255.254|255.255.255.255) ;;
    *) echo "ERROR: $1 must be a contiguous IPv4 netmask" >&2; exit 2 ;;
  esac
}

_boolean() {
  _single_line "$1" "$2"
  case "$2" in on|off|1|0|true|false|yes|no|ON|OFF|TRUE|FALSE|YES|NO) ;;
    *) echo "ERROR: $1 has an invalid boolean value" >&2; exit 2 ;;
  esac
}

_https_url() {
  local name="$1" value="$2"
  _single_line "$name" "$value"
  printf '%s' "$value" | python3 -c '
import sys
from urllib.parse import urlsplit
try:
    value = urlsplit(sys.stdin.read())
    port = value.port
    valid = (value.scheme == "https" and value.hostname is not None
             and value.username is None and value.password is None
             and (port is None or 1 <= port <= 65535))
except ValueError:
    valid = False
raise SystemExit(0 if valid else 1)
' >/dev/null 2>&1 \
    || { echo "ERROR: $name must be an https URL without credentials" >&2; exit 2; }
}

for _budget in INSTALL_TIMEOUT ACTIVATE_TIMEOUT START_TIMEOUT STATE_POLL; do
  _value="${!_budget}"
  _uint_between "$_budget" "$_value" 1 86400
done
unset _budget _value
_uint_between VLAN "$VLAN" 1 4094
_uint_between CPU "$CPU" 1 1048576
_uint_between MEM "$MEM" 1 1048576
_uint_between DISK "$DISK" 1 1048576
_ipv4 GUEST_IP "$GUEST_IP"
_ipv4 GW_IP "$GW_IP"
_netmask SVI_MASK "$SVI_MASK"
if [ "$MANAGEMENT_TYPE" = routed ]; then _ipv4 SVI_IP "$SVI_IP"; fi
_ipv4 IOS_SSH_HOST "$IOS_SSH_HOST"
_safe_host DEVICE_IP "$DEVICE_IP"
_safe_host STAGE_HOST "$STAGE_HOST"
_safe_word DEVICE_ID "$DEVICE_ID"
[[ "$APP_INTF" =~ ^[A-Za-z][A-Za-z0-9./_-]*$ ]] \
  || { echo "ERROR: APP_INTF contains unsafe characters" >&2; exit 2; }
_boolean IRIS_TELEMETRY "$IRIS_TELEMETRY"
_boolean IRIS_TELEMETRY_STREAM "$IRIS_TELEMETRY_STREAM"
_boolean IRIS_LOG "$IRIS_LOG"
[[ "$TARGET_FS" =~ ^[A-Za-z][A-Za-z0-9_-]*:$ ]] \
  || { echo "ERROR: TARGET_FS must be an IOS filesystem prefix such as sdflash:" >&2; exit 2; }
[[ "$PKG_FS" =~ ^[A-Za-z][A-Za-z0-9_-]*:$ ]] \
  || { echo "ERROR: PKG_FS must be an IOS filesystem prefix such as flash:" >&2; exit 2; }
[[ "$PKG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || { echo "ERROR: PKG must be a safe basename" >&2; exit 2; }
if [ -n "$SHARE_HOST_PATH" ]; then
  _single_line SHARE_HOST_PATH "$SHARE_HOST_PATH"
  [[ "$SHARE_HOST_PATH" =~ ^/[A-Za-z0-9._/-]+$ ]] \
    && [[ "/$SHARE_HOST_PATH/" != *"/../"* ]] \
    || { echo "ERROR: SHARE_HOST_PATH must be a safe absolute path" >&2; exit 2; }
  _single_line SHARE_IOS_PATH "$SHARE_IOS_PATH"
  [[ "$SHARE_IOS_PATH" =~ ^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]] \
    && [[ "/${SHARE_IOS_PATH#*:}/" != *"/../"* ]] \
    || { echo "ERROR: SHARE_IOS_PATH must be a safe IOS filesystem path" >&2; exit 2; }
fi

# The values below ride inside the double-quoted `run-opts N "-e K=V"` lines
# of the app-hosting block (appid_block). A literal double-quote or newline
# in any of them breaks out of that token or splices in extra config lines;
# the paste discards IOS's errors, so the malformed line was silently
# DROPPED, the app started without the variable, died on its entrypoint's
# required-env guard, and the installer timed out at wait_state RUNNING --
# after [1/9] had already torn down the previously working app. Same guard
# device/xr-install.sh applies to its docker-run-opts; reject early, before
# anything on the device is touched. A password is allowed to contain
# whitespace (it stays inside the quotes); the identity/URL values are not.
_no_quotes_or_newlines() {
  case "$2" in
    *'"'*|*$'\n'*|*$'\r'*)
      echo "ERROR: $1 must not contain a double quote, CR, or LF" >&2
      exit 1 ;;
  esac
  if [ "${3:-}" = "no-whitespace" ]; then
    case "$2" in *[[:space:]]*)
      echo "ERROR: $1 contains whitespace, which would split the quoted run-opts value" >&2
      exit 1 ;;
    esac
  fi
}
_no_quotes_or_newlines DEVICE_SSH_PASS "$DEVICE_SSH_PASS"
_no_quotes_or_newlines CATALOG_TOKEN "$CATALOG_TOKEN" no-whitespace
_no_quotes_or_newlines CATALOG_URL "$CATALOG_URL" no-whitespace
_no_quotes_or_newlines DEVICE_ID "$DEVICE_ID" no-whitespace
_no_quotes_or_newlines DEVICE_SSH_USER "$DEVICE_SSH_USER" no-whitespace
# IRIS_LOG rides the same quoted run-opts value as everything else above;
# reuse the one guard rather than trusting a bare on/off-shaped value.
_no_quotes_or_newlines IRIS_LOG "$IRIS_LOG" no-whitespace
_https_url CATALOG_URL "$CATALOG_URL"
[[ "$CATALOG_TOKEN" =~ ^[A-Za-z0-9._~+/-]+=*$ ]] \
  || { echo "ERROR: CATALOG_TOKEN contains unsafe characters" >&2; exit 2; }
[[ "$DEVICE_SSH_USER" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] \
  || { echo "ERROR: DEVICE_SSH_USER is not a safe SSH username" >&2; exit 2; }
if [ -n "${DEVICE_USER:-}" ]; then
  [[ "$DEVICE_USER" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] \
    || { echo "ERROR: DEVICE_USER is not a safe SSH username" >&2; exit 2; }
fi
if [ -n "${MODEL:-}" ]; then _safe_word MODEL "$MODEL"; fi
if [ -n "${EXPECTED_DEVICE_IDENTITY:-}" ]; then
  _safe_word EXPECTED_DEVICE_IDENTITY "$EXPECTED_DEVICE_IDENTITY"
fi
APPID=iris
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN() { "$HERE/../../lab/device-run.sh" "$DEVICE_IP"; }   # IOS cmds on stdin

# Resolve and prove the package before any idempotent teardown mutates the
# device. Console onboarding mounts the served artifact directory locally.
ART="${IRIS_ARTIFACTS_DIR:-$(cd "$HERE/../.." && pwd)/artifacts}"
PKG_FILE="${IRIS_IOX_PACKAGE_FILE:-$ART/$PKG}"
CATALOG_CA_FILE="${IRIS_CATALOG_CA_FILE:-${IRIS_CRT_FILE:-$ART/iris-catalog.pem}}"
CATALOG_CA_REMOTE="iris-catalog.pem"

case "$CATALOG_CA_FILE" in
  /*) ;;
  *) echo "ERROR: IRIS_CRT_FILE/IRIS_CATALOG_CA_FILE must be an absolute path" >&2; exit 2 ;;
esac
case "$CATALOG_CA_FILE" in *$'\n'*|*$'\r'*)
  echo "ERROR: catalog certificate path must be a single line" >&2; exit 2 ;;
esac

validate_public_cert() {
  [ -r "$1" ] || {
    echo "ERROR: catalog certificate is not readable: $1" >&2
    return 1
  }
  if grep -Eq 'BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY' "$1"; then
    echo "ERROR: catalog certificate file contains a private key; provide only the public certificate" >&2
    return 1
  fi
  openssl x509 -in "$1" -noout >/dev/null 2>&1 || {
    echo "ERROR: catalog certificate is not a valid PEM certificate: $1" >&2
    return 1
  }
}

classify_package_signature() {
  # Inspect member names only; never extract an untrusted package.  Either
  # Cisco signing marker is sufficient to keep platform verification enabled.
  python3 - "$1" <<'PY'
import pathlib
import sys
import tarfile

try:
    with tarfile.open(sys.argv[1], "r:*") as package:
        basenames = {pathlib.PurePosixPath(member.name).name
                     for member in package.getmembers()}
except (OSError, tarfile.TarError) as exc:
    print(f"ERROR: invalid IOx package: {exc}", file=sys.stderr)
    raise SystemExit(1)

markers = basenames.intersection({"package.sign", "package.cert"})
print("signed" if markers else "unsigned")
PY
}

PACKAGE_SIGNATURE_MODE="not-inspected"
if [ "$DRY" -eq 0 ]; then
  : "${DEVICE_USER:?set DEVICE_USER for the authenticated SCP push}"
  : "${DEVICE_PASS:?set DEVICE_PASS for the authenticated SCP push}"
  [[ "$DEVICE_USER" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] \
    || { echo "ERROR: DEVICE_USER is not a safe SSH username" >&2; exit 2; }
  [[ "$DEVICE_IP" =~ ^[A-Za-z0-9._:-]+$ ]] \
    || { echo "ERROR: DEVICE_IP is not a safe SSH host" >&2; exit 2; }
  case "$PKG_FILE" in
    /*) ;;
    *) echo "ERROR: IRIS_IOX_PACKAGE_FILE must be an absolute path" >&2; exit 2 ;;
  esac
  case "$PKG_FILE" in *$'\n'*|*$'\r'*)
    echo "ERROR: IRIS_IOX_PACKAGE_FILE must be a single line" >&2; exit 2 ;;
  esac
  if [ ! -r "$PKG_FILE" ]; then
    echo "ERROR: IOx package is not readable: $PKG_FILE" >&2
    exit 1
  fi
  validate_public_cert "$CATALOG_CA_FILE" || exit 1
  PACKAGE_SIGNATURE_MODE="$(classify_package_signature "$PKG_FILE")" || exit 1
elif [ -r "$PKG_FILE" ]; then
  PACKAGE_SIGNATURE_MODE="$(classify_package_signature "$PKG_FILE")" || exit 1
fi

# A deployment record binds this deployment to one physical device and
# platform.  Check both before an idempotent reinstall tears down the app on
# the target address.
MODEL="${MODEL:-}"
EXPECTED_DEVICE_IDENTITY="${EXPECTED_DEVICE_IDENTITY:-}"
if [ "$DRY" -eq 0 ]; then
  : "${EXPECTED_DEVICE_IDENTITY:?set EXPECTED_DEVICE_IDENTITY from the deployment record}"
  : "${MODEL:?set MODEL from the deployment record}"
  VERSION_OUT="$(printf 'show version\n' | RUN 2>/dev/null)"
  LIVE_MODEL="$(printf '%s\n' "$VERSION_OUT" \
    | sed -nE 's/^cisco[[:space:]]+([^[:space:]]+)[[:space:]]+\(.*/\1/p' | head -1)"
  LIVE_IDENTITY="$(printf '%s\n' "$VERSION_OUT" \
    | sed -nE 's/^[Pp]rocessor board ID[[:space:]]+([^[:space:]]+).*/\1/p' | head -1)"
  [ -n "$LIVE_IDENTITY" ] && [ "$LIVE_IDENTITY" = "$EXPECTED_DEVICE_IDENTITY" ] \
    || { echo "ERROR: device identity mismatch; refusing to configure $DEVICE_IP" >&2; exit 1; }
  [ -n "$LIVE_MODEL" ] && [ "$(printf '%s' "$LIVE_MODEL" | tr '[:lower:]' '[:upper:]')" = \
    "$(printf '%s' "$MODEL" | tr '[:lower:]' '[:upper:]')" ] \
    || { echo "ERROR: device model mismatch; expected $MODEL, detected ${LIVE_MODEL:-unknown}; refusing to configure $DEVICE_IP" >&2; exit 1; }
fi

ios_net() {           # networking + IOx enable (idempotent)
if [ "$MANAGEMENT_TYPE" = "inband" ]; then
# Inband: attach to the EXISTING operator-owned VLAN. IRIS creates NO vlan, SVI,
# route, or VRF. The ONE allowed touch is the AppGig trunk, and only ADDITIVELY —
# `allowed vlan add` never replaces the allowed list (the bare form would), and
# uninstall never removes it (operator-owned VLAN; the trunk may be shared).
# Without it the app's traffic has no L2 path off the box.
cat <<EOF
iox
!
interface $APP_INTF
 switchport mode trunk
 switchport trunk allowed vlan add $VLAN
!
file prompt quiet
!
! SCP server: the scp fallback hand-off (primary on IE-3x00; C9k uses the
! bind-mounted SSD share) pushes the scratch here, then the plain copy places it.
ip scp server enable
!
end
EOF
return
fi
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
! SCP server: the scp hand-off (primary on IE-3x00, where IOx cannot
! bind-mount sdflash:; the C9k default is the SSD share) pushes the scratch to
! guest-share, then the plain copy places it.
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
  run-opts 1 "-e IRIS_DEVICE_ID=$DEVICE_ID"
  run-opts 2 "-e IRIS_DEVICE_SSH_PASS=$DEVICE_SSH_PASS"
  run-opts 3 "-e IRIS_CATALOG_TOKEN=$CATALOG_TOKEN"
  run-opts 4 "-e IRIS_CATALOG_URL=$CATALOG_URL"
  run-opts 5 "-e IRIS_DEVICE_SSH_HOST=$IOS_SSH_HOST"
  run-opts 6 "-e IRIS_DEVICE_SSH_USER=$DEVICE_SSH_USER"
  run-opts 7 "-e IRIS_DEVICE_PLATFORM=iox"
  run-opts 8 "-e IRIS_TARGET_FS=$TARGET_FS"
  run-opts 9 "-e IRIS_TELEMETRY=$IRIS_TELEMETRY"
  run-opts 10 "-e IRIS_TELEMETRY_STREAM=$IRIS_TELEMETRY_STREAM"
  run-opts 11 "-e IRIS_LOG=$IRIS_LOG"
EOF
if [ -n "$SHARE_HOST_PATH" ]; then
cat <<EOF
  run-opts 12 "-e IRIS_SHARE_DIR=/mnt/share"
  run-opts 13 "-e IRIS_SHARE_IOS_PATH=$SHARE_IOS_PATH"
  run-opts 14 "-v $SHARE_HOST_PATH:/mnt/share"
EOF
fi
echo "end"
}

appid_block_redacted() {
  # A dry run is commonly pasted into an issue or build log.  Keep the shape
  # of every run-opt visible without printing either credential.
  local DEVICE_SSH_PASS='<redacted>' CATALOG_TOKEN='<redacted>'
  appid_block
}

iox_ready() {
  # ONE login per observation: both fields live in the SAME `show iox` output,
  # so reading it twice paid a second ssh handshake for nothing. The poll loop
  # around this still re-observes live state on every iteration -- only the
  # duplicated read WITHIN one observation is collapsed, never the polling.
  local out
  out="$(printf 'show iox\n' | RUN 2>/dev/null)" || return 1
  printf '%s' "$out" | grep -q 'IOx service (CAF).*Running' \
    && printf '%s' "$out" | grep -q 'Dockerd.*Running'
}

wait_iox_ready() {  # $1=timeout_s
  local t=0
  while [ "$t" -lt "$1" ]; do
    if iox_ready; then
      return 0
    fi
    sleep 5; t=$((t + 5))
    echo "[$t s] waiting for IOx services"
  done
  return 1
}

app_state() {
  printf 'show app-hosting list\n' | RUN 2>/dev/null \
    | awk -v a="$APPID" '$1==a{print $2}'
}

LAST_APP_STATE=""
wait_state() {  # $1=target state, $2=timeout_s
  local t=0 s
  while [ "$t" -lt "$2" ]; do
    sleep "$STATE_POLL"; t=$((t + STATE_POLL)); s="$(app_state)"
    LAST_APP_STATE="$s"
    if [ -n "$s" ]; then
      echo "[$t s] $APPID: $s"
    else
      echo "[$t s] waiting for app: $APPID"
    fi
    [ "$s" = "$1" ] && return 0
  done
  return 1
}

clear_partial_app_config() {
  printf 'configure terminal\nno app-hosting appid %s\nend\n' "$APPID" \
    | RUN >/dev/null 2>&1 || true
}

if [ "$DRY" -eq 1 ]; then
  echo "network configuration: $MANAGEMENT_TYPE"
  ios_net
  echo "app configuration: $APPID"
  appid_block_redacted
  if [ -n "$SHARE_IOS_PATH" ]; then
    echo "create shared directory"
    echo "mkdir $SHARE_IOS_PATH"
  fi
  echo "upload package and certificate"
  printf 'scp -O <artifacts>/%s %s@%s:%s%s\n' "$PKG" '${DEVICE_USER}' "$DEVICE_IP" "$PKG_FS" "$PKG"
  printf 'scp -O <public-certificate> %s@%s:%s%s\n' '${DEVICE_USER}' "$DEVICE_IP" "$PKG_FS" "$CATALOG_CA_REMOTE"
  echo "signature policy: $PACKAGE_SIGNATURE_MODE (verification enabled for signed packages, disabled for unsigned)"
  echo "install, activate, copy certificate, start and save: $APPID"
  exit 0
fi

echo "[1/7] check prerequisites: $DEVICE_IP"
# 2026-08-20 incident: an IE-3400 lost `ip routing` on re-image; onboarding still
# reported success (app RUNNING) while the app's VLAN traffic had no L3 path out
# of the box — a silent, invisible failure the operator burned hours chasing.
# Catch that (and a missing IOx SD partition, and a clock so wrong TLS will
# fail) here, in plain language, before any config is touched. These checks are
# all read-only, so they run BEFORE the teardown below: a failing prerequisite
# on a re-onboard must leave the existing working app untouched.
if [ "$MANAGEMENT_TYPE" = "routed" ]; then
  # `ip routing` can be the platform DEFAULT (seen on IE3x00): then neither
  # `ip routing` nor `no ip routing` appears in the config, and grepping for
  # the positive line false-fails a healthy switch. Decide from authoritative
  # signals instead: an explicit `no ip routing` line, or the route table
  # answering in host mode (`Default gateway ...`), means disabled — while a
  # session that never echoes the command back is a TRANSPORT failure and
  # must not masquerade as a routing problem.
  routing_out="$(printf 'show running-config | include no ip routing\nshow ip route | include Gateway|Default gateway\n' | RUN 2>/dev/null || true)"
  if ! printf '%s\n' "$routing_out" | grep -q 'show running-config'; then
    echo "PREREQ: could not verify ip routing on $DEVICE_IP — the device session failed (check reachability and device credentials)" >&2
    exit 1
  fi
  if printf '%s\n' "$routing_out" | grep -qE '^no ip routing[[:space:]]*$' \
     || printf '%s\n' "$routing_out" | grep -qE '^Default gateway'; then
    echo "PREREQ: ip routing is disabled on this switch — the app network (VLAN $VLAN -> SVI $SVI_IP) cannot reach $STAGE_HOST. Enable it first:  configure terminal ; ip routing ; end ; write" >&2
    exit 1
  fi
fi
if [ "$TARGET_FS" = "sdflash:" ]; then
  storage_out="$(printf 'show sdflash: filesys\n' | RUN 2>/dev/null || true)"
  case "$storage_out" in
    *"IOx Partition Exists"*) : ;;
    *) echo "PREREQ: no IOx partition on the SD card — IOx apps need the SD formatted with an IOx partition on IE3x00" >&2
       exit 1 ;;
  esac
fi
clock_out="$(printf 'show clock\n' | RUN 2>/dev/null || true)"
# no four-digit year (odd format, probe hiccup) leaves clock_year empty and
# skips the warning — the grep must not be fatal under pipefail
clock_year="$(printf '%s' "$clock_out" | grep -oE '[0-9]{4}' | tail -1 || true)"
if [ -n "$clock_year" ] && [ "$clock_year" -lt 2024 ]; then
  echo "PREREQ WARNING: device clock is $clock_year — TLS certificate validation may fail; set the clock or NTP"
fi

echo "[2/7] remove existing app: $APPID"
printf 'app-hosting stop appid %s\napp-hosting deactivate appid %s\napp-hosting uninstall appid %s\n' \
  "$APPID" "$APPID" "$APPID" | RUN >/dev/null 2>&1 || true
sleep 6
printf 'configure terminal\nno app-hosting appid %s\nend\n' "$APPID" | RUN >/dev/null 2>&1 || true

echo "[3/7] configure networking: $MANAGEMENT_TYPE"
{ echo "configure terminal"; ios_net; } | RUN >/dev/null

# The share dir must exist BEFORE activation binds it into the container.
# Idempotent ("already exists" is fine; the blank line answers the "Create
# directory" prompt on boxes without `file prompt quiet` yet), but a real
# failure (missing/unwritable SSD) is WARNED, not silent — the agent's share
# probe will fall back to scp at runtime, and this line says why.
if [ -n "$SHARE_IOS_PATH" ]; then
  mk_out="$(printf 'mkdir %s\n\n' "$SHARE_IOS_PATH" | RUN 2>/dev/null || true)"
  case "$mk_out" in
    *%Error*|*Invalid*) echo "  WARN: mkdir $SHARE_IOS_PATH failed on the device:" \
      "$(printf '%s' "$mk_out" | grep -Eo '%Error[^\r]*|Invalid[^\r]*' | head -1)" \
      "— the agent will fall back to scp for image transfer" ;;
  esac
fi

echo "waiting for IOx services"
wait_iox_ready 180 || {
  echo "ERROR: IOx services not ready after 180 seconds; check 'show iox' and retry" >&2
  exit 1
}

if [ "$PACKAGE_SIGNATURE_MODE" = signed ]; then
  verification_action=enable
  verification_description="enable signature verification (signed package)"
else
  verification_action=disable
  verification_description="disable signature verification (unsigned package)"
fi
echo "[4/7] $verification_description"
# Even after `show iox` reports CAF/Dockerd Running, the app-hosting EXEC layer
# can still answer "The process for the command is not responding or is
# otherwise unavailable" for a few more seconds. Retry until it reports success
# so a not-yet-ready box doesn't leave verification enabled and fail the install.
vok=0
for _ in $(seq 1 24); do
  vout="$(printf 'app-hosting verification %s\n' "$verification_action" | RUN 2>/dev/null || true)"
  case "$verification_action:$vout" in
    disable:*"disabled successfully"*|disable:*"already disabled"*|disable:*"verification is disabled"*)
      vok=1; break ;;
    enable:*"enabled successfully"*|enable:*"already enabled"*|enable:*"verification is enabled"*)
      vok=1; break ;;
  esac
  sleep 5
done
[ "$vok" -eq 1 ] || { echo "  ERROR: could not $verification_action app-hosting signature verification (app-hosting not responding)" >&2; exit 1; }

scp_device() {
  # IOS-XE HTTP Basic requires URL credentials or persistent global client
  # credentials. Both leak an enrollment secret, so initial delivery uses the
  # already-authenticated device SSH boundary instead. -O selects the legacy
  # SCP protocol implemented by IOS. Host identity is pinned by the same policy
  # as lab/device-run.sh; sshpass reads DEVICE_PASS from the environment.
  # shellcheck source=lab/iris-ssh-policy.sh
  . "$HERE/../../lab/iris-ssh-policy.sh" || return 1
  iris_ssh_policy "$DEVICE_IP" || return 1
  local rc=0
  SSHPASS="$DEVICE_PASS" sshpass -e scp -O -o ConnectTimeout=15 \
    "${IRIS_SSH_OPTS[@]}" "$1" "${DEVICE_USER}@${DEVICE_IP}:$2" || rc=$?
  iris_ssh_cleanup
  return "$rc"
}

echo "[5/7] upload package and certificate"
printf 'delete /force %s%s\ndelete /force %s%s\n' \
  "$PKG_FS" "$PKG" "$PKG_FS" "$CATALOG_CA_REMOTE" | RUN >/dev/null 2>&1 || true
ok=0
for a in 1 2 3; do
  if scp_device "$PKG_FILE" "${PKG_FS}${PKG}" \
     && scp_device "$CATALOG_CA_FILE" "${PKG_FS}${CATALOG_CA_REMOTE}"; then
    ok=1; break
  fi
  echo "    SCP attempt $a/3 failed; retrying"; sleep 8
done
[ "$ok" -eq 1 ] || { echo "  ERROR: SCP push of package/certificate failed after 3 attempts" >&2; exit 1; }

echo "[6/7] install and start app: $APPID"
{ echo "configure terminal"; appid_block; } | RUN >/dev/null
install_out="$(printf 'app-hosting install appid %s package %s%s\n' "$APPID" "$PKG_FS" "$PKG" | RUN 2>&1 || true)"
# RUN redacts device secrets. Print only the IOS lifecycle response, not the
# interactive SSH prompt/command echo that surrounds it.
printf '%s\n' "$install_out" | grep -E 'Installing package|Failed to install|%IOX|%APP' || true
wait_state DEPLOYED "$INSTALL_TIMEOUT" || {
  echo "  ERROR: app installation did not reach DEPLOYED within $INSTALL_TIMEOUT seconds." >&2
  echo "         Last observed state: ${LAST_APP_STATE:-none reported}" >&2
  echo "         Full IOS response to 'app-hosting install appid $APPID':" >&2
  printf '%s\n' "$install_out" >&2
  echo "         Partial app configuration removed; retry onboarding." >&2
  clear_partial_app_config
  exit 1
}
sleep 8                                       # let the install op fully settle
activate_out="$(printf 'app-hosting activate appid %s\n' "$APPID" | RUN 2>&1 || true)"
printf '%s\n' "$activate_out" | grep -E 'Activating|Failed to activate|%IOX|%APP' || true
wait_state ACTIVATED "$ACTIVATE_TIMEOUT" || {
  echo "  ERROR: app activation did not reach ACTIVATED within $ACTIVATE_TIMEOUT seconds." >&2
  echo "         Last observed state: ${LAST_APP_STATE:-none reported}" >&2
  # UNFILTERED: the grep above keeps the success path readable, but when the
  # wait fails the swallowed lines are the whole diagnosis (device-run.sh has
  # already redacted the device secrets it knows).
  echo "         Full IOS response to 'app-hosting activate appid $APPID':" >&2
  printf '%s\n' "$activate_out" >&2
  echo "         Activation may still be running. Check 'show app-hosting list', then retry onboarding." >&2
  exit 1
}
# CAF mounts application storage during activation. DEPLOYED rejects file
# management on IE-3400; copy trust only after ACTIVATED, while the entrypoint
# has not yet run. A failed copy must never proceed to app start.
data_out="$(printf 'app-hosting data appid %s copy %s%s %s\n' \
  "$APPID" "$PKG_FS" "$CATALOG_CA_REMOTE" "$CATALOG_CA_REMOTE" | RUN 2>&1 || true)"
case "$data_out" in
  *"Successfully copied file"*)
    : ;;
  *)
    echo "  ERROR: could not deliver the catalog certificate to IOx application data." >&2
    echo "         Full IOS response to 'app-hosting data appid $APPID copy':" >&2
    printf '%s\n' "$data_out" >&2
    echo "         App not started; fix certificate delivery and retry." >&2
    exit 1 ;;
esac
start_out="$(printf 'app-hosting start appid %s\n' "$APPID" | RUN 2>&1 || true)"
printf '%s\n' "$start_out" | grep -E 'Starting|Failed to start|%IOX|%APP' || true
wait_state RUNNING "$START_TIMEOUT" || {
  echo "  ERROR: app start did not reach RUNNING within $START_TIMEOUT seconds." >&2
  echo "         Last observed state: ${LAST_APP_STATE:-none reported}" >&2
  echo "         Full IOS response to 'app-hosting start appid $APPID':" >&2
  printf '%s\n' "$start_out" >&2
  exit 1
}

echo "[7/7] save configuration"
save_out="$(printf 'copy running-config startup-config\n' | RUN 2>&1 || true)"
case "$save_out" in
  *"[OK]"*|*"bytes copied"*) : ;;
  *) echo "  ERROR: failed to save startup-config after onboarding:" >&2
     printf '%s\n' "$save_out" >&2
     exit 1 ;;
esac

echo "onboard complete: $DEVICE_IP"
