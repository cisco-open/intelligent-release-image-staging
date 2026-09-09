#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# One-shot IRIS device installer, driven from the operator's laptop.
# HARDWARE-VALIDATED sequence (C9300 17.18.03, 2026-06-10): bring a bare/clean
# device to a running agent that pulls its assigned image over the swarm, verifies
# it, and places it at flash root via native EEM. Distribute/stage ONLY — never
# install/activate/reload.
#
# Required env:
#   DEVICE_IP VLAN SVI_IP SVI_MASK GUEST_IP CATALOG_URL CATALOG_TOKEN DEVICE_ID
#   STAGE_HOST
# CATALOG_TOKEN is a SHORT-LIVED enrollment token; the agent self-promotes it to a
# full catalog token on its first tick. RPC_SECRET is NOT required (baked empty); the
# agent fetches it on that first token-refresh.
# Optional env (defaults):
#   GW_IP=$SVI_IP  CPU=1110 MEM=512 PERSIST=256
#   HOST_USER/HOST_PASS — required ONLY when STAGE_HOST is a REMOTE host (to ssh the
#     per-device conf there); NOT needed for --dry-run or when running on the stage host.
#   DEVICE_USER (device login user, required) + DEVICE_PASS — used by lab/device-run.sh; export or 'source' creds/.
#   BUNDLE=iris-agent.tgz  STAGE=/flash/guest-share/iris
#   IRIS_CRT_FILE — local path to the server's BARE cert (crt.pem, NOT the combined
#     cert.pem+key). Supplied by tools/gen-device-installers.sh. Used to (a) paste the
#     cert into the on-device PKI trustpoint IRIS and (b) `curl --cacert` the preflight.
#     Required for a real run; optional for --dry-run (the block is rendered either way).
#   SVI_IGP — routed mode only. `isis` adds `ip router isis` to the IRIS SVI so a
#     fabric running IS-IS (e.g. an SD-Access underlay) learns the IRIS subnet.
#     Default `none`: IRIS never injects its subnet into the operator's IGP, and
#     never creates a `router isis` process, unless the record says so.
#
# Routed mode touches the AppGig trunk ADDITIVELY (`switchport trunk allowed
# vlan add`), exactly like inband: the bare form REPLACES the allowed list and
# would drop every other IOx app's VLAN from the switch's single app-hosting
# uplink. Teardown removes only the IRIS VLAN from that list.
set -euo pipefail

: "${DEVICE_IP:?set DEVICE_IP}"
: "${CATALOG_URL:?set CATALOG_URL}"; : "${CATALOG_TOKEN:?set CATALOG_TOKEN}"
: "${DEVICE_ID:?set DEVICE_ID}"; : "${STAGE_HOST:?set STAGE_HOST}"
if [ -n "${NETWORK_ATTACHMENT:-}" ] && [ -z "${MANAGEMENT_TYPE:-}" ]; then
  echo "ERROR: NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE; refusing to fall back to the routed default" >&2
  exit 1
fi
MANAGEMENT_TYPE="${MANAGEMENT_TYPE:-routed}"
case "$MANAGEMENT_TYPE" in
  routed)
    : "${VLAN:?set VLAN}"; : "${SVI_IP:?set SVI_IP}"; : "${SVI_MASK:?set SVI_MASK}"; : "${GUEST_IP:?set GUEST_IP}"
    GW_IP="${GW_IP:-$SVI_IP}"
    SVI_IGP="${SVI_IGP:-none}"
    case "$SVI_IGP" in
      none|isis) ;;
      *) echo "ERROR: SVI_IGP must be 'none' or 'isis' (got '$SVI_IGP')" >&2; exit 1 ;;
    esac ;;
  inband)
    : "${INBAND_VLAN:?set INBAND_VLAN}"; : "${APP_IP:?set APP_IP}"; : "${APP_MASK:?set APP_MASK}"; : "${APP_GATEWAY:?set APP_GATEWAY}"
    VLAN="$INBAND_VLAN"; GUEST_IP="$APP_IP"; SVI_MASK="$APP_MASK"; GW_IP="$APP_GATEWAY" ;;
  *) echo "ERROR: MANAGEMENT_TYPE must be routed or inband" >&2; exit 1 ;;
esac
RPC_SECRET=""   # NOT baked: the agent fetches it on its first token-refresh
CPU="${CPU:-1110}"; MEM="${MEM:-512}"; PERSIST="${PERSIST:-256}"
HOST_USER="${HOST_USER:-}"; HOST_PASS="${HOST_PASS:-}"   # required only when STAGE_HOST is REMOTE (enforced at the ssh path below)
STAGE="${STAGE:-/flash/guest-share/iris}"
[[ "$STAGE" =~ ^/[A-Za-z0-9._/-]+$ ]] \
  && [[ "$STAGE" != *"//"* ]] && [[ "/$STAGE/" != *"/../"* ]] \
  && [[ "/$STAGE/" != *"/./"* ]] \
  || { echo "ERROR: STAGE must be a simple absolute Guest Shell path" >&2; exit 1; }
IRIS_CRT_FILE="${IRIS_CRT_FILE:-}"   # local path to the bare crt.pem (trustpoint + curl --cacert)
# the resolved guest-side path of the pinned CA after bootstrap.sh moves it in (spec §3.4/§4.5)
CATALOG_CA="${STAGE}/iris-catalog.pem"

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

# --- Model-aware config: the ONE place the install path branches by device ---
# Catalyst 9300 and IE-3x00 differ in (a) the app-hosting port, (b) the writable
# filesystem that backs the guestshell scratch — flash: on the 9300, the SD card
# sdflash: on the IE3k where IOx lives — and (c) the CPU arch of the bundled
# aria2c (x86 vs ARM). The guest-SIDE path stays /flash/guest-share on both
# (guestshell exposes the scratch there regardless of the IOS-side backing FS);
# only the IOS-side prefix changes. Detect the model from `show version` (the
# same lowercase "cisco <MODEL> (" anchor as flash_target.device_model); set
# MODEL= to preview a platform in --dry-run or to force one. Every derived value
# stays individually env-overridable.
MODEL="${MODEL:-}"
if [ -z "$MODEL" ] && [ "$DRY" -eq 0 ]; then
  MODEL="$(printf 'show version\n' | "$HERE/../lab/device-run.sh" "$DEVICE_IP" \
            | sed -nE 's/^cisco[[:space:]]+([^[:space:]]+)[[:space:]]+\(.*/\1/p' | head -1)"
fi
case "$(printf '%s' "$MODEL" | tr 'a-z' 'A-Z')" in
  IE-3*)  APP_INTF="${APP_INTF:-AppGigabitEthernet1/1}"   # IE-3x00 IOx port
          IOS_FS="${IOS_FS:-sdflash:}"                    # IOx/guestshell live on the SD card
          BUNDLE="${BUNDLE:-iris-agent-arm.tgz}" ;;       # ARM aria2c
  *)      APP_INTF="${APP_INTF:-AppGigabitEthernet1/0/1}" # Catalyst 9300 (default)
          IOS_FS="${IOS_FS:-flash:}"
          BUNDLE="${BUNDLE:-iris-agent.tgz}" ;;
esac
# STAGE is the GUEST-side path (/flash/...). IOS sees the same dir as <IOS_FS>guest-share/...
IOS_STAGE="${IOS_FS}${STAGE#/flash}"

# --- the IOS config we apply (networking + resources + file prompt + EEM timers) ---
# NOTE: IRIS-COPYROOT is NOT installed here — the agent templates+fires it at runtime
# (event syslog/$_arg1 proved unreliable on 17.18; the agent's cli.configure does it).
ios_config() {
if [ "$MANAGEMENT_TYPE" = "inband" ]; then
# Inband keeps the operator's network intact: no vlan/SVI/route/VRF/IS-IS. The
# ONE allowed touch is the AppGig trunk, and only ADDITIVELY — `allowed vlan add`
# never replaces the allowed list (the bare form would), and uninstall never
# removes it (the VLAN is operator-owned; other apps may ride the same trunk).
# Without it the app's traffic has no L2 path to the catalog.
cat <<EOF
iox
!
interface $APP_INTF
 switchport mode trunk
 switchport trunk allowed vlan add $VLAN
!
app-hosting appid guestshell
 app-vnic AppGigabitEthernet trunk
  vlan $VLAN guest-interface 0
   guest-ipaddress $GUEST_IP netmask $SVI_MASK
 app-default-gateway $GW_IP guest-interface 0
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
 action 200 cli command "guestshell run bash /flash/guest-share/bootstrap.sh"
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
 switchport trunk allowed vlan add $VLAN
!
interface Vlan$VLAN
 description IRIS Guest Shell inline GRT
 ip address $SVI_IP $SVI_MASK
EOF
[ "$SVI_IGP" = "isis" ] && echo " ip router isis"
cat <<EOF
 no shutdown
!
app-hosting appid guestshell
 app-vnic AppGigabitEthernet trunk
  vlan $VLAN guest-interface 0
   guest-ipaddress $GUEST_IP netmask $SVI_MASK
 app-default-gateway $GW_IP guest-interface 0
 app-resource profile custom
  cpu $CPU
  memory $MEM
  persist-disk $PERSIST
!
file prompt quiet
!
! suppress the %IM-4-IOX_INST_WARN logged on every 'guestshell run' (the agent polls 60s).
! NOTE: IOS caps logging-discriminator names at 8 chars — keep this name <= 8 chars.
logging discriminator IRISQ mnemonics drops IOX_INST_WARN
logging buffered discriminator IRISQ
logging console discriminator IRISQ
logging monitor discriminator IRISQ
!
! single 60s timer running the BOOTSTRAP: it unpacks a freshly dropped bundle.tgz
! (= automatic install/upgrade), keeps aria2c up, then runs the agent once.
event manager applet IRIS-AGENT authorization bypass
 event timer watchdog time 60 maxrun 900
 action 100 cli command "enable"
 action 200 cli command "guestshell run bash /flash/guest-share/bootstrap.sh"
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
rpc_secret = $RPC_SECRET
catalog_ca = $CATALOG_CA
telemetry = ${TELEMETRY:-on}
telemetry_stream = ${TELEMETRY_STREAM:-off}
token_expires_at = 0
agent_version = $(cat "$HERE/../VERSION" 2>/dev/null || echo unknown)
EOF
[ -z "${PRESERVED_LKG_KEY:-}" ] || printf 'lkg_key = %s\n' "$PRESERVED_LKG_KEY"
}

# --- the PKI trustpoint that lets `copy https:` validate the self-signed server cert ---
# Pasted over the EXISTING SSH session BEFORE any copy (non-circular: trust arrives via
# SSH, bulk transfer rides the HTTPS that SSH just authorized — spec §3.7/§4.2).
# Idempotent: `no crypto pki trustpoint IRIS` first clears any prior cert, then re-add +
# re-authenticate, so re-running the installer = cert rotation. revocation-check none
# because a self-signed cert has no CRL/OCSP DP. We paste the BARE crt.pem (never the key).
# In --dry-run with no IRIS_CRT_FILE we still render the structure (PEM shown as a note)
# so the off-box bats gate can assert the block + that NO `copy http://` remains.
trustpoint_block() {
  # HARDWARE-VALIDATED (C9300 17.x): BOTH the trustpoint removal (when a cert is already
  # enrolled — i.e. re-install) and `crypto pki authenticate` (after the pasted cert)
  # prompt "...? [yes/no]:". Each MUST be answered with a `yes` line, or the CA import
  # silently fails ("Issuing CA authenticated: No") and every later `copy https:` dies
  # with "Connection failure". On a FIRST install the leading `yes` is a harmless no-op
  # ("% Invalid input" in config mode, then it continues).
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
    echo "! <contents of \$IRIS_CRT_FILE (the bare crt.pem) inserted here at apply time>"
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
  IOS_ROOT="${IOS_FS}/guest-share"
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
  echo "===== Save startup-config ====="
  echo "copy running-config startup-config"
  exit 0
fi

ssh_host() {                       # run a command on STAGE_HOST
  # password via env (sshpass -e), never argv — argv is world-readable in /proc.
  # The stage host receives the per-device enrollment token, so its identity
  # is verified like a device's: lab/iris-ssh-policy.sh (IRIS_SSH_KNOWN_HOSTS /
  # IRIS_SSH_HOST_KEY / persistent accept-new), never /dev/null.
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
  # $1 path, $2 maximum bytes. Symlinks are never accepted as trust or
  # capability inputs, even when their target is a regular file.
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  local _size
  _size="$(wc -c < "$1" 2>/dev/null | tr -d '[:space:]')"
  case "$_size" in ''|*[!0-9]*) return 1 ;; esac
  [ "$_size" -gt 0 ] && [ "$_size" -le "$2" ]
}

validate_and_stage_local_artifacts() {
  local _bundle _sidecar _signers _envelope _expected _actual _digest _tmp
  _bundle="$ART/$BUNDLE"
  _sidecar="$_bundle.sha256"
  _signers="$ART/iris-signers.pem"
  _envelope="$ART/staging/$INSTRUCTION_ENVELOPE"
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
  regular_bounded_file "$_signers" 65536 \
    || { echo "ERROR: iris-signers.pem is missing or invalid" >&2; return 1; }
  regular_bounded_file "$_envelope" 262144 \
    || { echo "ERROR: instruction bootstrap artifact is missing or invalid" >&2; return 1; }

  _digest="$ART/staging/$BUNDLE_DIGEST_FILE"
  _tmp="$ART/staging/.$BUNDLE_DIGEST_FILE.$$"
  (umask 077; printf '%s\n' "$_actual" > "$_tmp") \
    && mv -f "$_tmp" "$_digest" \
    || { rm -f "$_tmp" 2>/dev/null || true
         echo "ERROR: could not materialize bundle digest capability" >&2; return 1; }
}

validate_and_stage_remote_artifacts() {
  # All interpolated names have already passed the closed DEVICE_ID/CAP grammar.
  # Exit codes keep diagnostics fixed and prevent remote paths or bytes from
  # entering the operator transcript.
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
  local _app _probe
  _app="$(printf 'show app-hosting list\n' \
    | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null \
    | grep -i guestshell || true)"
  [ -n "$_app" ] || return 0
  case "$_app" in
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
# One SSH login for all three read-only pre-checks (flash free space, ip
# routing, device clock) instead of up to three -- same consolidation as
# _default_router_preflight in server/gui_onboard.py. IOS XE echoes these
# markers verbatim. The flash pre-check and clock check stay best-effort /
# informational, exactly as before a missing section there is silently
# skipped, never fatal. ip routing keeps its HARD fail-closed semantics: a
# missing ROUTING section (the session never echoed anything back) is a
# TRANSPORT failure and must not masquerade as, or be silently read as, a
# routing problem -- see the PREREQ checks below.
PRECHECK_MARKER="__IRIS_PRECHECK_"
precheck_request() {
cat <<EOF
echo ${PRECHECK_MARKER}FLASH__
dir flash: | include bytes free
EOF
if [ "$MANAGEMENT_TYPE" = "routed" ]; then
cat <<EOF
echo ${PRECHECK_MARKER}ROUTING__
show running-config | include no ip routing
show ip route | include Gateway|Default gateway
EOF
fi
cat <<EOF
echo ${PRECHECK_MARKER}CLOCK__
show clock
EOF
}
precheck_section() {
  python3 -c 'import re, sys
marker = "__IRIS_PRECHECK_"
name = sys.argv[1]
text = sys.stdin.read()
start = marker + name + "__"
match = re.search(re.escape(start) + r"\r?\n?(.*?)(?=" + re.escape(marker) + r"[A-Z_]+__|\Z)", text, re.DOTALL)
if not match:
    sys.exit(1)
sys.stdout.write(match.group(1))' "$1"
}
PRECHECK_OUT="$(precheck_request | "$HERE/../lab/device-run.sh" "$DEVICE_IP" || true)"
FLASH_RAW="$(printf '%s' "$PRECHECK_OUT" | precheck_section FLASH)" || true
printf '%s\n' "$FLASH_RAW" | grep -i 'bytes free' || true

echo "check routing and device clock"
# 2026-08-20 incident: an IE-3400 lost `ip routing` on re-image; onboarding still
# reported success (agent running) while the app's VLAN traffic had no L3 path
# out of the box — a silent, invisible failure the operator burned hours
# chasing. Catch that (and a clock so wrong TLS will fail) here, in plain
# language, before any config is touched. Only the routed path creates an
# IRIS-managed SVI that depends on global routing; inband rides the operator's
# own already-routed network.
if [ "$MANAGEMENT_TYPE" = "routed" ]; then
  # `ip routing` can be the platform DEFAULT (seen on IE3x00): then neither
  # `ip routing` nor `no ip routing` appears in the config, and grepping for
  # the positive line false-fails a healthy switch. Decide from authoritative
  # signals instead: an explicit `no ip routing` line, or the route table
  # answering in host mode (`Default gateway ...`), means disabled — while a
  # ROUTING section missing from the response entirely is a TRANSPORT failure
  # (the session never echoed anything back) and must not masquerade as a
  # routing problem.
  ROUTING_RAW="$(printf '%s' "$PRECHECK_OUT" | precheck_section ROUTING)" \
    || { echo "PREREQ: could not verify ip routing on $DEVICE_IP — the device session failed (check reachability and device credentials)" >&2; exit 1; }
  if printf '%s\n' "$ROUTING_RAW" | grep -qE '^no ip routing[[:space:]]*$' \
     || printf '%s\n' "$ROUTING_RAW" | grep -qE '^Default gateway'; then
    echo "PREREQ: ip routing is disabled on this switch — the app network (VLAN $VLAN -> SVI $SVI_IP) cannot reach $STAGE_HOST. Enable it first:  configure terminal ; ip routing ; end ; write" >&2
    exit 1
  fi
fi
CLOCK_RAW="$(printf '%s' "$PRECHECK_OUT" | precheck_section CLOCK)" || true
# no four-digit year (odd format, probe hiccup) leaves clock_year empty and
# skips the warning — the grep must not be fatal under pipefail
clock_year="$(printf '%s' "$CLOCK_RAW" | grep -oE '[0-9]{4}' | tail -1 || true)"
if [ -n "$clock_year" ] && [ "$clock_year" -lt 2024 ]; then
  echo "PREREQ WARNING: device clock is $clock_year — TLS certificate validation may fail; set the clock or NTP"
fi

echo "[2/6] prepare agent configuration"
ART="${IRIS_ARTIFACTS_DIR:-$(cd "$HERE/.." && pwd)/artifacts}"
# the agent's pinned CA = the SAME bare crt.pem; served as the fifth artifact and
# pulled over the now-trusted HTTPS (a runtime convenience copy — trust itself
# arrived earlier over SSH in the trustpoint paste, so this is non-circular).
: "${IRIS_CRT_FILE:?set IRIS_CRT_FILE — local path to the bare server cert crt.pem (the generator supplies it)}"
[ -r "$IRIS_CRT_FILE" ] || { echo "  ERROR: IRIS_CRT_FILE=$IRIS_CRT_FILE is not readable" >&2; exit 1; }
STAGE_LOCAL=0
if [ "${IRIS_STAGE_LOCAL:-0}" = "1" ] \
    || ip -o addr 2>/dev/null | grep -qw "$STAGE_HOST" \
    || [ "$STAGE_HOST" = "localhost" ]; then
  STAGE_LOCAL=1
fi
if [ "$STAGE_LOCAL" -eq 1 ]; then
  # we ARE the stage host — write directly, no ssh needed
  mkdir -p "$ART/staging"
  [ -d "$ART/staging" ] && [ ! -L "$ART/staging" ] \
    || { echo "ERROR: artifact staging directory is invalid" >&2; exit 1; }
  validate_and_stage_local_artifacts || exit 1
else
  : "${HOST_USER:?set HOST_USER (source creds/, or export it directly) — needed to ssh to remote STAGE_HOST $STAGE_HOST}"
  : "${HOST_PASS:?set HOST_PASS (source creds/, or export it directly) — needed to ssh to remote STAGE_HOST $STAGE_HOST}"
  validate_and_stage_remote_artifacts || exit 1
fi

# These probes are read-only and occur only after every required artifact has
# been validated. Preserve the device-local instruction LKG key when replacing
# the enrollment configuration, and refuse a legacy stage Guest Shell cannot
# write instead of deleting that directory and its runnable state.
PRESERVED_LKG_KEY=""
read_preserved_lkg_key
check_existing_stage_writable || exit 1

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
  # static served files are normally provisioned at container startup by
  # server/provision-served.sh (or by tools/make-agent-bundle.sh); the
  # copy-if-absent below also covers CLI runs from a stage host.
  [ -e "$ART/bootstrap.sh" ]     || cp "$HERE/bootstrap.sh" "$ART/bootstrap.sh"
  [ -e "$ART/iris-catalog.pem" ] || cp "$IRIS_CRT_FILE" "$ART/iris-catalog.pem"
else
  agent_conf | ssh_host "set -eu; umask 077; d=\$HOME/iris/artifacts/staging; c=\$d/.$CONF.\$\$; r=\$d/.$RPC_SECRET_FILE.\$\$; trap 'rm -f \"\$c\" \"\$r\"' EXIT HUP INT TERM; cat > \"\$c\"; printf '%s\n' '$RPC_SECRET' > \"\$r\"; mv -f \"\$c\" \"\$d/$CONF\"; mv -f \"\$r\" \"\$d/$RPC_SECRET_FILE\""
  ssh_host "cat > ~/iris/artifacts/iris-catalog.pem" < "$IRIS_CRT_FILE"
fi

echo "[3/6] configure IRIS ($MANAGEMENT_TYPE)"
{ echo "configure terminal"; ios_config; } | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null

# HARDWARE-LEARNED (C9300, 2026-07-04): <fs>guest-share must exist BEFORE
# `guestshell enable` — IOx binds the host dir into the guest at DEPLOY time.
# If it is missing then, the guest gets a permanent empty orphan dir instead:
# every later IOS-side copy lands invisibly and bootstrap never sees a file
# (fresh boxes, or re-onboarding after an undeploy that removed guest-share).
# Root-owned is fine for the ROOT (IOS does the copies, the guest only reads
# and creates its own subdir). Idempotent: "already exists" is swallowed. The
# blank line answers the "Create directory" prompt on boxes that don't have
# `file prompt quiet` applied yet ([3/6] has, but belt-and-braces).
printf 'mkdir %sguest-share\n\n' "$IOS_FS" | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true

echo "[4/6] start Guest Shell (may take several minutes)"
for i in $(seq 1 30); do
  state="$(printf 'show app-hosting list\n' | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null | grep -i guestshell || true)"
  case "$state" in
    *RUNNING*) echo "  guestshell RUNNING"; break ;;
  esac
  # (re)issue enable every few polls — harmless if already deploying, and IOx
  # rejects it with "process not responding" until it has finished cold-starting
  if [ $(( (i - 1) % 5 )) -eq 0 ]; then
    printf 'guestshell enable\n' | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true
  fi
  if [ "$i" -eq 30 ]; then
    echo "  ERROR: guestshell not RUNNING after ~7 minutes" >&2; exit 1
  fi
  sleep 15
done

echo "[5/6] copy certificate and agent files"
# Trust-anchor distribution: paste the bare server cert into trustpoint IRIS and
# select it as the HTTP client's secure trustpoint, over the EXISTING SSH session,
# BEFORE any `copy https:`. Idempotent (no-then-re-add). Non-circular by construction
# (spec §3.7/§4.2). The `quit` ends the terminal cert paste.
{ echo "configure terminal"; trustpoint_block; echo "end"; } \
  | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null
# everything device-side from here is AUTOMATIC: the IRIS-AGENT timer runs
# bootstrap.sh, which unpacks the bundle, starts aria2c, and runs the agent.
# preflight over VERIFIED https: is the artifact server serving, and does its cert
# validate against the SAME bare crt.pem we just trusted?

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
  echo "  Is the server container up, did you run tools/make-agent-bundle.sh, and is IRIS_CRT_FILE the server's crt.pem?" >&2
  exit 1
fi
# IMPORTANT: files go to the guest-share ROOT, not a subdirectory. Preserve the
# live Guest Shell work directory and its LKG/runtime state. Only stale incoming
# archive evidence at the root is safe to clear before the ordered copy.
IOS_ROOT="${IOS_FS}/guest-share"
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
    # capture THEN match — `grep -q` on a live pipe SIGPIPEs ssh at first match
    # and (with pipefail) falsely reports a successful copy as failed.
    # https:// (not http://) — the trustpoint configured above lets IOS validate
    # the server cert; the credentials in iris-agent.conf/rpc-secret no longer
    # travel in cleartext.
    out="$(printf 'copy https://%s:8000/%s %s/%s\n' "$STAGE_HOST" "$src" "$IOS_ROOT" "$dst" \
            | "$HERE/../lab/device-run.sh" "$DEVICE_IP" || true)"
    case "$out" in *"bytes copied"*) ok=1; break ;; esac
    echo "  copy of $src failed (attempt $attempt/3), retrying..."
    sleep 10
  done
  [ "$ok" -eq 1 ] || { echo "  ERROR: copy of $src failed after 3 attempts" >&2; exit 1; }
done

echo "[6/6] save startup-config"
save_out="$(printf 'copy running-config startup-config\n' \
           | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>&1 || true)"
case "$save_out" in
  *"[OK]"*|*"bytes copied"*) echo "  startup-config saved" ;;
  *) echo "  ERROR: failed to save startup-config after onboarding:" >&2
     printf '%s\n' "$save_out" >&2
     exit 1 ;;
esac

echo "onboard complete: $DEVICE_IP"
