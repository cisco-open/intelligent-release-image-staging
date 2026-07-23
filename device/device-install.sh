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
set -euo pipefail

: "${DEVICE_IP:?set DEVICE_IP}"; : "${VLAN:?set VLAN}"
: "${SVI_IP:?set SVI_IP}"; : "${SVI_MASK:?set SVI_MASK}"; : "${GUEST_IP:?set GUEST_IP}"
: "${CATALOG_URL:?set CATALOG_URL}"; : "${CATALOG_TOKEN:?set CATALOG_TOKEN}"
: "${DEVICE_ID:?set DEVICE_ID}"; : "${STAGE_HOST:?set STAGE_HOST}"
RPC_SECRET=""   # NOT baked: the agent fetches it on its first token-refresh
GW_IP="${GW_IP:-$SVI_IP}"; CPU="${CPU:-1110}"; MEM="${MEM:-512}"; PERSIST="${PERSIST:-256}"
HOST_USER="${HOST_USER:-}"; HOST_PASS="${HOST_PASS:-}"   # required only when STAGE_HOST is REMOTE (enforced at the ssh path below)
STAGE="${STAGE:-/flash/guest-share/iris}"
IRIS_CRT_FILE="${IRIS_CRT_FILE:-}"   # local path to the bare crt.pem (trustpoint + curl --cacert)
# the resolved guest-side path of the pinned CA after bootstrap.sh moves it in (spec §3.4/§4.5)
CATALOG_CA="${STAGE}/iris-catalog.pem"

HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

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
  MODEL="$(printf 'show version\n' | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>/dev/null \
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
 description IRIS Guest Shell inline GRT
 ip address $SVI_IP $SVI_MASK
 ip router isis
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
token_expires_at = 0
EOF
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
  echo "===== IOS CONFIG (apply via lab/device-run.sh $DEVICE_IP) ====="; ios_config
  echo "===== PKI TRUSTPOINT (pasted over SSH FIRST, before any copy) ====="; trustpoint_block
  echo "===== AGENT CONFIG (staged on $STAGE_HOST:8000 (https), copied to $STAGE/iris-agent.conf) ====="; agent_conf
  echo "===== INSTALL COPIES (over verified https) ====="
  IOS_ROOT="${IOS_FS}/guest-share"
  for pair in "bootstrap.sh:bootstrap.sh" "staging/iris-agent-$DEVICE_ID.conf:iris-agent.conf" \
              "staging/rpc-secret:rpc-secret" "$BUNDLE:bundle.tgz" \
              "iris-catalog.pem:iris-catalog.pem"; do
    src="${pair%%:*}"; dst="${pair##*:}"
    printf 'copy https://%s:8000/%s %s/%s\n' "$STAGE_HOST" "$src" "$IOS_ROOT" "$dst"
  done
  echo "===== guestshell enable + stage $BUNDLE + launch aria2c (see script) ====="
  echo "===== PERSIST: copy running-config startup-config (after successful onboarding) ====="
  exit 0
fi

ssh_host() {                       # run a command on STAGE_HOST
  # password via env (sshpass -e), never argv — argv is world-readable in /proc
  SSHPASS="$HOST_PASS" sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR "$HOST_USER@$STAGE_HOST" "$@"
}

echo "[1/6] flash pre-check on $DEVICE_IP"
printf 'dir flash: | include bytes free\n' | "$HERE/../lab/device-run.sh" "$DEVICE_IP" | grep -i 'bytes free' || true

echo "[2/6] stage per-device agent config into artifacts/ (served on :8000 by the container)"
CONF="iris-agent-$DEVICE_ID.conf"
ART="${IRIS_ARTIFACTS_DIR:-$(cd "$HERE/.." && pwd)/artifacts}"
# the agent's pinned CA = the SAME bare crt.pem; served as the fifth artifact and
# pulled over the now-trusted HTTPS (a runtime convenience copy — trust itself
# arrived earlier over SSH in the trustpoint paste, so this is non-circular).
: "${IRIS_CRT_FILE:?set IRIS_CRT_FILE — local path to the bare server cert crt.pem (the generator supplies it)}"
[ -r "$IRIS_CRT_FILE" ] || { echo "  ERROR: IRIS_CRT_FILE=$IRIS_CRT_FILE is not readable" >&2; exit 1; }
if [ "${IRIS_STAGE_LOCAL:-0}" = "1" ] || ip -o addr 2>/dev/null | grep -qw "$STAGE_HOST" || [ "$STAGE_HOST" = "localhost" ]; then
  # we ARE the stage host — write directly, no ssh needed
  mkdir -p "$ART/staging"
  agent_conf > "$ART/staging/$CONF"
  printf '%s\n' "$RPC_SECRET" > "$ART/staging/rpc-secret"
  # static served files are normally provisioned at container startup by
  # server/provision-served.sh (or by tools/make-agent-bundle.sh on bare
  # metal); the copy-if-absent is a fallback for bare-metal runs only.
  [ -e "$ART/bootstrap.sh" ]     || cp "$HERE/bootstrap.sh" "$ART/bootstrap.sh"
  [ -e "$ART/iris-catalog.pem" ] || cp "$IRIS_CRT_FILE" "$ART/iris-catalog.pem"
else
  : "${HOST_USER:?set HOST_USER (source creds/, or Console: Settings → Stage host) — needed to ssh to remote STAGE_HOST $STAGE_HOST}"
  : "${HOST_PASS:?set HOST_PASS (source creds/, or Console: Settings → Stage host) — needed to ssh to remote STAGE_HOST $STAGE_HOST}"
  agent_conf | ssh_host "mkdir -p ~/iris/artifacts/staging && cat > ~/iris/artifacts/staging/$CONF && printf '%s\n' '$RPC_SECRET' > ~/iris/artifacts/staging/rpc-secret"
  ssh_host "cat > ~/iris/artifacts/iris-catalog.pem" < "$IRIS_CRT_FILE"
fi

echo "[3/6] apply IOS config (IOx, VLAN $VLAN, Vlan$VLAN SVI, app-hosting, file prompt, EEM timers)"
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

echo "[4/6] guestshell enable (IOx cold start can take several minutes on a fresh device)"
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

echo "[5/6] push PKI trustpoint over SSH (FIRST), then drop files over verified https"
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
if ! curl -sf -o /dev/null --max-time 5 --cacert "$IRIS_CRT_FILE" "https://$STAGE_HOST:8000/bootstrap.sh"; then
  echo "  ERROR: https://$STAGE_HOST:8000/bootstrap.sh is not reachable / not trusted." >&2
  echo "  Is the server container up, did you run tools/make-agent-bundle.sh, and is IRIS_CRT_FILE the server's crt.pem?" >&2
  exit 1
fi
# IMPORTANT: files go to the guest-share ROOT, not a subdirectory. A dir made by
# IOS `mkdir` is root-owned and the guest user cannot write inside it; the
# bootstrap (running as the guest user) creates the working dir itself and moves
# these files in. Also remove any stale root-owned working dir from older installs.
printf 'delete /force /recursive %s\n' "$IOS_STAGE" | "$HERE/../lab/device-run.sh" "$DEVICE_IP" >/dev/null 2>&1 || true
IOS_ROOT="${IOS_FS}/guest-share"
for pair in "bootstrap.sh:bootstrap.sh" "staging/$CONF:iris-agent.conf" \
            "staging/rpc-secret:rpc-secret" "$BUNDLE:bundle.tgz" \
            "iris-catalog.pem:iris-catalog.pem"; do
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

echo "[6/7] persist successful onboarding to startup-config"
save_out="$(printf 'copy running-config startup-config\n' \
           | "$HERE/../lab/device-run.sh" "$DEVICE_IP" 2>&1 || true)"
case "$save_out" in
  *"[OK]"*|*"bytes copied"*) echo "  startup-config saved" ;;
  *) echo "  ERROR: failed to save startup-config after onboarding:" >&2
     printf '%s\n' "$save_out" >&2
     exit 1 ;;
esac

echo "[7/7] done. Within ~60s the IRIS-AGENT timer bootstraps the agent (unpack bundle,"
echo "      start aria2c), pulls '$DEVICE_ID's assigned image, verifies it, and places"
echo "      it at flash root via native EEM. Watch with:"
echo "      printf 'show logging | include IRIS\\n' | lab/device-run.sh $DEVICE_IP"
