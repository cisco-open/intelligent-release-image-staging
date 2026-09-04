#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Onboard the IRIS agent onto a Cisco 8000-series IOS-XR router as an appmgr
# Docker application. IRIS stages images only; this script never installs,
# activates, reloads, or changes boot -- staging on this platform means the
# agent container itself, bind-mounted straight onto harddisk: (see
# agentinfo/xr-support/LAB-RESULTS-2026-08-27.md, the 2026-08-28 addendum:
# write-through is hardware-proven, so there is no separate placement step
# the way every IOS-XE recipe here needs one).
#
# Delivery rides the OTHER hardware-proven path from that same addendum: an
# scp PUSH of the pre-built iris-xr.rpm straight to /harddisk:/, from a local
# file this script reads directly (no PKI trustpoint dance, no `copy https:`
# -- those are IOS-XE machinery this platform simply does not need. Catalog
# TLS is verified INSIDE the container against the current public certificate
# this installer places on harddisk: beside the RPM.  The canonical image is
# therefore deployment-neutral and can remain signed. This script is the console-drivable
# shape: DEVICE_IP/CATALOG_URL/CATALOG_TOKEN/DEVICE_ID/DEVICE_USER/DEVICE_PASS
# are the fields the onboarding service supplies. The split console/server
# deployment passes a host-mounted local artifacts directory explicitly;
# this installer never assumes the console shares the artifact-server
# container filesystem.
#
# IOS-XR has no separate "persist to startup" step the way classic IOS does:
# `commit` IS the persisted state (there is no running-config/startup-config
# split to bridge with a `copy running-config startup-config`), so this
# script never issues one.
#
# Required env:
#   DEVICE_IP CATALOG_URL CATALOG_TOKEN DEVICE_ID
#   DEVICE_USER DEVICE_PASS  -- device login (admin, never the IOS-XE 'dnac'
#     default); used by lab/xr-run.sh and this script's own scp push
# Optional env (defaults):
#   APPID=iris  SOURCE_NAME=iris-xr
#   IRIS_ARTIFACTS_DIR=<repo>/artifacts  XR_RPM_FILE=$IRIS_ARTIFACTS_DIR/iris-xr.rpm
#   IRIS_CRT_FILE=$IRIS_ARTIFACTS_DIR/iris-catalog.pem (public server cert)
#   XR_MIN_FREE_BYTES=2147483648 (2 GiB headroom floor on harddisk: -- raise
#     it for a larger assigned image set; one proven full image is 1.8GB)
#   IRIS_TELEMETRY=on  IRIS_TELEMETRY_STREAM=off
#   IRIS_LOG=off -- device-side aria2c.log opt-in (see device/container/entrypoint.sh);
#     off by default for flash write endurance. Forwarded verbatim as --env
#     IRIS_LOG so the container the agent runs in actually sees an operator's
#     opt-in -- previously this script dropped it silently and the entrypoint's
#     own default always won. Does not affect the %IRIS-6-<MNEMONIC> lines
#     emit() writes to this container's stdout; those are bounded separately,
#     below, by the docker-run-opts log-driver options.
#   MODEL -- hardware model from the fleet row, when known (same env contract
#     as DEVICE_ID; server/gui_onboard.py's OnboardService._build_env sets it).
#     Forwarded verbatim as IRIS_MODEL so heartbeats report it. The running
#     software version needs no such env: this script parses it itself, in
#     [1/5] below, from the same "show version" preflight probe that
#     classifies the box as IOS-XR.
#   ACTIVATE_TIMEOUT=300  ACTIVATE_POLL=10  (seconds; the appmgr application-table poll)
set -euo pipefail

: "${DEVICE_IP:?set DEVICE_IP}"
: "${CATALOG_URL:?set CATALOG_URL}"; : "${CATALOG_TOKEN:?set CATALOG_TOKEN}"
: "${DEVICE_ID:?set DEVICE_ID}"

APPID="${APPID:-iris}"
SOURCE_NAME="${SOURCE_NAME:-iris-xr}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

IRIS_ARTIFACTS_DIR="${IRIS_ARTIFACTS_DIR:-$(cd "$HERE/.." && pwd)/artifacts}"
XR_RPM_FILE="${XR_RPM_FILE:-$IRIS_ARTIFACTS_DIR/iris-xr.rpm}"
CATALOG_CA_FILE="${IRIS_CATALOG_CA_FILE:-${IRIS_CRT_FILE:-$IRIS_ARTIFACTS_DIR/iris-catalog.pem}}"
# One proven full image is 1.8GB (agentinfo/xr-support/LAB-RESULTS-2026-08-27.md
# section 1.4); 2 GiB is a same-order-of-magnitude floor for a single image.
# Raise it explicitly for a multi-image assignment.
XR_MIN_FREE_BYTES="${XR_MIN_FREE_BYTES:-2147483648}"
IRIS_TELEMETRY="${IRIS_TELEMETRY:-on}"
IRIS_TELEMETRY_STREAM="${IRIS_TELEMETRY_STREAM:-off}"
# Same fail-closed default as device/container/entrypoint.sh's IRIS_LOG parsing
# -- this is only the plumbing that lets an operator's opt-in actually reach
# it; the default stays off either way.
IRIS_LOG="${IRIS_LOG:-off}"
ACTIVATE_TIMEOUT="${ACTIVATE_TIMEOUT:-300}"
ACTIVATE_POLL="${ACTIVATE_POLL:-10}"

# The three values below ride inside a single double-quoted CLI token
# (docker-run-opts "..."); a literal double-quote or newline in any of them
# would break out of that token or splice in extra config lines. Reject
# early with a clear message instead of sending the device a malformed
# config line.
_no_quotes_or_newlines() {
  case "$2" in
    *'"'*|*$'\n'*|*$'\r'*)
      echo "ERROR: $1 must not contain a double quote, CR, or LF" >&2
      exit 1 ;;
  esac
  case "$2" in *[[:space:]]*)
    echo "ERROR: $1 contains whitespace, which would split the quoted docker-run-opts string" >&2
    exit 1 ;;
  esac
}

_safe_name() {
  _no_quotes_or_newlines "$1" "$2"
  [[ "$2" =~ ^[A-Za-z][A-Za-z0-9._-]*$ ]] \
    || { echo "ERROR: $1 contains unsafe characters" >&2; exit 2; }
}

_safe_fact() {
  _no_quotes_or_newlines "$1" "$2"
  [ -z "$2" ] || [[ "$2" =~ ^[A-Za-z0-9][A-Za-z0-9._+:/-]*$ ]] \
    || { echo "ERROR: $1 contains unsafe characters" >&2; exit 2; }
}

_boolean() {
  _no_quotes_or_newlines "$1" "$2"
  case "$2" in on|off|1|0|true|false|yes|no|ON|OFF|TRUE|FALSE|YES|NO) ;;
    *) echo "ERROR: $1 has an invalid boolean value" >&2; exit 2 ;;
  esac
}

_uint_between() {
  local name="$1" value="$2" minimum="$3" maximum="$4"
  [[ "$value" =~ ^[0-9]+$ ]] && [ "${#value}" -le "${#maximum}" ] \
    || { echo "ERROR: $name must be an integer from $minimum to $maximum" >&2; exit 2; }
  [ "$value" -ge "$minimum" ] && [ "$value" -le "$maximum" ] \
    || { echo "ERROR: $name must be an integer from $minimum to $maximum" >&2; exit 2; }
}

_https_url() {
  local name="$1" value="$2"
  _no_quotes_or_newlines "$name" "$value"
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

_no_quotes_or_newlines CATALOG_URL "$CATALOG_URL"
_no_quotes_or_newlines CATALOG_TOKEN "$CATALOG_TOKEN"
_no_quotes_or_newlines DEVICE_ID "$DEVICE_ID"
# MODEL: optional, set by the caller's env contract the same way DEVICE_ID is
# (server/gui_onboard.py's OnboardService._build_env exports it from the
# fleet row when known). Forwarded to the container so XR heartbeats report a
# real model instead of the "no CLI to ask" default -- see xr_deps.py.
_no_quotes_or_newlines MODEL "${MODEL:-}"
# IRIS_LOG rides the same quoted docker-run-opts token as everything else
# above; reuse the one guard rather than trusting a bare on/off-shaped value.
_no_quotes_or_newlines IRIS_LOG "$IRIS_LOG"
_https_url CATALOG_URL "$CATALOG_URL"
[[ "$CATALOG_TOKEN" =~ ^[A-Za-z0-9._~+/-]+=*$ ]] \
  || { echo "ERROR: CATALOG_TOKEN contains unsafe characters" >&2; exit 2; }
[[ "$DEVICE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] \
  || { echo "ERROR: DEVICE_ID contains unsafe characters" >&2; exit 2; }
[[ "$DEVICE_IP" =~ ^[A-Za-z0-9._:-]+$ ]] \
  || { echo "ERROR: DEVICE_IP is not a safe SSH host" >&2; exit 2; }
_safe_name APPID "$APPID"
_safe_name SOURCE_NAME "$SOURCE_NAME"
_safe_fact MODEL "${MODEL:-}"
_boolean IRIS_TELEMETRY "$IRIS_TELEMETRY"
_boolean IRIS_TELEMETRY_STREAM "$IRIS_TELEMETRY_STREAM"
_boolean IRIS_LOG "$IRIS_LOG"
_uint_between XR_MIN_FREE_BYTES "$XR_MIN_FREE_BYTES" 1 999999999999999
_uint_between ACTIVATE_TIMEOUT "$ACTIVATE_TIMEOUT" 1 86400
_uint_between ACTIVATE_POLL "$ACTIVATE_POLL" 1 3600
case "$XR_RPM_FILE" in /*) ;; *) echo "ERROR: XR_RPM_FILE must be an absolute path" >&2; exit 2 ;; esac
case "$XR_RPM_FILE" in *$'\n'*|*$'\r'*) echo "ERROR: XR_RPM_FILE must be a single line" >&2; exit 2 ;; esac
case "$CATALOG_CA_FILE" in /*) ;; *) echo "ERROR: IRIS_CRT_FILE/IRIS_CATALOG_CA_FILE must be an absolute path" >&2; exit 2 ;; esac
case "$CATALOG_CA_FILE" in *$'\n'*|*$'\r'*) echo "ERROR: catalog certificate path must be a single line" >&2; exit 2 ;; esac

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

if [ "$DRY" -eq 0 ]; then
  : "${DEVICE_USER:?set DEVICE_USER}"; : "${DEVICE_PASS:?set DEVICE_PASS}"
  [[ "$DEVICE_USER" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] \
    || { echo "ERROR: DEVICE_USER is not a safe SSH username" >&2; exit 2; }
  [ -r "$XR_RPM_FILE" ] || {
    echo "ERROR: XR_RPM_FILE=$XR_RPM_FILE is not readable (build it with tools/build-xr-package.sh)" >&2
    exit 1
  }
  validate_public_cert "$CATALOG_CA_FILE" || exit 1
fi

# docker-run-opts: the exact hardware-proven base ("-td --net=host -v
# /misc/disk1:/hostmount") plus a bounded container log driver plus one --env
# per secret/identity value. NEVER --name -- appmgr's opts validator rejects
# it outright ("Docker run invalid opts passed: unsupported arguments:
# --name"; appmgr names the container itself). No docker-run-cmd override:
# the image's own ENTRYPOINT (device/container/entrypoint.sh) is what should run.
#
# --log-driver/--log-opt: both are in appmgr's documented docker-run-opts
# flag surface pre-24.1.1 (agentinfo/xr-support/research/xrfact-appmgr-
# docker-hosting.md), and a working "--log-opt max-size=... --log-opt
# max-file=..." activation line is hardware-attested on NCS 5500
# (agentinfo/xr-support/research/sources/ncs5500-apphost-simple.txt:1158).
# Deliberately NOT --log-driver=none: emit_impl (xr_deps.py) writes every
# %IRIS-6-<MNEMONIC> line -- including every pre-heartbeat startup failure --
# ONLY to this stdout, XR has no syslog path for them (the deviation note at
# xr_deps.py:52-57), and `none` would discard all of it with no second
# channel. json-file with a small bound keeps that diagnostic history while
# still capping the write volume the unbounded default left open (scrubber
# #123).
#
# Bound: max-size=1m, max-file=3 -> 3 MiB total. The agent emits roughly one
# %IRIS line per 60s tick (xr_deps.py's emit_impl); at a generous ~200 bytes
# per json-file entry (the raw "%IRIS-6-MNEMONIC: msg" text plus the
# driver's per-line JSON/timestamp wrapper) that is ~281 KiB/day, so 3 MiB
# retains roughly 11 days of history -- comfortably past a long weekend --
# for about 0.08% of the ~3.9 GB /misc/app_host partition dockerd's container
# logs live on (agentinfo/xr-support/research/parity/install-bootstrap-
# parity.md), and nothing against a multi-GB harddisk: image.
docker_run_opts() {
  printf -- '-td --net=host -v /misc/disk1:/hostmount --log-driver json-file --log-opt max-size=1m --log-opt max-file=3 --env IRIS_DEVICE_PLATFORM=xr-appmgr --env IRIS_CATALOG_URL=%s --env IRIS_CATALOG_TOKEN=%s --env IRIS_DEVICE_ID=%s --env IRIS_MODEL=%s --env IRIS_VERSION=%s --env IRIS_TELEMETRY=%s --env IRIS_TELEMETRY_STREAM=%s --env IRIS_LOG=%s' \
    "$CATALOG_URL" "$CATALOG_TOKEN" "$DEVICE_ID" "${MODEL:-}" "${XR_VERSION:-}" \
    "$IRIS_TELEMETRY" "$IRIS_TELEMETRY_STREAM" "$IRIS_LOG"
}

activate_line() {
  printf 'appmgr application %s activate type docker source %s docker-run-opts "%s"\n' \
    "$APPID" "$SOURCE_NAME" "$(docker_run_opts)"
}

activate_line_redacted() {
  # Dry-run output is routinely copied into tickets and logs. Keep the exact
  # appmgr command shape while withholding the live enrollment credential.
  local CATALOG_TOKEN='<redacted>'
  activate_line
}

if [ "$DRY" -eq 1 ]; then
  echo "===== [1/5] preflight on \$DEVICE_IP: show version MUST classify IOS-XR; harddisk: free >= $XR_MIN_FREE_BYTES bytes ====="
  echo "===== [2/5] scp push $XR_RPM_FILE and the current public catalog certificate -> harddisk: ====="
  echo "===== [3/5] register: appmgr package install rpm /harddisk:/$SOURCE_NAME.rpm; verify show appmgr source-table lists $SOURCE_NAME ====="
  echo "===== [4/5] activate (config; every commit guarded by lab/xr-run.sh's show-configuration-failed/abort recovery) ====="
  echo "configure"
  activate_line_redacted
  echo "commit"
  echo "===== [5/5] verify show appmgr application-table shows $APPID Up (poll up to \${ACTIVATE_TIMEOUT}s / \${ACTIVATE_POLL}s) ====="
  echo "===== NOT DONE: no 'copy running-config startup-config' -- XR commit IS the persisted state ====="
  exit 0
fi

RUN() { "$HERE/../lab/xr-run.sh" "$DEVICE_IP"; }   # XR commands on stdin

echo "[1/5] preflight on $DEVICE_IP: classify IOS-XR, check harddisk: headroom"
VERSION_OUT="$(printf 'show version\n' | RUN 2>/dev/null)"
# Mirrors _OS_XR_RE in server/gui_onboard.py ('^\s*cisco\s+IOS[\s-]*XRv?\b'):
# the real banner is "Cisco IOS XR Software, Version 25.4.2 LNT"
# (agentinfo/xr-support/LAB-RESULTS-2026-08-27.md).
if ! printf '%s\n' "$VERSION_OUT" | grep -qiE '^[[:space:]]*cisco[[:space:]]+ios[[:space:]-]*xr([[:space:]]|$)'; then
  echo "ERROR: $DEVICE_IP does not report an IOS-XR banner; refusing to install the XR agent" >&2
  exit 1
fi
# The XR container has no CLI to ask (that's the whole reason it's a
# container, not a Guest Shell -- see xr_deps.py's _conf_fact), so this
# preflight banner is the ONLY place the running software version is ever
# known; captured now and carried into the container's env so heartbeats
# report it instead of "unknown". Same banner line the classification check
# above just matched; strip everything through "Version " to leave "25.4.2
# LNT" (whatever trails the version number, unparsed -- not just the digits).
XR_VERSION="$(printf '%s\n' "$VERSION_OUT" | tr -d '\r' \
  | grep -m1 -iE '^[[:space:]]*cisco[[:space:]]+ios[[:space:]-]*xr' \
  | sed -E 's/^.*[Vv]ersion[[:space:]]+//; s/[[:space:]]+$//')"
# First token only ("25.4.2", dropping a trailing label like "LNT"): the
# value rides INSIDE the quoted docker-run-opts string, where any embedded
# space splits the opts and the validator rejects the stray token -- a
# silent semantic commit failure (hardware-reproduced: '--env X=25.4.2 LNT'
# fails the whole pseudo-atomic commit).
XR_VERSION="${XR_VERSION%% *}"
_no_quotes_or_newlines XR_VERSION "$XR_VERSION"
_safe_fact XR_VERSION "$XR_VERSION"
DIR_OUT="$(printf 'dir harddisk: | include bytes free\n' | RUN 2>/dev/null)"
# Cisco 8000 dir output ends "<N> kbytes total (<M> kbytes free)" -- KBYTES,
# hardware-proven ("41968752 kbytes total (37916076 kbytes free)",
# agentinfo/xr-support/LAB-RESULTS-2026-08-27.md); some platforms say plain
# bytes. Accept both and normalise to bytes. Every grep sits behind
# "|| true": under pipefail a no-match grep would otherwise kill the script
# AT THE ASSIGNMENT, before the honest diagnostic below ever prints (the
# same failure shape the RPM build guard already had to close).
FREE_RAW="$(printf '%s\n' "$DIR_OUT" | grep -oiE '\([0-9]+ k?bytes free\)' | tail -1 || true)"
FREE_NUM="$(printf '%s\n' "$FREE_RAW" | grep -oE '[0-9]+' | head -1 || true)"
if [ -n "$FREE_NUM" ] && printf '%s' "$FREE_RAW" | grep -qi 'kbytes'; then
  FREE_BYTES=$((FREE_NUM * 1024))
else
  FREE_BYTES="$FREE_NUM"
fi
[ -n "$FREE_BYTES" ] || {
  echo "ERROR: could not determine free space on harddisk: (transport failure or unexpected 'dir' output); refusing to proceed" >&2
  exit 1
}
if [ "$FREE_BYTES" -lt "$XR_MIN_FREE_BYTES" ]; then
  echo "ERROR: only $FREE_BYTES bytes free on harddisk: (need >= $XR_MIN_FREE_BYTES); refusing to stage" >&2
  exit 1
fi

echo "[2/5] scp push $XR_RPM_FILE and current catalog certificate -> harddisk: (hardware-proven inbound-scp path)"
# The router's identity is verified with the same policy the transport uses
# (lab/iris-ssh-policy.sh), so the scp cannot hand the admin password to a
# host merely answering at the address.
# shellcheck source=lab/iris-ssh-policy.sh
. "$HERE/../lab/iris-ssh-policy.sh" || { echo "ERROR: cannot load lab/iris-ssh-policy.sh" >&2; exit 1; }
iris_ssh_policy "$DEVICE_IP" || exit 1
scp_rc=0
SSHPASS="$DEVICE_PASS" sshpass -e scp -o ConnectTimeout=15 "${IRIS_SSH_OPTS[@]}" \
      "$XR_RPM_FILE" "${DEVICE_USER}@${DEVICE_IP}:/harddisk:/$SOURCE_NAME.rpm" || scp_rc=$?
if [ "$scp_rc" -eq 0 ]; then
  SSHPASS="$DEVICE_PASS" sshpass -e scp -o ConnectTimeout=15 "${IRIS_SSH_OPTS[@]}" \
        "$CATALOG_CA_FILE" "${DEVICE_USER}@${DEVICE_IP}:/harddisk:/iris-catalog.pem" || scp_rc=$?
fi
iris_ssh_cleanup
if [ "$scp_rc" -ne 0 ]; then
  echo "ERROR: scp of the XR package/catalog certificate to $DEVICE_IP:harddisk: failed" >&2
  exit 1
fi

echo "[3/5] register the package: appmgr package install rpm /harddisk:/$SOURCE_NAME.rpm"
printf 'appmgr package install rpm /harddisk:/%s.rpm\n' "$SOURCE_NAME" | RUN >/dev/null 2>&1 || true
SRC_OUT="$(printf 'show appmgr source-table\n' | RUN 2>/dev/null || true)"
if ! printf '%s\n' "$SRC_OUT" | grep -q "$SOURCE_NAME"; then
  echo "ERROR: '$SOURCE_NAME' does not appear in 'show appmgr source-table' after install:" >&2
  printf '%s\n' "$SRC_OUT" >&2
  exit 1
fi

echo "[4/5] activate: appmgr application $APPID (source $SOURCE_NAME, host networking, harddisk: bind mount)"
{
  echo "configure"
  activate_line
  echo "commit"
} | RUN >/dev/null

echo "[5/5] waiting for $APPID to report Up (poll budget ${ACTIVATE_TIMEOUT}s)"
elapsed=0
app_up=0
APP_OUT=""
while [ "$elapsed" -lt "$ACTIVATE_TIMEOUT" ]; do
  APP_OUT="$(printf 'show appmgr application-table\n' | RUN 2>/dev/null || true)"
  if printf '%s\n' "$APP_OUT" | grep "$APPID" | grep -qw "Up"; then
    app_up=1
    break
  fi
  sleep "$ACTIVATE_POLL"
  elapsed=$((elapsed + ACTIVATE_POLL))
done
if [ "$app_up" -ne 1 ]; then
  echo "ERROR: '$APPID' did not reach Up within ${ACTIVATE_TIMEOUT}s. show appmgr application-table:" >&2
  printf '%s\n' "$APP_OUT" >&2
  exit 1
fi

echo "done. '$APPID' is Up. It downloads $DEVICE_ID's assigned image straight to harddisk:"
echo "      through the /hostmount bind mount (write-through, no placement step) and seeds it"
echo "      with catalog/tracker TLS pinned to harddisk:/iris-catalog.pem."
echo "      to the swarm. Watch:  printf 'dir harddisk:\\n' | lab/xr-run.sh $DEVICE_IP"
