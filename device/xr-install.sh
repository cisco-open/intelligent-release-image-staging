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
# TLS is verified INSIDE the container, against the cert baked into the
# image; see device/xr/Dockerfile). This script is the console-drivable
# shape: DEVICE_IP/CATALOG_URL/CATALOG_TOKEN/DEVICE_ID/DEVICE_USER/DEVICE_PASS
# are exactly the fields OnboardService._build_env already produces for
# every other platform (server/gui_onboard.py), and XR_RPM_FILE defaults
# under IRIS_ARTIFACTS_DIR the same way IRIS_CRT_FILE does for the others --
# the console always runs in the same container as the artifact server, so
# this script can always read the package locally.
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
#   XR_MIN_FREE_BYTES=2147483648 (2 GiB headroom floor on harddisk: -- raise
#     it for a larger assigned image set; one proven full image is 1.8GB)
#   IRIS_TELEMETRY=on  IRIS_TELEMETRY_STREAM=off
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
# One proven full image is 1.8GB (agentinfo/xr-support/LAB-RESULTS-2026-08-27.md
# section 1.4); 2 GiB is a same-order-of-magnitude floor for a single image.
# Raise it explicitly for a multi-image assignment.
XR_MIN_FREE_BYTES="${XR_MIN_FREE_BYTES:-2147483648}"
IRIS_TELEMETRY="${IRIS_TELEMETRY:-on}"
IRIS_TELEMETRY_STREAM="${IRIS_TELEMETRY_STREAM:-off}"
ACTIVATE_TIMEOUT="${ACTIVATE_TIMEOUT:-300}"
ACTIVATE_POLL="${ACTIVATE_POLL:-10}"

# The three values below ride inside a single double-quoted CLI token
# (docker-run-opts "..."); a literal double-quote or newline in any of them
# would break out of that token or splice in extra config lines. Reject
# early with a clear message instead of sending the device a malformed
# config line.
_no_quotes_or_newlines() {
  case "$2" in
    *'"'*|*$'\n'*)
      echo "ERROR: $1 must not contain a double quote or newline" >&2
      exit 1 ;;
  esac
  case "$2" in *[[:space:]]*)
    echo "ERROR: $1 contains whitespace, which would split the quoted docker-run-opts string" >&2
    exit 1 ;;
  esac
}
_no_quotes_or_newlines CATALOG_URL "$CATALOG_URL"
_no_quotes_or_newlines CATALOG_TOKEN "$CATALOG_TOKEN"
_no_quotes_or_newlines DEVICE_ID "$DEVICE_ID"
# MODEL: optional, set by the caller's env contract the same way DEVICE_ID is
# (server/gui_onboard.py's OnboardService._build_env exports it from the
# fleet row when known). Forwarded to the container so XR heartbeats report a
# real model instead of the "no CLI to ask" default -- see xr_deps.py.
_no_quotes_or_newlines MODEL "${MODEL:-}"

if [ "$DRY" -eq 0 ]; then
  : "${DEVICE_USER:?set DEVICE_USER}"; : "${DEVICE_PASS:?set DEVICE_PASS}"
  [ -r "$XR_RPM_FILE" ] || {
    echo "ERROR: XR_RPM_FILE=$XR_RPM_FILE is not readable (build it with tools/build-xr-package.sh)" >&2
    exit 1
  }
fi

# docker-run-opts: the exact hardware-proven base ("-td --net=host -v
# /misc/disk1:/hostmount") plus one --env per secret/identity value. NEVER
# --name -- appmgr's opts validator rejects it outright ("Docker run invalid
# opts passed: unsupported arguments: --name"; appmgr names the container
# itself). No docker-run-cmd override: the image's own ENTRYPOINT
# (device/xr/entrypoint.sh) is what should run.
docker_run_opts() {
  printf -- '-td --net=host -v /misc/disk1:/hostmount --env IRIS_CATALOG_URL=%s --env IRIS_CATALOG_TOKEN=%s --env IRIS_DEVICE_ID=%s --env IRIS_MODEL=%s --env IRIS_VERSION=%s --env IRIS_TELEMETRY=%s --env IRIS_TELEMETRY_STREAM=%s' \
    "$CATALOG_URL" "$CATALOG_TOKEN" "$DEVICE_ID" "${MODEL:-}" "${XR_VERSION:-}" \
    "$IRIS_TELEMETRY" "$IRIS_TELEMETRY_STREAM"
}

activate_line() {
  printf 'appmgr application %s activate type docker source %s docker-run-opts "%s"\n' \
    "$APPID" "$SOURCE_NAME" "$(docker_run_opts)"
}

if [ "$DRY" -eq 1 ]; then
  echo "===== [1/5] preflight on \$DEVICE_IP: show version MUST classify IOS-XR; harddisk: free >= $XR_MIN_FREE_BYTES bytes ====="
  echo "===== [2/5] scp push $XR_RPM_FILE -> \${DEVICE_USER}@\$DEVICE_IP:/harddisk:/$SOURCE_NAME.rpm ====="
  echo "===== [3/5] register: appmgr package install rpm /harddisk:/$SOURCE_NAME.rpm; verify show appmgr source-table lists $SOURCE_NAME ====="
  echo "===== [4/5] activate (config; every commit guarded by lab/xr-run.sh's show-configuration-failed/abort recovery) ====="
  echo "configure"
  activate_line
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

echo "[2/5] scp push $XR_RPM_FILE -> harddisk: (hardware-proven inbound-scp path)"
# The router's identity is verified with the same policy the transport uses
# (lab/iris-ssh-policy.sh), so the scp cannot hand the admin password to a
# host merely answering at the address.
# shellcheck source=lab/iris-ssh-policy.sh
. "$HERE/../lab/iris-ssh-policy.sh" || { echo "ERROR: cannot load lab/iris-ssh-policy.sh" >&2; exit 1; }
iris_ssh_policy "$DEVICE_IP" || exit 1
scp_rc=0
SSHPASS="$DEVICE_PASS" sshpass -e scp -o ConnectTimeout=15 "${IRIS_SSH_OPTS[@]}" \
      "$XR_RPM_FILE" "${DEVICE_USER}@${DEVICE_IP}:/harddisk:/$SOURCE_NAME.rpm" || scp_rc=$?
iris_ssh_cleanup
if [ "$scp_rc" -ne 0 ]; then
  echo "ERROR: scp of $XR_RPM_FILE to $DEVICE_IP:/harddisk:/$SOURCE_NAME.rpm failed" >&2
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
echo "      to the swarm. Watch:  printf 'dir harddisk:\\n' | lab/xr-run.sh $DEVICE_IP"
