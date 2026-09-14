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
#   IRIS_INSTRUCTION_BOOTSTRAP_FILE=<controller-owned private envelope snapshot>
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
INSTRUCTION_BOOTSTRAP_FILE="${IRIS_INSTRUCTION_BOOTSTRAP_FILE:-}"
unset IRIS_INSTRUCTION_BOOTSTRAP_FILE
INSTRUCTION_SNAPSHOT_DIR=""
INSTRUCTION_SNAPSHOT_FILE=""
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

cleanup_instruction_snapshot() {
  if [ -n "$INSTRUCTION_SNAPSHOT_DIR" ]; then
    rm -rf -- "$INSTRUCTION_SNAPSHOT_DIR"
    INSTRUCTION_SNAPSHOT_DIR=""
    INSTRUCTION_SNAPSHOT_FILE=""
  fi
}

# Everything this script has to remove on the way out goes here. bash keeps one
# EXIT trap, so a second `trap ... EXIT` anywhere below would silently replace
# this one -- and the first thing it would stop removing is the decrypted
# instruction bootstrap.
cleanup_all() {
  cleanup_instruction_snapshot
  [ -n "${RUN_ERR:-}" ] && rm -f -- "$RUN_ERR"
  [ -n "${PUSH_DIR:-}" ] && rm -rf -- "$PUSH_DIR"
  return 0
}
trap cleanup_all EXIT

snapshot_instruction_bootstrap() {
  [ -n "$INSTRUCTION_BOOTSTRAP_FILE" ] || return 1
  case "$INSTRUCTION_BOOTSTRAP_FILE" in /*) ;; *) return 1 ;; esac
  case "$INSTRUCTION_BOOTSTRAP_FILE" in *$'\n'*|*$'\r'*) return 1 ;; esac
  INSTRUCTION_SNAPSHOT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/iris-xr-instructions.XXXXXX")" \
    || return 1
  chmod 700 "$INSTRUCTION_SNAPSHOT_DIR" || return 1
  INSTRUCTION_SNAPSHOT_FILE="$INSTRUCTION_SNAPSHOT_DIR/bootstrap.envelope"
  export IRIS_XR_INSTRUCTION_SOURCE="$INSTRUCTION_BOOTSTRAP_FILE"
  export IRIS_XR_INSTRUCTION_DEST="$INSTRUCTION_SNAPSHOT_FILE"
  _instruction_snapshot_rc=0
  python3 - <<'PY' >/dev/null 2>&1 || _instruction_snapshot_rc=$?
import os
import stat

source_path = os.environ["IRIS_XR_INSTRUCTION_SOURCE"]
destination = os.environ["IRIS_XR_INSTRUCTION_DEST"]
flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
         getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
source = os.open(source_path, flags)
target = -1
try:
    before = os.fstat(source)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
            before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or
            not 1 <= before.st_size <= 256 * 1024):
        raise ValueError("unsafe source")
    target = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600)
    remaining = 256 * 1024 + 1
    total = 0
    while remaining:
        chunk = os.read(source, min(65536, remaining))
        if not chunk:
            break
        total += len(chunk)
        remaining -= len(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(target, view)
            view = view[written:]
    after = os.fstat(source)
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    if (total != before.st_size or total > 256 * 1024 or
            any(getattr(before, field) != getattr(after, field)
                for field in fields)):
        raise ValueError("source changed")
    os.fsync(target)
    installed = os.fstat(target)
    if (not stat.S_ISREG(installed.st_mode) or
            stat.S_IMODE(installed.st_mode) != 0o600 or
            installed.st_size != total):
        raise ValueError("unsafe snapshot")
finally:
    os.close(source)
    if target >= 0:
        os.close(target)
PY
  unset IRIS_XR_INSTRUCTION_SOURCE IRIS_XR_INSTRUCTION_DEST
  [ "$_instruction_snapshot_rc" -eq 0 ]
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
  if ! snapshot_instruction_bootstrap; then
    cleanup_instruction_snapshot
    echo "ERROR: instruction bootstrap snapshot is invalid" >&2
    exit 1
  fi
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
  echo "[1/5] check IOS-XR and harddisk: free space (minimum $XR_MIN_FREE_BYTES bytes)"
  echo "show version"
  echo "dir harddisk: | include bytes free"
  echo "[2/5] upload package, certificate, and bootstrap to harddisk:"
  echo "      (one scp session: IOS-XR's vty pool is five lines by default)"
  printf 'scp <%s.rpm> <public-certificate> <instruction-envelope> <user>@%s:/harddisk:/\n' \
    "$SOURCE_NAME" "$DEVICE_IP"
  echo "[3/5] register package"
  echo "appmgr package install rpm /harddisk:/$SOURCE_NAME.rpm"
  echo "show appmgr source-table"
  echo "[4/5] activate app"
  echo "configure"
  activate_line_redacted
  echo "commit"
  echo "[5/5] verify app is Up"
  echo "show appmgr application-table"
  exit 0
fi

# A reset session is retried this many times, this far apart: the vty pool
# frees a line when another session ends, so waiting is usually enough. Used by
# the preflight and by the upload.
XR_SCP_ATTEMPTS="${XR_SCP_ATTEMPTS:-3}"
XR_SCP_RETRY_SECONDS="${XR_SCP_RETRY_SECONDS:-10}"

RUN() { "$HERE/../lab/xr-run.sh" "$DEVICE_IP"; }   # XR commands on stdin

echo "[1/5] check device and storage: $DEVICE_IP"
# Capture the transport's own stderr instead of discarding it. Under
# 'set -e -o pipefail' a failed session kills the script AT THE ASSIGNMENT,
# before any check below runs, so the job used to end with nothing but an exit
# status -- an operator saw "[1/5] check device and storage" and "Job error."
# and had no way to tell a wrong password from an unreachable router.
# lab/xr-run.sh redacts DEVICE_PASS from what it writes there.
RUN_ERR="$(mktemp)"
# Both preflight questions in ONE session. IOS-XR serves five vty lines by
# default and every ssh session takes one, so two sessions back to back are
# reset at key exchange on a router with an operator connected -- measured on
# an NCS-540, where 'show version' succeeded and the 'dir' immediately after it
# was reset. A reset is also retried, because the line another session frees is
# usually the difference between attempts.
PREFLIGHT_OUT=""
run_rc=0
preflight_attempt=1
while : ; do
  run_rc=0
  PREFLIGHT_OUT="$(printf 'show version\ndir harddisk: | include bytes free\n' \
    | RUN 2>"$RUN_ERR")" || run_rc=$?
  [ "$run_rc" -eq 0 ] && [ -n "$PREFLIGHT_OUT" ] && break
  [ "$preflight_attempt" -ge "$XR_SCP_ATTEMPTS" ] && break
  echo "   preflight attempt $preflight_attempt failed; retrying in ${XR_SCP_RETRY_SECONDS}s" >&2
  sleep "$XR_SCP_RETRY_SECONDS"
  preflight_attempt=$((preflight_attempt + 1))
done
if [ "$run_rc" -ne 0 ] || [ -z "$PREFLIGHT_OUT" ]; then
  echo "ERROR: could not read 'show version' and 'dir harddisk:' on $DEVICE_IP (ssh exit $run_rc, $preflight_attempt attempt(s))" >&2
  echo "       Usual causes: the stored device credentials are wrong, the router" >&2
  echo "       is unreachable from the server, or its vty pool has no free line" >&2
  echo "       ('show users' on the device shows the pool)." >&2
  tail -5 "$RUN_ERR" >&2 || true
  exit 1
fi
VERSION_OUT="$PREFLIGHT_OUT"
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
# Same buffer: the free-space line came back with the banner, in one session.
DIR_OUT="$PREFLIGHT_OUT"
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

echo "[2/5] upload package, certificate, and bootstrap"
# The router's identity is verified with the same policy the transport uses
# (lab/iris-ssh-policy.sh), so the scp cannot hand the admin password to a
# host merely answering at the address.
# shellcheck source=lab/iris-ssh-policy.sh
. "$HERE/../lab/iris-ssh-policy.sh" || { echo "ERROR: cannot load lab/iris-ssh-policy.sh" >&2; exit 1; }
iris_ssh_policy "$DEVICE_IP" || exit 1
# One scp session carrying all three files, not three sessions carrying one
# each. IOS-XR serves a small vty pool -- five lines by default -- and every
# ssh or scp session takes one. This installer already spends two on the
# preflight, so three more in a burst exhausts the pool on a router that has
# an operator or another tool connected: the later connections are reset at
# key exchange and the upload fails with no indication that the device simply
# had no line free. Hardware-proven on an NCS-540 (2026-09-14) with four of
# five lines busy: three separate pushes failed on the second and third, one
# push of three files succeeded. A transient failure is retried, because a
# line freed by someone logging out is the usual difference between attempts.
#
# Names, not paths, decide where each file lands: scp writes into the
# directory under the name it read, so the sources are linked into a staging
# directory under the exact names the router must end up with.
PUSH_DIR="$(mktemp -d)"
_stage_push() {
  ln "$1" "$PUSH_DIR/$2" 2>/dev/null || cp "$1" "$PUSH_DIR/$2" || {
    echo "ERROR: cannot stage $2 for upload" >&2; exit 1; }
}
_stage_push "$XR_RPM_FILE" "$SOURCE_NAME.rpm"
_stage_push "$CATALOG_CA_FILE" "iris-catalog.pem"
_stage_push "$INSTRUCTION_SNAPSHOT_FILE" "iris-instructions.bootstrap"

scp_rc=0
scp_attempt=1
while : ; do
  scp_rc=0
  SSHPASS="$DEVICE_PASS" sshpass -e scp -o ConnectTimeout=15 "${IRIS_SSH_OPTS[@]}" \
        "$PUSH_DIR/$SOURCE_NAME.rpm" \
        "$PUSH_DIR/iris-catalog.pem" \
        "$PUSH_DIR/iris-instructions.bootstrap" \
        "${DEVICE_USER}@${DEVICE_IP}:/harddisk:/" 2>"$RUN_ERR" || scp_rc=$?
  [ "$scp_rc" -eq 0 ] && break
  [ "$scp_attempt" -ge "$XR_SCP_ATTEMPTS" ] && break
  echo "   upload attempt $scp_attempt failed: $(tail -1 "$RUN_ERR" 2>/dev/null)" >&2
  echo "   retrying in ${XR_SCP_RETRY_SECONDS}s" >&2
  sleep "$XR_SCP_RETRY_SECONDS"
  scp_attempt=$((scp_attempt + 1))
done
iris_ssh_cleanup
if [ "$scp_rc" -ne 0 ]; then
  echo "ERROR: XR package/catalog/bootstrap upload failed after $scp_attempt attempt(s)" >&2
  echo "       A router with no free vty line resets the connection here; 'show users'" >&2
  echo "       on the device shows whether its pool (five lines by default) is full." >&2
  # scp's own words, which are the difference between guessing and knowing.
  # iris_ssh_explain adds host-key hints; neither prints a credential.
  tail -5 "$RUN_ERR" >&2 || true
  iris_ssh_explain "$RUN_ERR" "$DEVICE_IP" 2>/dev/null || true
  exit 1
fi

echo "[3/5] register package: $SOURCE_NAME"
printf 'appmgr package install rpm /harddisk:/%s.rpm\n' "$SOURCE_NAME" | RUN >/dev/null 2>&1 || true
SRC_OUT="$(printf 'show appmgr source-table\n' | RUN 2>/dev/null || true)"
if ! printf '%s\n' "$SRC_OUT" | grep -q "$SOURCE_NAME"; then
  echo "ERROR: '$SOURCE_NAME' does not appear in 'show appmgr source-table' after install:" >&2
  printf '%s\n' "$SRC_OUT" >&2
  exit 1
fi

echo "[4/5] activate app: $APPID"
{
  echo "configure"
  activate_line
  echo "commit"
} | RUN >/dev/null

echo "[5/5] wait for app: $APPID"
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

echo "onboard complete: $DEVICE_IP"
