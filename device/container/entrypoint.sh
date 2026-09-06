#!/bin/sh

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# PID 1 for the unified IRIS IOx / IOS-XR appmgr device container.
# Consolidates the former IOx and IOS-XR container entrypoints; the separate
# Guest Shell bootstrap/runtime is unchanged:
#   1. ensure the stage dir + a config file exist (generate conf from env on first
#      boot if the persistent mount has none — robust to ephemeral storage),
#   2. keep aria2c running as the BT RPC daemon, re-seeding its rpc-secret when the
#      agent rotates it (mirrors bootstrap.sh),
#   3. run the agent control plane once every tick (the existing --once path).
set -eu
umask 077

fatal() {
  echo "IRIS-ENTRYPOINT: FATAL: $*" >&2
  exit 1
}

single_line() {
  # Environment values are written to iris-agent.conf. A newline would create
  # a second key and turn a data value into configuration, so reject it before
  # any directory or config write. Environment strings cannot contain NUL.
  _name="$1"; _value="$2"
  _cr="$(printf '\r')"
  case "$_value" in
    *"$_cr"*|*'
'*) fatal "$_name must be a single line" ;;
  esac
}

absolute_path() {
  _name="$1"; _value="$2"
  single_line "$_name" "$_value"
  case "$_value" in /*) ;; *) fatal "$_name must be an absolute path" ;; esac
  case "/$_value/" in */../*) fatal "$_name must not contain '..' path segments" ;; esac
}

uint_between() {
  _name="$1"; _value="$2"; _min="$3"; _max="$4"
  case "$_value" in ''|*[!0-9]*) fatal "$_name must be an integer from $_min to $_max" ;; esac
  [ "${#_value}" -le 9 ] || fatal "$_name is outside $_min..$_max"
  [ "$_value" -ge "$_min" ] && [ "$_value" -le "$_max" ] \
    || fatal "$_name is outside $_min..$_max"
}

boolean_value() {
  _name="$1"; _value="$2"
  single_line "$_name" "$_value"
  case "$_value" in
    on|off|1|0|true|false|yes|no|ON|OFF|TRUE|FALSE|YES|NO) ;;
    *) fatal "$_name has an invalid boolean value" ;;
  esac
}

safe_identifier() {
  _name="$1"; _value="$2"
  single_line "$_name" "$_value"
  case "$_value" in
    ''|*[!A-Za-z0-9._:-]*) fatal "$_name contains unsafe characters" ;;
  esac
}

safe_fact() {
  # Model/version facts are data, but they are also reconciled into a line-
  # oriented config. Keep their deliberately small device-fact alphabet.
  _name="$1"; _value="$2"
  single_line "$_name" "$_value"
  [ -z "$_value" ] || printf '%s' "$_value" \
    | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._+:/ -]*$' \
    || fatal "$_name contains unsafe characters"
}

https_url() {
  _name="$1"; _value="$2"
  single_line "$_name" "$_value"
  case "$_value" in
    https://*) ;;
    *) fatal "$_name must be an https URL" ;;
  esac
  case "$_value" in
    *[!A-Za-z0-9._~:/?#\[\]@!\$\&\'\(\)\*+,\;=%-]*)
      fatal "$_name contains unsafe characters" ;;
  esac
  # Validate the authority without ever putting the URL (which must not carry
  # credentials) in process argv or diagnostics. urlsplit also rejects a bad
  # bracketed IPv6 literal and an out-of-range port.
  printf '%s' "$_value" | python3 -c '
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
' >/dev/null 2>&1 || fatal "$_name must be an https URL without credentials"
}

bearer_token() {
  _name="$1"; _value="$2"
  single_line "$_name" "$_value"
  printf '%s' "$_value" | grep -Eq '^[A-Za-z0-9._~+/-]+=*$' \
    || fatal "$_name contains unsafe characters"
}

conf_platform() {
  sed -n 's/^[[:space:]]*device_platform[[:space:]]*=[[:space:]]*//p' "$1" \
    2>/dev/null | tail -n 1
}

conf_value() {
  _key="$1"; _path="$2"
  sed -n "s/^[[:space:]]*${_key}[[:space:]]*=[[:space:]]*//p" "$_path" \
    2>/dev/null | tail -n 1
}

conf_has_key() {
  grep -Eq "^[[:space:]]*$1[[:space:]]*=" "$2" 2>/dev/null
}

# New installs provide the single selector as an app runtime environment
# value. After the first successful start it is also persisted in the conf,
# so an already-deployed device can use the established dropped-conf pattern.
DEVICE_PLATFORM="${IRIS_DEVICE_PLATFORM:-}"
if [ -z "$DEVICE_PLATFORM" ]; then
  _found=""
  set -- "${IRIS_AGENT_CONF:-}" \
    "${CAF_APP_PERSISTENT_DIR:-/data}/iris/iris-agent.conf" \
    "/hostmount/iris-work/iris-agent.conf"
  for _candidate do
    [ -n "$_candidate" ] && [ -f "$_candidate" ] || continue
    _value="$(conf_platform "$_candidate")"
    [ -n "$_value" ] || continue
    if [ -n "$_found" ] && [ "$_found" != "$_value" ]; then
      fatal "persisted configs disagree about device_platform"
    fi
    _found="$_value"
  done
  DEVICE_PLATFORM="$_found"
fi
single_line IRIS_DEVICE_PLATFORM "$DEVICE_PLATFORM"
case "$DEVICE_PLATFORM" in
  iox|xr-appmgr) ;;
  '') fatal "IRIS_DEVICE_PLATFORM is required (iox or xr-appmgr)" ;;
  *) fatal "unknown IRIS_DEVICE_PLATFORM '$DEVICE_PLATFORM' (expected iox or xr-appmgr)" ;;
esac

# Former platform selectors are intentionally not compatibility aliases: a
# stale or misspelled combination must fail instead of choosing storage.
[ -z "${IRIS_RUNTIME_MODE:-}" ] || fatal "IRIS_RUNTIME_MODE is obsolete; set only IRIS_DEVICE_PLATFORM"

# Tests need writable temporary paths. Production overrides are refused so a
# deployment cannot redirect either staged images or the pinned trust anchor.
case "${IRIS_CONTAINER_TESTING:-0}" in 0|1) ;; *) fatal "IRIS_CONTAINER_TESTING must be 0 or 1" ;; esac
case "${IRIS_TEST_SKIP_MOUNT_CHECK:-0}" in 0|1) ;; *) fatal "IRIS_TEST_SKIP_MOUNT_CHECK must be 0 or 1" ;; esac
if [ "${IRIS_CONTAINER_TESTING:-0}" != 1 ]; then
  [ -z "${IRIS_STAGE_DIR:-}" ] || fatal "IRIS_STAGE_DIR is test-only; storage derives from IRIS_DEVICE_PLATFORM"
  [ -z "${IRIS_WORK_DIR:-}" ] || fatal "IRIS_WORK_DIR is test-only; storage derives from IRIS_DEVICE_PLATFORM"
  [ -z "${IRIS_AGENT_CONF:-}" ] || fatal "IRIS_AGENT_CONF is test-only in a device container"
  [ -z "${IRIS_AGENT_STATE:-}" ] || fatal "IRIS_AGENT_STATE is test-only in a device container"
  [ -z "${IRIS_CATALOG_CA:-}" ] || fatal "IRIS_CATALOG_CA is test-only; the trust anchor derives from IRIS_DEVICE_PLATFORM"
fi

case "$DEVICE_PLATFORM" in
  iox)
    PERSIST_ROOT="${CAF_APP_PERSISTENT_DIR:-/data}"
    STAGE_DIR="$PERSIST_ROOT/iris"
    WORK_DIR="$STAGE_DIR"
    # The installer delivers the current server certificate through IOS-XE's
    # application-data channel after the package is installed.  Unlike a file
    # baked into the OCI image, this survives package signing and can be
    # refreshed on every onboard without rebuilding the package.
    if [ "${IRIS_CONTAINER_TESTING:-0}" = 1 ]; then
      CATALOG_CA="${IRIS_CATALOG_CA:-$PERSIST_ROOT/iris-catalog.pem}"
    else
      : "${CAF_APP_APPDATA_DIR:?CAF_APP_APPDATA_DIR is required for the IOx catalog certificate}"
      CATALOG_CA="$CAF_APP_APPDATA_DIR/iris-catalog.pem"
    fi
    # Empty means prove a writable target from live IOS show/dir output. An
    # explicit, validated installer override remains supported for IOx models
    # whose storage policy is known by their deployment record.
    TARGET_FS="${IRIS_TARGET_FS:-}"
    # C9K installers mount this path; IE3x00 has no mount and the existing
    # share probe falls back to SCP. The target filesystem itself is proved
    # from IOS show/dir output by flash_target.py, never guessed here.
    SHARE_DIR="${IRIS_SHARE_DIR:-/mnt/share}"
    SHARE_IOS_PATH="${IRIS_SHARE_IOS_PATH:-usbflash1:iox_host_data_share}"
    ;;
  xr-appmgr)
    STAGE_DIR="/hostmount"
    WORK_DIR="$STAGE_DIR/iris-work"
    # xr-install.sh pushes the current certificate beside the RPM on
    # harddisk:.  /hostmount is the hardware-proven harddisk: bind mount.
    CATALOG_CA="/hostmount/iris-catalog.pem"
    TARGET_FS="harddisk:"
    SHARE_DIR=""
    SHARE_IOS_PATH=""
    ;;
esac

if [ "${IRIS_CONTAINER_TESTING:-0}" = 1 ]; then
  STAGE_DIR="${IRIS_STAGE_DIR:-$STAGE_DIR}"
  if [ -n "${IRIS_WORK_DIR:-}" ]; then
    WORK_DIR="$IRIS_WORK_DIR"
  elif [ "$DEVICE_PLATFORM" = xr-appmgr ]; then
    WORK_DIR="$STAGE_DIR/iris-work"
  else
    WORK_DIR="$STAGE_DIR"
  fi
  CATALOG_CA="${IRIS_CATALOG_CA:-$STAGE_DIR/iris-catalog.pem}"
fi
CONF="${IRIS_AGENT_CONF:-$WORK_DIR/iris-agent.conf}"
STATE="${IRIS_AGENT_STATE:-$WORK_DIR/iris-agent.state}"

absolute_path STAGE_DIR "$STAGE_DIR"
absolute_path WORK_DIR "$WORK_DIR"
absolute_path IRIS_AGENT_CONF "$CONF"
absolute_path IRIS_AGENT_STATE "$STATE"
absolute_path catalog_ca "$CATALOG_CA"
if [ "$DEVICE_PLATFORM" = iox ]; then
  single_line IRIS_TARGET_FS "$TARGET_FS"
  [ -z "$TARGET_FS" ] \
    || printf '%s' "$TARGET_FS" | grep -Eq '^[A-Za-z][A-Za-z0-9_-]*:$' \
    || fatal "IRIS_TARGET_FS must be a safe IOS filesystem prefix such as sdflash:"
  absolute_path IRIS_SHARE_DIR "$SHARE_DIR"
  single_line IRIS_SHARE_IOS_PATH "$SHARE_IOS_PATH"
  printf '%s' "$SHARE_IOS_PATH" \
    | grep -Eq '^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' \
    || fatal "IRIS_SHARE_IOS_PATH must be a safe IOS filesystem path"
  case "${SHARE_IOS_PATH#*:}" in *../*|../*|*/..|..) fatal "IRIS_SHARE_IOS_PATH must not contain '..'" ;; esac
else
  [ "${IRIS_TARGET_FS+x}" != x ] || fatal "xr-appmgr forbids IRIS_TARGET_FS; target is harddisk:"
  [ "${IRIS_SHARE_DIR+x}" != x ] || fatal "xr-appmgr forbids IRIS_SHARE_DIR"
  [ "${IRIS_SHARE_IOS_PATH+x}" != x ] || fatal "xr-appmgr forbids IRIS_SHARE_IOS_PATH"
fi

RPC_PORT="${IRIS_RPC_PORT:-6800}"
TICK="${IRIS_TICK_SECONDS:-60}"
# Bounded per-device cadence jitter + failure backoff (issue #59): a fleet of
# containers that starts, or restarts, together must not re-poll the catalog
# in lockstep -- that is exactly what turns an ordinary tick into a
# fleet-wide burst of policy GETs, heartbeats, and tracker re-announces.
#   * JITTER_PCT dithers every ordinary tick +/-10% of TICK (54-66s at the
#     60s default): enough that devices which started in the same second
#     drift apart over a handful of ticks, small enough that the AVERAGE
#     cadence -- and so token refresh / assignment convergence latency --
#     barely moves.
#   * a startup jitter (applied once, below, before the first tick) covers
#     the worse case directly: many containers starting in the same second
#     get their FIRST tick spread across the whole TICK window instead of
#     firing together.
#   * BACKOFF_MAX bounds the OTHER case -- the agent process itself failing
#     outright (catalog unreachable, timed out, or answering a non-2xx
#     status, the same shape a saturated server produces). See
#     next_tick_sleep below. Comfortably inside the token's multi-day
#     refresh slack (iris_agent.py's needs_refresh docstring), so a run of
#     backed-off ticks never strands the device.
JITTER_PCT="${IRIS_TICK_JITTER_PCT:-10}"
BACKOFF_MAX="${IRIS_TICK_BACKOFF_MAX:-600}"
MAX_PEERS="${IRIS_MAX_PEERS:-10}"
MAX_CONCURRENT="${IRIS_MAX_CONCURRENT:-100}"
uint_between IRIS_RPC_PORT "$RPC_PORT" 1 65535
uint_between IRIS_TICK_SECONDS "$TICK" 1 86400
uint_between IRIS_TICK_JITTER_PCT "$JITTER_PCT" 0 100
uint_between IRIS_TICK_BACKOFF_MAX "$BACKOFF_MAX" 1 86400
uint_between IRIS_MAX_PEERS "$MAX_PEERS" 1 1000
uint_between IRIS_MAX_CONCURRENT "$MAX_CONCURRENT" 1 1000
# Device-side logging is OFF by default: flash has finite write endurance,
# and aria2c's log is chatty and continuous for the whole life of a transfer
# (and, with --seed-ratio=0.0 below, a staged device seeds forever, so a log
# left on would never stop growing). Off means genuinely no recurring flash
# write from this source, not "a smaller file" -- start_aria2c below never
# puts --log= on the launch line unless this is explicitly on, and stdio is
# already redirected to /dev/null regardless (see start_aria2c). On, it is
# bounded by aria2's own --log-max-size/--log-max-files rather than growing
# without limit. Same fail-closed on/1/true/yes parsing
# telemetry_report.stream_enabled() uses; anything else, including garbage,
# stays off. This never touches agent error reporting (IOS syslog for IOx,
# appmgr stdout for XR) or the heartbeat's stage_error field.
IRIS_LOG="${IRIS_LOG:-off}"
boolean_value IRIS_LOG "$IRIS_LOG"
case "${IRIS_STARTUP_JITTER:-1}" in 0|1) ;; *) fatal "IRIS_STARTUP_JITTER must be 0 or 1" ;; esac

# Validate every supplied value that can be written or reconciled before the
# first mkdir, config rewrite, mount probe, or device action. In particular,
# these checks cannot be confined to first boot: deployment env overrides are
# also applied to an existing persistent config.
if [ "${IRIS_CATALOG_URL+x}" = x ]; then
  https_url IRIS_CATALOG_URL "$IRIS_CATALOG_URL"
fi
if [ "${IRIS_CATALOG_TOKEN+x}" = x ]; then
  bearer_token IRIS_CATALOG_TOKEN "$IRIS_CATALOG_TOKEN"
fi
if [ "${IRIS_DEVICE_ID+x}" = x ]; then
  safe_identifier IRIS_DEVICE_ID "$IRIS_DEVICE_ID"
fi
if [ "${IRIS_CATALOG_CA+x}" = x ]; then
  absolute_path IRIS_CATALOG_CA "$IRIS_CATALOG_CA"
fi
if [ "${IRIS_TELEMETRY+x}" = x ]; then
  boolean_value IRIS_TELEMETRY "$IRIS_TELEMETRY"
fi
if [ "${IRIS_TELEMETRY_STREAM+x}" = x ]; then
  boolean_value IRIS_TELEMETRY_STREAM "$IRIS_TELEMETRY_STREAM"
fi
if [ "${IRIS_MODEL+x}" = x ]; then safe_fact IRIS_MODEL "$IRIS_MODEL"; fi
if [ "${IRIS_VERSION+x}" = x ]; then safe_fact IRIS_VERSION "$IRIS_VERSION"; fi

if [ "$DEVICE_PLATFORM" = iox ]; then
  if [ "${IRIS_DEVICE_SSH_HOST+x}" = x ]; then
    single_line IRIS_DEVICE_SSH_HOST "$IRIS_DEVICE_SSH_HOST"
    case "$IRIS_DEVICE_SSH_HOST" in ''|*[!A-Za-z0-9._:-]*) fatal "IRIS_DEVICE_SSH_HOST contains unsafe characters" ;; esac
  fi
  if [ "${IRIS_DEVICE_SSH_USER+x}" = x ]; then
    single_line IRIS_DEVICE_SSH_USER "$IRIS_DEVICE_SSH_USER"
    case "$IRIS_DEVICE_SSH_USER" in ''|*[!A-Za-z0-9._-]*) fatal "IRIS_DEVICE_SSH_USER contains unsafe characters" ;; esac
  fi
  if [ "${IRIS_DEVICE_SSH_PASS+x}" = x ]; then single_line IRIS_DEVICE_SSH_PASS "$IRIS_DEVICE_SSH_PASS"; fi
  if [ "${IRIS_DEVICE_SSH_ENABLE+x}" = x ]; then single_line IRIS_DEVICE_SSH_ENABLE "$IRIS_DEVICE_SSH_ENABLE"; fi
  if [ "${IRIS_DEVICE_SSH_PORT+x}" = x ]; then uint_between IRIS_DEVICE_SSH_PORT "$IRIS_DEVICE_SSH_PORT" 1 65535; fi
  if [ "${IRIS_DEVICE_SSH_KNOWN_HOSTS+x}" = x ] && [ -n "$IRIS_DEVICE_SSH_KNOWN_HOSTS" ]; then
    absolute_path IRIS_DEVICE_SSH_KNOWN_HOSTS "$IRIS_DEVICE_SSH_KNOWN_HOSTS"
  fi
fi
LOG_FILE="$WORK_DIR/aria2c.log"
ARIA2_CONF="/tmp/iris-aria2.conf"
ARIA2="/opt/iris/bin/aria2c"
AGENT="/opt/iris/agent/iris_agent.py"
# --on-bt-download-complete: the per-peer transfer-record hook. Baked into the image by
# the Dockerfile (already executable), so unlike the Guest Shell launcher there
# is no copy-to-an-exec-capable-filesystem dance here. Checked once: an image
# built before this existed simply runs without it, and aria2c must not be
# handed an empty option value (Aria2 Next rejects those outright).
HOOK="/opt/iris/agent/peer-transfer-hook.sh"
[ -x "$HOOK" ] || HOOK=""

export IRIS_STAGE_DIR="$STAGE_DIR"
export IRIS_AGENT_CONF="$CONF"
export IRIS_AGENT_STATE="$STATE"
# The hook resolves its RPC endpoint from these; same netns, so 127.0.0.1.
export IRIS_RPC_PORT="$RPC_PORT"

# XR's /hostmount must be the harddisk: bind mount. Without it, an apparently
# successful stage would disappear with the container. Validate before mkdir;
# the bypass exists only for the source-level bats harness.
stage_dir_is_mounted() {
  _dir="$1"
  while :; do
    _hit=""
    while read -r _dev _mnt _rest; do
      [ "$_mnt" = "$_dir" ] || continue
      _hit="$_mnt"; break
    done < /proc/mounts
    case "$_hit" in '') ;; /) return 1 ;; *) return 0 ;; esac
    [ "$_dir" != / ] || return 1
    _dir="$(dirname "$_dir")"
  done
}

if [ "$DEVICE_PLATFORM" = xr-appmgr ]; then
  # The shared image contains SSH tools because IOx needs them, but XR has no
  # SSH-to-self credential or run-option surface and can never select it.
  if [ "${IRIS_DEVICE_SSH_HOST+x}" = x ] \
    || [ "${IRIS_DEVICE_SSH_USER+x}" = x ] \
    || [ "${IRIS_DEVICE_SSH_PASS+x}" = x ] \
    || [ "${IRIS_DEVICE_SSH_ENABLE+x}" = x ] \
    || [ "${IRIS_DEVICE_SSH_PORT+x}" = x ] \
    || [ "${IRIS_DEVICE_SSH_KNOWN_HOSTS+x}" = x ]; then
    fatal "xr-appmgr forbids IRIS_DEVICE_SSH_* variables"
  fi
  if [ "${IRIS_CONTAINER_TESTING:-0}" != 1 ] \
    || [ "${IRIS_TEST_SKIP_MOUNT_CHECK:-0}" != 1 ]; then
    stage_dir_is_mounted "$STAGE_DIR" \
      || fatal "$STAGE_DIR is not a mounted filesystem; refusing to stage outside harddisk:"
  fi
fi

mkdir -p "$STAGE_DIR" "$WORK_DIR" "$(dirname "$CONF")" "$(dirname "$STATE")"

# --- 1. config: use a dropped conf if present, else synthesize from env ---------
# A conf dropped onto persistent storage wins, and the agent rewrites it in
# place on token refresh. On first boot, secrets arrive through runtime env;
# none is baked into the image.
if [ ! -f "$CONF" ]; then
  : "${IRIS_CATALOG_URL:?set IRIS_CATALOG_URL to the reachable IRIS catalog URL}"
  : "${IRIS_CATALOG_TOKEN:?set IRIS_CATALOG_TOKEN to this device enrollment token}"
  : "${IRIS_DEVICE_ID:?set IRIS_DEVICE_ID to the catalog device id}"
  if [ "$DEVICE_PLATFORM" = iox ]; then
    : "${IRIS_DEVICE_SSH_HOST:?set IRIS_DEVICE_SSH_HOST to the IOS SSH-to-self address}"
    : "${IRIS_DEVICE_SSH_USER:?set IRIS_DEVICE_SSH_USER to the IOS SSH user}"
    : "${IRIS_DEVICE_SSH_PASS:?set IRIS_DEVICE_SSH_PASS to the IOS SSH password}"
  fi

  absolute_path catalog_ca "$CATALOG_CA"
  if [ "$DEVICE_PLATFORM" = iox ]; then
    single_line IRIS_DEVICE_SSH_ENABLE "${IRIS_DEVICE_SSH_ENABLE:-$IRIS_DEVICE_SSH_PASS}"
    if [ -n "${IRIS_DEVICE_SSH_PORT:-}" ]; then
      uint_between IRIS_DEVICE_SSH_PORT "$IRIS_DEVICE_SSH_PORT" 1 65535
    fi
    if [ -n "${IRIS_DEVICE_SSH_KNOWN_HOSTS:-}" ]; then
      absolute_path IRIS_DEVICE_SSH_KNOWN_HOSTS "$IRIS_DEVICE_SSH_KNOWN_HOSTS"
    fi
  fi

  echo "IRIS-ENTRYPOINT: no conf at $CONF; generating from environment"
  # mktemp creates the file without following a pre-created symlink; keep it
  # beside CONF so rename is atomic on the persistent filesystem.
  tmp="$(mktemp "$(dirname "$CONF")/.iris-agent.conf.XXXXXX")"
  chmod 600 "$tmp"
  trap 'rm -f "$tmp"' EXIT HUP INT TERM
  {
    printf '%s\n' \
      "catalog_url = ${IRIS_CATALOG_URL}" \
      "catalog_token = ${IRIS_CATALOG_TOKEN}" \
      "device_id = ${IRIS_DEVICE_ID}" \
      "device_platform = ${DEVICE_PLATFORM}" \
      "stage_dir = ${STAGE_DIR}" \
      "target_fs = ${TARGET_FS}" \
      "rpc_secret = " \
      "catalog_ca = ${CATALOG_CA}" \
      "token_expires_at = 0"
    if [ "$DEVICE_PLATFORM" = iox ]; then
      printf '%s\n' \
        "runtime_mode = container" \
        "device_ssh_host = ${IRIS_DEVICE_SSH_HOST}" \
        "device_ssh_user = ${IRIS_DEVICE_SSH_USER}" \
        "device_ssh_pass = ${IRIS_DEVICE_SSH_PASS}" \
        "device_ssh_enable = ${IRIS_DEVICE_SSH_ENABLE:-${IRIS_DEVICE_SSH_PASS}}" \
        "device_ssh_port = ${IRIS_DEVICE_SSH_PORT:-22}" \
        "device_ssh_known_hosts = ${IRIS_DEVICE_SSH_KNOWN_HOSTS:-}" \
        "share_dir = ${SHARE_DIR}" \
        "share_ios_path = ${SHARE_IOS_PATH}"
    else
      printf '%s\n' \
        "mode = xr" \
        "device_model = ${IRIS_MODEL:-}" \
        "device_version = ${IRIS_VERSION:-}"
    fi
    printf '%s\n' \
      "max_peers = ${MAX_PEERS}" \
      "telemetry = ${IRIS_TELEMETRY:-on}" \
      "telemetry_stream = ${IRIS_TELEMETRY_STREAM:-off}" \
      "rpc_port = ${RPC_PORT}" \
      "agent_version = $(cat /opt/iris/agent/VERSION 2>/dev/null || printf unknown)"
  } > "$tmp"
  mv -f "$tmp" "$CONF"
  trap - EXIT HUP INT TERM
fi
chmod 600 "$CONF" 2>/dev/null || true

# A persisted platform may supply the selector, but it may never contradict an
# explicit deployment value. XR configs carrying an IOx credential surface are
# refused before the agent can dispatch.
_persisted_platform="$(conf_platform "$CONF")"
[ -z "$_persisted_platform" ] || [ "$_persisted_platform" = "$DEVICE_PLATFORM" ] \
  || fatal "persisted device_platform '$_persisted_platform' conflicts with IRIS_DEVICE_PLATFORM '$DEVICE_PLATFORM'"

# A persistent conf is still input. Validate the fields the supervisor reads
# or reconciles before rewriting it or starting aria2c. The Python agent repeats
# these checks at load time; this early pass closes the existing-conf gap.
_conf_catalog_url="$(conf_value catalog_url "$CONF")"
_conf_catalog_token="$(conf_value catalog_token "$CONF")"
_conf_device_id="$(conf_value device_id "$CONF")"
[ -n "$_conf_catalog_url" ] || fatal "persisted config is missing catalog_url"
[ -n "$_conf_catalog_token" ] || fatal "persisted config is missing catalog_token"
[ -n "$_conf_device_id" ] || fatal "persisted config is missing device_id"
https_url catalog_url "$_conf_catalog_url"
bearer_token catalog_token "$_conf_catalog_token"
safe_identifier device_id "$_conf_device_id"
for _key in telemetry telemetry_stream; do
  if conf_has_key "$_key" "$CONF"; then
    boolean_value "$_key" "$(conf_value "$_key" "$CONF")"
  fi
done
for _key in device_model device_version agent_version; do
  if conf_has_key "$_key" "$CONF"; then
    safe_fact "$_key" "$(conf_value "$_key" "$CONF")"
  fi
done
for _key in stage_dir share_dir catalog_ca device_ssh_known_hosts; do
  _value="$(conf_value "$_key" "$CONF")"
  [ -z "$_value" ] || absolute_path "$_key" "$_value"
done
for _key in rpc_port max_peers device_ssh_port; do
  _value="$(conf_value "$_key" "$CONF")"
  [ -z "$_value" ] || case "$_key" in
    rpc_port|device_ssh_port) uint_between "$_key" "$_value" 1 65535 ;;
    max_peers) uint_between "$_key" "$_value" 1 1000 ;;
  esac
done
_value="$(conf_value target_fs "$CONF")"
[ -z "$_value" ] || printf '%s' "$_value" | grep -Eq '^[A-Za-z][A-Za-z0-9_-]*:$' \
  || fatal "target_fs must be a safe IOS filesystem prefix"
_value="$(conf_value share_ios_path "$CONF")"
if [ -n "$_value" ]; then
  single_line share_ios_path "$_value"
  printf '%s' "$_value" | grep -Eq '^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' \
    || fatal "share_ios_path must be a safe IOS filesystem path"
  case "${_value#*:}" in *../*|../*|*/..|..) fatal "share_ios_path must not contain '..'" ;; esac
fi
_value="$(conf_value announce_token "$CONF")"
[ -z "$_value" ] || bearer_token announce_token "$_value"
if [ "$DEVICE_PLATFORM" = xr-appmgr ]; then
  if sed -n '/^[[:space:]]*device_ssh_[^=]*=[[:space:]]*[^[:space:]]/p' "$CONF" | grep -q .; then
    fatal "xr-appmgr persisted config contains forbidden device_ssh_* values"
  fi
else
  _value="$(conf_value device_ssh_host "$CONF")"
  [ -n "$_value" ] || fatal "iox persisted config is missing device_ssh_host"
  case "$_value" in *[!A-Za-z0-9._:-]*) fatal "device_ssh_host contains unsafe characters" ;; esac
  _value="$(conf_value device_ssh_user "$CONF")"
  [ -n "$_value" ] || fatal "iox persisted config is missing device_ssh_user"
  case "$_value" in *[!A-Za-z0-9._-]*) fatal "device_ssh_user contains unsafe characters" ;; esac
  [ -n "$(conf_value device_ssh_pass "$CONF")" ] \
    || fatal "iox persisted config is missing device_ssh_pass"
fi

# Same operator-intent rule for the telemetry toggles: a console redeploy that
# flips reports or streaming must take effect on a device with an existing
# conf (spec section 5.5) — both keys reconcile, deploy-time env wins.
. "$(dirname "$0")/reconcile.sh"
reconcile_conf_key telemetry "${IRIS_TELEMETRY:-}"
reconcile_conf_key telemetry_stream "${IRIS_TELEMETRY_STREAM:-}"
reconcile_conf_fact stage_dir "$STAGE_DIR"
# The certificate location is a platform fact, not persisted operator state.
# Reconcile before checking the file so a package upgrade repairs the old
# baked-image path instead of failing before it can use the runtime-delivered
# certificate.
reconcile_conf_fact catalog_ca "$CATALOG_CA"
if [ "$DEVICE_PLATFORM" = iox ]; then
  # A non-empty deployment override wins after redeploy. With none, retain a
  # persisted target; a new blank conf lets flash_target.py auto-detect live.
  [ -z "$TARGET_FS" ] || reconcile_conf_fact target_fs "$TARGET_FS"
  reconcile_conf_fact mode ""
  reconcile_conf_fact runtime_mode container
  reconcile_conf_fact share_dir "$SHARE_DIR"
  reconcile_conf_fact share_ios_path "$SHARE_IOS_PATH"
else
  reconcile_conf_fact target_fs "$TARGET_FS"
  reconcile_conf_fact mode xr
  reconcile_conf_fact runtime_mode ""
  reconcile_conf_fact share_dir ""
  reconcile_conf_fact share_ios_path ""
  reconcile_conf_key device_model "${IRIS_MODEL:-}"
  reconcile_conf_key device_version "${IRIS_VERSION:-}"
fi
# Persist the selector after its storage/transport prerequisites. This lets a
# pre-selector dropped config be upgraded atomically one key at a time without
# transiently becoming an invalid xr-appmgr (wrong target) or IOx (no SSH)
# config. A config that already has the selector is validated on every step.
reconcile_conf_fact device_platform "$DEVICE_PLATFORM"
# agent_version is a fact about the IMAGE, not operator state: after a package
# upgrade a persistent conf still carries the previous build's number and every
# telemetry report mis-states what is actually running (field observation
# 2026-08-20: the 3400 kept reporting 2026.07.26 from a pre-release-cut
# package). The baked VERSION file wins on every start.
reconcile_conf_key agent_version \
  "$(cat /opt/iris/agent/VERSION 2>/dev/null || echo unknown)"

# aria2 performs tracker HTTPS itself, outside the Python catalog client, so
# it must receive the same pinned certificate as a global launch option. Read
# the reconciled value (not merely the environment default) and prove it is a
# usable CA bundle before starting a daemon; otherwise a syntactically valid
# but missing/corrupt pin would leave the app RUNNING while every announce
# failed in the background.
TRACKER_CA="$(conf_value catalog_ca "$CONF")"
[ -n "$TRACKER_CA" ] || fatal "persisted config is missing catalog_ca"
absolute_path catalog_ca "$TRACKER_CA"
[ -r "$TRACKER_CA" ] && [ -s "$TRACKER_CA" ] \
  || fatal "catalog_ca is not a readable certificate file"
python3 -c 'import ssl, sys; ssl.create_default_context(cafile=sys.argv[1])' \
  "$TRACKER_CA" >/dev/null 2>&1 \
  || fatal "catalog_ca is not a valid certificate bundle"

# --- 2/3. aria2c supervisor + agent tick loop ----------------------------------
read_secret() {
  sed -n 's/^[[:space:]]*rpc_secret[[:space:]]*=[[:space:]]*//p' "$CONF" 2>/dev/null \
    | tr -d '[:space:]'
}

# aria2c is owned by exact PID, never by process-name matching: it runs as a
# tracked background child of this PID-1 shell (no --daemon=true, which would
# double-fork and setsid() it out of reach), and ARIA2_PID plus the child's
# /proc starttime are the identity everything below acts on. Diagnostic tools
# remain available, but supervision never depends on process-name matching.
ARIA2_PID=""
ARIA2_START=""

proc_stat() {
  # Sets PROC_STATE / PROC_START (state letter, starttime -- /proc/<pid>/stat
  # fields 3 and 22); fails once the PID is gone. comm (field 2) may contain
  # spaces, so split after the LAST ") ". Builtins only: no fork, so the check
  # itself can never reap the zombie it is about to report.
  read -r _stat 2>/dev/null < "/proc/$1/stat" || return 1
  set -- ${_stat##*) }
  PROC_STATE="${1:-}"; PROC_START="${20:-}"
}

aria2_alive() {
  # Alive means: the recorded PID exists, is the process we started (same
  # starttime -- a recycled PID number belongs to somebody else and must never
  # be signalled), and has not exited. A zombie still passes kill -0, which is
  # why the state letter decides; stop_aria2c's wait is what reaps it.
  [ -n "$ARIA2_PID" ] || return 1
  proc_stat "$ARIA2_PID" || return 1
  [ "$PROC_START" = "$ARIA2_START" ] || return 1
  case "$PROC_STATE" in Z|X) return 1 ;; esac
}

stop_aria2c() {
  # TERM first -- aria2c saves its .aria2 control files on TERM, so an
  # interrupted download resumes on the next start -- then a bounded wait,
  # then KILL. CONT rides along because a stopped child cannot act on TERM.
  # wait(1) reaps the child, so PID 1 never leaves a zombie behind.
  _ours=0
  if [ -n "$ARIA2_PID" ]; then
    if ! proc_stat "$ARIA2_PID"; then
      # The recorded child has already disappeared; wait returns immediately
      # (or reaps the status the shell retained).
      _ours=1
    elif [ "$PROC_START" = "$ARIA2_START" ]; then
      _ours=1
    fi
  fi
  if [ "$_ours" -eq 1 ] && aria2_alive; then
    kill -TERM "$ARIA2_PID" 2>/dev/null || true
    kill -CONT "$ARIA2_PID" 2>/dev/null || true
    _w=0
    while aria2_alive && [ "$_w" -lt 5 ]; do
      sleep 1; _w=$((_w + 1))
    done
    if aria2_alive; then kill -KILL "$ARIA2_PID" 2>/dev/null || true; fi
  fi
  # A live PID with a different starttime is not ours. Never signal or wait
  # on it, even when a test shell happens to have spawned that stand-in.
  if [ "$_ours" -eq 1 ]; then wait "$ARIA2_PID" 2>/dev/null || true; fi
  ARIA2_PID=""; ARIA2_START=""
}

start_aria2c() {
  secret="$1"
  stop_aria2c
  # The RPC secret must never be visible in /proc/<pid>/cmdline.  aria2 reads
  # it from this owner-only ephemeral config instead.  Reject config syntax
  # before writing; generated secrets use this deliberately small alphabet.
  case "$secret" in
    ''|*[!A-Za-z0-9._~-]*)
      echo "IRIS-ENTRYPOINT: invalid RPC secret; refusing to start aria2c" >&2
      return 1 ;;
  esac
  _aria2_tmp="$(mktemp /tmp/.iris-aria2.conf.XXXXXX)" || return 1
  chmod 600 "$_aria2_tmp"
  if ! printf 'rpc-secret=%s\n' "$secret" > "$_aria2_tmp"; then
    rm -f "$_aria2_tmp"
    return 1
  fi
  mv -f "$_aria2_tmp" "$ARIA2_CONF"
  # Hand the hook the secret this daemon is being started with, by inheritance
  # through aria2c's fork. Deliberately not re-read from $CONF: the agent
  # rewrites that file on every token refresh, and a hook reading a secret the
  # running daemon has already moved off is precisely the file-vs-daemon skew
  # of the 2026-08-20 incident. This supervisor relaunches aria2c whenever the
  # secret changes, so the exported value tracks the daemon by construction.
  IRIS_RPC_SECRET="$secret"; export IRIS_RPC_SECRET
  # Positional args carry the optional hook flag: aria2c must never be handed
  # --on-bt-download-complete= with an empty value. "$secret" is already saved
  # above, so reusing $@ here is safe.
  set --
  case "${HOOK:-}" in ?*) set -- "--on-bt-download-complete=$HOOK" ;; esac
  # --log is added only when an operator explicitly opts in (IRIS_LOG=on);
  # see the IRIS_LOG comment near the top of this file for why leaving it
  # off the launch line entirely -- not writing a smaller/rotated file -- is
  # what "off" means here. --log-max-size/--log-max-files bound the file
  # once logging is on, since this platform has never shipped rotate-logs.sh
  # (no bash dependency added just for this) and aria2 already owns the fd.
  case "$(printf '%s' "$IRIS_LOG" | tr '[:upper:]' '[:lower:]')" in
    on|1|true|yes)
      set -- "$@" "--log=$LOG_FILE" --log-max-size=50M --log-max-files=1 ;;
  esac
  # A tracked child with its stdio on /dev/null -- exactly what --daemon=true's
  # daemon(0,0) did, minus the double fork. The redirect is not optional:
  # aria2c writes a progress readout line every second, to a pipe as readily
  # as to a terminal, for as long as anything is downloading OR seeding, and a
  # staged device seeds indefinitely -- that would flood the app log.
  # --check-integrity=true is a RESUME guard. Without it aria2 trusts the piece
  # map recorded in the .aria2 control file, so a completed piece that rotted
  # on flash (bit-rot, a torn write during a power loss) survives the resume:
  # the torrent reports complete and the staged image carries the wrong
  # SHA-256. The agent's whole-image hash still catches that, but only after
  # the whole remaining transfer, and the repair is then a full re-stage
  # instead of one 1 MiB piece.
  #
  # It sits on the launch line rather than being plumbed per download because
  # in aria2's own code (RequestGroup.cc, createInitialCommand for BitTorrent)
  # the launch flag ALREADY costs nothing on the two paths that are not a
  # resume:
  #   * nothing on disk yet -- every piece read returns 0 bytes, throws, and
  #     the piece is marked missing at once; no I/O, no hashing.
  #   * a COMPLETED file being re-added to seed -- --bt-seed-unverified=true
  #     above marks every piece done, and aria2 then takes the
  #     onDownloadFinished branch, skipping validation entirely. A device
  #     seeding ten staged images does not re-hash them on a relaunch.
  # So the read-back is paid exactly where the corruption can hide: over the
  # bytes an interrupted transfer already put on flash.
  "$ARIA2" \
    --conf-path="$ARIA2_CONF" \
    --enable-rpc=true --rpc-listen-all=false \
    --rpc-listen-port="$RPC_PORT" \
    --ca-certificate="$TRACKER_CA" --check-certificate=true \
    --enable-dht=false --enable-peer-exchange=false --bt-enable-lpd=false \
    --bt-max-peers="$MAX_PEERS" --bt-seed-unverified=true --seed-ratio=0.0 \
    --check-integrity=true \
    --max-concurrent-downloads="$MAX_CONCURRENT" \
    "$@" \
    --file-allocation=none --dir="$STAGE_DIR" \
    --log-level=warn --summary-interval=0 \
    </dev/null >/dev/null 2>&1 &
  ARIA2_PID=$!
  # starttime is fixed at fork and survives the exec, so it can be read right
  # away; it is what makes this PID *ours* on every later check.
  ARIA2_START=""
  if proc_stat "$ARIA2_PID"; then ARIA2_START="$PROC_START"; fi
  echo "IRIS-ENTRYPOINT: aria2c (re)started on :$RPC_PORT (pid $ARIA2_PID)"
}

# Health-probe bounds, in seconds. They are two different questions and the
# split is the whole point of this probe:
#   * --connect-timeout answers "is anything bound to the RPC port". On
#     loopback that is decided instantly -- a daemon that is gone gets the
#     connection REFUSED (curl exit 7), a daemon that is merely busy still
#     owns its listen socket, so the kernel completes the connection for it.
#   * --max-time bounds the wait for the ANSWER, and must sit well above the
#     longest stall a HEALTHY aria2c can have. Built without c-ares, aria2c
#     resolves tracker hostnames with a blocking getaddrinfo() on its
#     event-loop thread: one announce against a slow or unresponsive resolver
#     freezes the entire daemon -- RPC replies included -- for as long as the
#     resolver takes. Measured at 5.03 s (a blackholed forwarder), and the
#     glibc default of 5 s x 2 attempts is the ceiling to design for.
RPC_CONNECT_TIMEOUT=2
RPC_HEALTH_TIMEOUT=10

rpc_probe() {
  # One probe; the caller reads curl's own exit status (0 answered, 7 nothing
  # listening, 28 connected but no answer inside the bound, anything else a
  # transport failure mid-request). Run as a tracked background child and
  # waited on, for the same reason the tick's sleep is: a POSIX shell defers
  # traps while a FOREGROUND command runs, and PID 1 must never make the
  # container wait out a probe before it can act on TERM.
  # Feed the authenticated RPC body on stdin. Putting it after -d would expose
  # the RPC secret through /proc/<curl-pid>/cmdline.
  printf '%s' \
    '{"jsonrpc":"2.0","id":"h","method":"aria2.getVersion","params":["token:'"$1"'"]}' \
    | curl -s --connect-timeout "$RPC_CONNECT_TIMEOUT" --max-time "$RPC_HEALTH_TIMEOUT" \
      "http://127.0.0.1:$RPC_PORT/jsonrpc" --data-binary @- \
      >/dev/null 2>&1 &
  _probe_pid=$!
  _probe_rc=0
  wait "$_probe_pid" || _probe_rc=$?
  return "$_probe_rc"
}

rpc_healthy() {
  # Liveness is not health: an aria2c that is running but not answering RPC
  # blocks its own relaunch, and the agent then fails every tick on
  # ECONNREFUSED without ever heartbeating (field incident 2026-08-20, Guest
  # Shell; this supervisor had the identical condition). Ask the RPC itself.
  #
  # But a SLOW answer is not a dead daemon, and one curl with a 3 s bound
  # could not tell those apart: any overrun read as "kill it", so a daemon
  # stalled in getaddrinfo (see the bounds above) was killed and relaunched
  # while perfectly healthy -- twice in 300 s under one measured DNS stall,
  # its in-flight download dropped from the daemon each time. Two things
  # separate busy from dead here:
  #   * WHERE the probe failed. Connection refused means nothing is listening;
  #     that is a verdict on its own and must relaunch AT ONCE, because
  #     waiting there is exactly the 2026-08-20 deadlock. Any other failure
  #     only says the answer was late, which is a suspicion, not a verdict.
  #   * A SECOND probe. A resolver stall ends when the resolver gives up, so
  #     the retry gets through; a genuinely wedged daemon fails it too.
  _rc=0
  rpc_probe "$1" || _rc=$?
  case "$_rc" in
    0) return 0 ;;
    7) return 1 ;;
  esac
  # Any verdict this function returns is a plain healthy/unhealthy, never
  # curl's own status: the supervisor loop asks a yes/no question.
  rpc_probe "$1" || return 1
}

# rand_below N -- uniform 0..N-1. Shells out to python3, which is already a
# hard dependency of every tick below: this avoids relying on $RANDOM, a
# bash/ksh extension dash does not provide and busybox ash provides only
# inconsistently across builds.
rand_below() {
  python3 -c 'import random,sys; print(random.randrange(int(sys.argv[1])))' "$1"
}

# next_tick_sleep FAIL_STREAK -- seconds to sleep before the next tick.
#   FAIL_STREAK=0 (the ordinary path): TICK dithered by +/-JITTER_PCT%, see
#   the block above.
#   FAIL_STREAK>0: the tick that just ran failed outright (see the loop
#   below). Back off exponentially from TICK, capped at BACKOFF_MAX, still
#   jittered the same way so a batch of devices that failed together does
#   not retry together either.
next_tick_sleep() {
  streak="${1:-0}"
  base="$TICK"
  if [ "$streak" -gt 0 ]; then
    [ "$streak" -le 10 ] || streak=10   # 2**10 * TICK is already far past BACKOFF_MAX
    mult=1; i=0
    while [ "$i" -lt "$streak" ]; do mult=$((mult * 2)); i=$((i + 1)); done
    base=$((TICK * mult))
    [ "$base" -le "$BACKOFF_MAX" ] || base="$BACKOFF_MAX"
  fi
  spread=$(( (base * JITTER_PCT) / 100 ))
  [ "$spread" -gt 0 ] || spread=1
  echo $((base - spread + $(rand_below $((spread * 2 + 1)))))
}

AGENT_PID=""
SLEEP_PID=""
FAIL_STREAK=0

stop_agent() {
  trap - TERM INT
  for pid in "$AGENT_PID" "$SLEEP_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  stop_aria2c
  for pid in "$AGENT_PID" "$SLEEP_PID"; do
    [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
  done
  exit 0
}

trap stop_agent TERM INT

echo "IRIS-ENTRYPOINT: starting; stage=$STAGE_DIR conf=$CONF tick=${TICK}s"

# Spread a fleet-wide simultaneous restart across the whole tick window
# before the FIRST tick -- the case the steady-state dither above only
# corrects gradually. IRIS_STARTUP_JITTER=0 skips it (a single-device debug
# session watching for the first tick to fire).
if [ "${IRIS_STARTUP_JITTER:-1}" != "0" ] && [ "$TICK" -gt 0 ]; then
  startup_jitter="$(rand_below "$TICK")"
  if [ "$startup_jitter" -gt 0 ]; then
    echo "IRIS-ENTRYPOINT: startup jitter ${startup_jitter}s"
    sleep "$startup_jitter" &
    SLEEP_PID=$!
    wait "$SLEEP_PID" || true
    SLEEP_PID=""
  fi
fi

cur=""
while true; do
  want="$(read_secret)"
  [ -z "$want" ] && want="iris"          # placeholder until the agent fetches the real secret
  if [ "$want" != "$cur" ] \
     || ! aria2_alive \
     || ! rpc_healthy "$want"; then
    start_aria2c "$want" && cur="$want"
  fi
  # Keep foreground work as tracked children. POSIX shells defer traps while a
  # foreground command runs; waiting on a background child lets PID 1 handle
  # TERM immediately instead of making the container wait for the full tick.
  python3 "$AGENT" --once &
  AGENT_PID=$!
  if ! wait "$AGENT_PID"; then
    echo "IRIS-ENTRYPOINT: agent tick returned non-zero"
    FAIL_STREAK=$((FAIL_STREAK + 1))
  else
    FAIL_STREAK=0
  fi
  AGENT_PID=""

  sleep_for="$(next_tick_sleep "$FAIL_STREAK")"
  [ "$FAIL_STREAK" -eq 0 ] \
    || echo "IRIS-ENTRYPOINT: backing off ${sleep_for}s (failure streak $FAIL_STREAK)"
  sleep "$sleep_for" &
  SLEEP_PID=$!
  wait "$SLEEP_PID" || true
  SLEEP_PID=""
done
