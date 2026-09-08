#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Launch aria2c inside Guest Shell as an RPC daemon for the IRIS agent.
# - runs as the guestshell user (NOT root): /flash is SELinux-labeled (Phase 0)
# - copies the binary off /flash to an exec-capable fs (chmod denied on /flash)
# - private swarm: DHT/PEX/LPD OFF; seeds completed files without re-hashing
# - RPC on so iris_agent.py can addTorrent; the agent adds torrents (none on argv)
# - idempotent: retain an answering daemon only when its launch line carries
#   the current content-addressed tracker CA generation and verification flag
set -euo pipefail

STAGE_DIR="${STAGE_DIR:-/flash/guest-share/iris}"
EXEC_DIR="${EXEC_DIR:-/home/guestshell}"
ARIA2_SRC="${ARIA2_SRC:-$STAGE_DIR/aria2c}"
ARIA2="$EXEC_DIR/aria2c"
ARIA2_CONF="$EXEC_DIR/aria2.conf"
RPC_PORT="${RPC_PORT:-6800}"
RPC_SECRET_FILE="${RPC_SECRET_FILE:-$STAGE_DIR/rpc-secret}"
HOOK_SRC="${HOOK_SRC:-$STAGE_DIR/agent/peer-transfer-hook.sh}"
HOOK_DST="${HOOK_DST:-$EXEC_DIR/iris-peer-transfer-hook}"
LOG="${LOG:-$STAGE_DIR/aria2c.log}"
CATALOG_CA="$STAGE_DIR/iris-catalog.pem"
# Device-side logging is OFF by default: flash has finite write endurance,
# and aria2c's log is chatty and continuous for the whole life of a transfer
# (and, with --seed-ratio=0.0 below, a staged device seeds forever, so a log
# left on would never stop growing). Off means genuinely no recurring flash
# write from this source, not "a smaller file" -- with no --log= on the
# launch line below, aria2c's own daemon mode (-D/--daemon) already
# redirects its stdout/stderr to /dev/null itself (aria2 Next 2.5.6 --help,
# the -D entry), so nothing is opened on flash at all. Same fail-closed
# on/1/true/yes parsing telemetry_report.stream_enabled() uses; anything
# else, including garbage, stays off. This never touches error reporting:
# IOS syslog (emit(), via `send log`) and the heartbeat's stage_error field
# are unaffected either way -- only the continuous local aria2c.log file is
# optional.
IRIS_LOG="${IRIS_LOG:-off}"
MAX_PEERS="${MAX_PEERS:-10}"     # cap BT peer connections per torrent on a device
# Lift aria2's concurrency cap, which defaults to 5. A SEEDING torrent counts
# against that cap and never completes (--seed-ratio=0.0 below means seed
# forever, which is the point -- staged devices seed to their peers), so a
# device holding five staged images would queue the download for a sixth and
# never start it. A device may be assigned up to ten. The starvation is silent:
# aria2 reports the extra as `waiting`, not an error, so the device would report
# staging indefinitely with no fault recorded anywhere. Bandwidth is bounded by
# --bt-max-peers and transfer limits, never by this; using it as a throttle only
# starves. Same defect fixed on the origin in server/seed-launch.sh.
MAX_CONCURRENT="${MAX_CONCURRENT:-100}"
BT_LISTEN_PORT="${BT_LISTEN_PORT:-}"

# The catalog client and the BitTorrent tracker share the server certificate,
# but aria2 opens tracker connections itself. Fail before touching the daemon
# unless the installer-staged pin is a real CA bundle; otherwise onboarding
# appears healthy while announces fail silently in the background.
if [ ! -r "$CATALOG_CA" ] || [ ! -s "$CATALOG_CA" ]; then
  echo "catalog certificate is missing or unreadable at $CATALOG_CA" >&2
  exit 1
fi
if ! python3 -c \
    'import ssl, sys; ssl.create_default_context(cafile=sys.argv[1])' \
    "$CATALOG_CA" >/dev/null 2>&1; then
  echo "catalog certificate at $CATALOG_CA is not a valid certificate bundle" >&2
  exit 1
fi

# aria2 loads the CA bundle when the daemon starts; it does not re-read the
# path for every tracker announce. Re-onboard atomically replaces
# $CATALOG_CA, so comparing only that stable pathname would retain a daemon
# pinned to the OLD bytes after certificate rotation. Copy the validated bytes
# to a content-addressed path on the exec-capable filesystem and put THAT path
# on aria2's argv. The digest in the pathname is then a generation stamp tied
# directly to the exact daemon inspected below: changed bytes necessarily mean
# a changed expected argv and a restart. Never overwrite a wrong snapshot and
# then retain a daemon that may have loaded its old contents -- remember any
# repair/new creation and force this invocation through replacement.
CATALOG_CA_SHA256="$(python3 -c \
    'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
    "$CATALOG_CA")"
[[ "$CATALOG_CA_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "cannot fingerprint catalog certificate at $CATALOG_CA" >&2; exit 1; }
ARIA2_CA="$EXEC_DIR/iris-catalog-$CATALOG_CA_SHA256.pem"
CA_SNAPSHOT_CHANGED=0
_snapshot_sha=""
if [ -r "$ARIA2_CA" ]; then
  _snapshot_sha="$(python3 -c \
      'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
      "$ARIA2_CA" 2>/dev/null || true)"
fi
if [ "$_snapshot_sha" != "$CATALOG_CA_SHA256" ]; then
  _ca_tmp="$ARIA2_CA.new.$$"
  if ! cp -f "$CATALOG_CA" "$_ca_tmp" 2>/dev/null \
     || ! chmod 600 "$_ca_tmp" 2>/dev/null \
     || ! mv -f "$_ca_tmp" "$ARIA2_CA" 2>/dev/null; then
    rm -f "$_ca_tmp" 2>/dev/null || true
    echo "cannot install catalog certificate snapshot at $ARIA2_CA" >&2
    exit 1
  fi
  _installed_sha="$(python3 -c \
      'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
      "$ARIA2_CA" 2>/dev/null || true)"
  if [ "$_installed_sha" != "$CATALOG_CA_SHA256" ]; then
    echo "catalog certificate changed while installing its runtime snapshot; retry" >&2
    exit 1
  fi
  CA_SNAPSHOT_CHANGED=1
fi
# Validate the exact bytes aria2 will load, not only the staged source checked
# above. The installer replaces the source atomically; it can change between
# that first validation and the digest/copy, and a malformed replacement could
# otherwise acquire a self-consistent digest pathname and reach aria2. This is
# unconditional so a reused snapshot is held to the same fail-closed rule.
if ! python3 -c \
    'import ssl, sys; ssl.create_default_context(cafile=sys.argv[1])' \
    "$ARIA2_CA" >/dev/null 2>&1; then
  echo "catalog certificate snapshot at $ARIA2_CA is not a valid certificate bundle" >&2
  exit 1
fi
unset _snapshot_sha _installed_sha _ca_tmp

if [ -n "$BT_LISTEN_PORT" ]; then
  [[ "$BT_LISTEN_PORT" =~ ^[0-9]+$ ]] && [ "$BT_LISTEN_PORT" -ge 1 ] \
    && [ "$BT_LISTEN_PORT" -le 65535 ] \
    || { echo "invalid BT_LISTEN_PORT: $BT_LISTEN_PORT" >&2; exit 1; }
  set -- "--listen-port=$BT_LISTEN_PORT"
else
  set --
fi

# The installer bakes rpc-secret EMPTY (the agent fetches the real value on
# its first token-refresh). Resolve that one special case to the established
# placeholder, then apply the same small single-line alphabet as the container
# launcher. Never trim or repair input: whitespace, extra lines, unsafe bytes,
# and unreadable non-files all fail without exposing the value.
if [ ! -f "$RPC_SECRET_FILE" ] || [ ! -r "$RPC_SECRET_FILE" ]; then
  echo "invalid RPC secret input; refusing to start aria2c" >&2
  exit 1
fi
if ! RPC_SECRET="$(python3 -c '
import re, sys
value = open(sys.argv[1], "rb").read()
if value.endswith(b"\n"):
    value = value[:-1]
if re.fullmatch(br"[A-Za-z0-9._~-]*", value) is None:
    raise SystemExit(1)
sys.stdout.buffer.write(value)
' "$RPC_SECRET_FILE" 2>/dev/null)"; then
  echo "invalid RPC secret input; refusing to start aria2c" >&2
  exit 1
fi
RPC_SECRET="${RPC_SECRET:-iris}"
case "$RPC_SECRET" in
  *[!A-Za-z0-9._~-]*)
    echo "invalid RPC secret input; refusing to start aria2c" >&2
    exit 1 ;;
esac

# aria2 reads the secret from this fixed owner-only file, keeping it out of
# /proc/<pid>/cmdline. Build the complete owner-only replacement now, but keep
# changed bytes pending until the daemon using the old secret has stopped.
RPC_CONFIG_CHANGED=1
_aria2_conf_tmp="$(umask 077; mktemp "$ARIA2_CONF.new.XXXXXX")" \
  || { echo "cannot create private aria2 RPC config" >&2; exit 1; }
cleanup_rpc_config_tmp() {
  if [ -n "${_aria2_conf_tmp:-}" ]; then
    rm -f "$_aria2_conf_tmp" 2>/dev/null || true
  fi
}
trap cleanup_rpc_config_tmp EXIT
if ! printf 'rpc-secret=%s\n' "$RPC_SECRET" > "$_aria2_conf_tmp" 2>/dev/null \
   || ! chmod 600 "$_aria2_conf_tmp" 2>/dev/null; then
  echo "cannot install private aria2 RPC config" >&2
  exit 1
fi
# Compare bytes before publishing so a rotated secret forces replacement of a
# daemon that still has the previous value in memory. Mode-only repair does not
# change the content generation. Reject non-regular existing destinations.
if ! RPC_CONFIG_CHANGED="$(python3 -c '
import os, stat, sys
source, destination = sys.argv[1:3]
try:
    destination_stat = os.lstat(destination)
except FileNotFoundError:
    changed = 1
else:
    if not stat.S_ISREG(destination_stat.st_mode):
        raise SystemExit(1)
    with open(source, "rb") as new_file:
        new_bytes = new_file.read()
    with open(destination, "rb") as old_file:
        changed = int(new_bytes != old_file.read())
print(changed)
' "$_aria2_conf_tmp" "$ARIA2_CONF" 2>/dev/null)"; then
  echo "cannot install private aria2 RPC config" >&2
  exit 1
fi

publish_rpc_config() {
  # Recheck after any daemon shutdown wait, then use no-target-directory
  # replacement. A directory or symlink must fail rather than absorb the temp.
  if ! python3 -c '
import os, stat, sys
destination = sys.argv[1]
try:
    destination_stat = os.lstat(destination)
except FileNotFoundError:
    pass
else:
    if not stat.S_ISREG(destination_stat.st_mode):
        raise SystemExit(1)
' "$ARIA2_CONF" 2>/dev/null \
     || ! mv -fT "$_aria2_conf_tmp" "$ARIA2_CONF" 2>/dev/null; then
    echo "cannot install private aria2 RPC config" >&2
    exit 1
  fi
  unset _aria2_conf_tmp
  trap - EXIT
}

# Even identical bytes are republished to repair owner-only mode. This is safe
# while the daemon is live because its in-memory secret is already identical.
if [ "$RPC_CONFIG_CHANGED" = "0" ]; then
  publish_rpc_config
fi

# The per-peer transfer-record hook (--on-bt-download-complete, appended below).
# aria2 execs the value directly -- execlp with no shell (util.cc:2328) -- so
# it must be a real file with the exec bit, exactly like aria2c itself. /flash
# denies chmod, which is why aria2c is copied to $EXEC_DIR; a hook left in the
# stage dir could never be made executable, so it takes the same route.
#
# This runs ABOVE the "already up?" exit on purpose. Dropping a new bundle.tgz
# IS how the agent is upgraded, and an aria2c that is already serving is NOT
# relaunched -- so this is the only moment a refreshed hook can reach the path
# the running daemon already holds. The path never changes, so the live daemon
# picks up the new content on its next fire.
#
# temp + mv, never `cp -f` onto the live file: copying onto an executing file
# returns ETXTBSY, the same failure already documented for the binary below.
HOOK=""
if [ -f "$HOOK_SRC" ]; then
  _hook_tmp="$HOOK_DST.new.$$"
  if cp -f "$HOOK_SRC" "$_hook_tmp" 2>/dev/null \
     && chmod +x "$_hook_tmp" 2>/dev/null \
     && mv -f "$_hook_tmp" "$HOOK_DST" 2>/dev/null; then
    HOOK="$HOOK_DST"
  else
    rm -f "$_hook_tmp" 2>/dev/null || true
    # Not fatal, and deliberately so: without the hook a transfer still
    # completes and the report simply omits the per-peer transfer records
    # ("not measured"). Aborting the launcher over telemetry would silence
    # the device, which is the 2026-08-20 failure mode.
    echo "cannot install the peer-transfer hook at $HOOK_DST; transfers will run without per-peer transfer records" >&2
  fi
  unset _hook_tmp
fi
if [ -n "$HOOK" ]; then
  # Appended as an argument rather than written into the exec list literally:
  # Aria2 Next rejects an empty option value outright ("Empty string is not
  # allowed"), so --on-bt-download-complete= with no hook would stop aria2c
  # from launching at all -- the exact shape of the 2026-08-20 incident.
  set -- "$@" "--on-bt-download-complete=$HOOK"
fi

# --log is added only when an operator explicitly opts in (IRIS_LOG=on).
# Left off the exec line entirely when not: see the IRIS_LOG comment above
# for why that -- not a smaller/rotated file -- is what "off" means here.
case "$(printf '%s' "$IRIS_LOG" | tr '[:upper:]' '[:lower:]')" in
  on|1|true|yes) set -- "$@" "--log=$LOG" ;;
esac

# What the hook needs, handed over by inheritance through aria2c's fork rather
# than re-read from disk. The rpc-secret FILE and the running daemon can
# disagree (that skew IS the 2026-08-20 incident), and an empty file
# legitimately means the daemon is on the "iris" placeholder resolved above --
# so the value in this variable is the only one guaranteed to be the one the
# daemon is actually using. The daemon reads it from ARIA2_CONF, while the
# hook receives the same value by inheritance without putting it in argv.
# (The hook needs no stage path: aria2 hands it the staged file as argv[3].)
export IRIS_RPC_PORT="$RPC_PORT"
export IRIS_RPC_SECRET="$RPC_SECRET"

# Health-probe bounds, in seconds -- the same two questions the container
# supervisors ask (device/iox/entrypoint.sh, device/xr/entrypoint.sh):
#   * --connect-timeout answers "is anything bound to the RPC port". On
#     loopback a daemon that is gone refuses the connection instantly (curl
#     exit 7); a daemon that is merely busy still owns its listen socket, so
#     the kernel completes the connection for it.
#   * --max-time bounds the wait for the ANSWER, and sits well above the
#     longest stall a HEALTHY aria2c can have. Built without c-ares, aria2c
#     resolves tracker hostnames with a blocking getaddrinfo() on its
#     event-loop thread: one announce against a slow resolver freezes the whole
#     daemon -- RPC replies included -- for as long as the resolver takes
#     (5.03 s measured; glibc's 5 s x 2 attempts is the ceiling to design for).
# Unbounded, as this probe used to be, a wedged daemon hangs the launcher (and
# the EEM applet that runs it) instead.
RPC_CONNECT_TIMEOUT="${RPC_CONNECT_TIMEOUT:-2}"
RPC_HEALTH_TIMEOUT="${RPC_HEALTH_TIMEOUT:-10}"

rpc_probe() {
  printf '%s' \
    '{"jsonrpc":"2.0","id":"p","method":"aria2.getVersion","params":["token:'"$RPC_SECRET"'"]}' \
    | curl -s --connect-timeout "$RPC_CONNECT_TIMEOUT" --max-time "$RPC_HEALTH_TIMEOUT" \
      "http://127.0.0.1:$RPC_PORT/jsonrpc" --data-binary @- \
      >/dev/null 2>&1
}

rpc_up() {
  # A SLOW answer is not a dead daemon. Everything below this probe treats a
  # failure as "aria2c is not serving" and replaces it, so a probe that cannot
  # tell busy from dead kills healthy daemons and drops their in-flight
  # downloads. Connection refused means nothing is listening -- a verdict on
  # its own, and one that must stay immediate (the 2026-08-20 deadlock was a
  # stale daemon left alive). Any other failure is only a late answer, so
  # confirm it with a second probe: a resolver stall ends when the resolver
  # gives up, a wedged daemon fails the retry too.
  local rc=0
  rpc_probe || rc=$?
  case "$rc" in
    0) return 0 ;;
    7) return 1 ;;
  esac
  # A plain yes/no, never curl's own status: the caller asks "is it serving?".
  rpc_probe || return 1
}

aria2_pid_command() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  ps -ww -o args= -p "$pid" 2>/dev/null || return 1
}

aria2_pid_is_iris_rpc() {
  # Discovery by name is only a source of candidate PIDs. Ownership comes from
  # inspecting that PID's current argv: it must be the exact executable this
  # launcher owns, with RPC enabled on this launcher's configured port. This
  # deliberately excludes another aria2 daemon owned by the same Guest Shell
  # user, even if it also has --enable-rpc on its command line.
  local pid="$1" cmd executable
  cmd="$(aria2_pid_command "$pid")" || return 1
  # ps may left-pad its args column. Paths containing whitespace are not valid
  # Guest Shell executable locations; the production path is /home/guestshell.
  cmd="${cmd#"${cmd%%[![:space:]]*}"}"
  executable="${cmd%%[[:space:]]*}"
  [ "$executable" = "$ARIA2" ] || return 1
  case " $cmd " in
    *" --enable-rpc=true "*) ;;
    *) return 1 ;;
  esac
  case " $cmd " in
    *" --rpc-listen-port=$RPC_PORT "*) return 0 ;;
  esac
  return 1
}

iris_aria2_pids() {
  local pid
  while IFS= read -r pid; do
    aria2_pid_is_iris_rpc "$pid" && printf '%s\n' "$pid"
  done < <(pgrep -f 'aria2c' 2>/dev/null || true)
  # An unrelated final candidate makes the loop body's predicate false; that is
  # a successful filtered discovery, not an error for callers running under
  # `set -e`.
  return 0
}

aria2_tracker_tls_ready() {
  # A successful RPC answer proves the daemon is alive, not that it was
  # launched with HTTPS tracker verification. Inspect each matching daemon's
  # own command line and require the exact private conf path plus both exact TLS
  # options on the same PID. Never log the command line.
  local pid cmd
  while IFS= read -r pid; do
    # Re-read this exact PID rather than trusting the discovery snapshot. The
    # check is non-mutating, but using the same predicate as replacement keeps
    # an unrelated daemon from satisfying the healthy-IRIS decision too.
    aria2_pid_is_iris_rpc "$pid" || continue
    cmd="$(aria2_pid_command "$pid")" || continue
    case " $cmd " in
      *" --conf-path=$ARIA2_CONF "*) ;;
      *) continue ;;
    esac
    case " $cmd " in
      *" --rpc-secret"*) continue ;;
    esac
    case " $cmd " in
      *" --ca-certificate=$ARIA2_CA "*) ;;
      *) continue ;;
    esac
    case " $cmd " in
      *" --check-certificate=true "*) return 0 ;;
    esac
  done < <(iris_aria2_pids)
  return 1
}

# already up? (skip the probe in tests)
if [ "${SKIP_RPC_PROBE:-0}" != "1" ]; then
  if rpc_up; then
    if [ "$CA_SNAPSHOT_CHANGED" = "0" ] \
       && [ "$RPC_CONFIG_CHANGED" = "0" ] \
       && aria2_tracker_tls_ready; then
      echo "aria2c RPC already up on :$RPC_PORT with current tracker TLS verification"
      exit 0
    fi
    echo "aria2c RPC on :$RPC_PORT does not match the current tracker TLS generation — replacing it" >&2
  fi
fi

# Reaching here means the RPC probe failed OR the answering daemon lacks the
# required tracker TLS flags. Any surviving IRIS aria2c on this configured RPC
# port must go before relaunch: it still owns the RPC port (a new instance
# cannot bind) and `cp -f` over a running binary fails with ETXTBSY, so the
# stale build would keep running. Candidate discovery is deliberately broad,
# but signaling is PID-scoped and each PID is re-inspected immediately before
# the signal. Never sweep another aria2 daemon merely because its argv contains
# `enable-rpc`.
# Field incident 2026-08-20: leaving a non-answering process alive deadlocked
# devices for ~42 minutes — the agent hit ECONNREFUSED every tick and never
# reached its first heartbeat.
_iris_pids="$(iris_aria2_pids)"
if [ -n "$_iris_pids" ]; then
  echo "replacing the existing aria2c process on :$RPC_PORT" >&2
  _signaled_pids=""
  while IFS= read -r _pid; do
    [ -n "$_pid" ] || continue
    # PID reuse or an exec between discovery and this point must turn into a
    # skip, never a signal aimed at the new occupant.
    aria2_pid_is_iris_rpc "$_pid" || continue
    _signaled_pids="${_signaled_pids}${_signaled_pids:+
}${_pid}"
    # Use the external utility so the Bats safety harness can replace it. The
    # numeric PID has just been validated and is the only signal target.
    env kill -TERM "$_pid" 2>/dev/null || true
  done <<< "$_iris_pids"

  _w=0
  while [ -n "$_signaled_pids" ] && [ "$_w" -lt 10 ]; do
    _still_running=0
    while IFS= read -r _pid; do
      [ -n "$_pid" ] || continue
      if aria2_pid_is_iris_rpc "$_pid"; then
        _still_running=1
        break
      fi
    done <<< "$_signaled_pids"
    [ "$_still_running" = "1" ] || break
    sleep 1
    _w=$((_w + 1))
  done
  if [ "${_still_running:-0}" = "1" ]; then
    echo "existing aria2c process on :$RPC_PORT did not stop" >&2
    exit 1
  fi
fi
unset _iris_pids _signaled_pids _still_running _pid _w

# A content change stayed private in its sibling temp until every broadly
# owned old daemon was gone. A missing config follows this path too, so it is
# published before the new daemon launches.
if [ "$RPC_CONFIG_CHANGED" = "1" ]; then
  publish_rpc_config
fi

# copy the binary to an exec-capable fs and run it
cp -f "$ARIA2_SRC" "$ARIA2" \
  || { echo "cannot install aria2c from $ARIA2_SRC to $ARIA2" >&2; exit 1; }
chmod +x "$ARIA2" \
  || { echo "cannot make $ARIA2 executable" >&2; exit 1; }

# --check-integrity=true is a RESUME guard. Without it aria2 trusts the piece
# map recorded in the .aria2 control file, so a completed piece that rotted on
# flash (bit-rot, a torn write during a power loss) survives the resume: the
# torrent reports complete and the staged image carries the wrong SHA-256. The
# agent's whole-image hash still catches that, but only after the whole
# remaining transfer, and the repair is then a full re-stage instead of one
# 1 MiB piece. It rides the launch line because in aria2's own code
# (RequestGroup.cc, createInitialCommand for BitTorrent) it already costs
# nothing on the two paths that are not a resume: with nothing on disk every
# piece read returns 0 bytes and the piece is marked missing at once, and on a
# COMPLETED file --bt-seed-unverified=true above marks every piece done and
# aria2 skips validation entirely -- so a device seeding its staged images
# never re-hashes them at launch.
exec "$ARIA2" \
  --daemon=true \
  --enable-rpc=true \
  --rpc-listen-all=false \
  --rpc-listen-port="$RPC_PORT" \
  --conf-path="$ARIA2_CONF" \
  --ca-certificate="$ARIA2_CA" \
  --check-certificate=true \
  --enable-dht=false \
  --enable-peer-exchange=false \
  --bt-enable-lpd=false \
  --bt-max-peers="$MAX_PEERS" \
  --max-concurrent-downloads="$MAX_CONCURRENT" \
  "$@" \
  --bt-seed-unverified=true \
  --check-integrity=true \
  --seed-ratio=0.0 \
  --file-allocation=none \
  --dir="$STAGE_DIR" \
  --log-level=warn \
  --summary-interval=0
