#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Build and exec the aria2c seeder for IRIS. The container entrypoint runs this
# in the foreground. RPC is enabled so iris-publish can add new torrents
# live; every torrent already in the state dir is (re)seeded at startup.
# Private swarm: DHT / PEX / LPD all OFF.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

IRIS_ROOT="${IRIS_ROOT:-/opt/iris}"
IRIS_STATE="${IRIS_STATE:-/var/lib/iris}"
IRIS_CONFIG="${IRIS_CONFIG:-/etc/iris}"
IRIS_LOG="${IRIS_LOG:-/var/log/iris}"
IMAGES_DIR="${IMAGES_DIR:-/opt/images/iosxe/c9300}"
RPC_PORT="${RPC_PORT:-6800}"
ARIA2="${ARIA2:-$IRIS_ROOT/bin/aria2c}"

# Plaintext rpc-secret lives in tmpfs (decrypted at entrypoint). The volume-path
# fallback below is legacy and unreached in practice: the entrypoint always sets
# IRIS_RPC_SECRET_FILE. Left in place deliberately — removing it would force a
# rewrite of test_seed_launch.bats for no behavior change.
RPC_SECRET_FILE="${IRIS_RPC_SECRET_FILE:-$IRIS_CONFIG/rpc-secret}"
RPC_SECRET="$(cat "$RPC_SECRET_FILE" 2>/dev/null)" \
  || { echo "FATAL: rpc-secret missing or unreadable: $RPC_SECRET_FILE" >&2; exit 1; }
if [ -z "$RPC_SECRET" ]; then
  echo "FATAL: rpc-secret is empty in $RPC_SECRET_FILE — refusing to launch unauthenticated" >&2
  exit 1
fi
# SEEDER_LOG=- sends the log to stdout (the container does this so docker's
# json-file rotation caps it).
LOGFILE="${SEEDER_LOG:-$IRIS_LOG/seeder.log}"
# Pin the BT data port (so docker can publish it) and, in the container, tell the
# tracker our EXTERNAL address — otherwise peers are handed the container's
# internal IP and can never connect.
LISTEN_PORT="${LISTEN_PORT:-6881}"
EXT_FLAG=""
[ -n "${IRIS_HOST_IP:-}" ] && EXT_FLAG="--bt-external-ip=$IRIS_HOST_IP"

# Lift aria2's concurrency cap, which defaults to 5 and would otherwise starve
# this catalog. A SEEDING torrent never completes -- --seed-ratio=0.0 below means
# "seed forever" -- so each torrent holds one of those slots permanently, and
# every published image past the fifth is left queued, never seeded, forever.
# That failure is completely silent: aria2 reports the extras as `waiting`, not
# as an error, so a device assigned a starved image just reports staging
# indefinitely with no error recorded anywhere (live incident 2026-08-31: six
# published images, ie3x00 stuck in tellWaiting, an IE-3400 wedged in staging).
# This process only ever seeds, so the cap protects nothing here.
#
# A constant well above any plausible catalog, deliberately NOT a count derived
# from the input file: `iris-publish` adds torrents over RPC while this process
# runs, and a launch-time count would starve exactly those runtime additions.
SEED_MAX_CONCURRENT="${SEED_MAX_CONCURRENT:-1000}"

# Re-seed EVERY published torrent from its image's ACTUAL directory. Images live
# in per-model subdirs (/opt/images/iosxe/{c9300,IE3400,...}), so a single global
# --dir can't cover them: a torrent whose image isn't under --dir errors out
# ("Failed to open file ... Read-only file system") and never seeds. Build a
# per-torrent aria2 input file pairing each torrent with the dir that actually
# holds its image (located via the catalog id->filename map + a walk of the image
# tree). This is what lets the origin re-seed e.g. an IE-3x00 image after a
# restart, not just the c9300 images. (Runtime `iris-publish` still adds new
# torrents with an explicit per-call dir; this only governs startup re-seed.)
IMAGES_ROOT="${IMAGES_ROOT:-/opt/images}"
IRIS_IMAGES_DIR="${IRIS_IMAGES_DIR:-/var/lib/iris-images}"
RUN_DIR="${IRIS_RUN:-$IRIS_STATE}"
INPUT="$RUN_DIR/seeder.input"
mkdir -p "$RUN_DIR" 2>/dev/null || true
python3 "$SCRIPT_DIR/reseed_input.py" "$IRIS_STATE" "$IRIS_IMAGES_DIR:$IMAGES_ROOT" "$IMAGES_DIR" > "$INPUT" 2>/dev/null || : > "$INPUT"

# The RPC secret goes through a mode-0600 aria2 conf file, never the argv:
# `--rpc-secret=...` on the command line is visible to every local user on
# the Docker host via /proc/<pid>/cmdline (`docker top iris`, `ps`), which
# undoes the tmpfs-only discipline the entrypoint keeps for the plaintext.
# aria2 reads --conf-path before the remaining options, so everything else
# stays on the command line where the tests and operators can see it.
CONF="$RUN_DIR/seeder.aria2.conf"
( umask 077; printf 'rpc-secret=%s\n' "$RPC_SECRET" > "$CONF" ) \
  || { echo "FATAL: cannot write $CONF" >&2; exit 1; }
chmod 0600 "$CONF"
unset RPC_SECRET

# Tracker authentication is an HTTP Authorization header, never a query
# parameter in the torrent and never an argv value. Append it directly from
# the tmpfs secret store into the mode-0600 aria2 config.
PYTHONPATH="$SCRIPT_DIR" python3 - "${IRIS_SECRETS:-$RUN_DIR/secrets.json}" "$CONF" <<'PY' || {
import os
import sys
import secrets_store

store = secrets_store.load(sys.argv[1])
token = store.get("seeder", {}).get("announce_token", {}).get("value")
if not isinstance(token, str) or not token:
    raise SystemExit(1)
with open(sys.argv[2], "a") as stream:
    stream.write("header=Authorization: Bearer %s\n" % token)
PY
  echo "FATAL: seeder announce credential missing or unreadable — refusing to launch" >&2
  exit 1
}

exec "$ARIA2" \
  --conf-path="$CONF" \
  --listen-port="$LISTEN_PORT" \
  ${EXT_FLAG:+"$EXT_FLAG"} \
  --enable-rpc=true \
  --rpc-listen-all=false \
  --rpc-listen-port="$RPC_PORT" \
  --enable-dht=false \
  --enable-peer-exchange=false \
  --bt-enable-lpd=false \
  --bt-seed-unverified=true \
  --seed-ratio=0.0 \
  --max-concurrent-downloads="$SEED_MAX_CONCURRENT" \
  --file-allocation=none \
  --dir="$IMAGES_DIR" \
  --log="$LOGFILE" \
  --log-level=warn \
  --summary-interval=0 \
  --input-file="$INPUT"
