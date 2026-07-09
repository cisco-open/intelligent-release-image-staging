#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Build and exec the aria2c seeder for IRIS. systemd runs this in the
# foreground (Type=simple). RPC is enabled so iris-publish can add new torrents
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

# Plaintext rpc-secret lives in tmpfs (decrypted at entrypoint); fall back to
# the legacy volume path only when the broker env var is unset (bare-metal).
RPC_SECRET_FILE="${IRIS_RPC_SECRET_FILE:-$IRIS_CONFIG/rpc-secret}"
RPC_SECRET="$(cat "$RPC_SECRET_FILE" 2>/dev/null)" \
  || { echo "FATAL: rpc-secret missing or unreadable: $RPC_SECRET_FILE" >&2; exit 1; }
if [ -z "$RPC_SECRET" ]; then
  echo "FATAL: rpc-secret is empty in $RPC_SECRET_FILE — refusing to launch unauthenticated" >&2
  exit 1
fi
# SEEDER_LOG=- sends the log to stdout (the container does this so docker's
# json-file rotation caps it); bare-metal keeps the file + logrotate.d policy.
LOGFILE="${SEEDER_LOG:-$IRIS_LOG/seeder.log}"
# Pin the BT data port (so docker can publish it) and, in the container, tell the
# tracker our EXTERNAL address — otherwise peers are handed the container's
# internal IP and can never connect.
LISTEN_PORT="${LISTEN_PORT:-6881}"
EXT_FLAG=""
[ -n "${IRIS_HOST_IP:-}" ] && EXT_FLAG="--bt-external-ip=$IRIS_HOST_IP"

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

exec "$ARIA2" \
  --listen-port="$LISTEN_PORT" \
  ${EXT_FLAG:+"$EXT_FLAG"} \
  --enable-rpc=true \
  --rpc-listen-all=false \
  --rpc-listen-port="$RPC_PORT" \
  --rpc-secret="$RPC_SECRET" \
  --enable-dht=false \
  --enable-peer-exchange=false \
  --bt-enable-lpd=false \
  --bt-seed-unverified=true \
  --seed-ratio=0.0 \
  --file-allocation=none \
  --dir="$IMAGES_DIR" \
  --log="$LOGFILE" \
  --log-level=warn \
  --summary-interval=0 \
  --input-file="$INPUT"
