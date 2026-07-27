#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# One-shot, idempotent installer for the IRIS coordination server.
# Re-run = upgrade (code/units refreshed; cert/secret/tokens preserved).
# --uninstall removes everything EXCEPT the state dir (operator data).
# All paths are env-overridable; set SKIP_PRIVILEGED=1 to skip useradd/systemctl
# (used by the test to run unprivileged into a temp prefix).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IRIS_ROOT="${IRIS_ROOT:-/opt/iris}"
IRIS_STATE="${IRIS_STATE:-/var/lib/iris}"
IRIS_CONFIG="${IRIS_CONFIG:-/etc/iris}"
IRIS_LOG="${IRIS_LOG:-/var/log/iris}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
LOGROTATE_DIR="${LOGROTATE_DIR:-/etc/logrotate.d}"
SERVICE_USER="${SERVICE_USER:-iris}"
HOST_IP="${IRIS_HOST_IP:-127.0.0.1}"
SKIP_PRIVILEGED="${SKIP_PRIVILEGED:-0}"
# The age master PRIVATE key must NOT live in $IRIS_CONFIG next to the
# ciphertext it opens — co-locating them means any backup/snapshot/read of
# the config dir yields both halves and the at-rest encryption is theater.
# Default it to a dedicated operator-held dir OUTSIDE $IRIS_CONFIG; it is
# created 0700 and is deliberately excluded from the recursive chown below.
IRIS_KEY_DIR="${IRIS_KEY_DIR:-/etc/iris-key}"
IRIS_AGE_KEY_FILE="${IRIS_AGE_KEY_FILE:-$IRIS_KEY_DIR/.iris_age_key}"
DRY=0

log()  { echo "[install] $*"; }
run()  { if [ "$DRY" -eq 1 ]; then echo "  would: $*"; else eval "$*"; fi; }
priv() { if [ "$SKIP_PRIVILEGED" -eq 1 ]; then echo "  skip-priv: $*"; else run "$*"; fi; }

uninstall() {
  log "uninstalling (state dir $IRIS_STATE preserved)"
  priv "systemctl disable --now iris-tracker iris-catalog iris-seeder iris-artifacts iris-gui 2>/dev/null || true"
  run "rm -f '$SYSTEMD_DIR'/iris-*.service"
  run "rm -f '$LOGROTATE_DIR/iris'"
  run "rm -rf '$IRIS_ROOT' '$IRIS_CONFIG' '$IRIS_LOG'"
  priv "systemctl daemon-reload 2>/dev/null || true"
  log "done."
}

install() {
  log "installing from $REPO_ROOT"

  # 1. service user (privileged)
  priv "id -u '$SERVICE_USER' >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin '$SERVICE_USER'"

  # 2. directories
  run "mkdir -p '$IRIS_ROOT/server' '$IRIS_ROOT/bin' '$IRIS_STATE/torrents' '$IRIS_CONFIG/tls' '$IRIS_LOG'"
  # operator-held key dir, kept OFF the config volume (0700, never world-readable)
  run "mkdir -p '$IRIS_KEY_DIR'"
  run "chmod 700 '$IRIS_KEY_DIR'"

  # 3. code + binary (always refreshed = upgrade)
  run "cp -r '$REPO_ROOT/server/.' '$IRIS_ROOT/server/'"
  run "cp '$REPO_ROOT/bin/aria2c' '$IRIS_ROOT/bin/aria2c' 2>/dev/null || true"
  run "chmod +x '$IRIS_ROOT/server/seed-launch.sh' '$IRIS_ROOT/server/iris-publish' \
       '$IRIS_ROOT/server/iris-bootstrap' '$IRIS_ROOT/server/iris-secretfs' \
       '$IRIS_ROOT/bin/aria2c' 2>/dev/null || true"

  # 4–5. Encrypted secrets bootstrap (idempotent: no-op if .age files exist).
  # iris-bootstrap generates the age key (if missing), the rpc-secret, TLS
  # key+cert, and an initial secrets.json, then encrypts them to .age files
  # on the iris-config volume — no plaintext tokens.txt, no plaintext rpc-secret.
  # tokens.txt is retired; the broker manages per-device tokens in secrets.json.
  if [ "$DRY" -eq 1 ]; then
    echo "  would: run iris-bootstrap (idempotent; skipped in dry-run)"
  else
    IRIS_CONFIG="$IRIS_CONFIG" IRIS_HOST_IP="$HOST_IP" \
      IRIS_AGE_KEY_FILE="$IRIS_AGE_KEY_FILE" \
      IRIS_AGE_RECIPIENTS="${IRIS_AGE_RECIPIENTS:-}" \
      bash "$IRIS_ROOT/server/iris-bootstrap"
  fi

  # 7. systemd units + logrotate
  run "mkdir -p '$SYSTEMD_DIR' '$LOGROTATE_DIR'"
  run "cp '$REPO_ROOT/server/systemd/'*.service '$SYSTEMD_DIR/'"
  run "cp '$REPO_ROOT/server/logrotate.d/iris' '$LOGROTATE_DIR/iris'"

  # 8. ownership (privileged). NOTE: the recursive chown deliberately does NOT
  # cover $IRIS_KEY_DIR — the master key must not be swept into the same
  # ownership/backup surface as the ciphertext under $IRIS_CONFIG.
  priv "chown -R '$SERVICE_USER:$SERVICE_USER' '$IRIS_ROOT' '$IRIS_STATE' '$IRIS_CONFIG' '$IRIS_LOG'"
  # The unseal ExecStartPre runs as $SERVICE_USER and must read the key; give
  # it (and only it) ownership of the dedicated key dir, kept 0700/0600.
  priv "chown -R '$SERVICE_USER:$SERVICE_USER' '$IRIS_KEY_DIR'"
  priv "chmod 700 '$IRIS_KEY_DIR'"
  priv "chmod 600 '$IRIS_AGE_KEY_FILE' 2>/dev/null || true"

  # 9. enable + (re)start services (privileged)
  priv "systemctl daemon-reload"
  priv "systemctl enable --now iris-tracker iris-catalog iris-seeder iris-artifacts iris-gui"

  log "done. tracker :6969  catalog :8443 (https)  seeder rpc :6800"
  log "age key: $IRIS_AGE_KEY_FILE   (operator-held, OFF the config volume — back up + protect separately)"
  log "enroll device: IRIS_SECRETS=/run/iris/secrets.json $IRIS_ROOT/server/iris-mint-enrollment <device_id>"
  log "publish image: $IRIS_ROOT/server/iris-publish <img>"
}

case "${1:-}" in
  --uninstall) uninstall ;;
  --dry-run)   DRY=1; install ;;
  "")          install ;;
  *) echo "usage: install.sh [--dry-run|--uninstall]" >&2; exit 2 ;;
esac
