#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Assemble a clean, shareable IRIS release: all the code + docs someone needs
# to run it, and NONE of the lab secrets (creds/, fleet/iris-fleet.conf, devices.csv,
# tokens, images, torrents, evidence). Produces release/iris/ + a tarball.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/release/iris"
TARBALL="$REPO/release/iris.tgz"

rm -rf "$OUT"; mkdir -p "$OUT"

# top-level docs + build version (the VERSION file is the single source of truth)
cp "$REPO/README.md" "$REPO/VERSION" "$OUT/"
cp "$REPO/LICENSE" "$REPO/NOTICE" "$REPO/SECURITY.md" "$REPO/CODE_OF_CONDUCT.md" "$OUT/"
cp "$REPO/.gitignore" "$REPO/.dockerignore" "$OUT/"

# server (everything; tests included — no secrets live here)
mkdir -p "$OUT/server"
cp -R "$REPO/server/." "$OUT/server/"

# device (agent + launcher + installer + EEM refs + tests)
mkdir -p "$OUT/device"
cp -R "$REPO/device/." "$OUT/device/"

# tools
mkdir -p "$OUT/tools"
for f in get-aria2c.sh make-torrent.sh make-agent-bundle.sh \
         gen-device-installers.sh apply-assignments.sh; do
  cp "$REPO/tools/$f" "$OUT/tools/"
done

# lab helpers (the installer drives devices through these)
mkdir -p "$OUT/lab"
for f in device-run.sh gsrun.sh device-copy.sh; do
  cp "$REPO/lab/$f" "$OUT/lab/"
done

# optional Kubernetes seed-server deployment
mkdir -p "$OUT/kubernetes"
cp -R "$REPO/kubernetes/." "$OUT/kubernetes/"

# fleet: EXAMPLES ONLY (the real csv/conf carry tokens + passwords)
mkdir -p "$OUT/fleet"
cp "$REPO/fleet/README.md" "$REPO/fleet/devices.csv.example" \
   "$REPO/fleet/assignments.csv.example" "$REPO/fleet/iris-fleet.conf.example" "$OUT/fleet/"

# bin placeholder (the binary itself is fetched by tools/get-aria2c.sh)
mkdir -p "$OUT/bin"; : > "$OUT/bin/.gitkeep"

# artifacts dir: ship it (empty) so it exists + is owned by the unpacking user BEFORE
# `docker compose up`. Otherwise Docker's `../artifacts` bind-mount auto-creates it as
# root, and tools/make-agent-bundle.sh (run as the normal user) can't write the bundle.
mkdir -p "$OUT/artifacts"; : > "$OUT/artifacts/.gitkeep"

# scrub anything that must never ship
find "$OUT" -type d \( -name '__pycache__' -o -name '.pytest_cache' \) -prune -exec rm -rf {} + 2>/dev/null || true
find "$OUT" -name '*.pyc' -delete -o -name '.DS_Store' -delete 2>/dev/null || true

# sanitize: scrub lab credentials out of the shipped copies. The targets are NOT
# hardcoded here (this file ships to a public/company mirror) — they come from
# SCRUB_PASS / SCRUB_USER in the environment, or the gitignored creds/scrub.env.
# Values are passed to perl via the ENVIRONMENT (quotemeta'd, never interpolated
# into the regex) so special chars are safe. If neither is set, scrubbing is skipped.
[ -f "$REPO/creds/scrub.env" ] && . "$REPO/creds/scrub.env"
SCRUB_PASS="${SCRUB_PASS:-}"; SCRUB_USER="${SCRUB_USER:-}"
if [ -n "$SCRUB_PASS$SCRUB_USER" ]; then
  # Scrub all shipped text file types — not just *.sh / *.conf* / *.example.
  # A username or password in a .py, .md, .json, .cfg, .service, or .html file
  # would otherwise ship un-redacted.  `perl -I` (binary-safe) skips binary
  # files; `find … ! -name '*.pyc'` avoids double-processing compiled bytecode.
  find "$OUT" -type f ! -name '*.pyc' -print0 \
    | SCRUB_PASS="$SCRUB_PASS" SCRUB_USER="$SCRUB_USER" xargs -0 perl -pi -e '
        next if -B $ARGV;
        BEGIN { $p = $ENV{SCRUB_PASS}; $u = $ENV{SCRUB_USER}; }
        s/\Q$p\E/changeme/g if length $p;
        s/\b\Q$u\E\b/admin/g if length $u;'
fi

# safety net: refuse to package if any scrub secret leaked into the tree.
# Check BOTH SCRUB_PASS and SCRUB_USER — the old net only checked the password,
# so a leaked operator login in a .py or .md would silently ship.
_leak=0
for _s in "$SCRUB_PASS" "$SCRUB_USER"; do
  [ -n "$_s" ] || continue
  if grep -rIlF "$_s" "$OUT" --exclude-dir=.git >/dev/null 2>&1; then
    echo "ERROR: scrub secret found in the release tree — fix before sharing:" >&2
    grep -rIlF "$_s" "$OUT" >&2
    _leak=1
  fi
done
[ "$_leak" -eq 0 ] || exit 1

# Strip macOS cruft so the tarball doesn't sprinkle AppleDouble (._*) and
# .DS_Store files across the extracted tree on Linux. COPYFILE_DISABLE stops
# bsdtar from emitting the resource-fork ._ entries in the first place; the
# --exclude is belt-and-suspenders for GNU tar / pre-existing junk. --no-xattrs
# additionally drops com.apple.provenance/quarantine extended-attr PAX headers
# (harmless but noisy on GNU tar extract).
find "$OUT" \( -name '._*' -o -name '.DS_Store' \) -delete 2>/dev/null || true
COPYFILE_DISABLE=1 tar --no-xattrs --exclude='._*' --exclude='.DS_Store' \
  -czf "$TARBALL" -C "$REPO/release" iris
echo "Release ready (IRIS $(cat "$REPO/VERSION" 2>/dev/null || echo '?')):"
echo "  dir:     $OUT"
echo "  tarball: $TARBALL  ($(du -h "$TARBALL" | awk '{print $1}'))"
echo "Send the tarball. The recipient starts with README.md."
