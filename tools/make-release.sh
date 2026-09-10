#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Assemble a clean, shareable IRIS release: all the code + docs someone needs
# to run it, and NONE of the lab secrets. Produces release/iris/ + a tarball,
# a sha256 of the tarball, and a per-member sha256 inventory (MANIFEST.txt).
#
# What ships is decided by `git ls-files`, never by what happens to be lying
# in the working tree: only TRACKED files under the allowlist below are
# copied. Anything gitignored (server/.env, keys under server/certs/, the
# licensed console typeface, docker-compose.override.yml, device/xr/out/,
# creds/, fleet CSVs, images, torrents, evidence) can therefore never reach
# the tarball, whatever the assembling checkout contains. Working-tree
# CONTENT of a tracked file is what ships (so an uncommitted edit is
# included); a tracked file that is missing from the working tree aborts.
#
# The release is built under a temporary directory and only moved into
# release/ once every step -- copy, scrub, leak check, tar, checksum -- has
# succeeded, so a failed run leaves the previous release/ untouched and can
# never leave a truncated iris.tgz behind.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE_DIR="$REPO/release"
OUT="$RELEASE_DIR/iris"
TARBALL="$RELEASE_DIR/iris.tgz"

git -C "$REPO" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || { echo "ERROR: $REPO is not a git checkout -- the release is assembled from tracked files only" >&2; exit 1; }

mkdir -p "$RELEASE_DIR"
WORK="$(mktemp -d "$RELEASE_DIR/.iris.tmp-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/iris"
mkdir -p "$STAGE"

# ---------------------------------------------------------------------------
# Allowlist. Directories are shipped in full (tracked files only); single
# files are shipped by name. `--error-unmatch` makes a pathspec that matches
# no tracked file a hard error, so a renamed/removed input cannot silently
# drop out of the release.
# ---------------------------------------------------------------------------
SHIP=(
  # top-level docs + build version (VERSION is the single source of truth)
  README.md CHANGELOG.md DEVELOPMENT.md CONTRIBUTING.md TESTING.md VERSION
  LICENSE NOTICE SECURITY.md CODE_OF_CONDUCT.md
  .gitignore .dockerignore
  # The README links into the Zensical source tree. Ship the source, static
  # public site, and exact build inputs so those links work in the unpacked
  # release and recipients can build the same manual published by CI.
  docs zensical.toml requirements-docs.txt
  # TESTING.md tells the recipient to install these before running the suites,
  # and server/ ships the tests, so the declaration has to travel with them.
  requirements-dev.txt
  # server (everything tracked; tests included -- no secrets are tracked here)
  server
  # device (agent + launcher + installer + EEM refs + IOx/XR packaging + tests)
  device
  # tools: the operator helpers, plus the corresponding source for the
  # handed-in (GPL) aria2c binary. GPLv2 section 3 wants the source AND the
  # scripts used to control compilation, and NOTICE now says both ship here,
  # so the release must carry aria2c-patches/ AND aria2c-build/ -- shipping
  # the notice without them would make the notice false.
  tools/get-aria2c.sh tools/aria2c.sha256 tools/make-torrent.sh
  tools/make-agent-bundle.sh tools/gen-device-installers.sh
  tools/apply-assignments.sh tools/get-ioxclient.sh tools/ioxclient.sha256
  tools/stage-iox-package.sh tools/provision-iox-packages.sh
  tools/build-device-image.sh tools/build-xr-package.sh
  tools/check-package-freshness.sh
  tools/agent-source-freshness.sh
  tools/start-compose-server.sh tools/make-release.sh
  tools/aria2c-patches tools/aria2c-build
  # The IOS-XE and IOS-XR transports the install/undeploy recipes call, and
  # the SSH host-key policy they (and the installers) source.
  lab/device-run.sh lab/xr-run.sh lab/xr-dialogue.pl lab/iris-ssh-policy.sh
  # optional Kubernetes seed-server deployment
  kubernetes
  # fleet: EXAMPLES ONLY (the real csv/conf carry tokens + passwords)
  fleet/README.md fleet/devices.csv.example fleet/assignments.csv.example
)

# Copy every tracked file under the allowlist, preserving the relative path.
# `git ls-files` lists index entries; the working-tree content is copied.
# Collect in the foreground: a process substitution hides git's failure exit
# status and would otherwise publish an incomplete release on a missing input.
git -C "$REPO" ls-files -z --error-unmatch -- "${SHIP[@]}" > "$WORK/tracked-files"
copied=0
while IFS= read -r -d '' rel; do
  case "$rel" in
    */__pycache__/*|*.pyc|*/.DS_Store|.DS_Store|*/._*) continue ;;
  esac
  src="$REPO/$rel"
  [ -f "$src" ] || { echo "ERROR: tracked file missing from the working tree: $rel" >&2; exit 1; }
  mkdir -p "$STAGE/$(dirname "$rel")"
  cp -p "$src" "$STAGE/$rel"
  copied=$((copied + 1))
done < "$WORK/tracked-files"
[ "$copied" -gt 0 ] || { echo "ERROR: nothing to ship" >&2; exit 1; }

# bin placeholder -- aria2c is fetched by tools/get-aria2c.sh for the DEVICE
# agent bundle; the server gets its own copy baked into the image at build time.
mkdir -p "$STAGE/bin"; : > "$STAGE/bin/.gitkeep"

# artifacts dir: ship it (empty) so it exists + is owned by the unpacking user
# BEFORE `docker compose up`. Otherwise Docker's `../artifacts` bind-mount
# auto-creates it as root, and tools/make-agent-bundle.sh (run as the normal
# user) can't write the bundle.
mkdir -p "$STAGE/artifacts"; : > "$STAGE/artifacts/.gitkeep"

# sanitize: scrub lab credentials out of the shipped copies. The targets are NOT
# hardcoded here (this file ships to a public/company mirror) -- they come from
# SCRUB_PASS / SCRUB_USER in the environment, or the gitignored creds/scrub.env.
# Values are passed to perl via the ENVIRONMENT (quotemeta'd, never interpolated
# into the regex) so special chars are safe. If neither is set, scrubbing is skipped.
[ -f "$REPO/creds/scrub.env" ] && . "$REPO/creds/scrub.env"
SCRUB_PASS="${SCRUB_PASS:-}"; SCRUB_USER="${SCRUB_USER:-}"
if [ -n "$SCRUB_PASS$SCRUB_USER" ]; then
  # Scrub all shipped text file types -- not just *.sh / *.conf* / *.example.
  # A username or password in a .py, .md, .json, .cfg, or .html file
  # would otherwise ship un-redacted.  `perl -I` (binary-safe) skips binary
  # files; `find ... ! -name '*.pyc'` avoids double-processing compiled bytecode.
  find "$STAGE" -type f ! -name '*.pyc' -print0 \
    | SCRUB_PASS="$SCRUB_PASS" SCRUB_USER="$SCRUB_USER" xargs -0 perl -pi -e '
        next if -B $ARGV;
        BEGIN { $p = $ENV{SCRUB_PASS}; $u = $ENV{SCRUB_USER}; }
        s/\Q$p\E/changeme/g if length $p;
        s/\b\Q$u\E\b/admin/g if length $u;'
fi

# safety net: refuse to package if any scrub secret leaked into the tree.
# Check BOTH SCRUB_PASS and SCRUB_USER -- the old net only checked the password,
# so a leaked operator login in a .py or .md would silently ship.
_leak=0
for _s in "$SCRUB_PASS" "$SCRUB_USER"; do
  [ -n "$_s" ] || continue
  if grep -rIlF "$_s" "$STAGE" --exclude-dir=.git >/dev/null 2>&1; then
    echo "ERROR: scrub secret found in the release tree -- fix before sharing:" >&2
    grep -rIlF "$_s" "$STAGE" >&2
    _leak=1
  fi
done
[ "$_leak" -eq 0 ] || exit 1

# ---------------------------------------------------------------------------
# Inventory + tarball. MANIFEST.txt lists the sha256 of every shipped member
# (paths relative to the unpacked directory, `sha256sum -c` format) and ships
# inside the tree; iris.tgz.sha256 sits beside the tarball.
# ---------------------------------------------------------------------------
_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}
# (bash functions are not visible to xargs, hence the inline sh -c below)
( cd "$WORK" && find iris -type f -print0 | LC_ALL=C sort -z \
    | xargs -0 sh -c 'if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi' _ ) \
  > "$WORK/MANIFEST.txt"
cp "$WORK/MANIFEST.txt" "$STAGE/MANIFEST.txt"

# Reproducible archive: member order, ownership and mtimes are fixed (GNU tar;
# bsdtar lacks --sort/--mtime and falls back to a plain archive), gzip stores
# no timestamp (-n). Strip macOS cruft so the tarball doesn't sprinkle
# AppleDouble (._*) and .DS_Store files across the extracted tree on Linux;
# COPYFILE_DISABLE stops bsdtar emitting resource-fork ._ entries and
# --no-xattrs drops com.apple.* extended-attr PAX headers.
find "$STAGE" \( -name '._*' -o -name '.DS_Store' \) -delete 2>/dev/null || true
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || date +%s)}"
TAR_REPRO=()
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  TAR_REPRO=(--sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH")
fi
COPYFILE_DISABLE=1 tar --no-xattrs --exclude='._*' --exclude='.DS_Store' \
  ${TAR_REPRO[@]+"${TAR_REPRO[@]}"} -cf - -C "$WORK" iris | gzip -n > "$WORK/iris.tgz"
( cd "$WORK" && _sha256 iris.tgz ) > "$WORK/iris.tgz.sha256"

# ---------------------------------------------------------------------------
# Publish: everything succeeded, so replace the previous release now. The
# directory swap is rename-then-remove, so a crash here leaves either the
# old or the new tree, never a half-copied one.
# ---------------------------------------------------------------------------
if [ -d "$OUT" ]; then
  mv "$OUT" "$WORK/iris.previous"
fi
mv "$STAGE" "$OUT"
mv -f "$WORK/iris.tgz" "$TARBALL"
mv -f "$WORK/iris.tgz.sha256" "$TARBALL.sha256"
mv -f "$WORK/MANIFEST.txt" "$RELEASE_DIR/MANIFEST.txt"

echo "Release ready (IRIS $(cat "$REPO/VERSION" 2>/dev/null || echo '?')):"
echo "  dir:      $OUT"
echo "  tarball:  $TARBALL  ($(du -h "$TARBALL" | awk '{print $1}'))"
echo "  sha256:   $TARBALL.sha256  ($(awk '{print $1}' "$TARBALL.sha256"))"
echo "  manifest: $RELEASE_DIR/MANIFEST.txt  ($copied tracked files)"
echo "Send the tarball and its .sha256. The recipient starts with README.md."
