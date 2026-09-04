#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Reproducible static-musl build of aria2-next, published as `aria2c`.
#
# THIS IS THE CORRESPONDING SOURCE for the aria2c binaries IRIS redistributes
# (GPLv2 section 3: the scripts used to control compilation). IRIS itself does
# not run this file -- the binary is handed in and verified against
# tools/aria2c.sha256 by tools/get-aria2c.sh. It is here so a recipient can
# rebuild what we ship.
#
# The patch set has ONE home: ../aria2c-patches. This directory deliberately
# holds no copy of it, because two copies drift.
#
#   ./build.sh x86_64     -> linux/amd64
#   ./build.sh aarch64    -> linux/arm64
#
# Artifacts land in out/<arch>/. Nothing is pushed anywhere.
set -euo pipefail

ARCH="${1:-}"
case "$ARCH" in
  x86_64)  PLATFORM=linux/amd64 ;;
  aarch64) PLATFORM=linux/arm64 ;;
  *) echo "usage: $0 <x86_64|aarch64>" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$REPO_ROOT/vendor/aria2-next"
OUT="$REPO_ROOT/out/$ARCH"

# The pin is the approved release tag, not a moving branch.
PIN_TAG="v2.5.6"
PIN_SHA="d4971f0e12322e2ffcdb1721911b7d5c6206d0e5"

# Installed executable name. Deliberately `aria2c` for drop-in compatibility
# with tooling that shells out to stock aria2. Note this build is a superset,
# not stock aria2: it is the aria2-next fork and still self-identifies as
# "Aria2 Next" in --version.
BIN_NAME="aria2c"

# Size gates from CLAUDE.md: target < 10 MB, hard fail > 15 MB.
SIZE_TARGET=$((10 * 1024 * 1024))
SIZE_HARD_FAIL=$((15 * 1024 * 1024))

[ -d "$SRC/.git" ] || { echo "FAIL: $SRC is not a git checkout" >&2; exit 1; }

actual_sha="$(git -C "$SRC" rev-parse HEAD)"
if [ "$actual_sha" != "$PIN_SHA" ]; then
  echo "FAIL: source is at $actual_sha, expected pin $PIN_SHA ($PIN_TAG)" >&2
  echo "      run: git -C vendor/aria2-next checkout $PIN_TAG" >&2
  exit 1
fi

# Reset every tracked file to the pin, not just src/ - a future patch touching
# cmake/ or CMakeLists.txt would otherwise leave stale edits behind and the
# build would silently not correspond to patches/.
git -C "$SRC" checkout -- .
# Upstream ships its own AGENTS.md of agent instructions. It is third-party
# input, not our configuration, and tooling auto-loads it. Removed after the
# reset restores it.
rm -f "$SRC/AGENTS.md"

# The patch set lives in ../aria2c-patches, the single tracked record of our
# changes to upstream. PATCH_DIR overrides it only for testing a candidate set.
PATCH_DIR="${PATCH_DIR:-$REPO_ROOT/../aria2c-patches}"
if compgen -G "$PATCH_DIR/*.patch" >/dev/null; then
  for pf in "$PATCH_DIR"/*.patch; do
    echo "applying patch: $(basename "$pf")"
    git -C "$SRC" apply --check "$pf" || {
      echo "FAIL: $(basename "$pf") does not apply cleanly to pin $PIN_TAG" >&2
      exit 1
    }
    git -C "$SRC" apply "$pf"
  done
fi

# CMakeLists.txt is upstream's single source of truth for the version. Reading
# it here keeps artifact names correct across a pin bump instead of drifting
# from a hardcoded constant.
VERSION="$(sed -n 's/^[[:space:]]*VERSION \([0-9][0-9.]*\)$/\1/p' "$SRC/CMakeLists.txt" | head -1)"
[ -n "$VERSION" ] || { echo "FAIL: could not read VERSION from CMakeLists.txt" >&2; exit 1; }

# Time-invariant build: derive the timestamp from the pinned commit.
SOURCE_DATE_EPOCH="$(git -C "$SRC" log -1 --format=%ct)"

ARTIFACT="$OUT/$BIN_NAME"
RELEASE_NAME="$BIN_NAME-$VERSION-linux-$ARCH-static"

echo "arch:      $ARCH ($PLATFORM)"
echo "pin:       $PIN_TAG / $PIN_SHA"
echo "version:   $VERSION (read from CMakeLists.txt)"
echo "artifact:  $BIN_NAME  (release name: $RELEASE_NAME)"
echo "epoch:     $SOURCE_DATE_EPOCH"
echo

mkdir -p "$OUT"

# vendor/ is gitignored so this cannot be a committed file; generate it here to
# keep the repo self-contained. Excluding .git is also why SOURCE_DATE_EPOCH is
# passed in as a build-arg rather than derived inside the container.
printf '%s\n' 'aria2-next/.git' 'aria2-next/docs/media' > "$REPO_ROOT/vendor/.dockerignore"

docker buildx build \
  --platform "$PLATFORM" \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --target artifact \
  --output "type=local,dest=$OUT" \
  --progress plain \
  -f "$REPO_ROOT/Dockerfile" \
  "$REPO_ROOT/vendor"

mv "$OUT/aria2-next" "$ARTIFACT"
chmod +x "$ARTIFACT"

echo
echo "=== verification (from inside the build) ==="
cat "$OUT/verification.txt"

echo
echo "=== size gate ==="
# GNU stat first, BSD/macOS second. The other order is a trap: on GNU coreutils
# `stat -f` means --file-system, so it SUCCEEDS and prints a block of
# filesystem stats, the `||` fallback never runs, and $bytes becomes multi-line
# text. Every comparison below then dies with "integer expression expected",
# which is not fatal inside an `if`, so the size gate silently passed anything
# -- including a binary over the hard-fail ceiling it exists to catch.
bytes="$(stat -c %s "$ARTIFACT" 2>/dev/null || stat -f %z "$ARTIFACT")"
printf 'stripped size: %s bytes (%.2f MB)\n' "$bytes" "$(echo "scale=4; $bytes/1048576" | bc)"
if [ "$bytes" -gt "$SIZE_HARD_FAIL" ]; then
  echo "HARD FAIL: > 15 MB"; exit 1
elif [ "$bytes" -gt "$SIZE_TARGET" ]; then
  echo "OVER TARGET: > 10 MB, under the 15 MB hard fail"
else
  echo "UNDER TARGET: < 10 MB"
fi
