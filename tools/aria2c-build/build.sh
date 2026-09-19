#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Reproducible static-musl build of aria2-next, published as `aria2c`.
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

# One bound covers compiler jobs and GCC's separate LTO worker pool. Keep the
# default modest for emulated ARM builders sharing a host with lab services.
ARIA2C_BUILD_JOBS="${ARIA2C_BUILD_JOBS-2}"
case "$ARIA2C_BUILD_JOBS" in
  ''|0*|*[!0-9]*)
    echo "FAIL: ARIA2C_BUILD_JOBS must be a positive integer" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$REPO_ROOT/vendor/aria2-next"
OUT="${ARIA2_OUTPUT_DIR:-$REPO_ROOT/out/$ARCH}"

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

# Build an archive of the approved LOCAL pin. Never reset the working source:
# vendor/ may contain another investigation or operator changes.
mkdir -p "$REPO_ROOT/agentinfo"
BUILD_CONTEXT="$(mktemp -d "$REPO_ROOT/agentinfo/aria2-build.XXXXXX")"
trap 'rm -rf -- "$BUILD_CONTEXT"' EXIT
mkdir "$BUILD_CONTEXT/aria2-next"
git -C "$SRC" archive "$PIN_SHA" | tar -x -C "$BUILD_CONTEXT/aria2-next"
SOURCE_DATE_EPOCH="$(git -C "$SRC" log -1 --format=%ct)"
SRC="$BUILD_CONTEXT/aria2-next"
rm -f "$SRC/AGENTS.md"
# An independent repository prevents git apply from silently skipping files
# inside the parent repository's ignored agentinfo directory.
git -C "$SRC" init -q

# vendor/ is gitignored, so patches/ is the only tracked record of our changes.
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
printf '%s\n' 'aria2-next/.git' 'aria2-next/docs/media' > "$BUILD_CONTEXT/.dockerignore"

docker buildx build \
  --platform "$PLATFORM" \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --build-arg "ARIA2C_BUILD_JOBS=$ARIA2C_BUILD_JOBS" \
  --target artifact \
  --output "type=local,dest=$OUT" \
  --progress plain \
  -f "$REPO_ROOT/Dockerfile" \
  "$BUILD_CONTEXT"

mv "$OUT/aria2-next" "$ARTIFACT"
chmod +x "$ARTIFACT"

echo
echo "=== verification (from inside the build) ==="
cat "$OUT/verification.txt"

echo
echo "=== size gate ==="
bytes="$(stat -c %s "$ARTIFACT" 2>/dev/null || stat -f %z "$ARTIFACT")"
printf 'stripped size: %s bytes (%.2f MB)\n' "$bytes" "$(echo "scale=4; $bytes/1048576" | bc)"
if [ "$bytes" -gt "$SIZE_HARD_FAIL" ]; then
  echo "HARD FAIL: > 15 MB"; exit 1
elif [ "$bytes" -gt "$SIZE_TARGET" ]; then
  echo "OVER TARGET: > 10 MB, under the 15 MB hard fail"
else
  echo "UNDER TARGET: < 10 MB"
fi
