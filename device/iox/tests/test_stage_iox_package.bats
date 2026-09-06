#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# tools/stage-iox-package.sh validates inputs, picks the arch-correct name, and
# publishes each package with its adjacent provenance manifest.

setup() {
  HELPER="$BATS_TEST_DIRNAME/../../../tools/stage-iox-package.sh"
  TMP="$(mktemp -d)"; ART="$TMP/artifacts"; mkdir -p "$ART"
  # Stub docker to "no such container" so validation paths never depend on a
  # developer's running lab.
  NODOCKER="$TMP/nodocker"; mkdir -p "$NODOCKER"
  printf '#!/bin/sh\nexit 1\n' > "$NODOCKER/docker"
  chmod +x "$NODOCKER/docker"
}
teardown() { rm -rf "$TMP"; }

@test "help lists --arch and --artifacts-dir" {
  run bash "$HELPER" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--arch"* ]]
  [[ "$output" == *"--artifacts-dir"* ]]
}

@test "rejects an invalid --arch before building" {
  run bash "$HELPER" --arch mips --artifacts-dir "$ART"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--arch must be amd64 or arm64"* ]]
}

@test "fails when the artifacts dir is not writable" {
  chmod -w "$ART"
  run env PATH="$NODOCKER:$PATH" bash "$HELPER" --artifacts-dir "$ART"
  chmod +w "$ART"
  [ "$status" -eq 1 ]
  [[ "$output" == *"not writable"* ]]
}

@test "has no syntax errors" {
  run bash -n "$HELPER"
  [ "$status" -eq 0 ]
}

# ── docker cp placement is atomic ────────────────────────────────────────────
# The docker-cp branch (artifacts dir not writable, container running) used to
# copy straight onto /srv/artifacts/<pkg>, so a device fetching mid-copy could
# receive a torn package. The provenance sidecar is removed before the wrapper
# is replaced and published only after it. build.sh and docker are stubbed;
# the stub docker records every call.

@test "docker-cp placement copies to a temp name and mv's into place inside the container" {
  STUB="$BATS_TEST_TMPDIR/stub"; mkdir -p "$STUB/bin" "$STUB/tools" "$STUB/device/iox"
  ln -s "$HELPER" "$STUB/tools/stage-iox-package.sh"
  # fake build.sh: writes the package into the requested output dir
  cat > "$STUB/device/iox/build.sh" <<'B'
#!/usr/bin/env bash
echo "pkg bytes" > "$1/$PACKAGE_NAME"
echo "provenance" > "$1/$PACKAGE_NAME.manifest"
B
  chmod +x "$STUB/device/iox/build.sh"
  export DOCKER_LOG="$BATS_TEST_TMPDIR/docker.log"; : > "$DOCKER_LOG"
  cat > "$STUB/bin/docker" <<'D'
#!/usr/bin/env bash
echo "$*" >> "$DOCKER_LOG"
case "$1" in
  inspect) exit 0 ;;
  cp) exit 0 ;;
  exec) exit 0 ;;
  *) exit 0 ;;
esac
D
  chmod +x "$STUB/bin/docker"
  # unwritable default artifacts dir -> the docker-cp branch
  mkdir -p "$STUB/artifacts"; chmod -w "$STUB/artifacts"
  run env PATH="$STUB/bin:$PATH" IOXCLIENT=/bin/true bash "$STUB/tools/stage-iox-package.sh" --arch amd64
  chmod +w "$STUB/artifacts"
  [ "$status" -eq 0 ]
  grep -q 'cp .*/iris-amd64.tar iris:/srv/artifacts/.iris-amd64.tar.tmp' "$DOCKER_LOG"
  grep -q 'cp .*/iris-amd64.tar.manifest iris:/srv/artifacts/.iris-amd64.tar.manifest.tmp' "$DOCKER_LOG"
  grep -q 'exec iris rm -f /srv/artifacts/iris-amd64.tar.manifest' "$DOCKER_LOG"
  grep -q 'exec iris mv -f /srv/artifacts/.iris-amd64.tar.tmp /srv/artifacts/iris-amd64.tar' "$DOCKER_LOG"
  grep -q 'exec iris mv -f /srv/artifacts/.iris-amd64.tar.manifest.tmp /srv/artifacts/iris-amd64.tar.manifest' "$DOCKER_LOG"
  ! grep -q 'cp .*/iris-amd64.tar iris:/srv/artifacts/iris-amd64.tar$' "$DOCKER_LOG"
}

@test "host placement publishes wrapper and provenance together" {
  STUB="$BATS_TEST_TMPDIR/host-stub"
  mkdir -p "$STUB/tools" "$STUB/device/iox"
  ln -s "$HELPER" "$STUB/tools/stage-iox-package.sh"
  cat > "$STUB/device/iox/build.sh" <<'B'
#!/usr/bin/env bash
printf 'pkg bytes\n' > "$1/$PACKAGE_NAME"
printf 'provenance\n' > "$1/$PACKAGE_NAME.manifest"
B
  chmod +x "$STUB/device/iox/build.sh"

  # Placement is architecture-independent. Keep this stubbed build off the
  # ARM emulation bootstrap path so it needs neither binfmt nor Docker.
  run env PATH="$NODOCKER:$PATH" IOXCLIENT=/bin/true bash "$STUB/tools/stage-iox-package.sh" \
    --arch amd64 --artifacts-dir "$ART"
  [ "$status" -eq 0 ]
  [ "$(cat "$ART/iris-amd64.tar")" = "pkg bytes" ]
  [ "$(cat "$ART/iris-amd64.tar.manifest")" = "provenance" ]
  ! find "$ART" -maxdepth 1 -name '.iris-amd64.tar*' | grep -q .
}

@test "arm64 emulation readiness is read from binfmt_misc before any image is pulled" {
  run grep -F '/proc/sys/fs/binfmt_misc/qemu-aarch64' "$HELPER"
  [ "$status" -eq 0 ]
}
