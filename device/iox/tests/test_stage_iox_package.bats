#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# tools/stage-iox-package.sh validates inputs and picks the arch-correct name
# BEFORE building, so a missing cert / unwritable dir fails fast (no docker).

setup() {
  HELPER="$BATS_TEST_DIRNAME/../../../tools/stage-iox-package.sh"
  TMP="$(mktemp -d)"; ART="$TMP/artifacts"; mkdir -p "$ART"
  # "no docker" above is the point of this file, but the helper still PROBES
  # for a running iris container to decide whether it can source the pinned
  # cert (and the artifacts dir) from it. On a host that happens to be running
  # the IRIS stack that probe succeeds, the helper `docker cp`s the cert out of
  # the LIVE container and goes on to a full package build -- fetching
  # ioxclient over the network on the way -- so the fast-fail assertions below
  # were never reached and the file was green only on unprovisioned machines.
  # Stub docker to "no such container" so the input-validation paths under test
  # are exercised identically everywhere, with no daemon, container or network.
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
  run env CATALOG_PEM=/dev/null bash "$HELPER" --arch mips --artifacts-dir "$ART"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--arch must be amd64 or arm64"* ]]
}

@test "fails clearly when no cert inputs are set" {
  run env -u CATALOG_PEM -u CATALOG_PEM_URL PATH="$NODOCKER:$PATH" \
    bash "$HELPER" --artifacts-dir "$ART"
  [ "$status" -eq 1 ]
  [[ "$output" == *"CATALOG_PEM"* ]]
  # and it stopped at validation: no build, no ioxclient fetch
  [[ "$output" != *"building IOx package"* ]]
}

@test "fails when the artifacts dir is not writable" {
  chmod -w "$ART"
  run env CATALOG_PEM=/dev/null bash "$HELPER" --artifacts-dir "$ART"
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
# receive a torn package. It now copies to a dotted temp name and renames
# inside the container, mirroring the host branch. build.sh and docker are
# stubbed; the stub docker records every call.

@test "docker-cp placement copies to a temp name and mv's into place inside the container" {
  STUB="$BATS_TEST_TMPDIR/stub"; mkdir -p "$STUB/bin" "$STUB/tools" "$STUB/device/iox"
  ln -s "$HELPER" "$STUB/tools/stage-iox-package.sh"
  # fake build.sh: writes the package into the requested output dir
  cat > "$STUB/device/iox/build.sh" <<'B'
#!/usr/bin/env bash
echo "pkg bytes" > "$1/$PACKAGE_NAME"
B
  chmod +x "$STUB/device/iox/build.sh"
  export DOCKER_LOG="$BATS_TEST_TMPDIR/docker.log"; : > "$DOCKER_LOG"
  cat > "$STUB/bin/docker" <<'D'
#!/usr/bin/env bash
echo "$*" >> "$DOCKER_LOG"
case "$1" in
  inspect) exit 0 ;;
  cp) case "$2" in *:/srv/artifacts/iris-catalog.pem) printf -- '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n' > "$3" ;; esac; exit 0 ;;
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
  grep -q 'exec iris mv -f /srv/artifacts/.iris-amd64.tar.tmp /srv/artifacts/iris-amd64.tar' "$DOCKER_LOG"
  ! grep -q 'cp .*/iris-amd64.tar iris:/srv/artifacts/iris-amd64.tar$' "$DOCKER_LOG"
}

@test "arm64 emulation readiness is read from binfmt_misc before any image is pulled" {
  run grep -F '/proc/sys/fs/binfmt_misc/qemu-aarch64' "$HELPER"
  [ "$status" -eq 0 ]
}
