#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# build.sh: --amd64 is accepted and defaults the package name to iris-amd64.tar
# (naming-collision fix, gap #4). We do not run a full docker build here — we
# verify the flag is parsed and the amd64 default name is wired.

setup() { BUILD="$BATS_TEST_DIRNAME/../build.sh"; }

@test "build.sh --help lists the --amd64 flag" {
  run bash "$BUILD" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--amd64"* ]]
}

@test "build.sh has no syntax errors" {
  run bash -n "$BUILD"
  [ "$status" -eq 0 ]
}

@test "amd64 arm defaults PACKAGE_NAME to iris-amd64.tar" {
  run grep -F "DEFAULT_PACKAGE_NAME=iris-amd64.tar" "$BUILD"
  [ "$status" -eq 0 ]
}

@test "arm64 defaults PACKAGE_NAME to iris-arm64.tar" {
  run grep -F "DEFAULT_PACKAGE_NAME=iris-arm64.tar" "$BUILD"
  [ "$status" -eq 0 ]
}

@test "rejects an unknown option" {
  run bash "$BUILD" --nope
  [ "$status" -eq 2 ]
}

# CAF-compatible packaging: engines on the containerd image store make
# `docker save` (and `ioxclient docker package`) emit OCI-layout archives with
# buildx attestation manifests; IE3x00 CAF (dockerd 19.03) then installs and
# activates the app but refuses to start it. build.sh must export a classic
# docker-archive rootfs.tar itself and package the directory.

@test "build.sh exports rootfs.tar via skopeo docker-archive" {
  run grep -F -- 'skopeo copy "docker-daemon:$IMAGE_TAG" "docker-archive:$CTX/rootfs.tar:$IMAGE_TAG"' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh requires skopeo with an actionable message" {
  run grep -F 'skopeo is required' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh rejects OCI-index rootfs archives" {
  run grep -F 'grep -qx "index.json"' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh fails closed on attestation manifests in rootfs.tar" {
  run grep -F 'attestation-manifest' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh packages the staged directory, not a daemon-side save" {
  run grep -F '"$IOXCLIENT" package .' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F '"$IOXCLIENT" docker package' "$BUILD"
  [ "$status" -ne 0 ]
}

@test "build.sh packages the descriptor, rootfs.tar and the pinned-cert probe member, never the docker build context" {
  # `ioxclient package` tars its whole working directory into artifacts.tar.gz.
  # Packaging the build context shipped a second aria2c, the agent sources and
  # the Dockerfile as ~3.3 MB of dead weight in every IOx tar (measured
  # 2026-09-02), so the packaging step runs in a directory that holds exactly
  # package.yaml + rootfs.tar + iris-catalog.pem. The pem (a few KB) is the
  # PINNED-CERT PROBE MEMBER both freshness readers depend on (IRIS-12-001);
  # it was dropped with the rest and every fresh package then read as STALE.
  run grep -F 'mv "$CTX/rootfs.tar" "$PKG/rootfs.tar"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F 'cp "$PACKAGE_DESCRIPTOR" "$PKG/package.yaml"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F 'cp "$CTX/iris-catalog.pem" "$PKG/iris-catalog.pem"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F '( cd "$PKG" && "$IOXCLIENT" package . )' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F '( cd "$CTX" && "$IOXCLIENT" package . )' "$BUILD"
  [ "$status" -ne 0 ]
}
