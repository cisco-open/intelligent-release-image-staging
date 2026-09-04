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
  run grep -F -- 'skopeo copy --override-os linux --override-arch "$IOX_ARCH"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F -- '"oci-archive:$OCI_ARCHIVE"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F -- '"docker-archive:$CTX/rootfs.tar:iris-device:$IOX_ARCH"' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh requires skopeo with an actionable message" {
  run grep -F 'skopeo is required' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh rejects OCI-index rootfs archives" {
  run grep -F 'tar tf "$CTX/rootfs.tar" | grep -qx index.json' "$BUILD"
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

@test "IOx wrapper atomically publishes provenance bound to the canonical OCI" {
  STUB="$BATS_TEST_TMPDIR/stub"
  BIN="$BATS_TEST_TMPDIR/bin"
  OUT="$BATS_TEST_TMPDIR/out"
  mkdir -p "$STUB/device/iox" "$STUB/tools" "$BIN" "$OUT"
  ln -s "$BUILD" "$STUB/device/iox/build.sh"
  printf 'descriptor\n' > "$STUB/device/iox/package.yaml"
  printf 'descriptor\n' > "$STUB/device/iox/package-amd64.yaml"
  printf '0.0.0-test\n' > "$STUB/VERSION"
  cat > "$STUB/tools/build-device-image.sh" <<'STUB_COMMON'
#!/usr/bin/env bash
set -eu
ctx=""
while [ $# -gt 0 ]; do
  case "$1" in --context) ctx="$2"; shift 2 ;; *) shift ;; esac
done
archive="$TEST_ROOT/canonical.oci.tar"
printf 'oci\n' > "$archive"
printf '%s\n' "$archive" > "$ctx/iris-device-oci-path"
printf '%s\n' 'public cert' > "$ctx/iris-catalog.pem"
cat > "$ctx/iris-device-oci.manifest" <<EOF
format=iris-device-oci-v1
source_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
index_digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
archive_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
platforms=linux/amd64,linux/arm64
EOF
STUB_COMMON
  cat > "$BIN/skopeo" <<'STUB_SKOPEO'
#!/usr/bin/env bash
for arg in "$@"; do case "$arg" in docker-archive:*) out="${arg#docker-archive:}"; out="${out%%:*}" ;; esac; done
d="$(mktemp -d)"
printf '[{"Config":"config.json","RepoTags":["iris-device:test"],"Layers":[]}]\n' > "$d/manifest.json"
tar cf "$out" -C "$d" manifest.json
rm -rf "$d"
STUB_SKOPEO
  cat > "$BIN/ioxclient" <<'STUB_IOX'
#!/usr/bin/env bash
printf 'iox wrapper bytes\n' > package.tar
STUB_IOX
  chmod +x "$STUB/tools/build-device-image.sh" "$BIN/skopeo" "$BIN/ioxclient"

  run env PATH="$BIN:$PATH" TEST_ROOT="$BATS_TEST_TMPDIR" \
    bash "$STUB/device/iox/build.sh" "$OUT"
  [ "$status" -eq 0 ]
  [ -f "$OUT/iris-arm64.tar" ]
  manifest="$OUT/iris-arm64.tar.manifest"
  [ -f "$manifest" ]
  grep -q '^wrapper_kind=iox$' "$manifest"
  grep -q '^platform=linux/arm64$' "$manifest"
  grep -q '^canonical_index_digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb$' "$manifest"
  grep -q '^canonical_archive_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc$' "$manifest"
  grep -q '^canonical_source_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$' "$manifest"
  grep -q "^wrapper_sha256=$(sha256sum "$OUT/iris-arm64.tar" | awk '{print $1}')$" "$manifest"
  ! find "$OUT" -maxdepth 1 -name '.iris-arm64.tar.*' | grep -q .
}
