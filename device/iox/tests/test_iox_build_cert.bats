#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# #136: the canonical device image and native wrappers are deployment-neutral.
# Catalog trust is delivered at install/runtime, never fetched or baked here.

_build_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  BIN="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$STUBDIR/device/container" "$STUBDIR/device/agent" "$STUBDIR/tools" \
    "$STUBDIR/artifacts" "$STUBDIR/deliverables" "$BIN"
  ln -s "$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh" \
    "$STUBDIR/tools/build-device-image.sh"
  for file in Dockerfile entrypoint.sh reconcile.sh; do
    printf '%s\n' "$file" > "$STUBDIR/device/container/$file"
  done
  echo "# dummy" > "$STUBDIR/device/agent/dummy.py"
  printf '#!/bin/sh\nexit 0\n' > "$STUBDIR/device/agent/peer-transfer-hook.sh"
  touch "$STUBDIR/device/verify_image.py"
  echo "0.0.0-test" > "$STUBDIR/VERSION"
  printf 'fake amd64 aria2c\n' > "$STUBDIR/deliverables/aria2c-x86_64"
  printf 'fake arm64 aria2c\n' > "$STUBDIR/deliverables/aria2c-aarch64"
  chmod +x "$STUBDIR/deliverables/aria2c-x86_64" \
    "$STUBDIR/deliverables/aria2c-aarch64"
  {
    printf '%s  x86_64\n' "$(sha256sum "$STUBDIR/deliverables/aria2c-x86_64" | awk '{print $1}')"
    printf '%s  aarch64\n' "$(sha256sum "$STUBDIR/deliverables/aria2c-aarch64" | awk '{print $1}')"
  } > "$STUBDIR/tools/aria2c.sha256"

  cat > "$BIN/file" <<'STUB'
#!/bin/sh
case "$1" in
  *amd64) echo "$1: ELF 64-bit LSB executable, x86-64" ;;
  *arm64) echo "$1: ELF 64-bit LSB executable, ARM aarch64" ;;
esac
STUB
  cat > "$BIN/docker" <<'STUB'
#!/bin/sh
if [ "$1" = buildx ] && [ "$2" = version ]; then exit 0; fi
ctx=""
for value in "$@"; do ctx="$value"; done
find "$ctx" -type f -printf '%P\n' | LC_ALL=C sort > "$DOCKER_CONTEXT_FILES"
printf 'build\n' >> "$DOCKER_CALLS"
dest=""
for arg in "$@"; do
  case "$arg" in type=oci,dest=*) dest="${arg#type=oci,dest=}" ;; esac
done
work="$(mktemp -d)"
printf '{}' > "$work/manifest.json"
manifest_sha="$(sha256sum "$work/manifest.json" | awk '{print $1}')"
mkdir -p "$work/blobs/sha256"
cp "$work/manifest.json" "$work/blobs/sha256/$manifest_sha"
cat > "$work/index.json" <<EOF
{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:$manifest_sha","platform":{"os":"linux","architecture":"amd64"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:$manifest_sha","platform":{"os":"linux","architecture":"arm64"}}]}
EOF
tar cf "$dest" -C "$work" index.json blobs
rm -rf "$work"
STUB
  chmod +x "$BIN/file" "$BIN/docker"
  export DOCKER_CONTEXT_FILES="$BATS_TEST_TMPDIR/context-files"
  export DOCKER_CALLS="$BATS_TEST_TMPDIR/docker-calls"
  : > "$DOCKER_CALLS"
  BUILD="$STUBDIR/tools/build-device-image.sh"
  OUT="$BATS_TEST_TMPDIR/image.oci.tar"
}

_run_build() {
  local context="$1"
  shift
  mkdir -p "$context"
  run env PATH="$BIN:$PATH" IRIS_NO_PULL=1 "$@" \
    bash "$BUILD" --context "$context" --output "$OUT"
}

@test "canonical image builds with every catalog-certificate input unset" {
  _build_stub_setup
  unset CATALOG_PEM CATALOG_PEM_URL CATALOG_PEM_FINGERPRINT
  _run_build "$BATS_TEST_TMPDIR/context"

  [ "$status" -eq 0 ]
  [ -f "$OUT" ]
  ! grep -q 'iris-catalog.pem' "$DOCKER_CONTEXT_FILES"
}

@test "catalog certificate rotation does not change canonical source identity" {
  _build_stub_setup
  printf 'certificate A\n' > "$BATS_TEST_TMPDIR/a.pem"
  printf 'certificate B\n' > "$BATS_TEST_TMPDIR/b.pem"
  _run_build "$BATS_TEST_TMPDIR/context-a" CATALOG_PEM="$BATS_TEST_TMPDIR/a.pem"
  [ "$status" -eq 0 ]
  source_a="$(sed -n 's/^source_sha256=//p' "$OUT.manifest")"

  _run_build "$BATS_TEST_TMPDIR/context-b" CATALOG_PEM="$BATS_TEST_TMPDIR/b.pem"
  [ "$status" -eq 0 ]
  source_b="$(sed -n 's/^source_sha256=//p' "$OUT.manifest")"

  [ "$source_a" = "$source_b" ]
  [ "$(wc -l < "$DOCKER_CALLS" | tr -d ' ')" -eq 1 ]
  [[ "$output" == *"reusing canonical device OCI"* ]]
}

@test "build and wrapper definitions contain no baked or probe certificate path" {
  common="$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh"
  dockerfile="$BATS_TEST_DIRNAME/../../container/Dockerfile"
  wrapper="$BATS_TEST_DIRNAME/../build.sh"
  stage="$BATS_TEST_DIRNAME/../../../tools/stage-iox-package.sh"
  for file in "$common" "$dockerfile" "$wrapper" "$stage"; do
    run grep -E 'CATALOG_PEM|iris-catalog\.pem|catalog cert fingerprint' "$file"
    [ "$status" -ne 0 ] || return 1
  done
}

@test "Dockerfile leaves catalog CA selection to runtime onboarding" {
  dockerfile="$BATS_TEST_DIRNAME/../../container/Dockerfile"
  run grep -E '^COPY .*iris-catalog\.pem|IRIS_CATALOG_CA=' "$dockerfile"
  [ "$status" -ne 0 ]
}

@test "deployment-neutral builder has valid shell syntax" {
  run bash -n "$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh"
  [ "$status" -eq 0 ]
}
