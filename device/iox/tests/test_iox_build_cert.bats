#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# The canonical builder's CATALOG_PEM discipline and the IOx pinned-cert probe
# member (review findings IRIS-12-002 and IRIS-12-001).
#
# The real common builder runs, symlinked into a fake $REPO (the STUBDIR pattern
# from test_iox_build_aria2c.bats) with `docker` and `file` stubbed on PATH
# and checksum-pinned fake aria2c inputs. The docker stub records what the build
# context held at the moment `docker build` would have run.

_build_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  BIN="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$STUBDIR/device/container" "$STUBDIR/device/agent" "$STUBDIR/tools" \
    "$STUBDIR/artifacts" "$STUBDIR/deliverables" "$BIN"
  ln -s "$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh" \
    "$STUBDIR/tools/build-device-image.sh"
  for f in Dockerfile entrypoint.sh reconcile.sh; do
    touch "$STUBDIR/device/container/$f"
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
  # docker: snapshot the normalized certificate and emit the smallest OCI
  # index shape the common builder validates after BuildKit returns.
  cat > "$BIN/docker" <<'STUB'
#!/bin/sh
if [ "$1" = buildx ] && [ "$2" = version ]; then exit 0; fi
ctx="$(eval echo \${$#})"
echo "DOCKER-STUB: build context=$ctx"
cp "$ctx/iris-catalog.pem" "$DOCKER_STUB_SNAPSHOT"
if grep -q "PRIVATE KEY" "$ctx/iris-catalog.pem"; then
  echo "DOCKER-STUB: PRIVATE KEY block present in the build context"
else
  echo "DOCKER-STUB: no private key in context"
fi
dest=""
for arg in "$@"; do
  case "$arg" in type=oci,dest=*) dest="${arg#type=oci,dest=}" ;; esac
done
mkdir -p "$DOCKER_STUB_OCI"
printf '{}' > "$DOCKER_STUB_OCI/manifest.json"
manifest_sha="$(sha256sum "$DOCKER_STUB_OCI/manifest.json" | awk '{print $1}')"
mkdir -p "$DOCKER_STUB_OCI/blobs/sha256"
cp "$DOCKER_STUB_OCI/manifest.json" "$DOCKER_STUB_OCI/blobs/sha256/$manifest_sha"
cat > "$DOCKER_STUB_OCI/index.json" <<EOF
{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:$manifest_sha","platform":{"os":"linux","architecture":"amd64"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:$manifest_sha","platform":{"os":"linux","architecture":"arm64"}}]}
EOF
tar cf "$dest" -C "$DOCKER_STUB_OCI" index.json blobs
exit 0
STUB
  chmod +x "$BIN/file" "$BIN/docker"
  export DOCKER_STUB_SNAPSHOT="$BATS_TEST_TMPDIR/baked.pem"
  export DOCKER_STUB_OCI="$BATS_TEST_TMPDIR/oci"
  BUILD="$STUBDIR/tools/build-device-image.sh"
  CONTEXT="$BATS_TEST_TMPDIR/context"
  OUT="$BATS_TEST_TMPDIR/image.oci.tar"
  mkdir -p "$CONTEXT"
  # a real self-signed cert + key so the fixtures are the genuine shapes
  openssl req -x509 -newkey rsa:2048 -keyout "$BATS_TEST_TMPDIR/key.pem" \
    -out "$BATS_TEST_TMPDIR/cert.pem" -days 1 -nodes -subj "/CN=iris-test" 2>/dev/null
  cat "$BATS_TEST_TMPDIR/cert.pem" "$BATS_TEST_TMPDIR/key.pem" > "$BATS_TEST_TMPDIR/combined.pem"
}

_run_build() {
  run env PATH="$BIN:$PATH" IRIS_NO_PULL=1 "$@" \
    bash "$BUILD" --context "$CONTEXT" --output "$OUT"
}

@test "a combined cert+key CATALOG_PEM is refused before docker build" {
  # The server's IRIS_CERT is a combined cert+key file; pointing CATALOG_PEM at
  # it used to bake the catalog/console TLS private key into every layer of
  # a package served to, and left on, every device.
  _build_stub_setup
  _run_build CATALOG_PEM="$BATS_TEST_TMPDIR/combined.pem"
  [ "$status" -ne 0 ]
  [[ "$output" == *"CATALOG_PEM contains a PRIVATE KEY block"* ]]
  [[ "$output" == *"refusing to build"* ]]
  [[ "$output" == *"openssl x509 -in combined.pem -out iris-catalog.pem"* ]]
  # never reached docker, and never echoed the key material
  [[ "$output" != *"DOCKER-STUB"* ]]
  [[ "$output" != *"BEGIN PRIVATE KEY"* ]]
  [[ "$output" != *"BEGIN RSA PRIVATE KEY"* ]]
  [ ! -f "$DOCKER_STUB_SNAPSHOT" ]
}

@test "a cert-only CATALOG_PEM is accepted and baked unchanged" {
  _build_stub_setup
  _run_build CATALOG_PEM="$BATS_TEST_TMPDIR/cert.pem"
  [ "$status" -eq 0 ]
  [[ "$output" == *"DOCKER-STUB: no private key in context"* ]]
  cmp -s "$DOCKER_STUB_SNAPSHOT" "$BATS_TEST_TMPDIR/cert.pem"
}

@test "only CERTIFICATE blocks reach the image (stray text around them is dropped)" {
  _build_stub_setup
  { echo "subject=CN=iris-test (openssl x509 -text style preamble)"
    cat "$BATS_TEST_TMPDIR/cert.pem"
    echo "trailing note"; } > "$BATS_TEST_TMPDIR/annotated.pem"
  _run_build CATALOG_PEM="$BATS_TEST_TMPDIR/annotated.pem"
  [ "$status" -eq 0 ]
  cmp -s "$DOCKER_STUB_SNAPSHOT" "$BATS_TEST_TMPDIR/cert.pem"
}

@test "a CATALOG_PEM with no certificate block at all is refused" {
  _build_stub_setup
  _run_build CATALOG_PEM="$BATS_TEST_TMPDIR/key.pem"
  [ "$status" -ne 0 ]
  [[ "$output" != *"DOCKER-STUB"* ]]
}

# ---------------------------------------------------------------------------
# IRIS-12-001: the pinned-cert probe member. server/setup_status.py's
# package_fingerprint() and tools/check-package-freshness.sh read a top-level
# iris-catalog.pem out of artifacts.tar.gz; the 2026-09-02 slimming dropped
# it, so every fresh package read as "no pinned cert" -> STALE forever.
# ---------------------------------------------------------------------------

@test "build.sh packages the cert-only pem next to rootfs.tar as the probe member" {
  wrapper="$BATS_TEST_DIRNAME/../build.sh"
  common="$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh"
  run grep -F 'cp "$CTX/iris-catalog.pem" "$PKG/iris-catalog.pem"' "$wrapper"
  [ "$status" -eq 0 ]
  # The probe comes from the exact normalized cert embedded in the canonical image.
  run grep -F 'cp "$CONTAINER_DIR/Dockerfile" "$CONTAINER_DIR/entrypoint.sh"' "$common"
  [ "$status" -eq 0 ]
}

@test "the probe member is copied AFTER the private-key guard, from the cert-only file" {
  common="$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh"
  # ordering proof inside the sole producer: reject keys, then normalize.
  guard="$(grep -n 'PRIVATE KEY block -- refusing to build' "$common" | head -1 | cut -d: -f1)"
  # Ignore the clean-context owned-path list near the top of the builder: the
  # producer line is the redirection that creates the normalized cert-only
  # file after the private-key rejection.
  certonly="$(grep -n '> "$CONTEXT_DIR/iris-catalog.pem.cert-only"' "$common" | head -1 | cut -d: -f1)"
  [ -n "$guard" ] && [ -n "$certonly" ]
  [ "$guard" -lt "$certonly" ]
}
