#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# device/iox/build.sh's CATALOG_PEM discipline and its pinned-cert probe
# member (review findings IRIS-12-002 and IRIS-12-001).
#
# The real build.sh runs, symlinked into a fake $REPO (the STUBDIR pattern
# from test_iox_build_aria2c.bats) with `docker` and `file` stubbed on PATH
# and a fake aria2c handed in via ARIA2C_BIN, in --image-only mode so neither
# skopeo nor ioxclient is ever needed. The docker stub records what the build
# context held at the moment `docker build` would have run.

_build_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  BIN="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$STUBDIR/device/iox" "$STUBDIR/device/agent" "$STUBDIR/tools" \
    "$STUBDIR/artifacts" "$BIN"
  ln -s "$BATS_TEST_DIRNAME/../build.sh" "$STUBDIR/device/iox/build.sh"
  for f in Dockerfile entrypoint.sh reconcile.sh package.yaml package-amd64.yaml; do
    touch "$STUBDIR/device/iox/$f"
  done
  echo "# dummy" > "$STUBDIR/device/agent/dummy.py"
  printf '#!/bin/sh\nexit 0\n' > "$STUBDIR/device/agent/peer-transfer-hook.sh"
  touch "$STUBDIR/device/verify_image.py"
  echo "0.0.0-test" > "$STUBDIR/VERSION"
  printf 'fake aria2c\n' > "$BATS_TEST_TMPDIR/aria2c-fake"
  # `file` must claim the fake binary is aarch64 so the arch gate passes
  cat > "$BIN/file" <<'STUB'
#!/bin/sh
echo "$1: ELF 64-bit LSB executable, ARM aarch64"
STUB
  # docker: snapshot the context's iris-catalog.pem instead of building
  cat > "$BIN/docker" <<'STUB'
#!/bin/sh
ctx="$(eval echo \${$#})"
echo "DOCKER-STUB: build context=$ctx"
cp "$ctx/iris-catalog.pem" "$DOCKER_STUB_SNAPSHOT"
if grep -q "PRIVATE KEY" "$ctx/iris-catalog.pem"; then
  echo "DOCKER-STUB: PRIVATE KEY block present in the build context"
else
  echo "DOCKER-STUB: no private key in context"
fi
exit 0
STUB
  chmod +x "$BIN/file" "$BIN/docker"
  export DOCKER_STUB_SNAPSHOT="$BATS_TEST_TMPDIR/baked.pem"
  BUILD="$STUBDIR/device/iox/build.sh"
  # a real self-signed cert + key so the fixtures are the genuine shapes
  openssl req -x509 -newkey rsa:2048 -keyout "$BATS_TEST_TMPDIR/key.pem" \
    -out "$BATS_TEST_TMPDIR/cert.pem" -days 1 -nodes -subj "/CN=iris-test" 2>/dev/null
  cat "$BATS_TEST_TMPDIR/cert.pem" "$BATS_TEST_TMPDIR/key.pem" > "$BATS_TEST_TMPDIR/combined.pem"
}

_run_build() {
  run env PATH="$BIN:$PATH" ARIA2C_BIN="$BATS_TEST_TMPDIR/aria2c-fake" \
    IRIS_NO_PULL=1 "$@" bash "$BUILD" --image-only --arm64
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
  run grep -F 'cp "$CTX/iris-catalog.pem" "$PKG/iris-catalog.pem"' "$BATS_TEST_DIRNAME/../build.sh"
  [ "$status" -eq 0 ]
  # and says why, naming both readers
  grep -q 'PINNED-CERT' "$BATS_TEST_DIRNAME/../build.sh"
  grep -q 'setup_status.py' "$BATS_TEST_DIRNAME/../build.sh"
  grep -q 'check-package-freshness.sh' "$BATS_TEST_DIRNAME/../build.sh"
}

@test "the probe member is copied AFTER the private-key guard, from the cert-only file" {
  # ordering proof: the guard, then the cert-only rewrite, then the PKG copy
  guard="$(grep -n 'PRIVATE KEY block -- refusing to build' "$BATS_TEST_DIRNAME/../build.sh" | head -1 | cut -d: -f1)"
  certonly="$(grep -n 'iris-catalog.pem.certonly' "$BATS_TEST_DIRNAME/../build.sh" | head -1 | cut -d: -f1)"
  probe="$(grep -n 'cp "$CTX/iris-catalog.pem" "$PKG/iris-catalog.pem"' "$BATS_TEST_DIRNAME/../build.sh" | cut -d: -f1)"
  [ -n "$guard" ] && [ -n "$certonly" ] && [ -n "$probe" ]
  [ "$guard" -lt "$certonly" ] && [ "$certonly" -lt "$probe" ]
}
