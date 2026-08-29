#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for tools/build-xr-package.sh -- packages the Task-1 device/xr/
# image for appmgr delivery (agentinfo/plans/2026-08-28-xr-agent.md, Task
# 2). The real ios-xr/xr-appmgr-build tool needs network + rpmbuild and is
# not available here, so behavioral coverage stubs it (and docker, and git)
# on PATH. The critical property under test throughout: xr-appmgr-build
# prints "Done building" EVEN ON FAILURE (lab-confirmed on 100.90.168.20),
# so this script must verify the RPM landed on disk and never trust the
# tool's own exit code or message.

setup() {
  HELPER="$BATS_TEST_DIRNAME/../../../tools/build-xr-package.sh"
}

# ---------------------------------------------------------------------------
# Static / fast checks against the real script (no stubbing needed)
# ---------------------------------------------------------------------------

@test "has no syntax errors" {
  run bash -n "$HELPER"
  [ "$status" -eq 0 ]
}

@test "--help lists --out and --dry-run" {
  run bash "$HELPER" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--out"* ]]
  [[ "$output" == *"--dry-run"* ]]
}

@test "rejects an unknown option" {
  run bash "$HELPER" --nope
  [ "$status" -eq 2 ]
}

@test "pins the lab-proven xr-appmgr-build commit" {
  run grep -F 'APPMGR_BUILD_COMMIT:-37d79607' "$HELPER"
  [ "$status" -eq 0 ]
}

@test "pins the lab-proven appmgr release config" {
  run grep -F 'APPMGR_RELEASE:-ThinXR_7.3.15' "$HELPER"
  [ "$status" -eq 0 ]
}

@test "never trusts appmgr_build's exit status alone -- the RPM check runs regardless" {
  # The build is invoked with "|| true" specifically so a non-zero exit does
  # not short-circuit past the RPMS/ verification below it.
  run grep -F '$APPMGR_BUILD_CMD ) >"$LOG" 2>&1 || true' "$HELPER"
  [ "$status" -eq 0 ]
}

@test "clears RPMS/ before each run so a stale artifact cannot read as success" {
  run grep -F 'rm -rf "$APPMGR_BUILD_DIR/RPMS"' "$HELPER"
  [ "$status" -eq 0 ]
}

@test "reuses an existing clone instead of always re-cloning" {
  run grep -F 'if [ ! -x "$APPMGR_BUILD_DIR/appmgr_build" ]; then' "$HELPER"
  [ "$status" -eq 0 ]
  run grep -F 'reusing existing xr-appmgr-build' "$HELPER"
  [ "$status" -eq 0 ]
}

@test "refuses without CATALOG_PEM or CATALOG_PEM_URL" {
  run env -u CATALOG_PEM -u CATALOG_PEM_URL bash "$HELPER" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"CATALOG_PEM"* ]]
}

# ---------------------------------------------------------------------------
# CATALOG_PEM cert-only guard (device/iox/build.sh discipline)
# ---------------------------------------------------------------------------

_cert_only() {
  CERT_DIR="$BATS_TEST_TMPDIR/cert"
  mkdir -p "$CERT_DIR"
  openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert-only.pem" -days 1 -nodes -subj "/CN=test-catalog" 2>/dev/null
}

_cert_combined() {
  CERT_DIR="$BATS_TEST_TMPDIR/cert"
  mkdir -p "$CERT_DIR"
  openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert-only.pem" -days 1 -nodes -subj "/CN=test-catalog" 2>/dev/null
  cat "$CERT_DIR/cert-only.pem" "$CERT_DIR/key.pem" > "$CERT_DIR/combined.pem"
}

@test "cert-only guard: refuses a CATALOG_PEM carrying a PRIVATE KEY block" {
  _cert_combined
  run env CATALOG_PEM="$CERT_DIR/combined.pem" bash "$HELPER" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"PRIVATE KEY"* ]]
  [[ "$output" == *"refusing to build"* ]]
}

@test "cert-only guard: accepts a certificate-block-only CATALOG_PEM" {
  _cert_only
  run env CATALOG_PEM="$CERT_DIR/cert-only.pem" bash "$HELPER" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"PRIVATE KEY"* ]]
}

@test "cert-only guard fires before any docker/git dependency is required" {
  # No docker/git on PATH at all -- the guard must still reject a combined
  # file, proving it runs first.
  _cert_combined
  run env PATH="/usr/bin:/bin" CATALOG_PEM="$CERT_DIR/combined.pem" bash "$HELPER" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"PRIVATE KEY"* ]]
}

# ---------------------------------------------------------------------------
# --dry-run: build.yaml shape, no aria2c/docker/git required
# ---------------------------------------------------------------------------

@test "dry-run preview carries the build.yaml shape (name: iris-xr, release: ThinXR_7.3.15)" {
  _cert_only
  run env -u ARIA2C_BIN CATALOG_PEM="$CERT_DIR/cert-only.pem" bash "$HELPER" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"name: iris-xr"* ]]
  [[ "$output" == *"release: ThinXR_7.3.15"* ]]
  [[ "$output" == *"arch: x86_64"* ]]
  [[ "$output" == *"type: docker"* ]]
}

@test "dry-run never invokes docker or git" {
  _cert_only
  run env -u ARIA2C_BIN PATH="/usr/bin:/bin" CATALOG_PEM="$CERT_DIR/cert-only.pem" \
    bash "$HELPER" --dry-run
  [ "$status" -eq 0 ]
}

@test "dry-run honors --out in its final message" {
  _cert_only
  OUTDIR="$BATS_TEST_TMPDIR/custom-out"
  run env -u ARIA2C_BIN CATALOG_PEM="$CERT_DIR/cert-only.pem" \
    bash "$HELPER" --out "$OUTDIR" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"$OUTDIR/iris-xr.rpm"* ]]
}

# ---------------------------------------------------------------------------
# Behavioral tests: fake docker/git on PATH + a stub xr-appmgr-build, so the
# RPM-verification logic is exercised without network, real docker, or
# rpmbuild. Mirrors the STUBDIR/PATH-shim pattern in
# device/iox/tests/test_iox_build_amd64_name.bats and test_iox_install_output.bats.
# ---------------------------------------------------------------------------

_xr_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/tools" "$STUBDIR/device/xr" "$STUBDIR/device/agent" "$STUBDIR/bin"
  ln -s "$HELPER" "$STUBDIR/tools/build-xr-package.sh"
  cp "$BATS_TEST_DIRNAME/../Dockerfile" "$STUBDIR/device/xr/Dockerfile"
  cp "$BATS_TEST_DIRNAME/../entrypoint.sh" "$STUBDIR/device/xr/entrypoint.sh"
  echo "# dummy" > "$STUBDIR/device/agent/dummy.py"
  printf '#!/bin/sh\nexit 0\n' > "$STUBDIR/device/agent/peer-receipt-hook.sh"
  chmod +x "$STUBDIR/device/agent/peer-receipt-hook.sh"
  echo "0.0.0-test" > "$STUBDIR/VERSION"

  echo "fake aria2c bytes" > "$STUBDIR/aria2c-stub"
  chmod +x "$STUBDIR/aria2c-stub"

  _cert_only
  CERT_FILE="$CERT_DIR/cert-only.pem"

  # fake docker: build/save are both no-ops; save touches the -o target.
  cat > "$STUBDIR/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
case "$1" in
  build) exit 0 ;;
  save)
    shift; out=""
    while [ $# -gt 0 ]; do
      case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
    done
    [ -n "$out" ] && : > "$out"
    exit 0 ;;
  *) exit 0 ;;
esac
DOCKER
  chmod +x "$STUBDIR/bin/docker"

  # fake git: fails loudly if ever invoked -- proves the reuse-not-clone
  # path is honored when appmgr_build already exists in APPMGR_BUILD_DIR.
  cat > "$STUBDIR/bin/git" <<'GITSTUB'
#!/usr/bin/env bash
echo "STUB-GIT-SHOULD-NOT-BE-CALLED: $*" >&2
exit 99
GITSTUB
  chmod +x "$STUBDIR/bin/git"

  APPMGR_DIR="$BATS_TEST_TMPDIR/appmgr"
  mkdir -p "$APPMGR_DIR"
  OUT_DIR="$BATS_TEST_TMPDIR/out"
}

_run_real() {
  run env PATH="$STUBDIR/bin:$PATH" \
    CATALOG_PEM="$CERT_FILE" \
    ARIA2C_BIN="$STUBDIR/aria2c-stub" \
    APPMGR_BUILD_DIR="$APPMGR_DIR" \
    bash "$STUBDIR/tools/build-xr-package.sh" --out "$OUT_DIR"
}

@test "real run: appmgr_build reporting success (Done building, exit 0) with no RPM is still a failure" {
  _xr_stub_setup
  cat > "$APPMGR_DIR/appmgr_build" <<'EOF'
#!/usr/bin/env bash
echo "Building app..."
echo "Done building"
exit 0
EOF
  chmod +x "$APPMGR_DIR/appmgr_build"
  _run_real
  [ "$status" -ne 0 ]
  [[ "$output" == *"did not produce an RPM"* ]]
  [[ "$output" == *"not proof of success"* ]]
  [ ! -f "$OUT_DIR/iris-xr.rpm" ]
}

@test "real run: appmgr_build crashing (nonzero exit) with no RPM fails with the same honest message" {
  _xr_stub_setup
  cat > "$APPMGR_DIR/appmgr_build" <<'EOF'
#!/usr/bin/env bash
echo "some fatal rpmbuild error" >&2
exit 1
EOF
  chmod +x "$APPMGR_DIR/appmgr_build"
  _run_real
  [ "$status" -ne 0 ]
  [[ "$output" == *"did not produce an RPM"* ]]
  [[ "$output" == *"some fatal rpmbuild error"* ]]
}

@test "real run: a stale RPM left over from a previous run is not mistaken for this run's output" {
  _xr_stub_setup
  mkdir -p "$APPMGR_DIR/RPMS"
  echo "stale bytes from a previous run" > "$APPMGR_DIR/RPMS/iris-xr-old.x86_64.rpm"
  cat > "$APPMGR_DIR/appmgr_build" <<'EOF'
#!/usr/bin/env bash
echo "Done building"
exit 0
EOF
  chmod +x "$APPMGR_DIR/appmgr_build"
  _run_real
  [ "$status" -ne 0 ]
  [[ "$output" == *"did not produce an RPM"* ]]
  [ ! -f "$OUT_DIR/iris-xr.rpm" ]
}

@test "real run: an RPM actually produced is copied to OUT/iris-xr.rpm" {
  _xr_stub_setup
  cat > "$APPMGR_DIR/appmgr_build" <<'EOF'
#!/usr/bin/env bash
mkdir -p RPMS
echo "real rpm bytes" > RPMS/iris-xr-0.0.0-ThinXR_7.3.15.x86_64.rpm
echo "Done building"
exit 0
EOF
  chmod +x "$APPMGR_DIR/appmgr_build"
  _run_real
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/iris-xr.rpm" ]
  run cat "$OUT_DIR/iris-xr.rpm"
  [[ "$output" == "real rpm bytes" ]]
}

@test "real run: the build.yaml actually written carries the pinned name/release" {
  _xr_stub_setup
  cat > "$APPMGR_DIR/appmgr_build" <<'EOF'
#!/usr/bin/env bash
mkdir -p RPMS
echo "real rpm bytes" > RPMS/iris-xr-0.0.0-ThinXR_7.3.15.x86_64.rpm
EOF
  chmod +x "$APPMGR_DIR/appmgr_build"
  _run_real
  [ "$status" -eq 0 ]
  run cat "$APPMGR_DIR/build.yaml"
  [[ "$output" == *"name: iris-xr"* ]]
  [[ "$output" == *"release: ThinXR_7.3.15"* ]]
}

@test "real run: an existing clone (appmgr_build present) is reused -- git is never invoked" {
  _xr_stub_setup
  cat > "$APPMGR_DIR/appmgr_build" <<'EOF'
#!/usr/bin/env bash
mkdir -p RPMS
echo "real rpm bytes" > RPMS/iris-xr-0.0.0-ThinXR_7.3.15.x86_64.rpm
EOF
  chmod +x "$APPMGR_DIR/appmgr_build"
  _run_real
  [ "$status" -eq 0 ]
  [[ "$output" != *"STUB-GIT-SHOULD-NOT-BE-CALLED"* ]]
  [[ "$output" == *"reusing existing xr-appmgr-build"* ]]
}

@test "real run: a missing peer-receipt-hook.sh fails closed before docker is invoked" {
  _xr_stub_setup
  rm -f "$STUBDIR/device/agent/peer-receipt-hook.sh"
  _run_real
  [ "$status" -ne 0 ]
  [[ "$output" == *"peer-receipt-hook.sh"* ]]
}
