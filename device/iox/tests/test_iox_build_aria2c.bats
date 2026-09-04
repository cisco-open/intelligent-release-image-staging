#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# The canonical device-image builder must NOT fall back to downloading a stock aria2c client
# (the old abcfy2/aria2-static-build zip) when no local bundle is present.
# That default path used to ship the unpatched 1.37.0 binary — including the
# peer-blocklist use-after-free this repo's aria2-next fork fixes — into the
# default IOx image build. The shared builder now resolves aria2c only from
# explicit per-architecture overrides or handed-in deliverables/aria2c-<arch>,
# checksum-verified against tools/aria2c.sha256, and fails closed with no
# network fallback when neither is available.

# ---------------------------------------------------------------------------
# Regression guard: the abcfy2 download fallback must be fully gone.
# ---------------------------------------------------------------------------

@test "build.sh no longer references the abcfy2 download fallback" {
  BUILD="$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh"
  run grep -F "abcfy2" "$BUILD"
  [ "$status" -ne 0 ]
  run grep -F "ARIA2_URL" "$BUILD"
  [ "$status" -ne 0 ]
  run grep -F "ARIA2_VERSION" "$BUILD"
  [ "$status" -ne 0 ]
  run grep -F "DEFAULT_ARIA2_SHA256" "$BUILD"
  [ "$status" -ne 0 ]
}

@test "build.sh verifies deliverables/aria2c-<arch> against tools/aria2c.sha256" {
  BUILD="$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh"
  run grep -F 'elif [ -f "$REPO/deliverables/aria2c-$cpuarch" ]; then' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F 'SUMS="$REPO/tools/aria2c.sha256"' "$BUILD"
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Behavioral tests: run the real build.sh, symlinked into a fake $REPO so we
# control deliverables/, tools/aria2c.sha256 and the local agent bundle
# without touching the real repository's gitignored deliverables. Mirrors the
# STUBDIR pattern in test_iox_install_output.bats (HERE resolves off a
# symlinked script, so the fake repo layout must live two dirs above it).
# The failure paths below abort during aria2c staging, before docker/skopeo/
# ioxclient would ever be invoked, so nothing else needs to be stubbed.
# ---------------------------------------------------------------------------

_build_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  BIN="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$STUBDIR/device/container" "$STUBDIR/device/agent" "$STUBDIR/tools" \
    "$STUBDIR/artifacts" "$STUBDIR/deliverables" "$BIN"
  ln -s "$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh" \
    "$STUBDIR/tools/build-device-image.sh"
  # Old wrapper-local staging tests now exercise the one canonical builder:
  # it must validate both architecture inputs before BuildKit can run.
  touch "$STUBDIR/device/container/Dockerfile" \
    "$STUBDIR/device/container/entrypoint.sh" \
    "$STUBDIR/device/container/reconcile.sh"
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
  chmod +x "$BIN/file"
  BUILD="$STUBDIR/tools/build-device-image.sh"
  CONTEXT="$BATS_TEST_TMPDIR/context"
  OUT="$BATS_TEST_TMPDIR/image.oci.tar"
  mkdir -p "$CONTEXT"
}

_run_builder() {
  env -u ARIA2C_BIN_AMD64 -u ARIA2C_BIN_ARM64 PATH="$BIN:$PATH" \
    bash "$BUILD" --context "$CONTEXT" --output "$OUT"
}

@test "canonical builder refuses a pre-populated owned context" {
  _build_stub_setup
  mkdir -p "$CONTEXT/agent"
  echo "stale bytes" > "$CONTEXT/agent/stale.py"
  run _run_builder
  [ "$status" -ne 0 ]
  [[ "$output" == *"pre-existing builder-owned path"* ]]
  [[ "$output" == *"clean private --context"* ]]
  grep -q "stale bytes" "$CONTEXT/agent/stale.py"
}

@test "a build context without the aria2 completion hook fails closed" {
  # The Dockerfile COPYs agent/peer-transfer-hook.sh by name. Letting the stage
  # step skip it would push the failure into `docker build` as an opaque
  # missing-COPY-source error, long after the useful context is gone.
  _build_stub_setup
  rm -f "$STUBDIR/device/agent/peer-transfer-hook.sh"
  run _run_builder
  [ "$status" -ne 0 ]
  [[ "$output" == *"peer-transfer-hook.sh"* ]]
}

@test "missing deliverable + unset ARIA2C_BIN_ARM64 fails closed with a clear error" {
  _build_stub_setup
  rm -f "$STUBDIR/deliverables/aria2c-aarch64"
  run _run_builder
  [ "$status" -ne 0 ]
  [[ "$output" == *"no checksum-pinned aria2c available for aarch64"* ]]
  # and it must not have tried to reach the network for it
  [[ "$output" != *"curl"* ]]
  [[ "$output" != *"downloading"* ]]
}

@test "missing deliverable + unset ARIA2C_BIN_AMD64 fails closed with a clear error" {
  _build_stub_setup
  rm -f "$STUBDIR/deliverables/aria2c-x86_64"
  run _run_builder
  [ "$status" -ne 0 ]
  [[ "$output" == *"no checksum-pinned aria2c available for x86_64"* ]]
}

@test "corrupted deliverable (checksum mismatch) fails closed (arm64)" {
  _build_stub_setup
  echo "not the real aria2c binary" > "$STUBDIR/deliverables/aria2c-aarch64"
  chmod +x "$STUBDIR/deliverables/aria2c-aarch64"
  run _run_builder
  [ "$status" -ne 0 ]
  [[ "$output" == *"CHECKSUM MISMATCH"* ]]
  [[ "$output" == *"aarch64"* ]]
  [[ "$output" == *"refusing to build"* ]]
}

@test "corrupted deliverable (checksum mismatch) fails closed (amd64)" {
  _build_stub_setup
  echo "not the real aria2c binary" > "$STUBDIR/deliverables/aria2c-x86_64"
  chmod +x "$STUBDIR/deliverables/aria2c-x86_64"
  run _run_builder
  [ "$status" -ne 0 ]
  [[ "$output" == *"CHECKSUM MISMATCH"* ]]
  [[ "$output" == *"x86_64"* ]]
  [[ "$output" == *"refusing to build"* ]]
}

@test "a verified deliverable is accepted and staged (arm64, checksum matches)" {
  _build_stub_setup
  run _run_builder
  # Both staging passes succeed and the run fails at the next independent
  # input (the pinned certificate), before Docker can run.
  [ "$status" -ne 0 ]
  [[ "$output" != *"CHECKSUM MISMATCH"* ]]
  [[ "$output" != *"no checksum-pinned aria2c"* ]]
  [[ "$output" == *"CATALOG_PEM_URL"* ]]
}

@test "bundle-reused aria2c is also checksum-verified (mismatch fails closed, arm64)" {
  _build_stub_setup
  # No deliverable at all; only a local agent bundle carrying an aria2c that
  # does NOT match tools/aria2c.sha256 -- bundle reuse must not bypass
  # verification.
  ( cd "$STUBDIR" && mkdir -p _bundle_stage \
      && printf 'unverified aria2c from a stale bundle\n' > _bundle_stage/aria2c \
      && tar czf artifacts/iris-agent-arm.tgz -C _bundle_stage aria2c )
  rm -f "$STUBDIR/deliverables/aria2c-aarch64"
  # Preserve the checksum of the original deliverable; the bundle differs.
  run _run_builder
  [ "$status" -ne 0 ]
  [[ "$output" == *"CHECKSUM MISMATCH"* ]]
  [[ "$output" == *"iris-agent-arm.tgz"* ]]
}
