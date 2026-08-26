#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# device/iox/build.sh must NOT fall back to downloading a stock aria2c client
# (the old abcfy2/aria2-static-build zip) when no local bundle is present.
# That default path used to ship the unpatched 1.37.0 binary — including the
# peer-blocklist use-after-free this repo's aria2-next fork fixes — into the
# default IOx image build. build.sh now resolves aria2c only from an explicit
# ARIA2C_BIN override or from the handed-in deliverables/aria2c-<arch>,
# checksum-verified against tools/aria2c.sha256, and fails closed with no
# network fallback when neither is available.

# ---------------------------------------------------------------------------
# Regression guard: the abcfy2 download fallback must be fully gone.
# ---------------------------------------------------------------------------

@test "build.sh no longer references the abcfy2 download fallback" {
  BUILD="$BATS_TEST_DIRNAME/../build.sh"
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
  BUILD="$BATS_TEST_DIRNAME/../build.sh"
  run grep -F 'DELIVERABLE="$REPO/deliverables/aria2c-$IOX_CPUARCH"' "$BUILD"
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
  mkdir -p "$STUBDIR/device/iox" "$STUBDIR/device/agent" "$STUBDIR/tools" \
    "$STUBDIR/artifacts"
  ln -s "$BATS_TEST_DIRNAME/../build.sh" "$STUBDIR/device/iox/build.sh"
  # Just enough for build.sh to reach the aria2c staging step: a readable
  # package descriptor for each arch, and the agent python it stages first.
  touch "$STUBDIR/device/iox/package.yaml" "$STUBDIR/device/iox/package-amd64.yaml"
  echo "# dummy" > "$STUBDIR/device/agent/dummy.py"
  # the aria2 completion hook is staged alongside the agent python and the
  # Dockerfile COPYs it by name, so the build refuses to proceed without it
  printf '#!/bin/sh\nexit 0\n' > "$STUBDIR/device/agent/peer-receipt-hook.sh"
  touch "$STUBDIR/device/verify_image.py"
  echo "0.0.0-test" > "$STUBDIR/VERSION"
  BUILD="$STUBDIR/device/iox/build.sh"
}

@test "a build context without the aria2 completion hook fails closed" {
  # The Dockerfile COPYs agent/peer-receipt-hook.sh by name. Letting the stage
  # step skip it would push the failure into `docker build` as an opaque
  # missing-COPY-source error, long after the useful context is gone.
  _build_stub_setup
  rm -f "$STUBDIR/device/agent/peer-receipt-hook.sh"
  run env -u ARIA2C_BIN bash "$BUILD" --arm64
  [ "$status" -ne 0 ]
  [[ "$output" == *"peer-receipt-hook.sh"* ]]
}

@test "missing deliverable + unset ARIA2C_BIN fails closed with a clear error (arm64)" {
  _build_stub_setup
  # No ARIA2C_BIN, no artifacts/iris-agent-arm.tgz, no deliverables/aria2c-aarch64.
  run env -u ARIA2C_BIN bash "$BUILD" --arm64
  [ "$status" -ne 0 ]
  [[ "$output" == *"no aria2c available for aarch64"* ]]
  [[ "$output" == *"ARIA2C_BIN"* ]]
  [[ "$output" == *"deliverables/aria2c-aarch64"* ]]
  # and it must not have tried to reach the network for it
  [[ "$output" != *"curl"* ]]
  [[ "$output" != *"downloading"* ]]
}

@test "missing deliverable + unset ARIA2C_BIN fails closed with a clear error (amd64)" {
  _build_stub_setup
  run env -u ARIA2C_BIN bash "$BUILD" --amd64
  [ "$status" -ne 0 ]
  [[ "$output" == *"no aria2c available for x86_64"* ]]
  [[ "$output" == *"ARIA2C_BIN"* ]]
  [[ "$output" == *"deliverables/aria2c-x86_64"* ]]
}

@test "corrupted deliverable (checksum mismatch) fails closed (arm64)" {
  _build_stub_setup
  mkdir -p "$STUBDIR/deliverables"
  echo "not the real aria2c binary" > "$STUBDIR/deliverables/aria2c-aarch64"
  chmod +x "$STUBDIR/deliverables/aria2c-aarch64"
  # A checksum file with a recorded hash that does NOT match the file above.
  echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  aarch64" \
    > "$STUBDIR/tools/aria2c.sha256"
  run env -u ARIA2C_BIN bash "$BUILD" --arm64
  [ "$status" -ne 0 ]
  [[ "$output" == *"CHECKSUM MISMATCH"* ]]
  [[ "$output" == *"aarch64"* ]]
  [[ "$output" == *"refusing to build"* ]]
}

@test "corrupted deliverable (checksum mismatch) fails closed (amd64)" {
  _build_stub_setup
  mkdir -p "$STUBDIR/deliverables"
  echo "not the real aria2c binary" > "$STUBDIR/deliverables/aria2c-x86_64"
  chmod +x "$STUBDIR/deliverables/aria2c-x86_64"
  echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  x86_64" \
    > "$STUBDIR/tools/aria2c.sha256"
  run env -u ARIA2C_BIN bash "$BUILD" --amd64
  [ "$status" -ne 0 ]
  [[ "$output" == *"CHECKSUM MISMATCH"* ]]
  [[ "$output" == *"x86_64"* ]]
  [[ "$output" == *"refusing to build"* ]]
}

@test "a verified deliverable is accepted and staged (arm64, checksum matches)" {
  _build_stub_setup
  mkdir -p "$STUBDIR/deliverables"
  printf 'a fake but correctly-checksummed aria2c\n' > "$STUBDIR/deliverables/aria2c-aarch64"
  chmod +x "$STUBDIR/deliverables/aria2c-aarch64"
  sum="$(shasum -a 256 "$STUBDIR/deliverables/aria2c-aarch64" | awk '{print $1}')"
  echo "$sum  aarch64" > "$STUBDIR/tools/aria2c.sha256"
  run env -u ARIA2C_BIN bash "$BUILD" --arm64
  # Staging succeeds (checksum verified) and the run only fails later, past
  # aria2c, on the `file`/arch sanity check -- our fake binary is not really
  # an aarch64 ELF. That failure is the *next* gate, proving aria2c staging
  # itself accepted the verified deliverable.
  [ "$status" -ne 0 ]
  [[ "$output" != *"CHECKSUM MISMATCH"* ]]
  [[ "$output" != *"no aria2c available"* ]]
  [[ "$output" == *"aria2c does not match aarch64"* ]]
}

@test "bundle-reused aria2c is also checksum-verified (mismatch fails closed, arm64)" {
  _build_stub_setup
  # No deliverable at all; only a local agent bundle carrying an aria2c that
  # does NOT match tools/aria2c.sha256 -- bundle reuse must not bypass
  # verification.
  ( cd "$STUBDIR" && mkdir -p _bundle_stage \
      && printf 'unverified aria2c from a stale bundle\n' > _bundle_stage/aria2c \
      && tar czf artifacts/iris-agent-arm.tgz -C _bundle_stage aria2c )
  echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  aarch64" \
    > "$STUBDIR/tools/aria2c.sha256"
  run env -u ARIA2C_BIN bash "$BUILD" --arm64
  [ "$status" -ne 0 ]
  [[ "$output" == *"CHECKSUM MISMATCH"* ]]
  [[ "$output" == *"iris-agent-arm.tgz"* ]]
}
