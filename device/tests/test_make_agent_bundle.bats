#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# tools/make-agent-bundle.sh bundles bin/aria2c for every device. The binary
# is HANDED IN (produced by aria2-next-static, installed by get-aria2c.sh),
# and the manifest tools/aria2c.sha256 is the pin: an architecture check
# alone would happily bundle a stale or substituted x86-64 static binary, so
# the bundler must verify the checksum itself and fail closed on a mismatch.

FRESHNESS="$BATS_TEST_DIRNAME/../../tools/agent-source-freshness.sh"

setup() {
  ROOT="$BATS_TEST_TMPDIR/repo"
  mkdir -p "$ROOT/tools" "$ROOT/device/agent" "$ROOT/server" "$ROOT/bin" \
    "$ROOT/artifacts"
  # the script resolves REPO_ROOT off its own $0 — symlink it into the tree
  ln -s "$BATS_TEST_DIRNAME/../../tools/make-agent-bundle.sh" \
    "$ROOT/tools/make-agent-bundle.sh"
  # every piece the presence check looks for
  for f in agent/iris_agent.py agent/catalog_client.py agent/flashcheck.py \
           agent/flash_target.py agent/agent_config.py verify_image.py \
           agent/peer-transfer-hook.sh \
           bootstrap.sh guestshell-start.sh rotate-logs.sh; do
    mkdir -p "$ROOT/device/$(dirname "$f")"
    echo "stub" > "$ROOT/device/$f"
  done
  # a stub packer that records it ran and produces the bundle file
  cat > "$ROOT/server/pack-agent-bundle.sh" <<'EOF'
#!/usr/bin/env bash
echo "packed" > "$3"
EOF
  chmod +x "$ROOT/server/pack-agent-bundle.sh"
  # the handed-in "binary"
  printf 'fake-aria2c-binary\n' > "$ROOT/bin/aria2c"
  ARIA2_SHA="$( (shasum -a 256 "$ROOT/bin/aria2c" 2>/dev/null \
    || sha256sum "$ROOT/bin/aria2c") | awk '{print $1}')"
  # stub `file` so the ELF/arch/static check passes for the fake binary
  BIN="$BATS_TEST_TMPDIR/bin"; mkdir -p "$BIN"
  cat > "$BIN/file" <<'EOF'
#!/usr/bin/env bash
echo "ELF 64-bit LSB executable, x86-64, statically linked, stripped"
EOF
  chmod +x "$BIN/file"
}

@test "bundler fails closed when bin/aria2c does not match the manifest" {
  cat > "$ROOT/tools/aria2c.sha256" <<EOF
# test manifest
$(printf 'a%.0s' {1..64})  x86_64
EOF
  run env PATH="$BIN:$PATH" bash "$ROOT/tools/make-agent-bundle.sh" < /dev/null
  [ "$status" -ne 0 ]
  [[ "$output" == *"aria2c.sha256"* ]]
  [ ! -f "$ROOT/artifacts/iris-agent.tgz" ]
}

@test "bundler proceeds when bin/aria2c matches the manifest" {
  cat > "$ROOT/tools/aria2c.sha256" <<EOF
# test manifest
$ARIA2_SHA  x86_64
EOF
  run env PATH="$BIN:$PATH" bash "$ROOT/tools/make-agent-bundle.sh" < /dev/null
  [ "$status" -eq 0 ]
  [ -f "$ROOT/artifacts/iris-agent.tgz" ]
}

@test "bundler fails closed when the manifest has no x86_64 entry" {
  echo "# empty manifest" > "$ROOT/tools/aria2c.sha256"
  run env PATH="$BIN:$PATH" bash "$ROOT/tools/make-agent-bundle.sh" < /dev/null
  [ "$status" -ne 0 ]
  [ ! -f "$ROOT/artifacts/iris-agent.tgz" ]
}

# ---------------------------------------------------------------------------
# Staleness guard wiring (issue #119, the same mechanism as issue #72's
# device/iox/build.sh and tools/build-xr-package.sh): this bundler bakes in
# device/agent AS IT SITS IN $ROOT -- a worktree behind main under those
# paths ships an older Guest Shell agent with nothing in the built
# iris-agent.tgz saying so.
# ---------------------------------------------------------------------------

_git() {
  git -C "$ROOT" -c user.name=iris -c user.email=iris@example.com "$@"
}

# Turns $ROOT itself into a git repo, adds tools/agent-source-freshness.sh
# (the real guard), commits everything staged by setup() as C1, then makes a
# second commit C2 that touches device/agent -- and leaves the working tree
# checked out (detached) at C1, simulating a worktree that has fallen behind
# main under device/agent.
_make_stale_bundle_repo() {
  cp "$FRESHNESS" "$ROOT/tools/agent-source-freshness.sh"
  _git init -q -b main
  _git add -A
  _git commit -q -m "C1"
  C1="$(_git rev-parse HEAD)"
  echo "# changed" >> "$ROOT/device/agent/iris_agent.py"
  _git add -A
  _git commit -q -m "C2: touches device/agent"
  _git checkout -q "$C1"
}

_valid_manifest() {
  cat > "$ROOT/tools/aria2c.sha256" <<EOF
# test manifest
$ARIA2_SHA  x86_64
EOF
}

@test "bundler refuses before packing when IRIS_REQUIRE_FRESH_AGENT=1 and the checkout is stale under device/agent" {
  _make_stale_bundle_repo
  _valid_manifest
  run env PATH="$BIN:$PATH" IRIS_REQUIRE_FRESH_AGENT=1 \
    bash "$ROOT/tools/make-agent-bundle.sh" < /dev/null
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ "$output" == *"refusing to build a stale agent"* ]] || { echo "$output"; return 1; }
  [ ! -f "$ROOT/artifacts/iris-agent.tgz" ]
}

@test "bundler only warns (proceeds past the guard) by default when stale" {
  _make_stale_bundle_repo
  _valid_manifest
  run env PATH="$BIN:$PATH" bash "$ROOT/tools/make-agent-bundle.sh" < /dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *"WARNING"* ]] || { echo "$output"; return 1; }
  [[ "$output" != *"refusing to build a stale agent"* ]]
  [ -f "$ROOT/artifacts/iris-agent.tgz" ]
}

# Regression: a checkout without tools/agent-source-freshness.sh (e.g. one
# old enough to predate this guard -- precisely the stale-worktree case it
# exists to catch) must not turn the missing guard script into a raw
# "No such file or directory" abort that masks every real error after it.
# setup() never stages tools/agent-source-freshness.sh into $ROOT, so every
# other test in this file already exercises this path; this test names it
# explicitly.
@test "bundler proceeds normally (no crash) when tools/agent-source-freshness.sh is absent from the checkout" {
  _valid_manifest
  run env PATH="$BIN:$PATH" bash "$ROOT/tools/make-agent-bundle.sh" < /dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" != *"agent-source-freshness.sh: No such file or directory"* ]] \
    || { echo "$output"; return 1; }
  [ -f "$ROOT/artifacts/iris-agent.tgz" ]
}
