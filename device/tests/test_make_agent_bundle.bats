#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# tools/make-agent-bundle.sh bundles bin/aria2c for every device. The binary
# is HANDED IN (produced by aria2-next-static, installed by get-aria2c.sh),
# and the manifest tools/aria2c.sha256 is the pin: an architecture check
# alone would happily bundle a stale or substituted x86-64 static binary, so
# the bundler must verify the checksum itself and fail closed on a mismatch.

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
           agent/peer-receipt-hook.sh \
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
