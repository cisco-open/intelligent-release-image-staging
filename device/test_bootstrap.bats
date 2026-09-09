#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# bootstrap.sh must reconcile aria2c's RPC secret with the one the agent fetched
# on its first token-refresh. The installer bakes rpc-secret EMPTY; the agent
# writes the real value into iris-agent.conf. If bootstrap does not sync the
# rpc-secret file from the conf (and bounce a stale aria2c), aria2c runs with the
# wrong secret and the agent's addTorrent fails — the device never downloads.

setup() {
  TMP="$(mktemp -d)"
  SRC="$TMP/guest-share"; STAGE="$SRC/iris"
  mkdir -p "$STAGE"
  cp "$BATS_TEST_DIRNAME/../server/certs/cisco_bulkhash_verify.pem" \
    "$STAGE/iris-catalog.pem"
  # stub guestshell-start so bootstrap never launches a real aria2c
  printf '#!/usr/bin/env bash\necho started >> "%s/gss.log"\n' "$TMP" > "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  # stub pgrep (aria2c "not running") + pkill (record the bounce) on PATH
  BIN="$TMP/bin"; mkdir -p "$BIN"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$BIN/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/pkill.log"\n' "$TMP" > "$BIN/pkill"
  chmod +x "$BIN/pgrep" "$BIN/pkill"
  # tests above this line are not about cadence jitter/backoff (issue #59):
  # keep them fast and deterministic by disabling the pre-agent jitter sleep.
  # The jitter/backoff tests below override this explicitly.
  export IRIS_TICK_JITTER_MAX=0
}

teardown() { rm -rf "$TMP"; }

bundle_file_list() {
  cat <<'EOF'
agent/agent_config.py
agent/catalog_client.py
agent/cli_ssh.py
agent/flash_target.py
agent/flashcheck.py
agent/instr.py
agent/iris_agent.py
agent/peer-transfer-hook.sh
agent/telemetry_report.py
agent/verify_image.py
agent/xr_deps.py
aria2c
bootstrap.sh
guestshell-start.sh
iris-root.allowed_signers
iris-signers.allowed_signers
rotate-logs.sh
EOF
}

make_valid_bundle_tree() {
  BUNDLE_TREE="$TMP/bundle-src"
  rm -rf "$BUNDLE_TREE"
  mkdir -p "$BUNDLE_TREE/agent"
  while IFS= read -r name; do
    mkdir -p "$(dirname "$BUNDLE_TREE/$name")"
    printf 'fixture:%s\n' "$name" > "$BUNDLE_TREE/$name"
  done < <(bundle_file_list)
  printf 'open(r"%s/new-agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$BUNDLE_TREE/agent/iris_agent.py"
  printf '#!/usr/bin/env bash\necho new-started >> "%s/new-gss.log"\n' "$TMP" \
    > "$BUNDLE_TREE/guestshell-start.sh"
  { printf '#!/usr/bin/env bash\n'
    for _ in $(seq 1 400); do printf 'exit 99 # upgraded-bootstrap padding line\n'; done
  } > "$BUNDLE_TREE/bootstrap.sh"
}

pack_valid_bundle() {
  local out="$1"
  make_valid_bundle_tree
  # Match the production packer's explicit top-level list: no leading ./ entry.
  tar czf "$out" -C "$BUNDLE_TREE" agent bootstrap.sh guestshell-start.sh \
    rotate-logs.sh aria2c iris-signers.allowed_signers iris-root.allowed_signers
  cp "$BUNDLE_TREE/iris-signers.allowed_signers" \
    "$(dirname "$out")/iris-signers.allowed_signers"
}

write_bundle_digest() {
  local bundle="$1" digest="$2"
  sha256sum "$bundle" | awk '{print $1}' > "$digest"
}

install_prior_agent() {
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/prior-agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  printf 'prior instruction signer trust\n' > "$STAGE/iris-signers.allowed_signers"
  printf 'prior root signer trust\n' > "$STAGE/iris-root.allowed_signers"
}

@test "bootstrap syncs rpc-secret from conf and bounces aria2c when it changed" {
  printf 'rpc_secret = REALSECRET123\nrpc_port = 6800\n' > "$STAGE/iris-agent.conf"
  printf '\n' > "$STAGE/rpc-secret"   # baked empty
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  # the file aria2c reads now holds the agent's real secret
  [ "$(tr -d '[:space:]' < "$STAGE/rpc-secret")" = "REALSECRET123" ]
  # aria2c was bounced so it relaunches with the new secret
  [ -f "$TMP/pkill.log" ]
}

@test "bootstrap does NOT bounce aria2c when rpc-secret already matches the conf" {
  printf 'rpc_secret = REALSECRET123\n' > "$STAGE/iris-agent.conf"
  printf 'REALSECRET123\n' > "$STAGE/rpc-secret"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ ! -f "$TMP/pkill.log" ]
}

# ---------------------------------------------------------------------------
# Persisted aria2c launch overrides from iris-agent.conf (issue #122):
# guestshell-start.sh only reads its own live process environment, refreshed
# on each 60s EEM tick, so an operator has no way to make IRIS_LOG (or RPC_PORT)
# stick without this. Legacy max_peers remains parseable but inert. These
# tests run the REAL guestshell-start.sh (not a stub) against a stub aria2c
# so the launch line it actually builds can be inspected end to end.
# ---------------------------------------------------------------------------

@test "bootstrap propagates iris_log=on from iris-agent.conf to aria2c's real launch line" {
  printf 'rpc_secret = SAME\niris_log = on\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$(cat "$TMP/launched.txt")" == *"--log=$STAGE/aria2c.log"* ]]
}

@test "bootstrap leaves aria2c's default OFF logging alone when iris-agent.conf has no iris_log key" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$(cat "$TMP/launched.txt")" != *"--log="* ]]
}

@test "bootstrap rejects a hostile iris_log value instead of exporting it, and stays off" {
  # The value rides straight from the conf file into an exported env var,
  # never through eval/exec, so there is no shell-injection path regardless
  # -- but this proves it two ways: the shell metacharacters in the value
  # never run (no $TMP/pwned file appears), and the malformed value is
  # rejected rather than silently coerced to "on".
  printf 'rpc_secret = SAME\niris_log = on; touch %s/pwned #\n' "$TMP" \
    > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"ignoring invalid iris_log"* ]]
  [ ! -f "$TMP/pwned" ]
  [[ "$(cat "$TMP/launched.txt")" != *"--log="* ]]
}

@test "bootstrap propagates rpc_port while ignoring legacy max_peers" {
  printf 'rpc_secret = SAME\nrpc_port = 6900\nmax_peers = 65535\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  out="$(cat "$TMP/launched.txt")"
  [[ "$out" == *"--rpc-listen-port=6900"* ]]
  [[ "$out" == *"--bt-max-peers=10"* ]]
  [[ "$out" != *"--bt-max-peers=65535"* ]]
  [[ "$output" != *"max_peers"* ]]
}

@test "bootstrap ignores invalid rpc_port but accepts inert max_peers in iris-agent.conf" {
  printf 'rpc_secret = SAME\nrpc_port = not-a-port\nmax_peers = 65535\n' \
    > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  cp "$BATS_TEST_DIRNAME/guestshell-start.sh" "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$TMP" > "$STAGE/aria2c-stub"
  chmod +x "$STAGE/aria2c-stub"
  mkdir -p "$TMP/home"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      ARIA2_SRC="$STAGE/aria2c-stub" EXEC_DIR="$TMP/home" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"ignoring invalid rpc_port"* ]]
  [[ "$output" != *"max_peers"* ]]
  out="$(cat "$TMP/launched.txt")"
  [[ "$out" == *"--rpc-listen-port=6800"* ]]   # builtin default, unchanged
  [[ "$out" == *"--bt-max-peers=10"* ]]        # builtin default, unchanged
}

@test "a failed aria2c launch is recorded but does NOT block the agent" {
  # Sibling of the 2026-08-20 incident class: bootstrap used to `exit 1` when
  # guestshell-start.sh failed, so the agent (step 5) never ran and the device
  # never heartbeated — an aria2c LAUNCH regression (e.g. the empty rpc-secret
  # bug) was indistinguishable from a dead device. The agent is the device's
  # only line back to the catalog: it must run even when the swarm daemon is
  # down, and report the breakage instead of vanishing.
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$STAGE/guestshell-start.sh"
  chmod +x "$STAGE/guestshell-start.sh"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  # the failure is surfaced and recorded for forensics...
  [[ "$output" == *"failed to launch aria2c"* ]]
  [ -f "$STAGE/aria2c-launch-failed" ]
  # ...but the agent STILL ran, so the device still heartbeats
  [ -f "$TMP/agent-invoked" ]
}

@test "a failed log rotation warns but does NOT block the agent" {
  # Rotation is ancillary maintenance. A permissions/mktemp/filesystem error
  # in step 4 must not exit before step 5 — the agent is the device's only
  # path back to the catalog, so a fatal rotation error would permanently
  # silence the device on every EEM tick (same class as the aria2c-launch
  # failure above).
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$STAGE/rotate-logs.sh"
  chmod +x "$STAGE/rotate-logs.sh"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"log rotation failed"* ]]
  [ -f "$TMP/agent-invoked" ]
}

@test "a healthy aria2c launch clears a stale launch-failure marker" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  printf 'stale\n' > "$STAGE/aria2c-launch-failed"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ ! -f "$STAGE/aria2c-launch-failed" ]
}

@test "a live-but-unresponsive aria2c is relaunched, not skipped" {
  # 2026-08-20 incident (iris8kv-2/-3/-4 + C9300 .129, ~42min silent): step 3
  # gated the launch on `pgrep aria2c` — process EXISTENCE, not RPC HEALTH. An
  # aria2c that is alive but not serving RPC therefore blocked its own
  # relaunch forever: the agent hit ECONNREFUSED on 127.0.0.1:6800 every tick,
  # crashed before its first heartbeat, and the device never appeared. It only
  # recovered when the stale process happened to die. guestshell-start.sh is
  # ALREADY idempotent (it probes the RPC and exits 0 when healthy), so
  # bootstrap must delegate to it unconditionally.
  printf 'rpc_secret = SAME\nrpc_port = 6800\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"      # in sync: no bounce path taken
  # pgrep SUCCEEDS: a process is alive (the deadlock precondition)
  printf '#!/usr/bin/env bash\nexit 0\n' > "$BIN/pgrep"
  chmod +x "$BIN/pgrep"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  # the launcher MUST still have been consulted despite the live process
  [ -f "$TMP/gss.log" ]
}

@test "a verified bundle commits atomically, retains one prior footprint, and updates bootstrap by rename" {
  # bootstrap.sh runs FROM $SRC/bootstrap.sh (the EEM applet's path) and, on
  # a bundle drop, replaces that very file. `cp -f` rewrote the same inode,
  # so the bash still executing it resumed at its old byte offset inside the
  # NEW content -- executing whatever token landed there. The upgrade tick
  # must finish on the OLD script's logic (step 5 runs the agent) and leave
  # the new bootstrap in place for the next tick. The bundled replacement
  # here is pure `exit 99` lines, so an in-place overwrite fails loudly.
  cp "$BATS_TEST_DIRNAME/bootstrap.sh" "$SRC/bootstrap.sh"
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  install_prior_agent
  printf 'persistent\n' > "$STAGE/iris-instructions.lkg"
  pack_valid_bundle "$SRC/bundle.tgz"
  write_bundle_digest "$SRC/bundle.tgz" "$SRC/bundle.tgz.sha256"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$SRC/bootstrap.sh"
  [ "$status" -eq 0 ]
  # the tick that performed the upgrade still ran the agent...
  [ -f "$TMP/new-agent-invoked" ]
  # ...and the next tick will read the bundled bootstrap
  cmp -s "$SRC/bootstrap.sh" "$BUNDLE_TREE/bootstrap.sh"
  [ ! -e "$SRC/bootstrap.sh.new" ]
  [ ! -e "$STAGE/bundle.tgz" ]
  [ ! -e "$STAGE/bundle.tgz.sha256" ]
  [ "$(cat "$STAGE/iris-instructions.lkg")" = persistent ]
  grep -q 'prior-agent-invoked' "$STAGE/.bundle-previous/files/agent/iris_agent.py"
  [ -x "$STAGE/aria2c" ]
  [ -x "$STAGE/agent/peer-transfer-hook.sh" ]
  [ -x "$STAGE/guestshell-start.sh" ]
}

@test "a digest without a bundle waits without discarding the evidence" {
  install_prior_agent
  printf '%064d\n' 0 > "$SRC/bundle.tgz.sha256"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$STAGE/bundle.tgz.sha256" ]
  [ -f "$TMP/prior-agent-invoked" ]
  [[ "$output" != *"bundle rejected"* ]]
}

@test "a bundle without a digest is rejected while the prior agent continues" {
  install_prior_agent
  pack_valid_bundle "$SRC/bundle.tgz"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/prior-agent-invoked" ]
  [ ! -e "$SRC/bundle.tgz" ]
  [ ! -e "$STAGE/bundle.tgz" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle rejected (missing-digest)"* ]]
}

@test "malformed and mismatched digests are bounded and never replace the prior runtime" {
  install_prior_agent
  cp "$STAGE/agent/iris_agent.py" "$TMP/prior-agent.py"
  cp "$STAGE/iris-signers.allowed_signers" "$TMP/prior-signers"
  cp "$STAGE/iris-root.allowed_signers" "$TMP/prior-root-signers"
  pack_valid_bundle "$SRC/bundle.tgz"
  printf 'NOT-A-DIGEST secret-material-that-must-not-be-logged\n' \
    > "$SRC/bundle.tgz.sha256"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  cmp -s "$STAGE/agent/iris_agent.py" "$TMP/prior-agent.py"
  cmp -s "$STAGE/iris-signers.allowed_signers" "$TMP/prior-signers"
  cmp -s "$STAGE/iris-root.allowed_signers" "$TMP/prior-root-signers"
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle rejected (invalid-digest)"* ]]
  [[ "$output" != *"secret-material"* ]]
  [ "${#output}" -lt 512 ]

  rm -f "$TMP/prior-agent-invoked"
  pack_valid_bundle "$SRC/bundle.tgz"
  printf '%064d\n' 0 > "$SRC/bundle.tgz.sha256"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  cmp -s "$STAGE/agent/iris_agent.py" "$TMP/prior-agent.py"
  cmp -s "$STAGE/iris-signers.allowed_signers" "$TMP/prior-signers"
  cmp -s "$STAGE/iris-root.allowed_signers" "$TMP/prior-root-signers"
  [ -f "$TMP/prior-agent-invoked" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle rejected (digest-mismatch)"* ]]
}

@test "a 64-hex digest without its one required newline is malformed" {
  install_prior_agent
  pack_valid_bundle "$SRC/bundle.tgz"
  sha256sum "$SRC/bundle.tgz" | awk '{printf "%s", $1}' \
    > "$SRC/bundle.tgz.sha256"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/prior-agent-invoked" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle rejected (invalid-digest)"* ]]
}

@test "a FIFO bundle is rejected promptly instead of blocking the EEM tick" {
  install_prior_agent
  mkfifo "$SRC/bundle.tgz"
  printf '%064d\n' 0 > "$SRC/bundle.tgz.sha256"

  run timeout 3 env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/prior-agent-invoked" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle rejected (invalid-archive)"* ]]
}

@test "a hash-matching archive with a symlink is rejected before extraction" {
  install_prior_agent
  cp "$STAGE/agent/iris_agent.py" "$TMP/prior-agent.py"
  make_valid_bundle_tree
  cp "$BUNDLE_TREE/iris-signers.allowed_signers" \
    "$SRC/iris-signers.allowed_signers"
  rm -f "$BUNDLE_TREE/aria2c"
  ln -s /etc/passwd "$BUNDLE_TREE/aria2c"
  tar czf "$SRC/bundle.tgz" -C "$BUNDLE_TREE" agent bootstrap.sh \
    guestshell-start.sh rotate-logs.sh aria2c iris-signers.allowed_signers \
    iris-root.allowed_signers
  write_bundle_digest "$SRC/bundle.tgz" "$SRC/bundle.tgz.sha256"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  cmp -s "$STAGE/agent/iris_agent.py" "$TMP/prior-agent.py"
  [ "$(cat "$STAGE/iris-signers.allowed_signers")" = \
    "prior instruction signer trust" ]
  [ "$(cat "$STAGE/iris-root.allowed_signers")" = \
    "prior root signer trust" ]
  [ ! -L "$STAGE/aria2c" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle rejected (invalid-archive)"* ]]
}

@test "tar extension metadata is rejected before the archive parser runs" {
  install_prior_agent
  python3 - "$SRC/bundle.tgz" <<'PYTHON'
import io
import sys
import tarfile

with tarfile.open(sys.argv[1], "w:gz", format=tarfile.PAX_FORMAT) as archive:
    info = tarfile.TarInfo("unexpected")
    info.pax_headers = {"comment": "x" * 4096}
    info.size = 1
    archive.addfile(info, io.BytesIO(b"x"))
PYTHON
  write_bundle_digest "$SRC/bundle.tgz" "$SRC/bundle.tgz.sha256"

  hook="$TMP/tar-hook"
  mkdir -p "$hook"
  cat > "$hook/sitecustomize.py" <<'PYTHON'
import os
import tarfile

_real_open = tarfile.open


def _record_open(*args, **kwargs):
    with open(os.environ["IRIS_TAR_OPEN_MARKER"], "a") as stream:
        stream.write("opened\n")
    return _real_open(*args, **kwargs)


tarfile.open = _record_open
PYTHON
  run env PYTHONPATH="$hook" IRIS_TAR_OPEN_MARKER="$TMP/tar-opened" \
      PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ ! -e "$TMP/tar-opened" ]
  [ -f "$TMP/prior-agent-invoked" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle rejected (invalid-archive)"* ]]
}

@test "a standalone signer that differs from the verified bundle cannot change live trust" {
  install_prior_agent
  pack_valid_bundle "$SRC/bundle.tgz"
  write_bundle_digest "$SRC/bundle.tgz" "$SRC/bundle.tgz.sha256"
  printf 'different public signer bytes\n' > "$SRC/iris-signers.allowed_signers"

  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ "$(cat "$STAGE/iris-signers.allowed_signers")" = \
    "prior instruction signer trust" ]
  [ "$(cat "$STAGE/iris-root.allowed_signers")" = \
    "prior root signer trust" ]
  [ -f "$TMP/prior-agent-invoked" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle rejected (signer-mismatch)"* ]]
}

@test "an incomplete promotion is rolled back before anything launches" {
  TX="$STAGE/.bundle-transaction"
  mkdir -p "$TX/prior/files/agent" "$TX/prior/absent"
  printf 'open(r"%s/recovered-agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$TX/prior/files/agent/iris_agent.py"
  cp "$STAGE/guestshell-start.sh" "$TX/prior/files/guestshell-start.sh"
  for name in aria2c bootstrap.sh rotate-logs.sh \
      iris-signers.allowed_signers iris-root.allowed_signers; do
    : > "$TX/prior/absent/$name"
  done
  printf 'promoting\n' > "$TX/phase"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/partial-agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  printf 'partial\n' > "$STAGE/aria2c"

  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/recovered-agent-invoked" ]
  [ ! -e "$TMP/partial-agent-invoked" ]
  [ ! -e "$STAGE/aria2c" ]
  [ ! -e "$TX" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: recovered interrupted bundle install"* ]]
}

@test "a rollback that cannot prove the prior footprint hard-stops before launch" {
  TX="$STAGE/.bundle-transaction"
  mkdir -p "$TX/prior/files" "$TX/prior/absent" "$STAGE/agent"
  printf 'promoting\n' > "$TX/phase"
  printf 'open(r"%s/untrusted-agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"

  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -ne 0 ]
  [ ! -e "$TMP/untrusted-agent-invoked" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle transaction recovery failed"* ]]
}

@test "a prior footprint with both saved bytes and an absence marker hard-stops" {
  TX="$STAGE/.bundle-transaction"
  mkdir -p "$TX/prior/files" "$TX/prior/absent" "$STAGE/agent"
  for name in agent aria2c bootstrap.sh guestshell-start.sh rotate-logs.sh \
      iris-signers.allowed_signers iris-root.allowed_signers; do
    : > "$TX/prior/absent/$name"
  done
  printf 'saved but also marked absent\n' > "$TX/prior/files/aria2c"
  printf 'promoting\n' > "$TX/phase"
  printf 'open(r"%s/ambiguous-agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"

  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -ne 0 ]
  [ ! -e "$TMP/ambiguous-agent-invoked" ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle transaction recovery failed"* ]]
}

@test "a commit failure cannot replace an EEM bootstrap that had no staged prior" {
  install_prior_agent
  rm -f "$STAGE/bootstrap.sh"
  printf 'original EEM bootstrap\n' > "$SRC/bootstrap.sh"
  cp "$SRC/bootstrap.sh" "$TMP/original-eem-bootstrap"
  pack_valid_bundle "$SRC/bundle.tgz"
  write_bundle_digest "$SRC/bundle.tgz" "$SRC/bundle.tgz.sha256"

  real_python="$(command -v python3)"
  cat > "$BIN/python3" <<'PYTHON'
#!/usr/bin/env bash
if [ "${1:-}" = - ] && [ "${2:-}" = commit ]; then
  exit 1
fi
exec "$REAL_PYTHON" "$@"
PYTHON
  chmod +x "$BIN/python3"

  run env PATH="$BIN:$PATH" REAL_PYTHON="$real_python" SRC="$SRC" \
      STAGE="$STAGE" bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  cmp -s "$SRC/bootstrap.sh" "$TMP/original-eem-bootstrap"
  [ ! -e "$STAGE/.bundle-transaction" ]
  [ -f "$TMP/prior-agent-invoked" ]
}

@test "a failed EEM sibling rename leaves committed runtime for recovery" {
  install_prior_agent
  printf 'original EEM bootstrap\n' > "$SRC/bootstrap.sh"
  cp "$SRC/bootstrap.sh" "$TMP/original-eem-bootstrap"
  pack_valid_bundle "$SRC/bundle.tgz"
  write_bundle_digest "$SRC/bundle.tgz" "$SRC/bundle.tgz.sha256"

  real_cp="$(command -v cp)"
  cat > "$BIN/cp" <<'COPY'
#!/usr/bin/env bash
case "${*: -1}" in
  */bootstrap.sh.new) exit 1 ;;
esac
exec "$REAL_CP" "$@"
COPY
  chmod +x "$BIN/cp"

  run env PATH="$BIN:$PATH" REAL_CP="$real_cp" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -ne 0 ]
  [ "$(cat "$STAGE/.bundle-transaction/phase")" = committed ]
  cmp -s "$SRC/bootstrap.sh" "$TMP/original-eem-bootstrap"
  [ ! -e "$TMP/new-agent-invoked" ]

  rm -f "$BIN/cp"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ ! -e "$STAGE/.bundle-transaction" ]
  [ -f "$TMP/new-agent-invoked" ]
  cmp -s "$SRC/bootstrap.sh" "$BUNDLE_TREE/bootstrap.sh"
}

@test "an interrupted rollback restarts from an immutable prior snapshot" {
  TX="$STAGE/.bundle-transaction"
  mkdir -p "$TX/prior/files/agent" "$TX/prior/absent" "$STAGE/agent"
  printf 'open(r"%s/restartable-prior-agent", "w").write("ran")\n' "$TMP" \
    > "$TX/prior/files/agent/iris_agent.py"
  printf '#!/usr/bin/env bash\necho prior-started >> "%s/prior-started"\n' "$TMP" \
    > "$TX/prior/files/guestshell-start.sh"
  printf '#!/usr/bin/env bash\n: prior-bootstrap\n' \
    > "$TX/prior/files/bootstrap.sh"
  printf '#!/usr/bin/env bash\n: prior-rotate\n' \
    > "$TX/prior/files/rotate-logs.sh"
  printf 'prior aria2c\n' > "$TX/prior/files/aria2c"
  printf 'prior signer\n' > "$TX/prior/files/iris-signers.allowed_signers"
  printf 'prior root signer\n' > "$TX/prior/files/iris-root.allowed_signers"
  printf 'promoting\n' > "$TX/phase"
  printf 'open(r"%s/partial-agent", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"

  hook="$TMP/rollback-hook"
  mkdir -p "$hook"
  cat > "$hook/sitecustomize.py" <<'PYTHON'
import os

_real_replace = os.replace
_stopped = False


def _stop_after_first_restore(source, destination):
    global _stopped
    _real_replace(source, destination)
    source_text = os.fspath(source)
    destination_text = os.fspath(destination)
    if not _stopped and os.path.basename(destination_text) == "agent" \
            and ("/prior/files/agent" in source_text
                 or "/restore/agent" in source_text):
        _stopped = True
        with open(os.environ["IRIS_ROLLBACK_STOP_MARKER"], "w") as stream:
            stream.write("stopped\n")
        os._exit(86)


os.replace = _stop_after_first_restore
PYTHON
  run env PYTHONPATH="$hook" \
      IRIS_ROLLBACK_STOP_MARKER="$TMP/rollback-stopped" \
      PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -ne 0 ]
  [ -f "$TMP/rollback-stopped" ]

  run env PYTHONPATH= PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/restartable-prior-agent" ]
  [ -f "$TMP/prior-started" ]
  [ ! -e "$STAGE/.bundle-transaction" ]
  [ ! -e "$STAGE/.bundle-rollback-complete" ]
  [ "$(cat "$STAGE/aria2c")" = "prior aria2c" ]
}

@test "a bad initial bundle fails after one fixed diagnostic" {
  rm -f "$STAGE/guestshell-start.sh"
  pack_valid_bundle "$SRC/bundle.tgz"
  printf '%064d\n' 0 > "$SRC/bundle.tgz.sha256"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS-BOOTSTRAP: bundle rejected (digest-mismatch)"* ]]
  [ "$(printf '%s\n' "$output" | grep -c 'bundle rejected')" -eq 1 ]
}

# ---------------------------------------------------------------------------
# Cadence jitter + failure backoff (issue #59)
#
# The EEM watchdog fires this script on IOS's own fixed 60s clock, so a fleet
# installed or reloaded together keeps every device's timer in the same
# phase indefinitely -- amplifying every tick into a fleet-wide burst of
# policy GETs, heartbeats, and tracker re-announces. bootstrap.sh (a) sleeps
# a small per-device jitter before the actual catalog contact, and (b) skips
# that contact for a while after the agent fails outright, easing off an
# overloaded or unreachable server without the EEM timer's own cadence
# changing (steps 0-4, local upkeep, still run every tick).
# ---------------------------------------------------------------------------

@test "bootstrap sleeps a bounded per-tick jitter before invoking the agent" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  mkdir -p "$STAGE/agent"
  printf 'import sys\nopen(r"%s/events.log", "a").write("agent:" + " ".join(sys.argv[1:]) + "\\n")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  # Record the jitter sleep's argument instead of actually waiting. Pin the
  # random result to the upper in-range value: zero is also valid and
  # intentionally skips sleep, so leaving this to entropy makes the assertion
  # below fail one run in eight.
  printf '#!/usr/bin/env bash\necho "sleep:$1" >> "%s/events.log"\n' "$TMP" > "$BIN/sleep"
  real_python="$(command -v python3)"
  cat > "$BIN/python3" <<'PYTHON'
#!/usr/bin/env bash
if [ "$1" = "-c" ] && [[ "$2" == *random.randrange* ]]; then
  printf '%s\n' "$3" > "$IRIS_RNG_ARG_LOG"
  printf '%s\n' "$IRIS_TEST_JITTER"
  exit 0
fi
exec "$REAL_PYTHON" "$@"
PYTHON
  chmod +x "$BIN/sleep" "$BIN/python3"
  run env PATH="$BIN:$PATH" REAL_PYTHON="$real_python" IRIS_TEST_JITTER=7 \
      IRIS_RNG_ARG_LOG="$TMP/rng-arg.log" \
      SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=8 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ "$(cat "$TMP/rng-arg.log")" -eq 8 ]
  [ "$(cat "$TMP/events.log")" = $'sleep:7\nagent:--once' ]
}

@test "IRIS_TICK_JITTER_MAX=0 skips the jitter sleep entirely" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  printf '#!/usr/bin/env bash\necho "$1" >> "%s/sleep.log"\n' "$TMP" > "$BIN/sleep"
  chmod +x "$BIN/sleep"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=0 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/agent-invoked" ]
  [ ! -f "$TMP/sleep.log" ]
}

@test "a failed agent tick opens a backoff window that skips the NEXT tick's catalog contact" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  mkdir -p "$STAGE/agent"
  # counts real invocations, then always fails -- like an unreachable/overloaded catalog
  printf 'import sys\nwith open(r"%s/agent-invocations", "a") as f: f.write("x")\nsys.exit(1)\n' \
    "$TMP" > "$STAGE/agent/iris_agent.py"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=0 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 1 ]
  [ "$(wc -c < "$TMP/agent-invocations")" -eq 1 ]
  [ -f "$STAGE/.iris-tick-backoff" ]
  read -r skip_until streak < "$STAGE/.iris-tick-backoff"
  [ "$streak" -eq 1 ]
  [ "$skip_until" -gt "$(date +%s)" ]

  # the NEXT tick (EEM fires again 60s later, well inside the backoff window)
  # must skip catalog contact -- no second agent invocation -- and say so.
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=0 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"backing off catalog contact"* ]]
  [ "$(wc -c < "$TMP/agent-invocations")" -eq 1 ]
}

@test "a successful agent tick clears a stale backoff window" {
  printf 'rpc_secret = SAME\n' > "$STAGE/iris-agent.conf"
  printf 'SAME\n' > "$STAGE/rpc-secret"
  mkdir -p "$STAGE/agent"
  printf 'open(r"%s/agent-invoked", "w").write("ran")\n' "$TMP" \
    > "$STAGE/agent/iris_agent.py"
  # a backoff window that already expired, from a streak of 3 prior failures
  printf '%s %s\n' "$(( $(date +%s) - 5 ))" 3 > "$STAGE/.iris-tick-backoff"
  run env PATH="$BIN:$PATH" SRC="$SRC" STAGE="$STAGE" IRIS_TICK_JITTER_MAX=0 \
      bash "$BATS_TEST_DIRNAME/bootstrap.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/agent-invoked" ]
  [ ! -f "$STAGE/.iris-tick-backoff" ]
}
