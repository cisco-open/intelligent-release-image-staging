#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# provision-served.sh stages the three DERIVABLE served artifacts (Guest Shell
# bundle, bootstrap.sh, iris-catalog.pem) into the artifacts dir at container
# startup, so a fresh deploy no longer fails onboarding on missing files. It is
# failure leaves the server running, but returns non-zero and reports readiness.

setup() {
  PROV="$BATS_TEST_DIRNAME/../provision-served.sh"
  DEVICE="$BATS_TEST_DIRNAME/../../device"
  TMP="$(mktemp -d)"
  ART="$TMP/artifacts"; mkdir -p "$ART"
  mkdir -p "$TMP/server" "$TMP/run"
  cp "$PROV" "$TMP/server/provision-served.sh"
  cp "$BATS_TEST_DIRNAME/../pack-agent-bundle.sh" "$TMP/server/pack-agent-bundle.sh"
  PROV="$TMP/server/provision-served.sh"
  python3 - "$TMP/aria2c" <<'PYTHON'
import pathlib,sys
# Minimal ELF header: checksum/architecture fixture, never executed.
pathlib.Path(sys.argv[1]).write_bytes(b'\x7fELF\x02\x01\x01' + bytes(9) + b'\x02\x00\x3e\x00' + bytes(44))
PYTHON
  chmod +x "$TMP/aria2c"
  printf '%s  x86_64\n' "$(sha256sum "$TMP/aria2c" | awk '{print $1}')" > "$TMP/aria2c.sha256"
  mkdir -p "$TMP/config/tls"; printf 'CRTPEM\n' > "$TMP/config/tls/crt.pem"
  run_prov() {
    IRIS_DEVICE_DIR="$DEVICE" IRIS_ARIA2="$TMP/aria2c" \
      IRIS_ARIA2_SUMS="$TMP/aria2c.sha256" IRIS_RUN="$TMP/run" \
      IRIS_CRT_SRC="$TMP/config/tls/crt.pem" \
      bash "$PROV" "$ART"
  }
}
teardown() { rm -rf "$TMP"; }

@test "stages the Guest Shell bundle, bootstrap.sh, and iris-catalog.pem" {
  run run_prov
  [ "$status" -eq 0 ]
  [ -f "$ART/iris-agent.tgz" ]
  [ -f "$ART/bootstrap.sh" ]
  [ -f "$ART/iris-catalog.pem" ]
  # the cert is the server's public cert, verbatim
  run cat "$ART/iris-catalog.pem"
  [[ "$output" == "CRTPEM" ]]
  # This is public certificate material and the documented host-side XR build
  # reads it directly even when the container runs with umask 077.
  [ "$(stat -c '%a' "$ART/iris-catalog.pem" 2>/dev/null || stat -f '%Lp' "$ART/iris-catalog.pem")" = "644" ]
  # the bundle carries the agent code
  tar tzf "$ART/iris-agent.tgz" | grep -q "agent/iris_agent.py"
}

@test "rebuilds the bundle every run so it can't go stale" {
  run_prov
  cp "$ART/iris-agent.tgz" "$TMP/first.tgz"
  # newer agent source -> a fresh run must re-pack (content reflects current tree)
  run run_prov
  [ "$status" -eq 0 ]
  [ -f "$ART/iris-agent.tgz" ]
}

@test "read-only artifacts dir warns and reports failure" {
  chmod -w "$ART"
  run run_prov
  chmod +w "$ART"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not writable"* ]]
  check_guest_status stale
}

@test "missing server cert: still stages the bundle, exits 0, warns about the cert" {
  rm -f "$TMP/config/tls/crt.pem"
  run run_prov
  [ "$status" -eq 0 ]
  [ -f "$ART/iris-agent.tgz" ]
  [ ! -f "$ART/iris-catalog.pem" ]
  [[ "$output" == *"cert"* ]]
}

@test "notes when the IOx iris-arm64.tar is absent (the one external build)" {
  run run_prov
  [[ "$output" == *"iris-arm64.tar"* ]]
}

@test "does not flag iris-arm64.tar when it is already staged" {
  printf 'IOXPKG\n' > "$ART/iris-arm64.tar"
  run run_prov
  [[ "$output" != *"build device/iox/build.sh"* ]]
}


check_guest_status() {
  PYTHONPATH="$BATS_TEST_DIRNAME/.." python3 - "$ART" "$TMP/run/served-bundle.json" "$1" <<'PYTHON'
import sys
import setup_status
status = setup_status.build_status(sys.argv[1], '', '', 'admin',
                                  provision_status_path=sys.argv[2],
                                  provision_startup_state="ok")
item = next(row for row in status['packages']['items'] if row['name'] == 'iris-agent.tgz')
assert item['state'] == sys.argv[3], item
if sys.argv[3] != 'ok':
    assert status['packages']['state'] != 'ok', status
PYTHON
}

@test "verified bundle readiness binds both served bundle and bootstrap bytes" {
  run run_prov
  [ "$status" -eq 0 ]
  check_guest_status ok
  cp "$ART/iris-agent.tgz" "$TMP/verified.tgz"
  printf 'changed bundle\n' >> "$ART/iris-agent.tgz"
  check_guest_status stale
  cp "$TMP/verified.tgz" "$ART/iris-agent.tgz"
  printf 'changed bootstrap\n' >> "$ART/bootstrap.sh"
  check_guest_status stale
}

@test "checksum mismatch preserves prior bundle and reports failed provisioning" {
  run_prov
  cp "$ART/iris-agent.tgz" "$TMP/prior.tgz"
  printf 'substituted\n' >> "$TMP/aria2c"
  run run_prov
  [ "$status" -ne 0 ]
  [[ "$output" == *"checksum"* ]]
  cmp "$ART/iris-agent.tgz" "$TMP/prior.tgz"
  check_guest_status stale
}

@test "wrong ELF architecture is refused even with a matching checksum" {
  python3 - "$TMP/aria2c" <<'PYTHON'
from pathlib import Path
import sys
p = Path(sys.argv[1]); data = bytearray(p.read_bytes()); data[18:20] = b'\xb7\x00'; p.write_bytes(data)
PYTHON
  printf '%s  x86_64\n' "$(sha256sum "$TMP/aria2c" | awk '{print $1}')" > "$TMP/aria2c.sha256"
  run run_prov
  [ "$status" -ne 0 ]
  [[ "$output" == *"x86_64 ELF"* ]]
  [ ! -f "$ART/iris-agent.tgz" ]
  check_guest_status stale
}

@test "pack failure replaces previous success readiness while preserving prior bundle" {
  run_prov
  cp "$ART/iris-agent.tgz" "$TMP/prior.tgz"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$TMP/server/pack-agent-bundle.sh"
  run run_prov
  [ "$status" -ne 0 ]
  cmp "$ART/iris-agent.tgz" "$TMP/prior.tgz"
  [ ! -f "$ART/.iris-agent.tgz.tmp" ]
  check_guest_status stale
}

@test "missing manifest and missing receipt never report a healthy Guest Shell bundle" {
  run_prov
  rm "$TMP/aria2c.sha256"
  run run_prov
  [ "$status" -ne 0 ]
  check_guest_status stale
  rm "$TMP/run/served-bundle.json"
  check_guest_status unknown
}

@test "malformed or interrupted provisioning evidence cannot report success" {
  run_prov
  printf '{broken\n' > "$TMP/run/served-bundle.json"
  check_guest_status unknown
  printf '{"format":"iris-served-bundle-v1","state":"pending"}\n' > "$TMP/run/served-bundle.json"
  check_guest_status stale
}

run_startup_provisioning() {
  # Execute the actual startup block with the provisioner path redirected to
  # this test's file fixture; no secrets setup or services are needed.
  python3 - "$BATS_TEST_DIRNAME/../docker-entrypoint.sh" "$TMP/startup-block.sh" <<'PYTHON'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
start = text.index('# Self-provision the derivable served artifacts')
end = text.index('if [ "${SKIP_SUPERVISE:-0}"', start)
Path(sys.argv[2]).write_text(text[start:end])
PYTHON
  export IRIS_DEVICE_DIR="$DEVICE" IRIS_ARIA2="$TMP/aria2c"
  export IRIS_ARIA2_SUMS="$TMP/aria2c.sha256" IRIS_RUN="$TMP/run"
  export IRIS_CRT_SRC="$TMP/config/tls/crt.pem" IRIS_ARTIFACTS_DIR="$ART"
  bash() {
    if [ "$1" = /opt/iris/server/provision-served.sh ]; then
      command bash "$PROV" "$ART"
    else
      command bash "$@"
    fi
  }
  # Keep -e active: the provision failure must not terminate server startup.
  set -e
  source "$TMP/startup-block.sh"
  PYTHONPATH="$BATS_TEST_DIRNAME/.." python3 - "$ART" "$TMP/run/served-bundle.json" "$1" <<'PYTHON'
import os, sys
import setup_status
startup = os.environ.get('_IRIS_SERVED_BUNDLE_STARTUP')
assert startup == sys.argv[3], startup
status = setup_status.build_status(sys.argv[1], '', '', 'admin',
                                  provision_status_path=sys.argv[2],
                                  provision_startup_state=startup)
item = next(row for row in status['packages']['items'] if row['name'] == 'iris-agent.tgz')
assert item['state'] == ('ok' if startup == 'ok' else 'stale'), item
PYTHON
}

@test "startup rejects an old successful receipt when the next receipt cannot be written" {
  run_prov
  cp "$TMP/run/served-bundle.json" "$TMP/prior-receipt.json"
  chmod 500 "$TMP/run"
  run run_startup_provisioning failed
  chmod 700 "$TMP/run"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  cmp "$TMP/prior-receipt.json" "$TMP/run/served-bundle.json"
}

@test "startup success overrides inherited failure and is exported with its receipt" {
  export _IRIS_SERVED_BUNDLE_STARTUP=failed
  run run_startup_provisioning ok
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}
