#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

write_seeder_secrets() {
  printf '%s\n' '{"devices":{},"seeder":{"announce_token":{"value":"seedertoken"}}}' \
    > "$1"
}

@test "seed-launch reads the rpc-secret from IRIS_RPC_SECRET_FILE (tmpfs)" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/state/torrents" "$tmp/config/tls" "$tmp/log" "$tmp/images" "$tmp/run"
  echo "tmpfssecret" > "$tmp/run/rpc-secret"
  # an old plaintext on the volume must NOT be used when the env var is set
  echo "stalesecret" > "$tmp/config/rpc-secret"
  printf '%s\n' '-----BEGIN CERTIFICATE-----' 'test-only' \
    '-----END CERTIFICATE-----' > "$tmp/config/tls/crt.pem"
  write_seeder_secrets "$tmp/state/secrets.json"
  printf '#!/usr/bin/env bash\necho "$@"\n' > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"

  run env IRIS_STATE="$tmp/state" IRIS_CONFIG="$tmp/config" IRIS_LOG="$tmp/log" \
      IMAGES_DIR="$tmp/images" ARIA2="$tmp/aria2c-stub" \
      IRIS_RPC_SECRET_FILE="$tmp/run/rpc-secret" IRIS_HOST_IP=10.0.0.5 \
      bash "$BATS_TEST_DIRNAME/../seed-launch.sh"

  [ "$status" -eq 0 ]
  # Use grep for reliable substring matching after run (bats [[ ]] does not
  # enforce failures when -e is disabled by run's set+eET).
  # The secret never appears in the argv (IRIS-13-016); it is written to the
  # 0600 conf file aria2c is pointed at, and the stale on-volume value is
  # not what lands there.
  argv="$output"
  run grep -q -- "--rpc-secret=" <<<"$argv"
  [ "$status" -ne 0 ]
  grep -q -- "--conf-path=$tmp/state/seeder.aria2.conf" <<<"$argv"
  grep -qx "rpc-secret=tmpfssecret" "$tmp/state/seeder.aria2.conf"
  run grep -q "stalesecret" "$tmp/state/seeder.aria2.conf"
  [ "$status" -ne 0 ]
  rm -rf "$tmp"
}

make_config_validation_fixture() {
  tmp="$BATS_TEST_TMPDIR/seed-launch"
  mkdir -p "$tmp/state/torrents" "$tmp/config/tls" "$tmp/log" "$tmp/images" "$tmp/run"
  printf '%s\n' 'rpc-private-marker' > "$tmp/run/rpc-secret"
  printf '%s\n' '-----BEGIN CERTIFICATE-----' 'test-only' \
    '-----END CERTIFICATE-----' > "$tmp/config/tls/crt.pem"
  write_seeder_secrets "$tmp/run/secrets.json"
  cat > "$tmp/aria2c-stub" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$ARIA_ARGV_FILE"
touch "$ARIA_LAUNCH_MARKER"
STUB
  chmod +x "$tmp/aria2c-stub"
}

run_config_validation_fixture() {
  run env IRIS_STATE="$tmp/state" IRIS_CONFIG="$tmp/config" IRIS_LOG="$tmp/log" \
      IRIS_RUN="$tmp/run" IRIS_SECRETS="$tmp/run/secrets.json" \
      IMAGES_DIR="$tmp/images" ARIA2="$tmp/aria2c-stub" \
      IRIS_RPC_SECRET_FILE="$tmp/run/rpc-secret" IRIS_HOST_IP=10.0.0.5 \
      ARIA_ARGV_FILE="$tmp/aria2.argv" ARIA_LAUNCH_MARKER="$tmp/aria2.started" \
      bash "$BATS_TEST_DIRNAME/../seed-launch.sh"
}

assert_private_config_rejection() {
  [ "$status" -ne 0 ] || return 1
  [ "$output" = 'FATAL: seeder RPC or announce credential is invalid or unavailable; refusing to launch' ] || return 1
  [ ! -e "$tmp/aria2.started" ] || return 1
  [ ! -e "$tmp/aria2.argv" ] || return 1
  grep -qx 'prior-runtime-config' "$tmp/run/seeder.aria2.conf" || return 1
  [ -z "$(find "$tmp/run" -name '.seeder-config-*' -print -quit)" ] || return 1
}

@test "seed-launch rejects malformed announce values without changing config or launching aria2" {
  make_config_validation_fixture
  printf '%s\n' 'prior-runtime-config' > "$tmp/run/seeder.aria2.conf"
  for case_name in newline carriage tab space nul del nonascii surrogate empty null number boolean list object; do
    python3 - "$tmp/run/secrets.json" "$case_name" <<'PY' || return 1
import json
import pathlib
import sys

marker = "announce-private-marker"
values = {
    "newline": marker + "\nrpc-listen-all=true",
    "carriage": marker + "\rrpc-listen-all=true",
    "tab": marker + "\ttail",
    "space": marker + " tail",
    "nul": marker + "\x00tail",
    "del": marker + "\x7ftail",
    "nonascii": marker + "\u2603",
    "surrogate": marker + "\ud800",
    "empty": "", "null": None, "number": 123,
    "boolean": True, "list": [marker], "object": {"value": marker},
}
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "devices": {}, "seeder": {"announce_token": {"value": values[sys.argv[2]]}},
}))
PY
    run_config_validation_fixture
    assert_private_config_rejection || return 1
  done
}

@test "seed-launch rejects corrupt announce stores without tracebacks or credential output" {
  make_config_validation_fixture
  printf '%s\n' 'prior-runtime-config' > "$tmp/run/seeder.aria2.conf"
  for case_name in seeder-null seeder-list seeder-string record-null record-list record-string root-list broken-json invalid-utf8; do
    python3 - "$tmp/run/secrets.json" "$case_name" <<'PY' || return 1
import json
import pathlib
import sys

marker = "announce-private-marker"
values = {
    "seeder-null": {"seeder": None},
    "seeder-list": {"seeder": [marker]},
    "seeder-string": {"seeder": marker},
    "record-null": {"seeder": {"announce_token": None}},
    "record-list": {"seeder": {"announce_token": [marker]}},
    "record-string": {"seeder": {"announce_token": marker}},
    "root-list": [marker],
}
path = pathlib.Path(sys.argv[1])
if sys.argv[2] == "broken-json":
    path.write_text('{"seeder": "' + marker)
elif sys.argv[2] == "invalid-utf8":
    path.write_bytes(b'\xff' + marker.encode())
else:
    path.write_text(json.dumps(values[sys.argv[2]]))
PY
    run_config_validation_fixture
    assert_private_config_rejection || return 1
  done
}

@test "seed-launch rejects injected RPC credentials without changing config or launching aria2" {
  make_config_validation_fixture
  printf '%s\n' 'prior-runtime-config' > "$tmp/run/seeder.aria2.conf"
  for case_name in newline carriage trailing-cr tab space nul del nonascii empty; do
    python3 - "$tmp/run/rpc-secret" "$case_name" <<'PY' || return 1
import pathlib
import sys

marker = "rpc-private-marker"
values = {
    "newline": marker + "\nrpc-listen-all=true",
    "carriage": marker + "\rrpc-listen-all=true",
    "trailing-cr": marker + "\r\n",
    "tab": marker + "\ttail",
    "space": marker + " tail",
    "nul": marker + "\x00tail",
    "del": marker + "\x7ftail",
    "nonascii": marker + "\u2603",
    "empty": "",
}
pathlib.Path(sys.argv[1]).write_bytes(values[sys.argv[2]].encode())
PY
    run_config_validation_fixture
    assert_private_config_rejection || return 1
  done
}

@test "seed-launch keeps valid credentials in a private config and out of argv" {
  make_config_validation_fixture
  printf '%s\n' 'prior-runtime-config' > "$tmp/run/seeder.aria2.conf"
  chmod 0644 "$tmp/run/seeder.aria2.conf"
  printf '%s\n' 'rpc-private-marker_123-._~+/=!' > "$tmp/run/rpc-secret"
  printf '%s\n' '{"seeder":{"announce_token":{"value":"announce-private-marker_456-._~+/=!"}}}' \
    > "$tmp/run/secrets.json"
  run_config_validation_fixture
  [ "$status" -eq 0 ] || return 1
  [ -z "$output" ] || return 1
  [ -f "$tmp/aria2.started" ] || return 1
  [ "$(stat -c %a "$tmp/run/seeder.aria2.conf")" = 600 ] || return 1
  [ "$(wc -l < "$tmp/run/seeder.aria2.conf")" -eq 2 ] || return 1
  grep -Fxq 'rpc-secret=rpc-private-marker_123-._~+/=!' "$tmp/run/seeder.aria2.conf" || return 1
  grep -Fxq 'header=Authorization: Bearer announce-private-marker_456-._~+/=!' "$tmp/run/seeder.aria2.conf" || return 1
  ! grep -q 'private-marker' "$tmp/aria2.argv" || return 1
  ! grep -q -- '--rpc-secret\|--header' "$tmp/aria2.argv" || return 1
  [ -z "$(find "$tmp/run" -name '.seeder-config-*' -print -quit)" ] || return 1
}

@test "seed-launch cleans up a failed config write without launching aria2" {
  make_config_validation_fixture
  mkdir "$tmp/run/seeder.aria2.conf"
  run_config_validation_fixture
  [ "$status" -ne 0 ] || return 1
  [ "$output" = 'FATAL: seeder RPC or announce credential is invalid or unavailable; refusing to launch' ] || return 1
  [ ! -e "$tmp/aria2.started" ] || return 1
  [ -z "$(find "$tmp/run" -name '.seeder-config-*' -print -quit)" ] || return 1
}
