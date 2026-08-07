#!/usr/bin/env bats
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  export TMPDIR_T="$(mktemp -d)"
  export CONF="$TMPDIR_T/iris-agent.conf"
  cat > "$CONF" <<EOF
catalog_url = https://c:8443
catalog_token = t
device_id = d1
telemetry = on
telemetry_stream = off
EOF
  export PYTHONPATH="$BATS_TEST_DIRNAME/../../agent"
  source "$BATS_TEST_DIRNAME/../reconcile.sh"
}

teardown() { rm -rf "$TMPDIR_T"; }

@test "env value wins over persistent conf" {
  reconcile_conf_key telemetry_stream on
  grep -q '^telemetry_stream = on$' "$CONF"
}

@test "full enable-disable-enable cycle, both keys" {
  for key in telemetry telemetry_stream; do
    reconcile_conf_key "$key" on;  grep -q "^$key = on$" "$CONF"
    reconcile_conf_key "$key" off; grep -q "^$key = off$" "$CONF"
    reconcile_conf_key "$key" on;  grep -q "^$key = on$" "$CONF"
  done
}

@test "unset env is a no-op" {
  reconcile_conf_key telemetry_stream ""
  grep -q '^telemetry_stream = off$' "$CONF"
}

@test "entrypoint synthesizes telemetry_stream defaulting off" {
  grep -q 'telemetry_stream = \${IRIS_TELEMETRY_STREAM:-off}' \
    "$BATS_TEST_DIRNAME/../entrypoint.sh"
}
