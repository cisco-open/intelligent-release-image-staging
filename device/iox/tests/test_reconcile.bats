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

@test "a stale agent_version in a persistent conf is overwritten" {
  # The version string is a fact about the image, not operator state: after a
  # package upgrade a persistent conf still carried the old build's number and
  # every telemetry report mis-stated what was running (field observation
  # 2026-08-20: the 3400 kept reporting 2026.07.26 from a pre-release-cut
  # package). The baked VERSION must win on every start.
  echo "agent_version = 2026.07.26" >> "$CONF"
  reconcile_conf_key agent_version 2026.08.20
  grep -q '^agent_version = 2026.08.20$' "$CONF"
  ! grep -q '2026\.07\.26' "$CONF"
}

@test "entrypoint reconciles agent_version from the baked VERSION file" {
  grep -q 'reconcile_conf_key agent_version' "$BATS_TEST_DIRNAME/../entrypoint.sh"
}

@test "entrypoint synthesizes catalog_ca defaulting to the baked-in cert path" {
  # #12 fail-closed fix: every entrypoint must hand a real, non-empty
  # catalog_ca to a first-boot conf, or a fresh container would immediately
  # hit make_catalog_context's refusal instead of a verified connection.
  grep -q 'catalog_ca = \${IRIS_CATALOG_CA:-/opt/iris/iris-catalog.pem}' \
    "$BATS_TEST_DIRNAME/../entrypoint.sh"
}
