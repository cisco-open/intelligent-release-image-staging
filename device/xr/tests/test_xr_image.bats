#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for device/xr/{Dockerfile, entrypoint.sh} -- the XR appmgr agent
# container image (agentinfo/plans/2026-08-28-xr-agent.md, Task 1). The
# container is activated with "--net=host -v /misc/disk1:/hostmount"; that
# bind mount IS harddisk: (write-through hardware-proven, see
# agentinfo/xr-support/LAB-RESULTS-2026-08-27.md), so there is no placement
# step and no CLI/SSH-to-self transport the way the IOx image needs.

setup() {
  XR_DIR="$BATS_TEST_DIRNAME/.."
  DOCKERFILE="$XR_DIR/Dockerfile"
  ENTRYPOINT="$XR_DIR/entrypoint.sh"
  REPO="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
  ROOT="$BATS_TEST_TMPDIR/root"
  CONF="$ROOT/etc/iris/iris-agent.conf"
  STAGE="$ROOT/hostmount"
  mkdir -p "$STAGE"
}

# Run entrypoint.sh under a clean environment (env -i, only PATH kept) with
# the IRIS_* dirs redirected into our fake root -- no docker needed. The
# script runs conf synthesis, then hits the first reconcile_conf_key() call,
# which shells out to `python3 -c "import agent_config"`; this fake root has
# no /opt/iris/agent on PYTHONPATH, so that import fails and the function
# returns non-zero. That is a bare top-level statement under `set -eu`, so
# the script exits right there instead of falling through into its infinite
# aria2c/tick loop -- deterministic, no backgrounding or timeouts needed. We
# only ever assert on the conf file written before that point.
_run_entrypoint() {
  run env -i PATH="$PATH" \
    IRIS_AGENT_CONF="$CONF" IRIS_STAGE_DIR="$STAGE" \
    "$@" \
    bash "$ENTRYPOINT"
}

@test "entrypoint.sh has no syntax errors" {
  run bash -n "$ENTRYPOINT"
  [ "$status" -eq 0 ]
}

@test "entrypoint.sh does not reference CAF/IOx-specific paths" {
  ! grep -q 'CAF_APP_PERSISTENT_DIR' "$ENTRYPOINT"
  ! grep -q 'IRIS_SHARE_DIR\|IRIS_SHARE_IOS_PATH' "$ENTRYPOINT"
  ! grep -q 'IRIS_DEVICE_SSH_' "$ENTRYPOINT"
  ! grep -q 'IRIS_RUNTIME_MODE\|runtime_mode' "$ENTRYPOINT"
}

# ---------------------------------------------------------------------------
# Required env enforcement (first boot, no dropped conf)
# ---------------------------------------------------------------------------

@test "entrypoint refuses to start without IRIS_CATALOG_URL" {
  _run_entrypoint IRIS_CATALOG_TOKEN=tok123 IRIS_DEVICE_ID=8010-r1
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS_CATALOG_URL"* ]]
  [ ! -f "$CONF" ]
}

@test "entrypoint refuses to start without IRIS_CATALOG_TOKEN" {
  _run_entrypoint IRIS_CATALOG_URL=https://198.51.100.1:8443 IRIS_DEVICE_ID=8010-r1
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS_CATALOG_TOKEN"* ]]
  [ ! -f "$CONF" ]
}

@test "entrypoint refuses to start without IRIS_DEVICE_ID" {
  _run_entrypoint IRIS_CATALOG_URL=https://198.51.100.1:8443 IRIS_CATALOG_TOKEN=tok123
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS_DEVICE_ID"* ]]
  [ ! -f "$CONF" ]
}

# ---------------------------------------------------------------------------
# Conf synthesis correctness
# ---------------------------------------------------------------------------

@test "entrypoint synthesizes a conf with the required fields from env" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  [ -f "$CONF" ]
  run cat "$CONF"
  [[ "$output" == *"catalog_url = https://198.51.100.1:8443"* ]]
  [[ "$output" == *"catalog_token = tok123"* ]]
  [[ "$output" == *"device_id = 8010-r1"* ]]
  [[ "$output" == *"stage_dir = $STAGE"* ]]
}

@test "conf synthesis fixes target_fs to harddisk: and mode to xr" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  run cat "$CONF"
  [[ "$output" == *"target_fs = harddisk:"* ]]
  [[ "$output" == *"mode = xr"* ]]
}

@test "conf synthesis ignores an operator-supplied IRIS_TARGET_FS -- XR has no placement step" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1 \
    IRIS_TARGET_FS=sdflash:
  run cat "$CONF"
  [[ "$output" == *"target_fs = harddisk:"* ]]
  [[ "$output" != *"sdflash:"* ]]
}

@test "conf synthesis applies telemetry/rpc_port/max_peers env overrides" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1 \
    IRIS_RPC_PORT=6801 \
    IRIS_TELEMETRY=off \
    IRIS_TELEMETRY_STREAM=on \
    IRIS_MAX_PEERS=5
  run cat "$CONF"
  [[ "$output" == *"rpc_port = 6801"* ]]
  [[ "$output" == *"telemetry = off"* ]]
  [[ "$output" == *"telemetry_stream = on"* ]]
  [[ "$output" == *"max_peers = 5"* ]]
}

@test "conf synthesis defaults: telemetry on, telemetry_stream off, rpc_port 6800" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  run cat "$CONF"
  [[ "$output" == *"telemetry = on"* ]]
  [[ "$output" == *"telemetry_stream = off"* ]]
  [[ "$output" == *"rpc_port = 6800"* ]]
}

@test "conf synthesis leaves rpc_secret as an empty placeholder" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  run grep '^rpc_secret = $' "$CONF"
  [ "$status" -eq 0 ]
}

@test "conf synthesis defaults catalog_ca to the baked-in cert path" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  run cat "$CONF"
  [[ "$output" == *"catalog_ca = /opt/iris/iris-catalog.pem"* ]]
}

@test "conf synthesis writes exactly the caller-supplied catalog_token, once" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=super-secret-token \
    IRIS_DEVICE_ID=8010-r1
  run grep -c '^catalog_token = ' "$CONF"
  [ "$output" -eq 1 ]
  run grep '^catalog_token = super-secret-token$' "$CONF"
  [ "$status" -eq 0 ]
}

@test "entrypoint creates the iris-work subdir under the stage dir" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  [ -d "$STAGE/iris-work" ]
}

# ---------------------------------------------------------------------------
# Dropped-conf-wins
# ---------------------------------------------------------------------------

@test "a dropped conf at CONF wins over synthesis (dropped-conf-wins)" {
  mkdir -p "$(dirname "$CONF")"
  cat > "$CONF" <<'EOF'
catalog_url = https://sentinel.example:8443
catalog_token = sentinel-token
device_id = sentinel-device
mode = xr
target_fs = harddisk:
EOF
  chmod 600 "$CONF"
  _run_entrypoint \
    IRIS_CATALOG_URL=https://different.example:8443 \
    IRIS_CATALOG_TOKEN=different-token \
    IRIS_DEVICE_ID=different-device
  run cat "$CONF"
  [[ "$output" == *"sentinel"* ]]
  [[ "$output" != *"different"* ]]
}

# ---------------------------------------------------------------------------
# No secrets baked into the Dockerfile (static, no docker needed)
# ---------------------------------------------------------------------------

@test "Dockerfile carries no ENV default for any *_TOKEN/*_PASS/*_SECRET name" {
  # The only ENV defaults present are non-secret operational knobs (rpc
  # port, tick, peers, telemetry toggle, the public catalog cert path).
  # Secrets arrive only via appmgr docker-run-opts --env at activation.
  ! grep -iE '(TOKEN|PASS|SECRET)=' "$DOCKERFILE"
}

@test "Dockerfile does not install an SSH/CLI transport -- XR needs none" {
  # Check only the actual apt-get install line, not the explanatory comment
  # above it (which names openssh-client/sshpass deliberately, to say why
  # they are absent here unlike device/iox/Dockerfile).
  run grep 'apt-get install' "$DOCKERFILE"
  [ "$status" -eq 0 ]
  [[ "$output" != *"openssh-client"* ]]
  [[ "$output" != *"sshpass"* ]]
}

@test "Dockerfile is a multi-stage-free x86_64 build (no arch-pinned base image)" {
  grep -qE '^FROM python:3\.12-slim-[a-z]+$' "$DOCKERFILE"
  ! grep -qE '^FROM (arm64v8|amd64|i386|arm32v7)/' "$DOCKERFILE"
}

# ---------------------------------------------------------------------------
# Image build (skipped when docker is unavailable -- same command -v ... ||
# skip idiom device/tests/test_gen_installers.bats uses for optional tools)
# ---------------------------------------------------------------------------

_stage_build_context() {
  CTX="$BATS_TEST_TMPDIR/ctx"
  mkdir -p "$CTX/agent" "$CTX/agent_bin"
  cp "$REPO"/device/agent/*.py "$CTX/agent/"
  cp "$REPO/device/agent/peer-receipt-hook.sh" "$CTX/agent/"
  cp "$REPO/VERSION" "$CTX/agent/VERSION"
  # docker build only chmods this file, never executes it -- content is moot.
  printf '#!/bin/sh\nexit 0\n' > "$CTX/agent_bin/aria2c"
  chmod +x "$CTX/agent_bin/aria2c"
  # a throwaway self-signed cert stands in for the pinned catalog cert
  openssl req -x509 -newkey rsa:2048 -keyout "$CTX/key.pem" \
    -out "$CTX/iris-catalog.pem" -days 1 -nodes -subj "/CN=test-catalog" 2>/dev/null
  cp "$DOCKERFILE" "$ENTRYPOINT" "$CTX/"
}

@test "the XR image builds" {
  command -v docker >/dev/null 2>&1 || skip "docker not available"
  docker info >/dev/null 2>&1 || skip "docker daemon not reachable"
  _stage_build_context
  TAG="iris-xr-test:$$"
  run docker build -t "$TAG" "$CTX"
  docker rmi -f "$TAG" >/dev/null 2>&1 || true
  [ "$status" -eq 0 ]
}

@test "the built XR image bakes no secret-bearing env value in any layer" {
  command -v docker >/dev/null 2>&1 || skip "docker not available"
  docker info >/dev/null 2>&1 || skip "docker daemon not reachable"
  _stage_build_context
  TAG="iris-xr-test-history:$$"
  docker build -t "$TAG" "$CTX" >/dev/null
  run docker history --no-trunc "$TAG"
  docker rmi -f "$TAG" >/dev/null 2>&1 || true
  [ "$status" -eq 0 ]
  [[ "$output" != *"IRIS_CATALOG_TOKEN="* ]]
}
