#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# XR-profile tests for the one device/container image and entrypoint. The
# container is activated with "--net=host -v /misc/disk1:/hostmount"; that
# bind mount IS harddisk: (write-through hardware-proven, see
# agentinfo/xr-support/LAB-RESULTS-2026-08-27.md), so there is no placement
# step and no CLI/SSH-to-self transport the way the IOx image needs.

setup() {
  XR_DIR="$BATS_TEST_DIRNAME/.."
  CONTAINER_DIR="$XR_DIR/../container"
  DOCKERFILE="$CONTAINER_DIR/Dockerfile"
  ENTRYPOINT="$CONTAINER_DIR/entrypoint.sh"
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
# IRIS_CONTAINER_TESTING + IRIS_TEST_SKIP_MOUNT_CHECK: the entrypoint refuses
# dir is a real mount (the harddisk: bind mount on a device); the suite
# runs it against a plain temporary directory, so the check is bypassed
# here and exercised on its own below.
_run_entrypoint() {
  run env -i PATH="$PATH" IRIS_DEVICE_PLATFORM=xr-appmgr \
    IRIS_CONTAINER_TESTING=1 IRIS_TEST_SKIP_MOUNT_CHECK=1 \
    IRIS_AGENT_CONF="$CONF" IRIS_STAGE_DIR="$STAGE" \
    "$@" \
    bash "$ENTRYPOINT"
}

# ---------------------------------------------------------------------------
# Stage-dir mount check (review finding IRIS-12-006)
# ---------------------------------------------------------------------------

@test "entrypoint refuses a stage dir that is not a mounted filesystem" {
  # /tmp can itself be a bind mount in a sandbox. A nonexistent direct child
  # of / has no non-root mount ancestor on any host. This validation-only
  # sentinel must be rejected before mkdir or conf synthesis; never create it.
  unmounted="/__iris_xr_not_a_mount_${BASHPID}"
  [ ! -e "$unmounted" ]
  run env -i PATH="$PATH" \
    IRIS_DEVICE_PLATFORM=xr-appmgr IRIS_CONTAINER_TESTING=1 \
    IRIS_AGENT_CONF="$CONF" IRIS_STAGE_DIR="$unmounted" \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 IRIS_DEVICE_ID=8010-r1 \
    bash "$ENTRYPOINT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not a mounted filesystem"* ]]
  [[ "$output" == *"harddisk:"* ]]
  [ ! -e "$unmounted" ]
  [ ! -f "$CONF" ]
}

@test "entrypoint accepts a stage dir that sits under a real mount point" {
  # A directory beneath a mount other than / (the first such mount point in
  # /proc/mounts on this host) passes the check; the run then proceeds into
  # conf synthesis exactly like the bypassed runs below. Skipped where no
  # non-root mount is visible.
  probe=""
  while read -r mnt; do
    mkdir -p "$mnt/.iris-xr-bats-$$" 2>/dev/null || continue
    probe="$mnt/.iris-xr-bats-$$"; break
  done < <(awk '$2 != "/" && $2 !~ /^\/(proc|sys|dev)(\/|$)/ { print $2 }' /proc/mounts)
  [ -n "$probe" ] || skip "no writable non-root mount point visible in /proc/mounts"
  run env -i PATH="$PATH" \
    IRIS_DEVICE_PLATFORM=xr-appmgr IRIS_CONTAINER_TESTING=1 \
    IRIS_AGENT_CONF="$probe/iris-agent.conf" IRIS_STAGE_DIR="$probe" \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 IRIS_DEVICE_ID=8010-r1 \
    bash "$ENTRYPOINT"
  rc=$status; out=$output
  rm -rf "$probe"
  [[ "$out" != *"not a mounted filesystem"* ]]
  [ -n "$rc" ]
}

@test "the mount check bypass is documented as test-only" {
  grep -q 'IRIS_TEST_SKIP_MOUNT_CHECK' "$ENTRYPOINT"
  grep -q 'IRIS_CONTAINER_TESTING' "$ENTRYPOINT"
}

@test "entrypoint.sh has no syntax errors" {
  run bash -n "$ENTRYPOINT"
  [ "$status" -eq 0 ]
}

@test "xr-appmgr rejects the IOx SSH environment surface" {
  _run_entrypoint IRIS_DEVICE_SSH_HOST=192.0.2.1
  [ "$status" -ne 0 ]
  [[ "$output" == *"forbids IRIS_DEVICE_SSH_"* ]]
  [ ! -f "$CONF" ]
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

@test "conf synthesis rejects IRIS_TARGET_FS instead of overriding XR storage" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1 \
    IRIS_TARGET_FS=sdflash:
  [ "$status" -ne 0 ]
  [[ "$output" == *"forbids IRIS_TARGET_FS"* ]]
  [ ! -f "$CONF" ]
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

@test "conf synthesis uses the runtime certificate on the harddisk bind mount" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  run cat "$CONF"
  [[ "$output" == *"catalog_ca = $STAGE/iris-catalog.pem"* ]]
}

@test "conf synthesis writes device_model from the installer's env" {
  # device/xr-install.sh's --env IRIS_MODEL (the fleet row); xr_deps.py's
  # _conf_fact() reads this exact conf key for the heartbeat's model field --
  # there is no CLI on this platform to ask instead.
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1 \
    IRIS_MODEL=8201
  run cat "$CONF"
  [[ "$output" == *"device_model = 8201"* ]]
}

@test "conf synthesis writes device_version from the installer's env" {
  # device/xr-install.sh's --env IRIS_VERSION (parsed from its own preflight
  # show version); xr_deps.py's _conf_fact() reads this exact conf key for
  # the heartbeat's version field.
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1 \
    IRIS_VERSION="25.4.2 LNT"
  run cat "$CONF"
  [[ "$output" == *"device_version = 25.4.2 LNT"* ]]
}

@test "conf synthesis leaves device_model blank when the installer sent none" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  run grep -E '^device_model = $' "$CONF"
  [ "$status" -eq 0 ]
}

@test "conf synthesis leaves device_version blank when the installer sent none" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  run grep -E '^device_version = $' "$CONF"
  [ "$status" -eq 0 ]
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

@test "conf synthesis rejects a token outside the strict header grammar" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    'IRIS_CATALOG_TOKEN=literal\c-token' \
    IRIS_DEVICE_ID=8010-r1
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS_CATALOG_TOKEN contains unsafe characters"* ]]
  [ ! -e "$CONF" ]
}

@test "entrypoint creates the iris-work subdir under the stage dir" {
  _run_entrypoint \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1
  [ -d "$STAGE/iris-work" ]
}

# F3: the conf must default under the PERSISTENT mount (iris-work/, same
# directory the state file already lives in), never a container-local path
# like /etc/iris -- a recreated container starts with an empty container
# filesystem but the SAME /hostmount, so a conf that only ever existed at a
# container-local path re-synthesizes from the activation env (the original
# enrollment token) and 401s forever once that token is past its TTL.
@test "conf defaults under iris-work/ on the persistent mount, not a container-local path" {
  run env -i PATH="$PATH" IRIS_DEVICE_PLATFORM=xr-appmgr \
    IRIS_CONTAINER_TESTING=1 IRIS_TEST_SKIP_MOUNT_CHECK=1 \
    IRIS_STAGE_DIR="$STAGE" \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=tok123 \
    IRIS_DEVICE_ID=8010-r1 \
    bash "$ENTRYPOINT"
  [ -f "$STAGE/iris-work/iris-agent.conf" ]
}

@test "a conf synthesized at the default path survives a from-scratch container recreation" {
  # First boot: no conf anywhere, synthesize from the activation env (the
  # original enrollment token) at the default path.
  run env -i PATH="$PATH" IRIS_DEVICE_PLATFORM=xr-appmgr \
    IRIS_CONTAINER_TESTING=1 IRIS_TEST_SKIP_MOUNT_CHECK=1 \
    IRIS_STAGE_DIR="$STAGE" \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=enrollment-token \
    IRIS_DEVICE_ID=8010-r1 \
    bash "$ENTRYPOINT"
  DEFAULT_CONF="$STAGE/iris-work/iris-agent.conf"
  [ -f "$DEFAULT_CONF" ] || return 1
  # Simulate the agent rotating its token in place (write_conf round-trip),
  # exactly what a live token refresh does.
  sed -i.bak 's/^catalog_token = .*/catalog_token = rotated-token/' "$DEFAULT_CONF"
  # Second boot: a brand-new container -- same activation env (still the
  # ORIGINAL enrollment token, the only thing appmgr ever hands the
  # container), but the SAME persistent mount. dropped-conf-wins must see
  # the conf already at the default path and keep the rotated token.
  run env -i PATH="$PATH" IRIS_DEVICE_PLATFORM=xr-appmgr \
    IRIS_CONTAINER_TESTING=1 IRIS_TEST_SKIP_MOUNT_CHECK=1 \
    IRIS_STAGE_DIR="$STAGE" \
    IRIS_CATALOG_URL=https://198.51.100.1:8443 \
    IRIS_CATALOG_TOKEN=enrollment-token \
    IRIS_DEVICE_ID=8010-r1 \
    bash "$ENTRYPOINT"
  run cat "$DEFAULT_CONF"
  [[ "$output" == *"rotated-token"* ]] || return 1
  [[ "$output" != *"enrollment-token"* ]]
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
# Real reconcile pass (target_fs/stage_dir force -- xr-task1-review.md Finding 1)
#
# _run_entrypoint above deliberately runs with no PYTHONPATH: the first
# reconcile_conf_key call's `import agent_config` then fails and `set -eu`
# kills the script right there, before it ever reaches its infinite
# aria2c/tick loop -- convenient for the synthesis-only tests above, but it
# also means none of them ever observe what reconcile_conf_key actually
# writes. That blind spot is exactly how the target_fs/stage_dir corruption
# this section guards against went undetected: with a dropped conf that
# omits those two ("optional" per agent_config.py's own docstring, and the
# exact shape the dropped-conf-wins test above uses), agent_config.load()
# used to backfill them from its IOx-tuned DEFAULTS and the (previously
# unconditional-only-for-agent_version) write-back would persist that onto
# disk, silently undoing the "target_fs=harddisk: forced" platform
# invariant. These tests set a REAL PYTHONPATH (the actual device/agent/)
# so reconcile_conf_key's import genuinely succeeds and its read-modify-
# write runs for real. That means the script no longer dies at reconcile --
# it falls through into the infinite tick loop (aria2c missing from this
# fixture doesn't abort it either: that failure sits on the non-last side
# of a "cmd && cur=val" list, which set -e does not treat as fatal). So we
# bound the run and kill it, the same portable timeout idiom already used
# by device/iox/tests/test_iox_install_output.bats and
# device/tests/test_device_install.bats for the same reason (a process that
# legitimately keeps running past the point under test).
# ---------------------------------------------------------------------------

_run_entrypoint_real_reconcile_impl() {
  local outfile pid waited=0 secs=5
  outfile="$(mktemp)"
  ( env -i PATH="$PATH" PYTHONPATH="$REPO/device/agent" \
        IRIS_DEVICE_PLATFORM=xr-appmgr IRIS_CONTAINER_TESTING=1 \
        IRIS_TEST_SKIP_MOUNT_CHECK=1 \
        IRIS_AGENT_CONF="$CONF" IRIS_STAGE_DIR="$STAGE" IRIS_TICK_SECONDS=1 \
        "$@" \
        bash "$ENTRYPOINT" >"$outfile" 2>&1 ) &
  pid=$!
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$secs" ]; do
    sleep 1; waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
  else
    wait "$pid" 2>/dev/null
  fi
  cat "$outfile"
  rm -f "$outfile"
}

_run_entrypoint_real_reconcile() {
  run _run_entrypoint_real_reconcile_impl "$@"
}

# Shared dropped-conf shape for both tests below: the review's exact repro --
# catalog_url/catalog_token/device_id/mode present, target_fs and stage_dir
# both OMITTED (both documented "optional" by agent_config.py).
_drop_conf_missing_target_fs_and_stage_dir() {
  mkdir -p "$(dirname "$CONF")"
  cat > "$CONF" <<'EOF'
catalog_url = https://sentinel.example:8443
catalog_token = sentinel-token
device_id = sentinel-device
mode = xr
EOF
  chmod 600 "$CONF"
}

@test "real reconcile replaces the legacy baked certificate path before validating it" {
  _drop_conf_missing_target_fs_and_stage_dir
  printf '%s\n' 'catalog_ca = /opt/iris/iris-catalog.pem' >> "$CONF"
  _run_entrypoint_real_reconcile
  grep -qF "catalog_ca = $STAGE/iris-catalog.pem" "$CONF"
  ! grep -q '^catalog_ca = /opt/iris/iris-catalog.pem$' "$CONF"
}

@test "real reconcile: a dropped conf missing target_fs is force-corrected to harddisk:, not wiped by agent_config's IOx default" {
  _drop_conf_missing_target_fs_and_stage_dir
  _run_entrypoint_real_reconcile
  run grep -c '^target_fs = ' "$CONF"
  [ "$output" -eq 1 ]
  grep -q '^target_fs = harddisk:$' "$CONF"
}

@test "real reconcile: a dropped conf missing stage_dir is force-corrected to the mounted stage dir, not backfilled to IOx's default path" {
  _drop_conf_missing_target_fs_and_stage_dir
  _run_entrypoint_real_reconcile
  run grep -q '^stage_dir = /flash/guest-share/iris$' "$CONF"
  [ "$status" -ne 0 ]
  grep -qF "stage_dir = $STAGE" "$CONF"
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

@test "shared Dockerfile carries the IOx SSH transport but XR cannot select it" {
  # One image means the IOx transport is physically present. Runtime isolation
  # is enforced by the platform selector tests above: xr-appmgr rejects every
  # SSH credential variable before the agent starts.
  run grep -E '^RUN apk add' "$DOCKERFILE"
  [ "$status" -eq 0 ]
  [[ "$output" == *"openssh-client"* ]]
  [[ "$output" == *"sshpass"* ]]
}

@test "Dockerfile installs only the runtime packages the entrypoint needs" {
  # Alpine BusyBox supplies the four retained diagnostic commands
  # (ps/top/free/kill), so procps would only duplicate them. Nothing may be
  # pip-installed.
  run grep -E '^RUN apk add' "$DOCKERFILE"
  [ "$status" -eq 0 ]
  [[ "$output" == *"--no-cache"* ]]
  [[ "$output" == *" curl"* ]]
  [[ "$output" == *" ca-certificates"* ]]
  [[ "$output" != *"procps"* ]]
  ! grep -qE '^RUN .*pip3? install' "$DOCKERFILE"
}

@test "Dockerfile is a multi-stage-free multi-architecture build" {
  # Official python image on Alpine, pinned by INDEX digest (tag@sha256:...)
  # so a rebuild is reproducible; the tag stays for human readability.
  grep -qE '^FROM python:3\.12-alpine[0-9.]+@sha256:[0-9a-f]{64}$' "$DOCKERFILE"
  run grep -qE '^FROM (arm64v8|amd64|i386|arm32v7)/' "$DOCKERFILE"
  [ "$status" -ne 0 ]
  [ "$(grep -c '^FROM ' "$DOCKERFILE")" -eq 1 ]
  grep -q '^ARG TARGETARCH$' "$DOCKERFILE"
}

# ---------------------------------------------------------------------------
# Image build -- OPT-IN ONLY.
#
# Everything above is hermetic: it reads files and runs entrypoint.sh under
# env -i. The two tests below are different in kind -- they invoke a real
# `docker build`, which needs a reachable daemon, pulls the pinned base image
# over the network and takes minutes. That makes the default suite depend on
# the machine it runs on, so a clean checkout cannot be trusted to be green.
# They run only when an operator asks for them:
#
#   IRIS_TEST_HOST_INTEGRATION=1 bats device/xr/tests/test_xr_image.bats
#
# The docker-availability guards stay as a second gate for that opt-in run
# (same command -v ... || skip idiom device/tests/test_gen_installers.bats
# uses for optional tools).
# ---------------------------------------------------------------------------

_require_host_integration() {
  [ "${IRIS_TEST_HOST_INTEGRATION:-0}" = "1" ] \
    || skip "host-integration test: set IRIS_TEST_HOST_INTEGRATION=1 to run a real docker build"
}

_stage_build_context() {
  CTX="$BATS_TEST_TMPDIR/ctx"
  mkdir -p "$CTX/agent" "$CTX/agent_bin"
  cp "$REPO"/device/agent/*.py "$CTX/agent/"
  cp "$REPO/device/agent/peer-transfer-hook.sh" "$CTX/agent/"
  # verify_image.py lives in device/, not device/agent/ -- iris_agent.py
  # imports it, so a build context missing it builds fine (Docker doesn't
  # care that a wildcard COPY missed a file it never expected) but the
  # container dies on `import verify_image` at the agent's first tick. Same
  # staging step tools/build-xr-package.sh and device/iox/build.sh use.
  cp "$REPO"/device/verify_image.py "$CTX/agent/verify_image.py"
  cp "$REPO/VERSION" "$CTX/agent/VERSION"
  # docker build only chmods this file, never executes it -- content is moot.
  printf '#!/bin/sh\nexit 0\n' > "$CTX/agent_bin/aria2c-amd64"
  printf '#!/bin/sh\nexit 0\n' > "$CTX/agent_bin/aria2c-arm64"
  chmod +x "$CTX/agent_bin/aria2c-amd64" "$CTX/agent_bin/aria2c-arm64"
  # a throwaway self-signed cert stands in for the pinned catalog cert
  openssl req -x509 -newkey rsa:2048 -keyout "$CTX/key.pem" \
    -out "$CTX/iris-catalog.pem" -days 1 -nodes -subj "/CN=test-catalog" 2>/dev/null
  cp "$DOCKERFILE" "$ENTRYPOINT" "$CONTAINER_DIR/reconcile.sh" "$CTX/"
}

@test "the XR image builds" {
  _require_host_integration
  command -v docker >/dev/null 2>&1 || skip "docker not available"
  docker info >/dev/null 2>&1 || skip "docker daemon not reachable"
  _stage_build_context
  TAG="iris-xr-test:$$"
  run docker build -t "$TAG" "$CTX"
  docker rmi -f "$TAG" >/dev/null 2>&1 || true
  [ "$status" -eq 0 ]
}

@test "the built XR image bakes no secret-bearing env value in any layer" {
  _require_host_integration
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
