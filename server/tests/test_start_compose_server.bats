#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
#
# The bring-up must talk to the container ITS OWN compose project started, not
# to whatever container happens to be called "iris" on the host (issue #26).
# On a host already running a live IRIS the literal name made the health poll
# report the live server's health. Package readiness is now local provenance
# verification and never reads deployment TLS material from a container.

setup() {
  REPO="$BATS_TEST_TMPDIR/repo"
  STUB="$BATS_TEST_TMPDIR/bin"
  export DOCKER_LOG="$BATS_TEST_TMPDIR/docker.log"
  mkdir -p "$REPO/tools" "$REPO/server" "$REPO/artifacts" "$REPO/bin" "$STUB"

  cp "$BATS_TEST_DIRNAME/../../tools/start-compose-server.sh" "$REPO/tools/"
  cp "$BATS_TEST_DIRNAME/../setup_status.py" "$REPO/server/"
  chmod +x "$REPO/tools/start-compose-server.sh"
  : > "$REPO/server/docker-compose.yml"
  # the handed-in seeder client server/Dockerfile COPYs; present by default so
  # the bring-up gets past its preflight (issue #203)
  : > "$REPO/bin/aria2c"
  # present so the script reaches the XR freshness block below it
  printf '#!/usr/bin/env bash\nexit 0\n' > "$REPO/tools/provision-iox-packages.sh"
  chmod +x "$REPO/tools/provision-iox-packages.sh"
  : > "$REPO/artifacts/iris-xr.rpm"

  cat > "$STUB/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s|' "$@" >> "$DOCKER_LOG"; printf '\n' >> "$DOCKER_LOG"
case "$1" in
  compose)
    for a in "$@"; do [ "$a" = ps ] && { [ -n "${FAKE_PS_FAIL:-}" ] && exit 1; printf '%s\n' "${FAKE_CID-c0ffeecafe01}"; exit 0; }; done
    exit 0 ;;
  inspect) printf 'healthy\n' ;;
  exec) printf 'notBefore=Jan  1 00:00:00 2020 GMT\n' ;;
  *) exit 1 ;;
esac
STUB
  chmod +x "$STUB/docker"
}

run_bringup() {
  PATH="$STUB:$PATH" run bash "$REPO/tools/start-compose-server.sh"
}

@test "health poll targets the compose-resolved container, not the literal 'iris'" {
  run_bringup
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }

  grep -q '^inspect|-f|{{.State.Health.Status}}|c0ffeecafe01|$' "$DOCKER_LOG" || {
    echo "docker inspect did not target the compose-resolved container:"; cat "$DOCKER_LOG"; return 1; }
  # the literal name must never be used as a container argument
  grep -qE '^(inspect|exec)\|.*\|iris\|' "$DOCKER_LOG" && {
    echo "the literal 'iris' container was still addressed:"; cat "$DOCKER_LOG"; return 1; }
  return 0
}

@test "an explicit IRIS_CONTAINER wins over the compose lookup" {
  IRIS_CONTAINER=iris-dev run_bringup
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -q '^inspect|-f|{{.State.Health.Status}}|iris-dev|$' "$DOCKER_LOG" || {
    echo "$(cat "$DOCKER_LOG")"; return 1; }
  ! grep -q '^exec|' "$DOCKER_LOG"
}

@test "an unresolvable container fails loudly instead of poking another project's" {
  FAKE_CID= run_bringup
  [ "$status" -eq 1 ]
  [[ "$output" == *"could not resolve the iris container"* ]]
  grep -q '^inspect|' "$DOCKER_LOG" && { echo "inspected something anyway"; return 1; }
  return 0
}

@test "a failing compose lookup fails the bring-up rather than exiting silently" {
  # set -e + pipefail must not swallow the diagnostic: the operator has to be
  # told, not left with a bring-up that stopped after `up -d` with no reason.
  FAKE_PS_FAIL=1 run_bringup
  [ "$status" -eq 1 ]
  [[ "$output" == *"could not resolve the iris container"* ]]
}

@test "a fresh clone without the handed-in aria2c is refused before the build" {
  # bin/aria2c is a handed-in deliverable and git-ignored by design, so a fresh
  # clone has none and server/Dockerfile's COPY dies inside BuildKit with a
  # cache-key error naming no remedy (issue #203). Name the remedy, and name it
  # before anything is built or started.
  rm -f "$REPO/bin/aria2c"
  run_bringup
  [ "$status" -eq 1 ]
  [[ "$output" == *"bin/aria2c"* ]]
  [[ "$output" == *"tools/get-aria2c.sh"* ]]
  [ ! -s "$DOCKER_LOG" ] || { echo "docker ran anyway:"; cat "$DOCKER_LOG"; return 1; }
}
