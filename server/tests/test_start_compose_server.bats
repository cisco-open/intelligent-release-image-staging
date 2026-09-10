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
  # artifacts/ must be owned by the runtime uid. A test fixture cannot chown to
  # another uid unprivileged, and the preflight must never reach the real sudo
  # from a test run, so ownership is simulated: stat reports the runtime uid by
  # default, and the refusal test below overrides it (issue #204).
  : > "$REPO/artifacts/.gitkeep"
  printf '#!/usr/bin/env bash\ncase "$2" in %%u) echo 10001 ;; %%g) id -g ;; *) /usr/bin/stat "$@" ;; esac\n' > "$STUB/stat"
  printf '#!/usr/bin/env bash\necho "sudo must not be reached from a test" >&2\nexit 1\n' > "$STUB/sudo"
  chmod +x "$STUB/stat" "$STUB/sudo"
  # present so the script reaches the XR freshness block below it
  printf '#!/usr/bin/env bash\nexit 0\n' > "$REPO/tools/provision-iox-packages.sh"
  chmod +x "$REPO/tools/provision-iox-packages.sh"
  : > "$REPO/artifacts/iris-xr.rpm"
  # the hand-ins the IOx tooling needs, and a stub XR builder that writes the
  # two files the placement step copies (issue #204 follow-up)
  mkdir -p "$REPO/tools/bin" "$REPO/deliverables" "$REPO/instr-roots"
  : > "$REPO/tools/bin/ioxclient"; chmod +x "$REPO/tools/bin/ioxclient"
  : > "$REPO/deliverables/aria2c-x86_64"; : > "$REPO/deliverables/aria2c-aarch64"
  printf 'ssh-ed25519 AAAA root-a\n' > "$REPO/instr-roots/root-a.pub"
  printf 'ssh-ed25519 AAAA root-b\n' > "$REPO/instr-roots/root-b.pub"
  printf '#!/usr/bin/env bash\nout=""; while [ $# -gt 0 ]; do [ "$1" = --out ] && out="$2"; shift; done\n: > "$out/iris-xr.rpm"; : > "$out/iris-xr.rpm.manifest"\n' > "$REPO/tools/build-xr-package.sh"
  chmod +x "$REPO/tools/build-xr-package.sh"

  cat > "$STUB/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s|' "$@" >> "$DOCKER_LOG"; printf '\n' >> "$DOCKER_LOG"
case "$1" in
  compose)
    for a in "$@"; do [ "$a" = ps ] && { [ -n "${FAKE_PS_FAIL:-}" ] && exit 1; printf '%s\n' "${FAKE_CID-c0ffeecafe01}"; exit 0; }; done
    exit 0 ;;
  inspect) printf 'healthy\n' ;;
  exec) printf 'notBefore=Jan  1 00:00:00 2020 GMT\n' ;;
  cp) exit 0 ;;
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
  # the only exec is the XR placement, and it must address the override too
  ! grep '^exec|' "$DOCKER_LOG" | grep -vq '^exec|iris-dev|'
  grep -q '^exec|iris-dev|mv|' "$DOCKER_LOG"
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

@test "an artifacts dir the runtime uid cannot write is refused before the build" {
  # The silent-failure case: the server would start, skip self-provisioning,
  # and leave the Console reporting every device package absent with no way to
  # fix it from a container that has no Docker socket (issue #204). Stub stat
  # to report a foreign owner, and sudo to refuse, so the preflight has to
  # report rather than repair.
  printf '#!/usr/bin/env bash\ncase "$2" in %%u) echo 1000 ;; %%g) id -g ;; *) /usr/bin/stat "$@" ;; esac\n' > "$STUB/stat"
  chmod +x "$STUB/stat"
  run_bringup
  [ "$status" -eq 1 ]
  [[ "$output" == *"artifacts"* ]]
  [[ "$output" == *"10001"* ]]
  [[ "$output" == *"chown"* ]]
  [ ! -s "$DOCKER_LOG" ] || { echo "docker ran anyway:"; cat "$DOCKER_LOG"; return 1; }
}


@test "every missing hand-in is reported in one list before anything is built" {
  # The failure mode this replaces: an install that passed one preflight, built
  # for ten minutes, then died on the NEXT absent input. All of them, at once.
  rm -f "$REPO/bin/aria2c" "$REPO/tools/bin/ioxclient" "$REPO/deliverables/aria2c-aarch64" "$REPO/instr-roots/root-b.pub"
  run_bringup
  [ "$status" -eq 1 ]
  [[ "$output" == *"missing 4 input(s)"* ]]
  [[ "$output" == *"bin/aria2c"* ]]
  [[ "$output" == *"ioxclient"* ]]
  [[ "$output" == *"aria2c for arm64"* ]]
  [[ "$output" == *"exactly two public roots"* ]]
  [[ "$output" == *"custody ceremony"* ]]
  [ ! -s "$DOCKER_LOG" ] || { echo "docker ran anyway:"; cat "$DOCKER_LOG"; return 1; }
}

@test "the installer never generates trust roots" {
  grep -q "ssh-keygen" "$REPO/tools/start-compose-server.sh" && {
    echo "the installer must not mint instruction roots"; return 1; }
  return 0
}

@test "public roots are installed into the config volume between bootstrap and up" {
  run_bringup
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bootstrap_line="$(grep -n 'iris-bootstrap' "$DOCKER_LOG" | head -1 | cut -d: -f1)"
  roots_line="$(grep -n "instr-roots:/pub:ro" "$DOCKER_LOG" | head -1 | cut -d: -f1)"
  up_line="$(grep -n '|up|-d|' "$DOCKER_LOG" | head -1 | cut -d: -f1)"
  [ -n "$bootstrap_line" ] && [ -n "$roots_line" ] && [ -n "$up_line" ] || { cat "$DOCKER_LOG"; return 1; }
  [ "$bootstrap_line" -lt "$roots_line" ] && [ "$roots_line" -lt "$up_line" ] || {
    echo "roots must be installed after bootstrap and before up:"; cat "$DOCKER_LOG"; return 1; }
  # read-only, public halves only: never a private key path, never rw
  ! grep -q "instr-roots:/pub|" "$DOCKER_LOG"
}

@test "the XR RPM is built into a private dir and placed through the container" {
  run_bringup
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -q '^cp|.*iris-xr.rpm|c0ffeecafe01:/srv/artifacts/.iris-xr.rpm.tmp|$' "$DOCKER_LOG" || { cat "$DOCKER_LOG"; return 1; }
  grep -q '^exec|c0ffeecafe01|mv|-f|/srv/artifacts/.iris-xr.rpm.tmp|/srv/artifacts/iris-xr.rpm|$' "$DOCKER_LOG" || { cat "$DOCKER_LOG"; return 1; }
  [[ "$output" == *"XR package is staged"* ]]
}

@test "IRIS_SKIP_XR skips the XR build without failing the install" {
  IRIS_SKIP_XR=1 run_bringup
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  ! grep -q 'iris-xr.rpm.tmp' "$DOCKER_LOG"
  [[ "$output" == *"not building the XR RPM"* ]]
}
