#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  CHECK="$BATS_TEST_DIRNAME/../../tools/check-package-freshness.sh"
  STUB="$BATS_TEST_TMPDIR/bin"
  ARTIFACTS="$BATS_TEST_TMPDIR/artifacts"
  mkdir -p "$STUB" "$ARTIFACTS"
  export OPENSSL_LOG="$BATS_TEST_TMPDIR/openssl.log"
  : > "$OPENSSL_LOG"

  cat > "$STUB/openssl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$OPENSSL_LOG"
if [ "$1" = s_client ]; then
  printf '%s\n' "${FAKE_SERVED_CERT:-served}"
elif [ "${2:-}" = -outform ]; then
  cat
else
  input=""
  previous=""
  for value in "$@"; do
    if [ "$previous" = -in ]; then input="$value"; break; fi
    previous="$value"
  done
  case "$(cat "$input")" in
    *served*) fp=SERVED ;;
    *distributed*) fp=DISTRIBUTED ;;
    *) fp=OTHER ;;
  esac
  printf 'sha256 Fingerprint=%s\n' "$fp"
fi
STUB
  chmod +x "$STUB/openssl"

  cat > "$STUB/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  inspect) exit 0 ;;
  cp) printf '%s\n' "${FAKE_DISTRIBUTED_CERT:-served}" > "$3" ;;
  *) exit 1 ;;
esac
STUB
  chmod +x "$STUB/docker"
}

_make_package() {
  local name="$1" kind="$2" platform="$3" path sha
  path="$ARTIFACTS/$name"
  printf 'final wrapper bytes for %s\n' "$name" > "$path"
  sha="$(sha256sum "$path" | awk '{print $1}')"
  cat > "$path.manifest" <<EOF
format=iris-device-wrapper-v1
wrapper_kind=$kind
wrapper_file=$name
wrapper_sha256=$sha
platform=$platform
canonical_index_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111
canonical_archive_sha256=2222222222222222222222222222222222222222222222222222222222222222
canonical_source_sha256=3333333333333333333333333333333333333333333333333333333333333333
EOF
}

_make_required_packages() {
  _make_package iris-amd64.tar iox linux/amd64
  _make_package iris-arm64.tar iox linux/arm64
}

_run_check() {
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 \
    ARTIFACTS_DIR="$ARTIFACTS" run bash "$CHECK" "$@"
}

@test "served and distributed certificate mismatch fails without rebuilding packages" {
  _make_required_packages
  FAKE_DISTRIBUTED_CERT=distributed _run_check --rebuild

  [[ "$output" == *"MISMATCH"* ]]
  [[ "$output" == *"Package rebuilding cannot repair"* ]]
  [[ "$output" != *">> rebuilding"* ]]
  [ "$status" -eq 1 ]
}

@test "readable IOx wrappers with matching provenance are ready" {
  _make_required_packages
  _run_check

  [[ "$output" == *"iris-amd64.tar"*"READY"* ]]
  [[ "$output" == *"iris-arm64.tar"*"READY"* ]]
  [[ "$output" == *"iris-xr.rpm        absent"* ]]
  [[ "$output" == *"match their provenance manifests"* ]]
  [[ "$output" != *"pin the live catalog certificate"* ]]
  [ "$status" -eq 0 ]
}

@test "certificate replacement does not stale deployment-neutral packages" {
  _make_required_packages
  FAKE_SERVED_CERT=rotated FAKE_DISTRIBUTED_CERT=rotated _run_check

  [[ "$output" == *"iris-amd64.tar"*"READY"* ]]
  [[ "$output" == *"iris-arm64.tar"*"READY"* ]]
  [[ "$output" != *"STALE"* ]]
  [ "$status" -eq 0 ]
}

@test "a missing provenance sidecar is unknown, never ready" {
  _make_required_packages
  rm "$ARTIFACTS/iris-arm64.tar.manifest"
  _run_check

  [[ "$output" == *"iris-arm64.tar"*"UNKNOWN (provenance-absent)"* ]]
  [[ "$output" == *"NOT READY: iris-arm64.tar"* ]]
  [ "$status" -eq 1 ]
}

@test "wrapper bytes changed after provenance are stale" {
  _make_required_packages
  printf 'later mutation\n' >> "$ARTIFACTS/iris-amd64.tar"
  _run_check

  [[ "$output" == *"iris-amd64.tar"*"STALE (wrapper-digest-mismatch)"* ]]
  [[ "$output" == *"contents or validate a native package signature"* ]]
  [ "$status" -eq 1 ]
}

@test "XR uses the same provenance contract and no certificate-age heuristic" {
  _make_required_packages
  _make_package iris-xr.rpm xr-appmgr linux/amd64
  touch -t 200001010000 "$ARTIFACTS/iris-xr.rpm"
  _run_check

  [[ "$output" == *"iris-xr.rpm"*"READY"* ]]
  ! grep -q -- '-startdate' "$OPENSSL_LOG"
  [[ "$output" != *"MTIME"* ]]
  [ "$status" -eq 0 ]
}

@test "an absent required IOx wrapper is not reported as verified" {
  _run_check

  [[ "$output" == *"NOT READY: iris-amd64.tar iris-arm64.tar"* ]]
  [[ "$output" != *"required package bytes are readable"* ]]
  [ "$status" -eq 1 ]
}

@test "rebuild repairs the explicit relative artifact directory being checked" {
  _make_required_packages
  export READY_PACKAGES="$BATS_TEST_TMPDIR/ready-packages"
  export BUILD_LOG="$BATS_TEST_TMPDIR/build.log"
  mkdir -p "$READY_PACKAGES"
  cp "$ARTIFACTS/iris-arm64.tar" "$ARTIFACTS/iris-arm64.tar.manifest" "$READY_PACKAGES/"
  rm "$ARTIFACTS/iris-arm64.tar" "$ARTIFACTS/iris-arm64.tar.manifest"

  local repo="$BATS_TEST_TMPDIR/repo"
  mkdir -p "$repo/tools" "$repo/server"
  cp "$CHECK" "$repo/tools/check-package-freshness.sh"
  cp "$BATS_TEST_DIRNAME/../setup_status.py" "$repo/server/setup_status.py"
  cat > "$repo/tools/provision-iox-packages.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${IRIS_ARTIFACTS_HOST_DIR:-unset}" > "$BUILD_LOG"
[ -n "${IRIS_ARTIFACTS_HOST_DIR:-}" ] || exit 3
cp "$READY_PACKAGES/iris-arm64.tar" "$READY_PACKAGES/iris-arm64.tar.manifest" \
  "$IRIS_ARTIFACTS_HOST_DIR/"
STUB
  chmod +x "$repo/tools/provision-iox-packages.sh" "$repo/tools/check-package-freshness.sh"
  CHECK="$repo/tools/check-package-freshness.sh"
  cd "$BATS_TEST_TMPDIR"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 \
    ARTIFACTS_DIR=artifacts run bash "$CHECK" --rebuild

  [ "$status" -eq 0 ]
  [ "$(cat "$BUILD_LOG")" = "$ARTIFACTS" ]
  [[ "$output" == *">> re-checking"* ]]
  [[ "$output" == *"required package bytes are readable"* ]]
}

@test "checker has valid shell syntax and documents its only option" {
  run bash -n "$CHECK"
  [ "$status" -eq 0 ]
  run bash "$CHECK" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--rebuild"* ]]
}
