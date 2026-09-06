#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Fast source-level contract tests. The real multi-platform BuildKit and
# xr-appmgr/rpmbuild paths are integration builds, not default unit tests.

setup() {
  HELPER="$BATS_TEST_DIRNAME/../../../tools/build-xr-package.sh"
  COMMON="$BATS_TEST_DIRNAME/../../../tools/build-device-image.sh"
}

@test "XR package helper has valid shell syntax" {
  bash -n "$HELPER"
}

@test "help exposes output and dry-run controls" {
  run bash "$HELPER" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--out"* ]]
  [[ "$output" == *"--dry-run"* ]]
}

@test "unknown options fail as usage errors" {
  run bash "$HELPER" --nope
  [ "$status" -eq 2 ]
}

@test "dry-run is hermetic and names the canonical multi-platform OCI" {
  run env PATH="/usr/bin:/bin" bash "$HELPER" --out /tmp/iris-test-out --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"canonical amd64+arm64 OCI archive"* ]]
  [[ "$output" == *"tools/build-device-image.sh --context"* ]]
  [[ "$output" == *"/tmp/iris-test-out/iris-xr.rpm"* ]]
}

@test "XR wrapper consumes linux/amd64 from the canonical OCI, never rebuilds it" {
  grep -q '"\$REPO/tools/build-device-image.sh" --context "\$CTX"' "$HELPER"
  grep -q 'iris-device-oci.manifest' "$HELPER"
  grep -q 'skopeo copy --override-os linux --override-arch amd64' "$HELPER"
  ! grep -qE 'docker (build|save)' "$HELPER"
}

@test "XR and IOx wrappers call the same common builder" {
  IOX="$BATS_TEST_DIRNAME/../../iox/build.sh"
  run grep -F '$REPO/tools/build-device-image.sh" --context "$CTX"' "$HELPER"
  [ "$status" -eq 0 ]
  run grep -F '$REPO/tools/build-device-image.sh" --context "$CTX"' "$IOX"
  [ "$status" -eq 0 ]
}

@test "appmgr metadata stays on the hardware-proven release and source shape" {
  grep -q 'APPMGR_BUILD_COMMIT:-37d79607' "$HELPER"
  grep -q 'APPMGR_RELEASE:-ThinXR_7.3.15' "$HELPER"
  grep -q 'file: iris-src/\$IMAGE_TAR_NAME' "$HELPER"
  grep -q 'copy_hostname: false' "$HELPER"
  grep -q 'copy_ems_cert: false' "$HELPER"
}

@test "stale RPMS cannot satisfy a failed appmgr build" {
  grep -q 'rm -rf "\$APPMGR_BUILD_DIR/RPMS"' "$HELPER"
  grep -q "find .*RPMS.*-name '\*.rpm'" "$HELPER"
  grep -q 'did not produce an RPM' "$HELPER"
}

@test "common builder pins both architectures and records immutable identity" {
  grep -q -- '--platform linux/amd64,linux/arm64' "$COMMON"
  grep -q 'source_sha256=' "$COMMON"
  grep -q 'oci_identity()' "$COMMON"
  grep -q 'index_digest=\$index_digest' "$COMMON"
  grep -q 'archive_sha256=' "$COMMON"
  grep -q 'refusing to overwrite it' "$COMMON"
}

# Behavioral harness: the canonical builder, OCI selector, git, and appmgr
# build tool are small fakes; the real wrapper's ordering, stale-output guard,
# metadata, atomic publication, and provenance are exercised end to end.
_xr_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  APPMGR_DIR="$BATS_TEST_TMPDIR/appmgr"
  OUT_DIR="$BATS_TEST_TMPDIR/out"
  mkdir -p "$STUBDIR/tools" "$STUBDIR/device/xr" "$STUBDIR/bin" "$APPMGR_DIR"
  ln -s "$HELPER" "$STUBDIR/tools/build-xr-package.sh"
  printf '0.0.0-test\n' > "$STUBDIR/VERSION"

  cat > "$STUBDIR/tools/build-device-image.sh" <<'STUB'
#!/usr/bin/env bash
set -eu
[ "${COMMON_STUB_FAIL:-0}" = 0 ] || { echo "COMMON-STUB: refused" >&2; exit 41; }
ctx=""
while [ $# -gt 0 ]; do
  case "$1" in --context) ctx="$2"; shift 2 ;; *) shift ;; esac
done
archive="$TEST_ROOT/canonical.oci.tar"
printf 'canonical oci bytes\n' > "$archive"
printf '%s\n' "$archive" > "$ctx/iris-device-oci-path"
cat > "$ctx/iris-device-oci.manifest" <<EOF
format=iris-device-oci-v1
source_sha256=1111111111111111111111111111111111111111111111111111111111111111
index_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222
archive_sha256=3333333333333333333333333333333333333333333333333333333333333333
platforms=linux/amd64,linux/arm64
EOF
STUB
  chmod +x "$STUBDIR/tools/build-device-image.sh"

  cat > "$STUBDIR/bin/skopeo" <<'STUB'
#!/usr/bin/env bash
echo "SKOPEO-STUB: $*"
for arg in "$@"; do
  case "$arg" in
    docker-archive:*) out="${arg#docker-archive:}"; out="${out%%:*}" ;;
  esac
done
printf 'classic docker archive bytes\n' > "$out"
STUB
  cat > "$STUBDIR/bin/git" <<'STUB'
#!/usr/bin/env bash
echo "STUB-GIT-SHOULD-NOT-BE-CALLED: $*" >&2
exit 99
STUB
  chmod +x "$STUBDIR/bin/skopeo" "$STUBDIR/bin/git"
  export TEST_ROOT="$BATS_TEST_TMPDIR"
}

_run_real() {
  run env PATH="$STUBDIR/bin:$PATH" TEST_ROOT="$TEST_ROOT" \
    COMMON_STUB_FAIL="${COMMON_STUB_FAIL:-0}" \
    APPMGR_BUILD_DIR="$APPMGR_DIR" \
    bash "$STUBDIR/tools/build-xr-package.sh" --out "$OUT_DIR"
}

_appmgr_success() {
  cat > "$APPMGR_DIR/appmgr_build" <<'STUB'
#!/usr/bin/env bash
mkdir -p RPMS
printf 'real rpm bytes\n' > RPMS/iris-xr-test.x86_64.rpm
echo "Done building"
STUB
  chmod +x "$APPMGR_DIR/appmgr_build"
}

@test "behavior: a success-looking appmgr run without an RPM fails honestly" {
  _xr_stub_setup
  cat > "$APPMGR_DIR/appmgr_build" <<'STUB'
#!/usr/bin/env bash
echo "Done building"
exit 0
STUB
  chmod +x "$APPMGR_DIR/appmgr_build"
  _run_real
  [ "$status" -ne 0 ]
  [[ "$output" == *"did not produce an RPM"* ]]
  [[ "$output" == *"not proof of success"* ]]
  [ ! -e "$OUT_DIR/iris-xr.rpm" ]
}

@test "behavior: a stale RPM is removed before a failed build" {
  _xr_stub_setup
  mkdir -p "$APPMGR_DIR/RPMS"
  printf 'stale\n' > "$APPMGR_DIR/RPMS/old.rpm"
  printf '#!/usr/bin/env bash\necho Done building\n' > "$APPMGR_DIR/appmgr_build"
  chmod +x "$APPMGR_DIR/appmgr_build"
  _run_real
  [ "$status" -ne 0 ]
  [ ! -e "$OUT_DIR/iris-xr.rpm" ]
}

@test "behavior: a produced RPM and adjacent provenance publish atomically" {
  _xr_stub_setup
  _appmgr_success
  _run_real
  [ "$status" -eq 0 ]
  [ "$(cat "$OUT_DIR/iris-xr.rpm")" = "real rpm bytes" ]
  manifest="$OUT_DIR/iris-xr.rpm.manifest"
  [ -f "$manifest" ]
  grep -q '^format=iris-device-wrapper-v1$' "$manifest"
  grep -q '^wrapper_kind=xr-appmgr$' "$manifest"
  grep -q '^platform=linux/amd64$' "$manifest"
  grep -q '^canonical_index_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222$' "$manifest"
  grep -q '^canonical_archive_sha256=3333333333333333333333333333333333333333333333333333333333333333$' "$manifest"
  grep -q '^canonical_source_sha256=1111111111111111111111111111111111111111111111111111111111111111$' "$manifest"
  grep -q "^wrapper_sha256=$(sha256sum "$OUT_DIR/iris-xr.rpm" | awk '{print $1}')$" "$manifest"
  ! find "$OUT_DIR" -maxdepth 1 -name '.iris-xr.rpm.*' | grep -q .
}

@test "behavior: generated build.yaml keeps the proven source and release" {
  _xr_stub_setup
  _appmgr_success
  _run_real
  [ "$status" -eq 0 ]
  grep -q '^  release: "ThinXR_7.3.15"$' "$APPMGR_DIR/build.yaml"
  grep -q '^      file: iris-src/iris-xr.tar.gz$' "$APPMGR_DIR/build.yaml"
  [ -s "$APPMGR_DIR/iris-src/iris-xr.tar.gz" ]
}

@test "behavior: a reused builder cannot leak stale iris-src files into the wrapper" {
  _xr_stub_setup
  mkdir -p "$APPMGR_DIR/iris-src/config" "$APPMGR_DIR/iris-src/data"
  printf 'stale config\n' > "$APPMGR_DIR/iris-src/config/stale.conf"
  printf 'stale data\n' > "$APPMGR_DIR/iris-src/data/stale.bin"
  _appmgr_success
  _run_real
  [ "$status" -eq 0 ]
  [ ! -e "$APPMGR_DIR/iris-src/config/stale.conf" ]
  [ ! -e "$APPMGR_DIR/iris-src/data/stale.bin" ]
  [ -s "$APPMGR_DIR/iris-src/iris-xr.tar.gz" ]
}

@test "behavior: an existing builder is reused without git" {
  _xr_stub_setup
  _appmgr_success
  _run_real
  [ "$status" -eq 0 ]
  [[ "$output" == *"reusing existing xr-appmgr-build"* ]]
  [[ "$output" != *"STUB-GIT-SHOULD-NOT-BE-CALLED"* ]]
}

@test "behavior: nonempty APPMGR_BUILD_DIR without a builder is preserved and refused" {
  _xr_stub_setup
  printf 'operator data\n' > "$APPMGR_DIR/precious.txt"
  _run_real
  [ "$status" -ne 0 ]
  [[ "$output" == *"Refusing to clone over it"* ]]
  [ "$(cat "$APPMGR_DIR/precious.txt")" = "operator data" ]
}

@test "behavior: an empty APPMGR_BUILD_DIR is cloned without deletion" {
  _xr_stub_setup
  cat > "$STUBDIR/bin/git" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = clone ]; then
  mkdir -p "$3"
  cat > "$3/appmgr_build" <<'INNER'
#!/usr/bin/env bash
mkdir -p RPMS
printf 'cloned rpm\n' > RPMS/iris-xr.rpm
INNER
  chmod +x "$3/appmgr_build"
  echo "CLONED $3"
fi
exit 0
STUB
  chmod +x "$STUBDIR/bin/git"
  _run_real
  [ "$status" -eq 0 ]
  [[ "$output" == *"CLONED $APPMGR_DIR"* ]]
  [ -f "$OUT_DIR/iris-xr.rpm" ]
}

@test "behavior: canonical builder failure stops before wrapper work" {
  _xr_stub_setup
  _appmgr_success
  COMMON_STUB_FAIL=1 _run_real
  [ "$status" -eq 41 ]
  [[ "$output" == *"COMMON-STUB: refused"* ]]
  [[ "$output" != *"SKOPEO-STUB"* ]]
  [ ! -e "$OUT_DIR/iris-xr.rpm" ]
}
