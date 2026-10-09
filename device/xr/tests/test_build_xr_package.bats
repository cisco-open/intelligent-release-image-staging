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
  grep -q 'rm -rf -- "\$RPM_OUTPUT_DIR"' "$HELPER"
  grep -q 'find "\$RPM_OUTPUT_DIR" -type f -name' "$HELPER"
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
  mkdir -p "$STUBDIR/tools" "$STUBDIR/device/xr" "$STUBDIR/bin" \
    "$APPMGR_DIR/release_configs"
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

  # rpmbuild is a precondition the script checks before it writes anything.
  # Stub it so these cases exercise their intended behaviour on a host that
  # does not happen to have the rpm package installed.
  cat > "$STUBDIR/bin/rpmbuild" <<'STUB'
#!/usr/bin/env bash
echo "RPMBUILD-STUB: $*"
STUB
  chmod +x "$STUBDIR/bin/rpmbuild"
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
    APPMGR_BUILD_CMD="${APPMGR_BUILD_CMD:-bash ./appmgr_build}" \
    bash "$STUBDIR/tools/build-xr-package.sh" --out "$OUT_DIR"
}

_run_real_default() {
  run env -u APPMGR_BUILD_CMD PATH="$STUBDIR/bin:$PATH" TEST_ROOT="$TEST_ROOT" \
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

@test "behavior: pinned appmgr gets a private RPM log without modifying the cached builder" {
  _xr_stub_setup
  mkdir -p "$APPMGR_DIR/iris-src/config" "$APPMGR_DIR/RPMS"
  printf 'cached build config\n' > "$APPMGR_DIR/build.yaml"
  printf 'cached source\n' > "$APPMGR_DIR/iris-src/config/keep.conf"
  printf 'cached rpm\n' > "$APPMGR_DIR/RPMS/keep.rpm"
  printf 'cached log\n' > "$APPMGR_DIR/.iris-appmgr-build.log"
  cat > "$APPMGR_DIR/appmgr_build" <<'STUB'
#!/usr/bin/env python3
from pathlib import Path

def main():
    target = "x86_64"
    spec_file = "spec"
    RPM_SOURCE_DIR = "sources"
    release_conf = {"build": {"rpm_rpm_dir": "rpms"}}
    command = [
        "./build_rpm.sh",
        "--target",
        target,
        "--spec-file",
        spec_file,
        "--source-dir", RPM_SOURCE_DIR,
        "--rpm-dir",
        release_conf["build"]["rpm_rpm_dir"],
        "--output-dir", "RPMS",
        "--verbose",
    ]
    print("APP-MGR-RPM-ARGV=" + repr(command))
    Path("RPMS").mkdir(exist_ok=True)
    Path("RPMS/iris-xr-test.x86_64.rpm").write_bytes(b"private-log-test-rpm")

main()
STUB
  chmod +x "$APPMGR_DIR/appmgr_build"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$APPMGR_DIR/build_rpm.sh"
  chmod +x "$APPMGR_DIR/build_rpm.sh"
  before="$(sha256sum "$APPMGR_DIR/appmgr_build" | awk '{print $1}')"
  private_tmp="$BATS_TEST_TMPDIR/tmp with 'quote"
  mkdir -p "$private_tmp"
  TMPDIR="$private_tmp" _run_real_default
  [ "$status" -eq 0 ]
  [[ "$output" == *"APP-MGR-RPM-ARGV="*"--log-file"*"/.iris-rpmbuild.log"* ]]
  [[ "$output" != *"/tmp/rpmbuild.log"* ]]
  [ "$(sha256sum "$APPMGR_DIR/appmgr_build" | awk '{print $1}')" = "$before" ]
  [ "$(cat "$OUT_DIR/iris-xr.rpm")" = "private-log-test-rpm" ]
  [ "$(cat "$APPMGR_DIR/build.yaml")" = "cached build config" ]
  [ "$(cat "$APPMGR_DIR/iris-src/config/keep.conf")" = "cached source" ]
  [ "$(cat "$APPMGR_DIR/RPMS/keep.rpm")" = "cached rpm" ]
  [ "$(cat "$APPMGR_DIR/.iris-appmgr-build.log")" = "cached log" ]
}

@test "behavior: private pinned appmgr runs where its spec and build_rpm paths resolve" {
  _xr_stub_setup
  cat > "$APPMGR_DIR/appmgr_build" <<'STUB'
#!/usr/bin/env python3
from pathlib import Path
import subprocess

def main():
    root = Path(__file__).resolve().parent
    spec = root / "build" / "specs" / "iris-xr.spec"
    spec.parent.mkdir(parents=True, exist_ok=True)
    spec.write_text("test spec\n")
    command = [
        "./build_rpm.sh",
        "--spec-file", "./build/specs/iris-xr.spec",
        "--source-dir", "build/archives/SOURCES",
        "--rpm-dir", "build/archives/RPMS",
        "--output-dir", "RPMS",
        "--verbose",
    ]
    print("APP-MGR-CWD=" + str(Path.cwd()) + " ROOT=" + str(root))
    if Path.cwd() != root:
        raise SystemExit("APP-MGR-CWD-MISMATCH")
    subprocess.run(command, check=True)

main()
STUB
  cat > "$APPMGR_DIR/build_rpm.sh" <<'STUB'
#!/usr/bin/env bash
set -eu
spec=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--spec-file" ]; then spec="$2"; shift 2; else shift; fi
done
[ -f "$spec" ] || { echo "SPEC-MISSING:$PWD/$spec" >&2; exit 44; }
mkdir -p RPMS
printf 'cwd-bound rpm bytes\n' > RPMS/iris-xr-cwd-test.rpm
echo "SPEC-OK:$PWD/$spec"
STUB
  chmod +x "$APPMGR_DIR/appmgr_build" "$APPMGR_DIR/build_rpm.sh"

  _run_real_default

  [ "$status" -eq 0 ]
  [[ "$output" == *"APP-MGR-CWD="*" ROOT="* ]]
  [[ "$output" != *"APP-MGR-CWD-MISMATCH"* ]]
  [[ "$output" == *"SPEC-OK:"*"/build/specs/iris-xr.spec"* ]]
  [ "$(cat "$OUT_DIR/iris-xr.rpm")" = "cwd-bound rpm bytes" ]
}

@test "behavior: pinned appmgr failure prints its private detailed RPM log" {
  _xr_stub_setup
  cat > "$APPMGR_DIR/appmgr_build" <<'STUB'
#!/usr/bin/env python3
from pathlib import Path
import subprocess

def main():
    root = Path(__file__).resolve().parent
    spec = root / "build" / "specs" / "iris-xr.spec"
    spec.parent.mkdir(parents=True, exist_ok=True)
    spec.write_text("test spec\n")
    command = [
        "./build_rpm.sh",
        "--spec-file", "./build/specs/iris-xr.spec",
        "--source-dir", "build/archives/SOURCES",
        "--rpm-dir", "build/archives/RPMS",
        "--output-dir", "RPMS",
        "--verbose",
    ]
    subprocess.run(command)
    print("Done building package iris-xr")

main()
STUB
  cat > "$APPMGR_DIR/build_rpm.sh" <<'STUB'
#!/usr/bin/env bash
set -eu
log=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--log-file" ]; then log="$2"; shift 2; else shift; fi
done
printf 'RPBUILD-DETAIL: expected synthetic failure\n' > "$log"
exit 1
STUB
  chmod +x "$APPMGR_DIR/appmgr_build" "$APPMGR_DIR/build_rpm.sh"

  _run_real_default

  [ "$status" -ne 0 ]
  [[ "$output" == *"did not produce an RPM"* ]]
  [[ "$output" == *"RPBUILD-DETAIL: expected synthetic failure"* ]]
  [ ! -e "$OUT_DIR/iris-xr.rpm" ]
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
  rm -rf "$APPMGR_DIR/release_configs"
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

_finalized_xr_setup() {
  _xr_stub_setup
  ln -s "$BATS_TEST_DIRNAME/../../../tools/prepare-device-context.py" "$STUBDIR/tools/prepare-device-context.py"
  ln -s "$BATS_TEST_DIRNAME/../../../tools/iris_installer" "$STUBDIR/tools/iris_installer"
  FINALIZED="$BATS_TEST_TMPDIR/finalized"
  mkdir -p "$FINALIZED"
  export FORBIDDEN_LOG="$BATS_TEST_TMPDIR/forbidden.log" TOOL_LOG="$BATS_TEST_TMPDIR/tool.log"
  for path in "$STUBDIR/tools/build-device-image.sh" "$STUBDIR/bin/git" "$STUBDIR/bin/docker" "$STUBDIR/bin/curl"; do
    printf '#!/bin/sh\necho forbidden >> "$FORBIDDEN_LOG"\nexit 99\n' > "$path"
    chmod +x "$path"
  done
  cat > "$APPMGR_DIR/appmgr_build" <<'PY'
#!/usr/bin/env python3
from pathlib import Path
import os
import subprocess
import yaml

def main():
    command = [
        "./build_rpm.sh",
        "--output-dir", "RPMS",
        "--verbose",
    ]
    root = Path(__file__).resolve().parent
    assert Path.cwd() == root
    assert root != Path(os.environ["ORIGINAL_APPMGR_DIR"])
    assert Path("release_configs/ThinXR_7.3.15.yaml").is_file()
    config = yaml.safe_load(Path("build.yaml").read_text())
    assert config["packages"][0]["copy_hostname"] is False
    Path(os.environ["TOOL_LOG"]).write_text(str(root))
    subprocess.run(command, check=True)

main()
PY
  printf '#!/bin/sh\nmkdir -p RPMS\nprintf "finalized rpm" > RPMS/iris-xr.rpm\n' > "$APPMGR_DIR/build_rpm.sh"
  printf 'release: test\n' > "$APPMGR_DIR/release_configs/ThinXR_7.3.15.yaml"
  chmod +x "$APPMGR_DIR/appmgr_build" "$APPMGR_DIR/build_rpm.sh"
  APPMGR_ARCHIVE="$BATS_TEST_TMPDIR/appmgr.tar.gz"
  python3 - "$STUBDIR/tools" "$FINALIZED" "$APPMGR_DIR" "$APPMGR_ARCHIVE" <<'PY'
from pathlib import Path
import gzip, hashlib, io, json, sys, tarfile
sys.path.insert(0, sys.argv[1])
from iris_installer.device_finalize import TRUST
directory, tool, output = map(Path, sys.argv[2:])
archive = b'finalized canonical OCI fixture'
(directory / 'iris-device.oci.tar').write_bytes(archive)
sha, descriptor = 'a' * 64, 'sha256:' + 'b' * 64
platform = dict.fromkeys(('base_manifest_digest', 'manifest_digest', 'config_digest', 'layer_digest', 'diff_id'), descriptor)
platform.update(runtime_inventory_sha256=sha, runtime_members=1)
receipt = dict(format='iris-device-finalized-v1', base_archive_sha256=sha,
    neutral_source_sha256=sha, base_index_digest=descriptor, finalizer_source_commit='c' * 40,
    finalizer_module_sha256=sha, trust_renderer_sha256=sha,
    root_files_sha256={'a.pub': sha, 'b.pub': sha}, trust_files_sha256=dict.fromkeys(TRUST, sha),
    archive_sha256=hashlib.sha256(archive).hexdigest(), archive_size=len(archive), index_digest=descriptor,
    platforms={'amd64': platform, 'arm64': platform})
(directory / 'iris-device.oci.tar.finalization.json').write_text(json.dumps(receipt))
metadata = dict(format='iris-appmgr-source-v1', source_repository='https://github.com/ios-xr/xr-appmgr-build.git',
                source_revision='37d79607a32a129107819f08fb3a74187efd2d47')
(tool / 'iris-appmgr-source.json').write_text(json.dumps(metadata))
with tarfile.open(output, 'w:gz') as packed:
    for name in ('appmgr_build', 'build_rpm.sh', 'release_configs', 'iris-appmgr-source.json'):
        packed.add(tool / name, arcname=name)
PY
  FINAL_SHA="$(sha256sum "$FINALIZED/iris-device.oci.tar.finalization.json" | cut -d' ' -f1)"
  APPMGR_SHA="$(sha256sum "$APPMGR_ARCHIVE" | cut -d' ' -f1)"
  APPMGR_REVISION=37d79607a32a129107819f08fb3a74187efd2d47
}

_run_finalized_xr() {
  run env -u IRIS_INSTRUCTION_ROOTS_DIR -u APPMGR_BUILD_CMD \
    PATH="$STUBDIR/bin:$PATH" ORIGINAL_APPMGR_DIR="$APPMGR_DIR" \
    APPMGR_BUILD_DIR="$APPMGR_DIR" bash "$STUBDIR/tools/build-xr-package.sh" \
    --finalized-dir "$FINALIZED" --finalization-sha256 "$FINAL_SHA" \
    --appmgr-archive "$APPMGR_ARCHIVE" --appmgr-sha256 "$APPMGR_SHA" \
    --appmgr-revision "$APPMGR_REVISION" --out "$OUT_DIR" "$@"
}

@test "finalized XR builds only its wrapper from private pinned inputs and publishes exact v2" {
  _finalized_xr_setup
  before="$(sha256sum "$APPMGR_DIR/appmgr_build" | cut -d' ' -f1)"
  _run_finalized_xr
  [ "$status" -eq 0 ]
  [ "$(cat "$OUT_DIR/iris-xr.rpm")" = "finalized rpm" ]
  manifest="$OUT_DIR/iris-xr.rpm.manifest"
  [ "$(wc -l < "$manifest")" -eq 9 ]
  grep -qx 'format=iris-device-wrapper-v2' "$manifest"
  grep -qx "canonical_finalization_sha256=$FINAL_SHA" "$manifest"
  grep -qx "canonical_neutral_source_sha256=$(printf '%064d' 0 | tr 0 a)" "$manifest"
  ! grep -q '^canonical_source_sha256=' "$manifest"
  [ "$(sha256sum "$APPMGR_DIR/appmgr_build" | cut -d' ' -f1)" = "$before" ]
  [ -s "$TOOL_LOG" ]
  [ ! -e "$APPMGR_DIR/RPMS" ]
  [ ! -e "$APPMGR_DIR/build.yaml" ]
  [ ! -e "$FORBIDDEN_LOG" ]
}

@test "finalized XR refuses changed receipt archive or revision before tool execution" {
  _finalized_xr_setup
  FINAL_SHA="$(printf '%064d' 0)" _run_finalized_xr
  [ "$status" -ne 0 ]
  [[ "$output" == *"receipt differs"* ]]
  APPMGR_SHA="$(printf '%064d' 0)" _run_finalized_xr
  [ "$status" -ne 0 ]
  [[ "$output" == *"appmgr archive differs"* ]]
  APPMGR_REVISION="$(printf '%040d' 0)" _run_finalized_xr
  [ "$status" -ne 0 ]
  [[ "$output" == *"source metadata differs"* ]]
  [ ! -e "$TOOL_LOG" ]
  [ ! -e "$FORBIDDEN_LOG" ]
  [ ! -e "$OUT_DIR/iris-xr.rpm" ]
}

@test "finalized XR needs no home directory or source-builder cache" {
  _finalized_xr_setup
  run env -u HOME -u XDG_CACHE_HOME -u APPMGR_BUILD_DIR \
    -u IRIS_INSTRUCTION_ROOTS_DIR -u APPMGR_BUILD_CMD \
    PATH="$STUBDIR/bin:$PATH" ORIGINAL_APPMGR_DIR="$APPMGR_DIR" \
    bash "$STUBDIR/tools/build-xr-package.sh" \
    --finalized-dir "$FINALIZED" --finalization-sha256 "$FINAL_SHA" \
    --appmgr-archive "$APPMGR_ARCHIVE" --appmgr-sha256 "$APPMGR_SHA" \
    --appmgr-revision "$APPMGR_REVISION" --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ "$(cat "$OUT_DIR/iris-xr.rpm")" = "finalized rpm" ]
  [ ! -e "$FORBIDDEN_LOG" ]
}

@test "finalized XR preflights isolated Python YAML without installing dependencies" {
  _finalized_xr_setup
  cat > "$STUBDIR/bin/python3" <<'PY'
#!/bin/sh
echo "NO-YAML: $*" >&2
exit 7
PY
  chmod +x "$STUBDIR/bin/python3"
  _run_finalized_xr
  [ "$status" -ne 0 ]
  [[ "$output" == *"NO-YAML: -I -c import yaml"* ]]
  [[ "$output" == *"requires local Python YAML support"* ]]
  [ ! -e "$OUT_DIR" ]
  [ ! -e "$TOOL_LOG" ]
  [ ! -e "$FORBIDDEN_LOG" ]
}

@test "finalized XR requires paired hashes and refuses arbitrary appmgr commands" {
  _finalized_xr_setup
  run bash "$STUBDIR/tools/build-xr-package.sh" --finalized-dir "$FINALIZED"
  [ "$status" -eq 2 ]
  run env APPMGR_BUILD_CMD='./appmgr_build' bash "$STUBDIR/tools/build-xr-package.sh" \
    --finalized-dir "$FINALIZED" --finalization-sha256 "$FINAL_SHA" \
    --appmgr-archive "$APPMGR_ARCHIVE" --appmgr-sha256 "$APPMGR_SHA" \
    --appmgr-revision "$APPMGR_REVISION"
  [ "$status" -eq 2 ]
  [[ "$output" == *"unpinned appmgr command"* ]]
  [ ! -e "$FORBIDDEN_LOG" ]
}
