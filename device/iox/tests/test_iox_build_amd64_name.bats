#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# build.sh: --amd64 is accepted and defaults the package name to iris-amd64.tar
# (naming-collision fix, gap #4). We do not run a full docker build here — we
# verify the flag is parsed and the amd64 default name is wired.

setup() { BUILD="$BATS_TEST_DIRNAME/../build.sh"; }

@test "build.sh --help lists the --amd64 flag" {
  run bash "$BUILD" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--amd64"* ]]
}

@test "build.sh has no syntax errors" {
  run bash -n "$BUILD"
  [ "$status" -eq 0 ]
}

@test "amd64 arm defaults PACKAGE_NAME to iris-amd64.tar" {
  run grep -F "DEFAULT_PACKAGE_NAME=iris-amd64.tar" "$BUILD"
  [ "$status" -eq 0 ]
}

@test "arm64 defaults PACKAGE_NAME to iris-arm64.tar" {
  run grep -F "DEFAULT_PACKAGE_NAME=iris-arm64.tar" "$BUILD"
  [ "$status" -eq 0 ]
}

@test "rejects an unknown option" {
  run bash "$BUILD" --nope
  [ "$status" -eq 2 ]
}

# CAF-compatible packaging: engines on the containerd image store make
# `docker save` (and `ioxclient docker package`) emit OCI-layout archives with
# buildx attestation manifests; IE3x00 CAF (dockerd 19.03) then installs and
# activates the app but refuses to start it. build.sh must export a classic
# docker-archive rootfs.tar itself and package the directory.

@test "build.sh exports rootfs.tar via skopeo docker-archive" {
  run grep -F -- 'skopeo copy --override-os linux --override-arch "$IOX_ARCH"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F -- '"oci-archive:$OCI_ARCHIVE"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F -- '"docker-archive:$CTX/rootfs.tar:iris-device:$IOX_ARCH"' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh requires skopeo with an actionable message" {
  run grep -F 'skopeo is required' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh rejects OCI-index rootfs archives" {
  run grep -F 'tar tf "$CTX/rootfs.tar" | grep -qx index.json' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh fails closed on attestation manifests in rootfs.tar" {
  run grep -F 'attestation-manifest' "$BUILD"
  [ "$status" -eq 0 ]
}

@test "build.sh packages the staged directory, not a daemon-side save" {
  run grep -F '"$IOXCLIENT" package --skip-signing .' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F '"$IOXCLIENT" docker package' "$BUILD"
  [ "$status" -ne 0 ]
}

@test "build.sh packages only the descriptor and deployment-neutral rootfs" {
  # `ioxclient package` tars its whole working directory into artifacts.tar.gz.
  # Packaging the build context shipped a second aria2c, the agent sources and
  # the Dockerfile as ~3.3 MB of dead weight in every IOx tar (measured
  # 2026-09-02), so the packaging step runs in a directory that holds exactly
  # package.yaml + rootfs.tar. Deployment trust is supplied at runtime.
  run grep -F 'mv "$CTX/rootfs.tar" "$PKG/rootfs.tar"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F 'cp "$PACKAGE_DESCRIPTOR" "$PKG/package.yaml"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F 'iris-catalog.pem' "$BUILD"
  [ "$status" -ne 0 ]
  run grep -F '( cd "$PKG" && HOME="$IOX_HOME" "$IOXCLIENT" package --skip-signing . )' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F '( cd "$CTX" && "$IOXCLIENT" package . )' "$BUILD"
  [ "$status" -ne 0 ]
}

@test "build.sh packages with its own inert ioxclient profile, not the operator's" {
  # ioxclient refuses every command until a config exists in HOME and creates
  # one interactively, so a scripted run dies at its password prompt on a host
  # where nobody made a profile by hand. Packaging is offline, so the build
  # supplies a scratch HOME holding a placeholder profile -- which also keeps an
  # operator profile, and any real device credential in it, out of the run.
  run grep -F 'IOX_HOME="${IOXCLIENT_HOME:-}"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F 'IOX_HOME="$CTX/ioxclient-home"' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F 'auth_passwd: placeholder' "$BUILD"
  [ "$status" -eq 0 ]
  run grep -F 'host_ip: 127.0.0.1' "$BUILD"
  [ "$status" -eq 0 ]
  # The scratch home lives in the build context, which is removed on exit.
  run grep -F 'trap ' "$BUILD"
  [ "$status" -eq 0 ]
}

_iox_stub_setup() {
  STUB="$BATS_TEST_TMPDIR/stub"
  BIN="$BATS_TEST_TMPDIR/bin"
  OUT="$BATS_TEST_TMPDIR/out"
  mkdir -p "$STUB/device/iox" "$STUB/tools" "$BIN" "$OUT"
  ln -s "$BUILD" "$STUB/device/iox/build.sh"
  ln -s "$BATS_TEST_DIRNAME/../package_manifest.py" "$STUB/device/iox/package_manifest.py"
  printf 'descriptor\n' > "$STUB/device/iox/package.yaml"
  printf 'descriptor\n' > "$STUB/device/iox/package-amd64.yaml"
  printf '0.0.0-test\n' > "$STUB/VERSION"
  cat > "$STUB/tools/build-device-image.sh" <<'STUB_COMMON'
#!/usr/bin/env bash
set -eu
ctx=""
while [ $# -gt 0 ]; do
  case "$1" in --context) ctx="$2"; shift 2 ;; *) shift ;; esac
done
archive="$TEST_ROOT/canonical.oci.tar"
printf 'oci\n' > "$archive"
printf '%s\n' "$archive" > "$ctx/iris-device-oci-path"
cat > "$ctx/iris-device-oci.manifest" <<EOF
format=iris-device-oci-v1
source_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
index_digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
archive_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
platforms=linux/amd64,linux/arm64
EOF
STUB_COMMON
  cat > "$BIN/skopeo" <<'STUB_SKOPEO'
#!/usr/bin/env bash
if [ -n "${SELECTION_LOG:-}" ]; then
  for arg in "$@"; do
    case "$arg" in oci-archive:*)
      source="${arg#oci-archive:}"
      printf '%s %s %s\n' "$source" "$(stat -c %a "$source")" "$(sha256sum "$source" | cut -d' ' -f1)" >> "$SELECTION_LOG"
      ;;
    esac
  done
fi
for arg in "$@"; do case "$arg" in docker-archive:*) out="${arg#docker-archive:}"; out="${out%%:*}" ;; esac; done
d="$(mktemp -d)"
printf '[{"Config":"config.json","RepoTags":["iris-device:test"],"Layers":[]}]\n' > "$d/manifest.json"
tar cf "$out" -C "$d" manifest.json
rm -rf "$d"
STUB_SKOPEO
  cat > "$BIN/ioxclient" <<'STUB_IOX'
#!/usr/bin/env bash
[ -z "${TOOL_LOG:-}" ] || printf '%s\n' "$0" >> "$TOOL_LOG"
python3 - <<'PY'
import hashlib, io, tarfile
payloads = {'package.yaml': b'descriptor\n', 'artifacts.tar.gz': b'unchanged image'}
payloads['package.mf'] = ''.join(
    'SHA256(%s)= %s\n' % (name, hashlib.sha256(data).hexdigest())
    for name, data in payloads.items()).encode()
with tarfile.open('package.tar', 'w') as archive:
    for name, data in payloads.items():
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
PY
STUB_IOX
  chmod +x "$STUB/tools/build-device-image.sh" "$BIN/skopeo" "$BIN/ioxclient"
}

@test "IOx wrapper atomically publishes provenance bound to the canonical OCI" {
  _iox_stub_setup
  for arch in arm64 amd64; do
  run env PATH="$BIN:$PATH" TEST_ROOT="$BATS_TEST_TMPDIR" \
    bash "$STUB/device/iox/build.sh" "--$arch" "$OUT"
  [ "$status" -eq 0 ]
  [ -f "$OUT/iris-$arch.tar" ]
  manifest="$OUT/iris-$arch.tar.manifest"
  [ -f "$manifest" ]
  grep -q '^wrapper_kind=iox$' "$manifest"
  grep -q "^platform=linux/$arch$" "$manifest"
  grep -q '^canonical_index_digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb$' "$manifest"
  grep -q '^canonical_archive_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc$' "$manifest"
  grep -q '^canonical_source_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$' "$manifest"
  grep -q "^wrapper_sha256=$(sha256sum "$OUT/iris-$arch.tar" | awk '{print $1}')$" "$manifest"
  run python3 "$STUB/device/iox/package_manifest.py" "$OUT/iris-$arch.tar"
  [ "$status" -eq 0 ]
  ! find "$OUT" -maxdepth 1 -name ".iris-$arch.tar.*" | grep -q .
  done
}

_finalized_iox_setup() {
  _iox_stub_setup
  ln -s "$BATS_TEST_DIRNAME/../../../tools/prepare-device-context.py" "$STUB/tools/prepare-device-context.py"
  ln -s "$BATS_TEST_DIRNAME/../../../tools/iris_installer" "$STUB/tools/iris_installer"
  FINALIZED="$BATS_TEST_TMPDIR/finalized"
  mkdir -p "$FINALIZED"
  python3 - "$STUB/tools" "$FINALIZED" <<'PY'
from pathlib import Path
import hashlib, json, sys
sys.path.insert(0, sys.argv[1])
from iris_installer.device_finalize import TRUST
directory = Path(sys.argv[2])
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
PY
  FINAL_SHA="$(sha256sum "$FINALIZED/iris-device.oci.tar.finalization.json" | cut -d' ' -f1)"
  TOOL_SHA="$(sha256sum "$BIN/ioxclient" | cut -d' ' -f1)"
  export SELECTION_LOG="$BATS_TEST_TMPDIR/selection.log" TOOL_LOG="$BATS_TEST_TMPDIR/tool.log"
  export FORBIDDEN_LOG="$BATS_TEST_TMPDIR/forbidden.log"
  for path in "$STUB/tools/build-device-image.sh" "$STUB/tools/get-ioxclient.sh" \
      "$BIN/docker" "$BIN/curl" "$BIN/git"; do
    printf '#!/bin/sh\necho forbidden >> "$FORBIDDEN_LOG"\nexit 99\n' > "$path"
    chmod +x "$path"
  done
}

_run_finalized_iox() {
  run env -u IRIS_INSTRUCTION_ROOTS_DIR -u IOXCLIENT_HOME PATH="$BIN:$PATH" IOXCLIENT="$BIN/ioxclient" \
    bash "$STUB/device/iox/build.sh" --arm64 --finalized-dir "$FINALIZED" \
    --finalization-sha256 "$FINAL_SHA" --ioxclient-sha256 "$TOOL_SHA" "$@" "$OUT"
}

@test "finalized IOx wraps a verified private snapshot with exact v2 provenance and no source build" {
  _finalized_iox_setup
  _run_finalized_iox
  [ "$status" -eq 0 ]
  manifest="$OUT/iris-arm64.tar.manifest"
  [ "$(wc -l < "$manifest")" -eq 9 ]
  grep -qx 'format=iris-device-wrapper-v2' "$manifest"
  grep -qx "canonical_finalization_sha256=$FINAL_SHA" "$manifest"
  grep -qx "canonical_neutral_source_sha256=$(printf '%064d' 0 | tr 0 a)" "$manifest"
  grep -qx "canonical_archive_sha256=$(sha256sum "$FINALIZED/iris-device.oci.tar" | cut -d' ' -f1)" "$manifest"
  ! grep -q '^canonical_source_sha256=' "$manifest"
  grep -q '/finalized/iris-device.oci.tar 444 ' "$SELECTION_LOG"
  grep -q '/iox-tool/ioxclient$' "$TOOL_LOG"
  [ ! -e "$FORBIDDEN_LOG" ]
}

@test "finalized IOx refuses altered receipt or local tool before executing packaging" {
  _finalized_iox_setup
  FINAL_SHA="$(printf '%064d' 0)" _run_finalized_iox
  [ "$status" -ne 0 ]
  [[ "$output" == *"receipt differs"* ]]
  TOOL_SHA="$(printf '%064d' 0)" _run_finalized_iox
  [ "$status" -ne 0 ]
  [[ "$output" == *"ioxclient differs"* ]]
  [ ! -e "$TOOL_LOG" ]
  [ ! -e "$SELECTION_LOG" ]
  [ ! -e "$FORBIDDEN_LOG" ]
  [ ! -e "$OUT/iris-arm64.tar" ]
}

@test "finalized IOx requires paired inputs and rejects source trust overrides" {
  _finalized_iox_setup
  run bash "$STUB/device/iox/build.sh" --finalized-dir "$FINALIZED" "$OUT"
  [ "$status" -eq 2 ]
  _run_finalized_iox --instruction-roots-dir "$BATS_TEST_TMPDIR/roots"
  [ "$status" -eq 2 ]
  [[ "$output" == *"cannot use instruction roots"* ]]
  [ ! -e "$FORBIDDEN_LOG" ]
}
