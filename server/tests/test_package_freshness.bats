#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  CHECK="$BATS_TEST_DIRNAME/../../tools/check-package-freshness.sh"
  STUB="$BATS_TEST_TMPDIR/bin"
  ARTIFACTS="$BATS_TEST_TMPDIR/artifacts"
  mkdir -p "$STUB" "$ARTIFACTS"

  cat > "$STUB/openssl" <<'STUB'
#!/usr/bin/env bash
# notBefore is the certificate's own creation time -- the honest baseline for
# XR RPM freshness, since the pem file's mtime only tracks the last time the
# copy was staged. Default is far in the past so the common case is "the RPM
# was built after the cert existed".
for a in "$@"; do
  if [ "$a" = -startdate ]; then
    printf 'notBefore=%s\n' "${FAKE_CERT_NOTBEFORE:-Jan  1 00:00:00 2020 GMT}"
    exit 0
  fi
done
if [ "$1" = s_client ]; then
  printf 'served\n'
elif [ "${2:-}" = -outform ]; then
  cat
else
  case "$(cat "${3:?missing certificate path}")" in
    *served*) fp=SERVED ;;
    *distributed*) fp=DISTRIBUTED ;;
    *) fp=PACKAGE ;;
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
  exec) printf '%s' "${FAKE_CERT_EPOCH:-}" ;;
  *) exit 1 ;;
esac
STUB
  chmod +x "$STUB/docker"
}

@test "served and distributed certificate mismatch is failing drift" {
  PATH="$STUB:$PATH" FAKE_DISTRIBUTED_CERT=distributed \
    CATALOG_HOSTPORT=127.0.0.1:8443 ARTIFACTS_DIR="$ARTIFACTS" \
    run bash "$CHECK" --rebuild

  [[ "$output" == *"MISMATCH"* ]] || return 1
  [[ "$output" == *"Package rebuilding cannot repair"* ]] || return 1
  [[ "$output" != *">> rebuilding all IOx packages"* ]] || return 1
  [ "$status" -eq 1 ]
}

@test "present package without a pinned certificate is stale" {
  : > "$ARTIFACTS/iris-amd64.tar"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 \
    ARTIFACTS_DIR="$ARTIFACTS" run bash "$CHECK"

  [[ "$output" == *"NO PINNED CERT FOUND"* ]] || return 1
  [[ "$output" == *"STALE: iris-amd64.tar"* ]] || return 1
  [ "$status" -eq 1 ]
}

# ---------------------------------------------------------------------------
# XR RPM row (server/setup_status.py's _xr_package_item honesty model,
# mirrored here): no unpacker for the RPM's own shape, so it is never said
# to "pin" a certificate the way the tar rows are -- only its build time is
# compared against the live catalog certificate's own mtime, and every
# printed state says plainly that contents were not inspected.
# ---------------------------------------------------------------------------

@test "absent XR RPM is a neutral row, not a failure" {
  # Both IOx tars are staged so this run is about the XR RPM: an absent
  # tar is no longer swept into the verified summary (it inspects
  # nothing), which would otherwise mask what this test asserts.
  _make_built_package "$ARTIFACTS/iris-amd64.tar" "served" "served"
  _make_built_package "$ARTIFACTS/iris-arm64.tar" "served" "served"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 \
    ARTIFACTS_DIR="$ARTIFACTS" run bash "$CHECK"

  [[ "$output" == *"iris-xr.rpm        absent"* ]] || return 1
  [[ "$output" == *"no XR RPM is staged"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "XR RPM built after the live certificate is OK by mtime, contents not inspected" {
  # Both IOx tars are staged so this run is about the XR RPM: an absent
  # tar is no longer swept into the verified summary (it inspects
  # nothing), which would otherwise mask what this test asserts.
  _make_built_package "$ARTIFACTS/iris-amd64.tar" "served" "served"
  _make_built_package "$ARTIFACTS/iris-arm64.tar" "served" "served"
  : > "$ARTIFACTS/iris-xr.rpm"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 ARTIFACTS_DIR="$ARTIFACTS" \
    FAKE_CERT_NOTBEFORE="Jan  1 00:00:00 2020 GMT" run bash "$CHECK"

  [[ "$output" == *"OK-BY-MTIME (built after the certificate was created; contents not inspected)"* ]] || return 1
  [[ "$output" == *"verified: the XR RPM was built after that certificate -- by build time only, contents not inspected."* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "XR RPM built before the live certificate is stale by mtime, with the build-xr-package remedy" {
  : > "$ARTIFACTS/iris-xr.rpm"
  # a cert CREATED far in the future guarantees the RPM (just created) reads
  # as built BEFORE it, regardless of the exact instant this test runs.
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 ARTIFACTS_DIR="$ARTIFACTS" \
    FAKE_CERT_NOTBEFORE="Jan  1 00:00:00 2035 GMT" run bash "$CHECK"

  [[ "$output" == *"STALE-BY-MTIME (built before the certificate was created; contents not inspected)"* ]] || return 1
  [[ "$output" == *"STALE (by mtime): iris-xr.rpm"* ]] || return 1
  [[ "$output" == *"Fix: tools/build-xr-package.sh --out artifacts/"* ]] || return 1
  [ "$status" -eq 1 ]
}

# The false positive reported by the operator on 2026-08-31. The certificate was
# created long BEFORE this RPM was built, so the RPM is provably good -- but
# /srv/artifacts/iris-catalog.pem is a STAGED COPY that a later bring-up
# re-wrote, putting its mtime after the RPM's. Baselining on that mtime reported
# "Needs rebuild" for an RPM built eleven minutes AFTER the very certificate it
# was accused of predating. Only the certificate's own notBefore is immune: no
# re-copy can move it.
@test "a re-staged catalog pem does not make a good XR RPM look stale" {
  # Both IOx tars are staged so this run is about the XR RPM: an absent
  # tar is no longer swept into the verified summary (it inspects
  # nothing), which would otherwise mask what this test asserts.
  _make_built_package "$ARTIFACTS/iris-amd64.tar" "served" "served"
  _make_built_package "$ARTIFACTS/iris-arm64.tar" "served" "served"
  : > "$ARTIFACTS/iris-xr.rpm"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 ARTIFACTS_DIR="$ARTIFACTS" \
    FAKE_CERT_EPOCH=4102444800 FAKE_CERT_NOTBEFORE="Jan  1 00:00:00 2020 GMT" \
    run bash "$CHECK"

  [[ "$output" == *"OK-BY-MTIME"* ]] || return 1
  [[ "$output" != *"STALE-BY-MTIME"* ]] || return 1
  [[ "$output" != *"Needs rebuild"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "XR RPM freshness never overclaims: the summary names tars and the RPM separately" {
  # Both IOx tars are staged so this run is about the XR RPM: an absent
  # tar is no longer swept into the verified summary (it inspects
  # nothing), which would otherwise mask what this test asserts.
  _make_built_package "$ARTIFACTS/iris-amd64.tar" "served" "served"
  _make_built_package "$ARTIFACTS/iris-arm64.tar" "served" "served"
  : > "$ARTIFACTS/iris-xr.rpm"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 ARTIFACTS_DIR="$ARTIFACTS" \
    FAKE_CERT_NOTBEFORE="Jan  1 00:00:00 2020 GMT" run bash "$CHECK"

  # the old blanket claim ("all served packages pin the live catalog
  # certificate") must be gone -- an RPM checked by mtime only was never
  # verified to PIN anything, and the new summary must not say it was.
  if printf '%s\n' "$output" | grep -q 'all served packages pin the live catalog certificate'; then
    return 1
  fi
  [[ "$output" == *"IOx tars pin the live catalog certificate"* ]] || return 1
  [[ "$output" == *"by build time only, contents not inspected"* ]] || return 1
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# IOx package layouts as device/iox/build.sh REALLY produces them (review
# finding IRIS-12-001): artifacts.tar.gz holds package.yaml + a classic
# docker-archive rootfs.tar with the cert baked in a layer, and -- since the
# probe member's restoration -- a top-level iris-catalog.pem next to them.
# The "present package without a pinned certificate" case above uses an
# empty file; these use the real shapes.
# ---------------------------------------------------------------------------

# $1 = output path, $2 = pem text baked in the layer, $3 = probe-member pem
# text ("" = no probe member, the 2026-09-02..restoration build shape)
_make_built_package() {
  python3 - "$1" "$2" "$3" <<'PY'
import hashlib, io, json, sys, tarfile
out, baked, probe = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
def tar_bytes(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        for n, d in members:
            ti = tarfile.TarInfo(n); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
    return b.getvalue()
sha = lambda b: hashlib.sha256(b).hexdigest()
base = tar_bytes([("etc/os-release", b"ID=debian\n")])
top = tar_bytes([("opt/iris/iris-catalog.pem", baked)])
cfg = json.dumps({"rootfs": {"diff_ids": ["sha256:" + sha(base), "sha256:" + sha(top)]}}).encode()
manifest = json.dumps([{"Config": sha(cfg) + ".json", "RepoTags": ["iris-iox:arm64"],
                        "Layers": [sha(base) + ".tar", sha(top) + ".tar"]}]).encode()
rb = io.BytesIO()
with tarfile.open(fileobj=rb, mode="w") as t:
    for n, d in [("manifest.json", manifest), ("repositories", b"{}"), (sha(cfg) + ".json", cfg),
                 (sha(base) + ".tar", base), (sha(top) + ".tar", top)]:
        ti = tarfile.TarInfo(n); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
    for dig in (sha(base), sha(top)):
        ti = tarfile.TarInfo("legacy-" + dig[:12] + "/layer.tar"); ti.type = tarfile.SYMTYPE
        ti.linkname = "../" + dig + ".tar"; t.addfile(ti)
rootfs = rb.getvalue()
members = [("package.yaml", b"descriptor-schema-version: '2.8'\n"), ("rootfs.tar", rootfs)]
if probe:
    members.append(("iris-catalog.pem", probe))
ab = io.BytesIO()
with tarfile.open(fileobj=ab, mode="w:gz") as t:
    for n, d in members:
        ti = tarfile.TarInfo(n); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
art = ab.getvalue()
with tarfile.open(out, "w") as t:
    for n, d in [("package.yaml", b"descriptor-schema-version: '2.8'\n"), ("artifacts.tar.gz", art)]:
        ti = tarfile.TarInfo(n); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
PY
}

@test "a package carrying build.sh's top-level probe member pinning the live cert is OK" {
  # Both tars are staged because the summary this asserts says "both IOx
  # tars": with only one present the claim was true of nothing, which is the
  # absent-is-not-verified defect this file now also covers below.
  _make_built_package "$ARTIFACTS/iris-amd64.tar" "served" "served"
  _make_built_package "$ARTIFACTS/iris-arm64.tar" "served" "served"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 \
    ARTIFACTS_DIR="$ARTIFACTS" run bash "$CHECK"

  [[ "$output" == *"iris-arm64.tar"*"OK"* ]] || return 1
  [[ "$output" != *"NO PINNED CERT FOUND"* ]] || return 1
  [[ "$output" == *"verified: both IOx tars pin the live catalog certificate"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "a package built without the probe member is read from its layer, not reported as unpinned" {
  # the 2026-09-02..restoration build shape: cert only inside rootfs.tar's
  # layer. It used to print NO PINNED CERT FOUND -> STALE on every fresh
  # build, and --rebuild could never converge.
  # amd64 staged normally so the run is about the layer fallback, not about a
  # missing package (an absent tar is now correctly not "verified").
  _make_built_package "$ARTIFACTS/iris-amd64.tar" "served" "served"
  _make_built_package "$ARTIFACTS/iris-arm64.tar" "served" ""
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 \
    ARTIFACTS_DIR="$ARTIFACTS" run bash "$CHECK"

  [[ "$output" != *"NO PINNED CERT FOUND"* ]] || return 1
  [[ "$output" == *"iris-arm64.tar"*"OK"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "a package whose probe member pins a different cert is STALE with the pinned fingerprint named" {
  _make_built_package "$ARTIFACTS/iris-arm64.tar" "rotated-away" "rotated-away"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 \
    ARTIFACTS_DIR="$ARTIFACTS" run bash "$CHECK"

  [[ "$output" == *"STALE -> pins PACKAGE"* ]] || return 1
  [[ "$output" == *"STALE: iris-arm64.tar"* ]] || return 1
  [ "$status" -eq 1 ]
}

@test "an absent IOx package is never reported as verified" {
  # A missing package was not added to STALE, so a run with neither tar staged
  # printed "verified: both IOx tars pin the live catalog certificate (contents
  # inspected)" and exited 0 having inspected nothing -- a green answer that
  # means the opposite of what it says, on the check an operator runs before a
  # rollout. ARTIFACTS here is empty of tars.
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 ARTIFACTS_DIR="$ARTIFACTS" \
    run bash "$CHECK"

  [[ "$output" == *"NOT STAGED"* ]] || return 1
  [[ "$output" == *"iris-amd64.tar"* ]] || return 1
  [[ "$output" == *"iris-arm64.tar"* ]] || return 1
  [[ "$output" != *"verified: both IOx tars"* ]] || return 1
  [ "$status" -eq 1 ]
}
