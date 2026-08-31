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
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 \
    ARTIFACTS_DIR="$ARTIFACTS" run bash "$CHECK"

  [[ "$output" == *"iris-xr.rpm        absent"* ]] || return 1
  [[ "$output" == *"no XR RPM is staged"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "XR RPM built after the live certificate is OK by mtime, contents not inspected" {
  : > "$ARTIFACTS/iris-xr.rpm"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 ARTIFACTS_DIR="$ARTIFACTS" \
    FAKE_CERT_EPOCH=0 run bash "$CHECK"

  [[ "$output" == *"OK-BY-MTIME (built after the current certificate; contents not inspected)"* ]] || return 1
  [[ "$output" == *"verified: the XR RPM was built after that certificate -- by build time only, contents not inspected."* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "XR RPM built before the live certificate is stale by mtime, with the build-xr-package remedy" {
  : > "$ARTIFACTS/iris-xr.rpm"
  # a cert mtime far in the future guarantees the RPM (just created) reads
  # as built BEFORE it, regardless of the exact instant this test runs.
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 ARTIFACTS_DIR="$ARTIFACTS" \
    FAKE_CERT_EPOCH=4102444800 run bash "$CHECK"

  [[ "$output" == *"STALE-BY-MTIME (built before the current certificate; contents not inspected)"* ]] || return 1
  [[ "$output" == *"STALE (by mtime): iris-xr.rpm"* ]] || return 1
  [[ "$output" == *"Fix: tools/build-xr-package.sh --out artifacts/"* ]] || return 1
  [ "$status" -eq 1 ]
}

@test "XR RPM freshness never overclaims: the summary names tars and the RPM separately" {
  : > "$ARTIFACTS/iris-xr.rpm"
  PATH="$STUB:$PATH" CATALOG_HOSTPORT=127.0.0.1:8443 ARTIFACTS_DIR="$ARTIFACTS" \
    FAKE_CERT_EPOCH=0 run bash "$CHECK"

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
