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
