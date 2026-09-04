#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# tools/get-ioxclient.sh installs the CLI that SIGNS every IOx package devices
# install, and used to trust whatever the download URL served with no pin at
# all. It now verifies the extracted binary against tools/ioxclient.sha256
# and fails closed on a mismatch or an unrecorded version. `curl` is stubbed
# to hand back a locally built tarball; nothing touches the network.

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
  HELPER="$REPO/tools/get-ioxclient.sh"
  case "$(uname -s)-$(uname -m)" in Linux-x86_64|Linux-amd64) ;; *) skip "helper is Linux amd64 only" ;; esac
  W="$BATS_TEST_TMPDIR/w"; mkdir -p "$W/bin" "$W/pkg/ioxclient_1.18.0.0_linux_amd64" "$W/dest"
  printf '#!/bin/sh\necho fake ioxclient\n' > "$W/pkg/ioxclient_1.18.0.0_linux_amd64/ioxclient"
  chmod +x "$W/pkg/ioxclient_1.18.0.0_linux_amd64/ioxclient"
  tar -czf "$W/ioxclient.tar.gz" -C "$W/pkg" .
  GOOD="$(sha256sum "$W/pkg/ioxclient_1.18.0.0_linux_amd64/ioxclient" | awk '{print $1}')"
  # curl stub: copies the local tarball to the -o target
  cat > "$W/bin/curl" <<STUB
#!/usr/bin/env bash
out=""; while [ \$# -gt 0 ]; do case "\$1" in -o) out="\$2"; shift 2 ;; *) shift ;; esac; done
cp "$W/ioxclient.tar.gz" "\$out"
STUB
  chmod +x "$W/bin/curl"
  export PATH="$W/bin:$PATH"
  SUMS="$W/ioxclient.sha256"
}

@test "installs when the extracted binary matches the recorded sha256" {
  echo "$GOOD  1.18.0.0" > "$SUMS"
  run env IOXCLIENT_SHA256_FILE="$SUMS" bash "$HELPER" "$W/dest"
  [ "$status" -eq 0 ]
  [[ "$output" == *"verified against"* ]]
  [ -x "$W/dest/ioxclient" ]
}

@test "refuses on a checksum mismatch and installs nothing" {
  echo "0000000000000000000000000000000000000000000000000000000000000000  1.18.0.0" > "$SUMS"
  run env IOXCLIENT_SHA256_FILE="$SUMS" bash "$HELPER" "$W/dest"
  [ "$status" -eq 1 ]
  [[ "$output" == *"CHECKSUM MISMATCH"* ]]
  [ ! -e "$W/dest/ioxclient" ]
}

@test "refuses an unrecorded version unless IOXCLIENT_SKIP_VERIFY=1, and prints the sha256 to pin" {
  : > "$SUMS"
  run env IOXCLIENT_SHA256_FILE="$SUMS" bash "$HELPER" "$W/dest"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no checksum recorded"* ]]
  [[ "$output" == *"$GOOD"* ]]
  [ ! -e "$W/dest/ioxclient" ]
  run env IOXCLIENT_SHA256_FILE="$SUMS" IOXCLIENT_SKIP_VERIFY=1 bash "$HELPER" "$W/dest"
  [ "$status" -eq 0 ]
  [[ "$output" == *"UNVERIFIED"* ]]
  [ -x "$W/dest/ioxclient" ]
}

@test "the repository records a pin for the default version" {
  v="$(sed -n 's/^VERSION="\${IOXCLIENT_VERSION:-\(.*\)}"$/\1/p' "$HELPER")"
  [ -n "$v" ]
  grep -Eq "^[0-9a-f]{64}  $v\$" "$REPO/tools/ioxclient.sha256"
}
