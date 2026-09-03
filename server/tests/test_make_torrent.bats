#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# tools/make-torrent.sh used to embed a bare http://<host>:6969/announce URL.
# The IRIS tracker answers 403 to any announce without an announce_token (or
# legacy key), so such a torrent could never work. The helper now requires a
# credential and embeds it. mktorrent is stubbed so the test only inspects the
# announce URL the helper passes.

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  HELPER="$REPO/tools/make-torrent.sh"
  WORK="$BATS_TEST_TMPDIR/w"; mkdir -p "$WORK/bin"
  cat > "$WORK/bin/mktorrent" <<'STUB'
#!/usr/bin/env bash
echo "MKTORRENT ARGS: $*"
STUB
  chmod +x "$WORK/bin/mktorrent"
  export PATH="$WORK/bin:$PATH"
  echo "payload" > "$WORK/image.bin"
}

@test "refuses to build a torrent without an announce credential" {
  run env -u ANNOUNCE_TOKEN -u ANNOUNCE_URL bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 1 ]
  [[ "$output" == *"no announce credential"* ]]
  [[ "$output" != *"MKTORRENT ARGS"* ]]
}

@test "embeds ANNOUNCE_TOKEN as the announce_token query parameter" {
  run env ANNOUNCE_TOKEN=abc123 bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 0 ]
  [[ "$output" == *"-a http://192.0.2.10:6969/announce?announce_token=abc123"* ]]
  [[ "$output" == *"-p "* ]]
  # the success line does not echo the credential
  [[ "$output" == *"announce_token=<redacted>"* ]]
}

@test "ANNOUNCE_URL is used verbatim" {
  run env ANNOUNCE_URL='http://192.0.2.10:6969/announce?key=legacy' bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 0 ]
  [[ "$output" == *"-a http://192.0.2.10:6969/announce?key=legacy"* ]]
}

@test "rejects a token that is not URL-safe" {
  run env ANNOUNCE_TOKEN='a b&c' bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 1 ]
  [[ "$output" == *"URL-safe"* ]]
}
