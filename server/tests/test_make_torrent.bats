#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# tools/make-torrent.sh used to embed a bare tracker announce URL.
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
  [[ "$output" == *"-a https://192.0.2.10:6969/announce?announce_token=abc123"* ]]
  [[ "$output" == *"-p "* ]]
  # the success line does not echo the credential
  [[ "$output" == *"announce_token=<redacted>"* ]]
}

@test "ANNOUNCE_URL is used verbatim" {
  run env ANNOUNCE_URL='https://192.0.2.10:6969/announce?key=legacy' bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 0 ]
  [[ "$output" == *"-a https://192.0.2.10:6969/announce?key=legacy"* ]]
}

@test "rejects a token containing whitespace" {
  run env ANNOUNCE_TOKEN='a b&c' bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 1 ]
  [[ "$output" == *"printable ASCII"* ]]
  [[ "$output" != *"MKTORRENT ARGS"* ]]
}

@test "ANNOUNCE_URL without a credential is refused, not passed through" {
  # the escape hatch must not recreate the credential-less torrent the
  # default path refuses: the tracker answers 403 to such an announce
  run env ANNOUNCE_URL='https://192.0.2.10:6969/announce' bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 1 ]
  [[ "$output" == *"no announce credential"* ]]
  [[ "$output" != *"MKTORRENT ARGS"* ]]
}

@test "ANNOUNCE_URL with a blank credential value is refused" {
  run env ANNOUNCE_URL='https://192.0.2.10:6969/announce?announce_token=' bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 1 ]
  [[ "$output" != *"MKTORRENT ARGS"* ]]
}

@test "ANNOUNCE_URL with announce_token among other parameters is accepted" {
  run env ANNOUNCE_URL='https://192.0.2.10:6969/announce?x=1&announce_token=abc123' bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 0 ]
  [[ "$output" == *"-a https://192.0.2.10:6969/announce?x=1&announce_token=abc123"* ]]
}

@test "ANNOUNCE_URL refuses plaintext tracker transport" {
  run env ANNOUNCE_URL='http://192.0.2.10:6969/announce?key=legacy' \
    bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 1 ]
  [[ "$output" == *"HTTPS tracker"* ]]
  [[ "$output" != *"MKTORRENT ARGS"* ]]
}

@test "ANNOUNCE_URL refuses credentials nested inside another query value" {
  for query in 'x=?key=hidden-secret' 'x=?announce_token=hidden-secret' \
    'x=%3Fannounce_token%3Dhidden-secret' 'x=1#?key=hidden-secret'; do
    run env ANNOUNCE_URL="https://192.0.2.10:6969/announce?$query" \
      bash "$HELPER" "$WORK/image.bin" 192.0.2.10
    [ "$status" -eq 1 ]
    [[ "$output" != *"hidden-secret"* ]]
    [[ "$output" != *"MKTORRENT ARGS"* ]]
  done
}

@test "ANNOUNCE_URL decodes credential names and values while preserving the URL" {
  for query in 'announce%5Ftoken=abc%31%32%33' '%6Bey=abc%26def%3Dghi' \
    'x=?key=unrelated&announce_token=abc123'; do
    run env ANNOUNCE_URL="https://192.0.2.10:6969/announce?$query" \
      bash "$HELPER" "$WORK/image.bin" 192.0.2.10
    [ "$status" -eq 0 ]
    [[ "$output" == *"-a https://192.0.2.10:6969/announce?$query"* ]]
  done
}

@test "ANNOUNCE_URL refuses duplicate dedicated credentials including blank and encoded names" {
  for query in 'announce_token=secret&announce_token=secret' \
    'announce_token=secret&announce_token=other' \
    'announce_token=&announce_token=secret' \
    'announce_token=secret&announce%5Ftoken=' \
    'announce_token=&announce_token=&key=secret'; do
    run env ANNOUNCE_URL="https://192.0.2.10:6969/announce?$query" \
      bash "$HELPER" "$WORK/image.bin" 192.0.2.10
    [ "$status" -eq 1 ]
    [[ "$output" != *"secret"* ]]
    [[ "$output" != *"MKTORRENT ARGS"* ]]
  done
}

@test "ANNOUNCE_URL follows dedicated credential precedence over key parameters" {
  run env ANNOUNCE_URL='https://192.0.2.10:6969/announce?key=first&announce_token=abc123&key=second' \
    bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 0 ]
  [[ "$output" == *"MKTORRENT ARGS"* ]]
}

@test "ANNOUNCE_URL allows one unique fallback key including repeated encoded equivalents" {
  for query in 'announce_token=&key=abc123' 'key=abc123&key=abc%31%32%33' \
    'key=&key=abc123' 'announce_token&key=abc123'; do
    run env ANNOUNCE_URL="https://192.0.2.10:6969/announce?$query" \
      bash "$HELPER" "$WORK/image.bin" 192.0.2.10
    [ "$status" -eq 0 ]
    [[ "$output" == *"MKTORRENT ARGS"* ]]
  done
}

@test "ANNOUNCE_URL refuses ambiguous fallback keys or no nonempty fallback" {
  for query in 'key=first-secret&key=second-secret' \
    'announce_token=&key=first-secret&key=second-secret' \
    'announce_token=&key=' 'key' '%6Bey='; do
    run env ANNOUNCE_URL="https://192.0.2.10:6969/announce?$query" \
      bash "$HELPER" "$WORK/image.bin" 192.0.2.10
    [ "$status" -eq 1 ]
    [[ "$output" != *"first-secret"* ]]
    [[ "$output" != *"second-secret"* ]]
    [[ "$output" != *"MKTORRENT ARGS"* ]]
  done
}

@test "ANNOUNCE_URL refuses whitespace control and non-ASCII bytes in decoded credentials" {
  for query in 'announce_token=+' 'announce_token=secret%20value' \
    'announce_token=secret%09value' 'key=secret%0Avalue' \
    'announce_token=secret%0Dvalue' 'key=secret%00value' \
    'announce_token=secret%7Fvalue' 'key=secret%C3%A9value'; do
    run env ANNOUNCE_URL="https://192.0.2.10:6969/announce?$query" \
      bash "$HELPER" "$WORK/image.bin" 192.0.2.10
    [ "$status" -eq 1 ]
    [[ "$output" != *"secret"* ]]
    [[ "$output" != *"MKTORRENT ARGS"* ]]
  done
}

@test "ANNOUNCE_URL refuses literal whitespace controls and empty fragments" {
  for suffix in ' ' $'\t' $'\n' $'\r' $'\177' '#'; do
    run env ANNOUNCE_URL="https://192.0.2.10:6969/announce?announce_token=hidden-secret$suffix" \
      bash "$HELPER" "$WORK/image.bin" 192.0.2.10
    [ "$status" -eq 1 ]
    [[ "$output" != *"hidden-secret"* ]]
    [[ "$output" != *"MKTORRENT ARGS"* ]]
  done
}

@test "ANNOUNCE_URL requires an actual announce path in the verbatim URL" {
  for path in '' '/' '/wrong'; do
    run env ANNOUNCE_URL="https://192.0.2.10:6969$path?announce_token=hidden-secret" \
      bash "$HELPER" "$WORK/image.bin" 192.0.2.10
    [ "$status" -eq 1 ]
    [[ "$output" == *"HTTPS tracker"* ]]
    [[ "$output" != *"hidden-secret"* ]]
    [[ "$output" != *"MKTORRENT ARGS"* ]]
  done
}

@test "ANNOUNCE_TOKEN encodes reserved query and fragment characters" {
  run env -u ANNOUNCE_URL ANNOUNCE_TOKEN='a&b?c=d#e/+%' \
    bash "$HELPER" "$WORK/image.bin" 192.0.2.10
  [ "$status" -eq 0 ]
  [[ "$output" == *"-a https://192.0.2.10:6969/announce?announce_token=a%26b%3Fc%3Dd%23e%2F%2B%25"* ]]
  [[ "$output" == *"announce_token=<redacted>"* ]]
}

@test "ANNOUNCE_TOKEN refuses control and non-ASCII characters" {
  for token in $'hidden-secret\t' $'hidden-secret\n' $'hidden-secret\177' 'hidden-secreté'; do
    run env -u ANNOUNCE_URL ANNOUNCE_TOKEN="$token" \
      bash "$HELPER" "$WORK/image.bin" 192.0.2.10
    [ "$status" -eq 1 ]
    [[ "$output" == *"printable ASCII"* ]]
    [[ "$output" != *"hidden-secret"* ]]
    [[ "$output" != *"MKTORRENT ARGS"* ]]
  done
}
