#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  TMP="$(mktemp -d)"
  mkdir -p "$TMP/config/tls" "$TMP/run" "$TMP/state" "$TMP/log" \
    "$TMP/images" "$TMP/artifacts"
  export IRIS_IMAGES_DIR="$TMP/images"
  export IRIS_ARTIFACTS_DIR="$TMP/artifacts"
  # fake age: encrypt prepends AGEFAKE, decrypt strips it / fails on bad header
  cat > "$TMP/fake-age" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mode="$1"; shift
out=""; inp=""
if [ "$mode" = "-d" ]; then
  while [ "$#" -gt 0 ]; do case "$1" in
    -i) shift 2 ;; -o) out="$2"; shift 2 ;; *) inp="$1"; shift ;; esac; done
  head -n1 "$inp" | grep -q '^AGEFAKE$' || { echo "age: bad" >&2; exit 1; }
  tail -n +2 "$inp" > "$out"
else
  while [ "$#" -gt 0 ]; do case "$1" in
    -r) shift 2 ;; -o) out="$2"; shift 2 ;; *) inp="$1"; shift ;; esac; done
  { echo "AGEFAKE"; cat "$inp"; } > "$out"
fi
EOF
  chmod +x "$TMP/fake-age"
  # encrypted store + rpc-secret + key on the "volume"
  printf 'AGEFAKE\n{"devices":{},"seeder":{}}\n' > "$TMP/config/secrets.json.age"
  printf 'AGEFAKE\nrpcsecretval\n' > "$TMP/config/rpc-secret.age"
  printf 'AGEFAKE\nkeypem\n' > "$TMP/config/tls/key.pem.age"
  printf 'crtpem\n' > "$TMP/config/tls/crt.pem"
}

teardown() { rm -rf "$TMP"; }

@test "entrypoint fails closed when the master key is missing" {
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/does-not-exist" \
      SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"master key"* ]]
  # no plaintext leaked to the persistent volume
  [ ! -f "$TMP/config/secrets.json" ]
}

# Finding 5 (minor): the artifact server's stdout/stderr must NOT be discarded
# to /dev/null — startup/serving failures have to reach the container log.
@test "entrypoint does not discard the artifact server output to /dev/null" {
  ! grep -E 'artifact_server\.py[^&]*>/dev/null' \
      "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
}

@test "entrypoint tolerates a tmpfs mountpoint it cannot chmod (non-root runtime)" {
  # running as uid 10001 the entrypoint may not OWN /run/iris (k8s Memory
  # emptyDir stays root-owned; fsGroup only grants group access) — the chmod
  # must not abort startup there. Compose enforces 0700 via tmpfs uid=/mode=
  # mount options instead.
  grep -Eq 'chmod 700 "\$IRIS_RUN" 2>/dev/null \|\| true' \
      "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
}

@test "entrypoint self-provisions the served artifacts before launching services" {
  # the fresh-deploy fix: docker-entrypoint.sh calls provision-served.sh so the
  # Guest Shell bundle / bootstrap.sh / iris-catalog.pem exist before onboarding
  grep -q 'provision-served.sh' "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
}

@test "entrypoint execs a one-shot command instead of the supervisor" {
  # `docker compose run --rm iris iris-bootstrap` passes iris-bootstrap as an
  # arg to the fixed ENTRYPOINT. The entrypoint must exec it directly and
  # BYPASS the decrypt/fail-closed path — otherwise a fresh-volume bootstrap
  # (no secrets.json.age, no key yet) dies with "fail closed" before it can
  # create the secrets it exists to create.
  run env IRIS_CONFIG="$TMP/nonexistent-config" IRIS_STATE="$TMP/state" \
      IRIS_LOG="$TMP/log" IRIS_RUN="$TMP/run" \
      IRIS_AGE_KEY_FILE="$TMP/does-not-exist" \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh" echo BOOTSTRAP-RAN
  [ "$status" -eq 0 ]
  [[ "$output" == *"BOOTSTRAP-RAN"* ]]
  [[ "$output" != *"fail closed"* ]]
}

@test "entrypoint with no args still runs the normal startup path (fail-closed check intact)" {
  # regression guard: normal `docker compose up` passes NO args, so the exec
  # dispatch must not trigger — the key/decrypt fail-closed still applies.
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/does-not-exist" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"master key"* ]]
}

@test "entrypoint decrypts the store to tmpfs when the key is present" {
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  # plaintext store landed in tmpfs, NOT on the config volume
  [ -f "$TMP/run/secrets.json" ]
  [ ! -f "$TMP/config/secrets.json" ]
  run cat "$TMP/run/secrets.json"
  [[ "$output" == *'"devices"'* ]]
  # rpc-secret + tls key decrypted too
  [ -f "$TMP/run/rpc-secret" ]
  run cat "$TMP/run/rpc-secret"
  [[ "$output" == "rpcsecretval" ]]
  [ -f "$TMP/run/tls/key.pem" ]
  # combined cert built in tmpfs
  [ -f "$TMP/run/tls/cert.pem" ]
}
