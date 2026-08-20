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

# ---------------------------------------------------------------------------
# Console cert override + CA trust bundle (server TLS trust feature).
# The gui-cert build is best-effort BY DESIGN: a corrupt override must never
# stop the container — the console falls back to the bootstrap cert.
#
# The pair-validation tests below use REAL openssl-generated cert/key
# material rather than the plain-text placeholders the other secret files
# use in this suite: the boot script runs the real `openssl x509 -pubkey` /
# `openssl pkey -pubout` public-key compare against these files, so the
# fixtures have to be something openssl can actually parse. EC keys keep
# generation fast (~20ms) — the compare is deliberately key-type-agnostic.
# ---------------------------------------------------------------------------

gen_ec_pair() {
  # $1=key out path, $2=cert out path, $3=CN
  openssl ecparam -genkey -name prime256v1 -noout -out "$1" 2>/dev/null
  openssl req -x509 -key "$1" -days 1 -out "$2" -subj "/CN=$3" 2>/dev/null
}

@test "entrypoint builds the console cert override when the durable gui files exist" {
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  gen_ec_pair "$TMP/gui-key-plain.pem" "$TMP/config/tls/gui-crt.pem" "gui-a"
  { printf 'AGEFAKE\n'; cat "$TMP/gui-key-plain.pem"; } > "$TMP/config/tls/gui-key.pem.age"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/run/tls/gui-cert.pem" ]
  run cat "$TMP/run/tls/gui-cert.pem"
  [[ "$output" == *"BEGIN CERTIFICATE"* ]]
  [[ "$output" == *"BEGIN EC PRIVATE KEY"* ]]
}

@test "entrypoint keeps starting when the gui key does not decrypt (warn + skip, never fatal)" {
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  printf 'guicrtpem\n' > "$TMP/config/tls/gui-crt.pem"
  printf 'NOT-AGEFAKE\ncorrupt\n' > "$TMP/config/tls/gui-key.pem.age"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
  # the override is absent -> console falls back to the bootstrap cert, which
  # must still have been built
  [ ! -f "$TMP/run/tls/gui-cert.pem" ]
  [ -f "$TMP/run/tls/cert.pem" ]
}

@test "entrypoint discards a mismatched gui cert/key pair (warn + skip, never fatal)" {
  # Crash-window regression guard: gui_tls.persist_override writes the
  # durable key first, then the cert. A crash between the two — or any other
  # way the durable pair gets out of sync — must never leave a mismatched
  # pair combined into a servable file; the console has to fall back to the
  # built-in cert instead of crashing later inside ssl.load_cert_chain.
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  gen_ec_pair "$TMP/gui-key-a.pem" "$TMP/gui-crt-a.pem" "gui-a"
  gen_ec_pair "$TMP/gui-key-b.pem" "$TMP/gui-crt-b.pem" "gui-b"
  # durable crt is pair A's certificate; the (decryptable) durable key
  # decrypts to pair B's key — the two do not form a matching pair.
  cp "$TMP/gui-crt-a.pem" "$TMP/config/tls/gui-crt.pem"
  { printf 'AGEFAKE\n'; cat "$TMP/gui-key-b.pem"; } > "$TMP/config/tls/gui-key.pem.age"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
  [ ! -f "$TMP/run/tls/gui-cert.pem" ]
  # the intermediate decrypted key must not survive a mismatched pair either
  [ ! -f "$TMP/run/tls/gui-key.pem" ]
  [ -f "$TMP/run/tls/cert.pem" ]
}

@test "entrypoint builds the runtime CA bundle from a non-empty trust dir (sorted concat)" {
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  mkdir -p "$TMP/config/tls/trust"
  printf 'BBB-CA\n' > "$TMP/config/tls/trust/bbb.pem"
  printf 'AAA-CA\n' > "$TMP/config/tls/trust/aaa.pem"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  [ -f "$TMP/run/tls/ca-bundle.pem" ]
  run cat "$TMP/run/tls/ca-bundle.pem"
  # deterministic lexicographic filename order — must match trust.rebuild_bundle()
  [ "${lines[0]}" = "AAA-CA" ]
  [ "${lines[1]}" = "BBB-CA" ]
}

@test "entrypoint creates the durable trust dir and leaves no CA bundle when it is empty" {
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  [ -d "$TMP/config/tls/trust" ]
  [ ! -f "$TMP/run/tls/ca-bundle.pem" ]
}

# ---------------------------------------------------------------------------
# Review findings (per-file trust-bundle guard + stale gui-cert sweep).
# ---------------------------------------------------------------------------

@test "entrypoint tolerates one bad trust entry and keeps the good cert (per-file guard)" {
  # A single un-cat-able entry (here: a directory named *.pem) must not abort
  # the whole container start under set -e — mirrors trust.py rebuild_bundle()
  # skipping a bad entry rather than failing the whole rebuild.
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  mkdir -p "$TMP/config/tls/trust"
  printf 'GOOD-CA\n' > "$TMP/config/tls/trust/good.pem"
  mkdir -p "$TMP/config/tls/trust/bad.pem"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
  [ -f "$TMP/run/tls/ca-bundle.pem" ]
  run cat "$TMP/run/tls/ca-bundle.pem"
  [ "$output" = "GOOD-CA" ]
}

@test "entrypoint's CA bundle only includes *.pem entries (stray non-pem files ignored)" {
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  mkdir -p "$TMP/config/tls/trust"
  printf 'GOOD-CA\n' > "$TMP/config/tls/trust/good.pem"
  printf 'not a cert\n' > "$TMP/config/tls/trust/stray.txt"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  run cat "$TMP/run/tls/ca-bundle.pem"
  [ "$output" = "GOOD-CA" ]
}

@test "entrypoint sweeps a stale runtime CA bundle when the trust dir is empty" {
  # mirrors the equivalent iris-secretfs test — RuntimeDirectoryPreserve-style
  # staleness applies to the container's tmpfs too if the trust dir is emptied
  # between restarts.
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  mkdir -p "$TMP/run/tls"
  printf 'stale-ca\n' > "$TMP/run/tls/ca-bundle.pem"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  [ ! -f "$TMP/run/tls/ca-bundle.pem" ]
}

@test "entrypoint sweeps a stale runtime gui-cert override when the durable pair is absent" {
  # RuntimeDirectoryPreserve=yes keeps /run/iris across restarts — a PREVIOUS
  # boot's override must not silently keep serving once the durable pair is
  # gone (never uploaded, or removed via Settings).
  printf 'AGE-SECRET-KEY-FAKE\n' > "$TMP/agekey"
  mkdir -p "$TMP/run/tls"
  printf 'stale-cert\n' > "$TMP/run/tls/gui-cert.pem"
  printf 'stale-key\n' > "$TMP/run/tls/gui-key.pem"
  run env IRIS_CONFIG="$TMP/config" IRIS_STATE="$TMP/state" IRIS_LOG="$TMP/log" \
      IRIS_RUN="$TMP/run" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_KEY_FILE="$TMP/agekey" SKIP_SUPERVISE=1 \
      bash "$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  [ "$status" -eq 0 ]
  [ ! -f "$TMP/run/tls/gui-cert.pem" ]
  [ ! -f "$TMP/run/tls/gui-key.pem" ]
}

@test "entrypoint unseals via the shared secretfs.decrypt_to, not an inline reimplementation" {
  # Anti-drift guard, ported from the deleted test_systemd_units.bats. The
  # entrypoint must route decryption through server/secretfs.py so there is one
  # implementation of the at-rest format, not two that can diverge.
  local entrypoint="$BATS_TEST_DIRNAME/../docker-entrypoint.sh"
  grep -q 'import secretfs' "$entrypoint"
  grep -q 'secretfs\.decrypt_to(' "$entrypoint"
}
