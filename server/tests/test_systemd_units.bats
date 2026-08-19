#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Static assertions on the bare-metal systemd units + the iris-secretfs
# unseal helper. The bare-metal path must mirror the container entrypoint:
# decrypt the *.age ciphertext to a tmpfs (/run/iris) before any service
# starts (an ExecStartPre= unseal step per unit), point IRIS_SECRETS /
# IRIS_RPC_SECRET_FILE / IRIS_CERT at that tmpfs, and let the catalog write
# its audit log + re-encrypt under /etc/iris.
#
# Each load-bearing line gets its OWN @test: a bats @test reports only the
# LAST command's status, so bundling assertions hides regressions.

SYSTEMD_DIR="$BATS_TEST_DIRNAME/../systemd"
SECRETFS="$BATS_TEST_DIRNAME/../iris-secretfs"
CATALOG="$SYSTEMD_DIR/iris-catalog.service"
TRACKER="$SYSTEMD_DIR/iris-tracker.service"
SEEDER="$SYSTEMD_DIR/iris-seeder.service"

# ---------------------------------------------------------------------------
# Finding 1: bare-metal must decrypt secrets via a shared unseal helper that
# every unit runs as an ExecStartPre before its main process starts.
# ---------------------------------------------------------------------------
@test "iris-secretfs unseal helper exists and is executable" {
  [ -x "$SECRETFS" ]
}

@test "iris-secretfs decrypts secrets.json.age to the tmpfs run dir" {
  grep -q 'secrets.json.age' "$SECRETFS"
}

@test "iris-secretfs decrypts rpc-secret.age to the tmpfs run dir" {
  grep -q 'rpc-secret.age' "$SECRETFS"
}

@test "iris-secretfs decrypts tls/key.pem.age to the tmpfs run dir" {
  grep -q 'tls/key.pem.age' "$SECRETFS"
}

@test "iris-secretfs builds the combined cert.pem in the tmpfs run dir" {
  # The combined cert is crt.pem + key.pem concatenated, landing at
  # $IRIS_RUN/tls/cert.pem (now via an atomic temp + mv, so the cat target and
  # the final cert.pem are on separate lines — assert both facts).
  grep -Eq 'cat .*crt\.pem.*key\.pem' "$SECRETFS"
  grep -Eq '/tls/cert\.pem' "$SECRETFS"
}

# Up to three iris-secretfs run concurrently sharing one RuntimeDirectory, so
# the cert.pem build must be atomic (temp-in-same-dir + mv), never a bare
# truncate-then-write redirect into the live cert.pem that a concurrent reader
# could catch half-written.
@test "iris-secretfs builds cert.pem atomically (temp + mv, not in-place)" {
  # Final cert.pem is produced by a rename, not a direct redirect.
  grep -Eq 'mv .*/tls/cert\.pem' "$SECRETFS"
  # The combined cat must redirect into a temp, NOT straight into cert.pem.
  ! grep -Eq 'cat .*crt\.pem.*key\.pem[^>]*> *"?\$\{?IRIS_RUN\}?/tls/cert\.pem"? *$' "$SECRETFS"
}

@test "iris-secretfs reuses the shared secretfs.decrypt_to mechanism" {
  grep -q 'secretfs' "$SECRETFS"
}

@test "iris-secretfs fails closed when the master key is missing" {
  # Behavioral: run the helper with a nonexistent master key and a writable
  # tmpfs stand-in, and assert it actually aborts non-zero (not merely that the
  # variable name appears in the source).  IRIS_RUN is redirected to a temp dir
  # so the mkdir/chmod preamble succeeds and the ONLY failure cause is the
  # missing key.
  run env IRIS_RUN="$BATS_TEST_TMPDIR/run" \
          IRIS_AGE_KEY_FILE="$BATS_TEST_TMPDIR/nonexistent-key" \
          bash "$SECRETFS"
  [ "$status" -ne 0 ]
  [[ "$output" == *"master key"* ]]
  # No plaintext secret material may have landed before the abort.
  [ ! -e "$BATS_TEST_TMPDIR/run/secrets.json" ]
}

@test "catalog unit runs the iris-secretfs unseal step before start" {
  grep -Eq '^ExecStartPre=.*iris-secretfs' "$CATALOG"
}

@test "tracker unit runs the iris-secretfs unseal step before start" {
  grep -Eq '^ExecStartPre=.*iris-secretfs' "$TRACKER"
}

@test "seeder unit runs the iris-secretfs unseal step before start" {
  grep -Eq '^ExecStartPre=.*iris-secretfs' "$SEEDER"
}

@test "catalog unit points IRIS_SECRETS at the decrypted tmpfs store" {
  grep -q 'IRIS_SECRETS=/run/iris/secrets.json' "$CATALOG"
}

@test "tracker unit points IRIS_SECRETS at the decrypted tmpfs store" {
  grep -q 'IRIS_SECRETS=/run/iris/secrets.json' "$TRACKER"
}

@test "seeder unit points IRIS_RPC_SECRET_FILE at the decrypted tmpfs secret" {
  grep -q 'IRIS_RPC_SECRET_FILE=/run/iris/rpc-secret' "$SEEDER"
}

# ---------------------------------------------------------------------------
# Finding 2: the unit must point IRIS_CERT at the combined cert.pem the
# unseal step builds in tmpfs (bootstrap never writes a plaintext cert.pem
# on the config volume).
# ---------------------------------------------------------------------------
@test "catalog unit points IRIS_CERT at the tmpfs combined cert.pem" {
  grep -q 'IRIS_CERT=/run/iris/tls/cert.pem' "$CATALOG"
}

@test "catalog unit no longer points IRIS_CERT at a plaintext /etc/iris cert.pem" {
  ! grep -q 'IRIS_CERT=/etc/iris/tls/cert.pem' "$CATALOG"
}

# ---------------------------------------------------------------------------
# Finding 3: ProtectSystem=strict but catalog writes the audit log and
# re-encrypts secrets under /etc/iris at runtime -> /etc/iris must be
# read-write, and the tmpfs run dir must exist (RuntimeDirectory).
# ---------------------------------------------------------------------------
@test "catalog unit makes /etc/iris read-write for audit + re-encrypt" {
  grep -Eq '^ReadWritePaths=.*(/etc/iris)' "$CATALOG"
}

@test "catalog unit provisions the tmpfs run dir (RuntimeDirectory)" {
  grep -Eq '^RuntimeDirectory=iris' "$CATALOG"
}

@test "tracker unit provisions the tmpfs run dir (RuntimeDirectory)" {
  grep -Eq '^RuntimeDirectory=iris' "$TRACKER"
}

@test "seeder unit provisions the tmpfs run dir (RuntimeDirectory)" {
  grep -Eq '^RuntimeDirectory=iris' "$SEEDER"
}

# The three units SHARE RuntimeDirectory=iris; without preserve, stopping any
# one unit would wipe /run/iris out from under the others. Preserve keeps the
# decrypted tmpfs alive while any iris service is running.
# Must be exactly =yes: RuntimeDirectoryPreserve=no (the systemd default) would
# DELETE the shared /run/iris when any one unit stops, wiping decrypted secrets
# out from under the still-running units.  Assert the value, not mere presence.
@test "catalog unit preserves the shared run dir across restarts" {
  grep -Eq '^RuntimeDirectoryPreserve=yes' "$CATALOG"
}

@test "tracker unit preserves the shared run dir across restarts" {
  grep -Eq '^RuntimeDirectoryPreserve=yes' "$TRACKER"
}

@test "seeder unit preserves the shared run dir across restarts" {
  grep -Eq '^RuntimeDirectoryPreserve=yes' "$SEEDER"
}

# ---------------------------------------------------------------------------
# Dead env: the retired IRIS_TOKENS=/etc/iris/tokens.txt must be gone.
# ---------------------------------------------------------------------------
@test "catalog unit drops the retired IRIS_TOKENS env" {
  ! grep -q 'IRIS_TOKENS' "$CATALOG"
}

@test "tracker unit drops the retired IRIS_TOKENS env" {
  ! grep -q 'IRIS_TOKENS' "$TRACKER"
}

# ---------------------------------------------------------------------------
# Console cert override + CA trust bundle at unseal (server TLS trust
# feature). iris-secretfs mirrors docker-entrypoint.sh: build
# $IRIS_RUN/tls/gui-cert.pem when the durable override pair exists (decrypt
# failure = warn + skip, NEVER fatal — this helper is every unit's
# ExecStartPre, and a bad CONSOLE cert must not take the tracker down), and
# build $IRIS_RUN/tls/ca-bundle.pem from the trust dir when non-empty.
# Behavioral tests use a fake age (same AGEFAKE convention as
# test_entrypoint_secretfs.bats) and a temp stand-in for /etc/iris + /run/iris.
# ---------------------------------------------------------------------------

make_unseal_fixture() {
  FIX="$BATS_TEST_TMPDIR/fix"
  mkdir -p "$FIX/config/tls" "$FIX/run"
  cat > "$FIX/fake-age" <<'EOF'
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
  chmod +x "$FIX/fake-age"
  printf 'AGEFAKE\n{"devices":{},"seeder":{}}\n' > "$FIX/config/secrets.json.age"
  printf 'AGEFAKE\nrpcsecretval\n' > "$FIX/config/rpc-secret.age"
  printf 'AGEFAKE\nkeypem\n' > "$FIX/config/tls/key.pem.age"
  printf 'crtpem\n' > "$FIX/config/tls/crt.pem"
  printf 'AGE-SECRET-KEY-FAKE\n' > "$FIX/agekey"
}

run_secretfs() {
  run env IRIS_CONFIG="$FIX/config" IRIS_RUN="$FIX/run" \
      IRIS_AGE_BIN="$FIX/fake-age" IRIS_AGE_KEY_FILE="$FIX/agekey" \
      bash "$SECRETFS"
}

# Real openssl-generated cert/key material: the pair-validation code path
# runs the real `openssl x509 -pubkey` / `openssl pkey -pubout` compare
# against these files, so (unlike the other secret fixtures in this suite)
# they have to be something openssl can actually parse.
gen_ec_pair() {
  openssl ecparam -genkey -name prime256v1 -noout -out "$1" 2>/dev/null
  openssl req -x509 -key "$1" -days 1 -out "$2" -subj "/CN=$3" 2>/dev/null
}

@test "iris-secretfs builds the console cert override when the durable gui files exist" {
  make_unseal_fixture
  gen_ec_pair "$FIX/gui-key-plain.pem" "$FIX/config/tls/gui-crt.pem" "gui-a"
  { printf 'AGEFAKE\n'; cat "$FIX/gui-key-plain.pem"; } > "$FIX/config/tls/gui-key.pem.age"
  run_secretfs
  [ "$status" -eq 0 ]
  [ -f "$FIX/run/tls/gui-cert.pem" ]
  run cat "$FIX/run/tls/gui-cert.pem"
  [[ "$output" == *"BEGIN CERTIFICATE"* ]]
  [[ "$output" == *"BEGIN EC PRIVATE KEY"* ]]
}

@test "iris-secretfs skips an undecryptable gui key WITHOUT failing the unseal" {
  make_unseal_fixture
  printf 'guicrtpem\n' > "$FIX/config/tls/gui-crt.pem"
  printf 'NOT-AGEFAKE\ncorrupt\n' > "$FIX/config/tls/gui-key.pem.age"
  run_secretfs
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
  [ ! -f "$FIX/run/tls/gui-cert.pem" ]
  # the identity cert the units serve is untouched by the failure
  [ -f "$FIX/run/tls/cert.pem" ]
}

@test "iris-secretfs discards a mismatched gui cert/key pair WITHOUT failing the unseal" {
  # Crash-window regression guard: gui_tls.persist_override writes the
  # durable key first, then the cert, so a crash between the two can leave a
  # decryptable key paired with a stale cert. A bad CONSOLE cert must never
  # take the tracker/catalog/seeder down.
  make_unseal_fixture
  gen_ec_pair "$FIX/gui-key-a.pem" "$FIX/gui-crt-a.pem" "gui-a"
  gen_ec_pair "$FIX/gui-key-b.pem" "$FIX/gui-crt-b.pem" "gui-b"
  cp "$FIX/gui-crt-a.pem" "$FIX/config/tls/gui-crt.pem"
  { printf 'AGEFAKE\n'; cat "$FIX/gui-key-b.pem"; } > "$FIX/config/tls/gui-key.pem.age"
  run_secretfs
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
  [ ! -f "$FIX/run/tls/gui-cert.pem" ]
  # the intermediate decrypted key must not survive a mismatched pair either
  [ ! -f "$FIX/run/tls/gui-key.pem" ]
  [ -f "$FIX/run/tls/cert.pem" ]
}

@test "iris-secretfs builds the runtime CA bundle from a non-empty trust dir" {
  make_unseal_fixture
  mkdir -p "$FIX/config/tls/trust"
  printf 'BBB-CA\n' > "$FIX/config/tls/trust/bbb.pem"
  printf 'AAA-CA\n' > "$FIX/config/tls/trust/aaa.pem"
  run_secretfs
  [ "$status" -eq 0 ]
  [ -f "$FIX/run/tls/ca-bundle.pem" ]
  run cat "$FIX/run/tls/ca-bundle.pem"
  [ "${lines[0]}" = "AAA-CA" ]
  [ "${lines[1]}" = "BBB-CA" ]
}

@test "iris-secretfs removes a stale CA bundle when the trust dir is empty" {
  # RuntimeDirectoryPreserve=yes keeps /run/iris across unit restarts, so a
  # bundle built before the operator removed the last CA must not survive
  # the next unseal.
  make_unseal_fixture
  mkdir -p "$FIX/config/tls/trust" "$FIX/run/tls"
  printf 'stale\n' > "$FIX/run/tls/ca-bundle.pem"
  run_secretfs
  [ "$status" -eq 0 ]
  [ ! -f "$FIX/run/tls/ca-bundle.pem" ]
}

@test "iris-secretfs never creates the durable trust dir (non-console units mount /etc/iris read-only)" {
  make_unseal_fixture
  run_secretfs
  [ "$status" -eq 0 ]
  [ ! -d "$FIX/config/tls/trust" ]
}

@test "iris-secretfs builds gui-cert.pem atomically (temp + mv, not in-place)" {
  grep -Eq 'mv -f "\$gui_tmp" "\$IRIS_GUI_CERT"' "$SECRETFS"
}

@test "iris-secretfs builds ca-bundle.pem atomically (temp + mv, not in-place)" {
  grep -Eq 'mv -f "\$bundle_tmp" "\$IRIS_CA_BUNDLE"' "$SECRETFS"
}

# ---------------------------------------------------------------------------
# Review findings (per-file trust-bundle guard + stale gui-cert sweep).
# ---------------------------------------------------------------------------

@test "iris-secretfs tolerates one bad trust entry and keeps the good cert (per-file guard)" {
  # A single un-cat-able entry (here: a directory named *.pem) must not abort
  # the whole unseal under set -e, which would take every iris-*.service's
  # ExecStartPre down with it — mirrors trust.py rebuild_bundle() skipping a
  # bad entry rather than failing the whole rebuild.
  make_unseal_fixture
  mkdir -p "$FIX/config/tls/trust"
  printf 'GOOD-CA\n' > "$FIX/config/tls/trust/good.pem"
  mkdir -p "$FIX/config/tls/trust/bad.pem"
  run_secretfs
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
  [ -f "$FIX/run/tls/ca-bundle.pem" ]
  run cat "$FIX/run/tls/ca-bundle.pem"
  [ "$output" = "GOOD-CA" ]
}

@test "iris-secretfs sweeps a stale runtime gui-cert override when the durable pair is absent" {
  # RuntimeDirectoryPreserve=yes keeps /run/iris across restarts — a PREVIOUS
  # unit run's override must not silently keep serving once the durable pair
  # is gone (never uploaded, or removed via Settings).
  make_unseal_fixture
  mkdir -p "$FIX/run/tls"
  printf 'stale-cert\n' > "$FIX/run/tls/gui-cert.pem"
  printf 'stale-key\n' > "$FIX/run/tls/gui-key.pem"
  run_secretfs
  [ "$status" -eq 0 ]
  [ ! -f "$FIX/run/tls/gui-cert.pem" ]
  [ ! -f "$FIX/run/tls/gui-key.pem" ]
}
