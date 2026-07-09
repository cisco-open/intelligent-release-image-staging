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
