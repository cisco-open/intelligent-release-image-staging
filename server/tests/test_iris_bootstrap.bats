#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for server/iris-bootstrap.
#
# Strategy: stub age / age-keygen so the test never needs the real binaries,
# and stub openssl so the test does not require rsa:4096 generation time.
# The fake age (same pattern as test_entrypoint_secretfs.bats): encrypt
# prepends AGEFAKE, decrypt strips it.  The fake openssl generates a tiny
# placeholder file so the bootstrap's -x509 step succeeds instantly.
# The fake age-keygen writes a deterministic identity file.

setup() {
  TMP="$(mktemp -d)"
  IRIS_CONFIG="$TMP/etc/iris"
  mkdir -p "$IRIS_CONFIG/tls"

  # ---- fake age (encrypt/decrypt) ----
  cat > "$TMP/fake-age" <<'EOFA'
#!/usr/bin/env bash
set -euo pipefail
mode="$1"; shift
out=""; inp=""; recipients=()
if [ "$mode" = "-d" ]; then
  while [ "$#" -gt 0 ]; do case "$1" in
    -i) shift 2 ;; -o) out="$2"; shift 2 ;; *) inp="$1"; shift ;; esac; done
  head -n1 "$inp" | grep -q '^AGEFAKE$' || { echo "fake-age: bad ciphertext" >&2; exit 1; }
  tail -n +2 "$inp" > "$out"
else
  while [ "$#" -gt 0 ]; do case "$1" in
    -r) recipients+=("$2"); shift 2 ;; -o) out="$2"; shift 2 ;; *) inp="$1"; shift ;; esac; done
  { echo "AGEFAKE"; cat "$inp"; } > "$out"
fi
EOFA
  chmod +x "$TMP/fake-age"

  # ---- fake age-keygen ----
  cat > "$TMP/fake-age-keygen" <<'EOFK'
#!/usr/bin/env bash
set -euo pipefail
# Minimal age-keygen stub: writes a deterministic identity to -o <path>
out=""
while [ "$#" -gt 0 ]; do case "$1" in
  -o) out="$2"; shift 2 ;; *) shift ;; esac; done
[ -n "$out" ] || { echo "fake-age-keygen: -o required" >&2; exit 1; }
printf '# created: 2026-01-01T00:00:00Z\n# public key: age1fakerecipient000000000000000000000000000000000000000000\nAGE-SECRET-KEY-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK\n' > "$out"
EOFK
  chmod +x "$TMP/fake-age-keygen"

  # ---- fake openssl ----
  # Handles 'openssl rand -hex 32' and 'openssl req -x509 ...' with -keyout / -out
  cat > "$TMP/fake-openssl" <<'EOFO'
#!/usr/bin/env bash
set -euo pipefail
cmd="$1"; shift
if [ "$cmd" = "rand" ]; then
  # rand -hex 32 -> emit 64 hex chars
  printf '%064x\n' 12345678901234567890
elif [ "$cmd" = "req" ]; then
  keyout=""; out=""
  while [ "$#" -gt 0 ]; do case "$1" in
    -keyout) keyout="$2"; shift 2 ;; -out) out="$2"; shift 2 ;; *) shift ;; esac; done
  [ -n "$keyout" ] && printf 'FAKE-KEY\n' > "$keyout"
  [ -n "$out" ]    && printf 'FAKE-CERT\n' > "$out"
else
  echo "fake-openssl: unknown cmd $cmd" >&2; exit 1
fi
EOFO
  chmod +x "$TMP/fake-openssl"

  # Put stubs before real binaries on PATH
  export PATH="$TMP:$PATH"

  # Symlink age-keygen so iris-bootstrap finds it as 'age-keygen'
  ln -sf "$TMP/fake-age-keygen" "$TMP/age-keygen"
  ln -sf "$TMP/fake-age"        "$TMP/age"
  ln -sf "$TMP/fake-openssl"    "$TMP/openssl"

  BOOTSTRAP="$BATS_TEST_DIRNAME/../iris-bootstrap"
}

teardown() { rm -rf "$TMP"; }

# ---------------------------------------------------------------------------
# Helper: run bootstrap with standard env overrides
# ---------------------------------------------------------------------------
run_bootstrap() {
  local extra_args=("$@")
  run env \
    IRIS_CONFIG="$IRIS_CONFIG" \
    IRIS_HOST_IP="127.0.0.1" \
    IRIS_AGE_KEY_FILE="$TMP/iris_age_key" \
    IRIS_AGE_BIN="$TMP/fake-age" \
    IRIS_AGE_RECIPIENTS="" \
    bash "$BOOTSTRAP" "${extra_args[@]+"${extra_args[@]}"}"
}

# ---------------------------------------------------------------------------
# Test: happy path — all three .age files are created
# ---------------------------------------------------------------------------
@test "bootstrap creates all three .age files on a fresh config" {
  run_bootstrap
  [ "$status" -eq 0 ]
  [ -f "$IRIS_CONFIG/secrets.json.age"   ] || { echo "secrets.json.age missing"; return 1; }
  [ -f "$IRIS_CONFIG/rpc-secret.age"     ] || { echo "rpc-secret.age missing"; return 1; }
  [ -f "$IRIS_CONFIG/tls/key.pem.age"    ] || { echo "tls/key.pem.age missing"; return 1; }
}

# ---------------------------------------------------------------------------
# Test: public cert is written (not secret, stays plaintext)
# ---------------------------------------------------------------------------
@test "bootstrap writes tls/crt.pem (public cert)" {
  run_bootstrap
  [ "$status" -eq 0 ]
  [ -f "$IRIS_CONFIG/tls/crt.pem" ] || { echo "crt.pem missing"; return 1; }
}

# ---------------------------------------------------------------------------
# Test: no plaintext secrets.json / rpc-secret / key.pem remain on the volume
# ---------------------------------------------------------------------------
@test "bootstrap leaves NO plaintext secrets.json on the config volume" {
  run_bootstrap
  [ "$status" -eq 0 ]
  [ ! -f "$IRIS_CONFIG/secrets.json"     ] || { echo "plaintext secrets.json leaked!"; return 1; }
  [ ! -f "$IRIS_CONFIG/rpc-secret"       ] || { echo "plaintext rpc-secret leaked!"; return 1; }
  [ ! -f "$IRIS_CONFIG/tls/key.pem"      ] || { echo "plaintext tls/key.pem leaked!"; return 1; }
}

# ---------------------------------------------------------------------------
# Test: .age files are valid fake-age ciphertext (decrypt round-trips)
# ---------------------------------------------------------------------------
@test "bootstrap .age files decrypt back to valid content" {
  run_bootstrap
  [ "$status" -eq 0 ]
  # decrypt each .age file using the fake age binary and check the header
  "$TMP/fake-age" -d -i "$TMP/iris_age_key" -o "$TMP/secrets.json" \
    "$IRIS_CONFIG/secrets.json.age"
  # secrets.json must be valid JSON with 'seeder'
  python3 -c "import json; d=json.load(open('$TMP/secrets.json')); assert 'seeder' in d"

  "$TMP/fake-age" -d -i "$TMP/iris_age_key" -o "$TMP/rpc-secret" \
    "$IRIS_CONFIG/rpc-secret.age"
  [ -s "$TMP/rpc-secret" ]

  "$TMP/fake-age" -d -i "$TMP/iris_age_key" -o "$TMP/key.pem" \
    "$IRIS_CONFIG/tls/key.pem.age"
  [ -s "$TMP/key.pem" ]
}

# ---------------------------------------------------------------------------
# Test: idempotency — a second run WITHOUT --force does NOT clobber .age files
# ---------------------------------------------------------------------------
@test "second run without --force is idempotent (does not overwrite .age files)" {
  run_bootstrap
  [ "$status" -eq 0 ]
  # Record timestamps / sizes of the .age files
  secrets_before="$(wc -c < "$IRIS_CONFIG/secrets.json.age")"
  rpc_before="$(wc -c < "$IRIS_CONFIG/rpc-secret.age")"
  key_before="$(wc -c < "$IRIS_CONFIG/tls/key.pem.age")"

  # Second run must succeed and print "already exist" message (no overwrite)
  run_bootstrap
  [ "$status" -eq 0 ]
  [[ "$output" == *"already exist"* ]]

  [ "$(wc -c < "$IRIS_CONFIG/secrets.json.age")" = "$secrets_before" ]
  [ "$(wc -c < "$IRIS_CONFIG/rpc-secret.age")"   = "$rpc_before"     ]
  [ "$(wc -c < "$IRIS_CONFIG/tls/key.pem.age")"  = "$key_before"     ]
}

# ---------------------------------------------------------------------------
# Test: --force overwrites existing .age files
# ---------------------------------------------------------------------------
@test "--force overwrites existing .age files" {
  run_bootstrap
  [ "$status" -eq 0 ]
  # Corrupt one file to confirm --force regenerates
  printf 'CORRUPTED\n' > "$IRIS_CONFIG/secrets.json.age"
  run_bootstrap --force
  [ "$status" -eq 0 ]
  # secrets.json.age must now be valid again
  "$TMP/fake-age" -d -i "$TMP/iris_age_key" -o "$TMP/secrets2.json" \
    "$IRIS_CONFIG/secrets.json.age"
  python3 -c "import json; d=json.load(open('$TMP/secrets2.json')); assert 'seeder' in d"
}

# ---------------------------------------------------------------------------
# Test: age identity is generated when missing
# ---------------------------------------------------------------------------
@test "bootstrap generates an age identity when IRIS_AGE_KEY_FILE is missing" {
  KEY="$TMP/new_iris_age_key"
  [ ! -f "$KEY" ]
  run env \
    IRIS_CONFIG="$IRIS_CONFIG" \
    IRIS_HOST_IP="127.0.0.1" \
    IRIS_AGE_KEY_FILE="$KEY" \
    IRIS_AGE_BIN="$TMP/fake-age" \
    IRIS_AGE_RECIPIENTS="" \
    bash "$BOOTSTRAP"
  [ "$status" -eq 0 ]
  [ -f "$KEY" ]
}

# ---------------------------------------------------------------------------
# Test: prints next-step guidance (recipient, key file location)
# ---------------------------------------------------------------------------
@test "bootstrap prints next-step guidance" {
  run_bootstrap
  [ "$status" -eq 0 ]
  [[ "$output" == *"IRIS_AGE_RECIPIENTS"* ]]
  [[ "$output" == *"PROTECT AND BACK UP"* ]]
  [[ "$output" == *"tls/crt.pem"* ]]
}

# ---------------------------------------------------------------------------
# Test: unknown argument returns exit code 2
# ---------------------------------------------------------------------------
@test "unknown argument returns exit code 2" {
  run env IRIS_CONFIG="$IRIS_CONFIG" bash "$BOOTSTRAP" --bad-arg
  [ "$status" -eq 2 ]
}

@test "invalid public host fails before bootstrap writes state" {
  BAD_CONFIG="$TMP/bad-config"
  run env IRIS_CONFIG="$BAD_CONFIG" IRIS_HOST_IP="REPLACE_WITH_STATIC_EXTERNAL_IP" \
      IRIS_AGE_KEY_FILE="$TMP/iris_age_key" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_RECIPIENTS="age1testrecipient" bash "$BOOTSTRAP"
  [ "$status" -ne 0 ]
  [[ "$output" == *"valid device-reachable IPv4"* ]]
  [ ! -e "$BAD_CONFIG/secrets.json.age" ]
}
