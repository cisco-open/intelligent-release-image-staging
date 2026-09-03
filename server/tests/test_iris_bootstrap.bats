#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for server/iris-bootstrap.
#
# Strategy: stub age / age-keygen so the test never needs the real binaries,
# and stub openssl so the test does not require rsa:4096 generation time.
# The fake age (same pattern as test_entrypoint_secretfs.bats): encrypt
# prepends an "AGEFAKE <recipients>" header line, decrypt strips it — but only
# when the identity file's "# public key:" is one of the recorded recipients,
# so the bootstrap's post-write round-trip check behaves like real age.
# The fake openssl generates a tiny placeholder file so the bootstrap's -x509
# step succeeds instantly.  The fake age-keygen writes a deterministic
# identity file.

setup() {
  TMP="$(mktemp -d)"
  IRIS_CONFIG="$TMP/etc/iris"
  mkdir -p "$IRIS_CONFIG/tls"

  # ---- fake age (encrypt/decrypt) ----
  cat > "$TMP/fake-age" <<'EOFA'
#!/usr/bin/env bash
set -euo pipefail
mode="$1"; [ "$mode" = "-d" ] && shift
out=""; inp=""; ident=""; recipients=()
if [ "$mode" = "-d" ]; then
  while [ "$#" -gt 0 ]; do case "$1" in
    -i) ident="$2"; shift 2 ;; -o) out="$2"; shift 2 ;; *) inp="$1"; shift ;; esac; done
  hdr="$(head -n1 "$inp" || true)"
  case "$hdr" in AGEFAKE*) ;; *) echo "fake-age: bad ciphertext" >&2; exit 1 ;; esac
  pub="$(grep '^# public key:' "$ident" | awk '{print $NF}')"
  recs="${hdr#AGEFAKE}"; recs="${recs# }"
  case ",$recs," in *",$pub,"*) ;; *) echo "fake-age: no identity matched" >&2; exit 1 ;; esac
  tail -n +2 "$inp" > "$out"
else
  while [ "$#" -gt 0 ]; do case "$1" in
    -r) recipients+=("$2"); shift 2 ;; -o) out="$2"; shift 2 ;; *) inp="$1"; shift ;; esac; done
  { echo "AGEFAKE $(IFS=,; echo "${recipients[*]}")"; cat "$inp"; } > "$out"
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
# Test: --force is disaster recovery and needs --yes
# ---------------------------------------------------------------------------
# Rewritten for IRIS-13-003: --force alone used to wipe every device token and
# rotate the pinned certificate silently; it now refuses until --yes is given.
@test "--force without --yes refuses, names what it would destroy, and changes nothing" {
  run_bootstrap
  [ "$status" -eq 0 ]
  before="$(cat "$IRIS_CONFIG/secrets.json.age" "$IRIS_CONFIG/rpc-secret.age" "$IRIS_CONFIG/tls/key.pem.age" "$IRIS_CONFIG/tls/crt.pem" | sha256sum)"
  run_bootstrap --force
  [ "$status" -ne 0 ]
  [[ "$output" == *"--yes"* ]]
  [[ "$output" == *"device catalog token"* ]]
  [[ "$output" == *"certificate"* ]]
  [[ "$output" == *"--rekey"* ]]
  after="$(cat "$IRIS_CONFIG/secrets.json.age" "$IRIS_CONFIG/rpc-secret.age" "$IRIS_CONFIG/tls/key.pem.age" "$IRIS_CONFIG/tls/crt.pem" | sha256sum)"
  [ "$before" = "$after" ]
}

@test "--force --yes overwrites existing .age files" {
  run_bootstrap
  [ "$status" -eq 0 ]
  # Corrupt one file to confirm --force --yes regenerates
  printf 'CORRUPTED\n' > "$IRIS_CONFIG/secrets.json.age"
  run_bootstrap --force --yes
  [ "$status" -eq 0 ]
  [[ "$output" == *"WARNING"* ]]
  # secrets.json.age must now be valid again
  "$TMP/fake-age" -d -i "$TMP/iris_age_key" -o "$TMP/secrets2.json" \
    "$IRIS_CONFIG/secrets.json.age"
  python3 -c "import json; d=json.load(open('$TMP/secrets2.json')); assert 'seeder' in d"
}

# ---------------------------------------------------------------------------
# Helpers for the re-key / repair / corruption tests
# ---------------------------------------------------------------------------
PRIMARY_PUB="age1fakerecipient000000000000000000000000000000000000000000"
BREAKGLASS_PUB="age1breakglass0000000000000000000000000000000000000000000000"

# Bootstrap, then mint a device token with the real secrets_store so the store
# holds fleet state that a wipe would destroy.
seed_store_with_device() {
  run_bootstrap
  [ "$status" -eq 0 ]
  "$TMP/fake-age" -d -i "$TMP/iris_age_key" -o "$TMP/plain.json" "$IRIS_CONFIG/secrets.json.age"
  PYTHONPATH="$BATS_TEST_DIRNAME/.." python3 - "$TMP/plain.json" <<'PY'
import sys, time, secrets_store
s = secrets_store.load(sys.argv[1])
secrets_store.mint(s, "switch-01", "catalog_token", int(time.time()))
secrets_store.save(s, sys.argv[1])
PY
  "$TMP/fake-age" -r "$PRIMARY_PUB" -o "$IRIS_CONFIG/secrets.json.age" "$TMP/plain.json"
  rm -f "$TMP/plain.json"
}

decrypted_devices() {
  "$TMP/fake-age" -d -i "$TMP/iris_age_key" -o "$TMP/out.json" "$IRIS_CONFIG/secrets.json.age"
  python3 -c "import json; d=json.load(open('$TMP/out.json')); print(sorted(d.get('devices', {}).keys()))"
}

# ---------------------------------------------------------------------------
# Test: --rekey adds a recipient and preserves every secret (IRIS-13-003)
# ---------------------------------------------------------------------------
@test "--rekey re-encrypts existing state to the new recipient set without regenerating anything" {
  seed_store_with_device
  rpc_before="$(tail -n +2 "$IRIS_CONFIG/rpc-secret.age")"
  key_before="$(tail -n +2 "$IRIS_CONFIG/tls/key.pem.age")"
  crt_before="$(sha256sum < "$IRIS_CONFIG/tls/crt.pem")"
  # A console-written GUI key must ride along too.
  printf 'GUI-KEY\n' > "$TMP/gui-key.pem"
  "$TMP/fake-age" -r "$PRIMARY_PUB" -o "$IRIS_CONFIG/tls/gui-key.pem.age" "$TMP/gui-key.pem"

  run env IRIS_CONFIG="$IRIS_CONFIG" IRIS_HOST_IP="127.0.0.1" \
      IRIS_AGE_KEY_FILE="$TMP/iris_age_key" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_RECIPIENTS="$PRIMARY_PUB,$BREAKGLASS_PUB" bash "$BOOTSTRAP" --rekey
  [ "$status" -eq 0 ]
  [[ "$output" != *"generating"* ]]
  [[ "$output" != *"minting"* ]]

  # Every file now names both recipients and still holds the SAME plaintext.
  for f in secrets.json.age rpc-secret.age tls/key.pem.age tls/gui-key.pem.age; do
    hdr="$(head -n1 "$IRIS_CONFIG/$f")"
    [[ "$hdr" == *"$BREAKGLASS_PUB"* ]] || { echo "$f not re-encrypted to break-glass: $hdr"; return 1; }
    [[ "$hdr" == *"$PRIMARY_PUB"* ]]    || { echo "$f lost the primary recipient: $hdr"; return 1; }
    [ ! -e "$IRIS_CONFIG/$f.rekey.tmp" ]
  done
  [ "$(decrypted_devices)" = "['switch-01']" ]
  [ "$(tail -n +2 "$IRIS_CONFIG/rpc-secret.age")"  = "$rpc_before" ]
  [ "$(tail -n +2 "$IRIS_CONFIG/tls/key.pem.age")" = "$key_before" ]
  [ "$(sha256sum < "$IRIS_CONFIG/tls/crt.pem")"    = "$crt_before" ]
  [ "$(tail -n +2 "$IRIS_CONFIG/tls/gui-key.pem.age")" = "GUI-KEY" ]
}

@test "--add-recipient is an alias for --rekey" {
  run_bootstrap
  [ "$status" -eq 0 ]
  run env IRIS_CONFIG="$IRIS_CONFIG" IRIS_HOST_IP="127.0.0.1" \
      IRIS_AGE_KEY_FILE="$TMP/iris_age_key" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_RECIPIENTS="$PRIMARY_PUB,$BREAKGLASS_PUB" bash "$BOOTSTRAP" --add-recipient
  [ "$status" -eq 0 ]
  [[ "$(head -n1 "$IRIS_CONFIG/rpc-secret.age")" == *"$BREAKGLASS_PUB"* ]]
}

@test "--rekey to a recipient set that excludes the identity fails closed and leaves the old files intact" {
  seed_store_with_device
  before="$(cat "$IRIS_CONFIG/secrets.json.age" "$IRIS_CONFIG/rpc-secret.age" "$IRIS_CONFIG/tls/key.pem.age" | sha256sum)"
  run env IRIS_CONFIG="$IRIS_CONFIG" IRIS_HOST_IP="127.0.0.1" \
      IRIS_AGE_KEY_FILE="$TMP/iris_age_key" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_RECIPIENTS="$BREAKGLASS_PUB" bash "$BOOTSTRAP" --rekey
  [ "$status" -ne 0 ]
  [[ "$output" == *"IRIS_AGE_RECIPIENTS"* ]]
  after="$(cat "$IRIS_CONFIG/secrets.json.age" "$IRIS_CONFIG/rpc-secret.age" "$IRIS_CONFIG/tls/key.pem.age" | sha256sum)"
  [ "$before" = "$after" ]
  [ -z "$(ls "$IRIS_CONFIG" "$IRIS_CONFIG/tls" | grep '\.rekey\.tmp$' || true)" ]
}

@test "bootstrap guidance recommends --rekey, not --force, for the break-glass recipient" {
  run_bootstrap
  [ "$status" -eq 0 ]
  [[ "$output" == *"iris-bootstrap --rekey"* ]]
  [[ "$output" != *"iris-bootstrap --force"* ]]
}

# ---------------------------------------------------------------------------
# Test: partial state is refused, --repair regenerates one file (IRIS-13-004)
# ---------------------------------------------------------------------------
@test "a missing rpc-secret.age with the other files present refuses instead of regenerating everything" {
  seed_store_with_device
  crt_before="$(sha256sum < "$IRIS_CONFIG/tls/crt.pem")"
  rm -f "$IRIS_CONFIG/rpc-secret.age"
  run_bootstrap
  [ "$status" -ne 0 ]
  [[ "$output" == *"partial state"* ]]
  [[ "$output" == *"missing: rpc-secret"* ]]
  [[ "$output" == *"--repair"* ]]
  [[ "$output" == *"device catalog token"* ]]
  [ ! -e "$IRIS_CONFIG/rpc-secret.age" ]
  [ "$(decrypted_devices)" = "['switch-01']" ]
  [ "$(sha256sum < "$IRIS_CONFIG/tls/crt.pem")" = "$crt_before" ]
}

@test "--repair rpc-secret regenerates only that file" {
  seed_store_with_device
  crt_before="$(sha256sum < "$IRIS_CONFIG/tls/crt.pem")"
  key_before="$(sha256sum < "$IRIS_CONFIG/tls/key.pem.age")"
  rm -f "$IRIS_CONFIG/rpc-secret.age"
  run_bootstrap --repair rpc-secret
  [ "$status" -eq 0 ]
  [ -s "$IRIS_CONFIG/rpc-secret.age" ]
  "$TMP/fake-age" -d -i "$TMP/iris_age_key" -o "$TMP/rpc" "$IRIS_CONFIG/rpc-secret.age"
  [ -s "$TMP/rpc" ]
  [ "$(decrypted_devices)" = "['switch-01']" ]
  [ "$(sha256sum < "$IRIS_CONFIG/tls/crt.pem")"     = "$crt_before" ]
  [ "$(sha256sum < "$IRIS_CONFIG/tls/key.pem.age")" = "$key_before" ]
}

@test "--repair refuses when the named file already exists" {
  run_bootstrap
  [ "$status" -eq 0 ]
  before="$(sha256sum < "$IRIS_CONFIG/rpc-secret.age")"
  run_bootstrap --repair rpc-secret
  [ "$status" -ne 0 ]
  [[ "$output" == *"already exists"* ]]
  [ "$(sha256sum < "$IRIS_CONFIG/rpc-secret.age")" = "$before" ]
}

@test "--repair with an unknown file name returns exit code 2" {
  run env IRIS_CONFIG="$IRIS_CONFIG" bash "$BOOTSTRAP" --repair crt.pem
  [ "$status" -eq 2 ]
}

# ---------------------------------------------------------------------------
# Test: corrupt state is named, not reported as "nothing to do" (IRIS-13-013)
# ---------------------------------------------------------------------------
@test "an empty .age file is an error naming the file, not 'nothing to do'" {
  run_bootstrap
  [ "$status" -eq 0 ]
  : > "$IRIS_CONFIG/secrets.json.age"
  run_bootstrap
  [ "$status" -ne 0 ]
  [[ "$output" == *"secrets.json.age"* ]]
  [[ "$output" == *"empty"* ]]
  [[ "$output" != *"nothing to do"* ]]
}

@test "an .age file the mounted identity cannot decrypt is an error naming the file" {
  run_bootstrap
  [ "$status" -eq 0 ]
  printf 'GARBAGE\n' > "$IRIS_CONFIG/tls/key.pem.age"
  run_bootstrap
  [ "$status" -ne 0 ]
  [[ "$output" == *"tls/key.pem.age"* ]]
  [[ "$output" == *"cannot be decrypted"* ]]
  [[ "$output" != *"nothing to do"* ]]
}

@test "a fresh bootstrap whose recipients exclude the identity fails with a clear message" {
  run env IRIS_CONFIG="$IRIS_CONFIG" IRIS_HOST_IP="127.0.0.1" \
      IRIS_AGE_KEY_FILE="$TMP/iris_age_key" IRIS_AGE_BIN="$TMP/fake-age" \
      IRIS_AGE_RECIPIENTS="$BREAKGLASS_PUB" bash "$BOOTSTRAP"
  [ "$status" -ne 0 ]
  [[ "$output" == *"does not decrypt with"* ]]
  [[ "$output" == *"IRIS_AGE_RECIPIENTS"* ]]
  [[ "$output" != *"Bootstrap complete"* ]]
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

# ---------------------------------------------------------------------------
# Test: durable CA trust dir is provisioned alongside the tls dir
# ---------------------------------------------------------------------------
@test "bootstrap creates the durable CA trust dir" {
  run_bootstrap
  [ "$status" -eq 0 ]
  [ -d "$IRIS_CONFIG/tls/trust" ]
}
