#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  TMP="$(mktemp -d)"
  export IRIS_ROOT="$TMP/opt/iris"
  export IRIS_STATE="$TMP/var/lib/iris"
  export IRIS_CONFIG="$TMP/etc/iris"
  export IRIS_LOG="$TMP/var/log/iris"
  export SYSTEMD_DIR="$TMP/etc/systemd/system"
  export LOGROTATE_DIR="$TMP/etc/logrotate.d"
  export SKIP_PRIVILEGED=1            # no useradd / systemctl / chown
  INSTALL="$BATS_TEST_DIRNAME/../install.sh"

  # ---- stub binaries so install.sh (which calls iris-bootstrap) runs without
  # needing real age / age-keygen / a 4096-bit RSA key ----

  # fake age (same pattern as test_entrypoint_secretfs.bats / test_iris_bootstrap.bats)
  cat > "$TMP/age" <<'EOFA'
#!/usr/bin/env bash
set -euo pipefail
mode="$1"; shift; out=""; inp=""
if [ "$mode" = "-d" ]; then
  while [ "$#" -gt 0 ]; do case "$1" in
    -i) shift 2 ;; -o) out="$2"; shift 2 ;; *) inp="$1"; shift ;; esac; done
  head -n1 "$inp" | grep -q '^AGEFAKE$' || { echo "fake-age: bad" >&2; exit 1; }
  tail -n +2 "$inp" > "$out"
else
  while [ "$#" -gt 0 ]; do case "$1" in
    -r) shift 2 ;; -o) out="$2"; shift 2 ;; *) inp="$1"; shift ;; esac; done
  { echo "AGEFAKE"; cat "$inp"; } > "$out"
fi
EOFA
  chmod +x "$TMP/age"

  cat > "$TMP/age-keygen" <<'EOFK'
#!/usr/bin/env bash
set -euo pipefail
out=""
while [ "$#" -gt 0 ]; do case "$1" in
  -o) out="$2"; shift 2 ;; *) shift ;; esac; done
[ -n "$out" ] || { echo "fake-age-keygen: -o required" >&2; exit 1; }
printf '# created: 2026-01-01T00:00:00Z\n# public key: age1fakekey000000000000000000000000000000000000000000000000\nAGE-SECRET-KEY-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK\n' > "$out"
EOFK
  chmod +x "$TMP/age-keygen"

  cat > "$TMP/openssl" <<'EOFO'
#!/usr/bin/env bash
set -euo pipefail
cmd="$1"; shift
if [ "$cmd" = "rand" ]; then
  printf '%064x\n' 99999999999999999999
elif [ "$cmd" = "req" ]; then
  keyout=""; out=""
  while [ "$#" -gt 0 ]; do case "$1" in
    -keyout) keyout="$2"; shift 2 ;; -out) out="$2"; shift 2 ;; *) shift ;; esac; done
  [ -n "$keyout" ] && printf 'FAKE-KEY\n' > "$keyout"
  [ -n "$out" ]    && printf 'FAKE-CERT\n' > "$out"
else
  echo "fake-openssl: unknown $cmd" >&2; exit 1
fi
EOFO
  chmod +x "$TMP/openssl"

  export PATH="$TMP:$PATH"

  # Drive install.sh's OWN default key location, but rooted under TMP so the
  # test never writes to /etc/iris-key. install.sh defaults
  # IRIS_AGE_KEY_FILE to $IRIS_KEY_DIR/.iris_age_key, so we only set the dir.
  export IRIS_KEY_DIR="$TMP/etc/iris-key"
  export IRIS_AGE_RECIPIENTS=""
  export IRIS_AGE_BIN="$TMP/age"
}

teardown() { rm -rf "$TMP"; }

@test "dry-run makes no changes" {
  run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [ ! -d "$IRIS_ROOT" ]
}

@test "install creates layout, .age files, crt.pem, and no tokens.txt" {
  run bash "$INSTALL"
  [ "$status" -eq 0 ]
  [ -f "$IRIS_ROOT/server/tracker.py" ]
  # bootstrap created the encrypted files
  [ -f "$IRIS_CONFIG/secrets.json.age"  ]
  [ -f "$IRIS_CONFIG/rpc-secret.age"    ]
  [ -f "$IRIS_CONFIG/tls/key.pem.age"   ]
  [ -f "$IRIS_CONFIG/tls/crt.pem"       ]
  # NO plaintext secrets on the volume
  [ ! -f "$IRIS_CONFIG/rpc-secret"      ]
  [ ! -f "$IRIS_CONFIG/secrets.json"    ]
  [ ! -f "$IRIS_CONFIG/tls/key.pem"     ]
  # tokens.txt is retired
  [ ! -f "$IRIS_CONFIG/tokens.txt"      ]
  [ -f "$SYSTEMD_DIR/iris-tracker.service" ]
}

@test "re-run is idempotent (does not overwrite .age files)" {
  bash "$INSTALL"
  age_sz1="$(wc -c < "$IRIS_CONFIG/secrets.json.age")"
  bash "$INSTALL"
  age_sz2="$(wc -c < "$IRIS_CONFIG/secrets.json.age")"
  [ "$age_sz1" = "$age_sz2" ]
}

@test "uninstall removes code/config but keeps state" {
  bash "$INSTALL"
  mkdir -p "$IRIS_STATE/torrents"
  echo keep > "$IRIS_STATE/torrents/x.torrent"
  run bash "$INSTALL" --uninstall
  [ "$status" -eq 0 ]
  [ ! -d "$IRIS_ROOT" ]
  [ -f "$IRIS_STATE/torrents/x.torrent" ]
}

# ---------------------------------------------------------------------------
# Finding 4 (security): the age master PRIVATE key must NOT be co-resident
# with the ciphertext it opens. install.sh must default the key OUTSIDE
# $IRIS_CONFIG and must NOT chown it into the service-user-owned config dir.
# ---------------------------------------------------------------------------
@test "install.sh does NOT default the age key inside the config dir" {
  ! grep -Eq 'IRIS_AGE_KEY_FILE:?-\$?\{?IRIS_CONFIG\}?/' "$INSTALL"
}

@test "install.sh recursive chown of the config dir does NOT sweep in the age key" {
  # the recursive chown that covers $IRIS_CONFIG must not also cover the key
  run grep -nE 'chown -R.*IRIS_CONFIG' "$INSTALL"
  [ "$status" -eq 0 ]
  [[ "$output" != *'IRIS_AGE_KEY_FILE'* ]]
  [[ "$output" != *'IRIS_KEY_DIR'* ]]
}

@test "install: the age master key lands OUTSIDE the config dir" {
  run bash "$INSTALL"
  [ "$status" -eq 0 ]
  # default key dir is $TMP/etc/iris-key (set via IRIS_KEY_DIR in setup), not under $IRIS_CONFIG
  [ -f "$IRIS_KEY_DIR/.iris_age_key" ]
  [ ! -f "$IRIS_CONFIG/.iris_age_key" ]
}

# ---------------------------------------------------------------------------
# Finding 1: install.sh must install the iris-secretfs unseal helper (the
# units invoke it via ExecStartPre to decrypt the *.age ciphertext to tmpfs)
# and mark it executable.
# ---------------------------------------------------------------------------
@test "install marks iris-secretfs helper executable" {
  run bash "$INSTALL"
  [ "$status" -eq 0 ]
  [ -x "$IRIS_ROOT/server/iris-secretfs" ]
}
