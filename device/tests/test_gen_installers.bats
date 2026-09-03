#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  GEN="$REPO/tools/gen-device-installers.sh"
  WORK="$BATS_TEST_TMPDIR/work"
  BIN="$WORK/bin"
  mkdir -p "$BIN" "$WORK/fleet/dist"

  # A stub `docker` that emulates the running iris container. `docker ps` lists
  # `iris`; `docker exec iris cat /etc/iris/<f>` serves the secrets the generator
  # reads; `docker exec iris iris-mint-enrollment <id>` prints a fresh token line.
  cat > "$BIN/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  ps) echo iris ;;
  exec)
    # $2 = iris, $3.. = the command run inside the container
    shift 2
    case "$1" in
      cat)
        case "$2" in
          /etc/iris/rpc-secret) echo "rpc-from-container" ;;
          /etc/iris/tls/crt.pem) printf -- '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n' ;;
          *) exit 1 ;;
        esac ;;
      # Enrollment tokens are 32 hexadecimal characters, as minted by the
      # real secrets store.
      iris-mint-enrollment) echo "0123456789abcdef0123456789abcdef" ;;
      *) exit 1 ;;
    esac ;;
  restart) : ;;
  *) exit 1 ;;
esac
STUB
  chmod +x "$BIN/docker"

  cat > "$BIN/hostname" <<'STUB'
#!/usr/bin/env bash
echo "10.0.0.9"
STUB
  chmod +x "$BIN/hostname"

  export PATH="$BIN:$PATH"

  # Isolate generated installers from the live repo tree.
  export OUT="$BATS_TEST_TMPDIR/dist"
  mkdir -p "$OUT"

  # Point the generator at a CSV in our temp repo-like dir and an isolated OUT.
  CSV="$WORK/devices.csv"
  cat > "$CSV" <<'CSVEOF'
device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip
203.0.113.3,203.0.113.3,666,203.0.113.125,255.255.255.252,203.0.113.126
CSVEOF
}

@test "generator mints a per-device enrollment token via iris-mint-enrollment" {
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -eq 0 ]
  [[ "$(cat "$OUT/install-203.0.113.3.sh")" == *'CATALOG_TOKEN=0123456789abcdef0123456789abcdef'* ]]
}

@test "generator does NOT bake a permanent RPC secret" {
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -eq 0 ]
  [[ "$(cat "$OUT/install-203.0.113.3.sh")" == *'export RPC_SECRET=""'* ]]
}

@test "generator no longer writes a device-tokens.txt registry" {
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -eq 0 ]
  [[ "$output" != *"new token registered"* ]]
  [[ "$output" != *"device-tokens.txt"* ]]
}

# ── CSV without trailing newline ──────────────────────────────────────────────
# A 2-row CSV whose last data row has NO trailing newline must still produce 2
# installers. The `while read -r` idiom silently drops such rows; the fix is
# `while read -r ... || [ -n "$device_id" ]`.

@test "generator processes last CSV row when file has no trailing newline" {
  CSV_NOTRIM="$BATS_TEST_TMPDIR/notrim.csv"
  # Two data rows; printf omits the final newline on the second row.
  printf 'device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n203.0.113.3,203.0.113.3,666,203.0.113.125,255.255.255.252,203.0.113.126\n203.0.113.4,203.0.113.4,667,203.0.113.129,255.255.255.252,203.0.113.130' \
    > "$CSV_NOTRIM"
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV_NOTRIM"
  [ "$status" -eq 0 ]
  [ -f "$OUT/install-203.0.113.3.sh" ]
  # This assertion fails before the fix — the last row is silently dropped.
  [ -f "$OUT/install-203.0.113.4.sh" ]
}

@test "generator rejects a CSV field containing a shell quote" {
  CSV_UNSAFE="$BATS_TEST_TMPDIR/unsafe.csv"
  cat > "$CSV_UNSAFE" <<'CSVEOF'
device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip
unsafe"device,203.0.113.3,666,203.0.113.125,255.255.255.252,203.0.113.126
CSVEOF

  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV_UNSAFE"
  [ "$status" -ne 0 ]
  [[ "$output" == *"ERROR: device_id has an invalid format"* ]]
  [ ! -e "$OUT/install-unsafe\"device.sh" ]
}

# ── whole-CSV validation before minting; private, transactional output ─────────
# Before the fix the generator validated -> minted -> wrote one row at a time, so
# an invalid row 2 left install-sw1.sh (with a freshly minted token) on disk,
# world-readable (0755), next to an install-all.sh listing only sw1; a duplicate
# device id re-minted and overwrote silently; installers from an earlier CSV
# lingered in fleet/dist/.

# Replace the docker stub with one that also records every mint.
_mint_logging_stub() {
  export MINT_LOG="$WORK/mints.log"; : > "$MINT_LOG"
  cat > "$BIN/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  ps) echo iris ;;
  exec)
    shift 2
    case "$1" in
      cat) [ "$2" = /etc/iris/tls/crt.pem ] && printf -- '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n' ;;
      iris-mint-enrollment) echo "$2" >> "$MINT_LOG"; echo "0123456789abcdef0123456789abcdef" ;;
      *) exit 1 ;;
    esac ;;
  *) exit 1 ;;
esac
STUB
}

@test "an invalid later row mints nothing and writes nothing" {
  _mint_logging_stub
  cat > "$CSV" <<'CSVEOF'
device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip
sw1,203.0.113.3,666,203.0.113.125,255.255.255.252,203.0.113.126
sw2,203.0.113.4,667,203.0.113.129,255.255.255.252,203.0.113.130,,extra-column
sw3,203.0.113.5,668,203.0.113.133,255.255.255.252,203.0.113.134
CSVEOF
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -ne 0 ]
  [[ "$output" == *"line 3: expected 6 columns"* ]]
  [ ! -s "$MINT_LOG" ]
  [ ! -e "$OUT/install-sw1.sh" ]
  [ ! -e "$OUT/install-all.sh" ]
}

@test "a duplicate device_id is rejected before anything is minted" {
  _mint_logging_stub
  cat > "$CSV" <<'CSVEOF'
device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip
sw1,203.0.113.3,666,203.0.113.125,255.255.255.252,203.0.113.126
sw1,203.0.113.4,667,203.0.113.129,255.255.255.252,203.0.113.130
CSVEOF
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -ne 0 ]
  [[ "$output" == *"duplicate device_id 'sw1'"* ]]
  [ ! -s "$MINT_LOG" ]
  [ ! -e "$OUT/install-sw1.sh" ]
}

@test "installers carrying an enrollment token are written 0700, as is install-all.sh" {
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -eq 0 ]
  [ "$(stat -c %a "$OUT/install-203.0.113.3.sh")" = "700" ]
  [ "$(stat -c %a "$OUT/install-all.sh")" = "700" ]
}

@test "installers for devices no longer in the CSV are purged; output is a whole set" {
  echo "stale" > "$OUT/install-gone.sh"
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -eq 0 ]
  [ ! -e "$OUT/install-gone.sh" ]
  [ -f "$OUT/install-203.0.113.3.sh" ]
  grep -q 'install-203.0.113.3.sh' "$OUT/install-all.sh"
  run grep -q 'install-gone.sh' "$OUT/install-all.sh"
  [ "$status" -ne 0 ]
  run ls -A "$(dirname "$OUT")"
  [[ "$output" != *".dist.tmp"* ]]
}

@test "the generator refuses to replace an output directory holding files it did not create" {
  echo "keep me" > "$OUT/operator-notes.txt"
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -ne 0 ]
  [[ "$output" == *"refusing to replace"* ]]
  [ -f "$OUT/operator-notes.txt" ]
}
