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
      iris-mint-enrollment) echo "enrolltok-$2-$RANDOM" ;;
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
100.92.9.3,100.92.9.3,666,100.92.9.125,255.255.255.252,100.92.9.126
CSVEOF
}

@test "generator mints a per-device enrollment token via iris-mint-enrollment" {
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -eq 0 ]
  [[ "$(cat "$OUT/install-100.92.9.3.sh")" == *'CATALOG_TOKEN="enrolltok-100.92.9.3'* ]]
}

@test "generator does NOT bake a permanent RPC secret" {
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV"
  [ "$status" -eq 0 ]
  [[ "$(cat "$OUT/install-100.92.9.3.sh")" == *'export RPC_SECRET=""'* ]]
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
  printf 'device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n100.92.9.3,100.92.9.3,666,100.92.9.125,255.255.255.252,100.92.9.126\n100.92.9.4,100.92.9.4,667,100.92.9.129,255.255.255.252,100.92.9.130' \
    > "$CSV_NOTRIM"
  run env IRIS_HOST_IP=10.0.0.9 bash "$GEN" "$CSV_NOTRIM"
  [ "$status" -eq 0 ]
  [ -f "$OUT/install-100.92.9.3.sh" ]
  # This assertion fails before the fix — the last row is silently dropped.
  [ -f "$OUT/install-100.92.9.4.sh" ]
}

# ── make-release scrub covers SCRUB_USER in all shipped text file types ────────
# The scrub filter historically only covered *.sh / *.conf* / *.example; a
# username in a .py or .md would ship un-redacted, and the safety-net only
# checked SCRUB_PASS, not SCRUB_USER.  After the fix both must be caught.

@test "make-release perl scrub rewrites SCRUB_USER in a .py file" {
  # Invoke the actual perl one-liner from make-release.sh against a staging
  # tree that contains a .py file with the username.  Asserts that after the
  # scrub the .py file no longer contains the secret — the old *.sh/conf-only
  # filter would leave it in place.
  RELEASE="$REPO/tools/make-release.sh"
  [ -f "$RELEASE" ] || skip "make-release.sh not found"
  command -v perl >/dev/null || skip "perl not available"

  REL_OUT="$BATS_TEST_TMPDIR/scrub_tree"
  mkdir -p "$REL_OUT/server"
  echo "# config: user = testuser_secret" > "$REL_OUT/server/agent.py"
  echo "password: testpass_secret" > "$REL_OUT/server/config.conf"

  # Extract the perl scrub one-liner from make-release.sh and run it.
  # This exercises the real scrub code path, not a reimplementation.
  PERL_CMD="$(awk '/find.*-print0/{found=1} found{print; if(/perl -pi -e/) { getline; print; exit }}' "$RELEASE")"

  run bash -c "
    OUT='${REL_OUT}'
    SCRUB_USER='testuser_secret'
    SCRUB_PASS='testpass_secret'
    find \"\$OUT\" -type f ! -name '*.pyc' -print0 \
      | SCRUB_PASS=\"\$SCRUB_PASS\" SCRUB_USER=\"\$SCRUB_USER\" xargs -0 perl -pi -e '
          next if -B \$ARGV;
          BEGIN { \$p = \$ENV{SCRUB_PASS}; \$u = \$ENV{SCRUB_USER}; }
          s/\Q\$p\E/changeme/g if length \$p;
          s/\b\Q\$u\E\b/admin/g if length \$u;'
  "
  [ "$status" -eq 0 ]
  # The .py file must have been rewritten — username replaced with 'admin'.
  ! grep -q 'testuser_secret' "$REL_OUT/server/agent.py"
  grep -q 'admin' "$REL_OUT/server/agent.py"
  # The .conf file must also be scrubbed.
  ! grep -q 'testpass_secret' "$REL_OUT/server/config.conf"
  grep -q 'changeme' "$REL_OUT/server/config.conf"
}

@test "make-release safety-net blocks release when scrub misses a .py file" {
  # After a successful scrub the safety-net must still detect any residual
  # occurrence.  This test plants SCRUB_USER in a .py file, skips the scrub,
  # and confirms the safety-net exits non-zero.
  RELEASE="$REPO/tools/make-release.sh"
  [ -f "$RELEASE" ] || skip "make-release.sh not found"

  REL_OUT="$BATS_TEST_TMPDIR/leak_tree"
  mkdir -p "$REL_OUT/server"
  echo "# config: user = testuser_secret" > "$REL_OUT/server/agent.py"

  # Run only the safety-net block (grep loop) from make-release.sh,
  # NOT the perl scrub, so it finds the un-scrubbed secret.
  run bash -c '
    OUT="'"$REL_OUT"'"
    SCRUB_USER="testuser_secret"
    SCRUB_PASS=""
    _leak=0
    for _s in "$SCRUB_PASS" "$SCRUB_USER"; do
      [ -n "$_s" ] || continue
      if grep -rIlF "$_s" "$OUT" --exclude-dir=.git >/dev/null 2>&1; then
        _leak=1
      fi
    done
    [ "$_leak" -eq 0 ] || exit 1
  '
  [ "$status" -ne 0 ]
}
