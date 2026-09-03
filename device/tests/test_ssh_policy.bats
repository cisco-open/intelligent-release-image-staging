#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# lab/iris-ssh-policy.sh is the ONE trust policy behind every ssh/scp session
# IRIS opens (device-run.sh, xr-run.sh, the installers' stage-host push and
# the XR scp). Before it existed, every session ran StrictHostKeyChecking=no
# with UserKnownHostsFile=/dev/null, appended SHA-1/CBC/ssh-rsa algorithms
# unconditionally, and discarded ssh's stderr -- so the device password was
# typed into whatever answered at the address and "connection refused",
# "no matching KEX" and "host key changed" were indistinguishable.
#
# The stubbed sshpass records its argv and emits FAKE_STDERR on stderr, so
# these tests pin the options the transports pass and the diagnostics they
# forward, without opening a socket.
#
# `|| return 1` is load-bearing: under bash 3.2 a bare failing `[[ ]]` mid-body
# does NOT fail a bats test.

setup() {
  LAB="$BATS_TEST_DIRNAME/../../lab"
  STUB="$BATS_TEST_TMPDIR/bin"; mkdir -p "$STUB"
  ARGV_LOG="$BATS_TEST_TMPDIR/argv.log"; : > "$ARGV_LOG"
  export ARGV_LOG
  export TMPDIR="$BATS_TEST_TMPDIR"
  export IRIS_STATE="$BATS_TEST_TMPDIR/state"
  export DEVICE_USER=u DEVICE_PASS=zzsecretzz
  unset IRIS_SSH_KNOWN_HOSTS IRIS_SSH_HOST_KEY IRIS_SSH_LEGACY IRIS_SSH_STATE_DIR
  cat > "$STUB/sshpass" <<'STUBEOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$ARGV_LOG"
cat > /dev/null
echo "sw1#terminal length 0"
if [ -n "${FAKE_STDERR:-}" ]; then printf '%s\n' "$FAKE_STDERR" >&2; fi
exit "${FAKE_SSH_STATUS:-0}"
STUBEOF
  chmod +x "$STUB/sshpass"
  export PATH="$STUB:$PATH"
}

run_dev() { run bash -c "printf 'show clock\n' | bash '$LAB/device-run.sh' 192.0.2.10"; }
run_xr()  { run bash -c "printf 'show version\n' | bash '$LAB/xr-run.sh' 192.0.2.10"; }

# ---- default mode: accept-new against a PERSISTENT known_hosts -------------

@test "device-run.sh never uses /dev/null as known_hosts and defaults to accept-new" {
  run_dev
  [ "$status" -eq 0 ] || return 1
  ! grep -q 'UserKnownHostsFile=/dev/null' "$ARGV_LOG" || return 1
  ! grep -q 'StrictHostKeyChecking=no' "$ARGV_LOG" || return 1
  grep -q -- '-o StrictHostKeyChecking=accept-new' "$ARGV_LOG" || return 1
  grep -q -- "-o UserKnownHostsFile=$IRIS_STATE/ssh/known_hosts" "$ARGV_LOG" || return 1
  [ -f "$IRIS_STATE/ssh/known_hosts" ]
}

@test "xr-run.sh uses the same persistent accept-new policy" {
  run_xr
  [ "$status" -eq 0 ] || return 1
  ! grep -q 'UserKnownHostsFile=/dev/null' "$ARGV_LOG" || return 1
  grep -q -- '-o StrictHostKeyChecking=accept-new' "$ARGV_LOG" || return 1
  grep -q -- "-o UserKnownHostsFile=$IRIS_STATE/ssh/known_hosts" "$ARGV_LOG"
}

@test "the state directory and known_hosts are private (0700 / 0600)" {
  run_dev
  [ "$status" -eq 0 ] || return 1
  [ "$(stat -c %a "$IRIS_STATE/ssh")" = "700" ] || return 1
  [ "$(stat -c %a "$IRIS_STATE/ssh/known_hosts")" = "600" ]
}

@test "IRIS_SSH_STATE_DIR overrides where the persistent known_hosts lives" {
  IRIS_SSH_STATE_DIR="$BATS_TEST_TMPDIR/elsewhere" run_dev
  [ "$status" -eq 0 ] || return 1
  grep -q -- "-o UserKnownHostsFile=$BATS_TEST_TMPDIR/elsewhere/known_hosts" "$ARGV_LOG"
}

# ---- pinned modes ----------------------------------------------------------

@test "IRIS_SSH_KNOWN_HOSTS switches to StrictHostKeyChecking=yes against that file" {
  printf '192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n' > "$BATS_TEST_TMPDIR/kh"
  IRIS_SSH_KNOWN_HOSTS="$BATS_TEST_TMPDIR/kh" run_dev
  [ "$status" -eq 0 ] || return 1
  grep -q -- '-o StrictHostKeyChecking=yes' "$ARGV_LOG" || return 1
  grep -q -- "-o UserKnownHostsFile=$BATS_TEST_TMPDIR/kh" "$ARGV_LOG" || return 1
  ! grep -q 'accept-new' "$ARGV_LOG"
}

@test "an unreadable IRIS_SSH_KNOWN_HOSTS refuses to connect rather than falling back" {
  IRIS_SSH_KNOWN_HOSTS="$BATS_TEST_TMPDIR/missing" run_dev
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"not readable"* ]] || return 1
  [ ! -s "$ARGV_LOG" ]
}

@test "IRIS_SSH_HOST_KEY pins exactly that key for the peer, in a private temp known_hosts" {
  IRIS_SSH_HOST_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE" run_dev
  [ "$status" -eq 0 ] || return 1
  grep -q -- '-o StrictHostKeyChecking=yes' "$ARGV_LOG" || return 1
  kh="$(sed -nE 's/.*-o UserKnownHostsFile=([^ ]+).*/\1/p' "$ARGV_LOG" | head -1)"
  [ -n "$kh" ] || return 1
  [[ "$kh" == "$BATS_TEST_TMPDIR"/iris-known-hosts.* ]] || return 1
  # cleaned up after the session
  [ ! -e "$kh" ]
}

@test "a malformed IRIS_SSH_HOST_KEY is refused" {
  IRIS_SSH_HOST_KEY="not-a-key" run_dev
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"not a public host key"* ]] || return 1
  [ ! -s "$ARGV_LOG" ]
}

@test "the pinned temp known_hosts holds '<peer> <key>'" {
  # drive the policy directly so the file can be inspected before cleanup
  run bash -c ". '$LAB/iris-ssh-policy.sh'; IRIS_SSH_HOST_KEY='ssh-rsa AAAAB3FAKE' iris_ssh_policy 192.0.2.10 && cat \"\$IRIS_SSH_KNOWN_HOSTS_FILE\" && [ \"\$(stat -c %a \"\$IRIS_SSH_KNOWN_HOSTS_FILE\")\" = 600 ] && iris_ssh_cleanup"
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == "192.0.2.10 ssh-rsa AAAAB3FAKE" ]]
}

# ---- legacy algorithms are opt-in ------------------------------------------

@test "legacy KEX/cipher/host-key additions are NOT sent by default" {
  run_dev
  [ "$status" -eq 0 ] || return 1
  ! grep -q 'diffie-hellman-group14-sha1' "$ARGV_LOG" || return 1
  ! grep -q 'HostKeyAlgorithms=+ssh-rsa' "$ARGV_LOG" || return 1
  ! grep -q '3des-cbc' "$ARGV_LOG"
}

@test "IRIS_SSH_LEGACY=1 opts in to the legacy algorithms" {
  IRIS_SSH_LEGACY=1 run_dev
  [ "$status" -eq 0 ] || return 1
  grep -q -- '-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1' "$ARGV_LOG" || return 1
  grep -q -- '-o HostKeyAlgorithms=+ssh-rsa' "$ARGV_LOG" || return 1
  grep -q -- '-o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc' "$ARGV_LOG"
}

# ---- ssh diagnostics are forwarded, redacted, and explained ----------------

@test "device-run.sh forwards ssh's stderr instead of discarding it" {
  run env FAKE_STDERR='ssh: connect to host 192.0.2.10 port 22: Connection refused' FAKE_SSH_STATUS=255 \
    bash -c "printf 'show clock\n' | bash '$LAB/device-run.sh' 192.0.2.10 2>&1 >/dev/null"
  [ "$status" -eq 255 ] || return 1
  [[ "$output" == *"Connection refused"* ]]
}

@test "xr-run.sh forwards ssh's stderr instead of discarding it" {
  run env FAKE_STDERR='Unable to negotiate with 192.0.2.10 port 22: no matching key exchange method found.' FAKE_SSH_STATUS=255 \
    bash -c "printf 'show version\n' | bash '$LAB/xr-run.sh' 192.0.2.10 2>&1 >/dev/null"
  [ "$status" -eq 255 ] || return 1
  [[ "$output" == *"no matching key exchange method"* ]] || return 1
  [[ "$output" == *"IRIS_SSH_LEGACY=1"* ]]
}

@test "a changed host key is explained with the known_hosts path and the recovery command" {
  run env FAKE_STDERR='WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!' FAKE_SSH_STATUS=255 \
    bash -c "printf 'show clock\n' | bash '$LAB/device-run.sh' 192.0.2.10 2>&1 >/dev/null"
  [ "$status" -eq 255 ] || return 1
  [[ "$output" == *"ssh-keygen -R '192.0.2.10' -f '$IRIS_STATE/ssh/known_hosts'"* ]] || return 1
  [[ "$output" == *"possible interception"* ]]
}

@test "forwarded ssh stderr is redacted" {
  run env FAKE_STDERR='debug: password zzsecretzz leaked' \
    bash -c "printf 'show clock\n' | bash '$LAB/device-run.sh' 192.0.2.10 2>&1 >/dev/null"
  [[ "$output" != *"zzsecretzz"* ]] || return 1
  [[ "$output" == *"[REDACTED]"* ]]
}

# ---- the enable-escalation marker is no longer a predictable /tmp name ----

@test "the needs-enable marker lives under the private state dir, not TMPDIR" {
  cat > "$STUB/sshpass" <<'STUBEOF'
#!/usr/bin/env bash
cat > /dev/null
echo "sw1>terminal length 0"
STUBEOF
  chmod +x "$STUB/sshpass"
  run_dev
  [ -f "$IRIS_STATE/ssh/needs-enable/u@192.0.2.10" ] || return 1
  [ -z "$(find "$TMPDIR" -maxdepth 1 -name 'iris-needsenable-*' -print -quit)" ]
}
