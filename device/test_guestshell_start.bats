#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Candidate discovery is intentionally read-only and broad, then the launcher
# inspects exact executable + RPC-port argv before signaling one numeric PID.
# Every test still gets a neutered pgrep/kill by default: this protects a host
# that happens to run IRIS while also making any accidental return to a broad
# signal operation fail visibly in the tests that exercise replacement.
setup() {
  BATS_GS_SAFE="$(mktemp -d)"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$BATS_GS_SAFE/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/kill.log"\nexit 0\n' \
      "$BATS_GS_SAFE" > "$BATS_GS_SAFE/kill"
  chmod +x "$BATS_GS_SAFE/pgrep" "$BATS_GS_SAFE/kill"
  PATH="$BATS_GS_SAFE:$PATH"
  export PATH
}

teardown() {
  [ -n "${BATS_GS_SAFE:-}" ] && rm -rf "$BATS_GS_SAFE"
  return 0
}

_stage_catalog_ca() {
  # A tracked, parseable public certificate is sufficient for launch-line
  # tests. Tracker hostname/chain behavior is covered by the real aria2 TLS
  # integration test; these fixtures only prove fail-closed startup and argv.
  cp "$BATS_TEST_DIRNAME/../server/certs/cisco_bulkhash_verify.pem" \
    "$1/iris-catalog.pem"
}

_catalog_ca_digest() {
  python3 -c \
    'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
    "$1/iris-catalog.pem"
}

_runtime_catalog_ca() {
  printf '%s/iris-catalog-%s.pem\n' "$2" "$(_catalog_ca_digest "$1")"
}

@test "the suite can never signal a host process" {
  # Guard for the guard: if setup's stubs stop shadowing the real tools, this
  # fails here rather than by killing a seeder on someone's machine.
  run command -v pgrep
  [ "$status" -eq 0 ]
  [[ "$output" == "$BATS_GS_SAFE/pgrep" ]]
  # The launcher deliberately uses `env kill`, which resolves this external
  # PATH entry rather than bash's builtin.
  run type -P kill
  [ "$status" -eq 0 ]
  [[ "$output" == "$BATS_GS_SAFE/kill" ]]
  run pgrep -f 'aria2c'
  [ "$status" -eq 1 ]            # the branch that skips the sweep
}

@test "guestshell-start builds an RPC aria2c daemon with private-swarm flags" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  # RPC probe skipped so the launcher proceeds to launch the stub
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  out="$(cat "$tmp/launched.txt")"
  [[ "$out" == *"--enable-rpc=true"* ]]
  [[ "$out" == *"--rpc-secret=rpcsecret"* ]]
  [[ "$out" == *"--enable-dht=false"* ]]
  [[ "$out" == *"--bt-seed-unverified=true"* ]]
  [[ "$out" == *"--bt-max-peers=10"* ]]
  [[ "$out" == *"--dir=$tmp/stage"* ]]
  runtime_ca="$(_runtime_catalog_ca "$tmp/stage" "$tmp/home")"
  [[ "$out" == *"--ca-certificate=$runtime_ca"* ]]
  [ -r "$runtime_ca" ]
  [[ "$out" == *"--check-certificate=true"* ]]
  [[ "$out" != *"--listen-port="* ]]
}

@test "guestshell-start refuses a missing or malformed tracker certificate" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho launched > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"

  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"catalog certificate"* ]]
  [ ! -f "$tmp/launched.txt" ]

  printf '%s\n' 'not a certificate' > "$tmp/stage/iris-catalog.pem"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"not a valid certificate bundle"* ]]
  [ ! -f "$tmp/launched.txt" ]
}

# Same defect class as server/seed-launch.sh, reachable here because a device
# may be assigned up to ten images. aria2's max-concurrent-downloads defaults to
# 5, and a SEEDING torrent counts against it while never completing
# (--seed-ratio=0.0 below means seed forever, which is the whole point: staged
# devices seed to their peers). So once a device holds five staged images, the
# download for a sixth is queued and never starts -- silently, since aria2 calls
# it `waiting`, not an error, and the agent only ever enumerates that queue
# (_aria_downloads) rather than reporting it. The device would sit in staging
# forever with no fault recorded. Measured in exactly this shape on the server
# side 2026-08-31: tellActive pinned at five, the sixth image in tellWaiting.
@test "guestshell-start lifts aria2's default concurrency cap so a multi-image device is never starved" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || return 1
  out="$(cat "$tmp/launched.txt")"
  [[ "$out" == *"--max-concurrent-downloads=100"* ]]
}

@test "the device concurrency cap is env-overridable" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      MAX_CONCURRENT=12 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || return 1
  out="$(cat "$tmp/launched.txt")"
  [[ "$out" == *"--max-concurrent-downloads=12"* ]]
}

@test "an empty baked rpc-secret launches aria2c with the placeholder secret" {
  # Field incident 2026-08-20: every Guest Shell device fell silent after
  # redeploy. The installer bakes rpc-secret EMPTY by design (the agent
  # fetches the real value on its first token-refresh), and Aria2 Next 2.5.6
  # rejects --rpc-secret= outright ("Empty string is not allowed") where
  # aria2 1.37 accepted it. aria2c then never launched, bootstrap aborted
  # before ever running the agent, and the device never sent its first
  # heartbeat. Launch with the same "iris" placeholder the IOx entrypoint
  # uses; bootstrap's secret sync bounces aria2c onto the real secret right
  # after that first refresh.
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  printf '\n' > "$tmp/stage/rpc-secret"   # baked empty (installer default)
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  out="$(cat "$tmp/launched.txt")"
  [[ "$out" == *"--rpc-secret=iris "* ]]
}

@test "guestshell-start pins the BitTorrent port only when requested" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 BT_LISTEN_PORT=6881 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [[ "$(cat "$tmp/launched.txt")" == *"--listen-port=6881"* ]]
}

@test "an unresponsive aria2c is killed before relaunch (stale-process deadlock)" {
  # 2026-08-20 incident: reaching this point means the RPC probe already
  # FAILED, so any surviving aria2c is not serving. Leaving it alive makes the
  # relaunch useless — it still owns :6800 (new instance cannot bind) and
  # `cp -f` over a running binary fails with ETXTBSY, so the stale build keeps
  # running. Clear it first, then copy and launch.
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home" "$tmp/bin"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  # A stale IRIS aria2c IS present; record that the launcher signals its exact
  # numeric PID and make that PID disappear for the bounded wait.
  printf '#!/usr/bin/env bash\n[ -f "%s/gone" ] && exit 1\necho 4242\n' \
    "$tmp" > "$tmp/bin/pgrep"
  cat > "$tmp/bin/ps" <<'PS'
#!/usr/bin/env bash
[ -f "$GONE" ] && exit 1
echo "$IRIS_ARIA2 --daemon=true --enable-rpc=true --rpc-listen-port=6800"
PS
  cat > "$tmp/bin/kill" <<'KILL'
#!/usr/bin/env bash
echo "$@" >> "$KILL_LOG"
[ "${2:-}" = "4242" ] && touch "$GONE"
KILL
  chmod +x "$tmp/bin/pgrep" "$tmp/bin/ps" "$tmp/bin/kill"
  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      IRIS_ARIA2="$tmp/home/aria2c" GONE="$tmp/gone" KILL_LOG="$tmp/kill.log" \
      SKIP_RPC_PROBE=1 bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [ "$(cat "$tmp/kill.log")" = "-TERM 4242" ] # only the inspected PID
  [ -f "$tmp/launched.txt" ]                   # and the relaunch still happened
}

@test "replacement leaves an unrelated aria2 RPC daemon untouched" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home" "$tmp/bin"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"

  # Both candidates look like aria2 RPC daemons. Only 4242 is the executable
  # this launcher owns on its configured port; 4343 must never be signaled.
  cat > "$tmp/bin/pgrep" <<'PGREP'
#!/usr/bin/env bash
[ -f "$IRIS_GONE" ] || echo 4242
echo 4343
PGREP
  cat > "$tmp/bin/ps" <<'PS'
#!/usr/bin/env bash
pid="${@: -1}"
case "$pid" in
  4242)
    [ -f "$IRIS_GONE" ] && exit 1
    echo "$IRIS_ARIA2 --daemon=true --enable-rpc=true --rpc-listen-port=6800"
    ;;
  4343)
    echo "/home/other/aria2c --daemon=true --enable-rpc=true --rpc-listen-port=6800"
    ;;
esac
PS
  cat > "$tmp/bin/kill" <<'KILL'
#!/usr/bin/env bash
echo "$@" >> "$KILL_LOG"
case "${2:-}" in
  4242) touch "$IRIS_GONE" ;;
  4343) touch "$UNRELATED_SIGNALED" ;;
esac
KILL
  chmod +x "$tmp/bin/pgrep" "$tmp/bin/ps" "$tmp/bin/kill"

  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      IRIS_ARIA2="$tmp/home/aria2c" IRIS_GONE="$tmp/iris-gone" \
      UNRELATED_SIGNALED="$tmp/unrelated-signaled" KILL_LOG="$tmp/kill.log" \
      SKIP_RPC_PROBE=1 bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(cat "$tmp/kill.log")" = "-TERM 4242" ]
  [ ! -e "$tmp/unrelated-signaled" ]
  [ -f "$tmp/launched.txt" ]
}

@test "a candidate that changes identity before signal is not killed" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home" "$tmp/bin"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  printf '#!/usr/bin/env bash\necho 4242\n' > "$tmp/bin/pgrep"
  cat > "$tmp/bin/ps" <<'PS'
#!/usr/bin/env bash
n=$(cat "$PS_STATE" 2>/dev/null || echo 0)
n=$((n + 1)); echo "$n" > "$PS_STATE"
if [ "$n" -eq 1 ]; then
  echo "$IRIS_ARIA2 --daemon=true --enable-rpc=true --rpc-listen-port=6800"
else
  echo "/home/other/aria2c --daemon=true --enable-rpc=true --rpc-listen-port=6800"
fi
PS
  printf '#!/usr/bin/env bash\necho "$@" >> "$KILL_LOG"\n' > "$tmp/bin/kill"
  chmod +x "$tmp/bin/pgrep" "$tmp/bin/ps" "$tmp/bin/kill"

  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      IRIS_ARIA2="$tmp/home/aria2c" PS_STATE="$tmp/ps-state" \
      KILL_LOG="$tmp/kill.log" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ ! -e "$tmp/kill.log" ]
  [ -f "$tmp/launched.txt" ]
}

@test "a failed binary copy is reported, not silently ignored" {
  # cp/chmod failures were swallowed with `|| true`, so a device could exec a
  # stale binary (or nothing) with no diagnostic anywhere.
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/does-not-exist" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      SKIP_RPC_PROBE=1 bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"aria2c"* ]]
}

# ---------------------------------------------------------------------------
# --on-bt-download-complete: the per-peer transfer-record hook
#
# aria2 execs the option value directly (execlp, no shell), so the value must
# be a real executable FILE. /flash denies chmod, which is why the launcher
# copies the hook to $EXEC_DIR exactly as it does aria2c. The option is
# launch-time only -- OptionHandlerFactory.cc never marks it initial/changeable,
# so an addTorrent option dict would be silently dropped -- which is why these
# assertions live against the launcher and not the agent.
# ---------------------------------------------------------------------------

_gs_fixture() {           # $1 = tmpdir; stages a hook unless $2 = "nohook"
  mkdir -p "$1/stage/agent" "$1/home"
  _stage_catalog_ca "$1/stage"
  echo "rpcsecret" > "$1/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\nenv > "%s/env.txt"\n' \
    "$1" "$1" > "$1/aria2c-stub"
  chmod +x "$1/aria2c-stub"
  if [ "${2:-}" != "nohook" ]; then
    printf '#!/bin/sh\nexit 0\n' > "$1/stage/agent/peer-transfer-hook.sh"
  fi
}

@test "a staged hook is wired in as --on-bt-download-complete" {
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [[ "$(cat "$tmp/launched.txt")" == *"--on-bt-download-complete=$tmp/home/iris-peer-transfer-hook"* ]]
}

@test "the hook is installed on an exec-capable fs with the exec bit" {
  # A hook left in the stage dir could never be chmod'd (/flash is
  # SELinux-labeled), and execlp needs the bit -- so the copy is the mechanism,
  # not an optimisation.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [ -x "$tmp/home/iris-peer-transfer-hook" ]
}

@test "no staged hook means NO --on-bt-download-complete flag at all" {
  # Never an empty option value: Aria2 Next rejects those outright ("Empty
  # string is not allowed"), which is exactly how --rpc-secret= stopped aria2c
  # from launching at all in the 2026-08-20 incident. An agent bundle that
  # predates the hook must still launch a daemon.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp" nohook
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [ -f "$tmp/launched.txt" ]
  [[ "$(cat "$tmp/launched.txt")" != *"--on-bt-download-complete"* ]]
}

@test "a hook that cannot be installed is reported but never blocks the launch" {
  # Telemetry must not be able to silence a device. Without the hook the report
  # simply omits the transfer records ("not measured") and the transfer is unaffected.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  # an undeliverable destination: the copy fails, nothing else does
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      HOOK_DST="$tmp/no-such-dir/iris-peer-transfer-hook" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"peer-transfer hook"* ]]
  [ -f "$tmp/launched.txt" ]
  [[ "$(cat "$tmp/launched.txt")" != *"--on-bt-download-complete"* ]]
}

@test "a refreshed hook is installed even when aria2c is already serving" {
  # Dropping a new bundle.tgz IS the agent upgrade path, and a serving aria2c
  # is deliberately NOT relaunched -- so the install must sit ABOVE the
  # 'already up?' early exit or an upgraded hook could never reach the path the
  # running daemon already holds.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  printf '#!/bin/sh\n# v2\nexit 0\n' > "$tmp/stage/agent/peer-transfer-hook.sh"
  mkdir -p "$tmp/bin"
  runtime_ca="$(_runtime_catalog_ca "$tmp/stage" "$tmp/home")"
  cp "$tmp/stage/iris-catalog.pem" "$runtime_ca"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/curl"     # RPC answers: already up
  printf '#!/usr/bin/env bash\necho 4242\n' > "$tmp/bin/pgrep"
  printf '#!/usr/bin/env bash\necho "$IRIS_ARIA2 --enable-rpc=true --rpc-listen-port=6800 --ca-certificate=%s --check-certificate=true"\n' \
    "$runtime_ca" > "$tmp/bin/ps"
  chmod +x "$tmp/bin/curl" "$tmp/bin/pgrep" "$tmp/bin/ps"
  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      IRIS_ARIA2="$tmp/home/aria2c" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already up"* ]]        # took the early exit
  [ ! -f "$tmp/launched.txt" ]             # and did NOT relaunch aria2c
  grep -q "v2" "$tmp/home/iris-peer-transfer-hook"
}

@test "same-path catalog certificate rotation restarts the pinned daemon" {
  # aria2 loads its CA bytes once. Re-onboard replaces iris-catalog.pem at the
  # same path, so a path-only health check retained a daemon pinned to cert A
  # after cert B landed. The content-addressed runtime path must change and the
  # answering cert-A daemon must be replaced exactly once.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"

  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      SKIP_RPC_PROBE=1 bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  cp "$tmp/launched.txt" "$tmp/cert-a-args"
  cert_a_runtime="$(_runtime_catalog_ca "$tmp/stage" "$tmp/home")"
  [ -r "$cert_a_runtime" ]

  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
      -subj '/CN=iris-rotated-test' \
      -keyout "$tmp/rotated-key.pem" \
      -out "$tmp/stage/iris-catalog.pem" >/dev/null 2>&1
  cert_b_runtime="$(_runtime_catalog_ca "$tmp/stage" "$tmp/home")"
  [ "$cert_a_runtime" != "$cert_b_runtime" ]

  mkdir -p "$tmp/bin"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/curl"
  printf '#!/usr/bin/env bash\n[ -f "%s/gone" ] && exit 1\necho 4242\n' \
    "$tmp" > "$tmp/bin/pgrep"
  printf '#!/usr/bin/env bash\n[ -f "%s/gone" ] && exit 1\necho "$IRIS_ARIA2 $(cat "$OLD_ARGS")"\n' \
    "$tmp" > "$tmp/bin/ps"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/kill.log"\ntouch "%s/gone"\n' \
    "$tmp" "$tmp" > "$tmp/bin/kill"
  chmod +x "$tmp/bin/curl" "$tmp/bin/pgrep" "$tmp/bin/ps" "$tmp/bin/kill"

  run env PATH="$tmp/bin:$PATH" OLD_ARGS="$tmp/cert-a-args" \
      STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      IRIS_ARIA2="$tmp/home/aria2c" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *"current tracker TLS generation"* ]]
  [ "$(cat "$tmp/kill.log")" = "-TERM 4242" ]
  [ -r "$cert_b_runtime" ]
  [[ "$(cat "$tmp/launched.txt")" == *"--ca-certificate=$cert_b_runtime"* ]]
  [[ "$(cat "$tmp/launched.txt")" != *"--ca-certificate=$cert_a_runtime"* ]]
}

@test "a corrupted digest-named CA snapshot is repaired before daemon reuse" {
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  runtime_ca="$(_runtime_catalog_ca "$tmp/stage" "$tmp/home")"
  printf '%s\n' 'not a certificate' > "$runtime_ca"

  mkdir -p "$tmp/bin"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/curl"
  printf '#!/usr/bin/env bash\n[ -f "%s/gone" ] && exit 1\necho 4242\n' \
    "$tmp" > "$tmp/bin/pgrep"
  printf '#!/usr/bin/env bash\n[ -f "%s/gone" ] && exit 1\necho "$IRIS_ARIA2 --enable-rpc=true --rpc-listen-port=6800 --ca-certificate=%s --check-certificate=true"\n' \
    "$tmp" "$runtime_ca" > "$tmp/bin/ps"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/kill.log"\ntouch "%s/gone"\n' \
    "$tmp" "$tmp" > "$tmp/bin/kill"
  chmod +x "$tmp/bin/curl" "$tmp/bin/pgrep" "$tmp/bin/ps" "$tmp/bin/kill"

  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      IRIS_ARIA2="$tmp/home/aria2c" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  cmp -s "$tmp/stage/iris-catalog.pem" "$runtime_ca"
  [ "$(cat "$tmp/kill.log")" = "-TERM 4242" ] # never retained on repaired bytes
  [ -f "$tmp/launched.txt" ]
}

@test "a malformed CA swapped in after source validation is refused at the snapshot" {
  # Deterministically model the installer atomic-replacing the stable source
  # pathname immediately after its first SSL validation. The replacement's
  # digest and copied bytes agree, so only validation of the exact runtime
  # snapshot prevents aria2 from launching with malformed trust material.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  mkdir -p "$tmp/bin"
  real_python="$(command -v python3)"
  cat > "$tmp/bin/python3" <<'PYTHON'
#!/usr/bin/env bash
n=$(cat "$PYTHON_STATE" 2>/dev/null || echo 0)
n=$((n + 1)); echo "$n" > "$PYTHON_STATE"
"$REAL_PYTHON" "$@"
rc=$?
if [ "$n" -eq 1 ] && [ "$rc" -eq 0 ]; then
  printf '%s\n' 'not a certificate' > "$CA_SOURCE.new"
  mv -f "$CA_SOURCE.new" "$CA_SOURCE"
fi
exit "$rc"
PYTHON
  chmod +x "$tmp/bin/python3"

  run env PATH="$tmp/bin:$PATH" REAL_PYTHON="$real_python" \
      PYTHON_STATE="$tmp/python-state" CA_SOURCE="$tmp/stage/iris-catalog.pem" \
      STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      SKIP_RPC_PROBE=1 bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"certificate snapshot"*"not a valid certificate bundle"* ]]
  [ ! -f "$tmp/launched.txt" ]
}

@test "an answering pre-TLS daemon is replaced once" {
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  mkdir -p "$tmp/bin"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/curl"
  cat > "$tmp/bin/pgrep" <<'PGREP'
#!/usr/bin/env bash
n=$(cat "$PGREP_STATE" 2>/dev/null || echo 0)
n=$((n + 1)); echo "$n" > "$PGREP_STATE"
if [ "$n" -le 2 ]; then echo 4242; exit 0; fi
exit 1
PGREP
  printf '#!/usr/bin/env bash\n[ -f "$GONE" ] && exit 1\necho "$IRIS_ARIA2 --enable-rpc=true --rpc-listen-port=6800"\n' > "$tmp/bin/ps"
  printf '#!/usr/bin/env bash\necho "$@" >> "$KILL_LOG"\ntouch "$GONE"\n' > "$tmp/bin/kill"
  chmod +x "$tmp/bin/curl" "$tmp/bin/pgrep" "$tmp/bin/ps" "$tmp/bin/kill"

  run env PATH="$tmp/bin:$PATH" PGREP_STATE="$tmp/pgrep-state" \
      STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      IRIS_ARIA2="$tmp/home/aria2c" GONE="$tmp/gone" KILL_LOG="$tmp/kill.log" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *"does not match the current tracker TLS generation"* ]]
  [ "$(cat "$tmp/kill.log")" = "-TERM 4242" ]
  [ -f "$tmp/launched.txt" ]
  [[ "$(cat "$tmp/launched.txt")" == *"--check-certificate=true"* ]]
}

@test "the hook inherits the secret the daemon is actually launched with" {
  # Never re-read from the rpc-secret FILE: the file and the running daemon can
  # disagree, and that skew is the 2026-08-20 incident. Inheritance through
  # aria2c's fork is the only channel that cannot drift.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 RPC_PORT=6899 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  grep -qx "IRIS_RPC_SECRET=rpcsecret" "$tmp/env.txt"
  grep -qx "IRIS_RPC_PORT=6899" "$tmp/env.txt"
  [[ "$(cat "$tmp/launched.txt")" == *"--rpc-secret=rpcsecret"* ]]
}

@test "an empty baked secret exports the same placeholder aria2c is launched with" {
  # The empty file legitimately means the daemon is on the "iris" placeholder;
  # the hook must be told that, not left to guess from the file.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  printf '\n' > "$tmp/stage/rpc-secret"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  grep -qx "IRIS_RPC_SECRET=iris" "$tmp/env.txt"
}

# ---------------------------------------------------------------------------
# Resume integrity (#66)
# ---------------------------------------------------------------------------

@test "the launch re-verifies the bytes already on disk (--check-integrity)" {
  # Without it aria2 trusts the piece map in the .aria2 control file on a
  # resume, so a piece that rotted on flash survives, the torrent reports
  # complete, and the staged image has the wrong SHA-256 -- caught by the
  # agent's whole-image hash only after the whole remaining transfer, and
  # repaired only by re-staging the whole image. Reproduced on the real
  # binaries (128 MiB torrent, 256 bytes corrupted inside completed piece 0).
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  # Stub read-only candidate discovery; the suite-level external kill stub is
  # still the guard against signaling any host PID if selection regresses.
  mkdir -p "$tmp/bin"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$tmp/bin/pgrep"
  chmod +x "$tmp/bin/pgrep"
  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || return 1
  out="$(cat "$tmp/launched.txt")"
  [[ "$out" == *"--check-integrity=true"* ]] || return 1
  # The completed-file case must stay free: --bt-seed-unverified marks a
  # finished download done and aria2 then skips validation altogether, so a
  # device seeding its staged images never re-hashes them at launch.
  [[ "$out" == *"--bt-seed-unverified=true"* ]]
}

# ---------------------------------------------------------------------------
# The "already up?" probe must tell BUSY from DEAD (#77)
#
# Everything past that probe treats a failure as "aria2c is not serving" and
# replaces it. aria2c built without c-ares resolves tracker hostnames with a
# blocking getaddrinfo() on its event-loop thread, so one announce against a
# slow resolver freezes the daemon -- RPC included -- for as long as the
# resolver takes (5.03 s measured on the container supervisor, same binary).
# A probe that cannot tell that from a dead daemon kills healthy ones and
# drops their in-flight downloads.
# ---------------------------------------------------------------------------

# A curl stub handing out a scripted sequence of exit codes, one per call.
_curl_codes_stub() {                # $1 = tmpdir, $2.. = exit codes
  local tmp="$1"; shift
  mkdir -p "$tmp/bin"
  printf '%s\n' "$@" > "$tmp/curl-codes"
  cat > "$tmp/bin/curl" <<'CURL'
#!/usr/bin/env bash
n=$(cat "$CURL_STATE" 2>/dev/null || echo 0)
n=$((n + 1)); echo "$n" > "$CURL_STATE"
printf '%s\n' "$*" >> "$CURL_LOG"
rc="$(sed -n "${n}p" "$CURL_CODES")"
exit "${rc:-0}"
CURL
  # pgrep/ps model one daemon launched with the secure tracker options.
  # PID-scoped kill makes it disappear so the refused-port replacement test does not
  # spend ten seconds waiting on a deliberately static stub.
  runtime_ca="$(_runtime_catalog_ca "$tmp/stage" "$tmp/home")"
  cp "$tmp/stage/iris-catalog.pem" "$runtime_ca"
  printf '#!/usr/bin/env bash\n[ -f "%s/gone" ] && exit 1\necho 4242\n' \
    "$tmp" > "$tmp/bin/pgrep"
  printf '#!/usr/bin/env bash\n[ -f "%s/gone" ] && exit 1\necho "$IRIS_ARIA2 --enable-rpc=true --rpc-listen-port=6800 --ca-certificate=%s --check-certificate=true"\n' \
    "$tmp" "$runtime_ca" > "$tmp/bin/ps"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/kill.log"\ntouch "%s/gone"\n' \
    "$tmp" "$tmp" > "$tmp/bin/kill"
  chmod +x "$tmp/bin/curl" "$tmp/bin/pgrep" "$tmp/bin/ps" "$tmp/bin/kill"
}

@test "a daemon that answers late is left alone, not killed and relaunched" {
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  _curl_codes_stub "$tmp" 28 0        # no answer inside the bound, then an answer
  run env PATH="$tmp/bin:$PATH" CURL_STATE="$tmp/curl-state" \
      CURL_LOG="$tmp/curl.log" CURL_CODES="$tmp/curl-codes" \
      STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" IRIS_ARIA2="$tmp/home/aria2c" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *"already up"* ]] || { echo "$output"; return 1; }
  [ ! -f "$tmp/kill.log" ] || { echo "killed a healthy daemon"; return 1; }
  [ ! -f "$tmp/launched.txt" ] || { echo "relaunched over a healthy daemon"; return 1; }
  [ "$(wc -l < "$tmp/curl.log")" -eq 2 ]
}

@test "a refused RPC port still replaces the stale daemon at once" {
  # curl 7 means nothing is listening: a verdict, not a suspicion. The
  # 2026-08-20 deadlock was a stale daemon left alive for ~42 minutes, so this
  # path must not spend a confirming probe before acting.
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  _curl_codes_stub "$tmp" 7 7
  run env PATH="$tmp/bin:$PATH" CURL_STATE="$tmp/curl-state" \
      CURL_LOG="$tmp/curl.log" CURL_CODES="$tmp/curl-codes" \
      STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" IRIS_ARIA2="$tmp/home/aria2c" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(cat "$tmp/kill.log")" = "-TERM 4242" ] \
    || { echo "stale daemon not cleared by exact PID"; return 1; }
  [ -f "$tmp/launched.txt" ] || { echo "not relaunched"; return 1; }
  [ "$(wc -l < "$tmp/curl.log")" -eq 1 ]
}

@test "the probe is bounded, and waits longer than the worst measured resolver stall" {
  # It used to have no timeout at all, so a wedged daemon hung the launcher
  # and the EEM applet running it. The bound must still sit above a healthy
  # daemon's longest stall (5.03 s measured; glibc's 5 s x 2 attempts is the
  # ceiling to design for).
  t="$(sed -n 's/^RPC_HEALTH_TIMEOUT="\${RPC_HEALTH_TIMEOUT:-\([0-9]*\)}"$/\1/p' \
       "$BATS_TEST_DIRNAME/guestshell-start.sh")"
  [ -n "$t" ] || { echo "no RPC_HEALTH_TIMEOUT default"; return 1; }
  [ "$t" -gt 5 ] || { echo "probe bound is ${t}s, too short for a 5 s resolver stall"; return 1; }
  grep -q -- '--connect-timeout "\$RPC_CONNECT_TIMEOUT"' "$BATS_TEST_DIRNAME/guestshell-start.sh"
}

# ---------------------------------------------------------------------------
# Device-side logging is opt-in (flash write endurance)
#
# aria2c's --log is chatty and continuous for the whole life of a transfer,
# and with --seed-ratio=0.0 a staged device seeds forever, so a log left on
# never stops growing. Flash has finite write endurance, so the default must
# genuinely write nothing recurring -- not "a smaller file". Guarded here
# because "no --log= on the launch line" is the whole mechanism: aria2c's own
# daemon mode already redirects stdio to /dev/null with no --log given, so
# leaving the flag off the command line is sufficient, not just a smaller
# rotated file.
# ---------------------------------------------------------------------------

@test "device-side logging defaults OFF: no --log flag on the launch line at all" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  # IRIS_LOG deliberately unset: this proves the DEFAULT, not an explicit off.
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  out="$(cat "$tmp/launched.txt")"
  [[ "$out" != *"--log="* ]]
}

@test "IRIS_LOG=on puts --log=<aria2c.log> on the launch line" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 IRIS_LOG=on \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  out="$(cat "$tmp/launched.txt")"
  [[ "$out" == *"--log=$tmp/stage/aria2c.log"* ]]
}

@test "IRIS_LOG parsing accepts 1/true/yes/ON case-insensitively, and stays off for anything else" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  for v in 1 true yes ON On; do
    rm -f "$tmp/launched.txt"
    run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
        RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 IRIS_LOG="$v" \
        bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
    [ "$status" -eq 0 ] || { echo "IRIS_LOG=$v failed to launch"; return 1; }
    [[ "$(cat "$tmp/launched.txt")" == *"--log="* ]] \
      || { echo "IRIS_LOG=$v did not enable --log"; return 1; }
  done
  for v in off 0 false no garbage ""; do
    rm -f "$tmp/launched.txt"
    run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
        RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 IRIS_LOG="$v" \
        bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
    [ "$status" -eq 0 ] || { echo "IRIS_LOG=$v failed to launch"; return 1; }
    [[ "$(cat "$tmp/launched.txt")" != *"--log="* ]] \
      || { echo "IRIS_LOG=$v unexpectedly enabled --log"; return 1; }
  done
}

@test "logging off means rotate-logs.sh has nothing to trim (no aria2c.log ever created)" {
  # End-to-end proof that OFF is genuinely no recurring flash write, not just
  # a launch-line detail: a stub that mimics aria2c's OWN behavior (only
  # creates the log file when given a --log= argument, same as the real
  # binary) never creates aria2c.log by default, so bootstrap.sh's per-tick
  # rotate-logs.sh call (device/bootstrap.sh step 4) is a no-op every tick.
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
  _stage_catalog_ca "$tmp/stage"
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  cat > "$tmp/aria2c-stub" <<'STUB'
#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in --log=*) : > "${a#--log=}" ;; esac
done
STUB
  chmod +x "$tmp/aria2c-stub"
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [ ! -e "$tmp/stage/aria2c.log" ]
  # sanity: the SAME stub does create it when the operator opts in, so the
  # negative assertion above is proving something the stub can actually show
  run env STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" SKIP_RPC_PROBE=1 IRIS_LOG=on \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [ -e "$tmp/stage/aria2c.log" ]
}
