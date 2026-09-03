#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# guestshell-start.sh clears a stale daemon with
# `pkill -f 'aria2c.*enable-rpc'`, which matches by command line across the
# WHOLE machine. Most tests here run the launcher with the real PATH, so on a
# host that also runs IRIS that sweep aims at the live seeder. It has only ever
# missed because the seeder runs as a different uid and pkill got EPERM --
# run the suite as root, or as that uid, and it kills production.
#
# So every test gets a neutered pgrep/pkill by default: pgrep exits 1 ("no
# stale daemon"), which is the branch that skips the sweep entirely, and pkill
# is a no-op that records what it was asked to do. Tests that exercise the
# sweep put their own stubs in their own bin dir and prepend it, so theirs win
# and this stays a floor rather than a ceiling.
setup() {
  BATS_GS_SAFE="$(mktemp -d)"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$BATS_GS_SAFE/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/pkill.log"\nexit 0\n' \
      "$BATS_GS_SAFE" > "$BATS_GS_SAFE/pkill"
  chmod +x "$BATS_GS_SAFE/pgrep" "$BATS_GS_SAFE/pkill"
  PATH="$BATS_GS_SAFE:$PATH"
  export PATH
}

teardown() {
  [ -n "${BATS_GS_SAFE:-}" ] && rm -rf "$BATS_GS_SAFE"
  return 0
}

@test "the suite can never aim the stale-daemon sweep at a host process" {
  # Guard for the guard: if setup's stubs stop shadowing the real tools, this
  # fails here rather than by killing a seeder on someone's machine.
  run command -v pgrep
  [ "$status" -eq 0 ]
  [[ "$output" == "$BATS_GS_SAFE/pgrep" ]]
  run command -v pkill
  [ "$status" -eq 0 ]
  [[ "$output" == "$BATS_GS_SAFE/pkill" ]]
  run pgrep -f 'aria2c.*enable-rpc'
  [ "$status" -eq 1 ]            # the branch that skips the sweep
}

@test "guestshell-start builds an RPC aria2c daemon with private-swarm flags" {
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
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
  [[ "$out" != *"--listen-port="* ]]
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
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  # a stale aria2c IS present; record that the launcher clears it
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/pkill.log"\n' "$tmp" > "$tmp/bin/pkill"
  chmod +x "$tmp/bin/pgrep" "$tmp/bin/pkill"
  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      SKIP_RPC_PROBE=1 bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [ -f "$tmp/pkill.log" ]                      # stale process cleared
  [[ "$(cat "$tmp/pkill.log")" == *"aria2c"* ]]
  [ -f "$tmp/launched.txt" ]                   # and the relaunch still happened
}

@test "a failed binary copy is reported, not silently ignored" {
  # cp/chmod failures were swallowed with `|| true`, so a device could exec a
  # stale binary (or nothing) with no diagnostic anywhere.
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/stage" "$tmp/home"
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
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/curl"     # RPC answers: already up
  chmod +x "$tmp/bin/curl"
  run env PATH="$tmp/bin:$PATH" STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" \
      ARIA2_SRC="$tmp/aria2c-stub" RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"already up"* ]]        # took the early exit
  [ ! -f "$tmp/launched.txt" ]             # and did NOT relaunch aria2c
  grep -q "v2" "$tmp/home/iris-peer-transfer-hook"
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
  echo "rpcsecret" > "$tmp/stage/rpc-secret"
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\n' "$tmp" > "$tmp/aria2c-stub"
  chmod +x "$tmp/aria2c-stub"
  # Stub the stale-daemon sweep: with the real pgrep/pkill on PATH this script
  # hunts every `aria2c.*enable-rpc` process on the machine running the suite,
  # which on a seeding host is the live seeder.
  mkdir -p "$tmp/bin"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$tmp/bin/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/pkill.log"\n' "$tmp" > "$tmp/bin/pkill"
  chmod +x "$tmp/bin/pgrep" "$tmp/bin/pkill"
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
# pkills it. aria2c built without c-ares resolves tracker hostnames with a
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
  # pgrep/pkill: a stale-daemon replacement that must NOT happen here leaves
  # a trace either way.
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/pgrep"
  printf '#!/usr/bin/env bash\necho "$@" >> "%s/pkill.log"\n' "$tmp" > "$tmp/bin/pkill"
  chmod +x "$tmp/bin/curl" "$tmp/bin/pgrep" "$tmp/bin/pkill"
}

@test "a daemon that answers late is left alone, not killed and relaunched" {
  tmp="$(mktemp -d)"; _gs_fixture "$tmp"
  _curl_codes_stub "$tmp" 28 0        # no answer inside the bound, then an answer
  run env PATH="$tmp/bin:$PATH" CURL_STATE="$tmp/curl-state" \
      CURL_LOG="$tmp/curl.log" CURL_CODES="$tmp/curl-codes" \
      STAGE_DIR="$tmp/stage" EXEC_DIR="$tmp/home" ARIA2_SRC="$tmp/aria2c-stub" \
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *"already up"* ]] || { echo "$output"; return 1; }
  [ ! -f "$tmp/pkill.log" ] || { echo "killed a healthy daemon"; return 1; }
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
      RPC_SECRET_FILE="$tmp/stage/rpc-secret" \
      bash "$BATS_TEST_DIRNAME/guestshell-start.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ -f "$tmp/pkill.log" ] || { echo "stale daemon not cleared"; return 1; }
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
