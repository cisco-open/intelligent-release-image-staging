#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# --on-bt-download-complete wiring, across every runtime that launches aria2c,
# plus the packaging that gets the hook onto a device and the teardown that
# takes it off again.
#
# Why the assertions live here and not against the agent: the option is
# LAUNCH-TIME ONLY. OptionHandlerFactory.cc:1954-1962 never marks it initial or
# changeable, and RpcMethod.cc:158-164 filters per-download options through
# getInitialOption(), silently dropping the rest -- so passing it in
# aria2.addTorrent's options dict would be discarded with no error at all.
# There are three launchers: device/guestshell-start.sh (Catalyst AND router --
# router-install.sh runs the same bootstrap chain, differing only in the
# /bootflash prefix), device/iox/entrypoint.sh (IE3400 arm64 and the amd64
# app-hosting package), and device/xr/entrypoint.sh (Cisco 8000 series, added
# with IOS-XR support after this file first said "exactly two").
#
# The Guest Shell launcher's own behaviour is covered in
# device/test_guestshell_start.bats.

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  DEVICE="$REPO/device"
  ENTRYPOINT="$DEVICE/iox/entrypoint.sh"
  HOOK_SRC="$DEVICE/agent/peer-transfer-hook.sh"
  TMPD="$BATS_TEST_TMPDIR/w"
  mkdir -p "$TMPD/bin" "$TMPD/stage"
  # a recording aria2c, plus stubs so the supervisor's process management does
  # not touch the machine running the tests
  printf '#!/usr/bin/env bash\necho "$@" > "%s/launched.txt"\nenv > "%s/env.txt"\n' \
    "$TMPD" "$TMPD" > "$TMPD/bin/aria2c-stub"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$TMPD/bin/pkill"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$TMPD/bin/sleep"
  chmod +x "$TMPD/bin/aria2c-stub" "$TMPD/bin/pkill" "$TMPD/bin/sleep"
}

# Run the REAL start_aria2c out of entrypoint.sh (not a re-implementation), so
# a regression in the launch line fails here. $1 is the HOOK value under test.
run_start_aria2c() {
  PATH="$TMPD/bin:$PATH" bash -c '
    set -eu
    ARIA2="'"$TMPD"'/bin/aria2c-stub"
    RPC_PORT=6800; MAX_PEERS=10; STAGE_DIR="'"$TMPD"'/stage"
    HOOK="'"$1"'"
    eval "$(awk "/^start_aria2c\(\)/,/^}/" "'"$ENTRYPOINT"'")"
    start_aria2c "supervisorsecret"
  '
}

# ---------------------------------------------------------------------------
# IOx container (IE3400 arm64 + the amd64 app-hosting package)
# ---------------------------------------------------------------------------

@test "entrypoint launches aria2c with the hook baked into the image" {
  run run_start_aria2c "/opt/iris/agent/peer-transfer-hook.sh"
  [ "$status" -eq 0 ]
  [[ "$(cat "$TMPD/launched.txt")" == *"--on-bt-download-complete=/opt/iris/agent/peer-transfer-hook.sh"* ]]
}

@test "entrypoint omits the flag entirely when the image has no hook" {
  # Never --on-bt-download-complete= with an empty value: Aria2 Next rejects an
  # empty option outright, and an aria2c that refuses to launch is the
  # 2026-08-20 silent-device incident. An image built before this feature must
  # still come up.
  run run_start_aria2c ""
  [ "$status" -eq 0 ]
  [[ "$(cat "$TMPD/launched.txt")" != *"--on-bt-download-complete"* ]]
}

@test "entrypoint still passes the private-swarm flags alongside the hook" {
  run run_start_aria2c "/opt/iris/agent/peer-transfer-hook.sh"
  out="$(cat "$TMPD/launched.txt")"
  # `|| return 1`: a bare failing [[ ]] that is not the test's LAST command does
  # not fail a bats test under bash 3.2, so without these the first three
  # assertions here could never go red.
  [[ "$out" == *"--enable-dht=false"* ]] || return 1
  [[ "$out" == *"--bt-seed-unverified=true"* ]] || return 1
  [[ "$out" == *"--rpc-secret=supervisorsecret"* ]] || return 1
  [[ "$out" == *"--dir=$TMPD/stage"* ]]
}

# aria2's max-concurrent-downloads defaults to 5 and a SEEDING torrent counts
# against it while never completing (--seed-ratio=0.0 -- staged devices seed to
# their peers by design). A device may be assigned up to ten images, so once it
# holds five, the download for the sixth is queued and never starts. Silently:
# aria2 calls it `waiting`, not an error, and the agent only enumerates that
# queue rather than reporting it, so the device reports staging forever with no
# fault recorded. Measured in exactly this shape on the origin 2026-08-31.
@test "entrypoint lifts aria2's default concurrency cap so a multi-image device is never starved" {
  run run_start_aria2c "/opt/iris/agent/peer-transfer-hook.sh"
  [ "$status" -eq 0 ] || return 1
  [[ "$(cat "$TMPD/launched.txt")" == *"--max-concurrent-downloads=100"* ]]
}

@test "entrypoint hands the hook the secret the daemon is being started with" {
  # By inheritance through aria2c's fork, never by re-reading the conf: the
  # agent rewrites that file on token refresh, and a hook holding a secret the
  # daemon has moved off is the file-vs-daemon skew of the 2026-08-20 incident.
  run run_start_aria2c "/opt/iris/agent/peer-transfer-hook.sh"
  [ "$status" -eq 0 ]
  grep -qx "IRIS_RPC_SECRET=supervisorsecret" "$TMPD/env.txt"
}

@test "entrypoint exports the RPC port the hook must call back on" {
  grep -q 'export IRIS_RPC_PORT="\$RPC_PORT"' "$ENTRYPOINT"
}

@test "entrypoint resolves the hook path once and checks it is executable" {
  grep -q 'HOOK="/opt/iris/agent/peer-transfer-hook.sh"' "$ENTRYPOINT"
  grep -q '\[ -x "\$HOOK" \] || HOOK=""' "$ENTRYPOINT"
}

# ---------------------------------------------------------------------------
# Packaging: the hook has to reach the device before it can be wired
# ---------------------------------------------------------------------------

@test "the IOx image copies the hook in and gives it the exec bit" {
  # aria2 execs the value with execlp -- no shell, no PATH search fallback for
  # a non-executable file. Without the bit the hook is silently never run.
  grep -q '^COPY agent/peer-transfer-hook.sh /opt/iris/agent/peer-transfer-hook.sh$' \
    "$DEVICE/iox/Dockerfile"
  grep -q 'chmod +x .*/opt/iris/agent/peer-transfer-hook.sh' "$DEVICE/iox/Dockerfile"
}

@test "the IOx build stages the hook into the docker context" {
  # It is not *.py, so the agent glob does not carry it; the Dockerfile COPYs
  # it by name, so a missing line here fails the build on a missing source.
  grep -q 'cp "\$REPO/device/agent/peer-transfer-hook.sh" "\$CTX/agent/"' \
    "$DEVICE/iox/build.sh"
}

@test "the Guest Shell bundle ships the hook, executable, beside the agent" {
  # Dropping a new bundle.tgz IS the Guest Shell agent upgrade path, so this is
  # the only route an updated hook has onto a Catalyst or a router.
  out="$BATS_TEST_TMPDIR/iris-agent.tgz"
  printf 'fake-aria2c\n' > "$BATS_TEST_TMPDIR/aria2c"
  run bash "$REPO/server/pack-agent-bundle.sh" "$DEVICE" "$BATS_TEST_TMPDIR/aria2c" "$out"
  [ "$status" -eq 0 ]
  tar tzf "$out" | grep -qx "agent/peer-transfer-hook.sh"
  x="$BATS_TEST_TMPDIR/x"; mkdir -p "$x"
  tar xzf "$out" -C "$x" agent/peer-transfer-hook.sh
  [ -x "$x/agent/peer-transfer-hook.sh" ]
}

@test "the bundled hook is the file both launchers point at" {
  # guestshell-start.sh resolves $STAGE_DIR/agent/peer-transfer-hook.sh, which
  # is exactly where bootstrap.sh's tar extraction puts the bundled copy.
  grep -q 'HOOK_SRC="\${HOOK_SRC:-\$STAGE_DIR/agent/peer-transfer-hook.sh}"' \
    "$DEVICE/guestshell-start.sh"
  [ -f "$HOOK_SRC" ]
}

@test "the hook is POSIX sh, not bash (dash is /bin/sh in the container)" {
  head -n 1 "$HOOK_SRC" | grep -qx '#!/bin/sh'
  run sh -n "$HOOK_SRC"
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Teardown symmetry: everything the hook puts on a device comes back off
#
# Three artifacts per platform, and none of them is a new name at a preserved
# directory's root -- which is the property these tests exist to keep true. An
# orphan left at guest-share root is exactly what the collision preflight
# refuses on the next onboard.
#   1. the staged hook source   -> <stage>/agent/peer-transfer-hook.sh
#   2. the exec-capable copy    -> /home/guestshell (Guest Shell) or the image
#   3. the snapshots it writes  -> <stage>/<image>.peers.json
# aria2 is always launched with --dir=<stage>, and the agent's aria_add always
# passes the stage dir, so (3) can never land anywhere else -- notably not on
# the C9k app-hosting share, which the IOx teardown clears only by name.
# ---------------------------------------------------------------------------

@test "Catalyst teardown removes the guest filesystem holding the exec copy" {
  run env VLAN=666 bash "$DEVICE/device-uninstall.sh" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"guestshell destroy"* ]]        # /home/guestshell goes with it
  [[ "$output" == *"delete /force /recursive flash:guest-share"* ]]
}

@test "router teardown recursively clears the stage dir the snapshots land in" {
  # guest-share itself is a preserved platform directory here: only named files
  # at its root plus the whole iris/ subtree are removed. Every hook artifact
  # is inside iris/, so nothing new has to be named.
  run env VLAN=666 MODEL=C8000V MANAGEMENT_TYPE=router-routed VPG_NUMBER=10 \
      APP_IP=10.8.0.2 bash "$DEVICE/router-uninstall.sh" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"guestshell destroy"* ]]
  [[ "$output" == *"delete /force /recursive bootflash:guest-share/iris"* ]]
}

@test "IOx teardown frees the persist disk and the scp-push stage dir" {
  # The hook itself lives in the app image (gone with the app); its snapshots
  # live under $CAF_APP_PERSISTENT_DIR/iris, which app-hosting uninstall frees.
  run env VLAN=666 bash "$DEVICE/iox/uninstall.sh" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"app-hosting uninstall appid iris"* ]]
  [[ "$output" == *"delete /force /recursive sdflash:guest-share/iris"* ]]
}
