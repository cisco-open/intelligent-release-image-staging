#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

bats_require_minimum_version 1.5.0

# tools/agent-source-freshness.sh (issue #72): device/iox/build.sh and
# tools/build-xr-package.sh bake in device/agent's CURRENT WORKING-TREE
# CONTENTS -- whatever checkout/worktree happens to be run from. A worktree
# left behind `main` under those paths then silently ships an older agent,
# with nothing in the built image/package saying so (this is how a stale
# comparison image made it into a size-measurement report). These tests
# build a small SYNTHETIC git repo per test (never touch the real one) to
# exercise the shared guard function directly, then two lightweight
# end-to-end checks that device/iox/build.sh and tools/build-xr-package.sh
# actually call it and stop BEFORE any docker step when it refuses.

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
FRESHNESS="$REPO_ROOT/tools/agent-source-freshness.sh"

setup() {
  TMP="$(mktemp -d)"
  export GIT_AUTHOR_NAME=iris GIT_AUTHOR_EMAIL=iris@example.com
  export GIT_COMMITTER_NAME=iris GIT_COMMITTER_EMAIL=iris@example.com
}

teardown() { rm -rf "$TMP"; }

# Builds a repo at $TMP/repo with an initial commit (C1: device/agent/a.py,
# device/verify_image.py, device/iox/x, unrelated.txt), a second commit on
# main (C2) that ALSO touches device/agent, then leaves the working tree
# checked out (detached) at C1 -- simulating a worktree that has fallen
# behind main under the checked paths.
_make_stale_repo() {
  R="$TMP/repo"
  mkdir -p "$R/device/agent" "$R/device/iox"
  git -C "$TMP" init -q -b main repo
  echo "one" > "$R/device/agent/a.py"
  echo "one" > "$R/device/verify_image.py"
  echo "one" > "$R/device/iox/x"
  echo "one" > "$R/unrelated.txt"
  git -C "$R" add -A
  git -C "$R" commit -q -m "C1"
  C1="$(git -C "$R" rev-parse HEAD)"
  echo "two" > "$R/device/agent/a.py"
  git -C "$R" add -A
  git -C "$R" commit -q -m "C2: touches device/agent"
  git -C "$R" checkout -q "$C1"   # detach at the OLD commit -- the stale worktree
}

# Same shape, but C2 does NOT touch any of the checked paths.
_make_repo_stale_elsewhere() {
  R="$TMP/repo"
  mkdir -p "$R/device/agent" "$R/device/iox"
  git -C "$TMP" init -q -b main repo
  echo "one" > "$R/device/agent/a.py"
  echo "one" > "$R/unrelated.txt"
  git -C "$R" add -A
  git -C "$R" commit -q -m "C1"
  C1="$(git -C "$R" rev-parse HEAD)"
  echo "two" > "$R/unrelated.txt"
  git -C "$R" add -A
  git -C "$R" commit -q -m "C2: touches unrelated.txt only"
  git -C "$R" checkout -q "$C1"
}

_check() {   # runs iris_check_agent_freshness "$R" "device/agent device/verify_image.py device/iox"
  run env "$@" bash -c ". '$FRESHNESS' && iris_check_agent_freshness '$R' 'device/agent device/verify_image.py device/iox'"
}

# Every real caller (device/iox/build.sh, tools/build-xr-package.sh) sources
# this file into a script running `set -e`. A bare `CMD && return 0` (as
# opposed to an `if CMD; then return 0; fi`) still trips errexit on CMD's
# failure even though the function goes on to handle that failure itself --
# and `git merge-base --is-ancestor` fails on EVERY genuinely stale checkout,
# the exact case this function exists to warn about, not abort on. This
# regression (caught by the real build.sh test suite, not by the tests
# above, because none of them ran under `set -e`) turned every "warn about a
# stale checkout" into an unconditional hard abort of the calling script.
_check_under_set_e() {
  run env "$@" bash -c "set -e; . '$FRESHNESS'; iris_check_agent_freshness '$R' 'device/agent device/verify_image.py device/iox'; echo REACHED-THE-END"
}

@test "iris_check_agent_freshness does not abort its caller's set -e on a stale (warn-only) finding" {
  _make_stale_repo
  _check_under_set_e
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *"WARNING"* ]] || return 1
  [[ "$output" == *"REACHED-THE-END"* ]] || return 1
}

@test "iris_check_agent_freshness does not abort its caller's set -e when the checkout is fresh" {
  _make_stale_repo
  git -C "$R" checkout -q main
  _check_under_set_e
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *"REACHED-THE-END"* ]] || return 1
}

@test "warns (does not block) by default when the checkout is behind main under the checked paths" {
  _make_stale_repo
  _check
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"WARNING"* ]] || return 1
  [[ "$output" == *"behind main"* ]]
}

@test "names the missing commit(s) in the warning" {
  _make_stale_repo
  _check
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"C2: touches device/agent"* ]]
}

@test "IRIS_REQUIRE_FRESH_AGENT=1 turns the same finding into a hard failure" {
  _make_stale_repo
  _check IRIS_REQUIRE_FRESH_AGENT=1
  [ "$status" -eq 1 ] || return 1
  [[ "$output" == *"refusing to build a stale agent"* ]]
}

@test "IRIS_ALLOW_STALE_AGENT_ACK=1 overrides IRIS_REQUIRE_FRESH_AGENT=1" {
  _make_stale_repo
  _check IRIS_REQUIRE_FRESH_AGENT=1 IRIS_ALLOW_STALE_AGENT_ACK=1
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"WARNING"* ]]
}

@test "no warning when HEAD already carries everything main has" {
  _make_stale_repo
  git -C "$R" checkout -q main
  _check
  [ "$status" -eq 0 ] || return 1
  [ -z "$output" ]
}

@test "no warning when main only diverged in paths outside the checked pathspec" {
  _make_repo_stale_elsewhere
  _check
  [ "$status" -eq 0 ] || return 1
  [ -z "$output" ]
}

@test "a merged feature tip with identical source is fresh despite the merge commit" {
  # Identical timestamps must not choose which side survives Git's path-history
  # simplification. Give main an independent commit with the same source tree:
  # it remains absent from feature's ancestry regardless of merge walk order.
  export GIT_AUTHOR_DATE=2020-01-01T00:00:00Z GIT_COMMITTER_DATE=2020-01-01T00:00:00Z
  _make_stale_repo
  git -C "$R" branch feature main
  git -C "$R" branch -f main "$C1"
  git -C "$R" checkout -q main
  echo "two" > "$R/device/agent/a.py"
  git -C "$R" add device/agent/a.py
  git -C "$R" commit -q -m "Independent identical agent source"
  git -C "$R" merge -q --no-ff feature -m "Merge feature"
  git -C "$R" checkout -q feature
  [ "$(git -C "$R" rev-list --count HEAD..main -- device/agent)" -eq 1 ]
  git -C "$R" diff --exit-code HEAD main -- device/agent
  _check_under_set_e IRIS_REQUIRE_FRESH_AGENT=1
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" != *"WARNING"* ]]
}

_make_merged_feature_with_newer_agent() {
  export GIT_AUTHOR_DATE=2020-01-01T00:00:00Z GIT_COMMITTER_DATE=2020-01-01T00:00:00Z
  _make_stale_repo
  git -C "$R" branch feature main
  git -C "$R" branch -f main "$C1"
  git -C "$R" checkout -q main
  echo "two" > "$R/device/agent/a.py"
  git -C "$R" add device/agent/a.py
  git -C "$R" commit -q -m "Independent identical agent source"
  git -C "$R" merge -q --no-ff feature -m "Merge feature"
  MERGED_FEATURE="$(git -C "$R" rev-parse feature)"
  git -C "$R" checkout -q feature
  echo "newer feature" > "$R/device/agent/a.py"
  git -C "$R" add device/agent/a.py
  git -C "$R" commit -q -m "Continue agent work after merge"
}

@test "newer feature source is fresh when its merge into main added no guarded changes" {
  _make_merged_feature_with_newer_agent
  [ "$(git -C "$R" rev-list --count HEAD..main -- device/agent)" -gt 0 ]
  [ "$(git -C "$R" merge-base HEAD main)" = "$MERGED_FEATURE" ]
  git -C "$R" diff --exit-code "$MERGED_FEATURE" main -- device/agent device/verify_image.py device/iox
  run git -C "$R" diff --quiet HEAD main -- device/agent
  [ "$status" -eq 1 ]
  _check_under_set_e IRIS_REQUIRE_FRESH_AGENT=1
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *"REACHED-THE-END"* ]]
  [[ "$output" != *"WARNING"* ]]
}

@test "newer feature source still fails when main adds a genuine guarded change after merge" {
  _make_merged_feature_with_newer_agent
  git -C "$R" checkout -q main
  echo "upstream verification fix" > "$R/device/verify_image.py"
  git -C "$R" add device/verify_image.py
  git -C "$R" commit -q -m "New upstream verification fix"
  git -C "$R" checkout -q feature
  [ "$(git -C "$R" merge-base HEAD main)" = "$MERGED_FEATURE" ]
  _check_under_set_e IRIS_REQUIRE_FRESH_AGENT=1
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ "$output" == *"New upstream verification fix"* ]]
  [[ "$output" == *"refusing to build a stale agent"* ]]
  [[ "$output" != *"REACHED-THE-END"* ]]
}

@test "identical cherry-picked source is fresh but differing upstream bytes still fail" {
  _make_stale_repo
  upstream="$(git -C "$R" rev-parse main)"
  git -C "$R" checkout -q -b feature
  echo "feature" > "$R/unrelated.txt"
  git -C "$R" add unrelated.txt
  git -C "$R" commit -q -m "Unrelated feature"
  git -C "$R" cherry-pick "$upstream"
  _check IRIS_REQUIRE_FRESH_AGENT=1
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ -z "$output" ]
  git -C "$R" checkout -q main
  echo "three" > "$R/device/agent/a.py"
  git -C "$R" add device/agent/a.py
  git -C "$R" commit -q -m "New upstream source"
  git -C "$R" checkout -q feature
  _check IRIS_REQUIRE_FRESH_AGENT=1
  [ "$status" -eq 1 ]
}

@test "does nothing outside a git checkout" {
  R="$TMP/not-a-repo"
  mkdir -p "$R"
  _check
  [ "$status" -eq 0 ] || return 1
  [ -z "$output" ]
}

@test "does nothing when no reference branch can be resolved" {
  R="$TMP/repo"
  mkdir -p "$R/device/agent"
  git -C "$TMP" init -q -b trunk repo   # no 'main', no 'origin/main'
  echo "one" > "$R/device/agent/a.py"
  git -C "$R" add -A
  git -C "$R" commit -q -m "C1"
  _check
  [ "$status" -eq 0 ] || return 1
  [ -z "$output" ]
}

# ---------------------------------------------------------------------------
# Wiring: the real build scripts actually call the guard, and stop BEFORE
# any docker step when it refuses (safe to run here -- these tests never
# reach `docker build`).
# ---------------------------------------------------------------------------

_stage_iox_build_script() {
  mkdir -p "$R/device/iox"
  cp "$REPO_ROOT/device/iox/build.sh" "$R/device/iox/build.sh"
  cp "$REPO_ROOT/device/iox/package.yaml" "$R/device/iox/package.yaml"
  mkdir -p "$R/tools"
  cp "$FRESHNESS" "$R/tools/agent-source-freshness.sh"
}

@test "device/iox/build.sh refuses before any docker step when IRIS_REQUIRE_FRESH_AGENT=1 and the checkout is stale" {
  _make_stale_repo
  _stage_iox_build_script
  run env IRIS_REQUIRE_FRESH_AGENT=1 bash "$R/device/iox/build.sh"
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ "$output" == *"refusing to build a stale agent"* ]] || { echo "$output"; return 1; }
  # never got as far as staging the aria2c binary (long before any docker call)
  [[ "$output" != *"staging"*"aria2c"* ]]
}

@test "device/iox/build.sh only warns (proceeds past the guard) by default when stale" {
  _make_stale_repo
  _stage_iox_build_script
  # Let it proceed past the guard, then fail on the NEXT missing input
  # (aria2c) rather than reaching docker -- proves the guard did not block.
  run -127 env bash "$R/device/iox/build.sh"
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"WARNING"* ]] || { echo "$output"; return 1; }
  [[ "$output" != *"refusing to build a stale agent"* ]]
}

# Regression: a build context WITHOUT tools/agent-source-freshness.sh (e.g. a
# checkout old enough to predate this guard -- precisely the stale-worktree
# case it exists to catch) must not turn the missing guard script itself into
# a raw "No such file or directory" abort that masks every real error after
# it. Caught by device/iox/tests/test_iox_build_aria2c.bats and
# test_iox_build_cert.bats, whose STUBDIR fixtures build a fake $REPO without
# copying tools/ into it at all.
@test "device/iox/build.sh proceeds normally (no crash) when tools/agent-source-freshness.sh is absent from the checkout" {
  mkdir -p "$TMP/repo/device/iox" "$TMP/repo/device/agent"
  R="$TMP/repo"
  cp "$REPO_ROOT/device/iox/build.sh" "$R/device/iox/build.sh"
  cp "$REPO_ROOT/device/iox/package.yaml" "$R/device/iox/package.yaml"
  echo "# dummy" > "$R/device/agent/dummy.py"
  # deliberately NO $R/tools at all
  run -127 env -u ARIA2C_BIN bash "$R/device/iox/build.sh" --arm64
  [ "$status" -ne 0 ] || { echo "$output"; return 1; }
  # fails on the NEXT real thing build.sh needs (the common image builder is
  # missing), not on the freshness guard's own sourcing -- the buggy version
  # of this fixed a `build.sh: line N: .../tools/agent-source-freshness.sh:
  # No such file or directory` abort right there, before this message.
  [[ "$output" == *"build-device-image.sh"* ]] || { echo "$output"; return 1; }
  [[ "$output" != *"agent-source-freshness.sh: No such file or directory"* ]] \
    || { echo "$output"; return 1; }
}

_stage_xr_build_script() {
  mkdir -p "$R/device/xr"
  mkdir -p "$R/tools"
  cp "$REPO_ROOT/tools/build-xr-package.sh" "$R/tools/build-xr-package.sh"
  cp "$FRESHNESS" "$R/tools/agent-source-freshness.sh"
  echo "0.0.0-test" > "$R/VERSION"
}

@test "tools/build-xr-package.sh refuses before any docker step when IRIS_REQUIRE_FRESH_AGENT=1 and the checkout is stale" {
  _make_stale_repo
  # build-xr-package.sh checks device/xr/* too -- give it the real ones
  mkdir -p "$R/device/xr"
  git -C "$R" show main:device/agent/a.py >/dev/null 2>&1 || true
  _stage_xr_build_script
  run env IRIS_REQUIRE_FRESH_AGENT=1 bash "$R/tools/build-xr-package.sh"
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ "$output" == *"refusing to build a stale agent"* ]] || { echo "$output"; return 1; }
  [[ "$output" != *"staging pinned catalog cert"* ]]
}
