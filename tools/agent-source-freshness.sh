#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Shared staleness guard for the agent-baking build scripts (issue #72):
# device/iox/build.sh and tools/build-xr-package.sh both copy the CURRENT
# WORKING-TREE CONTENTS of device/agent (and friends) into their build
# context -- whatever checkout or git worktree the script happens to be run
# from. A build run from a worktree that has fallen behind the project's
# main branch under those paths then silently ships an OLDER agent than a
# build from a fresh checkout, with nothing in the built image or package
# saying so. That is exactly how a stale comparison image made it into a
# size/measurement report: three candidate worktrees stayed at an older
# commit while `main` moved on, and every package built from them carried
# device/agent/iris_agent.py and telemetry_report.py sha256 values that did
# not match the intended baseline -- discovered only by hand, after the
# fact, from the packaged files themselves.
#
# Best-effort ONLY: this never blocks a build that is not a git checkout, or
# where a reference branch cannot be resolved (a CI checkout with only its
# own ref and no local `main`, an exported tarball, a shallow clone with no
# `origin/main`) -- there is nothing to compare against, and that must never
# be why a release build fails. It also never blocks a checkout that is AT
# or AHEAD of the reference branch under the checked paths -- the ordinary
# case for anyone actually working on `main` or a feature branch built on
# top of it.
#
# Usage: source this file, then call
#   iris_check_agent_freshness "$REPO" "device/agent device/verify_image.py device/iox"
# (space-separated pathspecs, relative to $REPO). WARNS on stderr by
# default; set IRIS_REQUIRE_FRESH_AGENT=1 to turn a real finding into a hard
# build failure (exit 1) -- recommended for automation that builds candidate
# images specifically TO COMPARE them against a baseline, where a silent
# source mismatch corrupts the comparison the same way it did here.
# IRIS_ALLOW_STALE_AGENT_ACK=1 builds anyway even under
# IRIS_REQUIRE_FRESH_AGENT=1 (e.g. deliberately reproducing an older
# release) -- an explicit acknowledgement, not a default.

iris_check_agent_freshness() {
  local repo="$1" paths="$2" ref="" label head behind
  git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0
  for label in origin/main main; do
    if git -C "$repo" rev-parse --verify -q "$label" >/dev/null 2>&1; then
      ref="$label"; break
    fi
  done
  [ -n "$ref" ] || return 0
  head="$(git -C "$repo" rev-parse --verify -q HEAD 2>/dev/null || true)"
  [ -n "$head" ] || return 0
  # HEAD already carries everything $ref has (HEAD IS $ref, or is a merge/
  # rebase ahead of it) -- nothing under the checked paths can be stale.
  # An explicit if, not a bare `CMD && return 0`: this file is SOURCED into
  # callers running under `set -e`, and a bare `&&`/`||` statement (as
  # opposed to an if/while CONDITION) still trips errexit on the left side's
  # failure -- the ordinary case here, since --is-ancestor fails whenever
  # $ref is NOT an ancestor of HEAD, which is every genuinely stale checkout
  # this function exists to catch. Getting this wrong silently turned every
  # caller's stale-checkout WARNING into an unconditional hard abort.
  if git -C "$repo" merge-base --is-ancestor "$ref" HEAD 2>/dev/null; then
    return 0
  fi
  behind="$(git -C "$repo" rev-list --count "HEAD..$ref" -- $paths 2>/dev/null || true)"
  case "$behind" in ''|*[!0-9]*) return 0 ;; esac
  [ "$behind" -gt 0 ] || return 0
  {
    echo "!! WARNING: this checkout is $behind commit(s) behind $ref under: $paths"
    echo "   The image/package about to be built will ship OLDER agent code"
    echo "   than $ref. HEAD: $head"
    git -C "$repo" log --oneline "HEAD..$ref" -- $paths 2>/dev/null \
      | sed 's/^/     /' || true
    echo "   Rebase/pull this worktree onto $ref before building for a release"
    echo "   or a comparison against $ref, or set IRIS_ALLOW_STALE_AGENT_ACK=1"
    echo "   to build anyway (e.g. intentionally reproducing an older release)."
  } >&2
  if [ "${IRIS_REQUIRE_FRESH_AGENT:-0}" = "1" ] \
      && [ "${IRIS_ALLOW_STALE_AGENT_ACK:-0}" != "1" ]; then
    echo "!! refusing to build a stale agent (IRIS_REQUIRE_FRESH_AGENT=1);" \
         "set IRIS_ALLOW_STALE_AGENT_ACK=1 to override" >&2
    return 1
  fi
  return 0
}
