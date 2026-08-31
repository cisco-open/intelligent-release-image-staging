#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Record-driven inverse of device/xr-install.sh. IRIS on a Cisco 8000-series
# IOS-XR router is: the appmgr application '$APPID' (default iris), its
# registered package source '$SOURCE_NAME' (default iris-xr), the RPM staged
# at harddisk: root, the agent's own iris-work/ control-file directory
# under the bind-mounted harddisk: (agentinfo/plans/2026-08-28-xr-agent.md,
# Task 3), and any *.torrent/*.aria2/*.peers.json sidecar aria2 or the agent
# left at harddisk: ROOT. Sidecars land there, not inside iris-work/, because
# this platform has no placement step -- aria2 downloads each image straight
# to its final harddisk: location (xr_deps.py module docstring), so the
# metadata/progress/transfer-record files that ride alongside it never leave that
# same directory either. Unlike the router/IOx twins, XR activation uses
# ONLY --net=host -- no VirtualPortGroup, VLAN, SVI, or NAT is ever created,
# so there is no operator-owned network config an undeploy could
# accidentally touch.
# EVERY artifact IRIS ever creates here already carries its own name, so a
# record-driven teardown and an IRIS_FORCE_AGENT_ONLY=1 teardown remove
# exactly the same footprint -- FORCE exists for interface parity with the
# router/IOx uninstallers (a device stranded mid-onboard, no record to hand
# this script), not because XR needs a reduced-scope path the way they do.
#
# 'appmgr package uninstall source <name>' is the Cisco 8000 form (this
# script's only target platform; see plan Out of scope). The fallback form,
# 'appmgr package uninstall package <pkg-name>', addresses the SAME
# artifact by its full versioned package name instead of its source name --
# Cisco's own doc set disagrees on which form is current vs. deprecated
# across platforms (agentinfo/xr-support/research/xrfact-appmgr-docker-hosting.md);
# this script only ever uses the source form, which is unambiguous here.
#
# File removal rides the native XR EXEC 'delete /noprompt <path>' command
# under harddisk: -- NEVER 'run' (see the teardown-speed composite section
# below: 'run <cmd>' executes but never yields the piped -tt session's prompt
# back, hanging every line typed after it in the same login; deterministic on
# 8010-R4/100.90.170.84, intermittent on 8010-R1 -- same signature). 'delete
# /noprompt' returns cleanly in seconds and evaluates harddisk: globs, both
# hardware-proven (progress.md 8010-R4 probe matrix, 2026-08-31). 'delete'
# WITHOUT /noprompt hangs on its own [confirm] prompt (a piped newline never
# satisfies it) and 'rmdir' hangs the same way on its [y|n] prompt, so
# neither is ever used here. '/recurse' is invalid syntax in both flag
# orders -- an existing directory is emptied via its own glob
# (harddisk:/<dir>/*) then removed as a bare path: two commands, not one.
#
# No 'copy running-config startup-config': IOS-XR has no running/startup
# split to bridge -- 'commit' IS the persisted state.
#
# --- Teardown-speed composite (agentinfo/specs/2026-08-31-xr-teardown-speed.md
# section 2A) -----------------------------------------------------------------
# The per-step design used to make 6-11 separate lab/xr-run.sh logins per
# teardown (agentinfo/xr-support/teardown-speed-recon.md section 2.1) -- every
# one of those a full opportunity to burn the session wall-clock bound if
# 8010-R1's intermittent exec-spawn stall hit (the same recon's timing table:
# every live-recovered teardown burned ~3 stalled-to-the-bound sessions,
# 15.5-16 minutes total). Below, this collapses into AT MOST TWO bounded
# logins (spec amendment, review of this task's original design: two, not
# one -- see the "why two, not one" paragraph below), split on a SAFETY
# boundary, not a topical one:
#
#   session 1/2 (setup_request/run_setup): READ-ONLY probe + the one
#   genuinely unconditional-but-adjudicated write (deactivate). NOTHING
#   DESTRUCTIVE to the package/files rides this login.
#
#   session 2/2 (sweep_verify_request/run_sweep_verify): the destructive
#   commands (source uninstall, delete the RPM, empty-then-delete the work
#   dir) + the sidecar sweep (three unconditional harddisk: root globs --
#   *.torrent, *.aria2, *.peers.json; no listing needed, see the fix-wave
#   note below) + the final three-way verify -- composed and sent ONLY when
#   session 1's paired adjudication (below) did NOT conclude the app is a confirmed real
#   failure. A rejected-while-present deactivate exits before session 2 is
#   even built, so in that case NOTHING destructive is ever composed, let
#   alone sent -- table below.
#
# This ordering is the point: a session-2 stall or transport failure now
# fails BEFORE any destruction happens (session 2 hasn't been reached yet
# only in the paired-adjudication-failure case; in every OTHER case session 2
# is a single atomic login, so a stall inside IT can still land after the
# destructive lines were already typed at the device's prompt -- there is no
# way to bound "already sent over the wire" any tighter than one login
# without literally splitting destruction and verification into their own
# separate logins, which reintroduces the very stall-multiplication problem
# this whole task exists to remove). What this restructure actually buys is
# narrower and real: the one case this codebase has hard evidence for
# (D2's own incident -- deactivate silently skipped while the app kept
# running) can no longer be followed by an uninstall/rm against a device this
# script has already concluded is still running the app.
#
# Why two logins, not one: this is now purely a SAFETY-ordering constraint,
# not a structural one. (An earlier draft of this comment also cited a
# structural reason -- session 1's own `ls` result was needed to know which
# bare paths to hand a targeted `rm`. That reason is GONE: the fix-wave
# rewrite below replaced the listing+targeted-delete design with three
# unconditional harddisk: root globs, hardware-proven safe -- see
# sweep_verify_request()'s comment.) The safety reason stands on its own:
# there is no interactive transport here to react to a login's output before
# it ends (lab/xr-run.sh pipes the whole request in and reads the whole
# transcript back only once the session is over; making it react mid-stream
# is out of this script's own scope), so "adjudicate deactivate, THEN decide
# whether to compose and send anything destructive" can only happen BETWEEN
# two separate logins -- never within a single one, no matter what CLI
# syntax the destructive step itself uses. At most two logins is still a
# large win over the old per-step design's 6-11: worst case, a wedged router
# now burns at most 2x the session bound per teardown, not ~3x-11x, and a
# healthy teardown is one or two short logins instead of six-to-eleven.
#
# Per-step honesty is unchanged in kind, not just carried over as a slogan:
# every step still gets its own [n/5] marker on this script's OWN stdout (the
# same line gui_onboard's job log streams verbatim and the console's
# jobPhaseSuffix regex reads -- server/webroot/app.js:416,
# `/\[(\d+\/\d+)\]/.exec(job.last_line)` -- so the exact `[n/5] ...` text
# below is pinned, not decorative), the SAME rc-capture/end-marker/anchored-
# match discipline the old per-step [5/5] used (verify_section/end_after_start/
# table_contains/files_line_match, all unchanged below), and the SAME
# hostname-contains-appid fail-closed guard (table_contains excludes prompt
# lines, which is what actually defeats a router hostname that happens to
# contain the app id/source name). Steps [2/5]-[5/5] are only narrated on
# stdout once session 2 is actually about to be composed -- printing them
# earlier (as an early draft of this task did) would have claimed steps were
# attempted that a paired-adjudication failure now means never even got
# composed, let alone sent.
#
# Dry-run honesty: dry-run calls setup_request()/sweep_verify_request()
# directly (with include_destructive=1, since dry-run has no live device to
# adjudicate against) and prints their REAL
# output -- the same functions the live path sends over RUN(), not a
# hand-maintained second copy of the command text. This was a plain
# re-description in an earlier draft of this task; that risked exactly the
# kind of drift this whole task is about (dry-run claiming a shape the live
# path had already changed out from under it) -- one builder, one source of
# truth, for both paths.
#
# Deactivate is the one command that is genuinely NEW unconditional behavior
# here (recon table, row 1): today it is client-gated -- never sent at all
# against an app the probe already found absent. The composite sends it
# every run, unconditionally, and adjudicates the result by PAIRING the
# EARLY probe (before deactivate, in the same login) against whatever the
# deactivate section shows, rather than trying to parse XR's actual
# benign-vs-real error text for "remove an already-absent appmgr application"
# -- that text was never measured on 25.4.2 (recon section 3, row 1: UNKNOWN).
# What XR's own generic command-rejection banner looks like on this exact
# router IS measured (LAB-RESULTS-2026-08-27.md: `run sh -c "..."` came back
# `% Invalid input detected`) -- xr_command_rejected() below keys off that
# proven, generic string, never the unknown appmgr-specific one. Pairing:
#   - probe showed the app ABSENT before deactivate ran => benign no matter
#     what deactivate's own output looks like (there was nothing to remove);
#     log "already deactivated/absent; skipping", then compose and send
#     session 2 (destructive commands included -- there is nothing left to
#     protect).
#   - probe showed the app PRESENT and deactivate's own section carries that
#     proven rejection banner => a real failure, fail loud (refuse to
#     continue -- the SAME "still active" exit this script has always used).
#     Session 2 is NEVER composed, so NOTHING destructive -- not the source
#     uninstall, not either `delete /noprompt`, not the sidecar sweep -- is
#     ever sent to a device this script has just concluded is still running
#     the app.
#   - probe showed the app PRESENT and deactivate was NOT rejected =>
#     proceed; session 2 is composed (destructive commands included) and
#     [5/5]'s own independent re-probe there is still the sole arbiter of
#     whether the app is actually gone, exactly as recon row 1 recommends
#     ("let the composite's own final verify be the sole arbiter of whether
#     deactivate worked... sidesteps needing the deactivate command's own
#     benign-vs-real text at all"). The SAME xr_command_rejected() check also
#     guards [5/5]'s own app-table read (belt-and-suspenders: a rejected
#     final-verify probe must never be misread as "clean" any more than a
#     rejected early probe may be misread as "absent" -- the D2-3 incident's
#     failure mode, generalized to every app-table read in this script, not
#     just the first one).
#
# Env (mirrors device/xr-install.sh):
#   DEVICE_IP DEVICE_USER DEVICE_PASS
#   [APPID=iris] [SOURCE_NAME=iris-xr] [IRIS_FORCE_AGENT_ONLY=0]
# Usage:  xr-uninstall.sh [--dry-run]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

APPID="${APPID:-iris}"
SOURCE_NAME="${SOURCE_NAME:-iris-xr}"
FORCE_AGENT_ONLY="${IRIS_FORCE_AGENT_ONLY:-0}"
WORK_DIR_PATH="/misc/disk1/iris-work"
RPM_PATH="/misc/disk1/$SOURCE_NAME.rpm"

# Shared marker family every request below uses -- defined up front (ahead of
# the DEVICE_IP/RUN() setup further down) so dry-run can call the SAME
# request builders it prints, without needing a live device or credentials.
VERIFY_MARKER="__IRIS_XR_VERIFY_"

# ---------------------------------------------------------------------------
# Session 1/2 (setup): early probe, unconditional-but-adjudicated deactivate.
# NOTHING destructive to the package or files rides this login -- see the
# header comment's "why two, not one" and safety-boundary discussion above.
# No sidecar listing here (fix-wave rewrite): the sidecar sweep no longer
# needs one -- see sweep_verify_request() below.
# ---------------------------------------------------------------------------
setup_request() {
cat <<EOF
! ${VERIFY_MARKER}APPS__
show appmgr application-table
! ${VERIFY_MARKER}APPS_END__
! ${VERIFY_MARKER}DEACTIVATE__
configure
no appmgr application $APPID
commit
! ${VERIFY_MARKER}DEACTIVATE_END__
EOF
}

# ---------------------------------------------------------------------------
# Session 2/2 (sweep+verify): the destructive commands -- source uninstall,
# delete the RPM, empty-then-delete the work dir, and the sidecar sweep --
# only when $include_destructive = 1 (set to 1 by the live path ONLY once
# session 1's paired adjudication has NOT concluded a real failure), then the
# final three-way verify. Every destructive line here is native XR EXEC
# 'delete /noprompt <path>' (never 'run' -- see the top-of-file header
# comment and the teardown-speed composite comment above; both proven clean
# on hardware, progress.md 8010-R4 probe matrix, 2026-08-31).
#
# Fix-wave rewrite (this task): the sidecar sweep used to need session 1's
# own `ls` result to build one targeted `run rm -f <bare-name>` per matched
# file (never a glob handed to `run` -- unproven quote/glob handling, same
# trap as IOS-XE Guest Shell). That whole listing+match step is GONE: XR's
# native `delete /noprompt` evaluates harddisk: globs directly
# (hardware-proven: a verified-existing file was removed via
# `delete /noprompt harddisk:/*.torrent`), so the sweep is now three
# unconditional glob deletes at harddisk: root -- no listing, no per-name
# match, and session 1 no longer needs to list anything for this step's
# sake (see setup_request() above).
#
# This is the SAME builder for FORCE and record-driven paths -- FORCE only
# prepends a client-side banner before session 1, it never changes either
# composed stream, so the byte-parity test compares the real, complete
# streams.
#
# Run-4 fix wave (hardware ruling, 2026-08-31): the FILES read alone can no
# longer decide whether a present iris-work is a real leftover -- XR's CLI
# has NO prompt-free directory removal (bare `delete /noprompt <dir>` does
# NOT remove a directory -- its earlier apparent "success" was against a
# path already gone; `rmdir` prompts `[y|n]` and hangs; `rmdir /noprompt` is
# invalid syntax), so an iris-work that survives session 2's own
# empty-then-delete attempt may legitimately be empty, inert residue. The
# WORKDIR section (`dir harddisk:/iris-work`) rides right after FILES so
# [5/5] can disambiguate that from a genuine leftover -- see the
# adjudication below.
# ---------------------------------------------------------------------------
sweep_verify_request() {
  local include_destructive="$1"
  local destructive=""
  if [ "$include_destructive" = "1" ]; then
    destructive="$(printf 'appmgr package uninstall source %s\ndelete /noprompt harddisk:/%s\ndelete /noprompt harddisk:/%s/*\ndelete /noprompt harddisk:/%s\ndelete /noprompt harddisk:/*.torrent\ndelete /noprompt harddisk:/*.aria2\ndelete /noprompt harddisk:/*.peers.json\n' \
      "$SOURCE_NAME" "${RPM_PATH##*/}" "${WORK_DIR_PATH##*/}" "${WORK_DIR_PATH##*/}")"
  fi
cat <<EOF
$destructive
! ${VERIFY_MARKER}APPS__
show appmgr application-table
! ${VERIFY_MARKER}SOURCES__
show appmgr source-table
! ${VERIFY_MARKER}FILES__
dir harddisk:
! ${VERIFY_MARKER}WORKDIR__
dir harddisk:/iris-work
! ${VERIFY_MARKER}DONE__
EOF
}

if [ "$DRY" -eq 1 ]; then
  if [ "$FORCE_AGENT_ONLY" = "1" ]; then
    echo "===== FORCE: reclaiming only IRIS-marked artifacts (no deployment record) ====="
    echo "  The app named '$APPID', the source named '$SOURCE_NAME', and the"
    echo "  iris-work/ dir -- the same set a record-driven undeploy removes, since"
    echo "  XR activation (--net=host only) never creates anything else IRIS"
    echo "  would need a deployment record to prove ownership of."
  fi
  echo "===== composite session 1/2 (setup): probe, deactivate -- NOTHING destructive ====="
  echo "===== [1/5] deactivate: probe app-table first; unconditional no appmgr application $APPID / commit ====="
  setup_request
  echo "  (already absent before deactivate: benign idempotent-skip; still active and rejected: fail-closed, refuse to continue -- session 2 is never composed or sent in that case)"
  echo "===== composite session 2/2 (sweep+verify): composed ONLY when session 1 did not conclude real failure ====="
  echo "===== [2/5] appmgr package uninstall source $SOURCE_NAME (Cisco 8000 form) ====="
  echo "===== [3/5] remove IRIS files under harddisk: (native XR delete /noprompt, never run -- proven clean return) ====="
  echo "===== [4/5] sweep leftover IRIS sidecars (*.torrent, *.aria2, *.peers.json) at harddisk: root -- three unconditional glob deletes, no listing needed ====="
  echo "===== [5/5] verify no '$APPID' app, '$SOURCE_NAME' source, IRIS file, or sidecar remains (dir harddisk:) ====="
  sweep_verify_request 1
  echo "===== NOT DONE: no 'copy running-config startup-config' -- XR commit IS the persisted state ====="
  echo "===== LEFT IN PLACE: any operator-staged image already on harddisk: ====="
  exit 0
fi

: "${DEVICE_IP:?set DEVICE_IP}"; : "${DEVICE_USER:?set DEVICE_USER}"
: "${DEVICE_PASS:?set DEVICE_PASS}"
RUN() { "$HERE/../lab/xr-run.sh" "$DEVICE_IP"; }   # XR commands on stdin

# Shared marker-section reader: every read-only/adjudicated section below (the
# early app-table probe, the deactivate block, and the final three-way
# verify) rides the SAME VERIFY_MARKER family
# (`! __IRIS_XR_VERIFY_<NAME>__`, defined above), so a missing marker is
# always a hard transport error, never silently read as "nothing there" the
# way an empty section otherwise could be.
#
# `!`, not `echo` (live run 3 fix, hardware-proven): XR has NO `echo` EXEC
# command -- every `echo __IRIS_XR_VERIFY_...__` line used to mint its own
# `% Invalid input` banner INSIDE the very section it was meant to delimit,
# which xr_command_rejected() then (correctly) read as a real rejection,
# producing a false "probe was rejected" failure (this was runs 1-2's false
# absents too, under the pre-fix-wave code, before that banner's source was
# understood). XR treats `! <text>` as a silent comment at BOTH exec and
# config level -- proven on hardware with zero `% Invalid input` hits -- so
# every marker line here, config-mode sections included (the DEACTIVATE_END
# marker rides right after `commit`, still inside config mode), uses `!`.
# The -tt pty still echoes the input line into the transcript, so a marker
# now arrives as `RP/.../CPU0:hostname#! __IRIS_XR_VERIFY_APPS__` rather
# than a bare line -- verify_section()/end_after_start() below need no
# change for this: both search for the marker text as a substring anywhere
# in the captured blob, never anchored to the start of a line, so whatever
# prompt/`#!` prefix rides ahead of it on the same line is irrelevant.
#
# LAST match, not first: the real transport (ssh -tt via lab/xr-run.sh)
# echoes the ENTIRE piped request back as one upfront blob before anything
# actually executes, so every marker's FIRST occurrence sits inside that
# echoed blob -- its "section" there is just the next TYPED line, never
# real command output. The identical bug was found live in the Python XR
# preflight probe (commit 6fd43db, server/gui_onboard.py) and fixed the
# same way there: take the LAST occurrence, which is always the executed
# one. A stub transport with no upfront echo (bats) has exactly one
# occurrence per marker, so this is behavior-identical there.
verify_section() {
  python3 -c 'import re, sys
marker = "__IRIS_XR_VERIFY_"
name = sys.argv[1]
text = sys.stdin.read()
start = marker + name + "__"
matches = list(re.finditer(re.escape(start) + r"\r?\n?(.*?)(?=" + re.escape(marker) + r"[A-Z_]+__|\Z)", text, re.DOTALL))
if not matches:
    sys.exit(1)
sys.stdout.write(matches[-1].group(1))' "$1"
}

# Positional end-after-start check: a plain substring test for an end
# marker (`case "$text" in *"$end_marker"*)`) is USELESS against the same
# echoing transport verify_section guards against above -- the upfront
# echoed blob already contains a literal copy of the end marker's own text
# (it is part of what was piped in), so the substring is always "found"
# starting from the very first byte, whether or not the REAL execution ever
# reached it. This must compare byte positions instead: the executed end
# marker is only real if its LAST occurrence in the transcript comes AFTER
# the start marker's LAST (executed) occurrence.
end_after_start() {
  python3 -c 'import sys
text = sys.stdin.read()
start_marker, end_marker = sys.argv[1], sys.argv[2]
si = text.rfind(start_marker)
ei = text.rfind(end_marker)
sys.exit(0 if (si != -1 and ei != -1 and ei > si) else 1)' "$1" "$2"
}

# ERE-metacharacter escape for a LITERAL string that is about to be
# interpolated into a grep -E pattern below. APPID/SOURCE_NAME are
# operator-supplied overrides (env vars), not fixed literals -- without
# this, an override containing a regex metacharacter (e.g. APPID=iris.x)
# would have its '.' read as "any character" by table_contains()'s ERE,
# silently loosening the match: an unrelated table row like "irisAx" would
# then count as the app being present/absent, defeating the very
# word-anchoring this file's match functions exist to provide.
ere_escape() {
  printf '%s' "$1" | sed -e 's/[][\.^$*+?(){}|\\]/\\&/g'
}

# Word-anchored match against real table DATA lines only, excluding prompt
# lines. A router hostname that happens to CONTAIN the search term (e.g.
# host "iris-lab-8010" while probing for app "iris") would otherwise make
# an EMPTY app/source table look "present" forever via the prompt string
# embedded in the transcript (RP/0/RP0/CPU0:iris-lab-8010#) -- a plain
# substring test reads that as a permanent false-positive and never
# converges. Prompt lines always contain '#' (the XR exec prompt
# terminator); real appmgr application-table/source-table data rows never
# do. $2 is always a literal name (APPID or SOURCE_NAME) -- ere_escape()
# keeps it that way inside the ERE grep -E builds.
table_contains() {
  printf '%s\n' "$1" | grep -v '#' | grep -qE "(^|[[:space:]])$(ere_escape "$2")([[:space:]]|$)"
}

# $-anchored, per-line match against the harddisk: file listing (one
# dir-entry per line, suffix-anchored) instead of a whole-blob substring
# test, which would otherwise flag an unrelated operator file that merely
# CONTAINS the target text as a forbidden IRIS leftover forever (iris-workshop.txt for
# "iris-work"; notes.aria2.bak for ".aria2"). Callers hand this a COMPLETE
# ERE (metacharacters intentional, e.g. the anchors and the escaped literal
# dot in the RPM-suffix patterns below) -- unlike table_contains(), this
# function does not escape $2 itself; any operator-supplied name folded
# into a pattern must be ere_escape()'d at the call site first.
files_line_match() {
  printf '%s\n' "$1" | grep -qE "$2"
}

# Run-4 fix wave: distinguishes an EMPTY iris-work directory (inert residue
# -- see the [5/5] adjudication below) from a genuine leftover. "Has
# entries" means the WORKDIR section (`dir harddisk:/iris-work`) contains
# any line beyond a blank line or the "Directory of ..." header XR's own
# `dir` command always prints, whether or not the directory holds anything
# (the same header shape [5/5]'s own top-level `dir harddisk:` read already
# carries -- see FAKE_DIR_HARDDISK in the bats suite). Biased toward
# "has entries" on any unrecognized line, so an unexpected output shape
# fails closed (still forbidden) rather than risking a real leftover being
# silently waved through as empty residue.
workdir_has_entries() {
  printf '%s\n' "$1" | grep -v '^[[:space:]]*$' | grep -v '^Directory of ' | grep -q .
}

# D2-3 regression guard, generalized to every app-table read in this script
# (not just the first one): XR's generic CLI command-rejection banner is
# hardware-proven (LAB-RESULTS-2026-08-27.md -- `run sh -c "..."` came back
# `% Invalid input detected`). A section carrying that banner must never be
# read as "nothing there" -- table_contains()'s absence of a match is
# otherwise indistinguishable from a genuinely empty table, which is exactly
# the D2-3 incident: the old invalid probe command form's (never spelled out
# here -- see the regression pin in device/tests/test_xr_uninstall.bats)
# rejection was misread as "app absent" and deactivate was silently skipped
# while the app kept running. This deliberately does NOT try to recognize the
# unknown, unmeasured appmgr-specific "remove an already-absent application"
# error text (recon section 3, row 1) -- only this one proven, generic banner.
xr_command_rejected() {
  printf '%s\n' "$1" | grep -qF '% Invalid input'
}

if [ "$FORCE_AGENT_ONLY" = "1" ]; then
  echo "===== FORCE: reclaiming only IRIS-marked artifacts on $DEVICE_IP (no deployment record) ====="
  echo "  Removing: app '$APPID', source '$SOURCE_NAME', $RPM_PATH, $WORK_DIR_PATH."
fi

SETUP_OUT="$(setup_request | RUN 2>/dev/null)"
SETUP_RC=$?
# The transport's own exit status matters here in the same way it does for
# every other read/adjudicated section in this login: a wedged session that
# the session bound kills (rc 124) or any other nonzero transport failure
# must never be read as "app absent" or "nothing to report" just because the
# captured text happens to be empty.
#
# Fix-wave ordering fix (live-reproduced twice, progress.md L2 RUN 1/2,
# 100.90.170.84, 2026-08-31): the [1/5] step line below used to print
# BEFORE this rc check, unconditionally, right after the step's own
# announcement -- a dead transport (rc 124 at the session bound) still let
# that line reach stdout first, and its wording ("no appmgr application
# $APPID on $DEVICE_IP") reads exactly like a genuine absent-app verdict on
# any log that streams stdout without also surfacing the stderr ERROR
# right after it. The check now runs FIRST; on a transport failure this
# function returns/exits before [1/5] is ever printed, so a dead transport
# now yields ONLY the honest transport error below, never a line that could
# be misread as a verdict.
if [ "$SETUP_RC" -ne 0 ]; then
  echo "ERROR: teardown setup's transport exited $SETUP_RC; refusing to continue teardown on $DEVICE_IP" >&2
  exit 1
fi
APPS_BEFORE="$(printf '%s' "$SETUP_OUT" | verify_section APPS)" \
  || { echo "ERROR: deactivate probe did not return the appmgr application-table; refusing to continue teardown on $DEVICE_IP" >&2; exit 1; }
if ! printf '%s' "$SETUP_OUT" | end_after_start "${VERIFY_MARKER}APPS__" "${VERIFY_MARKER}APPS_END__"; then
  echo "ERROR: deactivate probe was truncated before its end marker; refusing to continue teardown on $DEVICE_IP" >&2
  exit 1
fi
if xr_command_rejected "$APPS_BEFORE"; then
  echo "ERROR: the appmgr application-table probe was rejected by the device; refusing to continue teardown on $DEVICE_IP" >&2
  exit 1
fi
# Transport succeeded and the probe section's integrity is verified -- only
# now is it honest to announce this step at all.
echo "[1/5] deactivate: no appmgr application $APPID on $DEVICE_IP"
PRESENT_BEFORE=0
table_contains "$APPS_BEFORE" "$APPID" && PRESENT_BEFORE=1

DEACT="$(printf '%s' "$SETUP_OUT" | verify_section DEACTIVATE)" \
  || { echo "ERROR: deactivate did not return its own section; refusing to continue teardown on $DEVICE_IP" >&2; exit 1; }
if ! printf '%s' "$SETUP_OUT" | end_after_start "${VERIFY_MARKER}DEACTIVATE__" "${VERIFY_MARKER}DEACTIVATE_END__"; then
  echo "ERROR: deactivate was truncated before its end marker; refusing to continue teardown on $DEVICE_IP" >&2
  exit 1
fi

# Paired adjudication (agentinfo/specs/2026-08-31-xr-teardown-speed.md
# section 2A): never trust deactivate's own (unmeasured) benign-vs-real
# error text. The early probe above already answered "was there anything to
# deactivate" -- pair THAT against the proven generic rejection banner. This
# exit is the ONLY path to the "still active" error below, and it is reached
# BEFORE session 2 (the destructive commands) is ever composed, let alone
# sent -- so this message stays accurate: teardown really has been refused
# before anything destructive happened.
if [ "$PRESENT_BEFORE" -eq 0 ]; then
  echo "  $APPID already deactivated/absent; skipping"
elif xr_command_rejected "$DEACT"; then
  echo "ERROR: refusing to continue teardown while application $APPID is still active on $DEVICE_IP" >&2
  exit 1
fi
# else: probe showed it present and deactivate was not rejected -- proceed;
# [5/5] below is the sole arbiter of whether it actually worked.

# Reaching here means session 1's paired adjudication did NOT conclude a
# real failure (the elif branch above already exited otherwise) -- session 2
# is safe to compose, destructive commands included. No sidecar listing to
# carry forward (fix-wave rewrite): sweep_verify_request()'s glob deletes
# need nothing from session 1.
echo "[2/5] appmgr package uninstall source $SOURCE_NAME"
echo "[3/5] remove IRIS files under harddisk: (native XR delete /noprompt)"
echo "[4/5] sweep leftover IRIS sidecars (*.torrent, *.aria2, *.peers.json) at harddisk: root"
echo "[5/5] verify no '$APPID' app, '$SOURCE_NAME' source, IRIS file, or sidecar remains"

# Same honesty contract as session 1/2's probe: capture the transport's own
# exit status instead of discarding it (a wedged/failed session, incl. rc
# 124 under the session bound, must never be read as "clean" just because
# the captured text happens to look empty), and require a trailing DONE
# marker positioned AFTER the real FILES marker -- an echoing transport that
# dies rc 0 right after the executed FILES marker still has the upfront
# echoed blob's own literal copy of every marker's text, so a plain
# substring presence check for DONE would be fooled the same way a plain
# APPS_END substring check would be; only the positional check catches it.
# WORKDIR sits physically between FILES and DONE in the composed stream
# (a single CLI session executes strictly in order), so this same
# FILES-before-DONE positional check also guarantees WORKDIR executed for
# real -- no separate WORKDIR/DONE position check is needed.
VERIFY_OUT="$(sweep_verify_request 1 | RUN 2>/dev/null)"
VERIFY_RC=$?
if [ "$VERIFY_RC" -ne 0 ]; then
  echo "ERROR: undeploy verify's transport exited $VERIFY_RC; refusing to declare $DEVICE_IP clean" >&2
  exit 1
fi
APPS="$(printf '%s' "$VERIFY_OUT" | verify_section APPS)" \
  || { echo "ERROR: undeploy verify did not return the appmgr application-table; refusing to declare $DEVICE_IP clean" >&2; exit 1; }
SOURCES="$(printf '%s' "$VERIFY_OUT" | verify_section SOURCES)" \
  || { echo "ERROR: undeploy verify did not return the appmgr source-table; refusing to declare $DEVICE_IP clean" >&2; exit 1; }
FILES="$(printf '%s' "$VERIFY_OUT" | verify_section FILES)" \
  || { echo "ERROR: undeploy verify did not return the harddisk: file check; refusing to declare $DEVICE_IP clean" >&2; exit 1; }
WORKDIR="$(printf '%s' "$VERIFY_OUT" | verify_section WORKDIR)" \
  || { echo "ERROR: undeploy verify did not return the iris-work directory listing; refusing to declare $DEVICE_IP clean" >&2; exit 1; }
if ! printf '%s' "$VERIFY_OUT" | end_after_start "${VERIFY_MARKER}FILES__" "${VERIFY_MARKER}DONE__"; then
  echo "ERROR: undeploy verify was truncated before its end marker; refusing to declare $DEVICE_IP clean" >&2
  exit 1
fi
if xr_command_rejected "$APPS"; then
  echo "ERROR: undeploy verify's appmgr application-table read was rejected by the device; refusing to declare $DEVICE_IP clean" >&2
  exit 1
fi

forbidden=""
if table_contains "$APPS" "$APPID"; then
  forbidden="${forbidden}${forbidden:+, }appmgr application $APPID"
fi
if table_contains "$SOURCES" "$SOURCE_NAME"; then
  forbidden="${forbidden}${forbidden:+, }appmgr source $SOURCE_NAME"
fi
if files_line_match "$FILES" "(^|[[:space:]])$(ere_escape "$SOURCE_NAME")\\.rpm\$"; then
  forbidden="${forbidden}${forbidden:+, }$RPM_PATH"
fi
if files_line_match "$FILES" '(^|[[:space:]])iris-work$'; then
  # Three-way adjudication (run-4 hardware ruling, 2026-08-31): iris-work
  # existing at root is no longer automatically forbidden. XR's CLI has NO
  # prompt-free directory removal (see sweep_verify_request()'s comment
  # above), so a present iris-work may legitimately be empty, inert residue
  # rather than a real leftover -- its own WORKDIR sub-listing (dir
  # harddisk:/iris-work) disambiguates the two. The SAME D2-3
  # rejected-must-never-read-as-empty discipline applies here: a rejected
  # WORKDIR read is a hard error, never silently read as "empty, therefore
  # benign".
  if xr_command_rejected "$WORKDIR"; then
    echo "ERROR: undeploy verify's iris-work directory listing was rejected by the device; refusing to declare $DEVICE_IP clean" >&2
    exit 1
  fi
  if workdir_has_entries "$WORKDIR"; then
    forbidden="${forbidden}${forbidden:+, }$WORK_DIR_PATH"
  else
    echo "note: empty iris-work directory left behind (XR CLI has no prompt-free directory removal); contents removed"
  fi
fi
if files_line_match "$FILES" '\.torrent$'; then
  forbidden="${forbidden}${forbidden:+, }leftover *.torrent sidecar on harddisk:"
fi
if files_line_match "$FILES" '\.aria2$'; then
  forbidden="${forbidden}${forbidden:+, }leftover *.aria2 sidecar on harddisk:"
fi
if files_line_match "$FILES" '\.peers\.json$'; then
  forbidden="${forbidden}${forbidden:+, }leftover *.peers.json sidecar on harddisk:"
fi

if [ -n "$forbidden" ]; then
  echo "ERROR: artifacts still present after undeploy: $forbidden" >&2
  exit 1
fi
echo "undeploy complete: $DEVICE_IP is clean (any operator-staged image on harddisk: was left in place)"
