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
# File removal rides 'run rm' at the Linux layer (proven:
# agentinfo/xr-support/LAB-RESULTS-2026-08-27.md section 1.3 -- a Linux-layer
# write/delete under /misc/disk1 is immediately visible at harddisk:) rather
# than the native XR 'delete' EXEC command, whose confirmation-prompt and
# recursive-delete syntax were never hardware-exercised. 'run' takes NO
# quotes (same trap already recorded for IOS-XE Guest Shell); every argument
# below is a bare path, so that trap does not apply here.
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
# 15.5-16 minutes total). Below, everything through the sidecar LISTING (probe,
# deactivate, source uninstall, file rm) collapses into ONE login
# (setup_request/run_setup); everything from the sidecar SWEEP through the
# final three-way verify is a SECOND, always-sent login
# (sweep_verify_request/run_sweep_verify). Two logins, not one: the sidecar
# sweep needs the FIRST login's own `ls` result to know which bare paths to
# hand `rm` (never a glob -- see the sidecar-sweep comment below), and there is
# no interactive transport here to react to a login's output before it ends
# (lab/xr-run.sh pipes the whole request in and reads the whole transcript back
# only once the session is over; making it react mid-stream is out of this
# script's own scope). This is a structural constraint, not a benign-error one
# -- flagged as an open question in the recon (section 5, concern 2) with no
# resolution handed to this script, so it stays exactly two bounded logins
# rather than inventing unproven on-device shell/glob syntax to force it to
# one (LAB-RESULTS-2026-08-27.md: bare `run` with no arguments HANGS a piped
# session, and `run sh -c "..."` is REJECTED with `% Invalid input detected` --
# both hardware-proven dead ends for folding list+match+delete into a single
# `run` line). Two logins is still a large win over 6-11: worst case, a
# wedged router now burns at most 2x the session bound per teardown, not
# ~3x-11x, and a healthy teardown is two short logins instead of six-to-eleven.
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
# contain the app id/source name).
#
# Deactivate becomes the one command that is genuinely NEW unconditional
# behavior here (recon table, row 1): today it is client-gated -- never sent
# at all against an app the probe already found absent. The composite sends
# it every run, unconditionally, and adjudicates the result by PAIRING the
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
#     log "already deactivated/absent; skipping" and keep going.
#   - probe showed the app PRESENT and deactivate's own section carries that
#     proven rejection banner => a real failure, fail loud (refuse to
#     continue -- the SAME "still active" exit this script has always used),
#     without composing/sending the sweep+verify login at all.
#   - probe showed the app PRESENT and deactivate was NOT rejected => proceed;
#     [5/5]'s own independent re-probe (in the second login) is still the sole
#     arbiter of whether the app is actually gone, exactly as recon row 1
#     recommends ("let the composite's own final verify be the sole arbiter of
#     whether deactivate worked... sidesteps needing the deactivate command's
#     own benign-vs-real text at all"). The SAME xr_command_rejected() check
#     also guards [5/5]'s own app-table read now (belt-and-suspenders: a
#     rejected final-verify probe must never be misread as "clean" any more
#     than a rejected early probe may be misread as "absent" -- the D2-3
#     incident's failure mode, generalized to every app-table read in this
#     script, not just the first one).
#
# Source uninstall and the two `run rm` file removals are UNCHANGED in kind
# from today (recon table rows 2-3): already unconditional, output already
# discarded, [5/5]'s own three-way check is already the sole arbiter of
# whether they worked. Nothing about making them run inside one composite
# login instead of three separate ones changes that contract.
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

if [ "$DRY" -eq 1 ]; then
  if [ "$FORCE_AGENT_ONLY" = "1" ]; then
    echo "===== FORCE: reclaiming only IRIS-marked artifacts (no deployment record) ====="
    echo "  The app named '$APPID', the source named '$SOURCE_NAME', and the"
    echo "  iris-work/ dir -- the same set a record-driven undeploy removes, since"
    echo "  XR activation (--net=host only) never creates anything else IRIS"
    echo "  would need a deployment record to prove ownership of."
  fi
  echo "===== composite session 1/2 (setup): probe, deactivate, uninstall, rm, sidecar list ====="
  echo "===== [1/5] deactivate: probe app-table first; unconditional no appmgr application $APPID / commit ====="
  echo "show appmgr application-table"
  echo "configure"
  echo "no appmgr application $APPID"
  echo "commit"
  echo "  (already absent before deactivate: benign idempotent-skip; still active and rejected: fail-closed, refuse to continue)"
  echo "===== [2/5] appmgr package uninstall source $SOURCE_NAME (Cisco 8000 form) ====="
  echo "appmgr package uninstall source $SOURCE_NAME"
  echo "===== [3/5] remove IRIS files under harddisk: (Linux layer, proven write-through) ====="
  echo "run rm -f $RPM_PATH"
  echo "run rm -rf $WORK_DIR_PATH"
  echo "===== [4/5] sweep leftover IRIS sidecars (*.torrent, *.aria2, *.peers.json) at harddisk: root ====="
  echo "run ls -1 /misc/disk1"
  echo "===== composite session 2/2 (sweep+verify): sidecar sweep (if any matched), then [5/5] ====="
  echo "run rm -f /misc/disk1/<name>   # one call per matched sidecar name, never a glob"
  echo "===== [5/5] verify no '$APPID' app, '$SOURCE_NAME' source, IRIS file, or sidecar remains (dir harddisk:) ====="
  echo "===== NOT DONE: no 'copy running-config startup-config' -- XR commit IS the persisted state ====="
  echo "===== LEFT IN PLACE: any operator-staged image already on harddisk: ====="
  exit 0
fi

: "${DEVICE_IP:?set DEVICE_IP}"; : "${DEVICE_USER:?set DEVICE_USER}"
: "${DEVICE_PASS:?set DEVICE_PASS}"
RUN() { "$HERE/../lab/xr-run.sh" "$DEVICE_IP"; }   # XR commands on stdin

# Shared marker-section reader: every read-only/adjudicated section below (the
# early app-table probe, the deactivate block, the sidecar listing, and the
# final three-way verify) rides this SAME family of
# `echo __IRIS_XR_VERIFY_<NAME>__` markers, so a missing marker is always a
# hard transport error, never silently read as "nothing there" the way an
# empty section otherwise could be.
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
VERIFY_MARKER="__IRIS_XR_VERIFY_"
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

# Word-anchored match against real table DATA lines only, excluding prompt
# lines. A router hostname that happens to CONTAIN the search term (e.g.
# host "iris-lab-8010" while probing for app "iris") would otherwise make
# an EMPTY app/source table look "present" forever via the prompt string
# embedded in the transcript (RP/0/RP0/CPU0:iris-lab-8010#) -- a plain
# substring test reads that as a permanent false-positive and never
# converges. Prompt lines always contain '#' (the XR exec prompt
# terminator); real appmgr application-table/source-table data rows never
# do.
table_contains() {
  printf '%s\n' "$1" | grep -v '#' | grep -qE "(^|[[:space:]])$2([[:space:]]|$)"
}

# $-anchored, per-line match against the harddisk: file listing -- the same
# shape the sidecar sweep above already uses (one dir-entry per line,
# suffix-anchored) instead of a whole-blob substring test, which would
# otherwise flag an unrelated operator file that merely CONTAINS the target
# text as a forbidden IRIS leftover forever (iris-workshop.txt for
# "iris-work"; notes.aria2.bak for ".aria2").
files_line_match() {
  printf '%s\n' "$1" | grep -qE "$2"
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

# ---------------------------------------------------------------------------
# Session 1/2 (setup): early probe, unconditional deactivate, unconditional
# source uninstall, unconditional file rm, sidecar listing -- one login.
# ---------------------------------------------------------------------------
setup_request() {
cat <<EOF
echo ${VERIFY_MARKER}APPS__
show appmgr application-table
echo ${VERIFY_MARKER}APPS_END__
echo ${VERIFY_MARKER}DEACTIVATE__
configure
no appmgr application $APPID
commit
echo ${VERIFY_MARKER}DEACTIVATE_END__
appmgr package uninstall source $SOURCE_NAME
run rm -f $RPM_PATH
run rm -rf $WORK_DIR_PATH
echo ${VERIFY_MARKER}SIDECARS__
run ls -1 /misc/disk1
echo ${VERIFY_MARKER}SIDECARS_END__
EOF
}

echo "[1/5] deactivate: no appmgr application $APPID on $DEVICE_IP"
echo "[2/5] appmgr package uninstall source $SOURCE_NAME"
echo "[3/5] remove IRIS files under harddisk:"

SETUP_OUT="$(setup_request | RUN 2>/dev/null)"
SETUP_RC=$?
# The transport's own exit status matters here in a way it does not for the
# best-effort source-uninstall/rm commands riding in the same login: a
# wedged session that the session bound kills (rc 124) or any other nonzero
# transport failure must never be read as "app absent" or "nothing to
# report" just because the captured text happens to be empty.
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
# deactivate" -- pair THAT against the proven generic rejection banner.
if [ "$PRESENT_BEFORE" -eq 0 ]; then
  echo "  $APPID already deactivated/absent; skipping"
elif xr_command_rejected "$DEACT"; then
  echo "ERROR: refusing to continue teardown while application $APPID is still active on $DEVICE_IP" >&2
  exit 1
fi
# else: probe showed it present and deactivate was not rejected -- proceed;
# [5/5] below is the sole arbiter of whether it actually worked.

# Sidecar listing rides the SAME login (best-effort, matching today's
# tolerance for a missing/short SIDECARS section -- this is a listing, not a
# safety-critical read like APPS/DEACTIVATE above; a missing section here
# just means no sidecar name is treated as swept-worthy this run, and [5/5]
# still independently catches anything left over).
SIDECAR_NAMES="$(printf '%s' "$SETUP_OUT" | verify_section SIDECARS 2>/dev/null \
  | grep -E '\.(torrent|aria2|peers\.json)$' || true)"

# ---------------------------------------------------------------------------
# Session 2/2 (sweep+verify): sidecar sweep (only the names the listing
# above actually matched -- never a glob handed to 'run', unproven
# quote/glob handling, same trap as IOS-XE Guest Shell), then the final
# three-way verify, one login. Always sent (even with nothing to sweep) --
# [5/5] is the sole arbiter for every unconditional step above.
# ---------------------------------------------------------------------------
sweep_verify_request() {
  local names="$1"
cat <<EOF
$( [ -n "$names" ] && printf '%s\n' "$names" | sed 's#^#run rm -f /misc/disk1/#' )
echo ${VERIFY_MARKER}APPS__
show appmgr application-table
echo ${VERIFY_MARKER}SOURCES__
show appmgr source-table
echo ${VERIFY_MARKER}FILES__
dir harddisk:
echo ${VERIFY_MARKER}DONE__
EOF
}

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
VERIFY_OUT="$(sweep_verify_request "$SIDECAR_NAMES" | RUN 2>/dev/null)"
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
if files_line_match "$FILES" "(^|[[:space:]])${SOURCE_NAME}\\.rpm\$"; then
  forbidden="${forbidden}${forbidden:+, }$RPM_PATH"
fi
if files_line_match "$FILES" '(^|[[:space:]])iris-work$'; then
  forbidden="${forbidden}${forbidden:+, }$WORK_DIR_PATH"
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
