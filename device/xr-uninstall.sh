#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Receipt-driven inverse of device/xr-install.sh. IRIS on a Cisco 8000-series
# IOS-XR router is: the appmgr application '$APPID' (default iris), its
# registered package source '$SOURCE_NAME' (default iris-xr), the RPM staged
# at harddisk: root, the agent's own iris-work/ control-file directory
# under the bind-mounted harddisk: (agentinfo/plans/2026-08-28-xr-agent.md,
# Task 3), and any *.torrent/*.aria2/*.peers.json sidecar aria2 or the agent
# left at harddisk: ROOT. Sidecars land there, not inside iris-work/, because
# this platform has no placement step -- aria2 downloads each image straight
# to its final harddisk: location (xr_deps.py module docstring), so the
# metadata/progress/receipt files that ride alongside it never leave that
# same directory either. Unlike the router/IOx twins, XR activation uses
# ONLY --net=host -- no VirtualPortGroup, VLAN, SVI, or NAT is ever created,
# so there is no operator-owned network config an undeploy could
# accidentally touch.
# EVERY artifact IRIS ever creates here already carries its own name, so
# receipted and IRIS_FORCE_AGENT_ONLY=1 teardown remove exactly the same
# footprint -- FORCE exists for interface parity with the router/IOx
# uninstallers (a device stranded mid-onboard, no receipt to hand this
# script), not because XR needs a reduced-scope path the way they do.
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
    echo "===== FORCE: reclaiming only IRIS-marked artifacts (no receipt) ====="
    echo "  The app named '$APPID', the source named '$SOURCE_NAME', and the"
    echo "  iris-work/ dir -- the same set a receipted undeploy removes, since"
    echo "  XR activation (--net=host only) never creates anything else IRIS"
    echo "  would need a receipt to prove ownership of."
  fi
  echo "===== [1/5] deactivate: probe app-table first; skip if $APPID is already absent (idempotent second run) ====="
  echo "show appmgr application-table"
  echo "configure"
  echo "no appmgr application $APPID"
  echo "commit"
  echo "  (re-probe app-table; retry deactivate once if still present; exit 1 fail-closed if still active after retry)"
  echo "===== [2/5] appmgr package uninstall source $SOURCE_NAME (Cisco 8000 form) ====="
  echo "appmgr package uninstall source $SOURCE_NAME"
  echo "===== [3/5] remove IRIS files under harddisk: (Linux layer, proven write-through) ====="
  echo "run rm -f $RPM_PATH"
  echo "run rm -rf $WORK_DIR_PATH"
  echo "===== [4/5] sweep leftover IRIS sidecars (*.torrent, *.aria2, *.peers.json) at harddisk: root ====="
  echo "run ls -1 /misc/disk1"
  echo "run rm -f /misc/disk1/<name>   # one call per matched sidecar name, never a glob"
  echo "===== [5/5] verify no '$APPID' app, '$SOURCE_NAME' source, IRIS file, or sidecar remains (dir harddisk:) ====="
  echo "===== NOT DONE: no 'copy running-config startup-config' -- XR commit IS the persisted state ====="
  echo "===== LEFT IN PLACE: any operator-staged image already on harddisk: ====="
  exit 0
fi

: "${DEVICE_IP:?set DEVICE_IP}"; : "${DEVICE_USER:?set DEVICE_USER}"
: "${DEVICE_PASS:?set DEVICE_PASS}"
RUN() { "$HERE/../lab/xr-run.sh" "$DEVICE_IP"; }   # XR commands on stdin

# Shared marker-section reader: every read-only probe below (the app-table
# probe, the sidecar listing, and the final three-way verify) rides this
# SAME family of `echo __IRIS_XR_VERIFY_<NAME>__` markers, so a missing
# marker is always a hard transport error, never silently read as "nothing
# there" the way an empty section otherwise could be.
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

if [ "$FORCE_AGENT_ONLY" = "1" ]; then
  echo "===== FORCE: reclaiming only IRIS-marked artifacts on $DEVICE_IP (no receipt) ====="
  echo "  Removing: app '$APPID', source '$SOURCE_NAME', $RPM_PATH, $WORK_DIR_PATH."
fi

echo "[1/5] deactivate: no appmgr application $APPID on $DEVICE_IP"
# Honest and idempotent: probe app-table BEFORE touching config (a second
# run against an already-torn-down device must converge, not resubmit a
# deactivate the router has nothing left to deactivate), then verify the
# submission actually took by re-probing rather than trusting the piped
# config call's own exit status. A rejected/failed commit that this script
# never read back is exactly the live-incident failure mode this guards
# against (step header comment above). Retries once, then fails closed --
# every later step is skipped, never run against a possibly-still-active
# app.
probe_app_request() {
cat <<EOF
echo ${VERIFY_MARKER}APPS__
show appmgr application-table
echo ${VERIFY_MARKER}APPS_END__
EOF
}
app_present() {
  local probe_out probe_rc apps
  # The transport's own exit status matters here in a way it does not for
  # [2/5]-[4/5]'s best-effort steps: a wedged session that Task 1's bound
  # kills (rc 124) or any other nonzero transport failure must never be
  # read as "app absent" just because the captured text happens to be
  # empty -- it is captured and checked explicitly instead of the usual
  # `|| true`.
  probe_out="$(probe_app_request | RUN 2>/dev/null)"
  probe_rc=$?
  if [ "$probe_rc" -ne 0 ]; then
    echo "ERROR: deactivate probe's transport exited $probe_rc; refusing to continue teardown on $DEVICE_IP" >&2
    exit 1
  fi
  apps="$(printf '%s' "$probe_out" | verify_section APPS)" \
    || { echo "ERROR: deactivate probe did not return the appmgr application-table; refusing to continue teardown on $DEVICE_IP" >&2; exit 1; }
  # Belt and suspenders beyond the rc check above, checked AFTER the section
  # itself was confirmed found (so a stream missing the start marker
  # entirely still reports the clearer "did not return the appmgr
  # application-table" above, not this one): a stream that dies right after
  # flushing the start marker (rc 0, or a failure that otherwise doesn't
  # surface as a transport error) is caught by requiring the trailing end
  # marker too -- a truncated-after-marker read is a hard error, never
  # silently treated as absent.
  case "$probe_out" in
    *"${VERIFY_MARKER}APPS_END__"*) : ;;
    *)
      echo "ERROR: deactivate probe was truncated before its end marker; refusing to continue teardown on $DEVICE_IP" >&2
      exit 1
      ;;
  esac
  case "$apps" in *"$APPID"*) return 0 ;; esac
  return 1
}
deactivate_request() {
cat <<EOF
configure
no appmgr application $APPID
commit
EOF
}
if app_present; then
  deactivate_request | RUN >/dev/null 2>&1 || true
  if app_present; then
    echo "  $APPID still active after deactivate; retrying once"
    deactivate_request | RUN >/dev/null 2>&1 || true
    if app_present; then
      echo "ERROR: refusing to continue teardown while application $APPID is still active on $DEVICE_IP" >&2
      exit 1
    fi
  fi
else
  echo "  $APPID already deactivated/absent; skipping"
fi

echo "[2/5] appmgr package uninstall source $SOURCE_NAME"
printf 'appmgr package uninstall source %s\n' "$SOURCE_NAME" | RUN >/dev/null 2>&1 || true

echo "[3/5] remove IRIS files under harddisk:"
printf 'run rm -f %s\n' "$RPM_PATH" | RUN >/dev/null 2>&1 || true
printf 'run rm -rf %s\n' "$WORK_DIR_PATH" | RUN >/dev/null 2>&1 || true

echo "[4/5] sweep leftover IRIS sidecars (*.torrent, *.aria2, *.peers.json) at harddisk: root"
# aria2 downloads straight to harddisk: root on this platform (no placement
# step, xr_deps.py module docstring), so its own control sidecars -- the
# .torrent metadata iris_agent.py stages before addTorrent, aria2's own
# .aria2 progress file, and the per-peer .peers.json receipt
# telemetry_report.py writes next to the staged image -- land at the SAME
# root as any operator-staged image, never inside iris-work/. Names alone
# prove IRIS wrote them (the same _OWNED_SUFFIXES rule xr_deps.purge_others
# uses at runtime); nothing here ever touches a bare image filename.
# Listing rides 'run ls -1 /misc/disk1' (one name per line -- avoids the
# multi-column layout a ttyed 'ls' can fall back to) so THIS SCRIPT decides
# what matches, never the device; deletion is still one 'run rm -f' per
# bare path, NEVER a glob handed to 'run' (unproven quote/glob handling,
# same trap as IOS-XE Guest Shell).
sidecar_list_request() {
cat <<EOF
echo ${VERIFY_MARKER}SIDECARS__
run ls -1 /misc/disk1
echo ${VERIFY_MARKER}SIDECARS_END__
EOF
}
SIDECAR_OUT="$(sidecar_list_request | RUN 2>/dev/null || true)"
SIDECAR_NAMES="$(printf '%s' "$SIDECAR_OUT" | verify_section SIDECARS 2>/dev/null \
  | grep -E '\.(torrent|aria2|peers\.json)$' || true)"
if [ -n "$SIDECAR_NAMES" ]; then
  printf '%s\n' "$SIDECAR_NAMES" | sed 's#^#run rm -f /misc/disk1/#' | RUN >/dev/null 2>&1 || true
fi

echo "[5/5] verify no '$APPID' app, '$SOURCE_NAME' source, IRIS file, or sidecar remains"
# One login for all three read-only verify checks, same consolidation
# _default_router_preflight/router-uninstall.sh's own verify pass use.
# FILES reads the harddisk: root listing exactly the way the lab probe
# verified file removal (agentinfo/xr-support/LAB-RESULTS-2026-08-27.md
# section 1.3: "dir harddisk:" listed, then, after removal, "verified
# gone") -- proven, unlike guessing at 'run test -e ... &&' semantics or a
# missing-file error string 'dir' was never hardware-exercised against.
verify_request() {
cat <<EOF
echo ${VERIFY_MARKER}APPS__
show appmgr application-table
echo ${VERIFY_MARKER}SOURCES__
show appmgr source-table
echo ${VERIFY_MARKER}FILES__
dir harddisk:
EOF
}
VERIFY_OUT="$(verify_request | RUN 2>/dev/null || true)"
APPS="$(printf '%s' "$VERIFY_OUT" | verify_section APPS)" \
  || { echo "ERROR: undeploy verify did not return the appmgr application-table; refusing to declare $DEVICE_IP clean" >&2; exit 1; }
SOURCES="$(printf '%s' "$VERIFY_OUT" | verify_section SOURCES)" \
  || { echo "ERROR: undeploy verify did not return the appmgr source-table; refusing to declare $DEVICE_IP clean" >&2; exit 1; }
FILES="$(printf '%s' "$VERIFY_OUT" | verify_section FILES)" \
  || { echo "ERROR: undeploy verify did not return the harddisk: file check; refusing to declare $DEVICE_IP clean" >&2; exit 1; }

forbidden=""
case "$APPS" in *"$APPID"*) forbidden="${forbidden}${forbidden:+, }appmgr application $APPID" ;; esac
case "$SOURCES" in *"$SOURCE_NAME"*) forbidden="${forbidden}${forbidden:+, }appmgr source $SOURCE_NAME" ;; esac
case "$FILES" in *"$SOURCE_NAME.rpm"*) forbidden="${forbidden}${forbidden:+, }$RPM_PATH" ;; esac
case "$FILES" in *"iris-work"*) forbidden="${forbidden}${forbidden:+, }$WORK_DIR_PATH" ;; esac
case "$FILES" in *".torrent"*) forbidden="${forbidden}${forbidden:+, }leftover *.torrent sidecar on harddisk:" ;; esac
case "$FILES" in *".aria2"*) forbidden="${forbidden}${forbidden:+, }leftover *.aria2 sidecar on harddisk:" ;; esac
case "$FILES" in *".peers.json"*) forbidden="${forbidden}${forbidden:+, }leftover *.peers.json sidecar on harddisk:" ;; esac

if [ -n "$forbidden" ]; then
  echo "ERROR: artifacts still present after undeploy: $forbidden" >&2
  exit 1
fi
echo "undeploy complete: $DEVICE_IP is clean (any operator-staged image on harddisk: was left in place)"
