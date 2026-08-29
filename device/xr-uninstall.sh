#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Receipt-driven inverse of device/xr-install.sh. IRIS on a Cisco 8000-series
# IOS-XR router is: the appmgr application '$APPID' (default iris), its
# registered package source '$SOURCE_NAME' (default iris-xr), the RPM staged
# at harddisk: root, and the agent's own iris-work/ control-file directory
# under the bind-mounted harddisk: (agentinfo/plans/2026-08-28-xr-agent.md,
# Task 3). Unlike the router/IOx twins, XR activation uses ONLY --net=host --
# no VirtualPortGroup, VLAN, SVI, or NAT is ever created, so there is no
# operator-owned network config an undeploy could accidentally touch.
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
  echo "===== [1/4] deactivate: no appmgr application $APPID (config; commit guarded by lab/xr-run.sh) ====="
  echo "configure"
  echo "no appmgr application $APPID"
  echo "commit"
  echo "===== [2/4] appmgr package uninstall source $SOURCE_NAME (Cisco 8000 form) ====="
  echo "appmgr package uninstall source $SOURCE_NAME"
  echo "===== [3/4] remove IRIS files under harddisk: (Linux layer, proven write-through) ====="
  echo "run rm -f $RPM_PATH"
  echo "run rm -rf $WORK_DIR_PATH"
  echo "===== [4/4] verify no '$APPID' app, '$SOURCE_NAME' source, or IRIS file remains (dir harddisk:) ====="
  echo "===== NOT DONE: no 'copy running-config startup-config' -- XR commit IS the persisted state ====="
  echo "===== LEFT IN PLACE: any operator-staged image already on harddisk: ====="
  exit 0
fi

: "${DEVICE_IP:?set DEVICE_IP}"; : "${DEVICE_USER:?set DEVICE_USER}"
: "${DEVICE_PASS:?set DEVICE_PASS}"
RUN() { "$HERE/../lab/xr-run.sh" "$DEVICE_IP"; }   # XR commands on stdin

if [ "$FORCE_AGENT_ONLY" = "1" ]; then
  echo "===== FORCE: reclaiming only IRIS-marked artifacts on $DEVICE_IP (no receipt) ====="
  echo "  Removing: app '$APPID', source '$SOURCE_NAME', $RPM_PATH, $WORK_DIR_PATH."
fi

echo "[1/4] deactivate: no appmgr application $APPID on $DEVICE_IP"
{
  echo "configure"
  echo "no appmgr application $APPID"
  echo "commit"
} | RUN >/dev/null 2>&1 || true

echo "[2/4] appmgr package uninstall source $SOURCE_NAME"
printf 'appmgr package uninstall source %s\n' "$SOURCE_NAME" | RUN >/dev/null 2>&1 || true

echo "[3/4] remove IRIS files under harddisk:"
printf 'run rm -f %s\n' "$RPM_PATH" | RUN >/dev/null 2>&1 || true
printf 'run rm -rf %s\n' "$WORK_DIR_PATH" | RUN >/dev/null 2>&1 || true

echo "[4/4] verify no '$APPID' app, '$SOURCE_NAME' source, or IRIS file remains"
# One login for all three read-only verify checks, same consolidation
# _default_router_preflight/router-uninstall.sh's own verify pass use --
# each command's answer is delimited by a marker this device echoes back
# verbatim, so a missing marker is a hard error (transport failure), never
# read as "nothing left" the way an empty section otherwise could be.
# FILES reads the harddisk: root listing exactly the way the lab probe
# verified file removal (agentinfo/xr-support/LAB-RESULTS-2026-08-27.md
# section 1.3: "dir harddisk:" listed, then, after removal, "verified
# gone") -- proven, unlike guessing at 'run test -e ... &&' semantics or a
# missing-file error string 'dir' was never hardware-exercised against.
VERIFY_MARKER="__IRIS_XR_VERIFY_"
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
verify_section() {
  python3 -c 'import re, sys
marker = "__IRIS_XR_VERIFY_"
name = sys.argv[1]
text = sys.stdin.read()
start = marker + name + "__"
match = re.search(re.escape(start) + r"\r?\n?(.*?)(?=" + re.escape(marker) + r"[A-Z_]+__|\Z)", text, re.DOTALL)
if not match:
    sys.exit(1)
sys.stdout.write(match.group(1))' "$1"
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

if [ -n "$forbidden" ]; then
  echo "ERROR: artifacts still present after undeploy: $forbidden" >&2
  exit 1
fi
echo "undeploy complete: $DEVICE_IP is clean (any operator-staged image on harddisk: was left in place)"
