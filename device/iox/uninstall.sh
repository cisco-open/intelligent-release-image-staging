#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Undeploy IRIS from a Cisco IOx app-hosting device — the inverse of
# device/iox/install.sh. IRIS runs there as an architecture-matched IOx Docker
# app (not Guest Shell), so teardown is app-hosting, not guestshell:
#   - stop -> deactivate -> uninstall the 'iris' app (frees its persist-disk,
#     and with it $CAF_APP_PERSISTENT_DIR/iris where aria2 stages images and
#     the --on-bt-download-complete hook leaves its <image>.peers.json
#     snapshots; the hook program itself lives in the app image)
#   - remove the app-hosting appid + the IRIS VLAN/SVI (or, on a router,
#     the IRIS VirtualPortGroup and, for router-nat, its NAT footprint)
#   - remove any IRIS-COPYROOT / IRIS-AGENT EEM applet the agent created at
#     runtime for its plain-copy placement (no-op if absent — IOx has no 60s
#     timer)
#   - remove crypto pki trustpoint IRIS + ip http client secure-trustpoint IRIS
#   - delete the staged app package (<pkg-fs>iris-arm64.tar), the runtime
#     certificate source (<pkg-fs>iris-catalog.pem), and, on C9k share
#     deployments, the IRIS iris/ subdir of the CAF share (transient transfer
#     copies; the share root itself is operator space and never touched)
# Deliberately LEFT IN PLACE (the installer re-applies the first three
# idempotently; the last two are generic + a delivered artifact):
#   iox, file prompt quiet, the AppGigabitEthernet trunk, ip scp server enable,
#   the staged OS image on the selected IOS disk. Successful cleanup is
#   persisted to startup-config so a reload cannot restore IRIS configuration.
# In a real run, recorded versus force-agent-only authority comes exclusively
# from the controller ready frame. IRIS_FORCE_AGENT_ONLY affects dry-run text
# only and cannot authorize teardown.
#
# Env (subset of the installer's, supplied by OnboardService._build_env):
#   DEVICE_IP DEVICE_USER DEVICE_PASS [DEVICE_ENABLE] [VLAN=666]
#   [PKG=iris-arm64.tar] [PKG_FS=flash:]
#   [EXPECTED_DEVICE_IDENTITY]  the processor board ID the deployment record
#       was written for (the same value the installer hard-requires). When set,
#       the FIRST device session is a read-only `show version` and the teardown
#       refuses to send any destructive command unless the live board ID
#       matches -- a re-addressed or replaced box, or a session that never
#       returned a board ID, aborts before anything is touched. Skipped in
#       force mode (IRIS_FORCE_AGENT_ONLY=1: the record-less rescue has no
#       identity to compare against, same as device/router-uninstall.sh).
#       Unset: no identity check (legacy callers).
# Usage:  iox/uninstall.sh [--dry-run]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

# VLAN_IN preserves whether a VLAN was actually supplied; the 666 default is
# ONLY for --dry-run text. A real run re-requires a non-empty VLAN below, so we
# never tear down the wrong SVI/VLAN and then falsely verify clean.
if [ -n "${NETWORK_ATTACHMENT:-}" ] && [ -z "${MANAGEMENT_TYPE:-}" ]; then
  echo "ERROR: NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE; refusing to fall back to the routed default" >&2
  exit 1
fi
MANAGEMENT_TYPE="${MANAGEMENT_TYPE:-routed}"
VLAN_IN="${VLAN:-${INBAND_VLAN:-}}"
VLAN="${VLAN_IN:-666}"
# See header: force preserves only the operator's VLAN/SVI network. Everything
# carrying IRIS's own name is still removed regardless of MANAGEMENT_TYPE.
FORCE_AGENT_ONLY="${IRIS_FORCE_AGENT_ONLY:-0}"
PKG="${PKG:-iris-arm64.tar}"; PKG_FS="${PKG_FS:-flash:}"
# C9k share-mount transfer: when set, [3/4] also deletes OUR iris/ subdir of
# the shared CAF dir (transient image copies orphaned by a mid-transfer kill).
# Never the share root — operator files there are not IRIS's to remove.
SHARE_IOS_PATH="${SHARE_IOS_PATH:-}"
# scp-push staging dir: on IE-3400 (and any C9300 that fell back from the
# share mount) the agent SCP-pushes the image to <TARGET_FS>guest-share/iris
# through the device's SCP server. That is OURS and must go — only the iris/
# subdir, never guest-share itself, which the platform and other apps share.
TARGET_FS="${TARGET_FS:-sdflash:}"
IRIS_STAGE_DIR="${TARGET_FS}guest-share/iris"
APPID=iris

_dry_single_line() {
  case "$2" in *$'\n'*|*$'\r'*)
    echo "ERROR: $1 must be a single line" >&2
    exit 2 ;;
  esac
}

_dry_fs() {
  _dry_single_line "$1" "$2"
  [[ "$2" =~ ^[A-Za-z][A-Za-z0-9_-]*:$ ]] || {
    echo "ERROR: $1 must be an IOS filesystem prefix" >&2
    exit 2
  }
}

_dry_validate() {
  case "$MANAGEMENT_TYPE" in routed|inband|router-routed|router-nat) ;; *)
    echo "ERROR: MANAGEMENT_TYPE must be routed, inband, router-routed, or router-nat" >&2; exit 2 ;;
  esac
  case "$FORCE_AGENT_ONLY" in 0|1) ;; *)
    echo "ERROR: IRIS_FORCE_AGENT_ONLY must be 0 or 1" >&2; exit 2 ;;
  esac
  if { [ "$MANAGEMENT_TYPE" = router-routed ] || [ "$MANAGEMENT_TYPE" = router-nat ]; } \
      && [ "$FORCE_AGENT_ONLY" != 1 ]; then
    # The router footprint is only removed under a record, and the record
    # names the group; a dry run must say what is missing rather than die on
    # an unbound variable inside a heredoc.
    [[ "${VPG_NUMBER:-}" =~ ^[0-9]+$ ]] && [ "$VPG_NUMBER" -ge 0 ] && [ "$VPG_NUMBER" -le 31 ] || {
      echo "ERROR: VPG_NUMBER must be an integer from 0 to 31" >&2; exit 2; }
    if [ "$MANAGEMENT_TYPE" = router-nat ]; then
      [ -n "${NAT_INTERFACE:-}" ] || { echo "ERROR: router-nat needs NAT_INTERFACE" >&2; exit 2; }
      [ -n "${APP_IP:-}" ] || { echo "ERROR: router-nat needs APP_IP for the swarm-port translation" >&2; exit 2; }
      [[ "${BT_LISTEN_PORT:-6881}" =~ ^[0-9]+$ ]] && [ "${BT_LISTEN_PORT:-6881}" -ge 1 ] \
        && [ "${BT_LISTEN_PORT:-6881}" -le 65535 ] || {
        echo "ERROR: BT_LISTEN_PORT must be an integer from 1 to 65535" >&2; exit 2; }
    fi
  fi
  if [ "$MANAGEMENT_TYPE" = routed ] && [ "$FORCE_AGENT_ONLY" != 1 ]; then
    [[ "$VLAN" =~ ^[0-9]+$ ]] && [ "${#VLAN}" -le 4 ] &&
      [ "$VLAN" -ge 1 ] && [ "$VLAN" -le 4094 ] || {
        echo "ERROR: VLAN must be an integer from 1 to 4094" >&2; exit 2;
      }
  fi
  _dry_single_line PKG "$PKG"
  [[ "$PKG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
    echo "ERROR: PKG must be a safe basename" >&2; exit 2;
  }
  _dry_fs PKG_FS "$PKG_FS"
  _dry_fs TARGET_FS "$TARGET_FS"
  if [ -n "$SHARE_IOS_PATH" ]; then
    _dry_single_line SHARE_IOS_PATH "$SHARE_IOS_PATH"
    [[ "$SHARE_IOS_PATH" =~ ^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]] &&
      [[ "/${SHARE_IOS_PATH#*:}/" != *"/../"* ]] || {
        echo "ERROR: SHARE_IOS_PATH must be a safe IOS filesystem path" >&2; exit 2;
      }
  fi
}

config_cleanup() {
# Every EEM applet the SHARED agent may have created (the IOx agent runs the
# same reclaim/copy-root code as Guest Shell over its SSH-to-self CLI): the
# copy-to-root applet and the on-demand low-space reclaim applets, which the
# agent never self-removes. IRIS-AGENT won't exist on IOx (no 60s timer) but
# the no-op is harmless. All no-ops if absent.
#
# Inband preserves the operator-owned VLAN/SVI, which no deployment record
# proves IRIS created. It still removes everything carrying IRIS's own name,
# including the IRISQ discriminator and the IRIS PKI trustpoint / HTTP-client binding:
# leaving those behind strands the device against its own next onboard, which
# preflight refuses while any of them is present.
if [ "$MANAGEMENT_TYPE" = "inband" ] || [ "$FORCE_AGENT_ONLY" = "1" ]; then
cat <<EOF
no app-hosting appid $APPID
no event manager applet IRIS-AGENT
no event manager applet IRIS-COPYROOT
no event manager applet IRIS-RECLAIM
no event manager applet IRIS-RECLAIM-BUNDLE
no logging buffered discriminator IRISQ
no logging console discriminator IRISQ
no logging monitor discriminator IRISQ
no logging discriminator IRISQ
no ip http client secure-trustpoint IRIS
no crypto pki trustpoint IRIS
yes
EOF
return
fi
if [ "$MANAGEMENT_TYPE" = "router-routed" ] || [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
# Router: remove the VirtualPortGroup and NAT footprint the install created,
# in device/router-uninstall.sh's order and under its ownership rules: the
# swarm-port static translation and the overload rule go before the ACL they
# reference (IOS keeps an overload rule while translations still use it, and
# the residue probe reports that rather than guessing); a NAT outside
# interface is only un-marked when the record says IRIS marked it.
cat <<EOF
no app-hosting appid $APPID
no event manager applet IRIS-AGENT
no event manager applet IRIS-COPYROOT
no event manager applet IRIS-RECLAIM
no event manager applet IRIS-RECLAIM-BUNDLE
EOF
if [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
cat <<EOF
no ip nat inside source static tcp $APP_IP ${BT_LISTEN_PORT:-6881} interface $NAT_INTERFACE ${BT_LISTEN_PORT:-6881}
no ip nat inside source list IRIS-NAT-$VPG_NUMBER interface $NAT_INTERFACE overload
no ip access-list standard IRIS-NAT-$VPG_NUMBER
EOF
  if [ "${NAT_OUTSIDE_OWNED:-0}" = "1" ]; then
cat <<EOF
interface $NAT_INTERFACE
 no ip nat outside
exit
EOF
  fi
fi
cat <<EOF
no interface VirtualPortGroup$VPG_NUMBER
no ip http client secure-trustpoint IRIS
no crypto pki trustpoint IRIS
yes
EOF
return
fi
cat <<EOF
no app-hosting appid $APPID
no event manager applet IRIS-AGENT
no event manager applet IRIS-COPYROOT
no event manager applet IRIS-RECLAIM
no event manager applet IRIS-RECLAIM-BUNDLE
no interface Vlan$VLAN
no vlan $VLAN
no ip http client secure-trustpoint IRIS
no crypto pki trustpoint IRIS
yes
EOF
}

if [ "$DRY" -eq 1 ]; then
  _dry_validate
  echo "[1/4] remove app: $APPID"
  printf 'app-hosting stop appid %s\napp-hosting deactivate appid %s\napp-hosting uninstall appid %s\n' \
    "$APPID" "$APPID" "$APPID"
  if [ "$MANAGEMENT_TYPE" = "inband" ] || [ "$FORCE_AGENT_ONLY" = "1" ]; then
    echo "[2/4] remove IRIS configuration"
  elif [ "$MANAGEMENT_TYPE" = "router-routed" ] || [ "$MANAGEMENT_TYPE" = "router-nat" ]; then
    echo "[2/4] remove IRIS configuration and VirtualPortGroup $VPG_NUMBER"
  else
    echo "[2/4] remove IRIS configuration and VLAN $VLAN"
  fi
  config_cleanup
  echo "[3/4] remove IRIS files"
  echo "delete /force ${PKG_FS}${PKG}"
  echo "delete /force ${PKG_FS}iris-catalog.pem"
  if [ -n "$SHARE_IOS_PATH" ]; then
    echo "delete /force $SHARE_IOS_PATH/iris-staged.bin"
    echo "delete /force $SHARE_IOS_PATH/iris-staged.bin.part"
    echo "delete /force $SHARE_IOS_PATH/iris-probe.txt"
    echo "delete /force /recursive $SHARE_IOS_PATH/iris"
  fi
  echo "delete /force /recursive $IRIS_STAGE_DIR"
  if [ "$FORCE_AGENT_ONLY" = 1 ]; then
    echo "[4/4] verify cleanup"
  else
    echo "[4/4] verify cleanup and save"
    echo "copy running-config startup-config"
  fi
  exit 0
fi

# Import the one strict framed-protocol implementation from the companion
# recipe.  Library mode is honored only while sourced; executing install.sh
# with a forged environment cannot bypass its controller handoff.
IRIS_IOX_RECIPE_LIBRARY=1
IRIS_IOX_RECIPE_ACTION=uninstall
# shellcheck source=device/iox/install.sh
. "$HERE/install.sh"
unset IRIS_IOX_RECIPE_LIBRARY

on_signal() {
  if [ "$PENDING_SIGNAL_RC" -eq 0 ]; then
    PENDING_SIGNAL_REASON="$1"
    PENDING_SIGNAL_RC="$2"
  fi
  if [ "$REQUEST_IN_FLIGHT" -eq 1 ]; then
    return 0
  fi
  SIGNAL_REASON="$PENDING_SIGNAL_REASON"
  exit "$PENDING_SIGNAL_RC"
}
on_exit() {
  local primary=$? reason final
  trap '' TERM INT HUP
  trap - EXIT
  reason="${SIGNAL_REASON:-$([ "$primary" -eq 0 ] && echo success || echo error)}"
  if recipe_finalize "$reason" "$primary"; then final=0; else final=$?; fi
  if [ "$final" -eq 0 ]; then
    echo "undeploy complete: ${DEVICE_IP:-device}"
  fi
  exit "$final"
}
trap on_exit EXIT
trap 'on_signal term 143' TERM
trap 'on_signal int 130' INT
trap 'on_signal hup 129' HUP

uninstall_recipe() {
  local out state rc i mode
  if request_capture out command app_stop; then :; else rc=$?; return "$rc"; fi
  mode="$IPC_MODE"
  case "$mode" in recorded|force_agent_only) ;; *)
    echo "ERROR: invalid private IOx controller protocol" >&2; PROTOCOL_BROKEN=1; return 4 ;;
  esac
  request_plain command app_deactivate || return $?
  request_plain command app_uninstall || return $?

  for i in $(seq 1 24); do
    if request_capture out command app_list; then :; else rc=$?; return "$rc"; fi
    state="$(printf '%s\n' "$out" | awk '$1=="iris"{print $2; exit}')"
    [ -z "$state" ] && break
    [ "$i" -lt 24 ] || { echo "ERROR: IRIS application remains after uninstall" >&2; return 4; }
  done

  request_plain command cleanup_config || return $?
  request_plain command cleanup_files || return $?
  if request_capture out command cleanup_config_probe; then :; else rc=$?; return "$rc"; fi
  # The closed controller probe includes a VLAN line only when that session is
  # authorized to remove its bound routed VLAN. The real recipe deliberately
  # receives no target values in its environment, so treat any VLAN returned
  # by that filtered probe as residue instead of consulting dry-run defaults.
  if printf '%s\n' "$out" | grep -Eq '^[[:space:]]*(iris[[:space:]]+[A-Za-z0-9_-]+|app-hosting appid iris|event manager applet IRIS-|logging ((buffered|console|monitor)[[:space:]]+)?discriminator IRISQ|ip http client secure-trustpoint IRIS|crypto pki trustpoint IRIS|interface Vlan[0-9]+|vlan[[:space:]]+[0-9]+|interface VirtualPortGroup[0-9]+|ip access-list standard IRIS-NAT-[0-9]+|ip nat inside source (list IRIS-NAT-[0-9]+|static tcp))([[:space:]]|$)'; then
    echo "ERROR: IRIS configuration remains after cleanup" >&2
    return 4
  fi
  if request_capture out command cleanup_stage_probe; then :; else rc=$?; return "$rc"; fi
  # The controller filters package rows to its bound PKG and certificate
  # names. Match every validated 1..128-character basename in those IOS rows,
  # including custom names; never infer the real package from this environment.
  local file_row='^[[:space:]]*[0-9]{1,20}[[:space:]]+[-d][rwx-]{1,9}[[:space:]]+[[:print:][:blank:]]{1,256}[[:space:]]+[A-Za-z0-9][A-Za-z0-9._-]{0,127}[[:space:]]*$'
  if printf '%s\n' "$out" | grep -Eq "$file_row|(^|[[:space:]/:])(iris-arm64\.tar|iris-ca\.pem|iris-catalog\.pem|iris-[0-9a-f]{32}\.tar)([[:space:]]|$)|Directory of [^[:space:]]*/iris[[:space:]]*$|^[[:space:]]*[0-9]+[[:space:]]+[-d][rwx-]+[[:space:]].*[[:space:]]iris[[:space:]]*$|iris-staged\.bin(\.part)?|iris-probe\.txt"; then
    echo "ERROR: IRIS temporary files remain after cleanup" >&2
    return 4
  fi

  # The controller rejects save for force_agent_only and permits it for a
  # record-bound teardown.  The ready binding, not IRIS_FORCE_AGENT_ONLY or
  # any other environment claim, is authoritative.  Ask the controller which
  # path is permitted by attempting save only when its current ready frame is
  # recorded; the protocol helper exposes no mutable binding to this shell.
  # The controller-side closed operation policy makes a forged choice fail.
  if [ "$mode" = recorded ]; then
    request_plain command save || return $?
  fi
  return 0
}

set +e
uninstall_recipe
_recipe_rc=$?
exit "$_recipe_rc"
