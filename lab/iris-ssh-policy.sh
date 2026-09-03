#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Shared SSH trust policy for every ssh/scp session IRIS opens itself: the
# device transports (lab/device-run.sh, lab/xr-run.sh), the stage-host push in
# device/device-install.sh and device/router-install.sh, and the RPM scp in
# device/xr-install.sh. `source` this file, call `iris_ssh_policy <peer>`, and
# splice "${IRIS_SSH_OPTS[@]}" into the ssh/scp argv.
#
# Until 2026-09 every one of those sessions ran StrictHostKeyChecking=no with
# UserKnownHostsFile=/dev/null and typed the device (or stage-host) password
# into whatever answered at the address. The peer is now verified, in one of
# three modes chosen by the environment:
#
#   IRIS_SSH_HOST_KEY     one public host key for THIS peer ("ssh-ed25519
#                         AAAA...", "ssh-rsa AAAA...", "ecdsa-sha2-nistp256
#                         AAAA..."). Written to a private temporary known_hosts
#                         entry and used with StrictHostKeyChecking=yes, so a
#                         session succeeds only against that exact key. This is
#                         the per-device pin a deployment record can carry.
#   IRIS_SSH_KNOWN_HOSTS  path to a known_hosts file (any number of hosts).
#                         Used with StrictHostKeyChecking=yes; an unknown or
#                         changed key is a hard failure. A path that is not
#                         readable refuses to connect rather than falling back.
#   (neither)             StrictHostKeyChecking=accept-new against a PERSISTENT
#                         known_hosts at $IRIS_SSH_STATE_DIR/known_hosts
#                         (default $IRIS_STATE/ssh, i.e. the server's state
#                         volume; ~/.iris/ssh outside the container). First
#                         contact records the key; every later session must
#                         present the same one. Never /dev/null.
#
# Legacy algorithms (SHA-1 KEX, ssh-rsa host/pubkey signatures, CBC ciphers)
# that old IOS-XE images need are OFF by default and enabled per session with
# IRIS_SSH_LEGACY=1. They were appended unconditionally before; ssh's own
# "no matching ... method found" error now names the switch.
#
# ssh's stderr is no longer discarded: callers capture it and pass it through
# `iris_ssh_explain`, which prints an IRIS hint for the two failures an
# operator most needs to recognise (changed host key, legacy-only peer).
#
# Functions:
#   iris_ssh_policy PEER   sets IRIS_SSH_OPTS (array), IRIS_SSH_KNOWN_HOSTS_FILE
#                          and IRIS_SSH_MODE (pinned|known-hosts|accept-new);
#                          returns 1 (with a message) when the policy cannot
#                          be satisfied -- callers must not connect then.
#   iris_ssh_explain FILE PEER   reads ssh's captured stderr from FILE and
#                          prints hints to stderr. Never fails.
#   iris_ssh_cleanup       removes the temporary known_hosts a pin created.
#   iris_ssh_forget PEER   removes PEER's entry from the PERSISTENT
#                          known_hosts accept-new mode records into (see
#                          below). Never touches an IRIS_SSH_HOST_KEY pin or
#                          an operator-supplied IRIS_SSH_KNOWN_HOSTS file --
#                          neither is IRIS-managed state.

iris_ssh_policy() {
  local peer="$1"
  IRIS_SSH_OPTS=()
  IRIS_SSH_KNOWN_HOSTS_FILE=""
  IRIS_SSH_MODE=""
  IRIS_SSH_TMP_KNOWN_HOSTS=""
  if [ -n "${IRIS_SSH_HOST_KEY:-}" ]; then
    case "$IRIS_SSH_HOST_KEY" in
      ssh-*\ *|ecdsa-sha2-*\ *|sk-*\ *) ;;
      *) echo "IRIS ssh: IRIS_SSH_HOST_KEY is not a public host key ('<type> <base64>'); refusing to connect to $peer unverified" >&2
         return 1 ;;
    esac
    IRIS_SSH_TMP_KNOWN_HOSTS="$(umask 077; mktemp "${TMPDIR:-/tmp}/iris-known-hosts.XXXXXX")" \
      || { echo "IRIS ssh: cannot create a temporary known_hosts for the pinned key" >&2; return 1; }
    printf '%s %s\n' "$peer" "$IRIS_SSH_HOST_KEY" > "$IRIS_SSH_TMP_KNOWN_HOSTS"
    IRIS_SSH_KNOWN_HOSTS_FILE="$IRIS_SSH_TMP_KNOWN_HOSTS"
    IRIS_SSH_MODE=pinned
    IRIS_SSH_OPTS+=(-o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$IRIS_SSH_KNOWN_HOSTS_FILE")
  elif [ -n "${IRIS_SSH_KNOWN_HOSTS:-}" ]; then
    if [ ! -r "$IRIS_SSH_KNOWN_HOSTS" ]; then
      echo "IRIS ssh: IRIS_SSH_KNOWN_HOSTS=$IRIS_SSH_KNOWN_HOSTS is not readable; refusing to connect to $peer unverified" >&2
      return 1
    fi
    IRIS_SSH_KNOWN_HOSTS_FILE="$IRIS_SSH_KNOWN_HOSTS"
    IRIS_SSH_MODE=known-hosts
    IRIS_SSH_OPTS+=(-o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$IRIS_SSH_KNOWN_HOSTS_FILE")
  else
    local dir="${IRIS_SSH_STATE_DIR:-${IRIS_STATE:-$HOME/.iris}/ssh}"
    if ! mkdir -p "$dir" 2>/dev/null; then
      echo "IRIS ssh: cannot create $dir for the persistent known_hosts (set IRIS_SSH_STATE_DIR or IRIS_SSH_KNOWN_HOSTS); refusing to connect to $peer unverified" >&2
      return 1
    fi
    chmod 700 "$dir" 2>/dev/null || true
    IRIS_SSH_KNOWN_HOSTS_FILE="$dir/known_hosts"
    if [ ! -e "$IRIS_SSH_KNOWN_HOSTS_FILE" ]; then
      (umask 077; : > "$IRIS_SSH_KNOWN_HOSTS_FILE") \
        || { echo "IRIS ssh: cannot create $IRIS_SSH_KNOWN_HOSTS_FILE; refusing to connect to $peer unverified" >&2; return 1; }
    fi
    IRIS_SSH_MODE=accept-new
    IRIS_SSH_OPTS+=(-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$IRIS_SSH_KNOWN_HOSTS_FILE")
  fi
  if [ "${IRIS_SSH_LEGACY:-0}" = "1" ]; then
    IRIS_SSH_OPTS+=(
      -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
      -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa
      -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    )
  fi
  return 0
}

iris_ssh_explain() {
  local errfile="$1" peer="$2"
  [ -s "$errfile" ] || return 0
  if grep -qE 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed|No .* host key is known' "$errfile"; then
    echo "IRIS ssh: $peer did not present the host key recorded in ${IRIS_SSH_KNOWN_HOSTS_FILE:-the known_hosts file} (mode: ${IRIS_SSH_MODE:-unknown})." >&2
    echo "IRIS ssh: if the device was legitimately re-imaged or replaced, remove the stale entry with: ssh-keygen -R '$peer' -f '${IRIS_SSH_KNOWN_HOSTS_FILE:-<known_hosts>}' (or supply the new key via IRIS_SSH_HOST_KEY); otherwise treat this as a possible interception and do not retry blindly." >&2
  fi
  if grep -qE 'no matching (key exchange method|host key type|cipher)|Unable to negotiate' "$errfile"; then
    echo "IRIS ssh: $peer offers only legacy SSH algorithms; set IRIS_SSH_LEGACY=1 to allow SHA-1 KEX / ssh-rsa / CBC for this session" >&2
  fi
  return 0
}

iris_ssh_cleanup() {
  [ -n "${IRIS_SSH_TMP_KNOWN_HOSTS:-}" ] && rm -f "$IRIS_SSH_TMP_KNOWN_HOSTS"
  IRIS_SSH_TMP_KNOWN_HOSTS=""
  return 0
}

# A re-imaged or replaced device presents a NEW host key; accept-new mode
# (the default above) then refuses every session with a changed-key error --
# correct trust-on-first-use behaviour, but the persistent known_hosts lives
# inside the IRIS state volume, which an operator does not always have shell
# access to. This is what the console's "forget host key" action (issue #84)
# calls, and what the ssh-keygen -R hint in iris_ssh_explain above is for
# when running by hand.
#
# Idempotent and narrowly scoped: only the SAME persistent file accept-new
# mode reads/writes ($IRIS_SSH_STATE_DIR/known_hosts, default
# $IRIS_STATE/ssh/known_hosts) is touched, and only PEER's own entry is
# removed -- every other device's pinned trust is untouched. A peer with
# nothing recorded (already forgotten, or never contacted) is success, not an
# error: the point is "no stale entry", and there already is none. The very
# NEXT session re-verifies and re-pins PEER's new key on first contact -- the
# same trust-on-first-use flow a brand-new device gets. This never sets
# StrictHostKeyChecking=no and never touches a pinned (IRIS_SSH_HOST_KEY) or
# operator-supplied (IRIS_SSH_KNOWN_HOSTS) file -- neither is IRIS-managed
# state, and forgetting a key an operator pinned deliberately would be a
# console action erasing an explicit operator decision, not a stale cache.
iris_ssh_forget() {
  local peer="$1"
  local dir="${IRIS_SSH_STATE_DIR:-${IRIS_STATE:-$HOME/.iris}/ssh}"
  local file="$dir/known_hosts"
  [ -e "$file" ] || return 0   # nothing ever recorded -- already "forgotten"
  # ssh-keygen -R's own exit status is not a reliable success signal across
  # OpenSSH versions (some report failure when nothing matched); verify the
  # outcome directly instead. Entries here are always PLAIN (accept-new never
  # sets HashKnownHosts), the same format iris_ssh_policy's pinned mode
  # writes, so a literal match is exact.
  ssh-keygen -R "$peer" -f "$file" >/dev/null 2>&1
  if grep -qF -- "$peer " "$file" 2>/dev/null; then
    echo "IRIS ssh: failed to remove $peer from $file" >&2
    return 1
  fi
  return 0
}
