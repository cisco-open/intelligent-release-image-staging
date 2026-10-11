#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Shared by the two Guest Shell installers. No native commands are run when
# sourced. Inputs and target names come only from the installer's fixed list.
guest_input_pairs() {
  printf '%s\n' "bootstrap.sh:bootstrap.sh" "staging/$CONF:iris-agent.conf" \
    "staging/$RPC_SECRET_FILE:rpc-secret" "iris-catalog.pem:iris-catalog.pem" \
    "iris-signers.pem:iris-signers.allowed_signers" \
    "staging/$INSTRUCTION_ENVELOPE:iris-instructions.bootstrap" \
    "staging/$BUNDLE_DIGEST_FILE:bundle.tgz.sha256" "$BUNDLE:bundle.tgz"
}

guest_input_metadata() {
  # This program also runs on a remote artifact host through the existing
  # pinned SSH helper. It emits sizes/digests only, never configuration bytes.
  local program
  program='import hashlib,os,stat,sys
for index,path in enumerate(sys.argv[1:]):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode) and (0 if index==2 else 1)<=before.st_size<=33554432
  digest=hashlib.sha256(); count=0
  while True:
   block=os.read(fd,65536)
   if not block: break
   count+=len(block); assert count<=33554432; digest.update(block)
  after=os.fstat(fd); named=os.lstat(path)
  signature=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
  assert count==before.st_size and signature(before)==signature(after)==signature(named)
  print(str(count)+":"+digest.hexdigest())
 finally: os.close(fd)'
  local pair src command
  local paths=()
  while IFS= read -r pair; do
    src="${pair%:*}"
    if [ "$STAGE_LOCAL" -eq 1 ]; then paths+=("$ART/$src")
    else paths+=("iris/artifacts/$src"); fi
  done < <(guest_input_pairs)
  if [ "$STAGE_LOCAL" -eq 1 ]; then
    python3 -c "$program" "${paths[@]}"
  else
    # Every path is relative to the same remote login's home, as in staging.
    printf -v command 'cd "$HOME" && python3 -c %q' "$program"
    for src in "${paths[@]}"; do printf -v command '%s %q' "$command" "$src"; done
    ssh_host "$command"
  fi
}

publish_guest_inputs() {
  local metadata pair src dst pending attempt out ok command marker row
  local expected=()
  metadata="$(guest_input_metadata)" \
    || { echo "ERROR: cannot fingerprint staged Guest Shell inputs" >&2; return 1; }
  while IFS= read -r row; do
    [[ "$row" =~ ^(0|[1-9][0-9]{0,7}):[0-9a-f]{64}$ ]] \
      || { echo "ERROR: invalid Guest Shell input fingerprint" >&2; return 1; }
    if [[ "$row" == 0:* ]] && [ "${#expected[@]}" -ne 2 ]; then return 1; fi
    expected+=("$row")
  done <<<"$metadata"
  [ "${#expected[@]}" -eq 8 ] || return 1
  while IFS= read -r pair; do
    src="${pair%:*}"; dst="${pair##*:}"
    pending="$IOS_ROOT/.iris-upload-$CAP-$dst"
    ok=0
    for attempt in 1 2 3; do
      # Only this invocation's unconsumed name is cleared on a copy retry.
      # Neither existing root inputs nor the runnable stage are deleted.
      out="$(printf 'delete /force %s\ncopy https://%s:8000/%s %s\n' \
        "$pending" "$STAGE_HOST" "$src" "$pending" \
        | "$HERE/../lab/device-run.sh" "$DEVICE_IP")" || out=""
      if printf '%s\n' "$out" | tr -d '\r' | grep -Eq '^[[:space:]]*[0-9]+ bytes copied([[:space:]]|$)'; then
        ok=1; break
      fi
      echo "  copy of $src failed (attempt $attempt/3)" >&2
      [ "$attempt" -eq 3 ] || sleep 10
    done
    [ "$ok" -eq 1 ] \
      || { echo "ERROR: incomplete Guest Shell upload; existing inputs retained" >&2; return 1; }
  done < <(guest_input_pairs)
  # A short typed command, with no token or arbitrary path argument. The
  # completed bootstrap checks its own bytes as well as the other seven files.
  command="guestshell run bash $GUEST_INPUT_ROOT/.iris-upload-$CAP-bootstrap.sh --publish-inputs $CAP"
  for row in "${expected[@]}"; do command="$command $row"; done
  [ "${#command}" -le 1024 ] || return 1
  out="$(printf '%s\n' "$command" | "$HERE/../lab/device-run.sh" "$DEVICE_IP")" \
    || { echo "ERROR: Guest Shell publication outcome unknown; inspect before retrying" >&2; return 1; }
  marker="IRIS-INPUTS-PUBLISHED:$CAP:${expected[7]#*:}"
  [ "$(printf '%s\n' "$out" | tr -d '\r' | grep -Fxc "$marker")" -eq 1 ] \
    || { echo "ERROR: Guest Shell publication not proved; inspect before retrying" >&2; return 1; }
  echo "  Guest Shell inputs published; bundle acceptance and runtime startup are separate checks"
}

render_guest_inputs() {
  local pair src dst
  while IFS= read -r pair; do
    src="${pair%:*}"; dst="${pair##*:}"
    printf 'copy https://%s:8000/%s %s/.iris-upload-%s-%s\n' \
      "$STAGE_HOST" "$src" "$IOS_ROOT" "$CAP" "$dst"
  done < <(guest_input_pairs)
  echo "# Publish under the bootstrap lock only after all eight source size/hash checks."
  printf 'guestshell run bash %s/.iris-upload-%s-bootstrap.sh --publish-inputs %s <eight-size:sha256-values>\n' \
    "$GUEST_INPUT_ROOT" "$CAP" "$CAP"
}
