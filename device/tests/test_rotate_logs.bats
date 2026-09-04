#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

file_size() {
  stat -c%s "$1" 2>/dev/null || stat -f%z "$1"
}

@test "bootstrap.sh invokes rotate-logs.sh each tick (wired into cadence)" {
  # Structural guard: bootstrap.sh must reference rotate-logs.sh so aria2c.log
  # is trimmed on every 60s EEM tick and cannot grow unbounded on flash.
  grep -qF 'rotate-logs.sh' "$BATS_TEST_DIRNAME/../bootstrap.sh"
}

@test "bootstrap.sh waits for aria2c to exit after pkill before relaunching (race guard)" {
  # Structural guard: after pkill the script must not immediately re-pgrep;
  # it must wait for the process to exit so the pgrep in step 3 sees it gone.
  # Check that a wait loop (while pgrep) appears after the pkill line.
  grep -A5 'pkill -f' "$BATS_TEST_DIRNAME/../bootstrap.sh" | grep -qF 'while pgrep'
}

@test "rotate-logs truncates a log past the cap, leaves a small one alone" {
  tmp="$(mktemp -d)"
  big="$tmp/aria2c.log"; small="$tmp/small.log"
  head -c 200000 /dev/zero > "$big"      # 200 KB
  head -c 100 /dev/zero > "$small"
  run env MAX_BYTES=1024 bash "$BATS_TEST_DIRNAME/../rotate-logs.sh" "$big" "$small"
  [ "$status" -eq 0 ]
  [ "$(file_size "$big")" -lt 200000 ]   # truncated
  [ "$(file_size "$small")" -eq 100 ]    # untouched
}

@test "rotate-logs trims in place so a writer holding the log open keeps writing to the visible file" {
  # aria2c opens --log once (O_APPEND) for its whole life and has no reopen
  # signal. The old tail-to-tmp + mv rotation gave the path a NEW inode: the
  # daemon kept writing to the old, unlinked one (invisible, never trimmed
  # again, growing until exit) while the visible file froze at the moment of
  # rotation. Copy-truncate keeps the inode, so the held-open writer's output
  # lands where `dir` and the operator can see it and the next trim still fires.
  tmp="$(mktemp -d)"
  big="$tmp/aria2c.log"
  head -c 200000 /dev/zero > "$big"      # 200 KB
  inode_before="$(stat -c%i "$big" 2>/dev/null || stat -f%i "$big")"
  exec 9>>"$big"                         # the daemon's descriptor, held open (fd 3 is bats' own)
  run env MAX_BYTES=1024 bash "$BATS_TEST_DIRNAME/../rotate-logs.sh" "$big"
  [ "$status" -eq 0 ]
  [ "$(stat -c%i "$big" 2>/dev/null || stat -f%i "$big")" -eq "$inode_before" ]
  trimmed="$(file_size "$big")"
  [ "$trimmed" -le 1024 ]
  echo "written after rotation" >&9      # what aria2c does next
  exec 9>&-
  [ "$(file_size "$big")" -gt "$trimmed" ]   # ...lands in the visible file
  grep -q "written after rotation" "$big"
  [ -z "$(ls -A "$tmp" | grep -v '^aria2c.log$')" ]   # no temp file left behind
}
