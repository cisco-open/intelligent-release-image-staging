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
