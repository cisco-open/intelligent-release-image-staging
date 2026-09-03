#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# tools/apply-assignments.sh promises all-or-nothing: no assignment may be
# written until every CSV row has been validated. Before the fix, pass 1 only
# checked that image_id was non-empty, so an unpublished image on row 2 left
# row 1 applied and row 3 never applied -- the partially-configured fleet the
# script's own comment said it prevented. A stub `docker` records every
# iris-assign call so the tests can see exactly what reached the server.

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  APPLY="$REPO/tools/apply-assignments.sh"
  WORK="$BATS_TEST_TMPDIR/work"; mkdir -p "$WORK/bin"
  export ASSIGN_LOG="$WORK/assign.log"; : > "$ASSIGN_LOG"
  cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  ps) echo iris ;;
  exec)
    shift 2
    case "$1" in
      iris-assign)
        if [ $# -eq 1 ]; then
          printf 'published images:\n  %-40s sha256 %s...\n  %-40s sha256 %s...\nassignments:\n  (none)\n' \
            cat9k_iosxe.26.01.01 abcdef012345 quarantined-image 123456abcdef
          exit 0
        fi
        echo "$2 $3" >> "$ASSIGN_LOG"
        case "$3" in
          quarantined-image) echo "error: image '$3' is quarantined" >&2; exit 1 ;;
          *) echo "assigned $2 -> $3"; exit 0 ;;
        esac ;;
      *) exit 1 ;;
    esac ;;
  *) exit 1 ;;
esac
STUB
  chmod +x "$WORK/bin/docker"
  export PATH="$WORK/bin:$PATH"
  CSV="$WORK/assignments.csv"
}

@test "all rows valid: every assignment is applied once, in order" {
  cat > "$CSV" <<'CSVEOF'
device_id,image_id
# comment row
sw1,cat9k_iosxe.26.01.01
sw2, cat9k_iosxe.26.01.01
CSVEOF
  run bash "$APPLY" "$CSV"
  [ "$status" -eq 0 ]
  [[ "$output" == *"applied 2 assignment(s)"* ]]
  [ "$(cat "$ASSIGN_LOG")" = $'sw1 cat9k_iosxe.26.01.01\nsw2 cat9k_iosxe.26.01.01' ]
}

@test "an unpublished image on a later row aborts BEFORE any row is applied" {
  cat > "$CSV" <<'CSVEOF'
device_id,image_id
sw1,cat9k_iosxe.26.01.01
sw2,not-published-anywhere
sw3,cat9k_iosxe.26.01.01
CSVEOF
  run bash "$APPLY" "$CSV"
  [ "$status" -eq 1 ]
  [[ "$output" == *"not-published-anywhere"* ]]
  [[ "$output" == *"no assignments applied"* ]]
  # this is the regression: before the fix sw1 reached the server
  [ ! -s "$ASSIGN_LOG" ]
}

@test "duplicate device ids and extra columns are rejected before applying" {
  cat > "$CSV" <<'CSVEOF'
device_id,image_id
sw1,cat9k_iosxe.26.01.01
sw1,cat9k_iosxe.26.01.01
sw2,cat9k_iosxe.26.01.01,extra
CSVEOF
  run bash "$APPLY" "$CSV"
  [ "$status" -eq 1 ]
  [[ "$output" == *"duplicate device_id 'sw1'"* ]]
  [[ "$output" == *"expected 2 columns"* ]]
  [ ! -s "$ASSIGN_LOG" ]
}

@test "identifier format is validated the way gen-device-installers validates device ids" {
  cat > "$CSV" <<'CSVEOF'
device_id,image_id
sw"1,cat9k_iosxe.26.01.01
CSVEOF
  run bash "$APPLY" "$CSV"
  [ "$status" -eq 1 ]
  [[ "$output" == *"invalid format"* ]]
  [ ! -s "$ASSIGN_LOG" ]
}

@test "--dry-run validates and applies nothing" {
  cat > "$CSV" <<'CSVEOF'
device_id,image_id
sw1,cat9k_iosxe.26.01.01
CSVEOF
  run bash "$APPLY" --dry-run "$CSV"
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run: 1 assignment(s) validated"* ]]
  [ ! -s "$ASSIGN_LOG" ]
}

@test "an apply-time refusal is reported honestly, naming the rows that did not land" {
  cat > "$CSV" <<'CSVEOF'
device_id,image_id
sw1,cat9k_iosxe.26.01.01
sw2,quarantined-image
sw3,cat9k_iosxe.26.01.01
CSVEOF
  run bash "$APPLY" "$CSV"
  [ "$status" -eq 1 ]
  [[ "$output" == *"applied 2 of 3 assignment(s); 1 FAILED"* ]]
  [[ "$output" == *"sw2 -> quarantined-image"* ]]
  [[ "$output" != *"no assignments applied"* ]]
}
