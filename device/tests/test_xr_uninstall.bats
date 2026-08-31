#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for device/xr-uninstall.sh (agentinfo/plans/2026-08-28-xr-agent.md,
# Task 3): the record-driven inverse of device/xr-install.sh.
#
# Teardown-speed composite (agentinfo/specs/2026-08-31-xr-teardown-speed.md
# section 2A, amended after review to "at most two bounded sessions"): the
# per-step design that made 6-11 separate lab/xr-run.sh logins per teardown
# collapsed into AT MOST TWO bounded logins, split on a SAFETY boundary, not
# a topical one -- session 1/2 ("setup": early probe, unconditional-but-
# adjudicated deactivate -- NOTHING destructive to the package or files
# rides this login) and session 2/2 ("sweep+verify": the destructive
# commands -- source uninstall, delete the RPM, empty-then-delete the work
# dir -- PLUS the sidecar sweep (three unconditional harddisk: root globs),
# PLUS the final three-way verify). Session 2 is composed and sent ONLY when
# session 1's paired adjudication did NOT conclude the app is a confirmed
# real failure -- a rejected-while-present deactivate exits before session 2
# is ever built, so nothing destructive is ever composed, let alone sent, in
# that case (this was a CRITICAL finding in review of this task's first
# version: the destructive commands originally rode session 1's own blind
# unconditional stream, so they had already executed by the time a real
# failure was detected -- fixed by moving them into session 2's builder).
#
# Run-free fix wave (agentinfo/specs/2026-08-31-xr-teardown-speed.md, live
# hardware probe on 8010-R4/100.90.170.84, 2026-08-31): every 'run <cmd>'
# line is GONE. 'run' EXECUTES its command but NEVER yields the piped -tt
# session's prompt back, hanging every line typed after it in the same login
# (deterministic on this box; the same signature as 8010-R1's intermittent
# wedge). File removal now rides native XR EXEC 'delete /noprompt <path>'
# (hardware-proven: 3s clean return, evaluates harddisk: globs); the old
# ls-based list-then-targeted-rm sidecar sweep is GONE too -- replaced by
# three unconditional glob deletes, so session 1 no longer lists anything.
#
# Two, not one: this is now purely a SAFETY-ordering constraint (the old
# structural reason -- session 1's own `ls` result was needed to build
# session 2's targeted deletes -- is gone along with the ls-based design).
# There is no interactive transport to react to a login's output before it
# ends, so "adjudicate deactivate, THEN decide whether to compose and send
# anything destructive" can only happen BETWEEN two separate logins -- see
# the long design comment at the top of xr-uninstall.sh for the full
# justification.
#
# Final-line discipline: this Mac's bash (3.2) does not treat a failing
# bare `[[ ... ]]` as fatal under `set -e` unless it is the last command
# bats' test-runner function executes -- a failing `[[ ]]` earlier in a
# test body is silently swallowed and the NEXT command's exit status wins.
# Every `[[ ]]` below that is not already the test's final statement is
# therefore chained with `|| return 1` so it actually fails the test.

setup() {
  UNINSTALL="$BATS_TEST_DIRNAME/../xr-uninstall.sh"
}

# ---------------------------------------------------------------------------
# Dry-run text pins
# ---------------------------------------------------------------------------

@test "dry-run deactivates the app inside configure/commit" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  configure_line="$(printf '%s\n' "$output" | grep -n '^configure$' | head -1 | cut -d: -f1)"
  no_app_line="$(printf '%s\n' "$output" | grep -n '^no appmgr application iris$' | head -1 | cut -d: -f1)"
  commit_line="$(printf '%s\n' "$output" | grep -n '^commit$' | head -1 | cut -d: -f1)"
  [ -n "$configure_line" ] && [ -n "$no_app_line" ] && [ -n "$commit_line" ]
  [ "$configure_line" -lt "$no_app_line" ]
  [ "$no_app_line" -lt "$commit_line" ]
}

@test "dry-run uses the Cisco 8000 'source' uninstall form" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"appmgr package uninstall source iris-xr"* ]] || return 1
  [[ "$output" != *"appmgr package uninstall package"* ]]
}

@test "dry-run removes the RPM and empties-then-removes the work dir, via native delete /noprompt" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"delete /noprompt harddisk:/iris-xr.rpm"* ]] || return 1
  [[ "$output" == *"delete /noprompt harddisk:/iris-work/*"* ]] || return 1
  [[ "$output" == *"delete /noprompt harddisk:/iris-work"* ]]
}

@test "dry-run never emits a startup-config persist step" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  if printf '%s\n' "$output" | grep -qE '^copy running-config startup-config$'; then
    return 1
  fi
}

@test "dry-run respects APPID and SOURCE_NAME overrides" {
  APPID=probe SOURCE_NAME=probe-xr run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no appmgr application probe"* ]] || return 1
  [[ "$output" == *"appmgr package uninstall source probe-xr"* ]] || return 1
  [[ "$output" == *"delete /noprompt harddisk:/probe-xr.rpm"* ]]
}

# Pin mapping (old -> new): "dry-run's [1/5] describes the probe-first,
# retry-once, fail-closed shape" -> this. The retry-once mechanic is GONE
# (deactivate is now sent unconditionally, exactly once, adjudicated by
# pairing the early probe against the deactivate section instead of retrying
# and re-probing) -- the dry-run text below describes the new shape and this
# pin asserts it, in place of the old "retry deactivate once" text.
@test "dry-run's [1/5] describes the probe-first, unconditional, paired-adjudication shape" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"show appmgr application-table"* ]] || return 1
  [[ "$output" == *"unconditional no appmgr application"* ]] || return 1
  [[ "$output" == *"already absent before deactivate: benign idempotent-skip"* ]] || return 1
  [[ "$output" == *"still active and rejected: fail-closed, refuse to continue"* ]]
}

# Fix-wave item 2 (dry-run honesty): dry-run calls setup_request()/
# sweep_verify_request() directly and prints their REAL output, rather than
# re-describing the composed streams by hand -- chosen over a superset-
# containment bats test because it removes the drift risk structurally (one
# builder, one source of truth for both the live and dry-run paths) instead
# of just detecting drift after the fact. These internal
# `! __IRIS_XR_VERIFY_...__` marker lines (XR silent-comment form -- see the
# live-run-3 fix wave below; XR has no `echo` EXEC command) are plumbing a
# hand-written narration would never emit -- their presence is only possible
# if dry-run is invoking the real builders.
@test "dry-run prints the actual composed request bodies, not a hand-maintained description" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"! __IRIS_XR_VERIFY_APPS__"* ]] || return 1
  [[ "$output" == *"! __IRIS_XR_VERIFY_DEACTIVATE_END__"* ]] || return 1
  [[ "$output" == *"! __IRIS_XR_VERIFY_DONE__"* ]]
}

# Fix-wave item 1 (CRITICAL restructure): dry-run's session 1/2 portion
# (everything before the "composite session 2/2" banner) must never contain
# a destructive command -- the same safety boundary the live path now
# enforces structurally via sweep_verify_request()'s include_destructive
# gate.
@test "dry-run's session 1/2 portion contains no destructive command" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  session1="$(printf '%s\n' "$output" | sed '/composite session 2\/2/q')"
  if printf '%s\n' "$session1" | grep -qE 'appmgr package uninstall source|delete /noprompt harddisk:'; then
    return 1
  fi
}

@test "xr-uninstall.sh never sends the invalid 'appmgr application summary' form" {
  [ -r "$UNINSTALL" ] || return 1
  count="$(grep -c 'application summary' "$UNINSTALL" || true)"
  [ "$count" -eq 0 ]
}

# Run-free fix wave (agentinfo/specs/2026-08-31-xr-teardown-speed.md, live
# hardware probe on 8010-R4/100.90.170.84, 2026-08-31): 'run <cmd>' executes
# but NEVER yields the piped -tt session's prompt back, hanging every line
# typed after it in the same login (deterministic on this box). No composed
# stream may contain a bare XR 'run' command line ever again -- pinned here
# against both dry-run modes' actual output text.
@test "dry-run output (plain and FORCE) never contains a bare XR 'run' command line" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  if printf '%s\n' "$output" | grep -qE '^run[[:space:]]'; then
    return 1
  fi
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  if printf '%s\n' "$output" | grep -qE '^run[[:space:]]'; then
    return 1
  fi
}

# Live-run-3 fix wave (hardware root cause): XR has NO 'echo' EXEC command --
# every 'echo __IRIS_XR_VERIFY_...__' marker line used to mint its own
# '% Invalid input' banner INSIDE the section it delimits, which the
# (correct) rejection check then honestly reported as "probe was rejected".
# Markers now ride XR's '! <text>' silent-comment form instead (proven at
# both exec and config level, zero banners). No composed stream may contain
# a bare XR 'echo' command line ever again -- pinned here against both
# dry-run modes' actual output text, mirroring the no-'run' pin above.
@test "dry-run output (plain and FORCE) never contains an XR 'echo' command line (XR has no echo)" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  if printf '%s\n' "$output" | grep -qE '^echo[[:space:]]'; then
    return 1
  fi
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  if printf '%s\n' "$output" | grep -qE '^echo[[:space:]]'; then
    return 1
  fi
}

@test "FORCE dry-run and record-driven dry-run touch the identical IRIS-named footprint" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  plain="$output"
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  forced="$output"
  # every actual command line in the plain run also appears in the forced
  # run -- FORCE only prepends an explanatory banner, it does not change
  # what gets touched (see the script header: XR activation is --net=host
  # only, so nothing here is ever ambiguously operator-owned the way a
  # router's VirtualPortGroup/NAT can be).
  for line in "show appmgr application-table" "no appmgr application iris" \
              "appmgr package uninstall source iris-xr" \
              "delete /noprompt harddisk:/iris-xr.rpm" "delete /noprompt harddisk:/iris-work"; do
    [[ "$plain" == *"$line"* ]] || return 1
    [[ "$forced" == *"$line"* ]] || return 1
  done
}

@test "FORCE dry-run names only IRIS-marked artifacts, nothing switch/router-shaped" {
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"FORCE"* ]] || return 1
  # never a VLAN/VirtualPortGroup/NAT primitive -- XR activation never
  # creates any of these (host networking only).
  if printf '%s\n' "$output" | grep -Eq '(^|[[:space:]])vlan [0-9]|VirtualPortGroup|switchport|ip nat|ip access-list'; then
    return 1
  fi
}

@test "real teardown without credentials fails through the friendly guard, not an unbound variable" {
  run env -u DEVICE_IP -u DEVICE_USER -u DEVICE_PASS bash "$UNINSTALL"
  [ "$status" -ne 0 ]
  [[ "$output" == *"set DEVICE_IP"* ]] || return 1
  [[ "$output" != *"unbound variable"* ]]
}

# ---------------------------------------------------------------------------
# The commit-failure guard: the deactivate step's commit must ride
# lab/xr-run.sh, never a direct ssh call.
# ---------------------------------------------------------------------------

@test "the uninstaller opens no SSH session of its own" {
  count="$(grep -c 'sshpass' "$UNINSTALL" || true)"
  [ "$count" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Live path against a stubbed lab/xr-run.sh
#
# The composite sends exactly TWO logins per real teardown: session 1/2
# ("setup") is the request that carries the DEACTIVATE marker (unique to it
# -- session 2/2 never touches configure/deactivate again); session 2/2
# ("sweep+verify") is the request that carries the FILES marker (unique to
# it -- session 1/2 never reads harddisk: directly). The stub below responds
# to each based on which marker the request itself is asking for, exactly
# the way the real device would answer whatever it was actually sent.
#
# A single shared app-table probe-call counter (FAKE_APP_ROW_<n>) spans BOTH
# logins in one script run: index 1 is always session 1/2's early probe;
# index 2 is always session 2/2's own re-probe. An index with no override
# falls back to the flat FAKE_APP_ROW (itself defaulting to "" -- app
# absent).
# ---------------------------------------------------------------------------

_xr_uninstall_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device"
  FAKE_COMMAND_LOG="$BATS_TEST_TMPDIR/xr-commands.log"
  : > "$FAKE_COMMAND_LOG"
  export FAKE_COMMAND_LOG

  cat > "$STUBDIR/lab/xr-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
if [ -n "${FAKE_COMMAND_LOG:-}" ]; then
  { echo "=== CALL START ==="; printf '%s\n' "$cmds"; echo "=== CALL END ==="; } >> "$FAKE_COMMAND_LOG"
fi

# True when the request carries this exact command on a line of its own. A
# device answers COMMANDS, not markers; keying the stub's replies off the
# marker alone is what let a read be deleted from the builder with the whole
# suite still green.
sent_line() { printf '%s\n' "$cmds" | grep -qxF "$1"; }

next_app_row() {
  countfile="${BATS_TEST_TMPDIR:-.}/probe-count"
  n=0
  [ -f "$countfile" ] && n="$(cat "$countfile")"
  n=$((n + 1))
  printf '%s' "$n" > "$countfile"
  indexed_var="FAKE_APP_ROW_$n"
  eval "printf '%s' \"\${$indexed_var-\$FAKE_APP_ROW}\""
}

case "$cmds" in
  *"__IRIS_XR_VERIFY_DEACTIVATE__"*)
    # session 1/2 (setup): APPS (early probe) -> DEACTIVATE. NOTHING
    # destructive rides this request -- the stub does not need to (and does
    # not) special-case that; it is the request body itself (asserted by the
    # tests below) that proves the destructive commands were never composed
    # into this call. No sidecar listing either (fix-wave rewrite): the
    # sidecar sweep is three unconditional harddisk: root globs now, sent
    # unconditionally in session 2 -- session 1 has nothing to list.
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      row="$(next_app_row)"
      echo "__IRIS_XR_VERIFY_APPS__"
      # XR stamps every exec command with a timestamp line before its output,
      # so even an EMPTY table still carries device-originated content. The
      # stub must model that: without it an absent app is indistinguishable
      # from a session that never executed anything, which is precisely the
      # C1 fail-open the script now refuses.
      echo "Mon Aug 31 14:24:08.136 UTC"
      printf '%s\n' "$row"
      # FAKE_VERIFY_OMIT_APPS_END simulates a probe truncated right after
      # its start marker + row -- a hard error, never read as absent.
      if [ "${FAKE_VERIFY_OMIT_APPS_END:-no}" != "yes" ]; then
        echo "__IRIS_XR_VERIFY_APPS_END__"
      fi
      # FAKE_PROBE_RC simulates the transport dying with a nonzero exit
      # (e.g. rc 124, the session-bound timeout) after whatever partial
      # output already made it out above -- before DEACTIVATE.
      if [ -n "${FAKE_PROBE_RC:-}" ] && [ "${FAKE_PROBE_RC}" != "0" ]; then
        exit "$FAKE_PROBE_RC"
      fi
    fi
    echo "__IRIS_XR_VERIFY_DEACTIVATE__"
    # FAKE_DEACTIVATE_REJECTED injects XR's proven generic rejection banner
    # (LAB-RESULTS-2026-08-27.md) into the deactivate section, standing in
    # for "the commit's own show configuration failed output flagged
    # something" without needing the unmeasured appmgr-specific text.
    if [ "${FAKE_DEACTIVATE_REJECTED:-no}" = "yes" ]; then
      echo "% Invalid input detected"
    fi
    if [ "${FAKE_VERIFY_OMIT_DEACTIVATE_END:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_DEACTIVATE_END__"
    fi
    # Post-commit re-probe: the script asks the device whether the app is
    # ACTUALLY gone rather than inferring it from the absence of an error.
    # This consumes app-table index 2, so session 2/2's own read is index 3.
    echo "__IRIS_XR_VERIFY_RECHECK__"
    echo "Mon Aug 31 14:24:09.221 UTC"
    printf '%s\n' "$(next_app_row)"
    echo "__IRIS_XR_VERIFY_RECHECK_END__"
    ;;
  *"__IRIS_XR_VERIFY_FILES__"*)
    # session 2/2 (sweep+verify): the destructive commands (when composed at
    # all -- gated client-side, not by this stub) -> APPS (final re-probe)
    # -> SOURCES -> FILES -> WORKDIR -> DONE.
    if sent_line "show appmgr application-table" \
       && [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      row="$(next_app_row)"
      echo "__IRIS_XR_VERIFY_APPS__"
      # XR stamps every exec command with a timestamp line before its output,
      # so even an EMPTY table still carries device-originated content. The
      # stub must model that: without it an absent app is indistinguishable
      # from a session that never executed anything, which is precisely the
      # C1 fail-open the script now refuses.
      echo "Mon Aug 31 14:24:08.136 UTC"
      printf '%s\n' "$row"
    fi
    if sent_line "show appmgr source-table"; then
      echo "__IRIS_XR_VERIFY_SOURCES__"
      echo "Mon Aug 31 14:24:11.615 UTC"
      printf '%s\n' "${FAKE_SOURCE_ROW-}"
    fi
    if sent_line "dir harddisk:" \
       && [ "${FAKE_VERIFY_OMIT_FILES:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_FILES__"
      echo "Mon Aug 31 14:24:15.440 UTC"
      printf '%s\n' "${FAKE_DIR_HARDDISK-Directory of harddisk:/}"
    fi
    # Run-4/5 fix wave: iris-work's own sub-listing. Default is the REAL
    # empty-directory shape captured live on hardware (run 5) -- header,
    # "No files in directory", blank line, kbytes-total footer -- harmless
    # for every test that never puts "iris-work" into FAKE_DIR_HARDDISK,
    # since [5/5] only ever consults this once the root-level FILES check
    # has already confirmed iris-work is present.
    if sent_line "dir harddisk:/iris-work" \
       && [ "${FAKE_VERIFY_OMIT_WORKDIR:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_WORKDIR__"
      echo "Mon Aug 31 14:24:05.992 UTC"
      printf '%s\n' "${FAKE_WORKDIR_LISTING-Directory of harddisk:/iris-work
No files in directory

41968752 kbytes total (39714572 kbytes free)}"
    fi
    if [ -n "${FAKE_VERIFY_RC:-}" ] && [ "${FAKE_VERIFY_RC}" != "0" ]; then
      exit "$FAKE_VERIFY_RC"
    fi
    echo "__IRIS_XR_VERIFY_DONE__"
    ;;
  *)
    echo "ok"
    ;;
esac
STUB
  chmod +x "$STUBDIR/lab/xr-run.sh"
  ln -sf "$UNINSTALL" "$STUBDIR/device/xr-uninstall.sh"
}

# CRITICAL fix pin: a fake lab/xr-run.sh shaped like the REAL ssh -tt
# transport (commit 6fd43db transcript shape) -- it echoes the ENTIRE piped
# request back verbatim as one upfront blob BEFORE anything executes, then
# appends the real (executed) section for whatever was actually asked for,
# same as the plain stub above. Every marker therefore appears at least
# twice in the transcript: once inside the echoed blob (whose "section" is
# just the next typed line, never real output) and once for real.
# verify_section must read the LAST occurrence, not the first.
_xr_uninstall_echoing_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device"
  FAKE_COMMAND_LOG="$BATS_TEST_TMPDIR/xr-commands.log"
  : > "$FAKE_COMMAND_LOG"
  export FAKE_COMMAND_LOG

  cat > "$STUBDIR/lab/xr-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
if [ -n "${FAKE_COMMAND_LOG:-}" ]; then
  { echo "=== CALL START ==="; printf '%s\n' "$cmds"; echo "=== CALL END ==="; } >> "$FAKE_COMMAND_LOG"
fi
printf '%s\n' "$cmds"

# FAKE_ECHO_ONLY: an rc-0 session that echoed the whole piped request back
# and executed NOTHING -- the transcript is the upfront blob and nothing
# else. Hardware-plausible: a login/banner state that closes early, or per
# command AAA authorization refusing every line. The markers are `!` comments
# that emit no output of their own, so marker PRESENCE cannot distinguish
# this from a real run; only device-originated content can.
if [ "${FAKE_ECHO_ONLY:-no}" = "yes" ]; then
  exit 0
fi

# True when the request carries this exact command on a line of its own. A
# device answers COMMANDS, not markers; keying the stub's replies off the
# marker alone is what let a read be deleted from the builder with the whole
# suite still green.
sent_line() { printf '%s\n' "$cmds" | grep -qxF "$1"; }

next_app_row() {
  countfile="${BATS_TEST_TMPDIR:-.}/probe-count"
  n=0
  [ -f "$countfile" ] && n="$(cat "$countfile")"
  n=$((n + 1))
  printf '%s' "$n" > "$countfile"
  indexed_var="FAKE_APP_ROW_$n"
  eval "printf '%s' \"\${$indexed_var-\$FAKE_APP_ROW}\""
}

case "$cmds" in
  *"__IRIS_XR_VERIFY_DEACTIVATE__"*)
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      row="$(next_app_row)"
      echo "__IRIS_XR_VERIFY_APPS__"
      # XR stamps every exec command with a timestamp line before its output,
      # so even an EMPTY table still carries device-originated content. The
      # stub must model that: without it an absent app is indistinguishable
      # from a session that never executed anything, which is precisely the
      # C1 fail-open the script now refuses.
      echo "Mon Aug 31 14:24:08.136 UTC"
      printf '%s\n' "$row"
      # FAKE_TRUNCATE_AFTER_APPS simulates the transport dying (rc 0) right
      # after the REAL start marker + row -- before its own end marker or
      # any later section. The echoed upfront blob still has a literal copy
      # of the end marker's text, so only the positional check catches this.
      if [ "${FAKE_TRUNCATE_AFTER_APPS:-no}" = "yes" ]; then
        exit 0
      fi
      if [ "${FAKE_VERIFY_OMIT_APPS_END:-no}" != "yes" ]; then
        echo "__IRIS_XR_VERIFY_APPS_END__"
      fi
    fi
    echo "__IRIS_XR_VERIFY_DEACTIVATE__"
    if [ "${FAKE_DEACTIVATE_REJECTED:-no}" = "yes" ]; then
      echo "% Invalid input detected"
    fi
    echo "__IRIS_XR_VERIFY_DEACTIVATE_END__"
    echo "__IRIS_XR_VERIFY_RECHECK__"
    echo "Mon Aug 31 14:24:09.221 UTC"
    printf '%s\n' "$(next_app_row)"
    echo "__IRIS_XR_VERIFY_RECHECK_END__"
    ;;
  *"__IRIS_XR_VERIFY_FILES__"*)
    # Session 1 succeeds normally; only the sweep+verify session comes back
    # echo-only at rc 0, so this isolates the verify-side half of the defect.
    if [ "${FAKE_ECHO_ONLY_VERIFY:-no}" = "yes" ]; then
      exit 0
    fi
    if [ -n "${FAKE_VERIFY_RC:-}" ] && [ "${FAKE_VERIFY_RC}" != "0" ]; then
      # "blob-only output": nothing real is ever produced -- the echoed
      # upfront blob (already printed above) is ALL this call returns
      # before the transport itself dies.
      exit "$FAKE_VERIFY_RC"
    fi
    if sent_line "show appmgr application-table" \
       && [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      row="$(next_app_row)"
      echo "__IRIS_XR_VERIFY_APPS__"
      # XR stamps every exec command with a timestamp line before its output,
      # so even an EMPTY table still carries device-originated content. The
      # stub must model that: without it an absent app is indistinguishable
      # from a session that never executed anything, which is precisely the
      # C1 fail-open the script now refuses.
      echo "Mon Aug 31 14:24:08.136 UTC"
      printf '%s\n' "$row"
    fi
    if sent_line "show appmgr source-table"; then
      echo "__IRIS_XR_VERIFY_SOURCES__"
      echo "Mon Aug 31 14:24:11.615 UTC"
      printf '%s\n' "${FAKE_SOURCE_ROW-}"
    fi
    if sent_line "dir harddisk:" \
       && [ "${FAKE_VERIFY_OMIT_FILES:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_FILES__"
      echo "Mon Aug 31 14:24:15.440 UTC"
      printf '%s\n' "${FAKE_DIR_HARDDISK-Directory of harddisk:/}"
    fi
    # FAKE_TRUNCATE_AFTER_FILES simulates the transport dying (rc 0) right
    # after the REAL FILES section -- before WORKDIR or DONE ever execute.
    # The echoed upfront blob still has a literal copy of every later
    # marker's text, so only the positional (last-DONE-after-last-FILES)
    # check catches this.
    if [ "${FAKE_TRUNCATE_AFTER_FILES:-no}" = "yes" ]; then
      exit 0
    fi
    # Run-4/5 fix wave: iris-work's own sub-listing (default: the REAL
    # empty-directory shape captured live on hardware, run 5).
    if sent_line "dir harddisk:/iris-work" \
       && [ "${FAKE_VERIFY_OMIT_WORKDIR:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_WORKDIR__"
      echo "Mon Aug 31 14:24:05.992 UTC"
      printf '%s\n' "${FAKE_WORKDIR_LISTING-Directory of harddisk:/iris-work
No files in directory

41968752 kbytes total (39714572 kbytes free)}"
    fi
    echo "__IRIS_XR_VERIFY_DONE__"
    ;;
  *)
    echo "ok"
    ;;
esac
STUB
  chmod +x "$STUBDIR/lab/xr-run.sh"
  ln -sf "$UNINSTALL" "$STUBDIR/device/xr-uninstall.sh"
}

# Live-run-3 fix pin: a fake lab/xr-run.sh shaped like the EXACT hardware
# evidence for the echo/comment fix -- a real marker line does not arrive
# bare; the device's own prompt is echoed immediately ahead of it on the
# SAME line (probe transcript evidence: "RP/.../CPU0:host#! __MARKER__",
# grep 'Invalid input' = 0). This stub prefixes every emitted marker with a
# synthetic XR prompt to prove verify_section()/end_after_start() -- which
# search for the marker text as a substring anywhere in the captured blob,
# never anchored to the start of a line -- parse this shape correctly with
# no code changes of their own.
_xr_uninstall_prompt_echoed_stub_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/stub"
  mkdir -p "$STUBDIR/lab" "$STUBDIR/device"
  FAKE_COMMAND_LOG="$BATS_TEST_TMPDIR/xr-commands.log"
  : > "$FAKE_COMMAND_LOG"
  export FAKE_COMMAND_LOG

  cat > "$STUBDIR/lab/xr-run.sh" <<'STUB'
#!/usr/bin/env bash
cmds="$(cat)"
if [ -n "${FAKE_COMMAND_LOG:-}" ]; then
  { echo "=== CALL START ==="; printf '%s\n' "$cmds"; echo "=== CALL END ==="; } >> "$FAKE_COMMAND_LOG"
fi

PROMPT="RP/0/RP0/CPU0:iris-lab-8010#"

case "$cmds" in
  *"__IRIS_XR_VERIFY_DEACTIVATE__"*)
    # session 1/2 (setup): a genuinely present app row, so this run also
    # exercises deactivate being sent for real -- every marker below arrives
    # prompt-echoed, never a bare line.
    printf '%s! __IRIS_XR_VERIFY_APPS__\n' "$PROMPT"
    printf 'Mon Aug 31 14:24:08.136 UTC\n'
    printf 'iris  docker  iris-xr  Up  app_manager\n'
    printf '%s! __IRIS_XR_VERIFY_APPS_END__\n' "$PROMPT"
    printf '%s! __IRIS_XR_VERIFY_DEACTIVATE__\n' "$PROMPT"
    printf '%s! __IRIS_XR_VERIFY_DEACTIVATE_END__\n' "$PROMPT"
    printf '%s! __IRIS_XR_VERIFY_RECHECK__\n' "$PROMPT"
    printf 'Mon Aug 31 14:24:09.221 UTC\n'
    printf '%s! __IRIS_XR_VERIFY_RECHECK_END__\n' "$PROMPT"
    ;;
  *"__IRIS_XR_VERIFY_FILES__"*)
    printf '%s! __IRIS_XR_VERIFY_APPS__\n' "$PROMPT"
    printf 'Mon Aug 31 14:24:08.136 UTC\n'
    printf '\n'
    printf '%s! __IRIS_XR_VERIFY_SOURCES__\n' "$PROMPT"
    printf 'Mon Aug 31 14:24:11.615 UTC\n'
    printf '\n'
    printf '%s! __IRIS_XR_VERIFY_FILES__\n' "$PROMPT"
    printf 'Directory of harddisk:/\n'
    printf '%s! __IRIS_XR_VERIFY_WORKDIR__\n' "$PROMPT"
    printf 'Directory of harddisk:/iris-work\n'
    printf '%s! __IRIS_XR_VERIFY_DONE__\n' "$PROMPT"
    ;;
  *)
    echo "ok"
    ;;
esac
STUB
  chmod +x "$STUBDIR/lab/xr-run.sh"
  ln -sf "$UNINSTALL" "$STUBDIR/device/xr-uninstall.sh"
}

_xr_uninstall_run_live() {
  # Fresh probe-call counter per script invocation -- two separate runs
  # against the same stub setup (the FORCE parity test below) must each see
  # call index 1 on their own first application-table probe, not inherit
  # the previous run's count.
  rm -f "$BATS_TEST_TMPDIR/probe-count"
  env DEVICE_IP=192.0.2.10 DEVICE_USER=admin DEVICE_PASS=pw \
    bash "$STUBDIR/device/xr-uninstall.sh"
}

# Isolates the Nth (1-indexed) login's own request body out of
# FAKE_COMMAND_LOG, so a test can assert something about exactly ONE call's
# content without the other call's lines being able to satisfy the same
# substring check (the failure mode a whole-log grep can't rule out).
_xr_call_body() {
  local want="$1"
  awk -v want="$want" '
    /=== CALL START ===/ { c++; if (c == want) capture = 1; next }
    /=== CALL END ===/   { if (c == want) capture = 0; next }
    capture { print }
  ' "$FAKE_COMMAND_LOG"
}

# Pin mapping (old -> new): this is a NEW pin (brief step 1(a)) with a
# documented deviation from a literal "exactly once" -- see the design
# comment at the top of xr-uninstall.sh and this file's own header comment.
# The composite sends exactly TWO logins, never a variable 6-11 the way the
# old per-step script did; this pins the count as a fixed, small constant.
@test "live: the real-run path invokes xr-run.sh exactly twice (setup, then sweep+verify)" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  count="$(printf '%s\n' "$log" | grep -c '=== CALL START ===')"
  [ "$count" -eq 2 ] || return 1
}

# Brief step 1(b): the composite stream (this script's own stdout, which is
# what gui_onboard's job log streams and the console's jobPhaseSuffix reads)
# contains all five step markers in order.
@test "live: all five [n/5] step markers appear on stdout, in order" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  for i in 1 2 3 4 5; do
    line="$(printf '%s\n' "$output" | grep -n "\[$i/5\]" | head -1 | cut -d: -f1)"
    eval "line_$i=\$line"
    [ -n "$line" ] || return 1
  done
  [ "$line_1" -lt "$line_2" ] || return 1
  [ "$line_2" -lt "$line_3" ] || return 1
  [ "$line_3" -lt "$line_4" ] || return 1
  [ "$line_4" -lt "$line_5" ] || return 1
}

# Brief step 1(c): the fixed probe command is present, the D2-3 invalid form
# is absent -- pinned again here against the LIVE composed request (the
# static-text pin above already covers the dry-run text).
@test "live: the composed setup request sends the fixed probe, never the invalid form" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  # Pinned by POSITION inside session 1's own body, which is the only form that
  # actually holds. A whole-log substring was satisfied by session 2's copy of
  # the same string; scoping to session 1 alone is still not enough, because
  # session 1 now carries a SECOND app-table read (the post-commit re-probe)
  # whose copy would keep this green with the probe deleted. What the paired
  # adjudication actually needs is a read that happens BEFORE the deactivate.
  body="$(_xr_call_body 1)"
  probe_at="$(printf '%s\n' "$body" | grep -n '^show appmgr application-table$' | head -1 | cut -d: -f1)"
  deact_at="$(printf '%s\n' "$body" | grep -n 'VERIFY_DEACTIVATE__' | head -1 | cut -d: -f1)"
  [ -n "$probe_at" ] || return 1
  [ -n "$deact_at" ] || return 1
  [ "$probe_at" -lt "$deact_at" ] || return 1
  if printf '%s\n' "$body" | grep -q 'application summary'; then
    return 1
  fi
}

@test "live: reports success once the app, source, and files are all gone" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ]
  [[ "$output" == *"undeploy complete"* ]]
}

# Pin mapping (old -> new): "live: [1/5] probes app-table, deactivates once,
# and continues once the re-probe shows it gone" -> this. There is no more
# re-probe/retry inside [1/5] -- deactivate is unconditional and sent
# exactly once every run; [5/5]'s own independent re-probe (not a [1/5]
# retry) is what confirms it actually worked.
@test "live: deactivate is sent exactly once when the app is present, and [5/5] confirms it's gone" {
  _xr_uninstall_stub_setup
  FAKE_APP_ROW_1="iris  docker  iris-xr  Up  app_manager" run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  count="$(printf '%s\n' "$log" | grep -c '^no appmgr application iris$')"
  [ "$count" -eq 1 ] || return 1
  [[ "$log" == *"appmgr package uninstall source iris-xr"* ]]
}

# Pin mapping (old -> new): "live: a second run against an already-
# deactivated app logs already-absent and still converges" -> this, updated
# for the new unconditional-send contract: deactivate IS still submitted
# (every run, unconditionally) even though the app was already absent --
# only the ADJUDICATION is benign now, not the submission itself.
@test "live: an already-absent app is submitted unconditionally but adjudicated benign, and still converges" {
  _xr_uninstall_stub_setup
  # FAKE_APP_ROW left unset: the app is absent at every probe, modeling a
  # second run after a partial teardown (app already gone, rpm/work dir
  # possibly still present -- those steps keep their own || true tolerance).
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"already deactivated/absent"* ]] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  [[ "$log" == *"no appmgr application iris"* ]] || return 1
}

# Pin mapping (old -> new): "live: refuses to continue teardown when the app
# is still active after two deactivate attempts" -> this. No more retry: the
# paired-adjudication REAL FAILURE case is probe-present + deactivate
# rejected (D2-3's own proven generic rejection banner standing in for the
# unmeasured appmgr-specific text) -- fails loud and never composes/sends
# the sweep+verify login at all.
#
# CRITICAL fix-wave pin (restored): an earlier version of this task's
# composite put the destructive commands (source uninstall, delete the RPM,
# delete the work dir) unconditionally in session 1's OWN blind stream, so
# by the time this exact real-failure verdict was reached they had ALREADY
# executed against a device this script had just concluded was still
# running the app -- confirmed by empirical transcript reproduction in
# review. The anti-uninstall/delete assertion below is the direct regression
# pin for that finding: it must fail the test if either destructive command
# appears ANYWHERE in the transport log once real failure is concluded, not
# just skip the check the way the earlier version did.
@test "live: refuses to continue when the app is present and deactivate is rejected (paired adjudication, real failure)" {
  _xr_uninstall_stub_setup
  FAKE_APP_ROW_1="iris  docker  iris-xr  Up  app_manager" FAKE_DEACTIVATE_REJECTED=yes \
    run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"refusing to continue teardown while application iris is still active"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  # exactly one login was made -- session 2/2 (sweep+verify) must never be
  # composed or sent once the paired adjudication fails loud.
  count="$(printf '%s\n' "$log" | grep -c '=== CALL START ===')"
  [ "$count" -eq 1 ] || return 1
  # RESTORED: nothing destructive was ever sent to the device in this run --
  # session 2, the only place any of the destructive commands can now live,
  # was never composed at all.
  if printf '%s\n' "$log" | grep -qE 'appmgr package uninstall source|delete /noprompt harddisk:'; then
    return 1
  fi
}

# CRITICAL fix-wave pin: the structural proof, independent of any particular
# outcome -- session 1's own request body NEVER contains a destructive
# command, whether the run goes on to succeed (this test, app absent so
# adjudication is benign and session 2 IS composed) or fails loud (the test
# above, session 2 never composed at all). Isolating call 1's own body (via
# _xr_call_body) rather than grepping the whole log rules out the failure
# mode review caught: a whole-log grep can't tell "absent from call 1" apart
# from "present, but only in call 2".
@test "live: session 1's own request body never contains a destructive command" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  first_call="$(_xr_call_body 1)"
  if printf '%s\n' "$first_call" | grep -qE 'appmgr package uninstall source|delete /noprompt harddisk:'; then
    return 1
  fi
  # contrast: the destructive commands DID move somewhere -- call 2, once
  # adjudication clears them -- proving this is a relocation gated on
  # outcome, not a silent deletion of the steps themselves.
  second_call="$(_xr_call_body 2)"
  [[ "$second_call" == *"appmgr package uninstall source iris-xr"* ]] || return 1
  [[ "$second_call" == *"delete /noprompt harddisk:/iris-xr.rpm"* ]] || return 1
  [[ "$second_call" == *"delete /noprompt harddisk:/iris-work/*"* ]] || return 1
  [[ "$second_call" == *"delete /noprompt harddisk:/iris-work"* ]] || return 1
  [[ "$second_call" == *"delete /noprompt harddisk:/*.torrent"* ]] || return 1
  [[ "$second_call" == *"delete /noprompt harddisk:/*.aria2"* ]] || return 1
  [[ "$second_call" == *"delete /noprompt harddisk:/*.peers.json"* ]]
}

# Run-free fix wave: pinned against the LIVE composed streams too (the
# dry-run pin above only covers dry-run's own text) -- neither session's own
# request body may ever contain a bare XR 'run' command line. 'run <cmd>'
# executes but never yields the piped -tt session's prompt back, hanging
# every line after it in the same login (hardware-proven, 8010-R4).
@test "live: neither composed session's request body ever contains a bare XR 'run' command line" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  first_call="$(_xr_call_body 1)"
  second_call="$(_xr_call_body 2)"
  if printf '%s\n%s\n' "$first_call" "$second_call" | grep -qE '^run[[:space:]]'; then
    return 1
  fi
}

# Live-run-3 fix wave: pinned against the LIVE composed streams too (the
# dry-run pin above only covers dry-run's own text) -- neither session's own
# request body may ever contain a bare XR 'echo' command line (XR has no
# 'echo' EXEC command; every marker now rides '! <text>' instead -- see the
# dry-run echo pin above for the root cause).
@test "live: neither composed session's request body ever contains an XR 'echo' command line" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  first_call="$(_xr_call_body 1)"
  second_call="$(_xr_call_body 2)"
  if printf '%s\n%s\n' "$first_call" "$second_call" | grep -qE '^echo[[:space:]]'; then
    return 1
  fi
  # positive half: every marker line in both bodies is the '!' comment form.
  [[ "$first_call" == *"! __IRIS_XR_VERIFY_APPS__"* ]] || return 1
  [[ "$second_call" == *"! __IRIS_XR_VERIFY_DONE__"* ]]
}

# New pin (brief step 1(d), paired-adjudication half): probe-absent +
# deactivate-rejected is BENIGN -- the idempotent-skip verdict, not a
# failure, even though deactivate's own section carries the same rejection
# banner the "real failure" case above uses. This is the D2-3 regression
# pin's other half: fail-loud on a rejection while genuinely present, never
# silent-skip -- but ALSO never a false failure while genuinely absent.
@test "live: an already-absent app with a rejected deactivate is still benign (paired adjudication, idempotent skip)" {
  _xr_uninstall_stub_setup
  FAKE_DEACTIVATE_REJECTED=yes run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"already deactivated/absent"* ]] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  # contrast with the real-failure test above: benign means session 2 IS
  # composed and the destructive commands DO run -- there is nothing left on
  # the device for them to endanger.
  log="$(cat "$FAKE_COMMAND_LOG")"
  [[ "$log" == *"appmgr package uninstall source iris-xr"* ]] || return 1
}

@test "live: a deactivate probe transport failure is a hard error, never read as absent" {
  _xr_uninstall_stub_setup
  FAKE_VERIFY_OMIT_APPS=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"deactivate probe did not return the appmgr application-table"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  # fails closed on the very first probe -- session 2/2 is never sent
  count="$(printf '%s\n' "$log" | grep -c '=== CALL START ===')"
  [ "$count" -eq 1 ] || return 1
}

@test "live: a probe transport that exits nonzero is a hard error, never read as absent" {
  _xr_uninstall_stub_setup
  FAKE_PROBE_RC=124 run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  count="$(printf '%s\n' "$log" | grep -c '=== CALL START ===')"
  [ "$count" -eq 1 ] || return 1
}

# Fix-wave ordering pin (live-reproduced twice, progress.md L2 RUN 1/2,
# 100.90.170.84, 2026-08-31): a simulated rc-124 (session-bound timeout)
# session 1 transcript must yield NO "[1/5] ... no appmgr application" line
# at all. Before the fix, that line printed unconditionally before the rc
# check below it, so a dead transport still let it reach stdout -- reading,
# on any log that streams stdout without also surfacing the stderr ERROR
# right after it, exactly like a genuine (false) "app absent" verdict. The
# rc check now runs FIRST, so on rc 124 the script exits before [1/5] is
# ever printed -- only the honest transport error appears.
@test "live: a dead-transport (rc 124) session 1 mints NO false '[1/5] ... no appmgr application' line" {
  _xr_uninstall_stub_setup
  FAKE_PROBE_RC=124 run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"transport exited 124"* ]] || return 1
  if printf '%s\n' "$output" | grep -q '\[1/5\].*no appmgr application'; then
    return 1
  fi
}

@test "live: a probe truncated after its start marker (missing end marker) is a hard error, never absent" {
  _xr_uninstall_stub_setup
  FAKE_VERIFY_OMIT_APPS_END=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  count="$(printf '%s\n' "$log" | grep -c '=== CALL START ===')"
  [ "$count" -eq 1 ] || return 1
}

@test "live: [5/5] still independently catches the app reappearing after a successful deactivate" {
  _xr_uninstall_stub_setup
  # index 1 (session 1/2's early probe): present. index 2 (session 1/2's
  # post-commit re-probe): ABSENT, so the deactivate genuinely worked and the
  # run proceeds to session 2/2. index 3 (session 2/2's own read) is present
  # again -- a flapping app -- and [5/5]'s independent check is still the last
  # line of defense.
  FAKE_APP_ROW_1="iris  docker  iris-xr  Up  app_manager" \
    FAKE_APP_ROW_2="" \
    FAKE_APP_ROW_3="iris  docker  iris-xr  Up  app_manager" \
    run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"artifacts still present"* ]] || return 1
  [[ "$output" == *"appmgr application iris"* ]]
}

# Review finding (2026-08-31): the paired adjudication gated the destructive
# session on a SYNTAX rejection alone. A deactivate whose `commit` fails --
# leaving the application running -- produces no `% Invalid input`, so the run
# proceeded to uninstall the source and delete the RPM and every sidecar on a
# device still running the app. That is the D2-3 fail-open shape the whole
# composite exists to prevent.
#
# The fix does not try to recognize commit-failure text, which has never been
# measured on this platform. It asks the device instead: re-probe the
# application table after the commit, in the same login, and refuse if the app
# is still there -- whatever the reason.
@test "live: an app still present after deactivate refuses before anything destructive is sent" {
  _xr_uninstall_stub_setup
  FAKE_APP_ROW_1="iris  docker  iris-xr  Up  app_manager" \
    FAKE_APP_ROW_2="iris  docker  iris-xr  Up  app_manager" \
    run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"still active"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  # Session 2 must never have been composed, let alone sent.
  [ "$(printf '%s\n' "$log" | grep -c 'delete /noprompt')" -eq 0 ] || return 1
  [ "$(printf '%s\n' "$log" | grep -c 'appmgr package uninstall source')" -eq 0 ] || return 1
  [ "$(printf '%s\n' "$log" | grep -c '=== CALL START ===')" -eq 1 ]
}

# ---------------------------------------------------------------------------
# CRITICAL: verify_section must read the EXECUTED marker, not the transport's
# own echo of what was piped in. ssh -tt (the real XR transport) echoes the
# WHOLE piped request as one upfront blob before anything runs, so every
# marker's first occurrence sits in that blob -- first-match section
# extraction returned the literal next typed line instead of real command
# output (commit 6fd43db fixed the identical bug in the Python XR preflight
# probe; this pins the same fix here, against the same transcript shape).
# ---------------------------------------------------------------------------

@test "live [echoing transport]: a running app is probed correctly and deactivated, not misread as absent" {
  _xr_uninstall_echoing_stub_setup
  FAKE_APP_ROW_1="iris  docker  iris-xr  Up  app_manager" run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  count="$(printf '%s\n' "$log" | grep -c '^no appmgr application iris$')"
  [ "$count" -eq 1 ] || return 1
}

@test "live [echoing transport]: the sidecar sweep still issues its unconditional glob deletes" {
  _xr_uninstall_echoing_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  [[ "$log" == *"delete /noprompt harddisk:/*.torrent"* ]] || return 1
  [[ "$log" == *"delete /noprompt harddisk:/*.aria2"* ]] || return 1
  [[ "$log" == *"delete /noprompt harddisk:/*.peers.json"* ]]
}

@test "live [echoing transport]: [5/5] still catches a planted forbidden artifact" {
  _xr_uninstall_echoing_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 1024 Aug 27 12:00 iris-xr.rpm" run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"artifacts still present"* ]] || return 1
  [[ "$output" == *"iris-xr.rpm"* ]]
}

@test "live [echoing transport]: truncated after the executed start marker (rc 0) is a hard error, never absent" {
  # The transport dies right after the REAL app-table marker -- rc 0, no
  # end marker of its own, and no later section at all. The upfront
  # echoed-blob still contains a literal copy of the end marker's text (it
  # is part of what was piped in), so a plain substring check for that text
  # would wrongly conclude "found" and let this read as an absent app; only
  # a positional (last-end-after-last-start) check catches it.
  _xr_uninstall_echoing_stub_setup
  FAKE_TRUNCATE_AFTER_APPS=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"truncated before its end marker"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  count="$(printf '%s\n' "$log" | grep -c '=== CALL START ===')"
  [ "$count" -eq 1 ] || return 1
}

@test "live [echoing transport]: session 2/2's verify transport exiting nonzero (blob-only output) is a hard error, not clean" {
  # The sweep+verify request dies immediately, rc 124, having produced
  # nothing but the echoed upfront blob (no real APPS/SOURCES/FILES/DONE at
  # all) -- a wedged session under the session bound. This must never be
  # read as "clean": every verify_section call would otherwise be satisfied
  # from the blob's own empty-looking sections alone, declaring the device
  # torn down when nothing was actually checked.
  _xr_uninstall_echoing_stub_setup
  FAKE_VERIFY_RC=124 run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"undeploy verify's transport exited 124"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
}

# C1 from the whole-series review (2026-08-31), reproduced twice against the
# unmodified script: end_after_start() compares only marker POSITIONS, and the
# composed request itself contains START before END for every pair, so a
# transcript consisting of nothing but the transport's upfront echo satisfied
# every integrity guard. verify_section()'s matches[-1] then landed inside that
# same blob and returned the next TYPED line as the "section" ($FILES became
# the literal string `dir harddisk:`), every residue check read no-match as
# nothing-there, and the run exited 0 announcing a clean teardown with all
# seven destructive commands already sent.
#
# The premise is not exotic. Since the markers became `!` comments they emit no
# output of their own, so a marker only ever reaches the transcript via the pty
# echo -- the guards structurally cannot tell "the command ran" from "the
# command was refused". Any rc-0 session refused with wording other than
# `% Invalid input` collapses identically: TACACS+ "Command authorization
# failed.", XR "% This command is not authorized", an early session close.
@test "live [echoing transport]: an rc-0 session that echoed the request but executed nothing is a hard error" {
  _xr_uninstall_echoing_stub_setup
  FAKE_ECHO_ONLY=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  # It must NOT be read as "the app was already absent" -- that verdict is the
  # gateway to composing and sending the destructive session.
  if printf '%s\n' "$output" | grep -q 'already deactivated/absent'; then
    return 1
  fi
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
  [[ "$output" == *"returned no device output"* ]]
}

@test "live [echoing transport]: an echo-only rc-0 verify session never reports the device clean" {
  _xr_uninstall_echoing_stub_setup
  FAKE_ECHO_ONLY_VERIFY=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
  [[ "$output" == *"returned no device output"* ]]
}

@test "live [echoing transport]: session 2/2's verify truncated after the executed FILES marker (rc 0) is a hard error, not clean" {
  _xr_uninstall_echoing_stub_setup
  FAKE_TRUNCATE_AFTER_FILES=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"undeploy verify was truncated before its end marker"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Live-run-3 fix wave: a transcript whose markers arrive PROMPT-ECHOED
# ("RP/.../CPU0:host#! __MARKER__", the exact hardware evidence shape) must
# still parse correctly end to end -- both verify_section() and
# end_after_start() search for marker text as a substring anywhere in the
# captured blob, never anchored to a line start, so a prompt/`#!` prefix
# ahead of the marker on the same line must not break extraction.
# ---------------------------------------------------------------------------

@test "live: a transcript whose markers arrive prompt-echoed ('...#! __X__') still parses correctly" {
  _xr_uninstall_prompt_echoed_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  # the present-app row (itself embedded right after a prompt-echoed APPS
  # marker) was correctly extracted and deactivated exactly once -- proving
  # session 1's prompt-echoed APPS/DEACTIVATE sections parsed for real,
  # not just "didn't error".
  count="$(printf '%s\n' "$log" | grep -c '^no appmgr application iris$')"
  [ "$count" -eq 1 ] || return 1
}

# The D2-3 guard itself had no test: deleting the session-1 probe-rejection
# check kept the suite green while re-arming the exact incident the composite
# exists to prevent -- a rejected probe read as "app absent", deactivate
# skipped, the app left running while teardown reported success.
@test "live: a rejected session-1 probe is a hard error, never read as app absent" {
  _xr_uninstall_stub_setup
  FAKE_APP_ROW_1="% Invalid input detected at '^' marker." run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  if printf '%s\n' "$output" | grep -q 'already deactivated/absent'; then
    return 1
  fi
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
  [[ "$output" == *"probe was rejected"* ]]
}

@test "live: a rejected verify-side app-table read is a hard error, never read as app gone" {
  _xr_uninstall_stub_setup
  # index 1 probe clean, index 2 re-probe clean, index 3 (session 2's own
  # read) comes back rejected.
  FAKE_APP_ROW_3="% Invalid input detected at '^' marker." run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
  [[ "$output" == *"APPS read was rejected"* ]]
}

# Review finding (2026-08-31): xr_command_rejected was applied to the app table
# only. A refused `show appmgr source-table` or `dir harddisk:` therefore read
# as an EMPTY table -- which is exactly "nothing left" -- clearing five residue
# checks at once with an error message. Same D2-3 fail-open direction as the
# app-table case that was already guarded.
@test "live: a rejected appmgr source-table read is a hard error, never read as no sources" {
  _xr_uninstall_stub_setup
  FAKE_SOURCE_ROW="% Invalid input detected at '^' marker." run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
  [[ "$output" == *"SOURCES read was rejected"* ]]
}

@test "live: a rejected harddisk: listing is a hard error, never read as no files" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="% Invalid input detected at '^' marker." run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
  [[ "$output" == *"FILES read was rejected"* ]]
}

# The rejection vocabulary was one literal, `% Invalid input`. AAA command
# authorization is ordinary in production and refuses with entirely different
# wording, which sailed through as an empty table.
@test "live: a TACACS+ command-authorization refusal is recognized as a rejection" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Command authorization failed." run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
  [[ "$output" == *"rejected"* ]]
}

@test "live: an XR task-group authorization refusal is recognized as a rejection" {
  _xr_uninstall_stub_setup
  FAKE_SOURCE_ROW="% This command is not authorized" run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
  [[ "$output" == *"rejected"* ]]
}

@test "live: fails when the source is still listed after teardown" {
  _xr_uninstall_stub_setup
  FAKE_SOURCE_ROW="iris-xr  0.1.0  ThinXR_7.3.15" run _xr_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"artifacts still present"* ]] || return 1
  [[ "$output" == *"appmgr source iris-xr"* ]]
}

@test "live: fails when the rpm or work dir is still listed on harddisk:" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 1024 Aug 27 12:00 iris-xr.rpm" run _xr_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"iris-xr.rpm"* ]]
}

@test "live: verify fails closed when a marker section never comes back" {
  _xr_uninstall_stub_setup
  FAKE_VERIFY_OMIT_FILES=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"did not return the harddisk: file check"* ]]
}

@test "live: verify fails closed when the iris-work sub-listing marker never comes back" {
  _xr_uninstall_stub_setup
  FAKE_VERIFY_OMIT_WORKDIR=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"did not return the iris-work directory listing"* ]]
}

# ---------------------------------------------------------------------------
# Run-4 fix wave (hardware ruling, 2026-08-31): XR's CLI has no prompt-free
# directory removal (bare `delete /noprompt <dir>` does not remove a
# directory -- its earlier apparent "success" was against an already-gone
# path; `rmdir` prompts [y|n] and hangs; `rmdir /noprompt` is invalid
# syntax), so an iris-work that survives session 2's own empty-then-delete
# attempt may legitimately be empty, inert residue rather than a real
# leftover. [5/5]'s adjudication is now three-way: absent (clean, as
# always), present+nonempty (still FAIL, unchanged strictness),
# present+empty (accepted -- an explicit note is printed, teardown still
# converges).
# ---------------------------------------------------------------------------

@test "live: iris-work absent from harddisk: root is clean, no residue note printed" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'note: empty iris-work'; then
    return 1
  fi
}

@test "live: iris-work present and NONEMPTY still fails verify (unchanged strictness)" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 512 Aug 27 12:00 iris-work" \
    FAKE_WORKDIR_LISTING="Directory of harddisk:/iris-work
    12345 -rw-------.  1    100 Aug 27 12:00 leftover.txt

41968752 kbytes total (39714572 kbytes free)" \
    run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"artifacts still present"* ]] || return 1
  [[ "$output" == *"iris-work"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'note: empty iris-work'; then
    return 1
  fi
}

# Run-6 fix: the same NONEMPTY case, but with the FULL live session chrome
# around the real listing (prompt-echoed `dir` command, XR timestamp line,
# trailing prompt) -- proves workdir_has_entries()'s chrome-stripping does
# NOT over-filter a real entry row down to "empty". Entry line verbatim from
# the coordinator's fixture.
@test "live: iris-work present and NONEMPTY (with prompt/timestamp chrome) still fails verify" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 512 Aug 27 12:00 iris-work" \
    FAKE_WORKDIR_LISTING="RP/0/RP0/CPU0:8010-R4#dir harddisk:/iris-work
Mon Aug 31 13:51:50.123 UTC

Directory of harddisk:/iris-work
    655365 -rw-------. 1  21 Aug 31 12:17 iris-agent.state

41968752 kbytes total (39714572 kbytes free)
RP/0/RP0/CPU0:8010-R4#" \
    run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"artifacts still present"* ]] || return 1
  [[ "$output" == *"iris-work"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'note: empty iris-work'; then
    return 1
  fi
}

# Real hardware shape for a genuinely empty directory on this platform
# (captured live, run 5) -- the header alone is NOT what XR prints; it also
# carries an explicit "No files in directory" line and a kbytes-total
# footer, both of which an earlier version of workdir_has_entries()
# misread as real entries (false branch-b FAIL on a genuinely empty
# directory, live-reproduced run 5). This is the BARE listing, with no
# session chrome around it -- kept alongside the run-6 fixture below, which
# adds that chrome back.
@test "live: iris-work present but EMPTY is accepted as inert residue -- note printed, still converges" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 512 Aug 27 12:00 iris-work" \
    FAKE_WORKDIR_LISTING="Directory of harddisk:/iris-work
No files in directory

41968752 kbytes total (39714572 kbytes free)" \
    run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  [[ "$output" == *"note: empty iris-work directory left behind"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'artifacts still present'; then
    return 1
  fi
}

# Run-6 regression fixture, VERBATIM from the live session shape that still
# failed branch (b) after the run-5 fix: the run-5 fixture had already
# trimmed off the session chrome, so it never caught that the LIVE marker
# section also carries the prompt-echoed `dir` command line, XR's own
# timestamp line, and the trailing prompt -- all three misread as entries
# on a directory that was genuinely empty.
@test "live: iris-work present but EMPTY, full run-6 session chrome (prompt/timestamp/echoed command) is still accepted as inert residue" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 512 Aug 27 12:00 iris-work" \
    FAKE_WORKDIR_LISTING="RP/0/RP0/CPU0:8010-R4#dir harddisk:/iris-work
Mon Aug 31 13:51:50.123 UTC

Directory of harddisk:/iris-work
No files in directory

41968752 kbytes total (39714572 kbytes free)
RP/0/RP0/CPU0:8010-R4#" \
    run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  [[ "$output" == *"note: empty iris-work directory left behind"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'artifacts still present'; then
    return 1
  fi
}

@test "live: a rejected iris-work directory listing is a hard error, never read as empty" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 512 Aug 27 12:00 iris-work" \
    FAKE_WORKDIR_LISTING="% Invalid input detected" \
    run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"iris-work directory listing was rejected"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
}

# ---------------------------------------------------------------------------
# IMPORTANT 2: a router hostname that happens to CONTAIN the app id/source
# name (e.g. host "iris-lab-8010" while the app id is "iris") must not turn
# a genuinely empty appmgr table into a permanent false "present" via the
# XR exec prompt string (RP/0/RP0/CPU0:iris-lab-8010#) riding along in the
# same captured section. A real data row must still be detected correctly
# alongside that same prompt noise.
# ---------------------------------------------------------------------------

@test "live: a hostname containing the app id does not block an already-absent app forever" {
  _xr_uninstall_stub_setup
  FAKE_APP_ROW_1='RP/0/RP0/CPU0:iris-lab-8010#' run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"already deactivated/absent"* ]] || return 1
  [[ "$output" == *"undeploy complete"* ]]
}

@test "live: a real app row is still detected as present alongside hostname-prompt noise" {
  _xr_uninstall_stub_setup
  FAKE_APP_ROW_1='RP/0/RP0/CPU0:iris-lab-8010#
iris  docker  iris-xr  Up  app_manager' run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  count="$(printf '%s\n' "$log" | grep -c '^no appmgr application iris$')"
  [ "$count" -eq 1 ] || return 1
}

@test "live: hostname-prompt noise does not block [5/5]'s independent APPS/SOURCES check either" {
  # index 1 (session 1/2's early probe) sees a genuinely empty table (no
  # override) and converges normally; index 2 (session 2/2's own re-probe)
  # is the one carrying the hostname-prompt noise in BOTH its APPS and
  # SOURCES sections, proving the same fix covers [5/5]'s independent check,
  # not just the early probe.
  _xr_uninstall_stub_setup
  FAKE_APP_ROW_2='RP/0/RP0/CPU0:iris-xr-lab#' \
    FAKE_SOURCE_ROW='RP/0/RP0/CPU0:iris-xr-lab#' \
    run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]]
}

# ---------------------------------------------------------------------------
# ERE hygiene: APPID/SOURCE_NAME are operator-supplied overrides, not fixed
# literals -- table_contains() interpolates them into a grep -E pattern (the
# word-anchored match used for the early probe and [5/5]'s own re-check), so
# an override containing an ERE metacharacter must not widen what counts as
# a match. A literal '.' is the sharpest case: unescaped, it matches ANY
# character, so an APPID override of "iris.x" would otherwise treat an
# unrelated table row spelling "irisAx" as the app being present.
# ---------------------------------------------------------------------------

@test "live: an APPID override containing an ERE metacharacter does not loosen the present-match" {
  _xr_uninstall_stub_setup
  APPID='iris.x' FAKE_APP_ROW_1='irisAx  docker  iris-xr  Up  app_manager' \
    run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  # Correctly escaped: "iris.x" (literal dot) does NOT match a table row
  # spelling "irisAx" -- the early probe must read the app as absent, not
  # present, and log the idempotent-skip message. An unescaped '.' would
  # match "irisAx" (any-character wildcard), skipping this message and
  # proceeding as if the app were genuinely found present.
  [[ "$output" == *"already deactivated/absent"* ]] || return 1
  [[ "$output" == *"undeploy complete"* ]]
}

# ---------------------------------------------------------------------------
# MINOR 4: [5/5]'s FILES checks must be $-anchored per-line matches, not
# whole-blob substring tests -- an operator file that merely CONTAINS the
# target text (notes.aria2.bak for ".aria2";
# iris-workshop.txt for "iris-work") must never be flagged as a forbidden
# IRIS leftover forever.
# ---------------------------------------------------------------------------

@test "live: an operator file that merely contains a forbidden substring does not block verify forever" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 512 Aug 27 12:00 notes.aria2.bak
    12345 -rw-------. 1 root root 512 Aug 27 12:00 iris-workshop.txt" run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]]
}

# ---------------------------------------------------------------------------
# F1: undeploy must also sweep IRIS's own *.torrent/*.aria2/*.peers.json
# sidecars off the harddisk: root -- aria2 downloads straight there (no
# placement step on this platform), so they never land inside iris-work/.
#
# Fix-wave rewrite: the sweep used to list harddisk: root first (`run ls`)
# and hand `rm` one targeted bare name per match. That whole listing+match
# step is GONE -- native XR `delete /noprompt` evaluates harddisk: globs
# directly (hardware-proven: a verified-existing file was removed via
# `delete /noprompt harddisk:/*.torrent`), so the sweep is now three
# unconditional glob deletes, sent every time session 2 is composed at all.
# Selectivity (which files a glob actually touches) is now the device's own
# proven glob-evaluation behavior, not something this script's composed
# command list can demonstrate directly -- these tests instead pin that the
# three sanctioned globs are exactly what gets sent, with no listing step
# and no per-name targeting.
# ---------------------------------------------------------------------------

@test "dry-run describes the unconditional glob-based sidecar sweep of harddisk: root" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"delete /noprompt harddisk:/*.torrent"* ]] || return 1
  [[ "$output" == *"delete /noprompt harddisk:/*.aria2"* ]] || return 1
  [[ "$output" == *"delete /noprompt harddisk:/*.peers.json"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'run ls'; then
    return 1
  fi
}

@test "live: session 2 always composes the three sidecar glob deletes, never a listing or targeted name" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ]
  [[ "$output" == *"undeploy complete"* ]] || return 1
  second_call="$(_xr_call_body 2)"
  [[ "$second_call" == *"delete /noprompt harddisk:/*.torrent"* ]] || return 1
  [[ "$second_call" == *"delete /noprompt harddisk:/*.aria2"* ]] || return 1
  [[ "$second_call" == *"delete /noprompt harddisk:/*.peers.json"* ]] || return 1
  # session 1 (the only login that could have listed harddisk: root) never
  # ran `run ls` -- it no longer exists anywhere in this script.
  if printf '%s\n' "$(cat "$FAKE_COMMAND_LOG")" | grep -q 'run ls'; then
    return 1
  fi
}

@test "live: fails when a torrent sidecar is still listed on harddisk: after teardown" {
  _xr_uninstall_stub_setup
  FAKE_DIR_HARDDISK="Directory of harddisk:/
    12345 -rw-------. 1 root root 2048 Aug 27 12:00 8000-x64-26.2.1.iso.torrent" run _xr_uninstall_run_live
  [ "$status" -ne 0 ]
  [[ "$output" == *"artifacts still present"* ]] || return 1
  [[ "$output" == *"torrent"* ]]
}

@test "live: FORCE mode sends the identical command sequence as record-driven mode" {
  _xr_uninstall_stub_setup
  _xr_uninstall_run_live >/dev/null
  plain_log="$(cat "$FAKE_COMMAND_LOG")"
  : > "$FAKE_COMMAND_LOG"
  # Same probe-count reset _xr_uninstall_run_live does for the plain run
  # above -- the forced run below is invoked directly (it needs
  # IRIS_FORCE_AGENT_ONLY set), so it must reset its own counter too, or it
  # would inherit the plain run's leftover call index and see a different
  # FAKE_APP_ROW_<n> sequence than the plain run just did.
  rm -f "$BATS_TEST_TMPDIR/probe-count"
  env DEVICE_IP=192.0.2.10 DEVICE_USER=admin DEVICE_PASS=pw IRIS_FORCE_AGENT_ONLY=1 \
    bash "$STUBDIR/device/xr-uninstall.sh" >/dev/null
  forced_log="$(cat "$FAKE_COMMAND_LOG")"
  [ "$plain_log" = "$forced_log" ]
}
