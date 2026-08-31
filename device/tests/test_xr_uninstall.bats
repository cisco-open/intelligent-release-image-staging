#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for device/xr-uninstall.sh (agentinfo/plans/2026-08-28-xr-agent.md,
# Task 3): the record-driven inverse of device/xr-install.sh.
#
# Teardown-speed composite (agentinfo/specs/2026-08-31-xr-teardown-speed.md
# section 2A): the per-step design that made 6-11 separate lab/xr-run.sh
# logins per teardown collapsed into TWO bounded logins -- session 1/2
# ("setup": early probe, unconditional deactivate, unconditional source
# uninstall, unconditional file rm, sidecar listing) and session 2/2
# ("sweep+verify": sidecar sweep for whatever session 1 actually listed, then
# the final three-way verify). Two, not one: the sidecar sweep needs session
# 1's own `ls` result to know which bare paths to hand `rm` (never a glob),
# and there is no interactive transport to react to a login's output before
# it ends -- see the long design comment at the top of xr-uninstall.sh for
# the full justification (this is a structural constraint the recon flagged
# as unresolved, not a benign-error one, and lab/xr-run.sh is out of this
# script's own scope to make interactive).
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

@test "dry-run removes only the two IRIS-named files, via run rm" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"run rm -f /misc/disk1/iris-xr.rpm"* ]] || return 1
  [[ "$output" == *"run rm -rf /misc/disk1/iris-work"* ]]
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
  [[ "$output" == *"run rm -f /misc/disk1/probe-xr.rpm"* ]]
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

@test "xr-uninstall.sh never sends the invalid 'appmgr application summary' form" {
  [ -r "$UNINSTALL" ] || return 1
  count="$(grep -c 'application summary' "$UNINSTALL" || true)"
  [ "$count" -eq 0 ]
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
              "run rm -f /misc/disk1/iris-xr.rpm" "run rm -rf /misc/disk1/iris-work"; do
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
# ("setup") is the request that carries the SIDECARS marker (unique to it --
# session 2/2 never lists the sidecar directory again); session 2/2
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
  *"__IRIS_XR_VERIFY_SIDECARS__"*)
    # session 1/2 (setup): APPS (early probe) -> DEACTIVATE -> SIDECARS.
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      row="$(next_app_row)"
      echo "__IRIS_XR_VERIFY_APPS__"
      printf '%s\n' "$row"
      # FAKE_VERIFY_OMIT_APPS_END simulates a probe truncated right after
      # its start marker + row -- a hard error, never read as absent.
      if [ "${FAKE_VERIFY_OMIT_APPS_END:-no}" != "yes" ]; then
        echo "__IRIS_XR_VERIFY_APPS_END__"
      fi
      # FAKE_PROBE_RC simulates the transport dying with a nonzero exit
      # (e.g. rc 124, the session-bound timeout) after whatever partial
      # output already made it out above -- before DEACTIVATE/SIDECARS.
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
    echo "__IRIS_XR_VERIFY_SIDECARS__"
    printf '%s\n' "${FAKE_ROOT_LISTING-}"
    echo "__IRIS_XR_VERIFY_SIDECARS_END__"
    ;;
  *"__IRIS_XR_VERIFY_FILES__"*)
    # session 2/2 (sweep+verify): APPS (final re-probe) -> SOURCES -> FILES -> DONE.
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      row="$(next_app_row)"
      echo "__IRIS_XR_VERIFY_APPS__"
      printf '%s\n' "$row"
    fi
    echo "__IRIS_XR_VERIFY_SOURCES__"
    printf '%s\n' "${FAKE_SOURCE_ROW-}"
    if [ "${FAKE_VERIFY_OMIT_FILES:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_FILES__"
      printf '%s\n' "${FAKE_DIR_HARDDISK-Directory of harddisk:/}"
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
  *"__IRIS_XR_VERIFY_SIDECARS__"*)
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      row="$(next_app_row)"
      echo "__IRIS_XR_VERIFY_APPS__"
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
    echo "__IRIS_XR_VERIFY_SIDECARS__"
    printf '%s\n' "${FAKE_ROOT_LISTING-}"
    echo "__IRIS_XR_VERIFY_SIDECARS_END__"
    ;;
  *"__IRIS_XR_VERIFY_FILES__"*)
    if [ -n "${FAKE_VERIFY_RC:-}" ] && [ "${FAKE_VERIFY_RC}" != "0" ]; then
      # "blob-only output": nothing real is ever produced -- the echoed
      # upfront blob (already printed above) is ALL this call returns
      # before the transport itself dies.
      exit "$FAKE_VERIFY_RC"
    fi
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      row="$(next_app_row)"
      echo "__IRIS_XR_VERIFY_APPS__"
      printf '%s\n' "$row"
    fi
    echo "__IRIS_XR_VERIFY_SOURCES__"
    printf '%s\n' "${FAKE_SOURCE_ROW-}"
    if [ "${FAKE_VERIFY_OMIT_FILES:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_FILES__"
      printf '%s\n' "${FAKE_DIR_HARDDISK-Directory of harddisk:/}"
    fi
    # FAKE_TRUNCATE_AFTER_FILES simulates the transport dying (rc 0) right
    # after the REAL FILES section -- before its own DONE marker. The
    # echoed upfront blob still has a literal copy of DONE's text, so only
    # the positional (last-DONE-after-last-FILES) check catches this.
    if [ "${FAKE_TRUNCATE_AFTER_FILES:-no}" = "yes" ]; then
      exit 0
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

_xr_uninstall_run_live() {
  # Fresh probe-call counter per script invocation -- two separate runs
  # against the same stub setup (the FORCE parity test below) must each see
  # call index 1 on their own first application-table probe, not inherit
  # the previous run's count.
  rm -f "$BATS_TEST_TMPDIR/probe-count"
  env DEVICE_IP=192.0.2.10 DEVICE_USER=admin DEVICE_PASS=pw \
    bash "$STUBDIR/device/xr-uninstall.sh"
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
  log="$(cat "$FAKE_COMMAND_LOG")"
  [[ "$log" == *"show appmgr application-table"* ]] || return 1
  if printf '%s\n' "$log" | grep -q 'application summary'; then
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
  if printf '%s\n' "$log" | grep -qE 'appmgr package uninstall source|run rm -f /misc/disk1/iris-xr\.rpm'; then
    : # source-uninstall/rm DO ride the same unconditional session 1/2 login
      # as deactivate (recon table rows 2-3, unchanged best-effort) -- this
      # branch intentionally does not fail the test on their presence.
  fi
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
  # index 1 (session 1/2's early probe): present. deactivate is not
  # rejected (default), so the run proceeds to session 2/2. index 2
  # (session 2/2's own re-probe) is ALSO present -- e.g. a flapping app --
  # [5/5]'s own independent check (unchanged by this task) is still the
  # last line of defense.
  FAKE_APP_ROW_1="iris  docker  iris-xr  Up  app_manager" \
    FAKE_APP_ROW_2="iris  docker  iris-xr  Up  app_manager" \
    run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"artifacts still present"* ]] || return 1
  [[ "$output" == *"appmgr application iris"* ]]
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

@test "live [echoing transport]: the sidecar sweep still issues its rm commands" {
  _xr_uninstall_echoing_stub_setup
  FAKE_ROOT_LISTING="8000-x64-26.2.1.iso
8000-x64-26.2.1.iso.torrent
notes.txt
iris-work" run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  [[ "$log" == *"run rm -f /misc/disk1/8000-x64-26.2.1.iso.torrent"* ]]
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

@test "live [echoing transport]: session 2/2's verify truncated after the executed FILES marker (rc 0) is a hard error, not clean" {
  _xr_uninstall_echoing_stub_setup
  FAKE_TRUNCATE_AFTER_FILES=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"undeploy verify was truncated before its end marker"* ]] || return 1
  if printf '%s\n' "$output" | grep -q 'undeploy complete'; then
    return 1
  fi
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
# MINOR 4: [5/5]'s FILES checks must be $-anchored per-line matches (the
# sidecar sweep's own shape), not whole-blob substring tests -- an operator
# file that merely CONTAINS the target text (notes.aria2.bak for ".aria2";
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
# ---------------------------------------------------------------------------

@test "dry-run describes a glob-free sidecar sweep of harddisk: root" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"run ls -1 /misc/disk1"* ]] || return 1
  if printf '%s\n' "$output" | grep -F 'run rm' | grep -q '[*?]'; then
    return 1
  fi
}

@test "live: sweeps torrent/aria2/peers.json sidecars but leaves operator files and the image alone" {
  _xr_uninstall_stub_setup
  FAKE_ROOT_LISTING="8000-x64-26.2.1.iso
8000-x64-26.2.1.iso.torrent
8000-x64-26.2.1.iso.aria2
8000-x64-26.2.1.iso.peers.json
notes.txt
iris-work" run _xr_uninstall_run_live
  [ "$status" -eq 0 ]
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  [[ "$log" == *"run rm -f /misc/disk1/8000-x64-26.2.1.iso.torrent"* ]] || return 1
  [[ "$log" == *"run rm -f /misc/disk1/8000-x64-26.2.1.iso.aria2"* ]] || return 1
  [[ "$log" == *"run rm -f /misc/disk1/8000-x64-26.2.1.iso.peers.json"* ]] || return 1
  if printf '%s\n' "$log" | grep -q 'run rm -f /misc/disk1/notes.txt'; then
    return 1
  fi
  if printf '%s\n' "$log" | grep -qFx 'run rm -f /misc/disk1/8000-x64-26.2.1.iso'; then
    return 1
  fi
}

@test "live: no sidecar-removal call is made when nothing at root needs sweeping" {
  _xr_uninstall_stub_setup
  FAKE_ROOT_LISTING="notes.txt
iris-work" run _xr_uninstall_run_live
  [ "$status" -eq 0 ]
  log="$(cat "$FAKE_COMMAND_LOG")"
  if printf '%s\n' "$log" | grep -q 'run rm -f /misc/disk1/notes.txt'; then
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
