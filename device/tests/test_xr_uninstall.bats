#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Tests for device/xr-uninstall.sh (agentinfo/plans/2026-08-28-xr-agent.md,
# Task 3): the receipt-driven inverse of device/xr-install.sh.
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

@test "dry-run's [1/5] describes the probe-first, retry-once, fail-closed shape" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"show appmgr application-table"* ]] || return 1
  [[ "$output" == *"already absent"* ]] || return 1
  [[ "$output" == *"retry deactivate once"* ]] || return 1
  [[ "$output" == *"fail-closed"* ]]
}

@test "xr-uninstall.sh never sends the invalid 'appmgr application summary' form" {
  [ -r "$UNINSTALL" ] || return 1
  count="$(grep -c 'application summary' "$UNINSTALL" || true)"
  [ "$count" -eq 0 ]
}

@test "FORCE dry-run and receipted dry-run touch the identical IRIS-named footprint" {
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
case "$cmds" in
  *"__IRIS_XR_VERIFY_APPS__"*)
    # xr-uninstall.sh now asks for the application-table marker from THREE
    # places against a single stub setup: step [1/5]'s initial probe, its
    # re-probe(s) after a deactivate attempt, and [5/5]'s final verify. A
    # call counter lets one test script "present, then absent" (deactivate
    # took) or "present every time" (deactivate never takes) across that
    # sequence via FAKE_APP_ROW_<n> (1-indexed); an index with no override
    # falls back to the flat FAKE_APP_ROW (itself defaulting to "" -- app
    # absent). FAKE_VERIFY_OMIT_APPS simulates a probe that never gets an
    # APPS section back at all (wedged/failed transport), independent of
    # FAKE_VERIFY_OMIT_FILES which only ever gated the final verify's FILES
    # section.
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      countfile="${BATS_TEST_TMPDIR:-.}/probe-count"
      n=0
      [ -f "$countfile" ] && n="$(cat "$countfile")"
      n=$((n + 1))
      printf '%s' "$n" > "$countfile"
      indexed_var="FAKE_APP_ROW_$n"
      row="$(eval "printf '%s' \"\${$indexed_var-\$FAKE_APP_ROW}\"")"
      echo "__IRIS_XR_VERIFY_APPS__"
      printf '%s\n' "$row"
      # probe_app_request() now asks for a trailing end marker too -- a
      # truncated-after-marker stream must be a hard error, never read as
      # absent. FAKE_VERIFY_OMIT_APPS_END drops just this line so a test
      # can simulate that truncation with the start marker/row intact.
      if [ "${FAKE_VERIFY_OMIT_APPS_END:-no}" != "yes" ]; then
        echo "__IRIS_XR_VERIFY_APPS_END__"
      fi
      # FAKE_PROBE_RC simulates the probe's own transport call dying with a
      # nonzero exit (e.g. rc 124 from Task 1's session bound) after
      # whatever partial output already made it out above.
      if [ -n "${FAKE_PROBE_RC:-}" ] && [ "${FAKE_PROBE_RC}" != "0" ]; then
        exit "$FAKE_PROBE_RC"
      fi
    fi
    echo "__IRIS_XR_VERIFY_SOURCES__"
    printf '%s\n' "${FAKE_SOURCE_ROW-}"
    if [ "${FAKE_VERIFY_OMIT_FILES:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_FILES__"
      printf '%s\n' "${FAKE_DIR_HARDDISK-Directory of harddisk:/}"
    fi
    ;;
  *"__IRIS_XR_VERIFY_SIDECARS__"*)
    echo "__IRIS_XR_VERIFY_SIDECARS__"
    printf '%s\n' "${FAKE_ROOT_LISTING-}"
    echo "__IRIS_XR_VERIFY_SIDECARS_END__"
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
case "$cmds" in
  *"__IRIS_XR_VERIFY_APPS__"*)
    if [ "${FAKE_VERIFY_OMIT_APPS:-no}" != "yes" ]; then
      countfile="${BATS_TEST_TMPDIR:-.}/probe-count"
      n=0
      [ -f "$countfile" ] && n="$(cat "$countfile")"
      n=$((n + 1))
      printf '%s' "$n" > "$countfile"
      indexed_var="FAKE_APP_ROW_$n"
      row="$(eval "printf '%s' \"\${$indexed_var-\$FAKE_APP_ROW}\"")"
      echo "__IRIS_XR_VERIFY_APPS__"
      printf '%s\n' "$row"
      if [ "${FAKE_VERIFY_OMIT_APPS_END:-no}" != "yes" ]; then
        echo "__IRIS_XR_VERIFY_APPS_END__"
      fi
    fi
    echo "__IRIS_XR_VERIFY_SOURCES__"
    printf '%s\n' "${FAKE_SOURCE_ROW-}"
    if [ "${FAKE_VERIFY_OMIT_FILES:-no}" != "yes" ]; then
      echo "__IRIS_XR_VERIFY_FILES__"
      printf '%s\n' "${FAKE_DIR_HARDDISK-Directory of harddisk:/}"
    fi
    ;;
  *"__IRIS_XR_VERIFY_SIDECARS__"*)
    echo "__IRIS_XR_VERIFY_SIDECARS__"
    printf '%s\n' "${FAKE_ROOT_LISTING-}"
    echo "__IRIS_XR_VERIFY_SIDECARS_END__"
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

@test "live: reports success once the app, source, and files are all gone" {
  _xr_uninstall_stub_setup
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ]
  [[ "$output" == *"undeploy complete"* ]]
}

@test "live: [1/5] probes app-table, deactivates once, and continues once the re-probe shows it gone" {
  _xr_uninstall_stub_setup
  FAKE_APP_ROW_1="iris  docker  iris-xr  Up  app_manager" run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  # deactivate was actually submitted -- exactly once, since the re-probe
  # (call 2, absent by the flat FAKE_APP_ROW fallback) already shows it gone
  count="$(printf '%s\n' "$log" | grep -c '^no appmgr application iris$')"
  [ "$count" -eq 1 ] || return 1
  [[ "$log" == *"appmgr package uninstall source iris-xr"* ]]
}

@test "live: a second run against an already-deactivated app logs already-absent and still converges" {
  _xr_uninstall_stub_setup
  # FAKE_APP_ROW left unset: the app is absent at every probe, modeling a
  # second run after a partial teardown (app already gone, rpm/work dir
  # possibly still present -- those steps keep their own || true tolerance).
  run _xr_uninstall_run_live
  [ "$status" -eq 0 ] || return 1
  [[ "$output" == *"already deactivated/absent"* ]] || return 1
  [[ "$output" == *"undeploy complete"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  if printf '%s\n' "$log" | grep -q '^no appmgr application iris$'; then
    return 1
  fi
}

@test "live: refuses to continue teardown when the app is still active after two deactivate attempts" {
  _xr_uninstall_stub_setup
  FAKE_APP_ROW="iris  docker  iris-xr  Up  app_manager" run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"refusing to continue teardown while application iris is still active"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  # exactly two deactivate submissions (the try, then the one retry) and
  # NOTHING from later steps -- teardown must stop dead, never uninstall
  # the source or rm files out from under a possibly-running app.
  count="$(printf '%s\n' "$log" | grep -c '^no appmgr application iris$')"
  [ "$count" -eq 2 ] || return 1
  if printf '%s\n' "$log" | grep -qE 'appmgr package uninstall source|run rm'; then
    return 1
  fi
}

@test "live: a deactivate probe transport failure is a hard error, never read as absent" {
  _xr_uninstall_stub_setup
  FAKE_VERIFY_OMIT_APPS=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"deactivate probe did not return the appmgr application-table"* ]] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  # fails closed on the very first probe -- no deactivate config was ever
  # submitted and no later step ran
  if printf '%s\n' "$log" | grep -qE 'no appmgr application iris|appmgr package uninstall source|run rm'; then
    return 1
  fi
}

@test "live: a probe transport that exits nonzero is a hard error, never read as absent" {
  _xr_uninstall_stub_setup
  FAKE_PROBE_RC=124 run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  # fails closed before any later step -- no deactivate config, no source
  # uninstall, no rm
  if printf '%s\n' "$log" | grep -qE 'no appmgr application iris|appmgr package uninstall source|run rm'; then
    return 1
  fi
}

@test "live: a probe truncated after its start marker (missing end marker) is a hard error, never absent" {
  _xr_uninstall_stub_setup
  FAKE_VERIFY_OMIT_APPS_END=yes run _xr_uninstall_run_live
  [ "$status" -ne 0 ] || return 1
  log="$(cat "$FAKE_COMMAND_LOG")"
  if printf '%s\n' "$log" | grep -qE 'no appmgr application iris|appmgr package uninstall source|run rm'; then
    return 1
  fi
}

@test "live: [5/5] still independently catches the app reappearing after a successful deactivate" {
  _xr_uninstall_stub_setup
  # call 1 (initial probe): present. call 2 (re-probe after deactivate):
  # absent -- deactivate is accepted as having worked and [1/5] proceeds.
  # call 3 (the final [5/5] verify's own app-table read): present again,
  # e.g. a flapping app -- [5/5]'s own independent check (unchanged by
  # this task) is still the last line of defense.
  FAKE_APP_ROW_1="iris  docker  iris-xr  Up  app_manager" \
    FAKE_APP_ROW_3="iris  docker  iris-xr  Up  app_manager" \
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

@test "live: FORCE mode sends the identical command sequence as receipted mode" {
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
