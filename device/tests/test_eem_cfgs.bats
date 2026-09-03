#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

DIR="$BATS_TEST_DIRNAME/.."
CFG="$DIR/eem-iris-copyroot.cfg"

# NOTE: keep ONE assertion per @test. Bats only checks the LAST command's exit
# status, so multiple `[[ ]]` in a single @test silently pass even when earlier
# ones fail. We use `grep -qE` / `grep -qF` so each assertion's exit code IS the
# @test's exit code. The old version of this file had four `[[ ]]` in one @test
# checking obsolete patterns (event syslog pattern, IRIS-6-DONE, regexp) that no
# longer existed in the cfg — it false-passed because the LAST assertion (the
# only one still valid) happened to be true.

@test "copyroot applet uses event none + maxrun 900 (event syslog/\$_arg1 are HW-unreliable on 17.18)" {
  grep -qE 'event none maxrun 900' "$CFG"
}

@test "copyroot applet has authorization bypass (AAA nodes silently no-op without it)" {
  grep -qF 'event manager applet IRIS-COPYROOT authorization bypass' "$CFG"
}

@test "copyroot applet copies with a plain copy (no /verify — agent owns the verdict)" {
  grep -qE 'copy flash:/guest-share/iris/<IMG> flash:<IMG>' "$CFG"
}

@test "copyroot applet never invokes ANY verify command in an action" {
  # Broader than the /verify guard below: no applet ACTION may run `verify`
  # in any form — not `verify /sha512`, not a bare `verify`, not a future
  # variant. The agent (_agent_reverify_root) is the sole author of the
  # verdict, and nothing on the box re-hashes the placed copy. This is the
  # assertion the pre-rewrite suite carried; keep both.
  ! grep -qE 'cli command "verify' "$CFG"
}

@test "copyroot applet never runs /verify — the agent is the sole author of the verdict" {
  # The applet makes NO verification claim of its own: no `copy /verify`, no
  # `verify` command at all. The agent (_agent_reverify_root) is the sole
  # author of the verdict, via `dir` presence + an exact byte-size match
  # against the catalog. Permanent regression guard — do not let /verify back
  # into an applet ACTION. Check non-comment lines only — the comment block
  # legitimately documents the absence of /verify in prose.
  ! grep -v '^!' "$CFG" | grep -qE '/verify'
}

@test "copyroot applet deletes any stale leftover BEFORE the copy" {
  # presence is the verdict, so a stale same-named file must be cleared first —
  # otherwise the agent's `dir` poll could bless a leftover this copy never
  # wrote. `file prompt quiet` (device-install.sh) suppresses the prompt.
  grep -qE 'delete /force flash:<IMG>' "$CFG"
}

@test "copyroot applet syslog is a NEUTRAL breadcrumb, not a verdict" {
  # The applet makes NO pass/fail claim — a syslog action fires regardless of
  # exit code, so an in-applet verdict can't be trusted. The agent owns the
  # verdict via `dir` presence + exact catalog byte size after the plain copy.
  grep -qF 'syslog msg "ROOTCOPY-ATTEMPTED <IMG>"' "$CFG"
}

@test "copyroot applet does NOT capture a self-blessed verdict (dead \$_ok/regexp removed)" {
  # Regression guard: the syslog-verdict machinery (set _ok / regexp / \$_ok)
  # was dead code (nothing read the line). It must not come back.
  ! grep -qE 'regexp|_ok' "$CFG"
}

@test "copyroot applet action does NOT contain the obsolete '+ verified' claim" {
  # Regression guard for the C1 review finding: no applet ACTION may claim the
  # file was verified. Only the agent (after _agent_reverify_root) does. Check
  # non-comment lines only — the comment block legitimately documents the
  # agent's success-log wording.
  ! grep -v '^!' "$CFG" | grep -qF 'placed at flash root + verified'
}

@test "copyroot applet does NOT rely on the HW-broken event syslog trigger" {
  ! grep -qE 'event syslog pattern' "$CFG"
}

@test "copyroot applet does NOT rely on \$_arg1 (does not populate on 17.18)" {
  # check only non-comment lines — the cfg's comment block intentionally
  # mentions $_arg1 as historical context for WHY the trigger pattern changed.
  ! grep -v '^!' "$CFG" | grep -qF '$_arg1'
}

@test "agent timer applet uses event timer watchdog" {
  grep -qE 'event timer watchdog' "$DIR/eem-iris-agent.cfg"
}

@test "agent timer applet has authorization bypass (AAA nodes silently no-op without it)" {
  grep -qF 'authorization bypass' "$DIR/eem-iris-agent.cfg"
}

@test "agent timer applet sets maxrun 900 (matches the installed applet)" {
  grep -qE 'maxrun 900' "$DIR/eem-iris-agent.cfg"
}

@test "agent timer applet runs bootstrap.sh in Guest Shell (the action, not the comment)" {
  # The former assertion grepped 'iris_agent.py --once', which only the prose
  # comment satisfies: the applet runs bootstrap.sh, which execs the agent.
  # Assert the ACTION on non-comment lines so deleting it fails the suite.
  grep -v '^!' "$DIR/eem-iris-agent.cfg" \
    | grep -qF 'action 200 cli command "guestshell run bash /flash/guest-share/bootstrap.sh"'
}

@test "agent timer applet reference equals the block device-install.sh installs" {
  # device-install.sh is documented to mirror this file; compare the applet
  # block structurally (non-comment lines) against a routed dry-run.
  ref="$(grep -v '^!' "$DIR/eem-iris-agent.cfg" | sed '/^[[:space:]]*$/d')"
  run env DEVICE_IP=100.92.9.3 VLAN=666 SVI_IP=100.92.9.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=100.92.9.126 CATALOG_URL=https://100.90.168.20:8443 CATALOG_TOKEN=deadbeef \
    DEVICE_ID=100.92.9.3 STAGE_HOST=100.90.168.20 bash "$DIR/device-install.sh" --dry-run
  [ "$status" -eq 0 ] || return 1
  installed="$(printf '%s\n' "$output" | sed -n '/^event manager applet IRIS-AGENT/,/^!/p' | sed '/^!/d')"
  [ "$ref" = "$installed" ]
}

@test "bundle reclaim applet uses authorization bypass + event none" {
  grep -qF 'event manager applet IRIS-RECLAIM-BUNDLE authorization bypass' "$DIR/eem-iris-reclaim-bundle.cfg"
}

@test "bundle reclaim applet deletes via delete /force" {
  grep -qE 'delete /force ' "$DIR/eem-iris-reclaim-bundle.cfg"
}

@test "bundle reclaim applet never runs install remove inactive (check non-comment lines)" {
  # check only non-comment lines — the cfg's comment block legitimately
  # documents WHY `install remove inactive` does not apply in bundle mode. No
  # applet ACTION may invoke it. (Same comment-filtering pattern as the
  # copyroot $_arg1 / '+ verified' guards above; one assertion per @test so the
  # exit code is the verdict.)
  ! grep -v '^!' "$DIR/eem-iris-reclaim-bundle.cfg" | grep -qF 'install remove inactive'
}
