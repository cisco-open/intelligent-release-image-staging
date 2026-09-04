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

@test "copyroot applet phase 1 copies with a plain copy to the RESERVED TEMP NAME, never the real name directly (no /verify — agent owns the verdict)" {
  # Crash-safety fix (scrubber #82): phase 1 lands the copy at <IMG>.iris-tmp,
  # never at <IMG> itself — see the two negative "does NOT" assertions below
  # for the exact-line check that catches a regression to the old direct
  # shape (a loose substring match here would still pass against that old
  # shape, since it's a prefix of this one — that's exactly how this went
  # stale the first time).
  run grep -qF 'action 030 cli command "copy flash:/guest-share/iris/<IMG> flash:<IMG>.iris-tmp"' "$CFG"
  [ "$status" -eq 0 ]
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

@test "copyroot applet phase 1 deletes any stale leftover at the TEMP NAME before the copy, never the real name" {
  # presence at the temp name is phase 1's verdict input, so a stale leftover
  # there must be cleared first — otherwise the agent's `dir` poll could bless
  # debris an earlier attempt left rather than bytes THIS copy wrote. `file
  # prompt quiet` (device-install.sh) suppresses the prompt. Crash-safety fix
  # (scrubber #82): this delete targets <IMG>.iris-tmp, which can never be the
  # running image or the BOOT target — <IMG> itself is never deleted by
  # either phase (see the two negative "does NOT" assertions below).
  run grep -qF 'action 020 cli command "delete /force flash:<IMG>.iris-tmp"' "$CFG"
  [ "$status" -eq 0 ]
}

@test "copyroot applet does NOT delete the real name directly (crash-safety fix, scrubber #82 — DO NOT regress)" {
  # The OLD one-phase shape deleted <IMG> itself before proving the copy,
  # which could leave a BOOT-named destination with nothing to boot on a copy
  # failure or power loss. Exact-line match (including the closing quote)
  # so a temp-suffixed delete line does NOT satisfy this — a bare substring
  # check would still match the new shape too, which is exactly how this
  # regression escaped the suite the first time.
  run grep -qF 'action 020 cli command "delete /force flash:<IMG>"' "$CFG"
  [ "$status" -ne 0 ]
}

@test "copyroot applet does NOT copy directly onto the real name (crash-safety fix, scrubber #82 — DO NOT regress)" {
  # Companion to the delete check above: the OLD shape's copy landed straight
  # on <IMG>. Exact-line match (including the closing quote) so the new
  # temp-suffixed copy line does NOT satisfy this.
  run grep -qF 'action 030 cli command "copy flash:/guest-share/iris/<IMG> flash:<IMG>"' "$CFG"
  [ "$status" -ne 0 ]
}

@test "copyroot applet phase 2 places the proven copy with a single rename over the real name" {
  # The ONLY command in either phase that ever touches <IMG> itself, fired
  # only once phase 1's temp copy is reverified (a directory-entry update,
  # not a data transfer — see the file's TRUST BOUNDARY comment).
  run grep -qF 'action 020 cli command "rename flash:<IMG>.iris-tmp flash:<IMG>"' "$CFG"
  [ "$status" -eq 0 ]
}

@test "copyroot applet is redefined between phase 1 and phase 2 (two-phase sequence, not one applet with extra actions)" {
  # Each phase's cli_configure block starts with `no event manager applet
  # IRIS-COPYROOT` so the second definition fully REPLACES the first rather
  # than appending to it (phase 2 has fewer actions than phase 1). One `no`
  # per phase; both phases share the applet name so the uninstall scripts'
  # `no event manager applet IRIS-COPYROOT` keeps covering it unchanged.
  # Non-comment lines only — the comment block above also mentions the `no`
  # form in prose.
  run bash -c "grep -v '^!' '$CFG' | grep -cF 'no event manager applet IRIS-COPYROOT'"
  [ "$status" -eq 0 ] && [ "$output" -eq 2 ]
}

@test "copyroot applet phase 1 syslog is a NEUTRAL breadcrumb, not a verdict" {
  # The applet makes NO pass/fail claim — a syslog action fires regardless of
  # exit code, so an in-applet verdict can't be trusted. The agent owns the
  # verdict via `dir` presence + exact catalog byte size after the plain copy.
  grep -qF 'syslog msg "ROOTCOPY-ATTEMPTED <IMG>"' "$CFG"
}

@test "copyroot applet phase 2 syslog is also a NEUTRAL breadcrumb, not a verdict" {
  # Same contract as phase 1's breadcrumb above: phase 2's rename makes no
  # pass/fail claim either. The agent's reverify of the real name afterwards
  # is the actual verdict, regardless of whether the rename itself raised.
  run grep -qF 'action 030 syslog msg "ROOTCOPY-PLACED <IMG>"' "$CFG"
  [ "$status" -eq 0 ]
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
  run env DEVICE_IP=203.0.113.3 VLAN=666 SVI_IP=203.0.113.125 SVI_MASK=255.255.255.252 \
    GUEST_IP=203.0.113.126 CATALOG_URL=https://192.0.2.10:8443 CATALOG_TOKEN=deadbeef \
    DEVICE_ID=203.0.113.3 STAGE_HOST=192.0.2.10 bash "$DIR/device-install.sh" --dry-run
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
