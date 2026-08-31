# server/tests/test_terminology.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Retired-vocabulary guard (terminology rename, spec 2026-08-30).

The rename retired `attachment`/`network_attachment` (-> management type),
deployment `receipt` (-> deployment record), and peer `receipt` (-> peer
transfer record) everywhere except a short, explicit set of fenced sites
(RFC 6266, an IOS logging discriminator, a CSV rejection guard, the
time-of-receipt sense of "receipt", append-only history, and a handful of
deliberate hard-break regression pins). This test scans every TRACKED file
(``git ls-files`` -- untracked/ignored paths such as HANDOFF.md and
skills-lock.json are excluded by construction, no allowlist entry needed)
for the retired vocabulary and fails on anything not covered by the
ALLOWLIST below. This file's own path is also excluded from the scan (see
_SELF_PATH / _tracked_files) -- its ALLOWLIST reasons and docstrings must
NAME the retired words to justify excluding them, so it would otherwise
self-trip on every one of its own comments.

Scan design: `network_attachment` and `NETWORK_ATTACHMENT` are, case-
insensitively, a strict substring of the word `attachment` -- every
occurrence of either is necessarily also an "attachment" hit -- so two
compiled regexes (`attachment`, `receipt`, both case-insensitive) cover all
four terms the rename plan names. One `git ls-files` call plus one read per
tracked file keeps this fast; there is no per-term re-scan.

ALLOWLIST entries are ``(path, lines, reason)``:
  path   -- repo-relative, exactly as `git ls-files` reports it
  lines  -- ``None`` to allowlist the WHOLE file (used once, for
            CHANGELOG.md's append-only history -- decision 4), or a
            frozenset of the 1-based line numbers where a hit is expected
  reason -- why this specific occurrence is retired vocabulary but not a
            violation; cites the spec decision or task where it was decided

A companion test (test_terminology_allowlist_entries_are_still_needed)
keeps this list honest: every entry must still point at a real hit, an
existing path, and (for line entries) an in-range line number, so a stale
entry left behind by a later refactor fails loudly instead of silently
widening the guard's blind spot.
"""

import os
import re
import subprocess

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

_PATTERNS = {
    "attachment": re.compile(r"attachment", re.IGNORECASE),
    "receipt": re.compile(r"receipt", re.IGNORECASE),
}

ALLOWLIST = [
    # -- decision 4: append-only history -------------------------------
    ("CHANGELOG.md", None,
     "append-only history (decision 4): old released entries keep their "
     "original wording verbatim, and the rename's own Unreleased entry "
     "narrates the change using both the old and new vocabulary by design"),

    # -- decision 5 hard exclusions: RFC / IOS / CSV-guard sites -------
    ("server/gui_server.py", frozenset({1240, 1248}),
     "Content-Disposition: attachment (RFC 6266) on the CSV export/example "
     "download headers -- hard exclusion, decision 5"),
    ("device/device-uninstall.sh", frozenset({19}),
     "IOS logging-discriminator \"attachments\" (EXPLICIT-name no-forms) -- "
     "hard exclusion, decision 5"),
    ("tools/gen-device-installers.sh", frozenset({26}),
     "network_attachment CSV-header REJECTION guard arm for legacy operator "
     "CSVs -- hard exclusion, decision 5 (this is the guard that refuses a "
     "v2 CSV outside Console/API onboarding, not the removed import alias)"),

    # -- decision 5 Family C: time-of-receipt sense, not the retired ---
    # -- peer-receipt/deployment-receipt identifiers -------------------
    ("server/live_samples.py", frozenset({26, 258, 270, 314, 348}),
     "time-of-receipt sense (spec section 3A/3B/4/10.1c) -- hard exclusion, "
     "decision 5"),
    ("server/telemetry.py", frozenset({1647, 1849, 1910}),
     "time-of-receipt sense (spec section 3B/4) -- hard exclusion, decision 5"),
    ("server/tests/test_docs_map.py", frozenset({242}),
     "time-of-receipt sense (\"the server stamps it on receipt\") -- hard "
     "exclusion, decision 5"),
    ("server/tests/test_telemetry_v2_ingest.py", frozenset({9, 204, 237, 316}),
     "time-of-receipt sense (validity keyed off the last OBSERVED receipt), "
     "Family C -- hard exclusion, decision 5"),
    ("docs/zensical/observability.md", frozenset({78}),
     "time-of-receipt sense (\"stamped at ingest by the server on receipt\") "
     "-- hard exclusion, decision 5"),
    ("docs/zensical/dashboards/splunk-iris-swarm.xml", frozenset({643}),
     "time-of-receipt sense (\"_time is the SERVER's receipt clock\") -- "
     "hard exclusion, decision 5"),

    # -- Task 2: six deliberate NETWORK_ATTACHMENT stale-wrapper -------
    # -- tripwires, and the bats pins that exercise each one -----------
    ("device/device-install.sh", frozenset({34, 35}),
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire -- fires only "
     "when an old install wrapper still exports the retired env var "
     "(Task 2 review)"),
    ("device/device-uninstall.sh", frozenset({54, 55}),
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review)"),
    ("device/router-install.sh", frozenset({17, 18}),
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review)"),
    ("device/router-uninstall.sh", frozenset({13, 14}),
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review)"),
    ("device/iox/install.sh", frozenset({49, 50}),
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review)"),
    ("device/iox/uninstall.sh", frozenset({43, 44}),
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review)"),
    ("device/tests/test_device_install.bats", frozenset({27, 28, 30}),
     "pins device-install.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/tests/test_device_uninstall.bats", frozenset({20, 21, 23}),
     "pins device-uninstall.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/tests/test_router_install.bats", frozenset({15, 16, 18}),
     "pins router-install.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/tests/test_router_uninstall.bats", frozenset({13, 14, 16}),
     "pins router-uninstall.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/iox/tests/test_iox_install_output.bats", frozenset({46, 47, 49}),
     "pins iox/install.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/iox/tests/test_iox_uninstall.bats", frozenset({19, 20, 22}),
     "pins iox/uninstall.sh's NETWORK_ATTACHMENT tripwire message"),

    # -- decision 1: the removed network_attachment CSV/read alias -----
    ("server/gui_fleet.py", frozenset({397}),
     "developer comment explaining the retired network_attachment CSV "
     "header alias is gone (decision 1) -- historical context, not live code"),
    ("server/tests/test_gui_fleet.py", frozenset({620, 621, 628}),
     "deliberate hard-break pin: a CSV using the retired network_attachment "
     "v2 header is rejected like any other unrecognized header (decision 1)"),
    ("server/tests/test_gui_fleet.py", frozenset({636, 637, 648, 652}),
     "deliberate hard-break pin: the removed network_attachment read-alias "
     "no longer classifies a fleet.json row (decision 1)"),
    ("server/tests/test_gui_server.py", frozenset({2363, 2368, 2384}),
     "deliberate hard-break pin: a fleet row carrying only the retired "
     "network_attachment alias plans as unclassified, not migrated "
     "(decision 1)"),
    ("server/tests/test_gui_server.py", frozenset({2398, 2400, 2411}),
     "deliberate hard-break pin: same alias-retirement boundary on the "
     "xr-appmgr/xr-host mutual-requirement side (decision 1)"),

    # -- Task 2 / decision 6: docstrings that name the pre-fix silent --
    # -- default a regression test guards against (historical prose) --
    ("server/tests/test_gui_server.py", frozenset({2458}),
     "docstring names the pre-fix silent default (falling through as "
     "attachment=None) this regression test guards against -- historical, "
     "Task 2 / decision 6"),
    ("server/tests/test_gui_server.py", frozenset({7125, 7136, 7137, 7140}),
     "deliberate hard-break pin: asserts app.js's deployRecordRows reads "
     "res.management_type and never falls back to the retired res.attachment "
     "(decision 6); line numbers shifted +1 by Wave C's unrelated edits "
     "earlier in this file (setup-status packages.items test); the pinned "
     "line is historical prose describing the pre-fix rendering this test "
     "guards against"),
    ("server/tests/test_gui_onboard.py", frozenset({319}),
     "docstring names the pre-fix silent default (_build_env used to "
     "default a missing attachment/management_type to \"routed\") this "
     "regression test guards against -- historical, Task 2 / decision 6"),
    ("server/tests/test_gui_onboard.py", frozenset({1437, 1440}),
     "docstring names the pre-fix three-level fallback chain "
     "(attachment -> management_type -> network_attachment) this "
     "regression test guards against -- historical, Task 2 / decision 6"),

    # -- declared break 7 family: receipt_id -> record_id on wire --------
    # -- responses (break 8 is the separate audit-detail-string wording) --
    ("server/tests/test_gui_server.py", frozenset({2625, 2630, 2643, 2649}),
     "deliberate hard-break pin: asserts the retired receipt_id key never "
     "leaks onto the onboard-job-status wire response (declared break 7's "
     "response-object family; NOT break 8, which is audit-string wording)"),

    # -- declared break 6: old-agent peer_receipts compatibility -------
    ("server/tests/test_catalog.py", frozenset({2118, 2119, 2126, 2129}),
     "deliberate hard-break pin: an old, not-yet-redeployed agent's stale "
     "peer_receipts key is dropped silently, not rejected (declared break 6)"),

    # -- Task 6: CSS property name, not the retired business term ------
    # Line number moved from 425 (Task 6) to 491 (Task 7) to 497 (Task 8) to
    # 538 (Task 9, --scroll-fade parameterization) to 542 (Wave A Magnetic
    # table-fidelity fixes: type roles, right-align, divergence comment) to
    # 578 when Wave B's left-nav fixes (icons, divider, on-grid indent,
    # flyout submenus, compact-anatomy comment) added lines above it to 593
    # when Wave E's flyout-indent review fix added its own comment+rule
    # above it -- same property, re-pinned at its new location.
    ("server/webroot/styles.css", frozenset({593}),
     "the CSS `background-attachment` property (Task 6's .table-scroll "
     "scroll-shadow gradients) -- unrelated to the retired attachment "
     "vocabulary, hard exclusion"),
]


_SELF_PATH = os.path.relpath(__file__, REPO).replace(os.sep, "/")


def _tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO,
                         capture_output=True, check=True)
    names = out.stdout.decode("utf-8", "surrogateescape").split("\0")
    # Exclude this guard's own path: its ALLOWLIST reasons, docstrings, and
    # _PATTERNS necessarily NAME the retired words to explain/justify what
    # they exclude, so scanning itself would self-trip on every one of them.
    return [n for n in names if n and n != _SELF_PATH]


def _allowlist_index():
    """-> (set of whole-file paths, {path: set(allowlisted line numbers)})."""
    whole = set()
    by_line = {}
    for path, lines, _reason in ALLOWLIST:
        if lines is None:
            whole.add(path)
        else:
            by_line.setdefault(path, set()).update(lines)
    return whole, by_line


def _iter_hits():
    """Yield (path, lineno, term, matched_text, line) for every retired-
    vocabulary occurrence in a tracked file that is not allowlisted."""
    whole, by_line = _allowlist_index()
    for path in _tracked_files():
        if path in whole:
            continue
        try:
            with open(os.path.join(REPO, path), "r", encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue          # binary or unreadable; not a vocabulary source
        allowed = by_line.get(path, ())
        for lineno, line in enumerate(text.splitlines(), start=1):
            if lineno in allowed:
                continue
            for term, pattern in _PATTERNS.items():
                m = pattern.search(line)
                if m:
                    yield path, lineno, term, m.group(0), line.strip()


def test_retired_vocabulary_guard():
    """No tracked file may contain network_attachment, NETWORK_ATTACHMENT,
    receipt, or the word attachment (case-insensitive) outside the ALLOWLIST
    above. A new hit means either Tasks 2-7 missed a rename site -- fix it --
    or it is a genuinely new fenced/historical/deliberate-pin site -- add a
    commented ALLOWLIST entry with a real reason. See agentinfo/specs/
    2026-08-30-terminology-rename.md decisions 4 and 5."""
    hits = list(_iter_hits())
    if not hits:
        return
    lines = ["Retired-vocabulary hit(s) found -- fix it, or add a justified "
             "ALLOWLIST entry in server/tests/test_terminology.py:"]
    for path, lineno, term, matched, text in hits:
        lines.append("  %s:%d: matched %r (term=%s) -- %s" %
                     (path, lineno, matched, term, text))
    raise AssertionError("\n".join(lines))


def test_terminology_allowlist_entries_are_still_needed():
    """Every ALLOWLIST entry must still correspond to a real, tracked,
    in-range retired-vocabulary occurrence. A stale entry (its line moved,
    was renamed away, or the file was deleted) silently widens the guard's
    blind spot for whatever now sits at that path/line -- so a stale entry
    must fail loudly here rather than rot quietly."""
    tracked = set(_tracked_files())
    for path, lines, reason in ALLOWLIST:
        assert path in tracked, (
            "%s: allowlisted but not a tracked file -- drop this entry (%s)"
            % (path, reason))
        with open(os.path.join(REPO, path), "r", encoding="utf-8") as fh:
            text = fh.read()
        if lines is None:
            assert any(p.search(text) for p in _PATTERNS.values()), (
                "%s: whole-file allowlist entry has ZERO retired-vocabulary "
                "hits left -- drop it (%s)" % (path, reason))
            continue
        file_lines = text.splitlines()
        for lineno in sorted(lines):
            assert 1 <= lineno <= len(file_lines), (
                "%s:%d: allowlisted line number is out of range -- stale "
                "entry (%s)" % (path, lineno, reason))
            line = file_lines[lineno - 1]
            assert any(p.search(line) for p in _PATTERNS.values()), (
                "%s:%d: allowlisted line no longer matches any retired "
                "term -- stale entry (%s)" % (path, lineno, reason))
