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

ALLOWLIST entries are ``(path, anchors, reason)``:
  path    -- repo-relative, exactly as `git ls-files` reports it
  anchors -- ``None`` to allowlist the WHOLE file (used once, for
             CHANGELOG.md's append-only history -- decision 4), or a tuple of
             distinctive SUBSTRINGS of the excluded lines. Content, never line
             numbers: a line-number pin made this vocabulary guard fail on
             every unrelated edit above it in 22 other files, and one entry
             was re-pinned seven times by CSS work alone. Keep an anchor
             narrow enough that it could not accidentally cover a NEW
             violation.
  reason  -- why this specific occurrence is retired vocabulary but not a
             violation; cites the spec decision or task where it was decided

A companion test (test_terminology_allowlist_entries_are_still_needed)
keeps this list honest: every entry must still point at an existing tracked
path, every anchor must still match at least one line, and every line an
anchor covers must still carry retired vocabulary -- so a stale or
over-broad entry fails loudly instead of silently widening the guard's
blind spot.
"""

import os
import re
import subprocess

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

_PATTERNS = {
    "attachment": re.compile(r"attachment", re.IGNORECASE),
    "receipt": re.compile(r"receipt", re.IGNORECASE),
}

# The six install/uninstall wrappers carry the identical two-line tripwire, and
# the six bats files carry the identical three-line pin of its message.
_TRIPWIRE_ANCHORS = (
    '${NETWORK_ATTACHMENT:-}',
    "NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE",
)
_TRIPWIRE_TEST_ANCHORS = (
    "stale NETWORK_ATTACHMENT without MANAGEMENT_TYPE",
    "NETWORK_ATTACHMENT=",
    "NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE",
)

# ALLOWLIST entries are anchored on line CONTENT, never on line numbers.
# Absolute line pins coupled this vocabulary guard to every unrelated edit in
# 22 other files: one entry alone was re-pinned seven times
# (425 -> 491 -> 497 -> 538 -> 542 -> 578 -> 593 -> 598) by CSS work that had
# nothing to do with terminology, and each drift failed this suite with a
# stale-entry assertion a contributor had to resolve by hand-counting lines.
# An anchor is a distinctive substring of the line being excluded; a line is
# allowlisted when it contains one of its file's anchors. Keep anchors narrow
# enough that they could not accidentally cover a NEW violation.
ALLOWLIST = [
    # -- decision 4: append-only history -------------------------------
    ("CHANGELOG.md", None,
     "append-only history (decision 4): old released entries keep their "
     "original wording verbatim, and the rename's own Unreleased entry "
     "narrates the change using both the old and new vocabulary by design"),

    # -- decision 5 hard exclusions: RFC / IOS / CSV-guard sites -------
    ("server/management_api.py", ('attachment; filename=',),
     "Content-Disposition: attachment (RFC 6266) on the CSV export/example "
     "download headers -- hard exclusion, decision 5"),
    ("tools/gen-device-installers.sh", ('*"network_attachment"*',),
     "network_attachment CSV-header REJECTION guard arm for legacy operator "
     "CSVs -- hard exclusion, decision 5 (this is the guard that refuses a "
     "v2 CSV outside Console/API onboarding, not the removed import alias)"),

    # -- decision 5 Family C: time-of-receipt sense, not the retired ---
    # -- peer-receipt/deployment-receipt identifiers -------------------
    ("server/live_samples.py",
     ("receipt-keyed", "RECEIPT-based", "receipt validity", "observed receipt",
      "receipt age"),
     "time-of-receipt sense (spec section 3A/3B/4/10.1c) -- hard exclusion, "
     "decision 5"),
    ("server/telemetry.py", ("observed receipt",),
     "time-of-receipt sense (spec section 3B/4) -- hard exclusion, decision 5"),
    ("server/tests/test_docs_map.py", ("stamps it on receipt",),
     "time-of-receipt sense (\"the server stamps it on receipt\") -- hard "
     "exclusion, decision 5"),
    ("server/tests/test_telemetry_v2_ingest.py",
     ("receipt-based validity", "_120s_receipt", "OBSERVED receipt",
      "by_receipt_120"),
     "time-of-receipt sense (validity keyed off the last OBSERVED receipt), "
     "Family C -- hard exclusion, decision 5"),
    ("docs/zensical/observability.md", ("server on receipt",),
     "time-of-receipt sense (\"stamped at ingest by the server on receipt\") "
     "-- hard exclusion, decision 5"),
    ("docs/zensical/dashboards/splunk-iris-swarm.xml",
     ("SERVER's receipt clock",),
     "time-of-receipt sense (\"_time is the SERVER's receipt clock\") -- "
     "hard exclusion, decision 5"),

    # -- Task 2: six deliberate NETWORK_ATTACHMENT stale-wrapper -------
    # -- tripwires, and the bats pins that exercise each one -----------
    #
    # Every tripwire is the same two lines in six scripts, so they share one
    # anchor pair; the bats files share the pins that assert the message.
    ("device/device-install.sh", _TRIPWIRE_ANCHORS,
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire -- fires only "
     "when an old install wrapper still exports the retired env var "
     "(Task 2 review)"),
    ("device/device-uninstall.sh",
     _TRIPWIRE_ANCHORS + ("attachments (EXPLICIT-name no-forms)",),
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review), "
     "plus the IOS logging-discriminator \"attachments\" EXPLICIT-name "
     "no-forms comment -- hard exclusion, decision 5"),
    ("device/router-install.sh", _TRIPWIRE_ANCHORS,
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review)"),
    ("device/router-uninstall.sh", _TRIPWIRE_ANCHORS,
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review)"),
    ("device/iox/install.sh", _TRIPWIRE_ANCHORS,
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review)"),
    ("device/iox/uninstall.sh", _TRIPWIRE_ANCHORS,
     "deliberate NETWORK_ATTACHMENT stale-wrapper tripwire (Task 2 review)"),
    ("device/tests/test_device_install.bats", _TRIPWIRE_TEST_ANCHORS,
     "pins device-install.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/tests/test_device_uninstall.bats", _TRIPWIRE_TEST_ANCHORS,
     "pins device-uninstall.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/tests/test_router_install.bats", _TRIPWIRE_TEST_ANCHORS,
     "pins router-install.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/tests/test_router_uninstall.bats", _TRIPWIRE_TEST_ANCHORS,
     "pins router-uninstall.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/iox/tests/test_iox_install_output.bats", _TRIPWIRE_TEST_ANCHORS,
     "pins iox/install.sh's NETWORK_ATTACHMENT tripwire message"),
    ("device/iox/tests/test_iox_uninstall.bats", _TRIPWIRE_TEST_ANCHORS,
     "pins iox/uninstall.sh's NETWORK_ATTACHMENT tripwire message"),

    # -- decision 1: the removed network_attachment CSV/read alias -----
    # Anchor on text that stays on ONE line. The previous anchor was
    # "retired network_attachment", which broke when the svi_igp work reflowed
    # this comment and split that phrase across two lines -- the guard then
    # reported both a stale anchor and an unlisted hit for the same unchanged
    # sentence.
    ("server/gui_fleet.py", ("network_attachment alias header is gone",),
     "developer comment explaining the retired network_attachment CSV "
     "header alias is gone (decision 1) -- historical context, not live code"),
    ("server/tests/test_gui_fleet.py",
     ("test_network_attachment_csv_header_is_rejected",
      "retired network_attachment v2 header alias is gone",
      'else "network_attachment"',
      "test_legacy_network_attachment_only_row_reads_as_unclassified",
      "the network_attachment read-alias is REMOVED",
      '"network_attachment": "routed"',
      'dev["network_attachment"]'),
     "deliberate hard-break pins: a CSV using the retired network_attachment "
     "v2 header is rejected like any other unrecognized header, and the "
     "removed read-alias no longer classifies a fleet.json row (decision 1)"),
    ("server/tests/test_gui_server.py",
     ("test_plan_ignores_the_network_attachment_alias",
      "retired network_attachment alias (never re-saved",
      '"network_attachment": "inband"',
      "test_plan_refuses_xr_appmgr_platform_on_a_network_attachment_alias_only_row",
      "hint of xr-host is the retired network_attachment alias",
      '"network_attachment": "xr-host"',
      "pass through as attachment=None",
      "test_onboard_job_status_wire_uses_record_id_not_receipt_id",
      "receipt_id key would leak the retired vocabulary",
      '"receipt_id" not in',
      "the Attachment value and four rows of dashes",
      "res.attachment"),
     "deliberate hard-break pins (decisions 1 and 6, declared break 7): the "
     "retired network_attachment alias plans as unclassified rather than "
     "migrated, the retired receipt_id key never reaches the wire, and "
     "app.js's deployRecordRows never falls back to res.attachment -- plus "
     "the docstrings that name the pre-fix behaviour each one guards against"),
    ("server/tests/test_gui_onboard.py",
     ('attachment/management_type to "routed"',
      "attachment -> management_type -> network_attachment",
      "bind evidence as attachment="),
     "docstrings naming the pre-fix silent default and the pre-fix "
     "three-level fallback chain these regression tests guard against -- "
     "historical, Task 2 / decision 6"),

    # -- declared break 6: old-agent peer_receipts compatibility -------
    ("server/tests/test_catalog.py", ("peer_receipts",),
     "deliberate hard-break pin: an old, not-yet-redeployed agent's stale "
     "peer_receipts key is dropped silently, not rejected (declared break 6)"),

    # -- Task 6: CSS property name, not the retired business term ------
    ("server/webroot/styles.css", ("background-attachment:",),
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
    """-> (set of whole-file paths, {path: tuple of content anchors})."""
    whole = set()
    by_anchor = {}
    for path, anchors, _reason in ALLOWLIST:
        if anchors is None:
            whole.add(path)
        else:
            by_anchor[path] = by_anchor.get(path, ()) + tuple(anchors)
    return whole, by_anchor


def _iter_hits():
    """Yield (path, lineno, term, matched_text, line) for every retired-
    vocabulary occurrence in a tracked file that is not allowlisted."""
    whole, by_anchor = _allowlist_index()
    for path in _tracked_files():
        if path in whole:
            continue
        try:
            with open(os.path.join(REPO, path), "r", encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue          # binary or unreadable; not a vocabulary source
        anchors = by_anchor.get(path, ())
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(anchor in line for anchor in anchors):
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
    retired-vocabulary occurrence. A stale entry (the line was renamed away, or
    the file was deleted) silently widens the guard's blind spot for whatever
    now sits behind that anchor -- so a stale entry must fail loudly here
    rather than rot quietly.

    Anchors are content, not line numbers, so an unrelated edit ABOVE an
    excluded line no longer fails this suite. An anchor that stops matching --
    or that matches a line no longer carrying retired vocabulary -- still
    does."""
    tracked = set(_tracked_files())
    for path, anchors, reason in ALLOWLIST:
        assert path in tracked, (
            "%s: allowlisted but not a tracked file -- drop this entry (%s)"
            % (path, reason))
        with open(os.path.join(REPO, path), "r", encoding="utf-8") as fh:
            text = fh.read()
        if anchors is None:
            assert any(p.search(text) for p in _PATTERNS.values()), (
                "%s: whole-file allowlist entry has ZERO retired-vocabulary "
                "hits left -- drop it (%s)" % (path, reason))
            continue
        file_lines = text.splitlines()
        for anchor in anchors:
            matched = [line for line in file_lines if anchor in line]
            assert matched, (
                "%s: allowlist anchor %r matches no line any more -- stale "
                "entry (%s)" % (path, anchor, reason))
            assert all(any(p.search(line) for p in _PATTERNS.values())
                       for line in matched), (
                "%s: allowlist anchor %r now covers a line with no retired "
                "term -- the anchor is too broad (%s)" % (path, anchor, reason))
