# server/tests/test_terminology.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Retired-vocabulary guard (terminology rename, spec 2026-08-30).

The rename retired `attachment`/`network_attachment` (-> management type),
deployment `receipt` (-> deployment record), and peer `receipt` (-> peer
transfer record) everywhere except a short, explicit set of fenced sites
(RFC 6266, an IOS logging discriminator, a CSV rejection guard, the
time-of-receipt sense of "receipt", Tasks 22–23's distinct schedule receipts,
append-only history, and a handful of deliberate hard-break regression pins).
This test scans every TRACKED file
(``git ls-files`` -- untracked/ignored paths such as HANDOFF.md and
skills-lock.json are excluded by construction, no allowlist entry needed)
for the retired vocabulary and fails on anything not covered by the
allowlists below. This file's own path is also excluded from the scan (see
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

TERM_FILE_ALLOWLIST entries are ``(path, terms, reason)``. They are reserved
for files wholly owned by a vocabulary that deliberately reuses one retired
word. Unlike a whole-file ALLOWLIST entry, these exemptions suppress only the
named pattern: for example, a schedule file exempted for ``receipt`` still
fails immediately if ``attachment`` appears in it.

TERM_SCOPE_ALLOWLIST entries are ``(path, scope, terms, reason)``. A dotted
Python class/function name fences a term exemption inside a shared module.
The AST supplies its current extent, so moving code does not widen the
exception into neighboring features or require brittle line-number pins.

A companion test (test_terminology_allowlist_entries_are_still_needed)
keeps this list honest: every entry must still point at an existing tracked
path, every anchor must still match at least one line, and every line an
anchor covers must still carry retired vocabulary -- so a stale or
over-broad entry fails loudly instead of silently widening the guard's
blind spot.
"""

import ast
import os
import re
import subprocess

import pytest

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
    ("server/tests/test_telemetry_v2_ingest.py",
     ("receipt-based validity", "_120s_receipt", "OBSERVED receipt",
      "by_receipt_120"),
     "time-of-receipt sense (validity keyed off the last OBSERVED receipt), "
     "Family C -- hard exclusion, decision 5"),
    ("docs/zensical/dashboards/splunk-iris-swarm.xml",
     ("SERVER's receipt clock",),
     "time-of-receipt sense (\"_time is the SERVER's receipt clock\") -- "
     "hard exclusion, decision 5"),

    # -- Native IOS hash completion, not deployment/peer terminology ---
    ("device/agent/iris_agent.py",
     ("share can carry a native IOS hash receipt",
      "requires a completion receipt written AFTER IOS",
      'receipt_dir = prefix + "guest-share/iris/"',
      "'action 030 file open result %s/result w' % receipt_dir",
      "'action 060 file open done %s/done w' % receipt_dir",
      "bounded IOS SHA-512 policy did not produce a receipt",
      "This unique directory contains only this call's hash receipts"),
     "private EEM hash completion records: a unique result/done pair proves "
     "that the native IOS hash command completed; unrelated to retired "
     "deployment records or peer transfer records"),
    ("device/agent/tests/test_guestshell_root_attestation.py",
     ("production lock, durable lease, fresh receipt and poll path",
      "test_native_hash_uses_fresh_receipt_and_only_read_only_ios_hash",
      "a stale receipt cannot prove a later request",
      "test_native_hash_does_not_accept_stale_receipt_after_timeout"),
     "tests of the private EEM hash completion records, including freshness "
     "and timeout rejection; no deployment or peer transfer terminology"),

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
      '"network_attachment": "inband"',
      "test_plan_refuses_xr_appmgr_platform_on_a_network_attachment_alias_only_row",
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

    # -- Task 22: schedule-receipt vocabulary in shared files ----------
    # Schedule receipts are durable per-device execution evidence. They are
    # unrelated to the retired deployment and peer-transfer receipt names.
    # Shared registry/API/contract files stay line-anchored so another feature
    # cannot begin using the retired word under a broad file exception.
    ("server/api_routes.py", ('"/schedules/{id}/receipts"',),
     "Task 22 schedule-receipt route registry entry"),
    ("server/management_api.py",
     ("(occurrences|receipts)",
      "receipt evidence is intentionally retained",
      "schedule_receipt_store",
      "schedules.MAX_RECEIPT_PAGE",
      "schedules.list_schedule_receipts"),
     "Task 22 schedule history route and its retained schedule-receipt "
     "evidence comment"),
    ("server/openapi_contract.py",
     ('"/schedules/{id}/receipts"',
      'suffix.endswith("/receipts")',
      '"receipts": {"type": "array", "maxItems": schedules.MAX_RECEIPT_PAGE',
      'receipt = {"occurrence_id":',
      '"Schedule-wide receipt page',
      '"receipts": [receipt]',
      "no per-device receipts",
      '"/receipts")):',
      '("occurrences" if occurrence_page else "receipts")',
      'schedule occurrences and schedule receipts expose',
      "_schedule_receipt_schema",
      "schedules.MAX_RECEIPT_ATTEMPTS",
      "schedules.RECEIPT_STATES",
      "schedules.TERMINAL_RECEIPT_STATES",
      "schedules.MAX_RECEIPT_PAGE"),
     "Task 22 schedule-receipt schemas, examples, paging, and contract "
     "declaration in the shared OpenAPI generator"),
    ("server/tests/test_openapi_contract.py",
     ('("GET", "/schedules/{id}/receipts", "200")',
      'suffix.endswith(("/occurrences", "/receipts"))'),
     "Task 22 schedule-receipt route and paging assertions in shared "
     "OpenAPI contract tests"),
    ("server/tests/test_openapi_validation.py",
     ("test_schedule_response_views_history_and_receipts_are_closed_and_bounded",
      'receipts = paths[prefix + "/schedules/{id}/receipts"]',
      'page_media = receipts["responses"]',
      'broken["receipts"]',
      'p for p in receipts["parameters"]',
      'for receipt in example.get("receipts", [])',
      "value in receipt.items()",
      "schedules._validate_receipt"),
     "Task 22 schedule-receipt schema validation and generated-example "
     "checks in the shared OpenAPI validation suite"),
    ("server/assignment_service.py",
     ("A result can precede its durable terminal runner receipt.",
      "acknowledgement after the runner saves its terminal receipt."),
     "Task 23 schedule-result retention comments inside the shared manual/"
     "scheduled assignment transaction; deployment records retain their name"),
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


# Tasks 22–23's dedicated schedule implementation/tests and generated OpenAPI
# document use "receipt" as a new, intentionally separate domain term. Exempt
# only that pattern; the attachment guard remains active in every listed file.
TERM_FILE_ALLOWLIST = [
    ("docs/zensical/openapi.yaml", ("receipt",),
     "generated Task 22 schedule-receipt API contract"),
    ("server/schedule_runner.py", ("receipt",),
     "Task 22 schedule runner and its per-device execution evidence"),
    ("server/schedules.py", ("receipt",),
     "Task 22 schedule store and its per-device execution evidence"),
    ("server/tests/test_schedule_api.py", ("receipt",),
     "Task 22 schedule API tests"),
    ("server/tests/test_schedule_runner.py", ("receipt",),
     "Task 22 schedule runner tests"),
    ("server/tests/test_schedules.py", ("receipt",),
     "Task 22 schedule store tests"),
    ("server/tests/test_scheduled_execution.py", ("receipt",),
     "Task 23 scheduled assignment/onboarding receipt and recovery tests"),
]


# Task 23 consumes the approved Task 22 per-device schedule-receipt contract.
# These scopes belong to that domain; the rest of each shared file remains
# guarded against retired deployment/peer vocabulary. No attachment exemption
# is implied, even inside these scopes.
TERM_SCOPE_ALLOWLIST = [
    ("server/assignment_service.py",
     "AssignmentService.acknowledge_schedule_result", ("receipt",),
     "Task 23 releases occurrence claims only after durable schedule receipts"),
    ("server/assignment_service.py", "AssignmentService._schedule_request",
     ("receipt",), "Task 23 preserves legacy schedule-receipt replay bindings"),
    ("server/deployment_records.py", "DeploymentRecordStore.admit_scheduled",
     ("receipt",), "Task 23 checks schedule-receipt ownership at record admission"),
    ("server/gui_onboard.py", "OnboardService.jobs_for_occurrence", ("receipt",),
     "Task 23 locates occurrence-owned jobs for schedule-receipt reconciliation"),
    ("server/management_api.py", "_ScheduledExecutor", ("receipt",),
     "Task 23 executor implements the approved dispatch/poll receipt contract"),
    ("server/tests/test_iris_assign.py",
     "test_recurring_claims_remain_until_explicit_acknowledgement", ("receipt",),
     "Task 23 pins schedule-result retention until receipt acknowledgement"),
    ("server/tests/test_iris_assign.py",
     "test_terminal_receipt_acknowledgement_reclaims_ambiguous_claim",
     ("receipt",), "Task 23 pins terminal schedule-receipt claim cleanup"),
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
    """Return whole-file, line-anchor, term-file, and term-scope exemptions."""
    whole = set()
    by_anchor = {}
    for path, anchors, _reason in ALLOWLIST:
        if anchors is None:
            whole.add(path)
        else:
            by_anchor[path] = by_anchor.get(path, ()) + tuple(anchors)
    by_term = {}
    for path, terms, _reason in TERM_FILE_ALLOWLIST:
        by_term[path] = by_term.get(path, frozenset()) | frozenset(terms)
    by_scope = {}
    for path, scope, terms, _reason in TERM_SCOPE_ALLOWLIST:
        by_scope.setdefault(path, []).append((scope, terms))
    return whole, by_anchor, by_term, by_scope


def _scope_ranges(text, entries):
    """Resolve explicit Python scopes; missing/ambiguous scopes fail closed."""
    if not entries:
        return []
    tree = ast.parse(text)
    ranges = []
    for scope, terms in entries:
        body = tree.body
        for name in scope.split("."):
            matches = [node for node in body
                       if isinstance(node, (ast.ClassDef, ast.FunctionDef,
                                            ast.AsyncFunctionDef))
                       and node.name == name]
            assert len(matches) == 1, (
                "term-scope allowlist %r is missing or ambiguous" % scope)
            node = matches[0]
            body = node.body
        start = min([node.lineno] + [item.lineno for item in node.decorator_list])
        ranges.append((start, node.end_lineno, frozenset(terms)))
    return ranges


def _iter_hits():
    """Yield (path, lineno, term, matched_text, line) for every retired-
    vocabulary occurrence in a tracked file that is not allowlisted."""
    whole, by_anchor, by_term, by_scope = _allowlist_index()
    for path in _tracked_files():
        if path in whole:
            continue
        try:
            with open(os.path.join(REPO, path), "r", encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue          # binary or unreadable; not a vocabulary source
        anchors = by_anchor.get(path, ())
        allowed_terms = by_term.get(path, frozenset())
        scope_ranges = _scope_ranges(text, by_scope.get(path, ()))
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(anchor in line for anchor in anchors):
                continue
            for term, pattern in _PATTERNS.items():
                if term in allowed_terms or any(
                        start <= lineno <= end and term in terms
                        for start, end, terms in scope_ranges):
                    continue
                m = pattern.search(line)
                if m:
                    yield path, lineno, term, m.group(0), line.strip()


def test_retired_vocabulary_guard():
    """No tracked file may contain network_attachment, NETWORK_ATTACHMENT,
    receipt, or the word attachment (case-insensitive) outside the allowlists
    above. A new hit means either Tasks 2-7 missed a rename site -- fix it --
    or it is a genuinely new fenced/historical/deliberate-pin site -- add a
    commented, narrowly scoped entry with a real reason. See agentinfo/specs/
    2026-08-30-terminology-rename.md decisions 4 and 5."""
    hits = list(_iter_hits())
    if not hits:
        return
    lines = ["Retired-vocabulary hit(s) found -- fix it, or add a justified "
             "narrow allowlist entry in server/tests/test_terminology.py:"]
    for path, lineno, term, matched, text in hits:
        lines.append("  %s:%d: matched %r (term=%s) -- %s" %
                     (path, lineno, matched, term, text))
    raise AssertionError("\n".join(lines))


def test_terminology_allowlist_entries_are_still_needed():
    """Every allowlist entry must still correspond to a real, tracked,
    retired-vocabulary occurrence. A stale entry (the line or term was renamed
    away, or the file was deleted) silently widens the guard's blind spot, so
    it must fail loudly here rather than rot quietly.

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

    for path, terms, reason in TERM_FILE_ALLOWLIST:
        assert path in tracked, (
            "%s: term-file allowlisted but not a tracked file -- drop this "
            "entry (%s)" % (path, reason))
        with open(os.path.join(REPO, path), "r", encoding="utf-8") as fh:
            text = fh.read()
        for term in terms:
            assert term in _PATTERNS, (
                "%s: unknown term-file allowlist pattern %r (%s)" %
                (path, term, reason))
            assert _PATTERNS[term].search(text), (
                "%s: term-file allowlist pattern %r has ZERO hits left -- "
                "drop it (%s)" % (path, term, reason))

    for path, scope, terms, reason in TERM_SCOPE_ALLOWLIST:
        assert path in tracked, (
            "%s: term-scope allowlisted but not tracked (%s)" % (path, reason))
        with open(os.path.join(REPO, path), "r", encoding="utf-8") as fh:
            text = fh.read()
        start, end, _terms = _scope_ranges(text, [(scope, terms)])[0]
        scoped_text = "\n".join(text.splitlines()[start - 1:end])
        for term in terms:
            assert term in _PATTERNS, (
                "%s: unknown term-scope pattern %r (%s)" % (path, term, reason))
            assert _PATTERNS[term].search(scoped_text), (
                "%s:%s: term-scope pattern %r has ZERO hits left -- drop it (%s)"
                % (path, scope, term, reason))


def test_schedule_receipt_exemptions_preserve_other_domains(tmp_path, monkeypatch):
    sources = {
        "server/management_api.py": (
            "receipt = None\n"
            "class _ScheduledExecutor:\n"
            "    receipt = None\n"
            "    network_attachment = None\n"
            "class Other:\n"
            "    receipt = None\n"
            "class _ScheduledExecutorExtra:\n"
            "    receipt = None\n"),
        "server/deployment_records.py": (
            "class DeploymentRecordStore:\n"
            "    def admit_scheduled(self):\n"
            "        receipt = None\n"
            "    def create(self):\n"
            "        receipt = None\n"),
        "server/tests/test_scheduled_execution.py": (
            "receipt = None\nnetwork_attachment = None\n"),
        "server/unrelated.py": "receipt = None\n",
    }
    for path, text in sources.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    monkeypatch.setitem(globals(), "REPO", str(tmp_path))
    monkeypatch.setitem(globals(), "_tracked_files", lambda: list(sources))
    assert [(path, line, term) for path, line, term, *_rest in _iter_hits()] == [
        ("server/management_api.py", 1, "receipt"),
        ("server/management_api.py", 4, "attachment"),
        ("server/management_api.py", 6, "receipt"),
        ("server/management_api.py", 8, "receipt"),
        ("server/deployment_records.py", 5, "receipt"),
        ("server/tests/test_scheduled_execution.py", 2, "attachment"),
        ("server/unrelated.py", 1, "receipt"),
    ]


@pytest.mark.parametrize("source", [
    "class Other:\n    receipt = None\n",
    "class _ScheduledExecutorExtra:\n    receipt = None\n",
    "class _ScheduledExecutor:\n    receipt = None\n" * 2,
])
def test_schedule_scope_exemptions_reject_stale_or_ambiguous_names(source):
    with pytest.raises(AssertionError, match="missing or ambiguous"):
        _scope_ranges(source, [("_ScheduledExecutor", ("receipt",))])
