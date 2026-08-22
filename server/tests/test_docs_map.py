# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Documentation-map completeness gate.

The site nav (zensical.toml), the docs index page, and the README's
documentation section describe the same set of pages from three places, and
they have drifted apart before (README listed 8 of 19 pages; index.md linked
6). This gate fails whenever a page exists in one map but not the others, so
adding a docs page means updating all three or failing CI.
"""
import os
import re
import tomllib

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCS = os.path.join(REPO, "docs", "zensical")


def _nav():
    with open(os.path.join(REPO, "zensical.toml"), "rb") as fh:
        cfg = tomllib.load(fh)
    return cfg["project"]["nav"] if "project" in cfg else cfg["nav"]


def _nav_pages(nav=None):
    """Every page in the nav, flattened. The nav is GROUPED: a title maps either
    to a page or to a list of nested entries, so this recurses."""
    pages = []
    for entry in _nav() if nav is None else nav:
        for _title, target in entry.items():
            if isinstance(target, list):
                pages.extend(_nav_pages(target))
            else:
                pages.append(target)
    return pages


def _nav_sections():
    """{section title: [pages]} for grouped entries only — top-level standalone
    pages (Overview) are not a section."""
    sections = {}
    for entry in _nav():
        for title, target in entry.items():
            if isinstance(target, list):
                sections[title] = _nav_pages(target)
    return sections


def test_every_nav_page_exists():
    for page in _nav_pages():
        assert os.path.isfile(os.path.join(DOCS, page)), \
            "zensical.toml nav references missing page: %s" % page


def test_every_docs_page_is_in_the_nav():
    nav = set(_nav_pages())
    on_disk = {name for name in os.listdir(DOCS) if name.endswith(".md")}
    orphans = on_disk - nav
    assert not orphans, \
        "docs pages missing from the zensical.toml nav: %s" % sorted(orphans)


def test_index_links_every_nav_page():
    with open(os.path.join(DOCS, "index.md")) as fh:
        index = fh.read()
    missing = [p for p in _nav_pages() if p != "index.md"
               and ("(%s)" % p) not in index]
    assert not missing, \
        "docs/zensical/index.md does not link these nav pages: %s" % missing


def test_readme_links_every_nav_page():
    with open(os.path.join(REPO, "README.md")) as fh:
        readme = fh.read()
    missing = [p for p in _nav_pages()
               if ("docs/zensical/%s" % p) not in readme]
    assert not missing, \
        "README.md documentation section is missing these pages: %s" % missing


def test_no_page_appears_twice_in_the_nav():
    """A page filed under two sections makes the sidebar ambiguous and breaks the
    'one home per page' assumption the index and README maps rely on."""
    pages = _nav_pages()
    dupes = sorted({p for p in pages if pages.count(p) > 1})
    assert not dupes, "pages listed more than once in the nav: %s" % dupes


def test_every_page_is_filed_under_a_section():
    """Only the Overview page sits at the top level; everything else belongs to a
    section, so the nav never regresses to one flat list."""
    grouped = {p for pages in _nav_sections().values() for p in pages}
    top_level = [p for p in _nav_pages() if p not in grouped]
    assert top_level == ["index.md"], \
        "these pages are not filed under a nav section: %s" % top_level


def test_index_and_readme_use_the_same_section_headings():
    """The three maps must agree on STRUCTURE, not just on the page set — a
    regrouped nav with stale index/README headings is the drift this gate
    exists to catch."""
    sections = _nav_sections()
    with open(os.path.join(DOCS, "index.md")) as fh:
        index = fh.read()
    with open(os.path.join(REPO, "README.md")) as fh:
        readme = fh.read()
    for title in sections:
        assert title in index, \
            "docs/zensical/index.md is missing the nav section heading: %s" % title
        assert title in readme, \
            "README.md is missing the nav section heading: %s" % title


def test_index_groups_pages_under_their_own_section():
    """Each page must be linked BELOW its section heading in index.md, so the
    page can't drift into the wrong group."""
    with open(os.path.join(DOCS, "index.md")) as fh:
        index = fh.read()
    order = [(index.index(t), t) for t in _nav_sections() if t in index]
    order.sort()
    for pos, title in order:
        later = [p for p, _t in order if p > pos]
        end = min(later) if later else len(index)
        block = index[pos:end]
        for page in _nav_sections()[title]:
            assert ("(%s)" % page) in block, \
                "index.md links %s outside its '%s' section" % (page, title)


# ---------------------------------------------------------------------------
# Contract assertions.
#
# The gate above is structural: it proves the nav, the index and the README
# agree on which pages exist. These check that the pages actually STATE the
# fail-closed contracts the implementation guarantees. Each one pins the
# load-bearing clause -- the half an operator would act on during an incident --
# so rewording the sentence into something false fails here rather than shipping
# a doc that misdescribes the system.


def _page(name):
    with open(os.path.join(DOCS, name)) as fh:
        return fh.read()


def _require(name, needles):
    page = _page(name)
    missing = [n for n in needles if n not in page]
    assert not missing, "%s is missing required contract text: %s" % (name, missing)


def test_docs_state_typed_principals():
    """A principal is (type, id); the device and service namespaces are
    distinct, and an unattributable peer is typed rather than guessed at."""
    _require("security.md", ["`service:seeder`", "`device:<id>`", "`legacy`"])


def test_docs_state_strict_credential_ownership():
    """Duplicate credential ownership must fail closed, not resolve to
    whichever record loaded last."""
    _require("security.md", ["Duplicate credential ownership"])


def test_docs_state_policy_read_precedence():
    """`fail_closed` is unreachable when BOTH policy files are absent -- that is
    the open-discovery case. Documenting it the other way sends an operator to
    the wrong repair mid-incident."""
    _require("security.md", ["At least one file present, neither valid",
                             "Neither file present"])


def test_docs_state_emergency_deny_seeder_exclusion():
    """Protecting the seeder under emergency deny depends on IRIS_HOST_IP being
    the address it actually announces from -- it is not automatic."""
    _require("security.md", ["IRIS_HOST_IP"])


def test_docs_state_no_known_address_is_not_enforced():
    """With no address to deny, the empty desired set is deliberately NOT sent,
    and the pass is never reported as enforced."""
    _require("security.md", ["deliberately does not send"])


def test_docs_state_enforcement_status_is_count_only():
    """The denied set is a count -- but conflict records name the disputed
    address, so the file is not address-free. The console API is the boundary."""
    _require("security.md", ["not address-free"])


def test_docs_state_announce_credential_travels_over_http():
    """The announce credential rides a private HTTP URL; that residual is a
    stated boundary, not an oversight."""
    _require("security.md", ["private HTTP"])


def test_docs_state_no_day1_revoke_or_migration():
    """Both credentials stay valid. There is no shipped revoke command and no
    automated migration on day one."""
    _require("security.md", ["no shipped command"])


def test_docs_state_stage_only_invariant():
    """Images are staged and verified, never installed, activated or reloaded."""
    _require("security.md", ["No install", "No reload", "No boot mutation"])


def test_docs_state_policy_outbox_backlog():
    """A stalled consumer blocks new operations with a 503 rather than silently
    dropping them, and the bound is checked before any write."""
    _require("operations.md", ["operation_backlog_full", "256"])


def test_docs_state_pending_endpoint_retry():
    """An endpoint write that fails is queued and retried; the device
    participates meanwhile but the reported status degrades."""
    _require("operations.md", ["peer-endpoints.json"])


def test_docs_state_device_retirement_retention():
    """Retirement derives deny from the RETAINED endpoint row, and re-onboard
    clears the old row before the fresh credential is usable."""
    _require("operations.md", ["retained"])


def test_docs_state_rotation_double_failure_is_hard_no_go():
    """A double failure can leave an image not being served. The docs must not
    imply serving is preserved."""
    _require("operations.md", ["hard no-go", "not being served"])


def test_docs_state_rotation_proof_is_loopback_swarm():
    """Rotation is proven by observing the typed current service seeder through
    the tracker's loopback /swarm -- no registry shortcut, no IP guess."""
    _require("operations.md", ["/swarm", "service:seeder"])


def test_docs_state_v1_event_ids_are_stamped_at_ingest():
    """v1 telemetry has no device-supplied id; the server stamps it on receipt."""
    _require("observability.md", ["stamped at ingest"])


def test_docs_state_legacy_participants_are_visible_but_unjoinable():
    """A legacy participant announces and is counted, but carries no device
    identity and cannot be quarantined individually."""
    _require("observability.md", ["legacy"])


def test_docs_state_swarm_map_is_proven_by_hand():
    """Static Python tests are not browser automation. The map's behavior is
    verified manually and the checklist must say so."""
    _require("validation.md", ["by hand in a browser"])


def test_docs_state_identity_gate_env_var():
    """The deployment gate is off by default and documented where env vars live."""
    _require("reference.md", ["IRIS_REQUIRE_IDENTITY_GATE"])
