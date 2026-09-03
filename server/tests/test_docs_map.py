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
    """The announce credential rides an HTTP URL, so it crosses the network in
    cleartext. The base may be any routable IPv4 -- nothing enforces a private
    one -- so the docs must state the exposure rather than imply a guarantee
    the code does not make."""
    _require("security.md", ["cleartext"])


def test_docs_state_previous_announce_token_is_bounded():
    # Was test_docs_state_no_day1_revoke_or_migration, which required the docs
    # to say both credentials stay valid indefinitely -- the defect itself.
    """Both credentials stay valid for a bounded overlap, after which the old
    one expires on its own. There is still no shipped revoke command, so the
    docs must not tell an operator to retire one by hand."""
    _require("security.md", ["no shipped command", "bounded overlap"])


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


# ---------------------------------------------------------------------------
# Environment-registry gate (IRIS-15-001).
#
# Compose injects ONLY what server/docker-compose.yml's `environment:` block
# names -- a variable set in server/.env or the shell but absent from that block
# is a silent no-op. Twelve documented knobs (including IRIS_METRICS_HOST, which
# security.md calls "the hard control" for the swarm surface, and the
# IRIS_OTLP_HEADERS collector credential) were unreachable that way. This gate
# fails if a variable documented in reference.md's env tables is neither passed
# through nor on the explicit host-side/one-shot list below.

# Documented, but deliberately NOT container environment. Each entry says why.
_COMPOSE_UNAVAILABLE = {
    # Read by Compose itself (project name) / interpolated into container_name;
    # neither is a container variable.
    "COMPOSE_PROJECT_NAME": "compose project name, host-side only",
    "IRIS_CONTAINER": "compose container_name + tools/ target, host-side only",
    # Interpolated host-side into the secrets/bind-mount stanzas, never injected.
    "IRIS_AGE_KEY_FILE_HOST": "host path of the age identity (docker secret)",
    "IRIS_ARTIFACTS_HOST_DIR": "host path of the artifacts bind mount",
    "IRIS_IMAGE_ROOT": "host path of the read-only image bind mount",
    # Build argument, not a runtime variable.
    "IRIS_VERSION": "docker build arg",
    # Read by the IOS-XR appmgr container's own entrypoint on the device, not
    # by the server: it never belongs in the server container's environment.
    "IRIS_XR_SKIP_MOUNT_CHECK": "device-side XR entrypoint, test-only",
    # Passed on the one-shot `run --rm -e ...` so the long-lived container never
    # holds the admin password in its environment.
    "IRIS_GUI_ADMIN_PASSWORD": "one-shot iris-gui-admin only",
    # Container-side defaults; the docs say none of these needs setting.
    "IRIS_GUI_CERT": "container default path",
    "IRIS_TRUST_DIR": "container default path",
    "IRIS_CA_BUNDLE": "container default path",
}

_ENV_TABLE_SECTIONS = (
    "### Required at deploy time",
    "### Optional at deploy time",
    "### Container paths",
    "### Image path variables",
    "### Telemetry variables",
)


def _reference_env_vars():
    """Every variable named in the first cell of a reference.md env table row."""
    with open(os.path.join(DOCS, "reference.md")) as fh:
        text = fh.read()
    found = set()
    for heading in _ENV_TABLE_SECTIONS:
        start = text.index(heading) + len(heading)
        rest = text[start:]
        nxt = re.search(r"^#{2,3} ", rest, re.M)
        block = rest[:nxt.start()] if nxt else rest
        for line in block.splitlines():
            m = re.match(r"\|\s*`([A-Z][A-Z0-9_]*)`\s*\|", line)
            if m:
                found.add(m.group(1))
    return found


def _compose_environment_keys():
    """Keys of the `environment:` mapping in server/docker-compose.yml, read as
    text so the gate needs no YAML dependency and no interpolation."""
    path = os.path.join(REPO, "server", "docker-compose.yml")
    with open(path) as fh:
        lines = fh.readlines()
    keys = set()
    indent = None
    for line in lines:
        if re.match(r"^\s*environment:\s*$", line):
            indent = len(line) - len(line.lstrip())
            continue
        if indent is None:
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        here = len(line) - len(line.lstrip())
        if here <= indent:
            break
        m = re.match(r"\s*([A-Z][A-Z0-9_]*)\s*:", line)
        if m:
            keys.add(m.group(1))
    return keys


def test_documented_env_vars_reach_the_compose_container():
    documented = _reference_env_vars()
    assert len(documented) > 25, \
        "reference.md env tables parsed as only %d rows" % len(documented)
    passed_through = _compose_environment_keys()
    missing = sorted(documented - passed_through - set(_COMPOSE_UNAVAILABLE))
    assert not missing, (
        "reference.md documents these variables but server/docker-compose.yml's "
        "environment: block does not pass them through, so setting them in "
        "server/.env or the shell is a silent no-op: %s" % missing)


def test_compose_unavailable_list_has_no_stale_entries():
    """An entry here claims a documented variable is deliberately not injected.
    If it IS injected, the carve-out is stale and misleading."""
    passed_through = _compose_environment_keys()
    stale = sorted(set(_COMPOSE_UNAVAILABLE) & passed_through)
    assert not stale, \
        "these are passed through after all; drop the carve-out: %s" % stale


def test_reference_states_the_compose_injection_mechanism():
    """The registry must say that server/.env alone does not reach the process --
    the false-confidence half of IRIS-15-001."""
    _require("reference.md", [
        "How a variable reaches the container",
        "environment:",
        "silently dropped",
    ])


# ---------------------------------------------------------------------------
# Shipped example CSVs (IRIS-14-005).
#
# fleet/devices.csv.example shipped three UNCOMMENTED rows carrying the
# maintainer's live lab addresses, so the documented `cp ... devices.csv` +
# import landed three phantom devices in a new operator's inventory (and
# published lab addressing in a public repo). The console's own generated
# template, FleetStore.example_csv(), already got this right; these gates keep
# the checked-in files from drifting from it again.

_EXAMPLE_CSVS = ("devices.csv.example", "assignments.csv.example")

# RFC 5737 documentation ranges + RFC 1918 / RFC 6598 private space, which is
# what an example router-side subnet legitimately uses.
_ALLOWED_EXAMPLE_NETS = (
    "192.0.2.", "198.51.100.", "203.0.113.",       # TEST-NET-1/2/3
    "10.", "192.168.", "127.", "100.64.",
) + tuple("172.%d." % n for n in range(16, 32))


def _example_csv_lines(name):
    with open(os.path.join(REPO, "fleet", name)) as fh:
        return fh.read().splitlines()


def test_example_csv_data_rows_are_all_commented():
    """Importing a shipped template as-is must add zero devices and zero
    assignments -- the header and comments are ignored, an uncommented row is
    not."""
    for name in _EXAMPLE_CSVS:
        lines = _example_csv_lines(name)
        for n, line in enumerate(lines[1:], start=2):   # line 1 is the header
            if not line.strip():
                continue
            assert line.lstrip().startswith("#"), \
                "fleet/%s line %d is a live data row: %r" % (name, n, line)


def test_example_csv_addresses_are_documentation_ranges():
    """No lab or customer addressing in a public template."""
    octet = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    for name in _EXAMPLE_CSVS:
        for n, line in enumerate(_example_csv_lines(name), start=1):
            for addr in octet.findall(line):
                if addr.startswith(("255.", "0.")):
                    continue                            # netmasks
                assert addr.startswith(_ALLOWED_EXAMPLE_NETS), \
                    "fleet/%s line %d ships a non-documentation address %s" \
                    % (name, n, addr)


def test_devices_csv_example_header_matches_the_console_template():
    """The checked-in template and the one the console serves are two copies of
    the same artifact; a header that is not CSV_V2_COLS fails import."""
    import sys
    sys.path.insert(0, os.path.join(REPO, "server"))
    try:
        import gui_fleet
    finally:
        sys.path.pop(0)
    header = _example_csv_lines("devices.csv.example")[0]
    assert header == ",".join(gui_fleet.CSV_V2_COLS), \
        "fleet/devices.csv.example header is not gui_fleet.CSV_V2_COLS"
    served = gui_fleet.FleetStore.example_csv().splitlines()
    served_header = next(l for l in served if l.startswith("device_id,"))
    assert header == served_header
