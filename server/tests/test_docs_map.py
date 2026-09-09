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


def test_docs_state_announce_credential_travels_over_pinned_https():
    """All tracker credentials cross pinned HTTPS; IOx/XR use a header,
    while Guest Shell's query credential remains inside the TLS connection."""
    page = _page("security.md")
    transport = page.split("### Tracker transport security", 1)[1].split(
        "### Peer policy failure posture", 1)[0]
    for contract in ("**HTTPS-only**", "public certificate as their CA",
                     "certificate verification enabled",
                     "Authorization: Bearer",
                     "TLS encrypts the complete request"):
        assert contract in transport, \
            "security.md tracker transport omits: %s" % contract


def test_docs_state_previous_announce_token_is_bounded():
    # Was test_docs_state_no_day1_revoke_or_migration, which required the docs
    # to say both credentials stay valid indefinitely -- the defect itself.
    """Both credentials stay valid for a bounded overlap, after which the old
    one expires on its own. There is still no shipped revoke command, so the
    docs must not tell an operator to retire one by hand."""
    _require("security.md", ["bounded overlap", "enforced automatically",
                             "operator command for revoking a previous credential"])


def test_docs_state_stage_only_invariant():
    """Images are staged and verified, never installed, activated or reloaded."""
    _require("security.md", ["No operating-system install", "No reload", "No boot mutation"])


def test_docs_state_policy_outbox_backlog():
    """A stalled consumer blocks new operations with a 503 rather than silently
    dropping them, and the bound is checked before any write."""
    _require("operations.md", ["operation_backlog_full", "256"])


def test_docs_state_phase_zero_role_and_qos_contract():
    """Phase 0 documentation must distinguish server enforcement from future
    device instructions and preserve the preflight-only origin boundary."""
    _require("security.md", [
        "virtual role ACL",
        "shadows the role",
        "does not sever existing connections",
        "preflight only",
        "shared_permit_deny",
        "agent-distribution exemption",
    ])
    _require("reference.md", [
        "`^[a-z0-9][a-z0-9._-]{0,31}$`",
        "at most 256 roles",
        "`peers` | the role itself; at most 64",
        "`0` means unlimited",
        "`per_peer_bps`",
        "modelling input",
        "| `announce_min_interval_s` | 30 s | 10–300 s |",
        "| `origin_max_peers` | 55 | 1–1,000 |",
        "`delivery_state: pre-instructions`",
        "`PUT /api/v1/peer-policy/roles/<name>`",
        "`GET /api/v1/peer-policy/explain?a=&b=`",
    ])
    _require("operations.md", [
        "`dry_run=1`",
        "`confirm_token`",
        "independent quarantine",
        "not sufficient",
        "unassign every image",
    ])
    _require("architecture.md", [
        "server-side cadence",
        "server-side peer selection",
        "Per-role origin shaping is not expressible",
    ])
    _require("observability.md", [
        "count-only",
        "`enforcement.mutual_origin.mode = preflight`",
        "`delivery_state = pre-instructions`",
    ])
    _assert_phase1_network_relationship(_page("network-ports.md"))
    _require("problems.md", [
        "## asymmetric_peers",
        "## role_isolated",
        "## role_in_use",
        "## role_reserved_name",
        "## operation_backlog_full",
    ])


def test_docs_state_phase_zero_recovery_and_interface_boundaries():
    """The Phase 0 operator contract must keep recovery monotonic, describe
    partial writes honestly, and use the exact public Problem fragments."""
    _require("security.md", [
        "cooperative and tamper-evident, never tamper-proof",
        "one full release of preflight observation",
        "union of current self-evaluation and mutual-origin evaluation",
        "current Phase 0 structural guards",
        "`degraded` because prior role state was lost",
        "`server/pack-agent-bundle.sh`",
    ])
    _require("operations.md", [
        "monotonic new revision",
        "no public restore route or CLI",
        "acknowledgement epoch",
        "stable event ID",
        "does not roll back a completed Fleet write",
        "`partial`",
        "persists both the accepted revision and its epoch",
    ])
    _require("reference.md", [
        "preview returns 200 JSON",
        "committed DELETE returns 204",
        "`console-session-required`",
        "`management-authentication-required`",
        "effective `endpoint_ttl()/3`",
        "Numeric QoS values reject booleans",
        "no per-role member cap",
        "`peers` must be a non-null array",
        "does not promise duplicate-net rejection",
        "`defs.<role>.qos.on_stale`",
        "never upload",
        "`origin_unreachable`",
    ])
    _require("console.md", [
        "— no role —",
        "changes may have been saved",
        "does not sever existing connections",
        "pair explanations are available only",
        "all-failed preview cannot commit",
    ])
    _require("observability.md", ["compiled policy membership",
                                   "Authorization data"])
    _assert_phase1_rollup_relationship(_page("observability.md"))
    _require("architecture.md", [
        "Fleet declaration",
        "compiled membership",
    ])
    _require("fleet-workflows.md", [
        "`fleet/roles.csv` is operator-owned and ignored",
    ])
    _require("problems.md", [
        "## bad_role",
        "## device_not_found",
        "## fleet_write_failed",
        "## incomparable_role_change",
        "## invalid_policy",
        "## invalid_policy_request",
        "## mixed_role_direction",
        "## policy_unavailable",
        "## precondition_failed",
        "## principal_unresolvable",
        "## revision_conflict",
        "## role_not_found",
    ])


def test_docs_state_pending_endpoint_retry():
    """An endpoint write that fails is queued and retried; the device
    participates meanwhile but the reported status degrades."""
    _require("operations.md", ["peer-endpoints.d/", "queued in memory", "retried"])


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


def test_docs_state_report_identity_survives_retries():
    """A report keeps its device identity through retries and export."""
    _require("observability.md", ["`report_id`", "frozen", "retry", "`event.id`",
                                  "deduplication"])


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
    "IRIS_CONSOLE_CONTAINER": "console container_name, host-side only",
    # Interpolated host-side into the secrets/bind-mount stanzas, never injected.
    "IRIS_AGE_KEY_FILE_HOST": "host path of the age identity (docker secret)",
    "IRIS_ARTIFACTS_HOST_DIR": "host path of the artifacts bind mount",
    "IRIS_IMAGE_ROOT": "host path of the read-only image bind mount",
    "IRIS_SHARP_SANS_FONT_HOST": "host path of the licensed-font bind mount",
    "IRIS_OBSERVABILITY_TOKEN_FILE_HOST": "host path of an observability-token bind mount",
    "IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE_HOST": "host path of the previous-token bind mount",
    "IRIS_OTLP_HEADERS_FILE_HOST": "host path of the OTLP-header bind mount",
    # Build argument, not a runtime variable.
    "IRIS_VERSION": "docker build arg",
    # Read by the IOS-XR appmgr container's own entrypoint on the device, not
    # by the server: it never belongs in the server container's environment.
    "IRIS_CONTAINER_TESTING": "device-container entrypoint, test-only",
    "IRIS_TEST_SKIP_MOUNT_CHECK": "device-container XR mount bypass, test-only",
    # Passed on the one-shot `run --rm -e ...` so the long-lived container never
    # holds the admin password in its environment.
    "IRIS_GUI_ADMIN_PASSWORD": "one-shot iris-gui-admin only",
    # Container-side defaults; the docs say none of these needs setting.
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
            indent = None
            continue
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


def test_workstream_a_docs_define_state_aware_tracker_cadence_and_downgrade():
    """Acceptance 26 keeps the persisted tracker contract executable in prose."""
    with open(os.path.join(DOCS, "reference.md")) as fh:
        reference = fh.read()
    with open(os.path.join(DOCS, "operations.md")) as fh:
        operations = fh.read()

    def ordered(text, terms):
        cursor = -1
        for term in terms:
            cursor = text.lower().find(term.lower(), cursor + 1)
            assert cursor >= 0, (term, terms)

    for term in ("10–300", "4–200", "announce_min_interval_s", "numwant",
                 "qos_state: {}"):
        assert term in reference, term
    reference_lower = reference.lower()
    assert re.search(r"omit(?:ted|ting)?.{0,60}qos_state.{0,120}preserv",
                     reference_lower, re.DOTALL)
    explicit_clear = re.search(
        r"qos_state\s*:\s*\{\}.{0,140}(?:remove|clear)"
        r".{0,100}(?:only|selected).{0,100}state.{0,180}",
        reference_lower, re.DOTALL)
    assert explicit_clear
    assert re.search(r"(?:preserv|retain|unchang).{0,80}"
                     r"(?:scalar qos|scalar layer)|"
                     r"(?:scalar qos|scalar layer).{0,80}"
                     r"(?:preserv|retain|unchang)",
                     explicit_clear.group(0), re.DOTALL)
    assert re.search(r"(?:full|complete) role[- ]definition replacement"
                     r".{0,180}(?:include|supply|send).{0,80}qos_state"
                     r".{0,120}retain", reference_lower, re.DOTALL)
    ordered(reference, ("builtin", "roles.qos_default",
                        "roles.qos_state_default", "roles.defs.<role>.qos",
                        "roles.defs.<role>.qos_state"))
    cadence = (reference + "\n" + operations).lower()
    assert re.search(r"(?:resolve|select|choose).{0,180}state.{0,120}"
                     r"(?:before|precede|then).{0,80}jitter", cadence,
                     re.DOTALL)
    assert re.search(r"(?:one|single|exactly one).{0,40}jitter|"
                     r"jitter.{0,40}(?:once|one)", cadence)
    assert re.search(r"issued.{0,100}(?:both|same|identical).{0,100}"
                     r"interval.{0,100}min(?:imum)? interval", cadence)
    assert re.search(r"twice.{0,100}issued.{0,80}interval", cadence)
    assert ("left == 0" in reference or "left == 0" in operations)

    assert re.search(r"service.{0,160}(?:outside|no).{0,80}"
                     r"(?:handout )?ledger", operations, re.IGNORECASE | re.DOTALL)
    assert re.search(r"service.{0,180}(?:origin|seeder).{0,180}"
                     r"(?:parsed|selected).{0,160}state", operations,
                     re.IGNORECASE | re.DOTALL)
    assert re.search(r"(?:global scalar|scalar global).{0,120}"
                     r"(?:global state|state).{0,120}cadence", operations,
                     re.IGNORECASE | re.DOTALL)
    assert re.search(r"unattributed.{0,80}legacy.{0,180}"
                     r"global-state", operations, re.IGNORECASE | re.DOTALL)
    assert re.search(r"\battributed\b.{0,100}legacy.{0,220}"
                     r"(?:selected|resolved).{0,140}state.{0,160}"
                     r"every possible owner", operations,
                     re.IGNORECASE | re.DOTALL)
    assert re.search(r"unattributed.{0,80}legacy", operations,
                     re.IGNORECASE | re.DOTALL)
    assert re.search(r"\battributed\b.{0,100}legacy", operations,
                     re.IGNORECASE | re.DOTALL)
    assert re.search(r"unreadable.{0,180}global cadence.{0,180}"
                     r"(?:fail[- ]closed).{0,180}"
                     r"(?:no candidates|no peers|withhold(?:s|ing)? candidates|"
                     r"empty candidate)",
                     operations, re.IGNORECASE | re.DOTALL)
    assert re.search(r"unreadable.{0,140}fallback", operations,
                     re.IGNORECASE | re.DOTALL)
    assert re.search(r"(?:shared|legacy).{0,80}NAT.{0,240}"
                     r"(?:max|maximum|slowest).{0,120}"
                     r"(?:interval|cadence).{0,120}"
                     r"(?:min|minimum|smallest).{0,120}(?:numwant|peer)",
                     operations, re.IGNORECASE | re.DOTALL)
    assert re.search(r"possible owners.{0,180}(?:state|owner).{0,180}"
                     r"(?:max|maximum|slowest).{0,160}"
                     r"(?:min|minimum|smallest)", operations,
                     re.IGNORECASE | re.DOTALL)

    downgrade = operations.lower()
    assert re.search(r"remove.{0,100}every.{0,100}(?:global|role).{0,100}state",
                     downgrade, re.DOTALL)
    assert re.search(r"(?:one|an) additional.{0,100}scalar-only.{0,100}"
                     r"commit", downgrade, re.DOTALL)
    for filename in ("peer-policy.json", "peer-policy.lkg.json"):
        assert filename in downgrade
    assert re.search(r"state-free.{0,80}schema[- ]1|schema[- ]1.{0,80}state-free",
                     downgrade, re.DOTALL)
    assert re.search(r"(?:do not|never).{0,80}retained.{0,80}"
                     r"state-bearing.{0,80}ring snapshot", downgrade,
                     re.DOTALL)
    assert "restricted-role" in downgrade and "quarantine" in downgrade
    assert re.search(r"(?:older|predating).{0,160}independent quarantine",
                     downgrade, re.DOTALL)
    assert re.search(r"not.{0,80}sufficient.{0,120}(?:quarantine|downgrad)",
                     downgrade, re.DOTALL)


def test_workstream_a_docs_separate_tracker_observability_and_api_only_state():
    """Acceptance 27/28 preserves scalar intent and the API-only boundary."""
    with open(os.path.join(DOCS, "observability.md")) as fh:
        observability = fh.read()
    with open(os.path.join(DOCS, "console.md")) as fh:
        console = fh.read()
    with open(os.path.join(REPO, "fleet", "README.md")) as fh:
        fleet = fh.read()
    with open(os.path.join(REPO, "CHANGELOG.md")) as fh:
        changelog = fh.read()

    obs = observability.lower()
    assert re.search(r"(?:scalar|legacy).{0,160}qos.{0,160}"
                     r"(?:instruction intent|pre-instructions)", obs,
                     re.DOTALL)
    assert re.search(r"tracker_qos.{0,160}(?:tracker|state).{0,160}"
                     r"(?:explain|source|provenance)", obs, re.DOTALL)
    for term in ("instruction", "control", "telemetry", "semantic",
                 "role artifact", "stamp", "serial", "envelope",
                 "heartbeat", "device configuration"):
        assert term in obs, term
    assert re.search(r"state.{0,160}tracker-only|tracker-only.{0,160}state",
                     obs, re.DOTALL)
    assert re.search(r"instruction.{0,80}(?:qos|control)|"
                     r"(?:qos|control).{0,80}instruction", obs, re.DOTALL)
    exclusion_verbs = ("never enters", "does not enter", "is excluded from",
                       "remains outside")
    exclusion_terms = ("instruction", "control", "telemetry", "semantic hashes",
                       "role artifact", "stamp", "serial", "envelope",
                       "heartbeat", "device configuration")
    exclusion_sentences = [sentence for sentence in re.split(r"(?<=[.!?])\s+", obs)
                           if "tracker-only" in sentence and
                           any(verb in sentence for verb in exclusion_verbs)]
    assert any(all(term in sentence for term in exclusion_terms)
               for sentence in exclusion_sentences)

    console_lower = console.lower()
    assert "qos_state" in console_lower
    assert re.search(r"qos_state.{0,160}(?:api-only|management api|documented api)",
                     console_lower, re.DOTALL)
    assert "no role-policy json editor" in console_lower

    fleet_lower = fleet.lower()
    for term in ("iris-role", "roles.csv", "scalar-only", "qos_state",
                 "qos_changed", "candidate-bound"):
        assert term in fleet_lower, term
    assert re.search(r"iris-role\s+export.{0,160}omit.{0,60}qos_state",
                     fleet_lower, re.DOTALL)
    assert re.search(r"iris-role\s+define.{0,160}(?:remove|clear).{0,80}state",
                     fleet_lower, re.DOTALL)
    assert re.search(r"iris-role\s+import.{0,160}(?:remove|clear).{0,80}state",
                     fleet_lower, re.DOTALL)
    assert re.search(r"(?:configure|preserve|remove).{0,100}state.{0,100}"
                     r"management api", fleet_lower, re.DOTALL)
    for verb in ("configure", "preserve", "remove"):
        assert re.search(r"%s.{0,120}state.{0,120}management api" % verb,
                         fleet_lower, re.DOTALL)
    assert re.search(r"replace.{0,160}(?:role|definition).{0,180}"
                     r"qos_state.{0,120}retain", fleet_lower, re.DOTALL)
    assert re.search(r"preview.{0,180}qos_changed", fleet_lower, re.DOTALL)
    assert re.search(r"candidate[- ]bound.{0,100}confirmation", fleet_lower,
                     re.DOTALL)
    assert "qos_state" in changelog and "tracker" in changelog.lower()


def test_workstream_a_docs_retain_existing_topology_and_drop_obsolete_cadence_claim():
    """Acceptance 27/28 adds no topology and leaves no stale cadence claim."""
    with open(os.path.join(DOCS, "architecture.md")) as fh:
        architecture = fh.read()
    with open(os.path.join(DOCS, "network-ports.md")) as fh:
        network = fh.read()
    allowed = ("reference.md", "operations.md", "observability.md",
               "architecture.md", "network-ports.md", "console.md")
    combined = ""
    for name in allowed:
        with open(os.path.join(DOCS, name)) as fh:
            combined += "\n" + fh.read()
    for path in (os.path.join(REPO, "fleet", "README.md"),
                 os.path.join(REPO, "CHANGELOG.md")):
        with open(path) as fh:
            combined += "\n" + fh.read()
    normalized = re.sub(r"\s+", " ", combined).lower()
    assert not re.search(r"no\s+independent\s+per[- ]state\s+"
                         r"cadence\s+setting", normalized)

    architecture_lower = architecture.lower()
    for component, responsibility in (
            ("catalog", "image metadata"),
            ("tracker", "announce"),
            ("management api", "server state"),
            ("telemetry service", "tracker")):
        assert re.search(r"\|\s*%s\s*\|[^|\n]*%s" %
                         (re.escape(component), responsibility),
                         architecture_lower)
    _assert_phase1_enforcement_boundary(architecture)
    assert "no new service" in architecture_lower
    assert "no new listener" in architecture_lower
    for line in architecture_lower.splitlines():
        assert not re.search(r"(?:adds?|introduces?|uses?)\s+(?:a\s+)?"
                             r"(?:new|additional)\s+(?:process|listener|service|flow|port)", line)

    network_lower = network.lower()
    for port in ("6969", "8443", "9443"):
        assert re.search(r"\|\s*%s\s*\|" % port, network_lower)
    _assert_phase1_network_relationship(network)
    assert "tracker https flow on 6969" in network_lower
    assert "console-to-management flow on 9443" in network_lower
    for line in network_lower.splitlines():
        assert not re.search(r"(?:adds?|introduces?|uses?)\s+(?:a\s+)?"
                             r"(?:new|additional)\s+(?:process|listener|service|flow|port)", line)


def test_workstream_d_docs_state_legacy_loss_and_downgrade_truth():
    """The operator surfaces describe the independent quarantine limit."""
    with open(os.path.join(DOCS, "operations.md")) as fh:
        operations = fh.read().lower()
    with open(os.path.join(REPO, "CHANGELOG.md")) as fh:
        changelog = fh.read().lower()

    def sentences(text):
        return re.split(r"(?<=[.!?])\s+", text)

    op_paragraphs = re.split(r"\n\s*\n", operations)
    op_sentences = sentences(operations)
    assert any("ordinary" in line and "acl" in line and
               re.search(r"preserv|retain", line)
               for line in op_sentences)
    assert any("legacy" in line and
               re.search(r"no surviving|cannot recover|unrecoverable|lost",
                         line) and "ordinary" in line
               for line in op_sentences)
    downgrade = next((paragraph for paragraph in op_paragraphs
                      if re.search(r"older|predating", paragraph) and
                      "independent quarantine" in paragraph), "")
    assert downgrade
    assert re.search(r"ignore|does not understand|incompatible", downgrade)
    assert re.search(r"independent quarantine.{0,180}"
                     r"(?:not sufficient|insufficient|cannot|ignore)",
                     downgrade, re.DOTALL)
    assert "quarantine restricted devices before downgrading" not in downgrade
    assert "quarantine restricted devices before downgrading" not in operations
    assert "pre-d" not in operations
    assert any("revoke" in line and "quarantine" in line and
               re.search(r"retain|preserv", line)
               for line in op_sentences)
    assert any(re.search(r"retir", line) and "quarantine" in line and
               re.search(r"clear|remove", line)
               for line in op_sentences)

    unreleased = changelog.split("## [unreleased]", 1)[1]
    unreleased = unreleased.split("\n## ", 1)[0]
    assert "unreleased" in changelog
    assert "pre-d" not in unreleased
    assert re.search(r"ordinary.{0,100}(?:acl|assignment).{0,120}preserv",
                     unreleased, re.DOTALL)
    assert re.search(r"legacy.{0,180}(?:history|unrecover|limitation|lost)",
                     unreleased, re.DOTALL)
    assert re.search(r"(?:older|predating).{0,180}(?:incompatib|downgrad)",
                     unreleased, re.DOTALL)


# ---------------------------------------------------------------------------
# Phase 1 encrypted-instruction operator contract.


_NETWORK_SENTENCE = "No new listener, port, network path, or firewall flow"


def _compact(text):
    return re.sub(r"\s+", " ", text).strip()


def _units(text):
    """Prose sentences, table rows, and paragraphs used for relationship tests."""
    paragraphs = [unit for unit in re.split(r"\n\s*\n", text)
                  if unit.strip()]
    sentences = []
    for paragraph in paragraphs:
        paragraph = re.sub(r"\s+", " ", paragraph).strip()
        sentences.extend(re.split(r"(?<=[.!?])\s+", paragraph))
    return [unit for unit in list(text.splitlines()) + paragraphs + sentences
            if unit.strip()]


def _assert_unit(text, terms, message):
    wanted = tuple(term.lower() for term in terms)
    assert any(all(term in unit.lower() for term in wanted)
               for unit in _units(text)), message


def _assert_ordered(text, terms, message, distance=500):
    pattern = ".{0,%d}" % distance
    expression = pattern.join(re.escape(term) for term in terms)
    assert re.search(expression, text, re.IGNORECASE | re.DOTALL), message


def _section(text, heading, next_heading=None):
    """Return one Markdown section so relationships cannot match elsewhere."""
    parts = text.split(heading, 1)
    assert len(parts) == 2, "missing section: %s" % heading
    section = parts[1]
    if next_heading:
        section = section.split(next_heading, 1)[0]
    return section


def _assert_phase1_network_relationship(text):
    """One canonical topology assertion shared by all three network guards."""
    lower = text.lower()
    assert _NETWORK_SENTENCE.lower() in lower
    _assert_unit(text, ("GET /v1/devices/{device_id}/instructions", "8443",
                        "existing", "catalog"),
                 "instruction requests must reuse catalog HTTPS 8443")
    _assert_unit(text, ("GET /v1/devices/{device_id}/instruction-keylist",
                        "8443", "authenticated"),
                 "the keylist must use the authenticated catalog path")
    _assert_unit(text, ("9443", "Console", "management", "only"),
                 "9443 must remain Console-to-server management only")


def _assert_phase1_enforcement_boundary(text):
    _assert_unit(text, ("tracker", "origin", "enforce"),
                 "server-side tracker/origin enforcement must remain authoritative")
    _assert_unit(text, ("device", "accepted", "LKG", "QoS"),
                 "device accepted/LKG/QoS state must not be described as server state")


def _assert_phase1_rollup_relationship(text):
    _assert_unit(text, ("fleet_rollup", "issued_revision", "nullable"),
                 "issued revision must be documented as current-or-null")
    _assert_unit(text, ("fleet_rollup", "applied", "policy revision"),
                 "applied rollup must count accepted policy revisions")
    for unit in _units(text):
        lower = unit.lower()
        affirmative = re.search(
            r"(?:fleet_rollup|applied).{0,100}"
            r"(?:group(?:ed|s)?|key(?:ed|s)?|index(?:ed|es)?|count(?:ed|s)?)"
            r".{0,80}(?:by|on|using).{0,60}instruction serial", lower)
        negative = re.search(
            r"(?:not|never)\s+(?:grouped\s+|keyed\s+|indexed\s+)?"
            r"(?:by\s+)?instruction serial", lower)
        if affirmative and not negative:
            raise AssertionError("fleet rollup must not key on instruction serial")



def test_docs_phase1_honest_guarantee_and_admin_boundary():
    """The exact promise and its cross-page pointer keep the admin limit honest."""
    guarantee = """The encrypted instruction file is confidential against users
    below privilege 15, against offline copies of flash and `show tech`, against
    swarm peers and network observers, and against reuse on another device. It
    is not, and cannot be, confidential against the device's own administrator,
    who is root where the agent runs and holds every key the agent holds. Its
    integrity and authenticity hold against everyone including that
    administrator once the verification root is pinned inside the signed image;
    on Guest Shell, and on any platform where the package signature is not
    enforced, integrity is tamper-evidence rather than tamper-proofing. Role
    isolation, announce cadence, peer discovery and origin rates are enforced by
    the tracker and the origin and do not depend on any device honouring
    anything."""
    security = _page("security.md")
    assert _compact(guarantee) in _compact(security)
    _assert_unit(security, ("privilege-15", "root-lr", "administrator", "root"),
                 "the device-administrator capabilities must share one clause")
    _assert_unit(security, ("tracker", "origin", "enforcement", "authoritative"),
                 "the enforcement-of-record relationship is missing")
    assert "(security.md#device-administrator-trust-boundary)" in \
        _page("device-agents.md")


def test_docs_phase1_envelope_custody_and_failure_contract():
    """Envelope, key placement, credential widths, and failures are relational."""
    security = _page("security.md")
    _assert_unit(security, ("SP800-108", "HMAC-SHA-256", "per-device",
                            "audience"),
                 "the named per-device KDF must bind the audience")
    _assert_unit(security, ("epoch", "instruction serial", "replay"),
                 "epoch and serial must explain replay rejection")
    _assert_unit(security, ("MAC", "before", "decrypt"),
                 "authentication must precede decryption")
    _assert_unit(security, ("MAC", "signature", "before", "apply"),
                 "authentication and signature checks must precede apply")
    _assert_unit(security, ("256 KiB", "reject", "before", "cryptograph"),
                 "the envelope cap must reject before cryptographic work")
    _assert_unit(security, ("exactly two", "distinct", "offline roots"),
                 "the trust set must contain exactly two distinct roots")
    _assert_unit(security, ("instruction key", "excluded", "platform configuration"),
                 "instruction private material must be excluded from platform config")
    _assert_unit(security, ("private keys", "instruction keys", "LKG key",
                            "never", "platform configuration"),
                 "all private instruction material must stay out of platform config")
    _assert_unit(security, ("IOx", "enrollment token", "SSH-to-self password",
                            "run-opts"),
                 "IOx bootstrap credential exceptions must be stated together")
    _assert_unit(security, ("XR", "enrollment token", "docker-run-opts"),
                 "XR bootstrap credential exception must be explicit")
    enrollment_units = [unit.lower() for unit in _units(security)
                        if "enrollment" in unit.lower() and
                        ("3,600" in unit or "3600" in unit) and
                        "120" in unit and "overlap" in unit.lower()]
    assert enrollment_units, "enrollment lifetime and overlap must be related"
    _assert_unit(security, ("bearer", "128", "key material", "256"),
                 "bearer and cryptographic-key widths must be distinguished")
    _assert_unit(security, ("unknown", "width", "reject", "before mint"),
                 "unknown/mismatched widths must fail before minting")

    operations = _page("operations.md")
    _assert_unit(operations, ("leaked", "honest device", "rotate --no-overlap"),
                 "leaked key on an honest device must map to no-overlap rotation")
    _assert_unit(operations, ("compromised", "retired", "iris-revoke"),
                 "compromised or retired devices must map to revocation")
    _assert_unit(operations, ("revoked", "rotation", "refused"),
                 "rotation must never spare a revoked device")

    problems = _page("problems.md")
    for code in ("instruction-keylist-unavailable", "instruction-keylist-missing",
                 "instruction-state-unavailable", "instruction-stamp-missing",
                 "stale_pointer", "instruction-device-forbidden",
                 "instruction-rate-limit-exceeded"):
        assert "## %s" % code in problems

    failures = _page("device-agents.md") + "\n\n" + _page("reference.md")
    for state, action in (
            ("none", "defaults"), ("applied", "serial"), ("lkg", "keep"),
            ("stale_expired", "on_stale"),
            ("allowlist_expired", "tracker-only"),
            ("rollback_rejected", "keep"), ("floor_reset", "floor"),
            ("audience_mismatch", "keep"),
            ("tamper_rejected", "keep"), ("verifier_missing", "defaults"),
            ("lkg_rejected", "defaults"), ("lkg_unreadable", "defaults"),
            ("oversize", "next tick"), ("reasserted", "aria2 session"),
            ("instr_unavailable", "next tick"),
            ("instr_pending", "next tick"),
            ("instr_forbidden", "refresh"), ("tracker-only", "no instruction")):
        _assert_unit(failures, (state, action),
                     "%s lacks its operator action/status relationship" % state)
    _assert_unit(failures, ("fetch", "verify", "LKG", "heartbeat", "staging continue"),
                 "fetch/verify fallback must retain heartbeat and staging")
    _assert_unit(failures, ("RPC apply", "heartbeat", "staging", "skipped", "tick"),
                 "RPC apply failure must send heartbeat and skip staging that tick")
    _assert_unit(failures, ("key_rejected", "unknown_key", "one",
                            "unscheduled", "refresh", "latched key id"),
                 "unknown keys must trigger one latched unscheduled refresh")
    _assert_unit(failures, ("key_rejected", "bad_mac", "no", "refresh",
                            "violation"),
                 "known-key bad MAC must be a violation without refresh")
    _assert_unit(failures, ("401", "403", "instr_forbidden", "one",
                            "refresh", "no in-tick", "loop"),
                 "forbidden responses need one refresh without an in-tick loop")
    _assert_unit(failures, ("404", "instr_unavailable", "next tick"),
                 "instruction 404 must wait until the next tick")
    _assert_unit(failures, ("409", "stale_pointer", "instr_pending",
                            "next tick", "no", "sleep"),
                 "stale pointers must remain pending without an in-tick sleep")
    _assert_unit(failures, ("429", "5xx", "transport", "instr_unavailable",
                            "next tick"),
                 "rate/server/transport failures must remain unavailable")
    _assert_unit(failures, ("deny", "expired", "remain", "effective"),
                 "expired deny posture must remain restrictive")
    _assert_unit(failures, ("allow", "expired", "tracker-only",
                            "independent", "on_stale"),
                 "expired allow posture must fail to tracker-only")
    _assert_unit(failures, ("on_stale=keep", "QoS", "retain"),
                 "stale keep must retain verified QoS")
    _assert_unit(failures, ("on_stale=defaults", "QoS", "defaults"),
                 "stale defaults must restore fixed QoS defaults")
    _assert_unit(failures, ("body serial", "higher", "pointer", "apply"),
                 "a body ahead of its pointer must still apply")
    _assert_unit(failures, ("body serial", "lower", "pointer", "fresh",
                            "pointer_skew", "apply"),
                 "a fresh body below its pointer must apply with skew evidence")
    _assert_unit(failures, ("at or below", "accepted floor", "rollback",
                            "reject"),
                 "a body at or below the replay floor must be rejected")
    _assert_unit(failures, ("equal identity", "different bytes", "reject"),
                 "equal identity with changed bytes must be rejected")


def test_docs_phase1_runtime_knobs_and_guestshell_divergence():
    reference = _page("reference.md")
    _assert_unit(reference, ("max_peers", "parsed", "ignored", "MAX-PEERS-IGNORED"),
                 "legacy max_peers must be parse-only with one notice")
    _assert_unit(reference, ("IRIS_MAX_PEERS", "IRIS_MAX_CONCURRENT",
                             "provisional", "first successful tick"),
                 "legacy env values need their bounded launch interval")
    _assert_unit(reference, ("IRIS_TICK_SECONDS", "mechanical", "catalog_tick_s",
                             "logical"),
                 "mechanical and signed logical cadence must be distinct")
    rows = [line for line in reference.splitlines()
            if re.match(r"\|\s*`max_peers`\s*\|", line)]
    assert rows and all("65535" not in row for row in rows)

    agents = _page("device-agents.md")
    for terms in (("Guest Shell", "runtime probe", "tracker-only"),
                  ("Guest Shell", "replaceable bundle", "tamper-evidence"),
                  ("Guest Shell", "IOS-owned", "60"),
                  ("IOx", "XR", "signed image", "pinned")):
        _assert_unit(agents, terms, "Guest Shell divergence row is incomplete")
    _assert_unit(_page("security.md"),
                 ("Guest Shell", "RPC secret", "mode-0600", "conf-path",
                  "command line"),
                 "Guest Shell RPC-secret argv mitigation is missing")
    _assert_unit(_page("containers.md"),
                 ("mechanical tick", "reassert", "heartbeat", "signed"),
                 "each mechanical tick must reassert and heartbeat")


def test_docs_phase1_iox_verification_transaction():
    iox = _page("iox.md")
    transaction = _section(iox, "## App-hosting verification transaction",
                           "## ")
    _assert_unit(transaction, ("device-global", "app-hosting verification"),
                 "the IOx control scope must be named")
    _assert_unit(transaction, ("signed wrapper", "no", "state change"),
                 "signed wrappers must leave verification unchanged")
    _assert_ordered(transaction, ("initially enabled", "record", "disable",
                                  "install", "restore", "read-back", "activate"),
                    "enabled-state transaction order is incomplete", 400)
    _assert_unit(transaction, ("initially disabled", "unchanged"),
                 "pre-disabled state must remain disabled")
    _assert_unit(transaction, ("unknown", "refuse", "mutation", "install"),
                 "unknown state must refuse mutation and installation")
    _assert_unit(transaction, ("crash", "resume", "durable", "obligation"),
                 "crash recovery must use the durable obligation")
    _assert_unit(transaction,
                 ("uninstall", "IRIS-owned", "never", "blindly enable"),
                 "uninstall may recover only owned obligations")
    _assert_unit(transaction, ("signature marker", "not", "cryptographic"),
                 "package markers must not be presented as verification")

    first = ("https://www.cisco.com/c/en/us/td/docs/switches/lan/"
             "cisco_ie3X00/software/17_14/b_cisco-iox-ie3x00-switches/"
             "m-ie3400-deploying-iox-applications.html")
    second = ("https://www.cisco.com/c/en/us/support/docs/switches/"
              "catalyst-9500-series-switches/222780-understand-app-hosting-on-"
              "catalyst-9000.html")
    assert first in transaction and second in transaction

    for name, terms in (
            ("getting-started.md", ("before onboarding", "device-global", "verification")),
            ("security.md", ("IOx", "signed", "verification enabled", "container")),
            ("operations.md", ("IOx", "verification obligation", "recover", "uninstall")),
            ("console.md", ("IOx", "verification obligation", "recover"))):
        _assert_unit(_page(name), terms, "%s omits its IOx operator consequence" % name)


def test_docs_phase1_network_process_and_state_topology():
    _assert_phase1_network_relationship(_page("network-ports.md"))
    server = _page("server.md")
    for path, custody in (
            ("$IRIS_CONFIG/instr/signing-key.age", "encrypted"),
            ("$IRIS_RUN/instr/signing-key", "plaintext runtime"),
            ("$IRIS_CONFIG/instr/signing-key.pub", "public"),
            ("$IRIS_CONFIG/instr/signing-key-cert.pub", "public"),
            ("$IRIS_CONFIG/instr/roots.d/", "public"),
            ("$IRIS_RUN/instr/signing-key-cert.pub", "public runtime"),
            ("$IRIS_STATE/instructions-epoch.json", "durable"),
            ("$IRIS_STATE/instructions-epoch.json.lock", "lock"),
            ("$IRIS_STATE/instructions/keylist.current", "durable"),
            ("$IRIS_STATE/instructions/keylist-state.json", "durable"),
            ("$IRIS_STATE/instructions/keylist.lock", "lock"),
            ("$IRIS_STATE/instructions/roles.d/", "durable"),
            ("$IRIS_STATE/instructions/role-state.json", "durable"),
            ("$IRIS_STATE/instructions/activation.json", "durable"),
            ("$IRIS_STATE/instructions/producer.lock", "lock"),
            ("$IRIS_STATE/instructions/admitted-devices.json", "durable"),
            ("$IRIS_STATE/instructions/serial-history.json", "durable"),
            ("$IRIS_STATE/instructions/roles.lock", "lock"),
            ("$IRIS_STATE/instruction-key-status.json", "status"),
            ("$IRIS_STATE/instruction-stamper-status.json", "status")):
        _assert_unit(server, (path, custody),
                     "%s lacks its custody classification" % path)
    _assert_unit(server, ("stamper", "daemon thread", "management process",
                          "five", "not", "sixth service"),
                 "stamper process topology is missing")
    _assert_phase1_enforcement_boundary(_page("architecture.md"))


def test_docs_phase1_kubernetes_and_split_host_custody():
    kubernetes = _page("kubernetes.md")
    _assert_unit(kubernetes, ("Phase 1", "existing", "iris-data", "PVC"),
                 "Phase 1 state must use the existing PVC")
    _assert_unit(kubernetes, ("no new", "Secret", "port", "Service",
                              "NetworkPolicy"),
                 "Phase 1 must add no Kubernetes topology object")
    _assert_unit(kubernetes, ("instruction", "single writer", "no cross-pod",
                              "replicas: 1"),
                 "instruction single-writer state must explain replica one")

    split = _page("docker-hosts.md")
    _assert_unit(split, ("server host only", "signing-key.age", "age identity",
                         "runtime signing key", "instruction state"),
                 "private custody material must remain on the server host")
    _assert_unit(split, ("public roots", "not secrets"),
                 "public trust material must not be called secret")

    validation = _page("validation.md")
    for layout, terms in (
            ("single-host Compose", ("custody", "stamp", "LKG", "drift",
                                     "artifact provenance", "8443", "9443")),
            ("split-host Compose", ("custody", "stamp", "LKG", "drift",
                                    "artifact provenance", "server host",
                                    "Console")),
            ("single-replica Kubernetes", ("custody", "stamp", "LKG",
                                            "drift", "artifact provenance",
                                            "PVC", "NetworkPolicy")),
            ("multi-replica server tier", ("not covered", "unsupported"))):
        _assert_unit(validation, (layout,) + terms,
                     "%s validation is not operationally meaningful" % layout)


def test_docs_phase1_operations_root_and_offline_runbooks():
    operations = _page("operations.md")
    _assert_unit(operations, ("quarterly", "two roots", "custodians", "sites",
                              "fingerprint"),
                 "quarterly two-root ceremony is incomplete")
    _assert_ordered(operations, ("one-root loss", "surviving root",
                                 "online certificate", "unchanged trust"),
                    "one-root failover must leave device trust unchanged")
    _assert_ordered(operations, ("both-roots-lost", "two new roots",
                                 "online certificate", "keylist", "Guest Shell",
                                 "OCI", "both IOx", "XR", "fleet reprovision"),
                    "both-root recovery must rebuild all package families", 220)
    _assert_unit(operations, ("offline", "bootstrap envelope", "ciphertext",
                              "not", "key"),
                 "offline payload must be identified as ciphertext, not a key")
    _assert_ordered(operations, ("sidecar", "before", "archive", "mismatch",
                                 "previous runnable bundle"),
                    "Guest Shell rollout must order evidence and retain rollback")
    _assert_unit(operations, ("authenticated refresh", "next", "self-heal"),
                 "offline bootstrap must converge through authenticated refresh")


def test_docs_phase1_observability_states_evidence_and_revisions():
    observability = _page("observability.md")
    _assert_phase1_rollup_relationship(observability)
    _assert_unit(observability, ("instr_protocol", "absent", "pre-instructions"),
                 "legacy protocol absence must map to pre-instructions")
    _assert_unit(observability, ("instr_protocol", "invalid", "unknown"),
                 "invalid protocol evidence must map to unknown")
    _assert_unit(observability, ("revoked", "server-observed", "precedence",
                                 "underlying"),
                 "durable revocation must override but retain device evidence")
    _assert_unit(observability, ("stale", "server-observed", "underlying",
                                 "agent-asserted"),
                 "receipt-age stale state must retain underlying evidence")
    _assert_unit(observability, ("unavailable", "unknown", "not", "zero"),
                 "unavailable evidence must not be rendered as healthy zero")
    _assert_unit(observability, ("violation = 0", "does not mean compliant"),
                 "zero violation is not proof of compliance")
    _assert_unit(observability, ("announce", "uploaded", "downloaded",
                                 "device-authored"),
                 "announce counters must be labeled device-authored")
    _assert_unit(observability, ("heartbeat", "instruction", "agent-asserted"),
                 "heartbeat instruction facts must be labeled agent-asserted")
    _assert_unit(observability, ("policy_revision", "server-issued", "intent"),
                 "policy revision meaning is missing")
    _assert_unit(observability, ("instr_serial", "per-device", "freshness"),
                 "instruction serial meaning is missing")
    _assert_unit(observability, ("applied_revision", "aria2", "blocklist",
                                 "unrelated"),
                 "blocklist revision must be separated from policy/serial")

    reference = _page("reference.md")
    _assert_unit(reference, ("raw", "instr_state", "agent-asserted"),
                 "raw device states must be labeled as agent evidence")
    _assert_unit(reference, (
        "raw states", "none", "applied", "lkg", "stale_expired",
        "allowlist_expired", "rollback_rejected", "floor_reset",
        "audience_mismatch", "key_rejected", "tamper_rejected",
        "verifier_missing", "lkg_rejected", "lkg_unreadable", "oversize",
        "reasserted", "instr_unavailable", "instr_pending",
        "instr_forbidden", "tracker-only"),
        "the closed raw-state vocabulary must be identified as one contract")
    _assert_unit(reference, (
        "display classes", "applied", "lkg", "stale", "rejected",
        "unavailable", "tracker-only", "pending", "forbidden",
        "floor_reset", "none", "pre-instructions", "revoked", "unknown",
        "server"),
        "server display classes must be separate from raw states")
    console = _page("console.md")
    _assert_unit(console, ("label", "server-created", "exact", "integer"),
                 "Console labels must preserve exact i63 identity")
    _assert_unit(console, ("stale", "revoked", "underlying", "evidence"),
                 "Console overrides must preserve underlying evidence")


def test_docs_phase1_changelog_and_release_boundary():
    with open(os.path.join(REPO, "CHANGELOG.md")) as fh:
        changelog = fh.read()
    parts = changelog.split("## [Unreleased]", 1)
    assert len(parts) == 2
    unreleased = parts[1].split("\n## ", 1)[0]
    _assert_unit(unreleased, ("encrypted instructions", "key custody",
                              "Guest Shell", "IOx verification"),
                 "Unreleased must summarize the Phase 1 operator change")
    _assert_unit(unreleased, ("server-observed", "agent-asserted", "Console"),
                 "Unreleased must identify the evidence-aware Console")
    for unit in _units(unreleased):
        if "phase 1" not in unit.lower():
            continue
        assert not re.search(
            r"\b(?:is|was|has been|now)\s+(?:released|deployed)\b|"
            r"\blive fleet\s+(?:is\s+|was\s+)?verified\b",
            unit, re.IGNORECASE)

    boundary = (_page("security.md") + "\n" + _page("operations.md") +
                "\n" + _page("observability.md"))
    _assert_unit(boundary, ("mutual-origin", "preflight only", "issue #153"),
                 "the open mutual-origin boundary must remain explicit")
    _assert_unit(boundary, ("one full tagged release", "dwell",
                            "separately authorized activation"),
                 "the activation gate must retain release dwell and authority")
