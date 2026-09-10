# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re


REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DASHBOARDS = os.path.join(REPO, "docs", "zensical", "dashboards")
SERVER = os.path.join(REPO, "server")
LEGACY_OPERATOR_WORDING = re.compile(
    r"(?<![A-Za-z_])(?:un)?attributed(?![A-Za-z_])", re.IGNORECASE)
COMPATIBILITY_METRICS = (
    "iris_peer_attributed_bytes_total",
    "iris_peer_unattributed_bytes_total",
    "iris_swarm_peers_attributed",
)


def test_dashboards_use_traced_wording_for_operators():
    """Metric identifiers stay compatible; prose uses traced/untraced."""
    for name in ("grafana-iris-swarm.json", "splunk-iris-swarm.xml"):
        with open(os.path.join(DASHBOARDS, name)) as stream:
            text = stream.read()
        assert LEGACY_OPERATOR_WORDING.search(text) is None, name
        assert all(metric in text for metric in COMPATIBILITY_METRICS), name


def test_swarmmap_verify_label_is_not_ios_specific():
    text = open(os.path.join(SERVER, "swarmmap.html"), encoding="utf-8").read()
    assert "IOS copy /verify" not in text, \
        "the verify row label must not name IOS: XR devices report 'unsupported' here"
    assert "Device copy verification" in text


def test_swarmmap_still_reads_the_persisted_wire_field():
    text = open(os.path.join(SERVER, "swarmmap.html"), encoding="utf-8").read()
    assert "ios_copy_verify_state" in text, \
        "the wire field name is persisted and must not be renamed"


# ---------------------------------------------------------------------------
# Query-shape gates.
#
# Nothing in the repo used to parse either dashboard, which is how a set of
# silently-empty queries survived (IRIS-16-001 .. 16-004). These assert the
# rules the dashboards state about themselves.

def _splunk_text():
    with open(os.path.join(DASHBOARDS, "splunk-iris-swarm.xml"),
              encoding="utf-8") as stream:
        return stream.read()


def _grafana():
    import json
    with open(os.path.join(DASHBOARDS, "grafana-iris-swarm.json"),
              encoding="utf-8") as stream:
        return json.load(stream)


def test_splunk_dashboard_is_well_formed_xml():
    import xml.etree.ElementTree as ET
    ET.parse(os.path.join(DASHBOARDS, "splunk-iris-swarm.xml"))


def test_splunk_peer_evidence_collapses_repeated_capture_before_aggregation():
    """A Console pull repeats the same counters with a fresh report/event id.
    The real Splunk fixture checks the arithmetic; this guards both shipped
    copies against returning to event-id-only deduplication."""
    import xml.etree.ElementTree as ET
    document = open(os.path.join(REPO, "docs", "zensical", "splunk.md")).read()
    section = document.split("### Peer-to-peer evidence\n", 1)[1].split(
        "### Assignment to confirmed seeding", 1)[0]
    docs_queries = re.findall(r"```spl\n(.*?)```", section, re.S)
    xml_queries = [query.text for query in ET.fromstring(_splunk_text()).iter("query")
                   if '"otel.log.name"="iris.device.peer_transfer_record"' in query.text]
    assert len(docs_queries) == len(xml_queries) == 3
    for query in docs_queries + xml_queries:
        commands = [command.strip() for command in query.split("|")]
        numeric = next(i for i, command in enumerate(commands)
                       if command.startswith("eval received_bytes=tonumber("))
        maximum = commands.index("sort 0 -received_bytes")
        collapse = commands.index(
            'dedup "device.id" "iris.image.id" "iris.transfer.id" "network.peer.address"')
        assert numeric < maximum < collapse
        # Filtering to device rows first could resurrect an older device
        # classification that the selected cumulative capture did not carry.
        assert '"iris.peer.attribution"="device"' not in commands[0]
        aggregations = [i for i, command in enumerate(commands)
                        if command.startswith(("stats ", "timechart ", "table "))]
        assert aggregations and min(aggregations) > collapse


def test_splunk_per_sender_table_keeps_distinct_unknown_peer_addresses():
    document = open(os.path.join(REPO, "docs", "zensical", "splunk.md")).read()
    query = next(query for query in re.findall(r"```spl\n(.*?)```", document, re.S)
                 if "max(received_bytes)" in query)
    group = query.split("BY ", 1)[1]
    assert '"network.peer.address"' in group


def test_splunk_eval_syntax_single_quotes_dotted_fields():
    """The file's own header states the rule: dotted field names need SINGLE
    quotes in eval syntax, which `where` uses. A double-quoted token there is a
    string LITERAL, so `where "iris.image.id"==img_cat` compares the constant
    string against the value and silently discards every row -- indistinguishable
    from "no device reported in this window"."""
    offenders = [line.strip()[:120]
                 for line in _splunk_text().splitlines()
                 if re.search(r'\|\s*where\s+[^|]*"iris\.', line)]
    assert not offenders, (
        "SPL `where` clause comparing a double-quoted dotted field name (a "
        "string literal, not the field) -- single-quote it:\n  "
        + "\n  ".join(offenders))


def test_grafana_never_rates_the_untraced_residue_gauge():
    """iris_peer_unattributed_bytes_total is emitted as a GAUGE: it is
    max(0, origin - traced) and steps DOWN when a device is traced late. rate()
    reads each step down as a counter reset and renders a positive spike exactly
    when tracing improved -- inverting the panel's meaning. Panels 16 and 17 and
    server/metrics.py all forbid it in prose; this enforces it."""
    forbidden = re.compile(
        r"(?:rate|irate|increase|deriv|resets)\s*\(\s*"
        r"[^)]*iris_peer_unattributed_bytes_total")
    bad = []
    for panel in _grafana().get("panels", []):
        for target in panel.get("targets", []) or []:
            expr = target.get("expr") or ""
            if forbidden.search(expr):
                bad.append("panel %s (%s) target %s"
                           % (panel.get("id"), panel.get("title"),
                              target.get("refId")))
    assert not bad, \
        "rate()/increase()/deriv()/resets() applied to the residue gauge: %s" % bad


def test_grafana_image_picker_uses_catalog_ids_and_passes_non_bin_images():
    """The one image picker mirrors publish.derive_id: .SPA.bin/.bin is
    stripped, while every other basename stays unchanged. A regex that does
    not match drops the value from Grafana's option list entirely."""
    variables = _grafana()["templating"]["list"]
    image_vars = [v for v in variables if v.get("name") == "image"]
    assert len(image_vars) == 1
    assert not any(v.get("name") == "image_catalog_id" for v in variables)
    var = image_vars[0]
    assert var["hide"] == 0
    assert var["multi"] is True
    assert var["includeAll"] is True
    assert var["allValue"] == ".*"
    body = var["regex"].strip("/")
    compiled = re.compile(body)
    for name, expected in (
            ("cat9k_iosxe.17.09.05.SPA.bin", "cat9k_iosxe.17.09.05"),
            ("c8000v.17.15.bin", "c8000v.17.15"),
            ("xr-8000.iso", "xr-8000.iso"),
            ("bundle.tar", "bundle.tar"),
            ("iris-xr.rpm", "iris-xr.rpm")):
        match = compiled.match(name)
        assert match, "%s drops out of the option list entirely" % name
        assert match.group(1) == expected, \
            "%s -> %r, expected %r" % (name, match.group(1), expected)


def test_grafana_single_image_picker_filters_every_prometheus_and_loki_leg():
    """Catalog-id reports and basename metrics/logs use the same selection.

    This pins every current image-bearing target, not only the five mixed
    arithmetic panels: adding a new raw ``$image`` matcher would otherwise
    silently reintroduce two incompatible identifier forms elsewhere.
    """
    dash = _grafana()
    basename = '(${image})(([.]SPA)?[.]bin)?'
    catalog = '${image}'
    prometheus = set()
    reports = set()
    peers = set()
    for panel in dash["panels"]:
        for target in panel.get("targets", []) or []:
            expr = target.get("expr") or ""
            source = (target.get("datasource") or {}).get("type")
            key = (panel["id"], target.get("refId"))
            if source == "prometheus" and "image=~" in expr:
                prometheus.add(key)
                assert 'image=~"%s"' % basename in expr, key
                assert 'image=~"$image"' not in expr, key
            if source != "loki" or "iris_image_id=~" not in expr:
                continue
            if 'otel_log_name="iris.device.transfer.report"' in expr:
                reports.add(key)
                assert 'iris_image_id=~"%s"' % catalog in expr, key
                assert basename not in expr, key
            elif ('otel_log_name="iris.swarm.peer_bytes"' in expr or
                  'otel_log_name="iris.swarm.peer_rate"' in expr):
                peers.add(key)
                assert 'iris_image_id=~"%s"' % basename in expr, key
            else:
                raise AssertionError("unclassified Loki image target %r" %
                                     (key,))

    assert prometheus == {
        (5, "A"), (6, "B"), (7, "B"), (8, "A"), (9, "A"),
        (11, "A"), (12, "A"), (13, "A"), (14, "A"), (14, "B"),
        (16, "A"), (16, "B"), (17, "A"), (18, "A"), (20, "A"),
        (20, "B"), (20, "C"), (20, "D"), (20, "E"), (20, "F"),
        (20, "G"), (20, "H"), (20, "I"), (20, "J"), (21, "A"),
        (21, "B"), (21, "C"), (22, "A"), (23, "A"), (23, "B"),
        (29, "A"), (30, "A"), (31, "A"), (33, "A"), (34, "A"),
    }
    assert reports == {
        (4, "A"), (6, "A"), (7, "A"), (11, "L"), (12, "L"),
        (32, "B"),
    }
    assert peers == {
        (25, "A"), (26, "A"), (27, "A"), (28, "A"), (32, "A"),
    }

    info_hash = next(v for v in dash["templating"]["list"]
                     if v.get("name") == "info_hash")
    assert 'image=~"%s"' % basename in info_hash["definition"]
    assert 'image=~"%s"' % basename in info_hash["query"]["query"]


def test_grafana_image_matchers_have_valid_quoted_strings_and_literal_suffixes():
    """Quoted PromQL/LogQL regex strings need a second escaping layer.

    These printable matchers use the JSON-compatible subset of Go string
    literals. Decode that layer before checking regex behavior, so a raw
    backslash-dot cannot pass merely because Python's regex accepts it.
    """
    dash = _grafana()
    expressions = [target.get("expr", "")
                   for panel in dash["panels"]
                   for target in panel.get("targets", []) or []]
    info_hash = next(v for v in dash["templating"]["list"]
                     if v.get("name") == "info_hash")
    expressions.extend((info_hash["definition"], info_hash["query"]["query"]))
    checked = 0
    for expression in expressions:
        if "(${image})(" not in expression:
            continue
        expression = expression.replace("${image}", "image-test")
        literals = re.findall(r'(?:image|iris_image_id)=~("(?:[^"\\]|\\.)*")',
                              expression)
        assert literals, expression
        for literal in literals:
            pattern = re.compile(json.loads(literal))
            for name in ("image-test", "image-test.bin", "image-test.SPA.bin"):
                assert pattern.fullmatch(name), (literal, name)
            for name in ("image-testxbin", "image-testxSPAxbin", "other.bin"):
                assert not pattern.fullmatch(name), (literal, name)
            checked += 1
    assert checked > 40


def test_grafana_dotted_multi_selection_uses_datasource_escaping_and_grouping():
    """Default datasource interpolation escapes both regex and query strings.

    Grafana's Prometheus formatter groups multi-values; Loki's joins with |.
    These fixtures represent their documented/source-tested output for two
    dotted IDs. Explicit :regex would bypass that second escaping layer, and
    omitting our outer grouping would apply the suffix only to Loki's last ID.
    """
    dash = _grafana()
    expressions = [(target.get("expr", ""),
                    (target.get("datasource") or {}).get("type"))
                   for panel in dash["panels"]
                   for target in panel.get("targets", []) or []]
    info_hash = next(v for v in dash["templating"]["list"]
                     if v.get("name") == "info_hash")
    expressions.extend(((info_hash["definition"], "prometheus"),
                        (info_hash["query"]["query"], "prometheus")))
    selected = ("cat9k.26.01", "c8000v.26.01")
    escaped_values = r'cat9k\\.26\\.01|c8000v\\.26\\.01'
    checked = 0
    for expression, source in expressions:
        if "${image" not in expression:
            continue
        assert "${image:regex}" not in expression, expression
        assert source in ("prometheus", "loki")
        replacement = ("(" + escaped_values + ")"
                       if source == "prometheus" else escaped_values)
        basename = "(${image})(" in expression
        rendered = expression.replace("${image}", replacement)
        literals = re.findall(r'(?:image|iris_image_id)=~("(?:[^"\\]|\\.)*")',
                              rendered)
        assert literals, rendered
        for literal in literals:
            pattern = re.compile(json.loads(literal))
            for name in selected:
                assert pattern.fullmatch(name), (source, literal, name)
                for suffix in (".bin", ".SPA.bin"):
                    assert bool(pattern.fullmatch(name + suffix)) == basename, \
                        (source, literal, name + suffix)
                assert not pattern.fullmatch(name + "-other.bin"), literal
                assert not pattern.fullmatch(name.replace(".", "x")), literal
            assert not pattern.fullmatch("unselected.26.01.bin"), literal
            checked += 1
    assert checked > 45


def test_grafana_one_picker_wording_has_no_manual_coupling_caveat():
    text = os.path.join(DASHBOARDS, "grafana-iris-swarm.json")
    with open(text, encoding="utf-8") as stream:
        body = stream.read()
    assert "image_catalog_id" not in body
    assert "NARROWING CAVEAT" not in body
    assert "set **both** pickers" not in body
    assert "single **Image** picker" in body


def test_grafana_prose_states_the_formula_the_panels_implement():
    """No panel multiplies an image size by a device count -- panel 33 forbids
    it in terms. The dashboard description and the 'How to read this board'
    panel must not teach that derivation."""
    dash = _grafana()
    texts = [dash.get("description", "")]
    for panel in dash.get("panels", []):
        texts.append(panel.get("description") or "")
        texts.append((panel.get("options") or {}).get("content") or "")
    blob = "\n".join(texts)
    assert "image size x completed devices - origin sent" not in blob
    assert "image size x completed devices minus" not in blob
