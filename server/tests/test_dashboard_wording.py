# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

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


def test_grafana_catalog_id_variable_passes_non_bin_images_through():
    """The variable mirrors publish.derive_id, which strips .SPA.bin/.bin and
    returns every other basename UNCHANGED. A Grafana variable regex that fails
    to match DROPS the value from the option list, so a regex anchored on a
    mandatory .bin suffix makes every .iso/.tar/.rpm image disappear from the
    picker instead of mapping to itself."""
    var = next(v for v in _grafana()["templating"]["list"]
               if v.get("name") == "image_catalog_id")
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


def test_grafana_catalog_id_variable_is_visible():
    """hide: 2 removed the picker from the UI, so it stayed pinned to its
    shipped All value: narrowing $image narrowed only the Prometheus (origin)
    leg while the Loki (delivery) leg still matched every image, and every
    derived peer share was silently inflated."""
    var = next(v for v in _grafana()["templating"]["list"]
               if v.get("name") == "image_catalog_id")
    assert var.get("hide", 0) != 2, \
        "image_catalog_id must be operator-visible; it does not follow $image"


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
