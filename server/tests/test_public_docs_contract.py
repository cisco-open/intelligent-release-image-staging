# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Keep introductory copy concise and API examples tied to runtime routes."""
import html
import re
from pathlib import Path

import api_routes

ROOT = Path(__file__).resolve().parents[2]


def test_indexes_use_family_names_and_do_not_promote_cli_or_lab_results():
    for name in ("docs/index.html", "docs/app.js", "docs/zensical/index.md"):
        text = (ROOT / name).read_text()
        assert "NCS" in text
        assert not re.search(r"NCS[- ]?\d|Cisco 8201", text, re.I), name
        assert not re.search(r"lab-validated|lifecycle testing|validation remain", text, re.I), name
        assert "iris-publish" not in text and "apply-assignments.sh" not in text
        assert not re.search(r"command.line|\bCLI\b", text, re.I), name


def test_introductory_api_examples_are_registered_console_operations():
    def normalize(path):
        return re.sub(r"\{[^}]+\}|<[A-Za-z_][A-Za-z0-9_-]*>", "{}", path)
    registered = {(route.method, normalize(route.path))
                  for route in api_routes.ROUTES if route.service == "console"}
    examples = []
    for name in ("docs/index.html", "docs/app.js",
                 "docs/zensical/getting-started.md", "docs/zensical/console.md",
                 "docs/zensical/fleet-workflows.md", "docs/zensical/reference.md",
                 "docs/zensical/device-agents.md", "docs/zensical/iox.md",
                 "docs/zensical/operations.md"):
        text = (ROOT / name).read_text()
        for method, path in re.findall(
                r"\b(GET|POST|PUT|PATCH|DELETE) (/api/v1/(?:[A-Za-z0-9_/{}/.-]|<[A-Za-z_][A-Za-z0-9_-]*>)+)", text):
            assert (method, normalize(path)) in registered, (name, method, path)
            examples.append((method, path))
    assert len(examples) >= 10


def test_static_workflow_fallback_matches_initial_script_copy():
    markup = (ROOT / "docs/index.html").read_text()
    script = (ROOT / "docs/app.js").read_text().split("  assign:", 1)[0]
    for field, element in (("title", "flow-title"), ("body", "flow-body"),
                           ("command", "flow-command")):
        expected = re.search(r'\b' + field + r': "([^"]*)"', script).group(1)
        actual = re.search(r'id="' + element + r'">([^<]*)<', markup).group(1)
        assert html.unescape(actual) == expected


def test_api_test_guide_describes_persisted_default_browser_identity():
    guide = (ROOT / "docs/zensical/api-testing.md").read_text()
    assert "tls/console-fallback.pem.age" in guide
    assert "reused on restart" in guide
    assert "not durable across" not in guide
    assert "Never disable" in guide and "TLS verification" in guide
