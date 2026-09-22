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
    # The manual reorganized into four guides; these are the pages that carry
    # introductory API examples now. reference/device-apis.md is deliberately
    # absent: it documents catalog and tracker routes, which are not Console
    # operations and would fail this gate.
    for name in ("docs/index.html", "docs/app.js",
                 "docs/zensical/install/certificates-and-tokens.md",
                 "docs/zensical/reference/index.md",
                 "docs/zensical/reference/console-api.md",
                 "docs/zensical/reference/peer-policy-api.md",
                 "docs/zensical/user-guide/console.md",
                 "docs/zensical/user-guide/onboarding.md",
                 "docs/zensical/user-guide/assignments.md",
                 "docs/zensical/user-guide/scheduling.md",
                 "docs/zensical/user-guide/roles.md",
                 "docs/zensical/user-guide/images.md",
                 "docs/zensical/admin-guide/rotations.md",
                 "docs/zensical/admin-guide/recovery.md",
                 "docs/zensical/user-guide/automation.md"):
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


def test_install_guide_describes_persisted_default_browser_identity():
    guide = (
        ROOT / "docs/zensical/install/certificates-and-tokens.md").read_text()
    assert "tls/console-fallback.pem.age" in guide
    assert "reused on restart" in guide
    assert "not durable across" not in guide
    assert "Never disable" in guide and "TLS verification" in guide
