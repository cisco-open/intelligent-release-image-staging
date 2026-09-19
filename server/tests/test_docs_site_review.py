# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Guard compatibility of moved links and the static transfer comparison."""
from pathlib import Path
import posixpath
import re
from urllib.parse import urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs/zensical"


@pytest.mark.parametrize("old_page,fragment,expected", [
    ("getting-started", "create-the-console-admin", "install/one-docker-host"),
    ("development", "embedded-agent-packages", "install/device-packages"),
    ("operations", "instruction-root-ceremony-and-recovery", "admin-guide/recovery"),
    ("operations", "rollback-after-the-shard-migration", "admin-guide/recovery"),
    ("operations", "f3-offline-bootstrap-envelope-redelivery", "admin-guide/instruction-keys"),
    ("aiagent", "build-and-publish-the-arm64-iox-package", "install/device-packages"),
    ("aiagent", "initialise-instruction-custody", "install/activate-signing"),
])
def test_retained_legacy_sections_reach_their_new_page(old_page, fragment, expected):
    meta = yaml.safe_load((DOCS / (old_page + ".md")).read_text().split("---")[1])
    target = urlsplit(meta.get("anchors", {}).get(fragment, meta["location"]))
    destination = posixpath.normpath(posixpath.join(old_page, target.path))
    assert destination == expected
    text = (DOCS / (destination + ".md")).read_text()
    target_fragment = target.fragment or fragment
    headings = re.findall(r"^#+ (.+)$", text, re.M)
    ids = set()
    for heading in headings:
        alias = re.search(r"\{ #([^ ]+) \}", heading)
        ids.add(alias[1] if alias else re.sub(r"[^\w -]", "", heading.lower()).replace(" ", "-"))
    assert target_fragment in ids


def test_comparison_is_compact_static_and_has_distinct_piece_states():
    css = (ROOT / "docs/styles.css").read_text()
    markup = (ROOT / "docs/index.html").read_text()
    comparison_css = css.split(".distribution-visual {", 1)[1].split(".benefits-grid {", 1)[0]
    assert "animation" not in comparison_css
    assert "@keyframes flow" not in css and "@keyframes pulse" not in css
    assert "min-height: 420px" not in comparison_css
    assert "max-width: 340px" in comparison_css
    assert "gap: 10px" in comparison_css
    assert ".flow-svg .node .piece {" in comparison_css
    assert ".flow-svg .node .piece.empty {" in comparison_css
    assert 'class="load' not in markup
    assert "seeds each image once" not in markup and "seeds once" not in markup
    assert "Turn on mutual TLS" in markup
    assert "HTTPS for every control path" not in markup
    assert "HTTPS for the Console and service APIs" in markup


def test_developer_index_links_every_contributor_page():
    index = (ROOT / "docs/dev/README.md").read_text()
    for page in (ROOT / "docs/dev").glob("*.md"):
        if page.name != "README.md":
            assert "](" + page.name + ")" in index, page


def test_contributor_relative_links_resolve_after_the_move():
    for page in (ROOT / "docs/dev").glob("*.md"):
        for target in re.findall(r"\]\(([^)]+)\)", page.read_text()):
            parts = urlsplit(target)
            if parts.scheme or not parts.path:
                continue
            destination = page.parent / parts.path
            assert destination.exists(), (page, target)
            if destination.suffix == ".md":
                text = destination.read_text()
                assert not re.match(r"\A---\s*\n.*?^template: redirect\.html$", text, re.M | re.S), (page, target)
