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
