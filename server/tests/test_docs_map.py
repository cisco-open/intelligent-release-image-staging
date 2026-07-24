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


def _nav_pages():
    with open(os.path.join(REPO, "zensical.toml"), "rb") as fh:
        cfg = tomllib.load(fh)
    nav = cfg["project"]["nav"] if "project" in cfg else cfg["nav"]
    pages = []
    for entry in nav:
        for _title, page in entry.items():
            pages.append(page)
    return pages


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
