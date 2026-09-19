# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Guard: every docs link in the Console help pages must resolve to a live
page under docs/zensical, not to one of the old pages that are now redirect
stubs (front matter ``template: redirect.html``). A stub still resolves at
build time, so a plain "does the file exist" check would not catch a help
link left pointing at retired content -- it has to read the front matter.
"""
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS_ROOT = os.path.join(REPO_ROOT, "docs", "zensical")
WEBROOT = os.path.join(REPO_ROOT, "server", "webroot")

DOCS_LINK_RE = re.compile(
    r'href="https://cisco-open\.github\.io/intelligent-release-image-staging'
    r'/docs/([^"#]*)(#[^"]*)?"'
)

HELP_PAGES = ("help-server.html", "help-device.html")


def _is_redirect_stub(path):
    with open(path, encoding="utf-8") as f:
        head = f.read(4096)
    if not head.startswith("---"):
        return False
    end = head.find("\n---", 3)
    front_matter = head[3:end if end != -1 else len(head)]
    return "template: redirect.html" in front_matter


def _resolve_slug(slug):
    """Map a docs/<slug>/ URL to the markdown source file it must build
    from, the way Zensical resolves folder URLs to <dir>/index.md."""
    slug = slug.strip("/")
    if slug == "":
        return os.path.join(DOCS_ROOT, "index.md")
    direct = os.path.join(DOCS_ROOT, slug + ".md")
    if os.path.isfile(direct):
        return direct
    folder_index = os.path.join(DOCS_ROOT, slug, "index.md")
    if os.path.isfile(folder_index):
        return folder_index
    return None


def _docs_links(html_path):
    with open(html_path, encoding="utf-8") as f:
        html = f.read()
    return [m.group(1) for m in DOCS_LINK_RE.finditer(html)]


@pytest.mark.parametrize("page", HELP_PAGES)
def test_help_pages_link_only_current_docs_pages(page):
    html_path = os.path.join(WEBROOT, page)
    slugs = _docs_links(html_path)
    assert slugs, "expected at least one docs link in %s" % page
    for slug in slugs:
        source = _resolve_slug(slug)
        assert source is not None, (
            "%s links to docs/%s, which does not resolve to any file "
            "under docs/zensical" % (page, slug))
        assert not _is_redirect_stub(source), (
            "%s links to docs/%s, which resolves to %s -- a redirect stub, "
            "not a current page" % (page, slug, os.path.relpath(source, REPO_ROOT)))
