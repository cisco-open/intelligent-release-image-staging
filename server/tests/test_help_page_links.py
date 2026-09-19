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


# ---------------------------------------------------------------------------
# server/iox_verification.py embeds a rendered docs URL and heading anchor
# directly in an operator-facing refusal detail, not in one of the help
# pages above. Nothing else in the suite resolves that anchor against a real
# heading, so a docs restructure that renames the heading, moves the page,
# or drops the anchor would leave a dead link in a runtime error message an
# operator reads during an interrupted IOx install, with every other gate
# green (issue #361).
# ---------------------------------------------------------------------------

RUNBOOK_LINK_RE = re.compile(
    r'^https://cisco-open\.github\.io/intelligent-release-image-staging'
    r'/docs/([^#]*)#(.+)$'
)

_HEADING_ID_RE = re.compile(r"\{\s*#([-\w]+)\s*\}\s*$")


def _markdown_headings(markdown_path):
    """Every ATX heading's raw text, skipping fenced code blocks so a shell
    comment starting with '#' is never mistaken for a heading."""
    with open(markdown_path, encoding="utf-8") as f:
        text = f.read()
    headings = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if fence is None:
            if marker:
                fence = marker.group(1)[0]
                continue
            match = re.match(r"^#{1,6}\s+(.*?)\s*$", line)
            if match:
                headings.append(match.group(1))
        elif marker and marker.group(1)[0] == fence:
            fence = None
    return headings


def _slugify(heading_text):
    """The natural heading slug: lowercase, spaces to hyphens, punctuation
    and inline-code backticks stripped."""
    text = _HEADING_ID_RE.sub("", heading_text).strip()
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"\s+", "-", text).strip("-")
    return text


def _heading_slugs(markdown_path):
    """Every id a link could target on this page: an explicit ``{ #id }``
    attribute where present, otherwise the heading's natural slug."""
    slugs = set()
    for heading in _markdown_headings(markdown_path):
        explicit = _HEADING_ID_RE.search(heading)
        slugs.add(explicit.group(1) if explicit else _slugify(heading))
    return slugs


def test_iox_verification_reconcile_runbook_anchor_resolves():
    """_RECONCILE_RUNBOOK must resolve to a real page and a real heading."""
    import iox_verification

    url = iox_verification._RECONCILE_RUNBOOK
    match = RUNBOOK_LINK_RE.match(url)
    assert match, "%s does not look like a rendered docs URL" % url
    slug, fragment = match.groups()

    source = _resolve_slug(slug)
    assert source is not None, (
        "iox_verification._RECONCILE_RUNBOOK links to docs/%s, which does "
        "not resolve to any file under docs/zensical" % slug)
    assert not _is_redirect_stub(source), (
        "iox_verification._RECONCILE_RUNBOOK links to docs/%s, which "
        "resolves to %s -- a redirect stub, not a current page"
        % (slug, os.path.relpath(source, REPO_ROOT)))

    slugs = _heading_slugs(source)
    assert fragment in slugs, (
        "iox_verification._RECONCILE_RUNBOOK's anchor #%s does not match "
        "any heading in %s (found: %s)"
        % (fragment, os.path.relpath(source, REPO_ROOT), sorted(slugs)))
