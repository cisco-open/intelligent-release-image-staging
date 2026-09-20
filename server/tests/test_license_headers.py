# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Audit tracked files, with explicit exceptions for formats and upstream works."""

import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
COPYRIGHT = "Copyright 2026 Cisco Systems, Inc. and its affiliates"
SPDX = "SPDX-License-Identifier: Apache-2.0"

# Do not put Cisco/Apache headers on upstream works or corrupt data formats.
# Keep paths explicit: a new file must be reviewed, not silently exempted by
# its directory or extension. Repository LICENSE/NOTICE cover first-party data.
EXEMPTIONS = {
    "CODE_OF_CONDUCT.md": "Contributor Covenant adaptation; attribution retained",
    "LICENSE": "Apache license text, not a source file",
    "NOTICE": "Project and third-party attribution text",
    "VERSION": "Machine-readable CalVer value",
    "artifacts/.gitkeep": "Empty directory placeholder",
    "bin/.gitkeep": "Empty directory placeholder",
    "bin/aria2c": "GPL executable; distribution terms recorded in NOTICE",
    "deliverables/aria2c-aarch64": "GPL executable; terms recorded in NOTICE",
    "deliverables/aria2c-x86_64": "GPL executable; terms recorded in NOTICE",
    "docs/zensical/dashboards/grafana-iris-swarm.json": "Strict JSON dashboard",
    "docs/zensical/openapi.yaml": "JSON-formatted contract consumed by json.load",
    "docs/zensical/swagger/LICENSE": "Unmodified upstream license",
    "docs/zensical/swagger/NOTICE": "Unmodified upstream attribution",
    "docs/zensical/swagger/package.json": "Unmodified upstream metadata",
    "docs/zensical/swagger/swagger-ui-bundle.js": "Vendored upstream asset",
    "docs/zensical/swagger/swagger-ui-bundle.js.LICENSE.txt": "Upstream licenses",
    "docs/zensical/swagger/swagger-ui.css": "Vendored upstream asset",
    "fleet/assignments.csv.example": "CSV header must remain the first row",
    "fleet/devices.csv.example": "CSV header must remain the first row",
    "fleet/roles.csv.example": "CSV header must remain the first row",
    "server/certs/cisco_bulkhash_verify.pem": "Public certificate, not source",
    "server/console-ui/package-lock.json": "Generated strict JSON lockfile",
    "server/console-ui/package.json": "Strict JSON package metadata",
    "server/webroot/fonts/Inter-Medium.woff2": "Upstream binary font; see Inter-OFL.txt",
    "server/webroot/fonts/Inter-Regular.woff2": "Upstream binary font; see Inter-OFL.txt",
    "server/webroot/fonts/Inter-SemiBold.woff2": "Upstream binary font; see Inter-OFL.txt",
    "server/webroot/fonts/Inter-OFL.txt": "Unmodified upstream font license",
    "server/webroot/fonts/RobotoMono-Medium.woff2": "Upstream font; see NOTICE",
    "server/webroot/fonts/RobotoMono-Regular.woff2": "Upstream font; see NOTICE",
    "tools/licenses/musl-COPYRIGHT": "Unmodified upstream license",
    "tools/aria2c-source/COPYING3": "Unmodified GNU GPL version 3 license text",
    "tools/aria2c-source/inputs.json": "Strict JSON source and dependency checksum manifest",
    "tools/aria2c-patches/0001-getpeers-keys-filter.patch": "GPL patch; see sibling README",
    "tools/aria2c-patches/0002-fix-uaf-peer-blocklist-disconnect.patch": "GPL patch; see sibling README",
    "tools/aria2c-patches/0003-fix-pkcs12-chain-type-confusion.patch": "GPL patch; see sibling README",
    "tools/aria2c-patches/0004-fix-ed2k-iterator-invalidation.patch": "GPL patch; see sibling README",
    "tools/aria2c-patches/0005-hard-bt-max-peers.patch": "GPL patch; see sibling README",
    "tools/aria2c-patches/0006-preserve-coalesced-bt-handshake.patch": "GPL patch; see sibling README",
    "tools/aria2c-patches/0007-seeder-goodbye-grace.patch": "GPL patch; see sibling README",
    "tools/aria2c-patches/0008-required-hybrid-peer-tls.patch": "GPL patch; see sibling README",
    "tools/aria2c-patches/0009-test-seeder-goodbye-grace.patch": "GPL patch; see sibling README",
    "tools/aria2c-patches/0010-resolve-crossed-peer-handshakes.patch": "GPL patch; see sibling README",
}


def _tracked_files():
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True,
    )
    return set(result.stdout.decode("utf-8").rstrip("\0").split("\0"))


def _header_problems(text):
    # Accommodate shebangs, XML declarations and Markdown YAML front matter,
    # but never accept a license mention buried in executable code or prose.
    header = "\n".join(text.splitlines()[:12])
    problems = []
    if COPYRIGHT not in header:
        problems.append("missing leading Cisco copyright")
    if SPDX not in header:
        problems.append("missing leading Apache-2.0 SPDX identifier")
    if "#!" in text and text.startswith(("# Copyright", "/*", "<!--")):
        # A shebang is meaningful only as the first line, not after a header.
        if any(line.startswith("#!") for line in text.splitlines()[1:12]):
            problems.append("header displaced executable shebang")
    return problems


def test_all_tracked_first_party_files_have_license_headers():
    paths = _tracked_files()
    # Check this new test before it is staged, as well as in subsequent CI runs.
    paths.add(Path(__file__).relative_to(ROOT).as_posix())
    failures = []
    for name in sorted(paths - EXEMPTIONS.keys()):
        try:
            text = (ROOT / name).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append(f"{name}: binary needs an explicit license review")
            continue
        failures.extend(f"{name}: {problem}" for problem in _header_problems(text))
    assert not failures, "\n".join(failures)


def test_license_exemptions_are_documented_and_not_stale():
    paths = _tracked_files()
    assert not EXEMPTIONS.keys() - paths
    assert all(EXEMPTIONS.values())


@pytest.mark.parametrize("text", [
    "print('missing header')\n",
    f"# {SPDX}\n",
    f"# {COPYRIGHT}\n",
    "\n" * 12 + f"# {COPYRIGHT}\n# {SPDX}\n",
    f"# {COPYRIGHT}\n# {SPDX}\n#!/bin/sh\n",
])
def test_license_gate_rejects_missing_buried_or_displaced_headers(text):
    assert _header_problems(text)


@pytest.mark.parametrize("text", [
    f"#!/bin/sh\n# {COPYRIGHT}\n#\n# {SPDX}\n",
    f"<!--\n{COPYRIGHT}\n\n{SPDX}\n-->\n",
    f"---\n# {COPYRIGHT}\n# {SPDX}\ntemplate: redirect.html\n---\n",
    f"! {COPYRIGHT}\n!\n! {SPDX}\n",
])
def test_license_gate_accepts_supported_header_layouts(text):
    assert not _header_problems(text)
