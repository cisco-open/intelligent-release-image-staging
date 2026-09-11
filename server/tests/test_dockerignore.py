# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The build context must not carry secrets, licensed material or built
packages into image layers.

``server/Dockerfile`` COPYs whole trees (``COPY server/``, ``COPY device/``,
``COPY lab/``). A ``.dockerignore`` pattern without a leading ``**/`` only
matches at the context root, so the old ``.env`` / ``*.key`` / ``*.pem``
lines never excluded ``server/.env`` or ``server/certs/x.key``. This module
evaluates the repository's ``.dockerignore`` with Docker's own matching
rules (Go ``filepath.Match`` plus ``**``, ``!`` re-inclusion, last match
wins, a matching parent directory excludes its subtree) against a planted
tree and asserts what must stay out -- and what the image still needs.
"""

import os
import re

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _go_pattern_to_regex(pattern):
    """Translate a moby/patternmatcher pattern to a regex (``**`` aware)."""
    out = "^"
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                # ``**/`` matches zero or more directories; a trailing ``**``
                # matches everything below.
                i += 2
                if i < n and pattern[i] == "/":
                    out += "(?:.*/)?"
                    i += 1
                else:
                    out += ".*"
                continue
            out += "[^/]*"
        elif ch == "?":
            out += "[^/]"
        elif ch == "[":
            j = pattern.find("]", i)
            if j == -1:
                out += re.escape(ch)
            else:
                cls = pattern[i + 1:j]
                if cls.startswith("^"):
                    cls = "\\" + cls
                out += "[" + cls + "]"
                i = j
        elif ch == "\\":
            i += 1
            if i < n:
                out += re.escape(pattern[i])
        else:
            out += re.escape(ch)
        i += 1
    return re.compile(out + "$")


def _clean(pattern):
    # filepath.Clean: drop a leading "/", trailing "/", "./" prefixes.
    p = pattern.strip()
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    p = p.rstrip("/")
    return p


def load_patterns(path=os.path.join(ROOT, ".dockerignore")):
    patterns = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            exclusion = line.startswith("!")
            if exclusion:
                line = line[1:]
            cleaned = _clean(line)
            if not cleaned:
                continue
            patterns.append((exclusion, _go_pattern_to_regex(cleaned)))
    return patterns


def excluded(rel_path, patterns):
    """True when Docker would leave ``rel_path`` out of the build context."""
    parents = []
    parts = rel_path.split("/")
    for k in range(1, len(parts)):
        parents.append("/".join(parts[:k]))
    matched = False
    for is_exclusion, rx in patterns:
        hit = rx.match(rel_path) is not None or any(rx.match(p) for p in parents)
        if hit:
            matched = not is_exclusion
    return matched


@pytest.fixture(scope="module")
def patterns():
    return load_patterns()


# What a live lab checkout carries under the COPY'd trees, none of which may
# reach an image layer.
MUST_EXCLUDE = [
    "server/.env",
    "server/lab.env",
    "server/certs/lab-private.key",
    "server/certs/lab.pem",
    "server/certs/server.crt",
    "server/certs/bundle.p12",
    "server/rpc-secret",
    "server/tokens.txt",
    "server/docker-compose.override.yml",
    "server/webroot/fonts/SharpSans-Bold.woff2",
    "server/tests/test_tracker.py",
    "device/xr/out/iris-xr.rpm",
    "device/xr/out/iris-xr.rpm.manifest",
    "device/iox/out/iris-amd64.tar",
    "device/iox/out/iris-amd64.tar.manifest",
    "device/xr/tests/test_xr_image.bats",
    "device/agent/tests/test_agent.py",
    "device/id_rsa",
    "lab/evidence/session.log",
    "lab/tests/test_lab_tools.py",
    "images/ios-xe/cat9k_iosxe.17.12.04.SPA.bin",
    "artifacts/iris-agent.tgz",
    "artifacts/iris-device-test.oci.tar",
    "artifacts/iris-device-test.oci.tar.manifest",
    "artifacts/iris-catalog.pem",
    "creds/deploy.env",
    "fleet/devices.csv",
    "fleet/dist/install-sw1.sh",
    "deliverables/aria2c-x86_64",
    "release/iris.tgz",
    ".env",
    "cat9k.bin",
    "image.torrent",
]

# What server/Dockerfile COPYs and the runtime reads: these must stay in.
MUST_INCLUDE = [
    "bin/aria2c",
    "tools/aria2c.sha256",
    "VERSION",
    "server/tracker.py",
    "server/docker-entrypoint.sh",
    "server/certs/cisco_bulkhash_verify.pem",
    "server/webroot/styles.css",
    "server/webroot/fonts/Inter-Regular.woff2",
    "device/agent/iris_agent.py",
    "device/bootstrap.sh",
    "device/iox/build.sh",
    "device/container/entrypoint.sh",
    "lab/device-run.sh",
    "lab/xr-run.sh",
]


@pytest.mark.parametrize("rel", MUST_EXCLUDE)
def test_secret_and_generated_material_is_excluded(rel, patterns):
    assert excluded(rel, patterns), "%s would be baked into the image" % rel


@pytest.mark.parametrize("rel", MUST_INCLUDE)
def test_material_the_image_needs_is_included(rel, patterns):
    assert not excluded(rel, patterns), "%s is needed by server/Dockerfile" % rel


SWAGGER_FILES = (
    "index.html", "swagger-initializer.js", "swagger-ui-bundle.js",
    "swagger-ui.css", "iris-swagger.css", "iris-openapi32.js",
    "LICENSE", "NOTICE", "SOURCE.md", "package.json",
    "swagger-ui-bundle.js.LICENSE.txt",
)


@pytest.mark.parametrize("rel", ["docs/zensical/openapi.yaml"] + [
    "docs/zensical/swagger/" + name for name in SWAGGER_FILES
])
def test_console_canonical_api_docs_are_included(rel, patterns):
    assert os.path.isfile(os.path.join(ROOT, rel)), rel
    assert not excluded(rel, patterns), "%s is needed by Dockerfile.console" % rel


@pytest.mark.parametrize("rel", [
    "docs/index.html", "docs/app.js", "docs/zensical/index.md",
    "docs/zensical/operator-notes.yaml", "docs/zensical/swagger/unreviewed.js",
    "docs/zensical/swagger/nested/index.html",
] + [
    prefix + name
    for prefix in ("docs/", "docs/zensical/", "docs/zensical/swagger/",
                   "docs/zensical/swagger/nested/")
    for name in (".env", "local.env", "private.key", "identity.pem",
                 "server.crt", "identity.p12", "rpc-secret", "tokens.txt",
                 "id_rsa", "image.bin", "image.torrent", "package.tar")
])
def test_console_api_docs_exceptions_do_not_reinclude_other_material(rel, patterns):
    # An EOF !docs/ or !swagger/** silently overrides recursive secret rules.
    # Use planted paths, never real credentials, to exercise last-match wins.
    assert excluded(rel, patterns), "%s would leak through the docs exceptions" % rel


def test_secret_patterns_are_recursive():
    """Root-anchored secret patterns silently miss nested files."""
    with open(os.path.join(ROOT, ".dockerignore"), encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    for ext in (".env", "*.env", "*.pem", "*.key", "*.crt", "*.p12", "*.torrent", "*.aria2", "*.rpm"):
        assert ext not in lines, "%s is root-anchored; write **/%s" % (ext, ext)
        assert "**/" + ext in lines, "**/%s missing" % ext


def test_evaluator_matches_docker_semantics():
    """Sanity-check the evaluator itself on the documented reference cases."""
    pats = [(False, _go_pattern_to_regex("*.md")), (False, _go_pattern_to_regex("**/*.key")),
            (False, _go_pattern_to_regex("bin")), (True, _go_pattern_to_regex("bin/aria2c"))]
    assert excluded("README.md", pats)
    assert not excluded("docs/README.md", pats)          # `*` never crosses `/`
    assert excluded("server/certs/x.key", pats)
    assert excluded("x.key", pats)                        # `**/` matches zero dirs
    assert excluded("bin/other", pats)                    # parent directory match
    assert not excluded("bin/aria2c", pats)               # `!` re-inclusion
    # planted tree on disk: the evaluator walks real paths the same way
    planted = ["server/.env", "server/certs/a.key", "server/app.py"]
    real = load_patterns()
    assert [p for p in planted if not excluded(p, real)] == ["server/app.py"]
