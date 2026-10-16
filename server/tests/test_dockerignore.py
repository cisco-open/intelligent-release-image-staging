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

import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import uuid

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
    "server/console-ui/node_modules/react/index.js",
    "server/console-ui/dist/console.js",
    "server/console-ui/dist/swarmmap.html",
    "server/console-ui/tests/build.test.mjs",
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
    "server/console-ui/package.json",
    "server/console-ui/package-lock.json",
    "server/console-ui/vite.config.js",
    "server/console-ui/src/main.jsx",
    "server/console-ui/src/swarm-map.jsx",
    "server/console-ui/scripts/build-map.mjs",
    "server/console-ui/templates/swarmmap.html",
    "bin/aria2c",
    "deliverables/aria2c-aarch64",
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
    "LICENSE", "NOTICE", "SOURCE.txt", "package.json",
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


@pytest.mark.parametrize("rel", [
    "deliverables/aria2c-x86_64", "deliverables/other-client",
    "deliverables/aria2c-aarch64.key", "deliverables/aria2c-aarch64.backup",
    "deliverables/nested/aria2c-aarch64", "deliverables/iris-arm64.tar",
    "deliverables/roots/root-a.key", "deliverables/.env",
])
def test_arm_client_exception_does_not_include_other_deliverables(rel, patterns):
    assert excluded(rel, patterns), rel


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is unavailable")
def test_actual_server_build_context_keeps_only_both_required_clients(tmp_path):
    """The c253 source install failed COPY ARM before creating any image.

    Exercise the actual Docker context filter with harmless stand-in clients,
    FROM scratch and no network. A parser-only Dockerfile test missed this.
    """
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "DOCKER_HOST": "unix:///var/run/docker.sock"}
    probe = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           env=environment, capture_output=True, timeout=20)
    if probe.returncode:
        pytest.skip("The local Docker daemon is unavailable")
    context = tmp_path / "context"
    context.mkdir()
    (context / "bin").mkdir()
    (context / "deliverables").mkdir()
    amd64, arm64 = b"test-amd64-client\n", b"test-arm64-client\n"
    (context / "bin/aria2c").write_bytes(amd64)
    (context / "deliverables/aria2c-aarch64").write_bytes(arm64)
    for name in ("aria2c-x86_64", "other-client", "aria2c-aarch64.key", "iris-arm64.tar"):
        (context / "deliverables" / name).write_bytes(b"must-not-enter-the-image\n")
    dockerfile = "FROM scratch\nCOPY bin/aria2c /amd64\nCOPY deliverables/aria2c-aarch64 /arm64\nCOPY deliverables/ /deliverables/\n"
    (context / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    with open(os.path.join(ROOT, ".dockerignore"), encoding="utf-8") as stream:
        actual_ignore = stream.read()
    exact_exception = "!deliverables/aria2c-aarch64\n"
    assert actual_ignore.count(exact_exception) == 1
    tag = "iris-context-regression-" + uuid.uuid4().hex + ":test"
    try:
        # Reproduce the original package's exclusion without building a server
        # or fetching a base image. The failed build must never create our tag.
        (context / ".dockerignore").write_text(actual_ignore.replace(exact_exception, ""), encoding="utf-8")
        argv = ["docker", "build", "--network=none", "--pull=false", "--no-cache",
                "--tag", tag, str(context)]
        failure = subprocess.run(argv, env=environment, capture_output=True, timeout=90)
        assert failure.returncode != 0
        assert b"aria2c-aarch64" in failure.stderr + failure.stdout
        tags = subprocess.run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
                              env=environment, capture_output=True, timeout=20)
        assert tags.returncode == 0 and tag not in tags.stdout.decode().splitlines()
        (context / ".dockerignore").write_text(actual_ignore, encoding="utf-8")
        build = subprocess.run(argv, env=environment, capture_output=True, timeout=90)
        assert build.returncode == 0, (build.stderr + build.stdout).decode(errors="replace")[-2000:]
        archive = tmp_path / "image.tar"
        exported = subprocess.run(["docker", "image", "save", "--output", str(archive), tag],
                                  env=environment, capture_output=True, timeout=20)
        assert exported.returncode == 0, exported.stderr.decode(errors="replace")
        # Inspect actual saved layers, without creating/running a container or
        # adding Docker's /etc and /dev placeholder files to the observation.
        files = {}
        with tarfile.open(archive) as saved:
            manifest = json.load(saved.extractfile("manifest.json"))
            assert len(manifest) == 1 and manifest[0]["RepoTags"] == [tag]
            for name in manifest[0]["Layers"]:
                with tarfile.open(fileobj=io.BytesIO(saved.extractfile(name).read())) as layer:
                    files.update({member.name.removeprefix("./"): layer.extractfile(member).read()
                                  for member in layer if member.isfile()})
        assert files == {"amd64": amd64, "arm64": arm64, "deliverables/aria2c-aarch64": arm64}
    finally:
        # Only the unique owned tag is removed. No image-ID delete,
        # daemon-wide cache pruning or lab deployment is involved.
        removed = subprocess.run(["docker", "image", "rm", tag], env=environment,
                                 capture_output=True, timeout=20)
        if removed.returncode:
            tags = subprocess.run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
                                  env=environment, capture_output=True, timeout=20)
            assert tags.returncode == 0 and tag not in tags.stdout.decode().splitlines()
