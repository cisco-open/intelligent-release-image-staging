# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""tools/aria2c-build/ is the corresponding source IRIS publishes for the GPL
aria2c binary it redistributes (GPLv2 section 3). Corresponding source that
cannot be built is not corresponding source, so the pins in that Dockerfile
have to keep resolving.

Two failure modes, two kinds of test here:

* Drift. A pin quietly relaxed to a floating package name would make a rebuild
  produce something other than what the recipe describes. The hermetic tests
  below assert the pinning discipline the file is built around: base image by
  digest, every apk package by exact version, no `latest`.

* Withdrawal. An Alpine release branch indexes only the newest `-rN` of each
  package, so a security bump deletes the version we pinned and `apk add`
  refuses the whole set. That is a hard, correct failure -- but it strands the
  published source until someone bumps the pin. Nothing hermetic can see it:
  the file is unchanged, the world moved. The opt-in test resolves every pin
  against the live APKINDEX for the pinned Alpine branch, which is how
  openssl-dev/openssl-libs-static=3.5.7-r0 (withdrawn from v3.24 in favour of
  3.5.8-r0) was caught.

The opt-in test needs network, so it runs under the same IRIS_TEST_HOST_INTEGRATION=1
gate as the real-`docker build` tests."""
import io
import os
import re
import tarfile
import urllib.error
import urllib.request

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
DOCKERFILE = os.path.join(HERE, "..", "..", "tools", "aria2c-build", "Dockerfile")

APKINDEX_URL = "https://dl-cdn.alpinelinux.org/alpine/v{branch}/{repo}/{arch}/APKINDEX.tar.gz"
REPOS = ("main", "community")
# build.sh drives both architectures; a pin must resolve for each.
ARCHES = ("x86_64", "aarch64")


def _text():
    return open(DOCKERFILE).read()


def _from_ref():
    """The first FROM line's image reference."""
    for line in _text().splitlines():
        m = re.match(r"^FROM\s+(\S+)", line)
        if m:
            return m.group(1)
    raise AssertionError("no FROM line in %s" % DOCKERFILE)


def _apk_add_block():
    """The `RUN apk add ...` command, continuation lines joined."""
    joined = _text().replace("\\\n", " ")
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.startswith("RUN apk add"):
            return re.sub(r"\s+", " ", stripped)
    raise AssertionError("no `RUN apk add` line in %s" % DOCKERFILE)


def _apk_packages():
    """Package arguments of the apk add command, as written (flags dropped)."""
    args = _apk_add_block().split()[3:]  # drop RUN, apk, add
    return [a for a in args if not a.startswith("-")]


def _apk_pins():
    """[(name, version)] for every pinned package."""
    pins = []
    for pkg in _apk_packages():
        name, sep, version = pkg.partition("=")
        assert sep, "package %r in %s is not version-pinned" % (pkg, DOCKERFILE)
        pins.append((name, version))
    return pins


# --------------------------------------------------------------------------
# Hermetic: the pinning discipline itself.
# --------------------------------------------------------------------------

def test_base_image_is_pinned_by_digest():
    ref = _from_ref()
    assert "@sha256:" in ref, (
        "the aria2c build base must be pinned by digest, got %s" % ref)
    assert not ref.split("@")[0].endswith(":latest"), (
        "the aria2c build base must not float on :latest, got %s" % ref)


def test_every_apk_package_is_pinned_to_an_exact_version():
    pins = _apk_pins()
    assert pins, "no packages found in the apk add line"
    for name, version in pins:
        assert re.fullmatch(r"[0-9][0-9A-Za-z._]*-r\d+", version), (
            "%s is not pinned to an exact Alpine version (got %r)" % (name, version))


def test_apk_add_does_not_float():
    block = _apk_add_block()
    assert "--no-cache" in block, "apk add must not leave an index cache behind"
    assert "latest" not in block, "no package in the apk add line may float on latest"
    # `apk upgrade` would pull newer packages than the pins name, defeating them.
    assert "apk upgrade" not in _text(), (
        "apk upgrade would move packages off their pins")


def test_openssl_dev_and_static_pins_move_together():
    # openssl-dev and openssl-libs-static are built from one source package;
    # a build that mixes versions links headers against a different library
    # than it statically embeds.
    pins = dict(_apk_pins())
    assert "openssl-dev" in pins and "openssl-libs-static" in pins
    assert pins["openssl-dev"] == pins["openssl-libs-static"], (
        "openssl-dev=%s but openssl-libs-static=%s"
        % (pins["openssl-dev"], pins["openssl-libs-static"]))


# --------------------------------------------------------------------------
# Opt-in: do the pins still exist upstream?
# --------------------------------------------------------------------------

def _alpine_branch():
    """`3.24` from a FROM of alpine:3.24.1@sha256:... -- the release branch
    whose package index apk actually reads."""
    ref = _from_ref()
    m = re.match(r"^alpine:(\d+)\.(\d+)", ref)
    assert m, "cannot read an Alpine release from %r" % ref
    return "%s.%s" % (m.group(1), m.group(2))


def _index_versions(branch, arch):
    """{package: {versions}} across the repositories apk is configured with."""
    found = {}
    for repo in REPOS:
        url = APKINDEX_URL.format(branch=branch, repo=repo, arch=arch)
        try:
            raw = urllib.request.urlopen(url, timeout=60).read()
        except urllib.error.URLError as exc:
            pytest.skip("Alpine package index unreachable (%s): %s" % (url, exc))
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            index = tar.extractfile("APKINDEX").read().decode("utf-8", "replace")
        for block in index.split("\n\n"):
            name = version = None
            for line in block.splitlines():
                if line.startswith("P:"):
                    name = line[2:]
                elif line.startswith("V:"):
                    version = line[2:]
            if name and version:
                found.setdefault(name, set()).add(version)
    return found


@pytest.mark.skipif(
    os.environ.get("IRIS_TEST_HOST_INTEGRATION") != "1",
    reason="network test: set IRIS_TEST_HOST_INTEGRATION=1 to resolve the "
           "aria2c build pins against the live Alpine index",
)
@pytest.mark.parametrize("arch", ARCHES)
def test_every_pin_still_resolves_in_the_pinned_alpine_branch(arch):
    branch = _alpine_branch()
    index = _index_versions(branch, arch)
    stale = []
    for name, version in _apk_pins():
        available = index.get(name, set())
        if version not in available:
            stale.append("%s=%s (v%s/%s carries: %s)"
                         % (name, version, branch, arch,
                            ", ".join(sorted(available)) or "no such package"))
    assert not stale, (
        "tools/aria2c-build/Dockerfile pins packages Alpine v%s no longer "
        "indexes, so the published corresponding source cannot be rebuilt:\n  %s\n"
        "Bump the pin in the Dockerfile on purpose -- keep the =version."
        % (branch, "\n  ".join(stale)))
