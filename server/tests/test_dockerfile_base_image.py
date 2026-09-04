# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Both images must sit on a Debian trixie base (OpenSSL 3.5 LTS), not bookworm
(OpenSSL 3.0, upstream EOL 2026-09-07).

This is security-critical rather than housekeeping: server/trust.py shells out
to the base image's `openssl` binary to parse the TLS trust store and verify
CMS integrity for downloaded CA bundles (PKCS#7/CMS). It does NOT verify Cisco
IOS image signatures -- IOS image authenticity is established server-side at
publish time, not via any on-device signature check (placement is a plain
`copy`, attested by the agent itself). The two Dockerfiles share a base and
must be bumped in lockstep, so a drift between them is itself a failure
(issue #13).

The second half of the file covers the other way a base goes stale: the tag is
floating, so every build that does not pass --pull silently reuses the build
host's cache (issue #64)."""
import os
import re
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_DOCKERFILE = os.path.join(HERE, "..", "Dockerfile")
IOX_DOCKERFILE = os.path.join(HERE, "..", "..", "device", "iox", "Dockerfile")


def _base_image(path):
    """The FROM line's image reference (first stage)."""
    for line in open(path).read().splitlines():
        m = re.match(r"^FROM\s+(\S+)", line)
        if m:
            return m.group(1)
    raise AssertionError("no FROM line in %s" % path)


def test_server_base_is_trixie():
    base = _base_image(SERVER_DOCKERFILE)
    assert "bookworm" not in base, (
        "server image is still on bookworm (OpenSSL 3.0, EOL 2026-09-07): %s" % base)
    assert "trixie" in base, "expected a trixie base, got %s" % base


def test_iox_base_is_trixie():
    base = _base_image(IOX_DOCKERFILE)
    assert "bookworm" not in base, (
        "IOx agent image is still on bookworm: %s" % base)
    assert "trixie" in base, "expected a trixie base, got %s" % base


def test_both_images_share_one_base_in_lockstep():
    # The IOx agent and the server run the same Python and the same OpenSSL;
    # bumping one without the other reintroduces the split this item closes.
    assert _base_image(SERVER_DOCKERFILE) == _base_image(IOX_DOCKERFILE)


def test_server_dockerfile_states_trust_boundary_accurately():
    # The OpenSSL rationale in the server Dockerfile must describe what
    # trust.py actually does -- CA-bundle / trust-store processing -- and must
    # NOT claim the server verifies IOS image signatures (authenticity is
    # established server-side at publish time, not via any on-device
    # signature check -- there is no `copy /verify` anymore).
    text = open(SERVER_DOCKERFILE).read().lower()
    assert "trust.py" in text
    assert "publish time" in text, (
        "Dockerfile must credit server-side publish-time attestation for "
        "image authenticity, not a device-side signature check")
    assert re.search(r"ca[ -]?bundle|trust store|trust-store", text), (
        "Dockerfile must describe CA-bundle/trust-store processing")
    assert "image signature" not in text and "image-signature" not in text, (
        "Dockerfile must not claim the server verifies IOS image signatures")


# ---------------------------------------------------------------------------
# A current base in the Dockerfile is only half of it: `python:3.12-slim-trixie`
# is a floating tag, so a build without `--pull` reuses whatever the build host
# cached and ships an out-of-date base while the Dockerfile still reads
# correctly (measured on the lab server: a 19-day-old cached tag was 12 Debian
# security updates behind, OpenSSL 3.5.6 vs 3.5.7 -- issue #13/#64). Every way
# we tell someone to build an IRIS image therefore has to pass --pull: the
# scripts that run the build, and the commands the docs hand an operator to
# paste.
# ---------------------------------------------------------------------------
REPO = os.path.join(HERE, "..", "..")

# script -> regex matching the line that actually invokes the build.
# tools/build-xr-package.sh builds a digest-pinned base, where --pull cannot
# change the result; it is held to the same rule anyway so that a future
# switch back to a floating tag cannot quietly reintroduce the stale-base bug.
BUILD_SCRIPTS = {
    os.path.join("device", "iox", "build.sh"): r"^docker build\b",
    os.path.join("tools", "build-xr-package.sh"): r"^docker build\b",
    os.path.join("tools", "start-compose-server.sh"): r"^\"\$\{COMPOSE\[@\]\}\" build\b",
}


def _expanded_build_lines(script_path, invocation_re):
    """Invocation lines with shell variables replaced by their DEFAULT value.

    The scripts spell the flag `PULL_FLAG="--pull"` with an IRIS_NO_PULL=1
    opt-out, so the literal string is not on the docker build line; the
    default assignment is what this rule is about.
    """
    defaults = {}
    lines = []
    for raw in open(script_path).read().splitlines():
        line = raw.strip()
        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"', line)
        if m and m.group(1) not in defaults:
            defaults[m.group(1)] = m.group(2)
        if line.startswith("#") or not re.search(invocation_re, line):
            continue
        expanded = line
        for name, value in defaults.items():
            expanded = expanded.replace('"$%s"' % name, value).replace("$%s" % name, value)
        lines.append(expanded)
    return lines


def test_every_image_build_script_pulls_a_fresh_base():
    for rel, invocation_re in BUILD_SCRIPTS.items():
        path = os.path.join(REPO, rel)
        found = _expanded_build_lines(path, invocation_re)
        assert found, "no build invocation matching %r in %s" % (invocation_re, rel)
        for line in found:
            assert "--pull" in line, (
                "%s builds without --pull, so it reuses the host's cached base "
                "image: %s" % (rel, line))
            assert "--pull=false" not in line, (
                "%s defaults to --pull=false; the opt-out belongs behind "
                "IRIS_NO_PULL, not in the default: %s" % (rel, line))


def test_every_documented_build_command_pulls_a_fresh_base():
    # A literal `docker build -...` anywhere a reader might copy it. Test
    # helpers are excluded: they build the digest-pinned XR image into a
    # throwaway tag, where a pull buys nothing and costs a download.
    command = re.compile(r"docker\s+(?:buildx\s+)?build\s+(?=-)")
    offenders = []
    listing = subprocess.run(
        ["git", "-C", REPO, "ls-files"], stdout=subprocess.PIPE)
    if listing.returncode != 0:
        pytest.skip("not a git checkout")
    for rel in listing.stdout.decode().splitlines():
        if "/tests/" in rel or os.path.basename(rel).startswith("test_"):
            continue
        try:
            text = open(os.path.join(REPO, rel), encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if command.search(line) and "--pull" not in line:
                offenders.append("%s:%d: %s" % (rel, lineno, line.strip()))
    assert not offenders, (
        "documented build commands omit --pull, so an operator pasting them "
        "builds on a stale cached base:\n  " + "\n  ".join(offenders))
