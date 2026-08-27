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
(issue #13)."""
import os
import re

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
