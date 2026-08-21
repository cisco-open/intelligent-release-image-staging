# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The handed-in aria2c binary is manifest-pinned: the image build must
verify bin/aria2c against the x86_64 entry in tools/aria2c.sha256 and fail
closed on a mismatch. Running get-aria2c.sh before the build is only a
convention — without an in-build check, any executable static binary at
bin/aria2c (stale, replaced, or from an unrelated image) would be baked in
silently despite the fail-closed supply-chain guarantee."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DOCKERFILE = os.path.join(HERE, "..", "Dockerfile")


def test_dockerfile_copies_the_checksum_manifest():
    text = open(DOCKERFILE).read()
    copy_lines = [l for l in text.splitlines() if l.startswith("COPY")]
    assert any("tools/aria2c.sha256" in l for l in copy_lines), \
        "tools/aria2c.sha256 is not copied into the build"


def test_dockerfile_verifies_aria2c_against_the_manifest():
    text = open(DOCKERFILE).read()
    assert "sha256sum /opt/iris/bin/aria2c" in text, \
        "the build does not hash bin/aria2c"
    assert 'awk \'$2 == "x86_64" {print $1}\'' in text, \
        "the build does not read the x86_64 entry from the manifest"
