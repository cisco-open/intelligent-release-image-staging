# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The server image must ship the `age` binary (apt package) so the
entrypoint and broker can decrypt/encrypt the at-rest secret files."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DOCKERFILE = os.path.join(HERE, "..", "Dockerfile")


def test_dockerfile_installs_age():
    text = open(DOCKERFILE).read()
    apt_lines = [l for l in text.splitlines() if "apt-get install" in l]
    assert apt_lines, "no apt-get install line found"
    assert any(" age" in l for l in apt_lines), \
        "age package not in apt-get install"
