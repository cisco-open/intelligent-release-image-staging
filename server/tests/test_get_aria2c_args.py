# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Exercise argument handling with tiny local fixtures, never real downloads."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "tools/get-aria2c.sh"


@pytest.fixture
def fixture_repo(tmp_path):
    (tmp_path / "tools").mkdir()
    (tmp_path / "bin").mkdir()
    (tmp_path / "deliverables").mkdir()
    shutil.copyfile(SOURCE, tmp_path / "tools/get-aria2c.sh")
    sums = []
    for arch in ("x86_64", "aarch64"):
        data = ("test-client-" + arch).encode()
        (tmp_path / "deliverables" / ("aria2c-" + arch)).write_bytes(data)
        sums.append(hashlib.sha256(data).hexdigest() + " " + arch)
    (tmp_path / "tools/aria2c.sha256").write_text("\n".join(sums) + "\n")
    (tmp_path / "bin/aria2c").write_bytes(b"preserve-existing-server-client")
    return tmp_path


def invoke(root, *args):
    env = dict(os.environ, ARIA2C_NO_DOWNLOAD="1")
    env.pop("ARIA2C_DELIVERABLE", None)
    return subprocess.run(["bash", str(root / "tools/get-aria2c.sh"), *args],
                          env=env, capture_output=True, text=True, timeout=5)


@pytest.mark.parametrize("args", [
    ("arm64", "--no-install"), ("amd64", "--unknown"),
    ("arm64", "amd64"), ("--no-install", "arm64", "extra"),
    ("--no-install", "--no-install", "arm64"), ("--unknown",),
])
def test_bad_invocation_fails_before_install(fixture_repo, args):
    result = invoke(fixture_repo, *args)
    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert "fetching" not in result.stdout
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"preserve-existing-server-client"


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_no_install_verifies_without_replacing_server_binary(fixture_repo, arch):
    result = invoke(fixture_repo, "--no-install", arch)
    assert result.returncode == 0, result.stderr
    assert "Verified:" in result.stdout
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"preserve-existing-server-client"


def test_valid_native_install_and_checksum_refusal(fixture_repo):
    assert invoke(fixture_repo, "amd64").returncode == 0
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"test-client-x86_64"
    (fixture_repo / "deliverables/aria2c-aarch64").write_bytes(b"wrong-bytes")
    result = invoke(fixture_repo, "arm64")
    assert result.returncode == 1 and "CHECKSUM MISMATCH" in result.stderr
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"test-client-x86_64"
