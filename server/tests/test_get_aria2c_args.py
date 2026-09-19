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


def invoke(root, *args, **extra_env):
    env = dict(os.environ, ARIA2C_NO_DOWNLOAD="1")
    env.pop("ARIA2C_DELIVERABLE", None)
    env.pop("IRIS_DEVICE_PLATFORMS", None)
    env.update(extra_env)
    return subprocess.run(["bash", str(root / "tools/get-aria2c.sh"), *args],
                          env=env, capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize("args", [
    ("arm64", "--no-install"), ("amd64", "--unknown"),
    ("arm64", "amd64"), ("--no-install", "arm64", "extra"),
    ("--no-install", "--no-install", "arm64"), ("--unknown",),
    ("--for-platforms", "linux/amd64", "extra"),
    ("--no-install", "--for-platforms", "linux/amd64"),
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


def test_for_platforms_installs_amd64_and_collects_every_other_arch(fixture_repo):
    """One run has to serve the whole deployment: the server image COPYs
    bin/aria2c, the device builders read deliverables/, and an ARM client that
    landed in bin/ would be baked into the server image (#319)."""
    result = invoke(fixture_repo, "--for-platforms", "linux/amd64,linux/arm64")
    assert result.returncode == 0, result.stderr
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"test-client-x86_64"
    assert (fixture_repo / "deliverables/aria2c-aarch64").read_bytes() \
        == b"test-client-aarch64"
    lines = result.stdout.strip().splitlines()
    assert len(lines) == 2, result.stdout
    assert lines[0].startswith("Installed: bin/aria2c") and "x86_64" in lines[0]
    assert lines[1].startswith("Collected: deliverables/aria2c-aarch64")
    assert all("sha256 matched tools/aria2c.sha256" in line for line in lines)


def test_for_platforms_defaults_to_the_device_platform_list(fixture_repo):
    result = invoke(fixture_repo, "--for-platforms",
                    IRIS_DEVICE_PLATFORMS="linux/amd64,linux/arm64")
    assert result.returncode == 0, result.stderr
    assert "deliverables/aria2c-aarch64" in result.stdout
    # and with neither a list nor the variable, only the server's own client
    (fixture_repo / "bin/aria2c").write_bytes(b"preserve-existing-server-client")
    result = invoke(fixture_repo, "--for-platforms")
    assert result.returncode == 0, result.stderr
    assert "aarch64" not in result.stdout
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"test-client-x86_64"


def test_for_platforms_refuses_a_bad_checksum(fixture_repo):
    (fixture_repo / "deliverables/aria2c-aarch64").write_bytes(b"wrong-bytes")
    result = invoke(fixture_repo, "--for-platforms", "linux/amd64,linux/arm64")
    assert result.returncode == 1
    assert "CHECKSUM MISMATCH" in result.stderr
    assert "nothing further was installed" in result.stderr
    # the one client that did verify is installed; the bad one is not adopted
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"test-client-x86_64"
    assert (fixture_repo / "deliverables/aria2c-aarch64").read_bytes() == b"wrong-bytes"


def test_for_platforms_rejects_an_unsupported_platform(fixture_repo):
    result = invoke(fixture_repo, "--for-platforms", "linux/amd64,linux/riscv64")
    assert result.returncode == 2
    assert "unsupported platform" in result.stderr


@pytest.mark.parametrize("existing", [False, True])
def test_no_install_collects_verified_external_handin(fixture_repo, existing):
    destination = fixture_repo / "deliverables/aria2c-aarch64"
    handin = fixture_repo / "approved-arm-client"
    handin.write_bytes(destination.read_bytes())
    if existing:
        destination.write_bytes(b"stale-unverified-client")
    else:
        destination.unlink()
    result = invoke(fixture_repo, "--for-platforms", "linux/arm64",
                    ARIA2C_DELIVERABLE=str(handin))
    assert result.returncode == 0, result.stderr
    assert destination.read_bytes() == handin.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o755
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"preserve-existing-server-client"


def test_valid_native_install_and_checksum_refusal(fixture_repo):
    assert invoke(fixture_repo, "amd64").returncode == 0
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"test-client-x86_64"
    (fixture_repo / "deliverables/aria2c-aarch64").write_bytes(b"wrong-bytes")
    result = invoke(fixture_repo, "arm64")
    assert result.returncode == 1 and "CHECKSUM MISMATCH" in result.stderr
    assert (fixture_repo / "bin/aria2c").read_bytes() == b"test-client-x86_64"
