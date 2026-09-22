# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Execute extracted AI-guide commands with local stubs, never sudo/network."""
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
# The old single AI guide split when the manual was reorganized: the operator
# steps went to the Installation Guide, the package-build recipe to the
# developer notes. Each block below is executed from the page that owns it.
GUIDE_INSTALL = (ROOT / "docs/zensical/install/check-the-host.md").read_text()
GUIDE_SIGNING = (ROOT / "docs/zensical/install/activate-signing.md").read_text()
GUIDE_BUILD = (ROOT / "docs/dev/device-packages.md").read_text()


def command_containing(needle, guide=None):
    text = GUIDE_INSTALL if guide is None else guide
    return next(block for block in re.findall(r"```bash\n(.*?)\n```", text, re.S)
                if needle in block)


@pytest.fixture
def stub_commands(tmp_path, monkeypatch):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    calls = tmp_path / "calls"
    for name, body in {
        "sudo": 'printf "sudo:%s\\n" "$*" >> "$IRIS_TEST_CALLS"\n'
                '[ "${IRIS_TEST_SUDO_FAIL:-0}" = 0 ] || exit 23\n'
                '[ "$1" = install ] || exit 99\nshift\ninstall "$@"\n',
        "git": 'printf "git:%s\\n" "$*" >> "$IRIS_TEST_CALLS"\n'
               '[ "${IRIS_TEST_GIT_FAIL:-0}" = 0 ] || exit 29\n',
    }.items():
        script = binaries / name
        script.write_text("#!/bin/sh\nset -eu\n" + body)
        script.chmod(0o700)
    monkeypatch.setenv("PATH", str(binaries) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("IRIS_TEST_CALLS", str(calls))
    return calls


def clone_block(target):
    block = command_containing("IRIS_DIR=/opt/iris/intelligent-release-image-staging")
    return block.replace("IRIS_DIR=/opt/iris/intelligent-release-image-staging",
                         'IRIS_DIR="$1"', 1)


def test_fresh_clone_creates_only_checkout_not_parent(tmp_path, stub_commands):
    target = tmp_path / "existing-parent" / "checkout"
    target.parent.mkdir(mode=0o711)
    before = target.parent.stat()
    result = subprocess.run(["bash", "-c", clone_block(target), "recipe", str(target)],
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    after = target.parent.stat()
    assert (after.st_mode, after.st_uid, after.st_gid) == (before.st_mode, before.st_uid, before.st_gid)
    calls = stub_commands.read_text().splitlines()
    assert calls[0].endswith(" " + str(target))
    assert "sudo:install -d -o " in calls[0]
    assert calls[1].endswith(" " + str(target))


@pytest.mark.parametrize("existing", ["directory", "file", "dangling-symlink"])
def test_clone_refuses_existing_target_before_sudo_or_git(tmp_path, stub_commands, existing):
    target = tmp_path / "checkout"
    if existing == "directory":
        target.mkdir()
    elif existing == "file":
        target.write_text("operator data")
    else:
        target.symlink_to(tmp_path / "not-created")
    result = subprocess.run(["bash", "-c", clone_block(target), "recipe", str(target)],
                            text=True, capture_output=True)
    assert result.returncode != 0
    assert "already exists" in result.stderr
    assert not stub_commands.exists()


@pytest.mark.parametrize("failure, code", [("sudo", 23), ("git", 29)])
def test_clone_failure_stops_before_next_step_or_changing_directory(
        tmp_path, stub_commands, monkeypatch, failure, code):
    target = tmp_path / "checkout"
    monkeypatch.setenv("IRIS_TEST_" + failure.upper() + "_FAIL", "1")
    script = clone_block(target) + '\nIRIS_RECIPE_RC=$?\npwd\nexit "$IRIS_RECIPE_RC"\n'
    result = subprocess.run(["bash", "-c", script, "recipe", str(target)],
                            cwd=tmp_path, text=True, capture_output=True)
    assert result.returncode == code
    assert result.stdout.strip() == str(tmp_path)
    calls = stub_commands.read_text().splitlines()
    assert len(calls) == (1 if failure == "sudo" else 2)
    if failure == "sudo":
        assert not target.exists()  # clone was never attempted


def test_detached_build_keeps_checkout_working_directory(tmp_path):
    build = tmp_path / "tools/aria2c-build"
    build.mkdir(parents=True)
    block = command_containing("setsid nohup ./build.sh aarch64", GUIDE_BUILD)
    # An exported shell function substitutes only the expensive background
    # command. The documented cd/subshell/redirections execute unchanged.
    script = 'setsid() { return 0; }; export -f setsid\n' + block + '\npwd\n'
    result = subprocess.run(["bash", "-c", script], cwd=tmp_path,
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(tmp_path)
    assert (build / "build-aarch64.pid").is_file()


def test_detached_build_stops_when_build_directory_is_missing(tmp_path):
    block = command_containing("setsid nohup ./build.sh aarch64", GUIDE_BUILD)
    script = 'setsid() { touch incorrectly-started; }; export -f setsid\n' + block
    result = subprocess.run(["bash", "-c", script], cwd=tmp_path,
                            text=True, capture_output=True)
    assert result.returncode != 0
    assert not (tmp_path / "incorrectly-started").exists()
    assert not (tmp_path / "build-aarch64.pid").exists()


def test_custody_status_requires_more_than_two_booleans():
    from instruction_keys import build_custody_status
    status = build_custody_status(now=1000, enabled=True, certificate_info=None,
                                 keylist_info=None, roots_configured=2)
    assert status["enabled"] is True and status["signing_refused"] is False
    assert status["state"] == "invalid"
    section = GUIDE_SIGNING.split("### Reading the status\n", 1)[1].split(
        "\n## ", 1)[0]
    assert "alone as readiness" in section
    assert "state: invalid" in section and "state: error" in section


def test_audit_export_recovery_does_not_reuse_uncertain_password():
    troubleshooting = (
        ROOT / "docs/zensical/user-guide/troubleshooting.md").read_text()
    row = next(line for line in troubleshooting.splitlines()
               if line.startswith("| An audit-export save says exports are disabled |"))
    assert "Reload" in row and "complete destination and password" in row
    assert "do not leave the password blank" in row
    assert "disabled until a complete save succeeds" in row
    assert "previous complete configuration may finish" in row
