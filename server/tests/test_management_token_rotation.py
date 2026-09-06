# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Management tier credential rotation never exposes credential values."""

import errno
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

import tier_auth


SCRIPT = Path(__file__).resolve().parents[1] / "iris-management-token"


def _run(action, current, previous):
    env = dict(os.environ,
               IRIS_MANAGEMENT_API_TOKEN_FILE=str(current),
               IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE=str(previous))
    return subprocess.run(
        [sys.executable, str(SCRIPT), action], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        check=False)


def test_rotate_keeps_old_as_previous_and_never_prints_either_value(tmp_path):
    current = tmp_path / "current.json"
    previous = tmp_path / "previous.json"
    old = "old-" + "a" * 60
    current.write_text(json.dumps({"scope": "management", "token": old}) + "\n",
                       encoding="utf-8")
    current.chmod(0o600)

    result = _run("rotate", current, previous)
    assert result.returncode == 0, result.stderr
    new, overlap = tier_auth.load_pair(str(current), str(previous))
    assert new != old.encode()
    assert overlap == old.encode()
    for token in (old, new.decode()):
        assert tier_auth.authorized(
            {"Authorization": "Bearer " + token}, str(current), str(previous))
    output = result.stdout + result.stderr
    assert old not in output
    assert new.decode() not in output
    assert current.stat().st_mode & 0o777 == 0o600
    assert previous.stat().st_mode & 0o777 == 0o600

    result = _run("retire-previous", current, previous)
    assert result.returncode == 0, result.stderr
    assert not previous.exists()
    assert tier_auth.load_pair(str(current), str(previous))[1] is None
    assert not tier_auth.authorized(
        {"Authorization": "Bearer " + old}, str(current), str(previous))


@pytest.mark.parametrize("existing_overlap", [False, True])
@pytest.mark.parametrize("interruption", ["overlap-sync", "current-replace", "current-sync", None])
def test_rotation_keeps_old_credential_accepted_at_durability_boundaries(
        tmp_path, monkeypatch, capsys, existing_overlap, interruption):
    loader = importlib.machinery.SourceFileLoader("management_token", str(SCRIPT))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    current = tmp_path / "current.json"
    previous = tmp_path / "previous.json"
    old = "old-" + "a" * 60
    new = "new-" + "b" * 60
    original = json.dumps({"scope": "management", "token": old}) + "\n"
    current.write_text(original, encoding="utf-8")
    current.chmod(0o600)
    if existing_overlap:
        previous.write_text("older-" + "c" * 60, encoding="utf-8")
        previous.chmod(0o600)
    monkeypatch.setenv("IRIS_MANAGEMENT_API_TOKEN_FILE", str(current))
    monkeypatch.setenv("IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE", str(previous))
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda _length: new)

    events = []
    real_replace = os.replace
    real_fsync = os.fsync

    def replace(source, destination):
        if destination == str(current):
            # The first directory sync must finish before attempting current.
            assert events == ["overlap-replace", "overlap-sync"]
            assert tier_auth.authorized(
                {"Authorization": "Bearer " + old}, str(current), str(previous))
            if interruption == "current-replace":
                raise OSError(errno.EIO, "injected current replacement failure")
        real_replace(source, destination)
        events.append("current-replace" if destination == str(current) else "overlap-replace")

    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            phase = "current-sync" if "current-replace" in events else "overlap-sync"
            if phase == interruption:
                raise OSError(errno.EIO, "injected directory sync failure")
            real_fsync(fd)
            events.append(phase)
        else:
            real_fsync(fd)

    monkeypatch.setattr(module.os, "replace", replace)
    monkeypatch.setattr(module.os, "fsync", fsync)
    if interruption is None:
        module.rotate()
        assert events == ["overlap-replace", "overlap-sync", "current-replace", "current-sync"]
    else:
        with pytest.raises(OSError, match="injected"):
            module.rotate()

    replaced_current = interruption in (None, "current-sync")
    if not replaced_current:
        assert "current-replace" not in events
        assert current.read_text(encoding="utf-8") == original
    assert previous.read_text(encoding="utf-8") == original
    assert tier_auth.authorized(
        {"Authorization": "Bearer " + old}, str(current), str(previous))
    assert tier_auth.authorized(
        {"Authorization": "Bearer " + new}, str(current), str(previous)) == replaced_current
    for path in (current, previous):
        assert path.stat().st_mode & 0o777 == 0o600
    assert sorted(path.name for path in tmp_path.iterdir()) == ["current.json", "previous.json"]
    output = capsys.readouterr()
    assert output.out == output.err == ""


def test_rotate_refuses_symlink_current_without_disclosing_value(tmp_path):
    real = tmp_path / "real.json"
    current = tmp_path / "current.json"
    previous = tmp_path / "previous.json"
    value = "secret-" + "b" * 60
    real.write_text(json.dumps({"scope": "management", "token": value}) + "\n",
                    encoding="utf-8")
    real.chmod(0o600)
    current.symlink_to(real)
    result = _run("rotate", current, previous)
    assert result.returncode == 1
    assert value not in result.stdout + result.stderr
    assert not previous.exists()
