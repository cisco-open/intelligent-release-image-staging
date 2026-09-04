# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Management tier credential rotation never exposes credential values."""

import json
import os
from pathlib import Path
import subprocess
import sys

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
    output = result.stdout + result.stderr
    assert old not in output
    assert new.decode() not in output
    assert current.stat().st_mode & 0o777 == 0o600
    assert previous.stat().st_mode & 0o777 == 0o600

    result = _run("retire-previous", current, previous)
    assert result.returncode == 0, result.stderr
    assert not previous.exists()
    assert tier_auth.load_pair(str(current), str(previous))[1] is None


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
