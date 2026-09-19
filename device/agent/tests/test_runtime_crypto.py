# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import os
import shutil

import pytest
import instruction_aead
import runtime_crypto


def fixture(tmp_path):
    stage = tmp_path/'stage'
    agent = stage/'agent'
    runtime = tmp_path/'exec'
    agent.mkdir(parents=True)
    runtime.mkdir()
    shutil.copyfile(instruction_aead.helper_path(), agent/'iris-aead')
    return stage, agent, runtime


def test_native_known_answer_probe_and_atomic_promotion(tmp_path):
    stage, agent, runtime = fixture(tmp_path)
    assert runtime_crypto.select(str(agent), str(runtime)) is None
    assert runtime_crypto.install(str(stage), str(runtime))
    target = runtime_crypto.select(str(agent), str(runtime))
    assert target == str(runtime/'iris-aead')
    assert Path(target).stat().st_mode & 0o777 == 0o700
    assert not runtime_crypto.install(str(stage), str(runtime))
    (runtime/'iris-aead').chmod(0o755)
    assert runtime_crypto.select(str(agent), str(runtime)) is None


def test_bad_candidate_does_not_replace_working_helper(tmp_path):
    stage, agent, runtime = fixture(tmp_path)
    runtime_crypto.install(str(stage), str(runtime))
    before = (runtime/'iris-aead').read_bytes()
    (agent/'iris-aead').write_bytes(b'\x7fELFbad candidate')
    with pytest.raises((ValueError, OSError)):
        runtime_crypto.install(str(stage), str(runtime))
    assert (runtime/'iris-aead').read_bytes() == before
    assert runtime_crypto.select(str(agent), str(runtime)) is None


def test_symlink_source_is_not_followed(tmp_path):
    stage, agent, runtime = fixture(tmp_path)
    source = agent/'iris-aead'
    source.rename(agent/'original')
    source.symlink_to(agent/'original')
    with pytest.raises((ValueError, OSError)):
        runtime_crypto.install(str(stage), str(runtime))
    assert not (runtime/'iris-aead').exists()
