# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Clean pod shutdown evidence is bound to this precise runtime, not deletion."""

import json
from pathlib import Path
import subprocess
import uuid

import pytest

import installer_shutdown as shutdown


@pytest.fixture
def environment(tmp_path):
    for name in ('state', 'run'):
        (tmp_path / name).mkdir(mode=0o700)
    return {'IRIS_INSTALLER_SHUTDOWN_PROOF': str(tmp_path / 'state/installer-shutdown.json'),
            'IRIS_STATE': str(tmp_path / 'state'), 'IRIS_RUN': str(tmp_path / 'run'),
            'IRIS_POD_UID': str(uuid.uuid4())}


def test_clean_children_produce_pod_and_start_bound_proof(environment):
    shutdown.prepare(environment)
    nonce = (Path(environment['IRIS_RUN']) / 'installer-shutdown-nonce').read_text()
    shutdown.record(['10:0', '11:0'], environment)
    proof = Path(environment['IRIS_INSTALLER_SHUTDOWN_PROOF'])
    data = json.loads(proof.read_bytes())
    assert data == {'pod_uid': environment['IRIS_POD_UID'], 'nonce': nonce, 'clean': True,
                    'children': [{'pid': 10, 'exit_code': 0}, {'pid': 11, 'exit_code': 0}]}
    assert proof.stat().st_mode & 0o777 == 0o600
    shutdown.prepare(environment)
    assert not proof.exists()
    assert (Path(environment['IRIS_RUN']) / 'installer-shutdown-nonce').read_text() != nonce


@pytest.mark.parametrize('children', [[], ['10:137'], ['10:143'], ['10:1'], ['10:0', '10:0'], ['bad'], ['0:0']])
def test_forced_or_failed_shutdown_never_gets_clean_proof(environment, children):
    shutdown.prepare(environment)
    with pytest.raises(ValueError):
        shutdown.record(children, environment)
    assert not Path(environment['IRIS_INSTALLER_SHUTDOWN_PROOF']).exists()


def test_proof_never_overwrites_symlink_or_unrelated_path(environment, tmp_path):
    target = tmp_path / 'unrelated'
    target.write_bytes(b'owner data')
    Path(environment['IRIS_INSTALLER_SHUTDOWN_PROOF']).symlink_to(target)
    with pytest.raises(ValueError):
        shutdown.prepare(environment)
    assert target.read_bytes() == b'owner data'
    environment['IRIS_INSTALLER_SHUTDOWN_PROOF'] = str(target)
    with pytest.raises(ValueError):
        shutdown.prepare(environment)


def test_no_evidence_without_start_nonce(environment):
    with pytest.raises(OSError):
        shutdown.record(['10:0'], environment)


def test_unmanaged_runtime_is_unchanged():
    shutdown.prepare({})
    shutdown.record([], {})


@pytest.mark.parametrize('exit_code', [0, 7])
def test_entrypoint_retains_individual_child_exit_status(exit_code):
    source = (Path(__file__).parents[1] / 'docker-entrypoint.sh').read_text()
    function = 'stop_services() {' + source.split('stop_services() {', 1)[1].split('\non_shutdown()', 1)[0]
    program = function + '\nbash -c "exit ' + str(exit_code) + '" & child=$!\nwait "$child" || true\nPIDS=("$child")\nstop_services\nprintf "%s\\n" "${CHILD_RESULTS[@]}"\n'
    result = subprocess.run(['bash', '-c', program], capture_output=True, check=True, text=True)
    assert result.stdout.strip().endswith(':' + str(exit_code))
