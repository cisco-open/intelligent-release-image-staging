# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real-file interruption tests for managed application upgrade authority."""

import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import upgrade_state as state
from iris_installer.state import InstallError, atomic_write

INSTANCE = '95e38cd1-74e5-4f3e-a713-c39383d2ea14'
OPERATION = '67c8aebe-fc1d-4b1f-9df7-762b2d137bf1'


@pytest.fixture
def operation(tmp_path):
    tmp_path.chmod(0o700)
    value = state.Operation(tmp_path, OPERATION, INSTANCE)
    value.create({'recorded': 'before-any-mutation'})
    return value


@pytest.mark.parametrize('phase', sorted(state.PHASES - state.PASSIVE))
def test_all_admitted_phases_block_every_other_operation(operation, phase):
    operation.phase(phase)
    with pytest.raises(InstallError, match='Recover'):
        state.guard(operation.base)
    assert state.guard(operation.base, inspection=True) is True
    assert state.guard(operation.base, operation_id=OPERATION, instance_id=INSTANCE) is False


@pytest.mark.parametrize('phase', sorted(state.PASSIVE))
def test_preparation_and_terminal_records_do_not_block(operation, phase):
    operation.phase(phase)
    assert state.guard(operation.base) is False


def test_failed_unplanned_build_allows_new_preparation_without_deleting_old_attempt(operation):
    before = operation.path.read_bytes()
    retained = operation.directory / 'partial-output'
    retained.write_bytes(b'failed build output retained')
    replacement = state.Operation(operation.base, '5b491b68-b33d-4e73-bb90-ffb77d9d8b61', INSTANCE)
    replacement.create({'recorded': 'independent new preparation'})
    assert operation.path.read_bytes() == before
    assert retained.read_bytes() == b'failed build output retained'
    assert not (operation.directory / 'plan.json').exists()
    assert state.guard(operation.base) is False


def test_missing_pointer_is_not_idle_and_only_exact_recovery_repairs(operation):
    path = operation.base / 'application-upgrade.json'
    path.unlink()
    with pytest.raises(InstallError, match='pointer is missing'):
        state.guard(operation.base)
    with pytest.raises(InstallError):
        state.guard(operation.base, operation_id=OPERATION, instance_id=INSTANCE,
                    recovery_record=dict(operation.record, changed=True))
    assert not path.exists()
    operation.load(recover=True)
    assert json.loads(path.read_bytes()) == state.pointer(operation.record)


@pytest.mark.parametrize('old,new', [('building', 'prepared'), ('prepared', 'building'),
                                   ('upgraded', 'prepared'), ('fencing', 'stopped')])
def test_stale_pointer_requires_explicit_same_operation_recovery(operation, old, new):
    operation.phase(old)
    operation.record['phase'] = new
    atomic_write(operation.path, state.canonical(operation.record))
    with pytest.raises(InstallError, match='pointer differs'):
        state.guard(operation.base, inspection=True)
    operation.load(recover=True)
    assert json.loads((operation.base / 'application-upgrade.json').read_bytes())['phase'] == new


def test_schema_boolean_is_not_schema_one(operation):
    atomic_write(operation.path, state.canonical(dict(operation.record, schema=True)))
    with pytest.raises(InstallError, match='Unsupported'):
        operation.load(recover=True)


def test_guard_refuses_foreign_identity_even_for_explicit_recovery(operation):
    operation.record['instance_id'] = OPERATION
    atomic_write(operation.path, state.canonical(operation.record))
    with pytest.raises(InstallError, match='another'):
        operation.load(recover=True)


def test_plan_cannot_be_replaced_or_approved_under_another_digest(operation):
    value = {'instance_id': INSTANCE, 'operation_id': OPERATION, 'generation': 'new'}
    operation.write_plan(value)
    assert operation.plan(operation.record['plan_sha256']) == value
    with pytest.raises(InstallError, match='cannot be replaced'):
        operation.write_plan(dict(value, generation='different'))
    with pytest.raises(InstallError, match='explicit approval'):
        operation.plan('0' * 64)


def test_linked_or_public_custody_never_authorizes_recovery(operation):
    operation.path.chmod(0o644)
    with pytest.raises(InstallError, match='Unsafe'):
        operation.load(recover=True)


def test_recovery_record_preserves_json_boolean_integer_distinction(operation):
    operation.record['evidence'] = True
    operation.save()
    with pytest.raises(InstallError, match='authority changed'):
        state.guard(operation.base, operation_id=OPERATION, instance_id=INSTANCE,
                    recovery_record=dict(operation.record, evidence=1))
