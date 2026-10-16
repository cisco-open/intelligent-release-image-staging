# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exact uninstall plans, negative admission and original-operation recovery."""

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import cli, deploy, managed_worker, state, uninstall as api
from iris_installer import uninstall_runtime as runtime, upgrade_state
from iris_installer.state import InstallError, Journal, atomic_write


class Adapter:
    def __init__(self, rows):
        self.rows, self.calls, self.fail = rows, [], None

    def snapshot(self):
        return {'engine': 'owned-engine', 'resources': copy.deepcopy(self.rows)}

    def stable(self, value):
        return {'engine': value['engine'], 'resources': {
            key: {name: row[name] for name in ('id', 'sha256')} for key, row in value['resources'].items()}}

    def stop(self, key, expected):
        assert self.stable(self.snapshot()) == expected
        self.calls.append(('stop', key))
        self.rows[key]['running'] = False
        return self.snapshot()

    def remove(self, key, expected):
        assert self.stable(self.snapshot()) == expected
        self.calls.append(('remove', key))
        if self.fail == 'before':
            self.fail = None
            raise InstallError('unknown removal result')
        del self.rows[key]
        if self.fail == 'after':
            self.fail = None
            raise InstallError('unknown removal result')
        return self.snapshot()


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip('real root-owned service and installation locks require root')
    base = tmp_path / 'state'
    base.mkdir(mode=0o700)
    identifier = str(uuid.uuid4())
    document = {'schema': 1, 'id': identifier, 'config': {'target': 'docker', 'instance': 'iris-owned'},
                'completed': {}, 'state': 'ready'}
    with Journal(base).locked() as journal:
        journal.document = document
        journal.save()
    units = tmp_path / 'units'
    units.mkdir()
    unit = units / ('iris-lifecycle-' + identifier + '.service')
    atomic_write(unit, b'owned unit', 0o644)
    saved = {'record': {'unit': unit.name}, 'unit_sha256': hashlib.sha256(unit.read_bytes()).hexdigest(), 'dropin': None}
    adapter = Adapter({'container/iris': {'id': 'a' * 64, 'sha256': '1' * 64, 'running': True},
                       'network/iris': {'id': 'b' * 64, 'sha256': '2' * 64},
                       'volume/iris': {'id': 'iris-volume', 'sha256': '3' * 64}})
    install = SimpleNamespace(base=base, config=document['config'], verify_inputs=lambda: None)
    calls = []
    monkeypatch.setattr(managed_worker, '_root', lambda: None)
    monkeypatch.setattr(managed_worker, '_path', lambda path: Path(path))
    monkeypatch.setattr(managed_worker, 'UNIT_DIRECTORY', units)
    monkeypatch.setattr(api, 'worker_snapshot', lambda _: saved)
    monkeypatch.setattr(api, 'check_worker', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api, 'worker_stopped', lambda *_args: {'stopped': True})
    monkeypatch.setattr(api, 'idle', lambda _: calls.append('idle'))
    monkeypatch.setattr(api.upgrade_runtime, 'jobs_idle', lambda _: calls.append('jobs-idle'))
    monkeypatch.setattr(api.upgrade_runtime, 'drain', lambda _, **kw: calls.append(('drain', kw.get('stopped', False))))
    from iris_installer import trust_maintenance
    monkeypatch.setattr(trust_maintenance, '_stopped', lambda _: calls.append('all-writers-stopped'))
    monkeypatch.setattr(deploy, 'installation', lambda journal: install)
    monkeypatch.setattr(runtime, 'discover', lambda _: {'local': {'names': {
        'container': {'iris': {}}, 'network': {'iris': {}}, 'volume': {'iris': {}}}}})
    monkeypatch.setattr(runtime, 'driver', lambda *_args: adapter)
    def command(argv, **_kwargs):
        calls.append(argv)
        if argv[:2] == ['systemctl', 'show']:
            return b'LoadState=not-found\nActiveState=inactive\nMainPID=0\n'
        return b''
    monkeypatch.setattr(managed_worker, 'command', command)
    return SimpleNamespace(base=base, adapter=adapter, calls=calls, unit=unit, document=document,
                           args=SimpleNamespace(state_dir=base, purge_data=False, allow_downtime=True))


def prepared(deployment, purge=False):
    deployment.args.purge_data = purge
    assert api.plan(deployment.args) == 0
    record = api.read(deployment.base)
    deployment.args.operation_id = record['operation_id']
    deployment.args.plan_sha256 = record['plan_sha256']
    return record


@pytest.mark.parametrize('purge', [False, True])
def test_plan_then_apply_exact_resources_and_retained_history(deployment, purge):
    original = (deployment.base / 'installation.json').read_bytes()
    prepared(deployment, purge)
    assert not deployment.adapter.calls
    assert api.apply(deployment.args) == 0
    assert api.read(deployment.base)['phase'] == 'uninstalled'
    assert set(deployment.adapter.rows) == (set() if purge else {'volume/iris'})
    assert (deployment.base / 'installation.json').read_bytes() == original
    assert not deployment.unit.exists()
    assert deployment.calls.index('all-writers-stopped') < deployment.calls.index(('drain', True))
    assert api.status(deployment.args) == 0
    with pytest.raises(InstallError, match='uninstall'):
        with Journal(deployment.base).locked():
            pass
    with pytest.raises(InstallError, match='uninstall'):
        upgrade_state.guard(deployment.base)


@pytest.mark.parametrize('failure', ['before', 'after'])
def test_unknown_remove_retains_intent_and_recovery_observes_original(deployment, failure):
    prepared(deployment)
    deployment.adapter.fail = failure
    with pytest.raises(InstallError, match='unknown'):
        api.apply(deployment.args)
    record = api.read(deployment.base)
    assert record['phase'] == 'removing' and record['pending'] == ['local', 'container/iris']
    with pytest.raises(InstallError, match='recover'):
        api.apply(deployment.args)
    assert api.apply(deployment.args, recovery=True) == 0
    attempts = [call for call in deployment.adapter.calls if call == ('remove', 'container/iris')]
    assert len(attempts) == (2 if failure == 'before' else 1)


def test_unknown_remove_replacement_is_never_adopted(deployment):
    prepared(deployment)
    deployment.adapter.fail = 'after'
    with pytest.raises(InstallError):
        api.apply(deployment.args)
    deployment.adapter.rows['container/iris'] = {'id': 'f' * 64, 'sha256': '1' * 64, 'running': False}
    before = list(deployment.adapter.calls)
    with pytest.raises(InstallError, match='changed or replaced'):
        api.apply(deployment.args, recovery=True)
    assert deployment.adapter.calls == before


@pytest.mark.parametrize('change', ['operation', 'digest', 'purge', 'downtime', 'journal', 'resource', 'missing'])
def test_stale_or_ambiguous_approval_refuses_before_fencing(deployment, change):
    prepared(deployment)
    if change == 'operation':
        deployment.args.operation_id = str(uuid.uuid4())
    elif change == 'digest':
        deployment.args.plan_sha256 = 'f' * 64
    elif change == 'purge':
        deployment.args.purge_data = True
    elif change == 'downtime':
        deployment.args.allow_downtime = False
    elif change == 'journal':
        with Journal(deployment.base).locked() as journal:
            journal.document['extra'] = 'changed'
            journal.save()
    elif change == 'resource':
        deployment.adapter.rows['volume/iris']['sha256'] = 'f' * 64
    else:
        del deployment.adapter.rows['volume/iris']
    with pytest.raises(InstallError):
        api.apply(deployment.args)
    assert not deployment.adapter.calls
    assert not any(isinstance(call, list) and call[:2] == ['systemctl', 'disable'] for call in deployment.calls)


@pytest.mark.parametrize('gate', ['idle', 'drain'])
def test_active_jobs_or_undeployed_devices_block_plan(deployment, monkeypatch, gate):
    def fail(*_args, **_kwargs):
        raise InstallError('admission refused')
    if gate == 'idle':
        monkeypatch.setattr(api, 'idle', fail)
    else:
        monkeypatch.setattr(api.upgrade_runtime, 'drain', fail)
    with pytest.raises(InstallError, match='admission'):
        api.plan(deployment.args)
    assert not (deployment.base / api.RECORD).exists()
    assert not deployment.adapter.calls


def test_device_removal_is_rechecked_after_writer_stop(deployment, monkeypatch):
    prepared(deployment)
    def drain(_install, *, stopped=False):
        if stopped:
            raise InstallError('device appeared before shutdown')
    monkeypatch.setattr(api.upgrade_runtime, 'drain', drain)
    with pytest.raises(InstallError, match='device appeared'):
        api.apply(deployment.args)
    assert not any(call[0] == 'remove' for call in deployment.adapter.calls)
    assert api.read(deployment.base)['phase'] == 'fencing'


def test_cancel_archives_only_unapplied_plan_and_allows_fresh_plan(deployment):
    saved = prepared(deployment)
    raw = (deployment.base / api.RECORD).read_bytes()
    assert api.cancel(deployment.args) == 0
    history = deployment.base / ('uninstall-cancelled-' + saved['operation_id'] + '.json')
    assert history.read_bytes() == raw
    assert not (deployment.base / api.RECORD).exists()
    prepared(deployment)
    assert api.read(deployment.base)['operation_id'] != saved['operation_id']


def test_plan_and_apply_respect_existing_locks(deployment):
    with Journal(deployment.base).locked():
        with pytest.raises(InstallError, match='Another installer'):
            api.plan(deployment.args)
    prepared(deployment)
    with managed_worker._service_lock(deployment.base):
        with pytest.raises(InstallError, match='Another managed'):
            api.apply(deployment.args)


@pytest.mark.parametrize('verb', ['plan', 'apply', 'recover', 'status', 'cancel'])
def test_cli_dispatch_uses_explicit_plan_and_purge_choice(monkeypatch, tmp_path, verb):
    calls = []
    handler = 'apply' if verb == 'recover' else verb
    monkeypatch.setattr(api, handler, lambda args, **kw: calls.append((args, kw)) or 0)
    argv = ['uninstall', verb, '--state-dir', str(tmp_path)]
    if verb in ('apply', 'recover', 'cancel'):
        argv += ['--operation-id', str(uuid.uuid4()), '--plan-sha256', 'a' * 64]
    if verb in ('apply', 'recover'):
        argv += ['--allow-downtime', '--purge-data']
    assert cli.main(argv) == 0
    assert calls[0][0].state_dir == tmp_path
    if verb == 'recover':
        assert calls[0][1] == {'recovery': True}


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'mode', 'digest'])
def test_private_plan_custody_refuses_replacement(deployment, kind):
    prepared(deployment)
    path = deployment.base / api.RECORD
    if kind == 'symlink':
        renamed = deployment.base / 'other'
        path.rename(renamed)
        path.symlink_to(renamed)
    elif kind == 'hardlink':
        os.link(path, deployment.base / 'other')
    elif kind == 'mode':
        path.chmod(0o644)
    else:
        saved = json.loads(path.read_bytes())
        saved['plan']['purge_data'] = True
        atomic_write(path, json.dumps(saved).encode())
    with pytest.raises((InstallError, OSError)):
        api.status(deployment.args)


def test_purge_selects_only_exact_owned_data_and_secrets_not_namespace():
    rows = {kind + '/owned': {} for kind in (
        'Namespace', 'Deployment', 'Service', 'PersistentVolumeClaim', 'Secret', 'ConfigMap', 'NetworkPolicy')}
    default = runtime.targets('kubernetes', {'resources': rows}, False)
    purge = runtime.targets('kubernetes', {'resources': rows}, True)
    assert 'Namespace/owned' not in default + purge
    assert 'Secret/owned' not in default and 'PersistentVolumeClaim/owned' not in default
    assert set(purge) - set(default) == {'Secret/owned', 'PersistentVolumeClaim/owned'}


def pending_capture(base, identity, phase):
    if phase in ('stopping', 'restart_required'):
        atomic_write(base / 'backup-operation.json', json.dumps({
            'state': 'stopping' if phase == 'stopping' else 'failed',
            'restart_required': phase == 'restart_required', 'backup_set_id': str(uuid.uuid4())}).encode())
        return
    directory = base / 'backup-captures'
    directory.mkdir(mode=0o700)
    request = str(uuid.uuid4())
    atomic_write(directory / (request + '.json'), json.dumps({'schema': 1,
        'request_id': request, 'phase': phase, 'generation': {'instance_id': identity}}).encode())


@pytest.mark.parametrize('phase', ['stopping', 'restart_required', 'exporting', 'settlement-required'])
def test_real_idle_guard_refuses_standalone_interrupted_capture(tmp_path, phase):
    if os.geteuid() != 0:
        pytest.skip('root-private existing capture guard')
    base = tmp_path / 'state'
    base.mkdir(mode=0o700)
    identity = str(uuid.uuid4())
    pending_capture(base, identity, phase)
    with Journal(base).locked() as journal:
        journal.document = {'schema': 1, 'id': identity, 'config': {}, 'completed': {}, 'state': 'ready'}
        journal.save()
        with pytest.raises(InstallError, match='interrupted'):
            api.idle(journal)
    assert not (base / api.RECORD).exists()


@pytest.mark.parametrize('when', ['before-apply', 'after-writer-stop', 'during-removal-recovery'])
def test_pending_capture_blocks_new_removal_but_keeps_uninstall_status(deployment, monkeypatch, when):
    prepared(deployment)
    if when == 'after-writer-stop':
        def drain(_install, *, stopped=False):
            if stopped:
                pending_capture(deployment.base, deployment.document['id'], 'restart_required')
        monkeypatch.setattr(api.upgrade_runtime, 'drain', drain)
    elif when == 'during-removal-recovery':
        deployment.adapter.fail = 'before'
        with pytest.raises(InstallError, match='unknown'):
            api.apply(deployment.args)
        pending_capture(deployment.base, deployment.document['id'], 'stopping')
    else:
        pending_capture(deployment.base, deployment.document['id'], 'stopping')
    removals_before = [row for row in deployment.adapter.calls if row[0] == 'remove']
    with pytest.raises(InstallError, match='interrupted'):
        api.apply(deployment.args, recovery=when == 'during-removal-recovery')
    assert [row for row in deployment.adapter.calls if row[0] == 'remove'] == removals_before
    assert api.status(deployment.args) == 0
    assert api.read(deployment.base)['phase'] != 'uninstalled'
