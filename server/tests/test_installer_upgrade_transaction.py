# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real filesystem publication/recovery with simulated Docker/systemd boundaries.

These are fault-injection tests, not live deployment qualification.
"""

import copy
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import application_upgrade as upgrade, upgrade_plan as plan, upgrade_runtime as runtime
from iris_installer import credential_maintenance, upgrade_state
from iris_installer import upgrade_boot_guard
from iris_installer.state import InstallError, atomic_write

INSTANCE = '1e2ac67b-07c1-4e94-a66b-08b19f8e2d75'
OPERATION = '7f761c39-450f-4101-836e-6515449d7b28'
IMAGES = {'iris': 'sha256:' + '1' * 64, 'console': 'sha256:' + '2' * 64}
REAL_FENCE_WORKER = runtime.fence_worker


def sha(value):
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def transaction(tmp_path, monkeypatch):
    base = tmp_path / 'deployment'; base.mkdir(mode=0o700)
    for name in ('source', 'artifacts', 'images', 'roots', 'volume-iris-state', 'volume-iris-config'):
        (base / name).mkdir(mode=0o755)
    atomic_write(base / 'source/code.py', b'old committed code', 0o644)
    atomic_write(base / 'artifacts/iris-catalog.pem', b'existing public runtime certificate', 0o644)
    atomic_write(base / 'volume-iris-config/account.age', b'existing encrypted owner', 0o600)
    atomic_write(base / 'volume-iris-state/replay', b'epoch=17;high_water=900', 0o600)
    atomic_write(base / 'images/owned.img', b'existing owner content', 0o644)
    atomic_write(base / 'age.txt', b'existing service identity', 0o600)
    original_compose = {'name': 'owned', 'services': {name: {
        'image': 'old-' + name, 'container_name': 'owned-' + name, 'restart': 'unless-stopped',
        'environment': {'CURRENT_CREDENTIAL': '/existing'},
        'volumes': [{'source': 'original-state', 'target': '/state'}]}
        for name in plan.SERVICES}, 'volumes': {'original-state': {'name': 'original-state'}},
        'networks': {'default': {'name': 'owned-network'}}}
    raw_compose = plan.canonical(original_compose)
    original = {'schema': 1, 'id': INSTANCE, 'config': {'target': 'docker', 'instance': 'owned'},
        'source_manifest': {'code.py': sha(b'old committed code')},
        'root_digests': {'root-a.pub': 'a' * 64, 'root-b.pub': 'b' * 64},
        'completed': {'prepared': sha(raw_compose), 'images': {'old-iris': 'sha256:' + '3' * 64,
            'old-console': 'sha256:' + '4' * 64}, 'packages': {name: 'c' * 64 for name in plan.NATIVE_FILES},
            'signing': True, 'guestshell': {'state': 'ok'}}, 'state': 'PRODUCTION_REVIEW_REQUIRED'}
    atomic_write(base / 'compose.json', raw_compose)
    atomic_write(base / 'installation.json', plan.canonical(original))
    operation = upgrade_state.Operation(base, OPERATION, INSTANCE)
    worker = {'record': {'unit': 'iris-lifecycle-' + INSTANCE + '.service'}, 'unit_sha256': 'd' * 64}
    operation.create({'original': original, 'worker_before': worker})
    source = base / ('.upgrade-source-' + OPERATION); source.mkdir(mode=0o755)
    atomic_write(source / 'code.py', b'new committed code', 0o644)
    outputs = operation.directory / 'artifacts'; outputs.mkdir(mode=0o755)
    files = {}
    for name in plan.BUILD_FILES:
        data = ('new approved bytes:' + name).encode()
        atomic_write(outputs / name, data, 0o644); files[name] = sha(data)
    final = plan.candidate_compose(original_compose, original_compose, original_compose, IMAGES)
    for spec in final['services'].values():
        spec['labels'] = {'com.cisco.iris.application-upgrade': OPERATION}
    candidate = {'selection': {'runtime': {'state.py': 'f' * 64}, 'commit': '9' * 40},
        'source': {'code.py': sha(b'new committed code')}, 'images': IMAGES, 'files': files,
        'compose': final, 'source_directory': str(source), 'artifacts_directory': str(outputs)}
    containers = [{'id': 'old-' + name, 'service': name, 'running': True} for name in ('console', 'iris')]
    sources = {'volume-iris-state': base / 'volume-iris-state', 'volume-iris-config': base / 'volume-iris-config'}
    volumes = {'original-state': str(base / 'volume-iris-state')}
    review = {'schema': plan.SCHEMA, 'operation_id': OPERATION, 'instance_id': INSTANCE,
        'original': original, 'compose_before': raw_compose.decode(), 'worker_before': worker,
        'resources': {'volumes': volumes, 'containers': containers}, 'candidate': candidate}
    operation.record['candidate'] = candidate
    operation.write_plan(review)
    control = {'events': [], 'failure': None, 'triggered': False, 'worker_fenced': False,
        'containers': {row['service']: dict(row, image=original['completed']['images'][row['id']], restart='unless-stopped')
                       for row in containers}}

    def event(name):
        control['events'].append(name)
        if control['failure'] == name and not control['triggered']:
            control['triggered'] = True
            raise InstallError('injected:' + name)

    class Install:
        def __init__(self, journal):
            self.journal, self.base, self.source = journal, base, base / 'source'
            self.config, self.compose_file = journal.document['config'], base / 'compose.json'

        def verify_inputs(self):
            actual = {'code.py': sha((base / 'source/code.py').read_bytes())}
            assert actual == self.journal.document['source_manifest']

        def command(self, argv, **kwargs):
            if argv[:3] == ['docker', 'container', 'ls']:
                name = next(name for name in plan.SERVICES
                            if argv[6] == 'name=^/' + re.escape('owned-' + name) + '$')
                row = control['containers'].get(name)
                return (row['id'] if row else '').encode()
            if argv[:2] == ['docker', 'inspect']:
                row = next((row for name, row in control['containers'].items()
                            if argv[2] in (row['id'], 'owned-' + name)), None)
                if row is None:
                    raise InstallError('No such container')
                return plan.canonical([{'Id': row['id'], 'Image': row['image'],
                    'Config': {'Labels': {'com.cisco.iris.installer': INSTANCE,
                        'com.docker.compose.project': 'owned', 'com.docker.compose.service': row['service'],
                        **({'com.cisco.iris.application-upgrade': OPERATION}
                           if row['image'] == IMAGES[row['service']] else {})}},
                    'State': {'Running': row['running'], 'ExitCode': 0},
                    'HostConfig': {'RestartPolicy': {'Name': row['restart']}}}])
            if argv[:2] == ['docker', 'update']:
                row = next(row for row in control['containers'].values() if row['id'] == argv[-1])
                row['restart'] = argv[2].split('=', 1)[1]
                if row['restart'] != 'no': event('enable-' + row['service'])
                return b''
            if argv[:2] == ['docker', 'stop']:
                row = next(row for row in control['containers'].values() if row['id'] == argv[-1])
                row['running'] = False
                return b''
            raise AssertionError(argv)

        def compose(self, *args, **kwargs):
            assert args[0] == 'up'
            name = args[-1]
            assert self.journal.document['completed']['images'][IMAGES[name]] == IMAGES[name]
            control['containers'][name] = dict(id='new-' + name, service=name, running=True,
                image=IMAGES[name], restart='no')
            event('start-' + name)

        def packages(self):
            event('packages')
            runtime.verify_files(base / 'artifacts', {name: files[name] for name in plan.NATIVE_FILES})
            self.journal.checkpoint('guestshell', {'state': 'ok', 'sha256': 'e' * 64})

    def capture(install, **kwargs):
        return sources, volumes, [{key: row[key] for key in ('id', 'service', 'running')}
            for name in ('console', 'iris') for row in [control['containers'][name]]]

    def fence(*args, **kwargs):
        saved = json.loads(operation.path.read_bytes())
        assert saved.get('fence_intent') == worker
        control['worker_fenced'] = True
        event('fence-worker')
        return {'ActiveState': 'inactive', 'UnitFileState': 'disabled'}

    def capture_backup(*args):
        event('backup')
        return {'paths': {}, 'proof': {'verified': True}}

    def stop(install, rows, **kwargs):
        for row in control['containers'].values(): row['running'] = False
        event('stop-writers')

    def authority(*args):
        event('authority')
        return {name: sha((base / name).read_bytes()) for name in
                ('age.txt', 'volume-iris-config/account.age', 'volume-iris-state/replay', 'images/owned.img')}

    def refresh(*args):
        control['worker_fenced'] = False
        event('refresh-worker')
        return {'managed': True, 'active': True, 'enabled': True}

    monkeypatch.setattr(upgrade, '_root', lambda value: Path(value))
    monkeypatch.setattr(upgrade.managed_worker, '_service_lock', lambda _: nullcontext())
    monkeypatch.setattr(upgrade.managed_worker, 'command', lambda *a, **kw: b'')
    monkeypatch.setattr(upgrade.deploy, 'DockerInstall', Install)
    monkeypatch.setattr(upgrade, '_idle', lambda journal, **kwargs: runtime.jobs_idle(base))
    monkeypatch.setattr(upgrade_boot_guard, 'install', lambda *args: None)
    monkeypatch.setattr(upgrade_boot_guard, 'verify', lambda *args: None)
    monkeypatch.setattr(upgrade.backup, 'capture_plan', capture)
    monkeypatch.setattr(upgrade.backup, 'stop_writers', stop)
    monkeypatch.setattr(runtime, 'fence_worker', fence)
    monkeypatch.setattr(runtime, 'capture_and_verify', capture_backup)
    monkeypatch.setattr(runtime, 'verify_backup', lambda *a: {'verified': True})
    monkeypatch.setattr(runtime, 'verify_images', lambda *a: event('images'))
    monkeypatch.setattr(runtime, 'drain', lambda *a, **k: {'ready': True})
    monkeypatch.setattr(runtime, 'authority', authority)
    monkeypatch.setattr(runtime, 'refresh_worker', refresh)
    monkeypatch.setattr(runtime.os, 'chown', lambda *a: None)
    monkeypatch.setattr(credential_maintenance, '_consumer_proof', lambda *a: event('consumer') or {'management_https': 'verified'})
    return SimpleNamespace(base=base, operation=operation, original=original, control=control,
        args=SimpleNamespace(state_dir=base, operation_id=OPERATION,
                             plan_sha256=operation.record['plan_sha256'], allow_downtime=True), event=event)


def assert_preserved(tx):
    assert (tx.base / 'age.txt').read_bytes() == b'existing service identity'
    assert (tx.base / 'volume-iris-config/account.age').read_bytes() == b'existing encrypted owner'
    assert (tx.base / 'volume-iris-state/replay').read_bytes() == b'epoch=17;high_water=900'
    assert (tx.base / 'images/owned.img').read_bytes() == b'existing owner content'
    assert (tx.base / 'artifacts/iris-catalog.pem').read_bytes() == b'existing public runtime certificate'


def test_upgrade_complete_real_publication_keeps_owner_storage_replay(transaction):
    tx = transaction
    assert upgrade.apply(tx.args) == 0
    journal = json.loads((tx.base / 'installation.json').read_bytes())
    assert journal['id'] == INSTANCE and journal['config'] == tx.original['config']
    assert journal['root_digests'] == tx.original['root_digests']
    assert journal['completed']['images'] == {value: value for value in IMAGES.values()}
    assert (tx.base / 'source/code.py').read_bytes() == b'new committed code'
    assert (tx.base / ('.retained-source-' + OPERATION) / 'code.py').read_bytes() == b'old committed code'
    assert all(row['running'] and row['restart'] == 'unless-stopped' for row in tx.control['containers'].values())
    assert_preserved(tx)
    before = list(tx.control['events'])
    assert upgrade.apply(tx.args) == 0
    assert tx.control['events'] == before


@pytest.mark.parametrize('boundary', ['fence-worker', 'backup', 'stop-writers', 'authority', 'images',
    'start-iris', 'start-console', 'consumer', 'packages', 'refresh-worker', 'enable-console', 'enable-iris'])
def test_each_host_boundary_refuses_then_recovers_same_generation(transaction, boundary):
    tx = transaction
    tx.control['failure'] = boundary
    with pytest.raises(InstallError, match='injected'):
        upgrade.apply(tx.args)
    assert not any(row['running'] for row in tx.control['containers'].values())
    assert json.loads(tx.operation.path.read_bytes())['phase'] == 'recovery-required'
    with pytest.raises(InstallError, match='Use upgrade recover'):
        upgrade.apply(tx.args)
    assert upgrade.apply(tx.args, recovery=True) == 0
    assert all(row['running'] and row['image'] == IMAGES[name]
               for name, row in tx.control['containers'].items())
    assert_preserved(tx)


@pytest.mark.parametrize('rename_number', [1, 2, 3, 4])
def test_crash_after_each_source_artifact_rename_is_forward_recoverable(transaction, monkeypatch, rename_number):
    tx = transaction
    original = upgrade.storage.os.rename
    count = 0
    def rename(first, second):
        nonlocal count
        original(first, second)
        count += 1
        if count == rename_number:
            raise OSError('injected rename interruption')
    monkeypatch.setattr(upgrade.storage.os, 'rename', rename)
    with pytest.raises(OSError, match='injected'):
        upgrade.apply(tx.args)
    assert not any(row['running'] for row in tx.control['containers'].values())
    assert upgrade.apply(tx.args, recovery=True) == 0
    assert (tx.base / 'source/code.py').read_bytes() == b'new committed code'
    assert_preserved(tx)


def test_wrong_plan_and_changed_owner_generation_cannot_admit_mutation(transaction):
    tx = transaction
    tx.args.plan_sha256 = '0' * 64
    with pytest.raises(InstallError, match='explicit approval'):
        upgrade.apply(tx.args)
    assert not tx.control['events']
    tx.args.plan_sha256 = tx.operation.record['plan_sha256']
    changed = copy.deepcopy(tx.original); changed['config']['unexpected'] = True
    atomic_write(tx.base / 'installation.json', plan.canonical(changed))
    with pytest.raises(InstallError, match='preimage'):
        upgrade.apply(tx.args)
    assert not tx.control['events']


def test_changed_new_source_is_refused_before_publication_and_original_retained(transaction):
    tx = transaction
    atomic_write(tx.base / ('.upgrade-source-' + OPERATION) / 'code.py', b'not approved')
    with pytest.raises(InstallError, match='input changed'):
        upgrade.apply(tx.args)
    assert (tx.base / 'source/code.py').read_bytes() == b'old committed code'
    assert not any(row['running'] for row in tx.control['containers'].values())
    assert_preserved(tx)


def test_foreign_worker_unit_refusal_never_disables_or_stops_replacement(transaction, monkeypatch):
    tx = transaction
    calls = []
    monkeypatch.setattr(runtime, 'fence_worker', REAL_FENCE_WORKER)
    monkeypatch.setattr(runtime.managed_worker, '_load',
                        lambda _: copy.deepcopy(tx.operation.record['worker_before']['record']))
    monkeypatch.setattr(runtime.managed_worker, '_file', lambda *args, **kwargs: b'foreign replacement unit')
    monkeypatch.setattr(runtime.managed_worker, 'command', lambda args, **kwargs: calls.append(args) or b'')
    with pytest.raises(InstallError, match='worker unit changed'):
        upgrade.apply(tx.args)
    assert calls == []
    saved = json.loads(tx.operation.path.read_bytes())
    assert saved['phase'] == 'recovery-required'
    assert saved['problems'] == ['worker-fence-unconfirmed']


def test_foreign_same_image_service_replacement_is_not_fenced(transaction, monkeypatch):
    tx = transaction
    def packages(install):
        tx.control['containers']['iris']['id'] = 'foreign-replacement'
        raise InstallError('injected foreign replacement')
    monkeypatch.setattr(upgrade.deploy.DockerInstall, 'packages', packages)
    with pytest.raises(InstallError, match='foreign replacement'):
        upgrade.apply(tx.args)
    saved = json.loads(tx.operation.path.read_bytes())
    assert saved['service_start_intents']['iris']['container_id'] == 'new-iris'
    assert saved['problems'] == ['iris-fence-unconfirmed']
    assert tx.control['containers']['iris']['running'] is True
    assert tx.control['containers']['console']['running'] is False


def test_interrupted_compose_after_old_removal_can_finish_unacquired_start(transaction, monkeypatch):
    tx = transaction
    original = upgrade.deploy.DockerInstall.compose
    interrupted = False
    def compose(install, *args, **kwargs):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            tx.control['containers'].pop('iris')
            raise InstallError('injected creation interruption')
        return original(install, *args, **kwargs)
    monkeypatch.setattr(upgrade.deploy.DockerInstall, 'compose', compose)
    with pytest.raises(InstallError, match='creation interruption'):
        upgrade.apply(tx.args)
    saved = json.loads(tx.operation.path.read_bytes())
    assert saved['service_start_intents']['iris'] == {'image': IMAGES['iris']}
    assert saved['problems'] == ['iris-fence-unconfirmed']
    assert upgrade.apply(tx.args, recovery=True) == 0
    assert_preserved(tx)


@pytest.mark.parametrize('component,number,after', [(kind, number, after) for kind in ('compose', 'journal')
    for number in (1, 2, 3) for after in (False, True)])
def test_each_compose_journal_publication_window_recovers_forward(transaction, monkeypatch, component, number, after):
    from iris_installer import state
    tx = transaction
    owner = upgrade if component == 'compose' else state
    original = owner.atomic_write
    filename = 'compose.json' if component == 'compose' else 'installation.json'
    seen = 0
    def write(path, data, *args):
        nonlocal seen
        if path.name == filename:
            seen += 1
            if seen == number:
                if after: original(path, data, *args)
                raise OSError('injected generation publication')
        return original(path, data, *args)
    monkeypatch.setattr(owner, 'atomic_write', write)
    with pytest.raises(OSError, match='injected'):
        upgrade.apply(tx.args)
    assert not any(row['running'] for row in tx.control['containers'].values())
    assert upgrade.apply(tx.args, recovery=True) == 0
    assert all(row['running'] and row['image'] == IMAGES[name]
               for name, row in tx.control['containers'].items())
    assert_preserved(tx)


@pytest.mark.parametrize('after', [False, True])
def test_terminal_record_interruption_is_not_a_false_success(transaction, monkeypatch, after):
    tx = transaction
    original = upgrade_state.atomic_write
    failed = False
    def write(path, data, *args):
        nonlocal failed
        if path.name == 'record.json' and json.loads(data).get('phase') == 'upgraded' and not failed:
            failed = True
            if after: original(path, data, *args)
            raise OSError('injected terminal record interruption')
        return original(path, data, *args)
    monkeypatch.setattr(upgrade_state, 'atomic_write', write)
    with pytest.raises(OSError, match='injected'):
        upgrade.apply(tx.args)
    assert not any(row['running'] for row in tx.control['containers'].values())
    assert json.loads(tx.operation.path.read_bytes())['phase'] == 'recovery-required'
    assert upgrade.apply(tx.args, recovery=True) == 0
    assert_preserved(tx)
