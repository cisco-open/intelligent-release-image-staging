# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Uninstall boundaries with real custody, journal and topology state machines.

Only systemd, Docker/SSH and Kubernetes transports are substituted. No live
service, cluster, remote host or deployment is contacted by these tests.
"""

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import deploy, kube_deploy as kube, managed_worker
from iris_installer import uninstall as api, uninstall_docker as docker, uninstall_runtime as runtime
from iris_installer.state import InstallError, Journal, atomic_write
from test_installer_kube_deploy import config
from test_installer_uninstall_runtime import DockerEngine


@pytest.mark.parametrize('verb', ['plan', 'apply', 'recover'])
def test_purge_help_discloses_owned_credential_secret_deletion(verb, capsys):
    from iris_installer import cli
    with pytest.raises(SystemExit) as stopped:
        cli.main(['uninstall', verb, '--help'])
    assert stopped.value.code == 0
    assert 'data volumes, or PVC and credential Secrets' in ' '.join(capsys.readouterr().out.split())


@pytest.fixture
def worker(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip('actual root-owned file and service custody requires root')
    base = tmp_path / 'state'
    base.mkdir(mode=0o700)
    units = tmp_path / 'units'
    units.mkdir(mode=0o700)
    unit = units / ('iris-lifecycle-' + str(uuid.uuid4()) + '.service')
    atomic_write(unit, b'[Service]\nExecStart=/owned/worker\n', 0o644)
    directory = unit.with_name(unit.name + '.d')
    directory.mkdir(mode=0o700)
    dropin = directory / '20-iris-upgrade.conf'
    atomic_write(dropin, b'[Unit]\nConditionPathExists=/owned/guard\n', 0o644)
    record = {'unit': unit.name, 'instance_id': str(uuid.uuid4())}
    atomic_write(base / managed_worker.RECORD, runtime.canonical(record))
    saved = {'record': record, 'unit_sha256': deploy.digest(unit),
             'dropin': {'path': str(dropin), 'sha256': deploy.digest(dropin)}}
    monkeypatch.setattr(managed_worker, 'UNIT_DIRECTORY', units)
    return SimpleNamespace(base=base, units=units, unit=unit, dropin=dropin, saved=saved)


@pytest.mark.parametrize('change', ['record', 'unit', 'dropin', 'foreign-dropin', 'unit-symlink', 'dropin-symlink'])
def test_actual_worker_custody_rejects_changed_or_foreign_files(worker, change):
    api.check_worker(worker.base, worker.saved)
    if change == 'record':
        atomic_write(worker.base / managed_worker.RECORD, b'{}')
    elif change in ('unit', 'dropin'):
        atomic_write(getattr(worker, change), b'changed', 0o644)
    elif change == 'foreign-dropin':
        atomic_write(worker.dropin.parent / 'foreign.conf', b'foreign', 0o644)
    else:
        leaf = worker.unit if change == 'unit-symlink' else worker.dropin
        leaf.unlink()
        leaf.symlink_to(worker.base / managed_worker.RECORD)
    with pytest.raises(InstallError):
        api.check_worker(worker.base, worker.saved, unit_may_be_absent=True)


def test_worker_absence_requires_original_durable_removal_intent(worker):
    worker.unit.unlink()
    with pytest.raises(InstallError, match='before removal intent'):
        api.check_worker(worker.base, worker.saved)
    api.check_worker(worker.base, worker.saved, unit_may_be_absent=True)
    worker.dropin.unlink()
    worker.dropin.parent.rmdir()
    api.check_worker(worker.base, worker.saved, unit_may_be_absent=True)


def test_split_adapter_pins_transport_and_sends_only_exact_json_request():
    engine = DockerEngine()
    calls = []
    transport = {'key': 'a' * 64, 'known_hosts': 'b' * 64}
    install = SimpleNamespace(journal=SimpleNamespace(document={'completed': {'split-transport': transport}}),
        transport_fingerprints=lambda: dict(transport), ssh_command=lambda text: ['ssh', '-F', '/owned/ssh.conf', text])
    def command(argv, **kwargs):
        calls.append((argv, kwargs))
        parts = shlex.split(argv[-1])
        assert parts[:8] == ['sudo', '-n', 'env', '-i', 'PATH=/usr/bin:/bin', 'python3', '-I', '-B']
        assert parts[8] == '-c' and parts[9] == Path(docker.__file__).read_text()
        request = json.loads(kwargs['input'])
        assert kwargs['capture'] is True and kwargs['timeout'] == 240
        return runtime.canonical(docker.perform(request, engine.run))
    install.command = command
    adapter = runtime.Docker(install, dict(engine.request, root='/owned/console'), remote=True)
    observed = adapter.snapshot()
    stopped = adapter.stop('container/iris-server', adapter.stable(observed))
    adapter.remove('container/iris-server', adapter.stable(stopped))
    assert [json.loads(row[1]['input'])['action'] for row in calls] == ['inspect', 'stop', 'remove']
    assert all(b'not-output' not in kwargs['input'] for _, kwargs in calls)
    install.transport_fingerprints = lambda: dict(transport, key='c' * 64)
    with pytest.raises(InstallError, match='Pinned Console SSH'):
        adapter.snapshot()
    assert len(calls) == 3


@pytest.mark.parametrize('refusal', [None, 'owner', 'locked', 'linked-owner'])
def test_split_remote_actual_owner_and_nonblocking_host_lock(monkeypatch, refusal):
    if os.geteuid() != 0:
        pytest.skip('remote root-owner/ancestor policy requires actual root')
    # The real remote guard forbids writable ancestors, including /tmp.
    with tempfile.TemporaryDirectory(prefix='iris-uninstall-boundary-', dir='/root') as directory:
        root = Path(directory)
        request = dict(DockerEngine().request, root=str(root))
        marker = root / 'owner.json'
        atomic_write(marker, runtime.canonical({'instance_id': request['instance_id'], 'project': request['project']}))
        calls = []
        def perform(value):
            assert value == request and docker.LOCK is not None
            other = os.open(root / '.backup-capture.lock', os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(other)
            calls.append(value)
            return {'observed': True}
        monkeypatch.setattr(docker, 'perform', perform)
        lock = None
        if refusal == 'owner':
            atomic_write(marker, runtime.canonical({'instance_id': str(uuid.uuid4()), 'project': request['project']}))
        elif refusal == 'linked-owner':
            os.link(marker, root / 'other-owner.json')
        elif refusal == 'locked':
            lock = os.open(root / '.backup-capture.lock', os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            if refusal:
                with pytest.raises((ValueError, BlockingIOError)):
                    docker.remote(request)
                assert not calls
            else:
                assert docker.remote(request) == {'observed': True}
                assert len(calls) == 1
            assert docker.LOCK is None
        finally:
            if lock is not None:
                os.close(lock)


class KubeTransport:
    """API transport only; ownership, scale and recovery use shipped methods."""
    def __init__(self, install):
        self.install, self.rows, self.calls = install, {}, []
        self.fail_scale = self.fail_delete = False

    def get(self, kind, name):
        return copy.deepcopy(next((row for row in self.rows.values()
            if row['kind'].lower() == kind.lower() and row['metadata']['name'] == name), None))

    def call(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == 'get':
            kinds = {'networkpolicies': 'networkpolicy', 'pods': 'pod', 'replicasets': 'replicaset'}
            kind = kinds.get(args[1].lower(), args[1].lower())
            return runtime.canonical({'items': [row for row in self.rows.values() if row['kind'].lower() == kind]})
        if args[0] == 'wait':
            return b''
        if args[0] in ('create', 'replace'):
            row = json.loads(kwargs['input'])
            key = row['kind'] + '/' + row['metadata']['name']
            if args[0] == 'replace':
                before = self.rows[key]['metadata']
                assert row['metadata']['uid'] == before['uid']
                assert row['metadata']['resourceVersion'] == before['resourceVersion']
            else:
                assert key not in self.rows
                row['metadata']['uid'] = str(uuid.uuid4())
            row['metadata']['resourceVersion'] = str(int(row['metadata'].get('resourceVersion', '0')) + 1)
            self.rows[key] = row
            if self.fail_scale and args[0] == 'replace':
                self.fail_scale = False
                raise InstallError('unknown scale response after accepted exact UID write')
            return runtime.canonical(row)
        assert args[:2] == ('delete', '--raw')
        options = json.loads(kwargs['input'])
        key, = [key for key, row in self.rows.items() if row['metadata']['uid'] == options['preconditions']['uid']]
        if 'resourceVersion' in options['preconditions']:
            assert options['preconditions']['resourceVersion'] == self.rows[key]['metadata']['resourceVersion']
        del self.rows[key]
        if self.fail_delete and key.startswith('Deployment/'):
            self.fail_delete = False
            raise InstallError('unknown delete response after accepted exact UID write')
        return b''


@pytest.fixture
def kube_install(worker, monkeypatch):
    obj = object.__new__(kube.KubeInstall)
    obj.base, obj.source, obj.config = worker.base, Path(__file__).resolve().parents[2], config()
    obj.manifest_file, obj.env = obj.base / 'kube.json', {}
    document = {'schema': 1, 'id': worker.saved['record']['instance_id'], 'config': obj.config,
                'state': 'ready', 'completed': {'kube-cluster': {'uid': str(uuid.uuid4())},
                    'kube-images': {service: 'example.invalid/' + service + '@sha256:' + 'a' * 64
                                    for service in kube.SERVICES}}}
    with Journal(obj.base).locked() as journal:
        journal.document = document
        obj.journal = journal
        desired = [obj._object('Namespace', obj.config['kube_namespace']),
                   obj._object('PersistentVolumeClaim', 'iris-data'),
                   obj._object('Secret', 'iris-age', data={'identity': 'private-not-output'})]
        for service, name in kube.SERVICES.items():
            desired.append(obj._object('Deployment', name, spec={'replicas': 1 if service == 'iris' else 2,
                'template': {'spec': {'containers': [{'name': service, 'image': 'example.invalid/iris@sha256:' + 'a' * 64}]}}}))
        atomic_write(obj.manifest_file, kube._canonical(desired))
        document['completed']['kube-manifests'] = deploy.digest(obj.manifest_file)
        document['completed']['kube-resources'] = {}
        transport = KubeTransport(obj)
        for row in desired:
            key = row['kind'] + '/' + row['metadata']['name']
            uid = str(uuid.uuid4())
            document['completed']['kube-resources'][key] = {'uid': uid, 'sha256': hashlib.sha256(kube._canonical(row)).hexdigest()}
            transport.rows[key] = copy.deepcopy(row)
            transport.rows[key]['metadata'].update(uid=uid, resourceVersion='1')
        journal.save()
    obj.kube, obj.get = transport.call, transport.get
    obj.cluster_preflight = lambda: None
    obj.verify_inputs = lambda: None
    obj.pin_runtime = lambda: None
    obj._pods = lambda service: [{'uid': 'original-server-pod'}]
    obj.execute = lambda *_args, **_kwargs: b'a' * 32
    def maintenance_run(*_args, **_kwargs):
        obj.assert_writers_stopped()
        return runtime.canonical({'pod_uid': 'original-server-pod', 'nonce': 'a' * 32,
                                  'clean': True, 'children': [{'exit_code': 0}]})
    obj.maintenance_run = maintenance_run
    def installation(journal):
        obj.journal = journal
        return obj
    monkeypatch.setattr(deploy, 'installation', installation)
    monkeypatch.setattr(api, 'worker_snapshot', lambda _: worker.saved)
    monkeypatch.setattr(api, 'idle', lambda _: None)
    monkeypatch.setattr(api.upgrade_runtime, 'jobs_idle', lambda _: None)
    drains = []
    def drain(install, *, stopped=False):
        if stopped:
            install.assert_writers_stopped()
        drains.append(stopped)
    monkeypatch.setattr(api.upgrade_runtime, 'drain', drain)
    commands = []
    def systemd(argv, **_kwargs):
        commands.append(argv)
        if argv[:2] == ['systemctl', 'show']:
            return (b'LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled\n'
                    if worker.unit.exists() else b'LoadState=not-found\nActiveState=inactive\nMainPID=0\n')
        return b''
    monkeypatch.setattr(managed_worker, 'command', systemd)
    args = SimpleNamespace(state_dir=obj.base, purge_data=True, allow_downtime=True)
    return SimpleNamespace(obj=obj, transport=transport, args=args, worker=worker, drains=drains, commands=commands)


@pytest.mark.parametrize('failure', ['scale', 'delete'])
def test_real_kube_fence_journal_exact_removal_and_original_operation_recovery(kube_install, failure):
    fixture = kube_install
    assert api.plan(fixture.args) == 0
    original = api.read(fixture.obj.base)
    fixture.args.operation_id = original['operation_id']
    fixture.args.plan_sha256 = original['plan_sha256']
    setattr(fixture.transport, 'fail_' + failure, True)
    with pytest.raises(InstallError, match='unknown ' + failure):
        api.apply(fixture.args)
    pending = api.read(fixture.obj.base)
    assert pending['plan'] == original['plan']
    assert pending['phase'] == ('fencing' if failure == 'scale' else 'removing')
    if failure == 'scale':
        assert (fixture.obj.base / 'kube-update.json').exists()
        assert not any(args[0] == 'delete' for args, _ in fixture.transport.calls)
    else:
        assert pending['pending'] == ['kubernetes', 'Deployment/iris-console']
        assert pending['fenced_installation'] != original['plan']['installation']
    assert api.apply(fixture.args, recovery=True) == 0
    result = api.read(fixture.obj.base)
    assert result['plan'] == original['plan'] and result['phase'] == 'uninstalled'
    assert result['stopped_drain_verified'] and True in fixture.drains
    assert not (fixture.obj.base / 'kube-update.json').exists()
    assert set(fixture.transport.rows) == {'Namespace/iris-test', 'NetworkPolicy/iris-maintenance-isolation'}
    assert not fixture.worker.unit.exists() and not fixture.worker.dropin.parent.exists()
    replacements = [json.loads(kwargs['input']) for args, kwargs in fixture.transport.calls if args[0] == 'replace']
    assert len(replacements) == 2 and all(row['spec']['replicas'] == 0 for row in replacements)
    deletes = [json.loads(kwargs['input']) for args, kwargs in fixture.transport.calls if args[0] == 'delete']
    uids = [row['preconditions']['uid'] for row in deletes]
    assert len(uids) == len(set(uids))  # accepted unknown writes are observed, never replayed
    assert 'private-not-output' not in json.dumps(api.public(fixture.obj.base, result))


def test_kube_recovery_rejects_unrelated_journal_change(kube_install):
    fixture = kube_install
    api.plan(fixture.args)
    original = api.read(fixture.obj.base)
    fixture.args.operation_id, fixture.args.plan_sha256 = original['operation_id'], original['plan_sha256']
    fixture.transport.fail_scale = True
    with pytest.raises(InstallError, match='unknown scale'):
        api.apply(fixture.args)
    with Journal(fixture.obj.base).locked(allow_uninstall=True) as journal:
        journal.document['completed']['foreign-authority'] = 'changed'
        journal.save()
    count = len(fixture.transport.calls)
    with pytest.raises(InstallError, match='unrelated installation authority'):
        api.apply(fixture.args, recovery=True)
    assert len(fixture.transport.calls) == count
