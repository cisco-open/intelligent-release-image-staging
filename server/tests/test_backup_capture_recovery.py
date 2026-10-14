# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Private intent and real cryptographic evidence with modeled service state."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import backup, backup_archive, backup_capture as capture
from iris_installer.kube_deploy import KubeInstall, INTENT
from iris_installer.state import InstallError, atomic_write


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip('root-private capture authority requires root')
    state, data, recovery = [tmp_path / name for name in ('state', 'data', 'recovery')]
    for path in (state, data, recovery):
        path.mkdir(mode=0o700)
    signer = state / 'backup-custody/signer'
    signer.parent.mkdir(mode=0o700)
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(signer)], check=True)
    key = tmp_path / 'identity'
    subprocess.run(['age-keygen', '-o', str(key)], check=True, capture_output=True)
    recipient = subprocess.check_output(['age-keygen', '-y', str(key)], text=True).strip()
    document = {'id': str(uuid.uuid4()), 'config': {'target': 'docker'},
                'source_manifest': {'fixture': 'a' * 64}, 'root_digests': {},
                'completed': {'images': {'fixture': 'sha256:' + 'a' * 64}}}
    journal = SimpleNamespace(directory=state, document=document)
    install = SimpleNamespace(base=state, journal=journal)
    initial = [{'id': 'console-id', 'service': 'console', 'running': True},
               {'id': 'server-id', 'service': 'iris', 'running': True}]
    current = copy.deepcopy(initial)
    events = []
    install.capture_recovery_inventory = lambda _authority: ({'volume': '/owned'}, copy.deepcopy(current))
    install.capture_recovery_health = lambda container: events.append('health-' + container['service'])

    def restart(_install, container):
        events.append('start-' + container['service'])
        next(item for item in current if item['id'] == container['id'])['running'] = True
    monkeypatch.setattr(backup, 'restart_writer', restart)
    authority = {'process': capture._process(os.getpid()), 'boot_id': capture._boot(),
                 'unit_sha256': 'b' * 64, 'record_sha256': 'c' * 64}
    monkeypatch.setattr(capture, 'writer_authority', lambda _install, _old=None: copy.deepcopy(authority))
    request_id, backup_id, set_id = [str(uuid.uuid4()) for _ in range(3)]
    operation = capture.Capture(install, request_id, backup_id).begin(
        output=data / backup_id, recovery=recovery / backup_id, signer=signer,
        containers=initial, volumes={'volume': '/owned'}, set_id=set_id)
    return SimpleNamespace(operation=operation, install=install, initial=initial,
        current=current, events=events, signer=signer, key=key, recipient=recipient, state=state)


def publish(fixture, kind):
    operation = fixture.operation
    destination = Path(operation.record['destinations'][kind]['path'])
    payload = fixture.state / 'fixture-file'
    atomic_write(payload, b'real encrypted test content')
    envelope = backup_archive.create({'fixture': payload}, destination, fixture.recipient,
        fixture.signer, metadata={'backup_set_id': operation.record['set_id'], 'scope': kind})
    operation.published(kind, envelope)
    return destination


@pytest.mark.parametrize('publication_count', [0, 1, 2])
def test_same_job_settlement_never_recaptures_or_removes_partial_output(fixture, monkeypatch, publication_count):
    operation = fixture.operation
    operation.record['clean_stop'] = True
    operation.phase('capturing')
    if publication_count:
        publish(fixture, 'recovery')
    if publication_count == 2:
        publish(fixture, 'data')
    else:
        partial = Path(operation.record['destinations']['data']['path'])
        partial.mkdir(mode=0o700)
        atomic_write(partial / 'partial', b'retain incomplete bytes')
    for container in fixture.current:
        container['running'] = False
    def forbidden(*_args, **_kwargs):
        pytest.fail('same-job settlement repeated capture')
    monkeypatch.setattr(backup_archive, 'create', forbidden)
    saved = operation.path.read_bytes()
    resumed = capture.Capture(fixture.install, operation.request_id, operation.backup_id).load()
    assert resumed.record == json.loads(saved)
    result = resumed.settle()
    assert result['state'] == ('captured' if publication_count == 2 else 'failed')
    assert result['recaptured'] is False and result['services_healthy'] is True
    assert fixture.events == ['start-iris', 'health-iris', 'start-console', 'health-console']
    if publication_count != 2:
        assert (partial / 'partial').read_bytes() == b'retain incomplete bytes'
    # Same-ID recovery after a crash following a successful start observes
    # healthy running services instead of replaying start commands.
    fixture.events.clear()
    assert resumed.settle() == result
    assert fixture.events == ['health-iris', 'health-console']


def test_published_pair_changed_is_failed_not_captured_but_services_resume(fixture):
    operation = fixture.operation
    operation.record['clean_stop'] = True
    publish(fixture, 'recovery')
    data = publish(fixture, 'data')
    raw = (data / 'payload.tar.age').read_bytes()
    atomic_write(data / 'payload.tar.age', raw + b'changed')
    for container in fixture.current:
        container['running'] = False
    assert operation.settle()['state'] == 'failed'
    assert operation.record['completion_refused'] is True
    assert (data / 'payload.tar.age').read_bytes() == raw + b'changed'


@pytest.mark.parametrize('change', ['generation', 'container', 'volume', 'storage', 'signer'])
def test_changed_capture_authority_never_restarts_services(fixture, change):
    operation = fixture.operation
    if change == 'generation':
        fixture.install.journal.document['source_manifest']['fixture'] = 'f' * 64
    elif change == 'container':
        fixture.current[0]['id'] = 'replacement'
    elif change == 'volume':
        fixture.install.capture_recovery_inventory = lambda _a: ({'foreign': '/owned'}, fixture.current)
    elif change == 'storage':
        operation.record['destinations']['data']['parent_inode'] += 1
    else:
        atomic_write(fixture.signer, b'changed private signer')
    with pytest.raises(InstallError):
        operation.settle()
    assert fixture.events == []


def test_live_writer_refusal_precedes_service_and_publication_observation(fixture, monkeypatch):
    def refuse(*_args):
        raise InstallError('An earlier capture writer is still active')
    monkeypatch.setattr(capture, 'writer_authority', refuse)
    with pytest.raises(InstallError, match='writer is still active'):
        fixture.operation.settle()
    assert fixture.events == []


def test_kube_stop_annotations_and_replicas_are_only_allowed_spec_differences():
    resource = {'kind': 'Deployment', 'metadata': {'name': 'iris-seed-server', 'annotations': {INTENT: 'before'}},
                'spec': {'replicas': 1, 'template': {'spec': {'containers': [{'image': 'pin'}]}}}}
    changed = copy.deepcopy(resource)
    changed['metadata']['annotations'][INTENT] = 'after'
    changed['spec']['replicas'] = 0
    assert KubeInstall._capture_resource_digest(resource) == KubeInstall._capture_resource_digest(changed)
    changed['spec']['template']['spec']['containers'][0]['image'] = 'foreign'
    assert KubeInstall._capture_resource_digest(resource) != KubeInstall._capture_resource_digest(changed)


def test_process_birth_is_actual_and_pid_reuse_is_not_original():
    child = subprocess.Popen(['/usr/bin/python3', '-c', 'import time;time.sleep(30)'])
    try:
        identity = capture._process(child.pid)
        assert identity and identity['pid'] == child.pid and identity['birth'] > 0
        assert capture._process(child.pid) == identity
        assert dict(identity, birth=identity['birth'] - 1) != capture._process(child.pid)
    finally:
        child.terminate()
        child.wait(timeout=5)
    assert capture._process(child.pid) is None


@pytest.mark.parametrize('change', [None, 'inode', 'owner', 'foreign-destination', 'foreign-instance'])
def test_exact_tracked_stage_custody_and_changed_stage_refusals(fixture, change):
    operation = fixture.operation
    atomic_write(fixture.state / 'installation.json', json.dumps(fixture.install.journal.document).encode())
    data_root = Path(operation.record['destinations']['data']['path']).parent
    recovery_root = Path(operation.record['destinations']['recovery']['path']).parent
    stage = data_root / '.iris-backup-exact-stage'
    stage.mkdir(mode=0o700)
    operation.stage('data', stage)
    atomic_write(stage / 'partial.age', b'partial unverified ciphertext')
    if change == 'inode':
        stage.rename(data_root / '.retained-original')
        stage.mkdir(mode=0o700)
    elif change == 'owner':
        stage.chmod(0o755)
    elif change == 'foreign-destination':
        operation.record['destinations']['data']['path'] = str(data_root / str(uuid.uuid4()))
        operation.save()
    elif change == 'foreign-instance':
        operation.record['generation']['instance_id'] = str(uuid.uuid4())
        operation.save()
    if change:
        with pytest.raises(InstallError):
            capture.protected_stages(fixture.state, data_root, recovery_root)
    else:
        result = capture.protected_stages(fixture.state, data_root, recovery_root)
        assert list(result) == [str(stage)]
        assert result[str(stage)]['request_id'] == operation.request_id
        assert (stage / 'partial.age').read_bytes() == b'partial unverified ciphertext'
        assert operation.record['publications'] == {}


def test_untracked_temporary_name_is_not_a_managed_capture_waiver(fixture):
    from iris_installer.lifecycle_retention import Retention
    from iris_installer.lifecycle_history import RetentionConflict
    operation = fixture.operation
    atomic_write(fixture.state / 'installation.json', json.dumps(fixture.install.journal.document).encode())
    data_root = Path(operation.record['destinations']['data']['path']).parent
    recovery_root = Path(operation.record['destinations']['recovery']['path']).parent
    stage = data_root / '.iris-backup-untracked'
    stage.mkdir(mode=0o700)
    worker = SimpleNamespace(state_dir=fixture.state, backup_dir=data_root, recovery_dir=recovery_root,
                             managed_captures=True, jobs=[{'state': 'running'}])
    retained = object.__new__(Retention)
    retained.worker, retained.store = worker, SimpleNamespace(pending=lambda: [])
    with pytest.raises(RetentionConflict, match='exact maintenance request ID'):
        retained.backup_inventory()


@pytest.mark.parametrize('states,pending,upgrading,expected', [
    (['recovery-required'], False, False, True),
    (['running'], False, False, False),
    (['failed'], False, False, False),
    (['recovery-required', 'failed'], False, False, True),
    (['recovery-required', 'recovery-required'], False, False, False),
    (['recovery-required', 'running'], False, False, False),
    (['recovery-required'], True, False, False),
    (['recovery-required'], False, True, False),
    ([], False, False, False),
])
def test_retention_recoverable_selector_is_only_exact_sole_interrupted_job(states, pending, upgrading, expected):
    from iris_installer.lifecycle_retention import Retention
    jobs = [{'id': str(uuid.uuid4()), 'action': 'backup', 'state': state} for state in states]
    retained = object.__new__(Retention)
    retained.worker = SimpleNamespace(jobs=jobs)
    retained.store = SimpleNamespace(pending=lambda: [{'state': 'recovery-required'}] if pending else [],
                                    operation=lambda _id: None)
    retained.backup_inventory = lambda: (set(), [], upgrading)
    retained.eligible = lambda _job: (False, 'unfinished')
    result = retained.status()
    assert result['recoverable_job_id'] == (jobs[0]['id'] if expected else None)
    assert result['busy'] is bool(pending or upgrading or any(state in ('running', 'recovery-required') for state in states))


@pytest.mark.parametrize('source', ['intent', 'job', 'ambiguous-status'])
def test_ordinary_host_capture_cannot_bypass_pending_capture(fixture, source):
    operation = fixture.operation
    if source != 'intent':
        operation.path.unlink()
    if source == 'job':
        atomic_write(fixture.state / 'lifecycle-jobs.json', json.dumps([{
            'id': operation.request_id, 'backup_id': operation.backup_id,
            'action': 'backup', 'state': 'recovery-required'}]).encode())
    elif source == 'ambiguous-status':
        atomic_write(fixture.state / 'backup-operation.json', json.dumps({
            'state': 'stopping', 'backup_set_id': operation.record['set_id']}).encode())
    with pytest.raises(InstallError, match='[Rr]ecover|authority'):
        capture.guard(fixture.state, instance_id=fixture.install.journal.document['id'])
    assert fixture.events == []


def test_guard_admits_only_same_intent_and_settled_history(fixture):
    operation = fixture.operation
    atomic_write(fixture.state / 'backup-operation.json', json.dumps({
        'state': 'stopping', 'backup_set_id': operation.record['set_id']}).encode())
    capture.guard(fixture.state, request_id=operation.request_id,
                  instance_id=fixture.install.journal.document['id'])
    with pytest.raises(InstallError):
        capture.guard(fixture.state, request_id=str(uuid.uuid4()),
                      instance_id=fixture.install.journal.document['id'])
    operation.phase('settled-failed')
    atomic_write(fixture.state / 'backup-operation.json', b'{"state":"failed","restart_required":[]}')
    capture.guard(fixture.state, instance_id=fixture.install.journal.document['id'])


@pytest.mark.parametrize('pre_authority', [False, True])
def test_pre_intent_recovery_requires_exact_false_handoff_and_never_restarts(fixture, monkeypatch, pre_authority):
    from contextlib import contextmanager
    operation = fixture.operation
    operation.path.unlink()
    atomic_write(fixture.state / 'lifecycle-jobs.json', json.dumps([{
        'id': operation.request_id, 'backup_id': operation.backup_id, 'action': 'backup',
        'state': 'recovery-required', 'capture_authority_started': False}]).encode())
    events = []
    @contextmanager
    def locked():
        yield fixture.install.journal
    monkeypatch.setattr(backup, 'Journal', lambda _p: SimpleNamespace(locked=locked))
    monkeypatch.setattr(backup, '_installation', lambda _j: fixture.install)
    monkeypatch.setattr(capture, 'writer_authority', lambda _i: events.append('actual-worker-gate'))
    if pre_authority:
        result = backup.recover(fixture.state, request_id=operation.request_id,
                               backup_id=operation.backup_id, pre_authority_recovery=True)
        assert result == {'state': 'failed', 'services_healthy': False, 'recaptured': False,
                          'partial_output_retained': True, 'preflight_only': True}
        assert events == ['actual-worker-gate']
    else:
        with pytest.raises(InstallError, match='no saved same-job recovery authority'):
            backup.recover(fixture.state, request_id=operation.request_id, backup_id=operation.backup_id)
        assert events == []
    assert fixture.events == [] and list(operation.path.parent.iterdir()) == []


@pytest.mark.parametrize('change', ['name', 'directory', 'mode', 'owner', 'symlink', 'hardlink'])
def test_only_inert_private_atomic_scratch_files_can_be_ignored(fixture, change):
    operation = fixture.operation
    scratch = operation.path.parent / '.iris-interrupted-atomic-save'
    atomic_write(scratch, b'partial record bytes are never authority')
    if change == 'name':
        scratch.rename(scratch.with_name('foreign'))
    elif change == 'directory':
        scratch.unlink()
        scratch.mkdir(mode=0o700)
    elif change == 'mode':
        scratch.chmod(0o644)
    elif change == 'owner':
        os.chown(scratch, 1001, 1001)
    elif change == 'symlink':
        scratch.unlink()
        scratch.symlink_to(operation.path)
    elif change == 'hardlink':
        os.link(scratch, scratch.with_name('.iris-another-link'))
    with pytest.raises(InstallError):
        capture.guard(fixture.state, request_id=operation.request_id,
                      instance_id=fixture.install.journal.document['id'])


def test_interrupted_atomic_scratch_never_invents_intent_or_completion(fixture, monkeypatch):
    from contextlib import contextmanager
    operation = fixture.operation
    operation.path.unlink()
    scratch = operation.path.parent / '.iris-interrupted-atomic-save'
    raw = b'not a published capture intent'
    atomic_write(scratch, raw)
    atomic_write(fixture.state / 'installation.json', json.dumps(fixture.install.journal.document).encode())
    data_root = Path(operation.record['destinations']['data']['path']).parent
    recovery_root = Path(operation.record['destinations']['recovery']['path']).parent
    assert capture.protected_stages(fixture.state, data_root, recovery_root) == {}
    @contextmanager
    def locked():
        yield fixture.install.journal
    monkeypatch.setattr(backup, 'Journal', lambda _p: SimpleNamespace(locked=locked))
    monkeypatch.setattr(backup, '_installation', lambda _j: fixture.install)
    monkeypatch.setattr(capture, 'writer_authority', lambda _i: pytest.fail('scratch admitted capture recovery'))
    with pytest.raises(InstallError, match='no saved same-job recovery authority'):
        backup.recover(fixture.state, request_id=operation.request_id, backup_id=operation.backup_id)
    for marker in (True, None, 'false'):
        atomic_write(fixture.state / 'lifecycle-jobs.json', json.dumps([{
            'id': operation.request_id, 'backup_id': operation.backup_id, 'action': 'backup',
            'state': 'recovery-required', 'capture_authority_started': marker}]).encode())
        with pytest.raises(InstallError, match='saved same-job handoff'):
            backup.recover(fixture.state, request_id=operation.request_id, backup_id=operation.backup_id,
                           pre_authority_recovery=True)
    assert scratch.read_bytes() == raw and not operation.path.exists() and fixture.events == []
