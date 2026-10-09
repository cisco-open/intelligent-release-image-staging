# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Remote offline inputs and accepted plans never become network/source installs."""

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import split_dependencies as remote, split_deploy as split
from iris_installer import offline_dependencies as dependencies, prebuilt_dependencies as plans, release_kit
from iris_installer.state import InstallError
from test_installer_split_deploy import install
from test_installer_offline_dependencies import signed_repository
from test_installer_offline_inputs import directory_archive


def sha(data):
    return hashlib.sha256(data).hexdigest()


def plan():
    return {'schema': 'iris-offline-dependency-plan-v1', 'closure_sha256': 'e' * 64,
            'status_sha256': 'f' * 64, 'provider': [], 'docker_path': None,
            'required_roots': sorted(remote.REMOTE_ROOTS), 'roots': ['openssl=1.0'],
            'packages': [{'name': 'openssl', 'version': '1.0', 'old_version': None, 'architecture': 'amd64'}]}


def planned():
    return {'schema': remote.PLAN, 'host': 'a' * 64, 'plan': plan(),
            'evidence': {'unchanged_records_sha256': 'b' * 64}}


def done():
    return {'schema': remote.DONE, 'host': 'a' * 64, 'status_sha256': 'c' * 64}


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    obj = install(tmp_path)
    obj.source = tmp_path / 'source'
    files = obj.source / 'tools/iris_installer'
    files.mkdir(parents=True)
    inventory = {}
    for name in remote.SOURCES:
        data = ('# public helper fixture ' + name + '\n').encode()
        (files / name).write_bytes(data)
        inventory['tools/iris_installer/' + name] = sha(data)
    kitdir = tmp_path / 'kit'
    kitdir.mkdir(mode=0o700)
    payload = b'authenticated closure fixture'
    (kitdir / 'dependencies.tar.gz').write_bytes(payload)
    asset = release_kit.Asset(remote.ROLE, 'dependencies.tar.gz', len(payload), sha(payload), 'tar.gz',
                              dependency_manifest_sha256='e' * 64)
    kit = release_kit.VerifiedKit(kitdir, 'v2026.10.09', 'a' * 40, 'b' * 64,
                                 'c' * 64, 'd' * 64, 'e' * 64, True, (asset,), remote.ROLE)
    obj._verified_kit = kit
    obj.transport_fingerprints = lambda: {'console_ssh_key': '1' * 64, 'console_known_hosts': '2' * 64}
    obj.console_build_file.write_text('{}')
    obj.journal.document.update(source_manifest=inventory, state='split-prepared',
        input_selection=release_kit.selection('prebuilt', kit=kit, offline=True),
        dependency_provisioning={'schema': 'iris-prebuilt-dependencies-v1',
            'kit': kit.receipt(), 'accepted_changes': True, 'phase': 'complete'})
    obj.journal.document['completed'] = {'prepared': split.digest(obj.compose_file),
        'split-prepared': split.digest(obj.console_build_file), 'split-transport': obj.transport_fingerprints()}
    obj.saved = []
    obj.journal.save = lambda: obj.saved.append(deepcopy(obj.journal.document))
    return obj


def fake_exchange(monkeypatch, deployment, *, fail_apply=False):
    calls = []
    def exchange(obj, kit, request, helpers):
        assert obj is deployment and kit is obj._verified_kit
        calls.append(deepcopy(request))
        assert set(helpers) == set(remote.SOURCES)
        if request['action'] == 'plan':
            assert remote.RECORD not in obj.journal.document
            return planned()
        saved = obj.journal.document[remote.RECORD]
        assert obj.saved and saved['accepted_changes'] is True
        assert request['plan'] == saved['plan'] and request['evidence'] == saved['evidence']
        if fail_apply:
            raise InstallError('interrupted SSH response')
        return done()
    monkeypatch.setattr(remote, '_exchange', exchange)
    return calls


def test_remote_exact_acceptance_is_durable_before_apply_and_complete_resume_never_replans(deployment, monkeypatch):
    calls = fake_exchange(monkeypatch, deployment)
    remote.provision(deployment)
    assert [row['action'] for row in calls] == ['plan', 'apply']
    first = deployment.saved[0][remote.RECORD]
    assert first['phase'] == 'accepted'
    assert first['plan'] == plan()
    assert first['authority']['endpoint'] == {'console_ssh_host': '192.0.2.11',
        'console_ssh_port': 22, 'console_ssh_user': 'operator'}
    assert first['authority']['transport'] == deployment.transport_fingerprints()
    assert first['authority']['kit'] == deployment._verified_kit.receipt()
    assert deployment.journal.document[remote.RECORD]['completion'] == done()
    remote.provision(deployment)
    assert [row['action'] for row in calls] == ['plan', 'apply', 'apply']
    assert calls[-1]['phase'] == 'complete'


def test_completed_host_can_receive_operator_updates_without_new_apply_authority(deployment, monkeypatch):
    fake_exchange(monkeypatch, deployment)
    remote.provision(deployment)
    original = deepcopy(deployment.journal.document[remote.RECORD])
    def current(obj, kit, request, helpers):
        assert request['action'] == 'apply' and request['phase'] == 'complete'
        return dict(done(), status_sha256='9' * 64)
    monkeypatch.setattr(remote, '_exchange', current)
    remote.provision(deployment)
    assert deployment.journal.document[remote.RECORD] == original


def test_interruption_reuses_only_the_recorded_remote_plan(deployment, monkeypatch):
    calls = fake_exchange(monkeypatch, deployment, fail_apply=True)
    with pytest.raises(InstallError, match='interrupted'):
        remote.provision(deployment)
    saved = deepcopy(deployment.journal.document[remote.RECORD])
    assert saved['phase'] == 'accepted'
    calls = fake_exchange(monkeypatch, deployment)
    remote.provision(deployment)
    assert [row['action'] for row in calls] == ['apply']
    assert calls[0]['plan'] == saved['plan']


def test_failure_to_save_acceptance_never_reaches_apply(deployment, monkeypatch):
    calls = fake_exchange(monkeypatch, deployment)
    def failed(): raise InstallError('journal interrupted')
    deployment.journal.save = failed
    with pytest.raises(InstallError, match='journal interrupted'):
        remote.provision(deployment)
    assert [row['action'] for row in calls] == ['plan']


@pytest.mark.parametrize('value', [None, {}, {'accepted_changes': True},
    {'schema': 'iris-prebuilt-dependencies-v1', 'accepted_changes': True, 'phase': 'accepted'}])
def test_first_remote_plan_requires_completed_accepted_matching_local_selection(deployment, monkeypatch, value):
    deployment.journal.document['dependency_provisioning'] = value
    monkeypatch.setattr(remote, '_exchange', lambda *a: pytest.fail('No remote call without accepted selection'))
    with pytest.raises(InstallError, match='accepted split installation'):
        remote.provision(deployment)


@pytest.mark.parametrize('value', [None, {}, False, {'phase': 'complete'}])
def test_malformed_present_remote_receipt_is_not_replaced(deployment, monkeypatch, value):
    deployment.journal.document[remote.RECORD] = value
    monkeypatch.setattr(remote, '_exchange', lambda *a: pytest.fail('No remote call with malformed record'))
    with pytest.raises(InstallError):
        remote.provision(deployment)


@pytest.mark.parametrize('stage', ['images', 'console-image', 'console-prepared', 'server',
                                  'packages', 'guestshell', 'prebuilt-image-server-image-intent'])
def test_missing_receipt_after_deployment_progress_never_authorizes_a_new_plan(deployment, monkeypatch, stage):
    deployment.journal.document['completed'][stage] = {}
    deployment.journal.document['state'] = stage
    monkeypatch.setattr(remote, '_exchange', lambda *a: pytest.fail('Mature journal must not replan'))
    with pytest.raises(InstallError, match='acceptance is missing after deployment progressed'):
        remote.provision(deployment)


def test_missing_receipt_with_mature_state_alone_does_not_replan(deployment, monkeypatch):
    deployment.journal.document['state'] = 'PRODUCTION_REVIEW_REQUIRED'
    monkeypatch.setattr(remote, '_exchange', lambda *a: pytest.fail('Mature state must not replan'))
    with pytest.raises(InstallError, match='acceptance is missing after deployment progressed'):
        remote.provision(deployment)


@pytest.mark.parametrize('changed', ['endpoint', 'transport', 'helper', 'instance', 'root'])
def test_recorded_remote_authority_cannot_drift(deployment, monkeypatch, changed):
    fake_exchange(monkeypatch, deployment)
    remote.provision(deployment)
    if changed == 'endpoint': deployment.config['console_ssh_host'] = '192.0.2.12'
    elif changed == 'transport': deployment.transport_fingerprints = lambda: {'console_ssh_key': 'changed'}
    elif changed == 'helper': deployment.journal.document['source_manifest']['tools/iris_installer/state.py'] = '9' * 64
    elif changed == 'instance': deployment.journal.document['id'] = 'different-owner'
    else: deployment.config['console_state_dir'] = '/etc/iris/other-console'
    monkeypatch.setattr(remote, '_exchange', lambda *a: pytest.fail('Changed authority reached remote'))
    with pytest.raises(InstallError):
        remote.provision(deployment)


def test_transmitted_helpers_must_match_authenticated_source_before_any_ssh(deployment, monkeypatch):
    (deployment.source / 'tools/iris_installer/state.py').write_bytes(b'changed helper')
    monkeypatch.setattr(remote, '_run_remote', lambda *a: pytest.fail('Unverified helper executed'))
    with pytest.raises(InstallError, match='helper differs'):
        remote._exchange(deployment, deployment._verified_kit, {}, remote._helper_hashes(deployment))


def test_exchange_snapshots_role_and_pins_wire_before_remote_execution(deployment, monkeypatch):
    copied, inspected, sent = [], [], []
    original = release_kit.VerifiedKit.copy_asset
    def copy(self, role, destination):
        copied.append(role)
        return original(self, role, destination)
    def inspect(path, **kwargs):
        inspected.append((path, kwargs))
    def send(command, environment, wire):
        length = int.from_bytes(wire.read(8), 'big')
        raw = wire.read(length)
        tokens = shlex.split(command[-1])
        assert tokens[-1] == sha(raw)
        assert 'StrictHostKeyChecking=yes' in command and 'ForwardAgent=no' in command
        assert ['python3', '-I', '-B', '-c'] == tokens[tokens.index('python3'):tokens.index('python3') + 4]
        header = json.loads(raw)
        assert header['request'] == {'action': 'plan'}
        assert [row['name'] for row in header['files']] == [*remote.SOURCES, 'closure.tar.gz']
        for row in header['files']:
            assert sha(wire.read(row['size'])) == row['sha256']
        assert not wire.read(1)
        sent.append(header)
        return planned()
    monkeypatch.setattr(release_kit.VerifiedKit, 'copy_asset', copy)
    monkeypatch.setattr(remote.offline_inputs, 'inspect_dependency_archive', inspect)
    monkeypatch.setattr(remote, '_run_remote', send)
    assert remote._exchange(deployment, deployment._verified_kit, {'action': 'plan'}, remote._helper_hashes(deployment)) == planned()
    assert copied == [remote.ROLE]
    assert inspected[0][1] == {'expected_manifest_sha256': 'e' * 64}
    assert not inspected[0][0].parent.exists()
    assert len(sent) == 1


def test_changed_private_closure_is_refused_before_ssh(deployment, monkeypatch):
    def changed(path, **kwargs): path.write_bytes(b'changed after authentication')
    monkeypatch.setattr(remote.offline_inputs, 'inspect_dependency_archive', changed)
    monkeypatch.setattr(remote, '_run_remote', lambda *a: pytest.fail('Changed closure transferred'))
    with pytest.raises(InstallError):
        remote._exchange(deployment, deployment._verified_kit, {}, remote._helper_hashes(deployment))


def test_transport_is_rechecked_after_bounded_input_preparation(deployment, monkeypatch):
    def changed(path, **kwargs):
        deployment.transport_fingerprints = lambda: {'changed': 'transport'}
    monkeypatch.setattr(remote.offline_inputs, 'inspect_dependency_archive', changed)
    monkeypatch.setattr(remote, '_run_remote', lambda *a: pytest.fail('Changed SSH authority executed'))
    with pytest.raises(InstallError, match='transport changed before dependency execution'):
        remote._exchange(deployment, deployment._verified_kit, {}, remote._helper_hashes(deployment))


def test_response_limit_kills_child_while_receiving_without_disk_growth(monkeypatch):
    monkeypatch.setattr(remote, 'MAX_JSON', 1024)
    with tempfile.TemporaryFile() as wire:
        with pytest.raises(InstallError, match='response exceeds'):
            remote._run_remote([sys.executable, '-I', '-c',
                'import os\nwhile True: os.write(1,b"x"*4096)'], dict(os.environ), wire)


def test_response_timeout_terminates_child(monkeypatch):
    monkeypatch.setattr(remote, 'TRANSFER_TIMEOUT', 0.1)
    with tempfile.TemporaryFile() as wire:
        with pytest.raises(InstallError, match='timed out'):
            remote._run_remote([sys.executable, '-I', '-c', 'import time; time.sleep(30)'], dict(os.environ), wire)


@pytest.mark.parametrize('output', ["print('{}')", "print('not-json')", "raise SystemExit(1)"])
def test_response_is_strict_json_and_exit_status(output):
    with tempfile.TemporaryFile() as wire:
        if output == "print('{}')":
            assert remote._run_remote([sys.executable, '-I', '-c', output], dict(os.environ), wire) == {}
        else:
            with pytest.raises(InstallError):
                remote._run_remote([sys.executable, '-I', '-c', output], dict(os.environ), wire)


def wire_fixture(marker):
    sources = {name: b'# authenticated test helper\n' for name in remote.SOURCES}
    sources['split_dependencies.py'] = (
        'from pathlib import Path\n'
        'def perform_remote(path, request):\n'
        ' Path(' + repr(str(marker)) + ').write_text("executed")\n'
        ' return {"verified": path.read_bytes().decode()}\n').encode()
    sources['closure.tar.gz'] = b'closure fixture'
    header = remote._json({'schema': 'iris-split-dependency-wire-v1', 'request': {'action': 'plan'},
        'files': [{'name': name, 'size': len(data), 'sha256': sha(data)} for name, data in sources.items()]})
    data = len(header).to_bytes(8, 'big') + header + b''.join(sources.values())
    return data, sha(header)


@pytest.mark.parametrize('change', ['none', 'header', 'helper', 'closure', 'truncated', 'extra'])
def test_exact_bootstrap_authenticates_every_byte_before_import(tmp_path, change):
    marker = tmp_path / 'helper-executed'
    data, digest = wire_fixture(marker)
    if change == 'header': digest = '0' * 64
    elif change == 'helper': data = data.replace(b'# authenticated test helper', b'# unauthenticatd test helper', 1)
    elif change == 'closure': data = data[:-1] + b'x'
    elif change == 'truncated': data = data[:-1]
    elif change == 'extra': data += b'additional payload'
    # The test supplies a fake uid only; no apt, sudo, SSH or host operation runs.
    code = 'import os; os.geteuid=lambda:0\n' + remote.BOOTSTRAP
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, digest], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if change == 'none':
        assert result.returncode == 0 and marker.read_text() == 'executed'
        assert json.loads(result.stdout) == {'verified': 'closure fixture'}
    else:
        assert result.returncode != 0 and not marker.exists()


@pytest.fixture
def remote_operations(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(remote, '_remote_identity', lambda request: 'a' * 64)
    monkeypatch.setattr(remote.offline_inputs, 'inspect_dependency_archive',
                        lambda path, **kwargs: calls.append(('inspect', kwargs)))
    @contextmanager
    def validate(path, digest):
        # Keyring overrides are deliberately absent: each remote uses its own.
        calls.append(('ubuntu-validate', digest))
        yield SimpleNamespace(digest=digest)
    monkeypatch.setattr(dependencies, 'validate_closure', validate)
    monkeypatch.setattr(dependencies, 'plan_dependencies',
        lambda closure, **kwargs: calls.append(('plan', kwargs)) or plan())
    monkeypatch.setattr(plans, 'evidence_for_plan', lambda value: planned()['evidence'])
    monkeypatch.setattr(plans, 'apply_accepted_plan',
        lambda closure, value, evidence, **kwargs: calls.append(('apply', value, evidence, kwargs)) or
        {'status_sha256': 'c' * 64})
    monkeypatch.setattr(plans, 'validate_completed_plan',
        lambda closure, value, evidence: calls.append(('recover', value, evidence)) or {'status_sha256': 'c' * 64})
    request = {'action': 'plan', 'root': '/etc/iris/console', 'identity': 'owned-id',
               'project': 'iris-test', 'dependency_manifest_sha256': 'e' * 64}
    return tmp_path / 'closure.tar.gz', request, calls


def test_remote_plan_revalidates_ubuntu_with_its_own_keyring_and_only_console_roots(remote_operations):
    archive, request, calls = remote_operations
    assert remote.perform_remote(archive, request) == planned()
    assert [row[0] for row in calls] == ['inspect', 'ubuntu-validate', 'plan']
    assert calls[-1][1] == {'required_roots': remote.REMOTE_ROOTS}


def test_remote_readonly_plan_uses_real_signed_closure_and_console_subset(tmp_path, signed_repository, monkeypatch):
    directory, keyring, digest = signed_repository
    archive = tmp_path / 'closure.tar.gz'
    archive.write_bytes(directory_archive(directory))
    status = tmp_path / 'synthetic-empty-status'
    status.write_bytes(b'')
    monkeypatch.setattr(remote, '_remote_identity', lambda request: 'a' * 64)
    monkeypatch.setattr(plans, 'STATUS', status)
    monkeypatch.setattr(dependencies.shutil, 'which', lambda *a, **k: None)
    validate, make_plan = dependencies.validate_closure, dependencies.plan_dependencies
    monkeypatch.setattr(dependencies, 'validate_closure',
        lambda path, expected: validate(path, expected, keyring=keyring))
    monkeypatch.setattr(dependencies, 'plan_dependencies',
        lambda closure, **kwargs: make_plan(closure, status=status, **kwargs))
    monkeypatch.setattr(dependencies, 'apply_dependencies', lambda *a, **k: pytest.fail('Read-only plan installed packages'))
    request = {'action': 'plan', 'root': '/etc/iris/console', 'identity': 'owned-id',
               'project': 'iris-test', 'dependency_manifest_sha256': digest}
    answer = remote.perform_remote(archive, request)
    assert {item['name'] for item in answer['plan']['packages']} == remote.REMOTE_ROOTS
    assert answer['plan']['required_roots'] == sorted(remote.REMOTE_ROOTS)
    assert answer['plan']['closure_sha256'] == digest
    assert answer['plan']['status_sha256'] == sha(b'')
    assert answer['evidence'] == {'unchanged_records_sha256': sha(b'{}')}
    assert status.read_bytes() == b''


@pytest.mark.parametrize('phase,operation', [('accepted', 'apply'), ('complete', 'recover')])
def test_remote_accepted_and_complete_phases_use_shared_recovery_policy(remote_operations, phase, operation):
    archive, request, calls = remote_operations
    request.update(action='apply', accepted_changes=True, phase=phase,
                   **{name: planned()[name] for name in ('host', 'plan', 'evidence')})
    assert remote.perform_remote(archive, request) == done()
    assert [row[0] for row in calls] == ['inspect', 'ubuntu-validate', operation]
    assert calls[-1][1:3] == (plan(), planned()['evidence'])
    if phase == 'accepted': assert calls[-1][3] == {'accept_changes': True}


@pytest.mark.parametrize('change', ['host', 'acceptance', 'scope', 'phase', 'extra'])
def test_remote_changed_authority_refuses_before_dependency_validation(remote_operations, change):
    archive, request, calls = remote_operations
    request.update(action='apply', accepted_changes=True, phase='accepted',
                   **{name: planned()[name] for name in ('host', 'plan', 'evidence')})
    if change == 'host': request['host'] = '9' * 64
    elif change == 'acceptance': request['accepted_changes'] = False
    elif change == 'scope': request['plan']['required_roots'] = ['skopeo']
    elif change == 'phase': request['phase'] = 'retry-anything'
    else: request['keyring'] = '/caller-selected-keyring'
    with pytest.raises(InstallError):
        remote.perform_remote(archive, request)
    assert calls == []


def test_split_ownership_inspection_never_claims_or_provisions(tmp_path, monkeypatch):
    obj = install(tmp_path)
    obj.journal.document['completed']['split-prepared'] = 'existing'
    calls = []
    monkeypatch.setattr(split.DockerInstall, 'verify_resource_ownership', lambda self: calls.append('local-inspect'))
    obj.remote = lambda action, **values: calls.append((action, values))
    obj.verify_resource_ownership()
    assert calls == ['local-inspect', ('ownership', {'require_runtime': True})]


@pytest.mark.parametrize('exists,required,docker', [(False, False, False), (False, True, False),
                                                  (True, False, False), (True, True, False), (True, True, True)])
def test_exact_remote_ownership_program_is_readonly(tmp_path, monkeypatch, exists, required, docker):
    root = tmp_path / 'console-custody'
    marker = {'instance_id': 'owned-id', 'project': 'iris-test'}
    if exists:
        root.mkdir()
        (root / 'owner.json').write_text(json.dumps(marker))
    request = dict(action='ownership', root=str(root), identity='owned-id', project='iris-test', require_runtime=required)
    calls = []
    original = Path.stat
    def protected(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        return SimpleNamespace(st_uid=0, st_mode=value.st_mode & ~0o022)
    def inspected(command, **kwargs):
        calls.append(command)
        assert command[0] == 'docker' and command[1] in ('container', 'volume', 'network') and command[2] == 'ls'
        return SimpleNamespace(returncode=0, stdout=b'')
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'stat', protected)
        patch.setattr(shutil, 'which', lambda name: '/usr/bin/docker' if docker else None)
        patch.setattr(subprocess, 'run', inspected)
        patch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode())))
        if required and (not exists or not docker):
            with pytest.raises(RuntimeError, match='missing|unavailable'):
                exec(compile(split.REMOTE_PROGRAM, '<ownership-only>', 'exec'), {})
        else:
            exec(compile(split.REMOTE_PROGRAM, '<ownership-only>', 'exec'), {})
    assert root.exists() == exists
    if exists: assert list(path.name for path in root.iterdir()) == ['owner.json']
    assert len(calls) == (3 if docker else 0)


@pytest.mark.parametrize('changed', [None, 'owner', 'mode', 'resource', 'machine'])
def test_remote_dependency_identity_checks_existing_custody_without_mutation(tmp_path, monkeypatch, changed):
    from iris_installer import ubuntu
    root = tmp_path / 'console-custody'
    root.mkdir()
    owner = root / 'owner.json'
    owner.write_text(json.dumps({'instance_id': 'other' if changed == 'owner' else 'owned-id', 'project': 'iris-test'}))
    calls = []
    monkeypatch.setattr(remote.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(ubuntu, 'check_platform', lambda: None)
    monkeypatch.setattr(release_kit, '_protected_directory', lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))
    original = Path.lstat
    def root_owner(path, *args, **kwargs):
        if path == owner: return SimpleNamespace(st_uid=0, st_mode=0o644 if changed == 'mode' else 0o600)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', root_owner)
    read = remote.regular_bytes
    monkeypatch.setattr(remote, 'regular_bytes', lambda path, limit: (
        b'bad machine' if changed == 'machine' else b'a' * 32 + b'\n') if str(path) == '/etc/machine-id' else read(path, limit))
    monkeypatch.setattr(shutil, 'which', lambda *args, **kwargs: '/usr/bin/docker')
    def command(args):
        calls.append(args)
        if args[2] == 'ls': return 'container-id' if args[1] == 'container' else ''
        return json.dumps([{'Config': {'Labels': {'com.cisco.iris.installer':
            'unfamiliar' if changed == 'resource' else 'owned-id'}}}])
    monkeypatch.setattr(dependencies, '_run', command)
    request = {'root': str(root), 'identity': 'owned-id', 'project': 'iris-test'}
    if changed:
        with pytest.raises(InstallError): remote._remote_identity(request)
    else:
        assert remote._remote_identity(request) == sha(b'a' * 32)
    assert all(args[0] == '/usr/bin/docker' and args[2] in ('ls', 'inspect') for args in calls)
    assert list(root.iterdir()) == [owner]


def test_split_prepare_dispatches_offline_only_during_preparation(deployment, monkeypatch):
    obj = deployment
    obj.console_build_file.write_text('{}')
    completed = obj.journal.document['completed']
    completed.update(prepared=split.digest(obj.compose_file), **{'split-prepared': split.digest(obj.console_build_file)})
    calls = []
    obj.remote = lambda action, **values: calls.append(action)
    monkeypatch.setattr(remote, 'provision', lambda value: calls.append('accepted-offline'))
    obj.prepare()
    assert calls == ['claim', 'accepted-offline', 'provision']
