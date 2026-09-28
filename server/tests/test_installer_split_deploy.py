# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Split deployment custody, routing and immutable image regression tests."""

import base64
import contextlib
import io
import json
from pathlib import Path
import stat
import sys
import uuid
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import split_deploy as split
from iris_installer import management_sync
from iris_installer.state import InstallError


def config():
    return dict(target='docker-split', instance='iris-test', host='192.0.2.10',
                console_bind='127.0.0.1', console_port=28080, peer_tls='required',
                recovery_recipient='age1' + 'q' * 58,
                console_ssh_host='192.0.2.11', console_ssh_user='operator', console_ssh_port=22,
                console_ssh_key='/etc/iris/ssh', console_known_hosts='/etc/iris/known_hosts',
                console_state_dir='/etc/iris/test-console', management_bind='192.0.2.10')


def fake_files(monkeypatch, *, mode=0o100600, owner=0):
    monkeypatch.setattr(Path, 'resolve', lambda self: self)
    monkeypatch.setattr(Path, 'lstat', lambda self: SimpleNamespace(st_mode=mode, st_uid=owner))
    monkeypatch.setattr(split, 'regular_bytes', lambda *args: b'pinned-key')


@pytest.mark.parametrize('change', [
    {'console_ssh_host': '-oProxyCommand=evil'}, {'console_ssh_user': 'root; evil'},
    {'console_ssh_port': True}, {'console_ssh_port': 0}, {'management_bind': '0.0.0.0'},
    {'management_bind': '192.0.2.12'}, {'console_state_dir': '/'},
    {'console_state_dir': '/etc/iris/../other'}, {'console_state_dir': '/etc/iris/x;id'},
    {'console_ssh_key': 'relative'}, {'extra': 'field'},
])
def test_rejects_unsafe_transport_and_custody(monkeypatch, change):
    fake_files(monkeypatch)
    with pytest.raises(InstallError):
        split.validate_split_config(dict(config(), **change))


@pytest.mark.parametrize('mode,owner', [(0o100644, 0), (0o100600, 1000), (0o010600, 0)])
def test_rejects_private_transport_file_exposure(monkeypatch, mode, owner):
    fake_files(monkeypatch, mode=mode, owner=owner)
    with pytest.raises(InstallError):
        split.validate_split_config(config())


def test_accepts_explicit_root_custody(monkeypatch):
    fake_files(monkeypatch)
    split.validate_split_config(config())


def install(tmp_path):
    obj = object.__new__(split.SplitDockerInstall)
    obj.config = config()
    obj.base = tmp_path
    obj.compose_file = tmp_path / 'compose.json'
    obj.console_file = tmp_path / 'console-compose.json'
    obj.console_build_file = tmp_path / 'console-build.json'
    obj.env = {}
    obj.journal = SimpleNamespace(document={'id': 'fixture-id', 'config': obj.config,
        'completed': {'images': {'server-tag': 'sha256:' + 'a' * 64}, 'console-image': 'sha256:' + 'b' * 64}})
    obj.compose_file.write_text(json.dumps({'services': {'iris': {'image': 'server-tag', 'build': 'source'}}}))
    obj.console_file.write_text('{}')
    return obj


def test_ssh_transport_pins_host_and_disables_ambient_credentials(tmp_path):
    obj = install(tmp_path)
    command = obj.ssh_command('fixed-command')
    assert command[:3] == ['ssh', '-F', '/dev/null']
    for expected in ('StrictHostKeyChecking=yes', 'BatchMode=yes', 'IdentitiesOnly=yes',
                     'PasswordAuthentication=no', 'ForwardAgent=no', 'ClearAllForwardings=yes',
                     'GlobalKnownHostsFile=/dev/null', 'UserKnownHostsFile=/etc/iris/known_hosts'):
        assert expected in command
    assert command[-2:] == ['operator@192.0.2.11', 'fixed-command']


def test_secrets_are_only_on_remote_stdin(tmp_path):
    obj = install(tmp_path)
    calls = []
    obj.command = lambda args, **kw: calls.append((args, kw)) or b'ok'
    obj.remote('write', files={'current.json': 'secret-fixture'})
    assert 'secret-fixture' not in str(calls[0][0])
    payload = json.loads(calls[0][1]['input'])
    assert payload['files']['current.json'] == 'secret-fixture'
    assert payload['identity'] == 'fixture-id'
    assert payload['root'] == '/etc/iris/test-console'


@pytest.mark.parametrize('args', [('stop', 'console'), ('up', '-d', 'console'),
                                ('exec', '-T', 'console', 'python3', '-c', 'code')])
def test_console_commands_use_remote_engine(tmp_path, args):
    obj = install(tmp_path)
    obj.remote_console = lambda *values, **kwargs: values
    assert obj.compose(*args) == args


def test_runtime_projection_preserves_remote_routing_and_pins_server(tmp_path):
    obj = install(tmp_path)
    obj._runtime_images = obj.journal.document['completed']['images']
    captured = []
    def command(args, **kwargs):
        document = json.loads(Path(args[args.index('-f') + 1]).read_bytes())
        captured.append(document)
        return b'local'
    obj.command = command
    assert obj.compose('up', '-d', 'iris') == b'local'
    assert captured[0]['services']['iris'] == {'image': 'sha256:' + 'a' * 64}
    assert json.loads(obj.compose_file.read_bytes())['services']['iris']['image'] == 'server-tag'
    assert not list(tmp_path.glob('split-runtime-*'))


@pytest.mark.parametrize('args', [('stop', '--timeout', '120', 'console', 'iris'),
                                ('stop', '--timeout', '120')])
def test_mixed_stop_orders_remote_console_before_server(tmp_path, args):
    obj = install(tmp_path)
    calls = []
    obj.remote_console = lambda *values, **kwargs: calls.append(('remote', values)) or b''
    obj.command = lambda values, **kwargs: calls.append(('local', values)) or b''
    obj.compose(*args)
    assert [item[0] for item in calls] == ['remote', 'local']
    assert calls[0][1][-1] == 'console'
    assert calls[1][1][-1] == 'iris'
    assert 'console' not in calls[1][1]


def test_pin_runtime_rejects_changed_local_image_before_remote_mutation(tmp_path):
    obj = install(tmp_path)
    obj.command = lambda *args, **kwargs: b'sha256:changed'
    obj.remote = lambda *args, **kwargs: pytest.fail('No remote mutation on changed local image')
    with pytest.raises(InstallError):
        obj.pin_runtime()


def test_management_export_is_allowlisted_and_clears_previous(tmp_path):
    obj = install(tmp_path)
    obj.python = lambda code: json.dumps({'current.json': 'YQ==', 'ca.pem': 'Yg=='}).encode()
    calls = []
    obj.remote = lambda action, **values: calls.append((action, values))
    obj.sync_console_credentials()
    assert calls == [('write', {'files': {'current.json': 'YQ==', 'ca.pem': 'Yg==', 'previous.json': ''}})]
    obj.python = lambda code: json.dumps({'current.json': 'YQ==', 'ca.pem': 'Yg==', 'age.txt': 'Yw=='}).encode()
    with pytest.raises(InstallError):
        obj.sync_console_credentials()


def test_remote_backup_is_encrypted_before_any_disk_write(tmp_path):
    obj = install(tmp_path)
    obj.assert_writers_stopped = lambda: None
    obj.console_custody_snapshot = lambda: b'private-console-custody'
    def command(args, **kwargs):
        if args[0] == 'age-keygen':
            return ('age1' + 'p' * 58).encode()
        assert args[0] == 'age'
        assert kwargs['input'] == b'private-console-custody'
        return b'encrypted-console-custody'
    obj.command = command
    sources = {}
    obj.capture_backup_extras(sources)
    assert sources['remote-console-custody'].read_bytes() == b'encrypted-console-custody'
    assert stat.S_IMODE(sources['remote-console-custody'].stat().st_mode) == 0o600


def test_restore_rejects_service_key_transfer(tmp_path):
    obj = install(tmp_path)
    with pytest.raises(InstallError):
        obj.restore_console_custody(b'{"age.txt":"PRIVATE"}')


def test_consumer_proof_must_be_authenticated_and_fingerprinted(tmp_path):
    obj = install(tmp_path)
    good = {'management_https': 'verified', 'certificate_sha256': 'a' * 64}
    obj.remote_console = lambda *args, **kwargs: json.dumps(good).encode()
    assert obj.verify_console_management() == good
    obj.remote_console = lambda *args, **kwargs: b'{"management_https":"verified"}'
    with pytest.raises(InstallError):
        obj.verify_console_management()


def test_remote_program_compiles_and_has_no_service_private_export():
    compile(split.REMOTE_PROGRAM, '<remote-console>', 'exec')
    assert 'age.txt' not in split.REMOTE_PROGRAM
    assert 'management-key' not in split.REMOTE_PROGRAM


def test_prepare_separates_console_and_exposes_only_authenticated_management(tmp_path, monkeypatch):
    obj = install(tmp_path)
    def combined(self):
        self.compose_file.write_text(json.dumps({'services': {
            'iris': {'image': 'server-tag', 'ports': []},
            'console': {'image': 'console-tag', 'depends_on': {'iris': {}},
                        'volumes': [{'source': 'local-tier-volume'}], 'environment': {}}
        }}))
    monkeypatch.setattr(split.DockerInstall, 'prepare', combined)
    obj.journal.checkpoint = lambda name, value: obj.journal.document['completed'].update({name: value})
    obj.transport_fingerprints = lambda: {'ssh': 'pinned'}
    calls = []
    obj.remote = lambda action, **kwargs: calls.append(action)
    obj.prepare()
    document = json.loads(obj.compose_file.read_bytes())
    assert set(document['services']) == {'iris'}
    assert document['services']['iris']['ports'] == [{'target': 9443, 'published': '9443',
        'host_ip': '192.0.2.10', 'protocol': 'tcp'}]
    console = json.loads(obj.console_build_file.read_bytes())['services']['console']
    assert 'depends_on' not in console and console['volumes'] == []
    assert calls == ['claim', 'provision']
    obj.prepare()  # Owned rendered inputs verified without rendering again.
    assert calls == ['claim', 'provision']


def test_remote_build_has_only_console_custody_and_immutable_image(tmp_path, monkeypatch):
    obj = install(tmp_path)
    obj.console_build_file.write_text(json.dumps({'services': {'console': {
        'image': 'console-tag', 'build': {'context': '/source'}, 'environment': {},
        'volumes': [], 'ports': []}}}))
    monkeypatch.setattr(split.DockerInstall, 'build', lambda self: None)
    expected = obj.journal.document['completed']['console-image']
    obj.command = lambda *args, **kwargs: expected.encode()
    transferred = []
    obj._transfer_image = lambda image: transferred.append(image)
    requests = []
    def remote(action, **kwargs):
        requests.append((action, kwargs))
        return expected.encode() if action == 'inspect' else b''
    obj.remote = remote
    obj.journal.checkpoint = lambda name, value: obj.journal.document['completed'].update({name: value})
    obj.build()
    spec = json.loads(obj.console_file.read_bytes())['services']['console']
    assert spec['image'] == expected and 'build' not in spec
    assert spec['volumes'] == [{'type': 'bind', 'source': '/etc/iris/test-console',
        'target': '/run/iris-console-custody', 'read_only': True, 'bind': {'create_host_path': False}}]
    assert '/run/iris-console-custody/current.json' == spec['environment']['IRIS_MANAGEMENT_API_TOKEN_FILE']
    assert spec['environment']['IRIS_MANAGEMENT_API_URL'] == 'https://192.0.2.10:9443'
    assert transferred == [expected]
    assert list(requests[-1][1]['files']) == ['compose.json']


def test_management_operation_sync_binds_publication_to_replacement_and_rechecks(tmp_path, monkeypatch):
    obj = install(tmp_path)
    operation = 'a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12
    authority = {'request_id': operation, 'current_sha256': 'b' * 64}
    calls = []
    monkeypatch.setattr(management_sync, 'validate_operation', lambda *_: calls.append('validate') or authority)
    obj.verify_resource_ownership = lambda: calls.append('owned')
    obj.remote_container = lambda: calls.append('container')
    obj.sync_console_credentials = lambda: calls.append('publish')
    obj.verify_console_management = lambda **kwargs: calls.append(('proof', kwargs))
    assert obj.sync_management_operation(operation) == dict(authority, consumers_verified=1)
    assert calls == ['validate', 'owned', 'container', 'publish',
                     ('proof', {'expected_token': 'b' * 64}), 'validate']


def test_remote_consumer_proof_rejects_overlap_token(tmp_path):
    obj = install(tmp_path)
    obj.remote_console = lambda *args, **kwargs: json.dumps({
        'management_https': 'verified', 'certificate_sha256': 'a' * 64,
        'current_token_sha256': 'b' * 64}).encode()
    with pytest.raises(InstallError, match='replacement'):
        obj.verify_console_management(expected_token='c' * 64)


@pytest.mark.parametrize('operation', ['not-a-uuid', '../state', None])
def test_management_sync_rejects_unbounded_operation_ids(tmp_path, operation):
    obj = install(tmp_path)
    obj.python = lambda *_: pytest.fail('invalid request reached server')
    with pytest.raises(InstallError):
        management_sync.validate_operation(obj, operation)


def test_management_sync_real_public_intent_validation(tmp_path, monkeypatch):
    import key_maintenance
    import tier_auth
    current, previous = tmp_path / 'current', tmp_path / 'previous'
    current.write_bytes(b'a' * 64)
    current.chmod(0o600)
    monkeypatch.setenv('IRIS_MANAGEMENT_API_TOKEN_FILE', str(current))
    monkeypatch.setenv('IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE', str(previous))
    monkeypatch.setenv('IRIS_STATE', str(tmp_path))
    monkeypatch.setenv('IRIS_INSTALLER_TARGET', 'docker')
    clock = [10000]
    engine = key_maintenance.Maintenance(tmp_path, now=lambda: clock[0])
    engine.update({'action': 'save-policy', 'revision': 0, 'policy': {
        'id': str(uuid.uuid4()), 'family': 'management-token', 'target': 'deployment',
        'enabled': True, 'next_at': 10001, 'interval_days': 14, 'window_minutes': 30}})
    clock[0] += 1
    engine.tick()
    job = engine.status()['jobs'][0]
    obj = install(tmp_path)
    def python(code, *arguments):
        output = io.StringIO()
        with monkeypatch.context() as patch:
            patch.setattr(sys, 'argv', ['-c', *arguments])
            with contextlib.redirect_stdout(output):
                exec(compile(code, '<management-sync>', 'exec'), {})
        return output.getvalue().encode()
    obj.python = python
    assert management_sync.validate_operation(obj, job['id']) == {
        'request_id': job['id'], 'current_sha256': job['after']}
    current.write_bytes(b'changed-unapproved-token' * 3)
    with pytest.raises(RuntimeError, match='authority changed'):
        management_sync.validate_operation(obj, job['id'])
