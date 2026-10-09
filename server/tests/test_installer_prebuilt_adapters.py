# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Prepared-host adapter paths use synthetic kits, never real host mutations."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import deploy, kube_deploy as kube, prebuilt_install, release_kit
from iris_installer import split_deploy as split, ubuntu
from iris_installer.state import InstallError, Journal


INSTANCE = '12345678-1234-1234-1234-123456789abc'
IDS = {'iris': 'sha256:' + '1' * 64, 'console': 'sha256:' + '2' * 64}
CLASSES = {'docker': deploy.DockerInstall, 'docker-split': split.SplitDockerInstall,
           'kubernetes': kube.KubeInstall}


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    def make(target='docker'):
        base = tmp_path / target
        base.mkdir(mode=0o700)
        config = dict(target=target, instance='iris-prebuilt-test', host='192.0.2.10',
                      console_bind='127.0.0.1', console_port=28080,
                      peer_tls='required', recovery_recipient='age1' + 'q' * 58,
                      management_bind='192.0.2.10', console_ssh_host='192.0.2.11',
                      console_state_dir='/etc/iris/prebuilt-test', kube_registry_auth='',
                      kube_registry='registry.example/iris', kube_image_import='registry')
        assets = tuple(release_kit.Asset(role, role + '.tar', 1, 'a' * 64,
                       'docker-archive', ('linux/amd64',), IDS[service])
                       for service, role in prebuilt_install.SERVICE_ROLES.items())
        kit = release_kit.VerifiedKit(base, 'v2026.10.09', 'a' * 40,
                                     'b' * 64, 'c' * 64, 'd' * 64, 'e' * 64, True, assets)
        journal = Journal(base)
        journal.document = dict(schema=1, id=INSTANCE, config=config, completed={},
            input_selection=release_kit.selection('prebuilt', kit=kit, offline=True))
        journal.save()
        obj = object.__new__(CLASSES[target])
        obj.base, obj.config, obj.journal, obj._verified_kit = base, config, journal, kit
        obj.source, obj.compose_file, obj.env = base / 'source', base / 'compose.json', {}
        obj.console_file, obj.console_build_file = base / 'console.json', base / 'console-build.json'
        obj.source.mkdir()
        obj.calls = []
        def runner(command, **kwargs):
            command = [str(item) for item in command]
            obj.calls.append(command)
            if command[:2] == ['age-keygen', '-o']:
                Path(command[2]).write_bytes(b'synthetic private identity')
                return b''
            if command[:2] == ['age-keygen', '-y']:
                return b'age1synthetic'
            if command[:2] == ['docker', 'compose'] and 'config' in command:
                return json.dumps({'services': {
                    'iris': {'image': 'unselected:latest', 'build': {'context': 'server'},
                             'volumes': [], 'ports': []},
                    'console': {'image': 'unselected-console:latest', 'build': {'context': 'server'},
                                'depends_on': {'iris': {}}, 'volumes': [], 'ports': []}},
                    'volumes': {'data': {}}, 'networks': {'default': {}}}).encode()
            pytest.fail('Unexpected host operation: ' + repr(command))
        obj.runner = runner
        return obj
    monkeypatch.setattr(os, 'chown', lambda *args: None)
    return make


def specs(obj, services=('iris', 'console')):
    return {service: dict(image=prebuilt_install.image_tag(obj, service),
                          pull_policy='never', environment={}, volumes=[], ports=[])
            for service in services}


def imports(monkeypatch, obj):
    observed = []
    def importing(kit, role, instance, workspace, runner, *, previous, intent):
        service = next(name for name, value in prebuilt_install.SERVICE_ROLES.items() if value == role)
        expected = prebuilt_install.core_image_intent(kit, role, instance)
        persisted = json.loads(obj.journal.path.read_bytes())['completed']
        assert persisted['prebuilt-intent-' + service] == expected
        assert previous is None or previous == dict(expected, image_id=IDS[service])
        assert intent == (expected if previous is None else None)
        observed.append((service, previous))
        return dict(expected, image_id=IDS[service])
    monkeypatch.setattr(prebuilt_install, 'import_core_image', importing)
    return observed


@pytest.mark.parametrize('target', CLASSES)
def test_prebuilt_provision_selects_read_only_prepared_host_check(adapter, monkeypatch, target):
    obj = adapter(target)
    checked = []
    monkeypatch.setattr(ubuntu, 'preflight_prebuilt', lambda selected: checked.append(selected))
    monkeypatch.setattr(ubuntu, 'provision', lambda *_: pytest.fail('Must not install dependencies'))
    obj.provision_host()
    assert checked == [target] and obj.calls == []


@pytest.mark.parametrize('target', CLASSES)
def test_prepare_removes_build_and_sets_never_pull_for_every_core_service(adapter, monkeypatch, target):
    obj = adapter(target)
    events = []
    if target == 'docker-split':
        obj.transport_fingerprints = lambda: {'ssh': 'synthetic-pin'}
        obj.remote = lambda action, **kwargs: events.append(action)
    if target == 'kubernetes':
        obj.cluster_preflight = lambda: events.append('cluster-preflight')
    obj.prepare()
    rendered = json.loads(obj.compose_file.read_bytes())['services']
    if target == 'docker-split':
        assert set(rendered) == {'iris'} and events == ['claim', 'provision']
        rendered.update(json.loads(obj.console_build_file.read_bytes())['services'])
    assert set(rendered) == {'iris', 'console'}
    for service, spec in rendered.items():
        assert 'build' not in spec and spec['pull_policy'] == 'never'
        assert spec['image'] == prebuilt_install.image_tag(obj, service)
        assert spec['labels']['com.cisco.iris.installer'] == INSTANCE
    assert all('build' not in command and 'pull' not in command for command in obj.calls)
    original = copy.deepcopy(rendered)
    obj.prepare()
    current = json.loads(obj.compose_file.read_bytes())['services']
    if target == 'docker-split':
        current.update(json.loads(obj.console_build_file.read_bytes())['services'])
    assert current == original


@pytest.mark.parametrize('changed', [None, 'source', 'roots'])
def test_local_input_custody_precedes_kit_authentication_and_source_binding(adapter, monkeypatch, changed):
    obj = adapter()
    (obj.source / 'code').write_bytes(b'unchanged source')
    roots = obj.base / 'roots'
    roots.mkdir()
    values = {'a.pub': b'ssh-ed25519 AAAA a\n', 'b.pub': b'ssh-ed25519 BBBB b\n'}
    for name, value in values.items():
        (roots / name).write_bytes(value)
    manifest = {'code': hashlib.sha256(b'unchanged source').hexdigest()}
    obj.journal.document.update(source_manifest=manifest,
        root_digests={name: hashlib.sha256(value).hexdigest() for name, value in values.items()},
        prebuilt_ioxclient='/licensed/ioxclient')
    events = []
    monkeypatch.setattr(prebuilt_install, 'verify_selected', lambda journal: events.append('authenticate') or obj._verified_kit)
    monkeypatch.setattr(prebuilt_install, 'bind_source', lambda kit, inventory, workspace:
                        events.append(('bind', kit, inventory, workspace)))
    monkeypatch.setattr(prebuilt_install, 'validate_packaging_tool', lambda kit, tool, workspace:
                        events.append(('tool', kit, tool, workspace)))
    if changed == 'source':
        (obj.source / 'code').write_bytes(b'changed source')
    elif changed == 'roots':
        (roots / 'a.pub').write_bytes(b'ssh-ed25519 CCCC a\n')
    if changed:
        with pytest.raises(InstallError, match='changed'):
            obj.verify_inputs()
        assert events == []
    else:
        obj.verify_inputs()
        assert events == ['authenticate', ('bind', obj._verified_kit, manifest, obj.base),
                          ('tool', obj._verified_kit, '/licensed/ioxclient', obj.base)]
    assert obj.calls == []


@pytest.mark.parametrize('target', CLASSES)
@pytest.mark.parametrize('change', ['missing', 'changed'])
def test_resume_rechecks_licensed_tool_before_any_host_preparation(adapter, monkeypatch, target, change):
    from iris_installer import packaging_inputs
    obj = adapter(target)
    tool = obj.base / 'licensed-ioxclient'
    original = b'bounded executable fixture'
    tool.write_bytes(original)
    tool.chmod(0o700)
    if change == 'missing':
        tool.unlink()
    else:
        tool.write_bytes(b'changed executable')
    obj.journal.document.update(source_manifest={}, root_digests={}, prebuilt_ioxclient=str(tool))
    events = []
    monkeypatch.setattr(deploy, 'read_roots', lambda path: {})
    monkeypatch.setattr(prebuilt_install, 'verify_selected', lambda journal: obj._verified_kit)
    monkeypatch.setattr(prebuilt_install, 'bind_source', lambda *a: None)
    monkeypatch.setattr(packaging_inputs, 'prepare_packaging_inputs',
                        lambda *a: events.append('authenticated-packaging') or
                        SimpleNamespace(ioxclient_sha256=hashlib.sha256(original).hexdigest()))
    for name in ('provision_host', 'verify_resource_ownership', 'prepare', 'build', 'bootstrap'):
        monkeypatch.setattr(obj, name, lambda *a: pytest.fail('Tool must pass before host changes'))
    with pytest.raises((InstallError, FileNotFoundError)):
        obj.resume()
    assert events == ['authenticated-packaging'] and obj.calls == []
    assert not list(obj.base.glob('prebuilt-tool-check-*'))


@pytest.mark.parametrize('generated', [None, {}, {'schema': 1, 'directory': 'recorded-private-stage'}])
def test_existing_generation_defers_cache_validation_without_requiring_original_tool(adapter, monkeypatch, generated):
    obj = adapter()
    obj.journal.document.update(source_manifest={}, root_digests={}, prebuilt_ioxclient='/missing/ioxclient')
    obj.journal.document['completed']['prebuilt-package-generated'] = generated
    monkeypatch.setattr(deploy, 'read_roots', lambda path: {})
    monkeypatch.setattr(prebuilt_install, 'verify_selected', lambda journal: obj._verified_kit)
    monkeypatch.setattr(prebuilt_install, 'bind_source', lambda *a: None)
    monkeypatch.setattr(prebuilt_install, 'validate_packaging_tool',
                        lambda *a: pytest.fail('Recorded generation is validated by the package adapter'))
    obj.verify_inputs()
    assert obj.calls == []


def test_docker_build_imports_and_rechecks_same_ids_without_compose_build(adapter, monkeypatch):
    obj = adapter()
    obj.compose_file.write_text(json.dumps({'services': specs(obj)}))
    observed = imports(monkeypatch, obj)
    obj.runner = lambda command, **kwargs: obj.calls.append(command) or b''
    obj.build()
    expected = {prebuilt_install.image_tag(obj, service): identity for service, identity in IDS.items()}
    assert obj.journal.document['completed']['images'] == expected
    first = copy.deepcopy(obj.journal.document['completed'])
    obj.build()
    assert obj.journal.document['completed'] == first
    assert len(observed) == 4 and all(previous for _, previous in observed[2:])
    assert all(command[:3] == ['docker', 'image', 'ls'] for command in obj.calls)


@pytest.mark.parametrize('changed', [None, 'local', 'remote', 'saved'])
def test_split_import_retains_immutable_transfer_and_refuses_drift(adapter, monkeypatch, changed):
    obj = adapter('docker-split')
    obj.compose_file.write_text(json.dumps({'services': specs(obj, ('iris',))}))
    obj.console_build_file.write_text(json.dumps({'services': specs(obj, ('console',))}))
    observed = imports(monkeypatch, obj)
    remote, transferred = [], []
    if changed == 'saved':
        obj.journal.document['completed']['console-image'] = 'sha256:' + '3' * 64
    def command(argv, **kwargs):
        obj.calls.append(argv)
        if argv[:3] == ['docker', 'image', 'ls']:
            return b''
        assert argv[:3] == ['docker', 'image', 'inspect']
        return ('sha256:' + '3' * 64 if changed == 'local' else IDS['console']).encode()
    obj.command = command
    obj._transfer_image = lambda identity: transferred.append(identity)
    def request(action, **kwargs):
        remote.append((action, kwargs))
        return ('sha256:' + '3' * 64 if changed == 'remote' else IDS['console']).encode()
    obj.remote = request
    if changed:
        with pytest.raises(InstallError, match='differs|changed|verification failed'):
            obj.build()
        assert not any(action == 'write' for action, _ in remote)
        if changed != 'remote':
            assert transferred == []
    else:
        obj.build()
        result = json.loads(obj.console_file.read_bytes())['services']['console']
        assert result['image'] == IDS['console'] and result['pull_policy'] == 'never'
        assert 'build' not in result and transferred == [IDS['console']]
        assert [action for action, _ in remote] == ['inspect', 'write']
        assert obj.journal.document['completed']['console-image'] == IDS['console']
    assert {service for service, _ in observed} == {'iris', 'console'}
    assert all(command[:3] in (['docker', 'image', 'ls'], ['docker', 'image', 'inspect']) for command in obj.calls)


def test_kubernetes_import_keeps_digest_transport_and_resume_without_republication(adapter, monkeypatch):
    obj = adapter('kubernetes')
    obj.compose_file.write_text(json.dumps({'services': specs(obj)}))
    observed = imports(monkeypatch, obj)
    def command(argv, **kwargs):
        obj.calls.append(argv)
        if argv[:3] == ['docker', 'image', 'ls'] or argv[:2] in (['docker', 'tag'], ['docker', 'push']):
            return b''
        assert argv[:3] == ['docker', 'image', 'inspect']
        service = 'console' if '-console:' in argv[3] else 'iris'
        return json.dumps([{'Id': IDS[service], 'RepoDigests': [argv[3].split(':')[0] + '@' + IDS[service]]}]).encode()
    obj.command = command
    obj.build()
    expected = {service: 'registry.example/iris/iris-prebuilt-test-' + service + '@' + identity
                for service, identity in IDS.items()}
    assert obj.journal.document['completed']['kube-images'] == expected
    first_calls = len(obj.calls)
    obj.build()
    assert obj.calls[first_calls:] == [] and len(observed) == 4
    assert all(previous for _, previous in observed[2:])
    assert sum(command[:2] == ['docker', 'push'] for command in obj.calls) == 2
    assert all('build' not in command and 'pull' not in command for command in obj.calls)


def test_kubernetes_local_import_keeps_existing_archive_and_digest_guards(adapter, monkeypatch):
    obj = adapter('kubernetes')
    obj.config.update(kube_registry='', kube_image_import='k3s')
    obj.compose_file.write_text(json.dumps({'services': specs(obj)}))
    imports(monkeypatch, obj)
    active = {}
    manifests = {'iris': 'sha256:' + '3' * 64, 'console': 'sha256:' + '4' * 64}
    def command(argv, **kwargs):
        argv = [str(value) for value in argv]
        obj.calls.append(argv)
        if argv[:3] == ['docker', 'image', 'ls']:
            return b''
        if argv[:2] == ['docker', 'tag']:
            active['service'] = 'console' if '-console:' in argv[3] else 'iris'
            active['tag'] = argv[3]
        elif argv[:2] == ['docker', 'save']:
            assert argv[-1] == active['tag']
        elif argv[:3] == ['skopeo', 'inspect', '--raw']:
            return json.dumps({'config': {'digest': IDS[active['service']]}}).encode()
        elif argv[:4] == ['k3s', 'ctr', 'images', 'list']:
            return (active['tag'] + ' manifest ' + manifests[active['service']] + '\n').encode()
        else:
            assert argv[:4] in (['k3s', 'ctr', 'images', 'import'], ['k3s', 'ctr', 'images', 'tag'])
        return b''
    obj.command = command
    obj.build()
    assert obj.journal.document['completed']['kube-images'] == {
        service: 'docker.io/iris-installer/iris-prebuilt-test-' + service + '@' + identity
        for service, identity in manifests.items()}
    assert sum(command[:4] == ['k3s', 'ctr', 'images', 'import'] for command in obj.calls) == 2
    assert all('build' not in command and 'pull' not in command and 'push' not in command for command in obj.calls)


@pytest.mark.parametrize('target', CLASSES)
def test_resume_never_skips_local_import_identity_guard_for_saved_topology_images(adapter, monkeypatch, target):
    obj = adapter(target)
    obj.compose_file.write_text(json.dumps({'services': specs(obj)}))
    completed = obj.journal.document['completed']
    completed['kube-images'] = {service: 'example/image@' + identity for service, identity in IDS.items()}
    completed['console-image'] = IDS['console']
    for service, role in prebuilt_install.SERVICE_ROLES.items():
        evidence = prebuilt_install.core_image_intent(obj._verified_kit, role, INSTANCE)
        completed['prebuilt-import-' + service] = dict(evidence, image_id=IDS[service])
    def changed(*args, **kwargs):
        assert kwargs['previous'] is not None and kwargs['intent'] is None
        raise InstallError('Previously imported image is missing or changed')
    monkeypatch.setattr(prebuilt_install, 'import_core_image', changed)
    with pytest.raises(InstallError, match='missing or changed'):
        obj.build()
    assert obj.calls == []


def test_split_remote_provision_request_carries_explicit_prebuilt_mode(adapter):
    obj = adapter('docker-split')
    obj.journal.document['completed']['split-transport'] = {'ssh': 'pinned'}
    obj.transport_fingerprints = lambda: {'ssh': 'pinned'}
    obj.ssh_command = lambda command: ['fixture-only-ssh', command]
    sent = []
    obj.command = lambda command, **kwargs: sent.append(json.loads(kwargs['input'])) or b''
    obj.remote('provision')
    assert sent == [{'action': 'provision', 'root': obj.config['console_state_dir'],
                     'identity': INSTANCE, 'project': obj.config['instance'], 'prebuilt': True}]


@pytest.mark.parametrize('target', CLASSES)
def test_missing_explicit_packager_cannot_fall_back_to_download_or_build(adapter, target):
    obj = adapter(target)
    with pytest.raises(InstallError, match='explicitly supplied local ioxclient'):
        obj.packages()
    assert obj.calls == [] and obj.journal.document['completed'] == {}


def test_kubernetes_resume_does_not_provision_client_or_dependencies(adapter, monkeypatch):
    obj = adapter('kubernetes')
    events = []
    monkeypatch.setattr(ubuntu, 'provision', lambda *_: pytest.fail('No apt provisioning'))
    monkeypatch.setattr(ubuntu, 'provision_kubernetes_client', lambda *_: pytest.fail('No client download'))
    monkeypatch.setattr(ubuntu, 'preflight_prebuilt', lambda target: events.append(('preflight', target)))
    for method in ('verify_inputs', 'verify_resource_ownership', 'prepare', 'build', 'bootstrap'):
        setattr(obj, method, lambda selected=method: events.append(selected))
    obj.command = lambda argv, **kwargs: events.append('time-check')
    obj.signing = lambda certificate: events.append('signing') or False
    assert obj.resume() == deploy.WAITING_APPROVAL
    assert events == ['verify_inputs', ('preflight', 'kubernetes'), 'verify_resource_ownership',
                      'time-check', 'prepare', 'build', 'bootstrap', 'signing']


@pytest.mark.parametrize('missing', [None, 'docker', 'openssl', 'compose'])
def test_exact_split_remote_program_prebuilt_provision_is_read_only(tmp_path, monkeypatch, missing):
    root = tmp_path / 'remote-console'
    root.mkdir()
    marker = {'instance_id': INSTANCE, 'project': 'iris-prebuilt-test'}
    (root / 'owner.json').write_text(json.dumps(marker))
    request = dict(action='provision', root=str(root), identity=INSTANCE,
                   project=marker['project'], prebuilt=True)
    calls = []
    real_stat, real_text = Path.stat, Path.read_text
    def protected_stat(path, *args, **kwargs):
        actual = real_stat(path, *args, **kwargs)
        return SimpleNamespace(st_uid=0, st_mode=actual.st_mode & ~0o022)
    def read_text(path, *args, **kwargs):
        return 'ID=ubuntu\nVERSION_ID="24.04"\n' if str(path) == '/etc/os-release' else real_text(path, *args, **kwargs)
    def run(command, **kwargs):
        calls.append(command)
        assert command == ['docker', 'info'] or command == ['docker', 'compose', 'version'] or (
            command[0] == 'docker' and command[1] in ('container', 'volume', 'network') and command[2] == 'ls')
        return SimpleNamespace(returncode=int(missing == 'compose' and command == ['docker', 'compose', 'version']), stdout=b'')
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'stat', protected_stat)
        patch.setattr(Path, 'read_text', read_text)
        patch.setattr(platform, 'machine', lambda: 'x86_64')
        patch.setattr(shutil, 'which', lambda name: None if name == missing else '/usr/bin/' + name)
        patch.setattr(subprocess, 'run', run)
        patch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode())))
        if missing:
            with pytest.raises(RuntimeError, match='already installed|Remote operation failed'):
                exec(compile(split.REMOTE_PROGRAM, '<prebuilt-remote>', 'exec'), {})
        else:
            with pytest.raises(SystemExit) as stopped:
                exec(compile(split.REMOTE_PROGRAM, '<prebuilt-remote>', 'exec'), {})
            assert stopped.value.code == 0
    assert json.loads((root / 'owner.json').read_bytes()) == marker
    assert sorted(path.name for path in root.iterdir()) == ['owner.json']
    if missing in ('docker', 'openssl'):
        assert calls == []
    elif not missing:
        assert calls[:2] == [['docker', 'info'], ['docker', 'compose', 'version']]
        assert len(calls) == 5
