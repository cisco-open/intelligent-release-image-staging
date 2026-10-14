# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Explicit persisted metrics opt-in; no service or dependency commands run."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import cli, deploy, kube_deploy, local_setup, split_deploy, upgrade_candidate
from iris_installer.state import InstallError, Journal
from test_installer_kube_deploy import config as kube_config, install as kube_install
from test_installer_split_deploy import config as split_config, fake_files


def config():
    return dict(target='docker', instance='iris-test', host='192.0.2.10', console_bind='127.0.0.1',
                console_port=18080, recovery_recipient='age1' + 'q' * 58, peer_tls='required')


@pytest.mark.parametrize('target', ['docker', 'docker-split', 'kubernetes'])
@pytest.mark.parametrize('enabled', [False, True])
def test_both_cli_paths_and_guided_forwarding_preserve_exact_boolean(target, enabled):
    flags = ['--observability'] if enabled else []
    for command in ('install', 'setup'):
        args = cli.parser().parse_args([command, '--target', target, *flags])
        assert args.observability is enabled
        if command == 'setup':
            forwarded = local_setup.install_arguments(args)
            assert forwarded.count('--observability') == int(enabled)
            assert cli.parser().parse_args(forwarded).observability is enabled


@pytest.mark.parametrize('value', [None, 0, 1, 'true', 'false', '', [], {}])
def test_all_closed_validators_refuse_non_boolean_without_mutating_input(monkeypatch, value):
    fake_files(monkeypatch)
    for factory, validator in ((config, deploy.validate_config), (kube_config, kube_deploy.validate_config),
                               (split_config, split_deploy.validate_split_config)):
        record = dict(factory(), observability=value)
        original = copy.deepcopy(record)
        with pytest.raises(InstallError, match='Observability'):
            validator(record)
        assert record == original
        with pytest.raises(InstallError, match='Observability'):
            deploy.validate_config(record)


@pytest.mark.parametrize('value', ['legacy', False, True])
def test_legacy_and_explicit_journals_validate_without_rewriting(monkeypatch, value):
    fake_files(monkeypatch)
    for factory, validator in ((config, deploy.validate_config), (kube_config, kube_deploy.validate_config),
                               (split_config, split_deploy.validate_split_config)):
        record = factory()
        if value != 'legacy': record['observability'] = value
        original = copy.deepcopy(record)
        validator(record)
        deploy.validate_config(record)
        assert record == original
        assert deploy.observability_enabled(record) is (value is True)


@pytest.mark.parametrize('value', ['legacy', False, True])
@pytest.mark.parametrize('split', [False, True])
def test_actual_docker_and_split_prepare_pass_only_recorded_opt_in(tmp_path, monkeypatch, value, split):
    # Docker Compose itself is a process boundary; its actual input env and
    # argv are asserted, and its public JSON output models that interpolation.
    record = config()
    if value != 'legacy': record['observability'] = value
    if split: record.update(split_config())
    doc = {'id': 'owned', 'config': record, 'completed': {}}
    journal = SimpleNamespace(directory=tmp_path, document=doc,
        checkpoint=lambda key, item: doc['completed'].update({key: item}))
    captured = []
    def runner(argv, **kwargs):
        if argv[:2] == ['age-keygen', '-o']: Path(argv[2]).write_bytes(b'private-stand-in')
        if argv[:2] == ['age-keygen', '-y']: return b'age1primary'
        if 'config' in argv:
            captured.append(kwargs['env'])
            assert argv[argv.index('--env-file') + 1] == str(tmp_path / 'compose.env')
            return json.dumps({'services': {'iris': {'volumes': [], 'environment': {
                'IRIS_OBSERVABILITY': kwargs['env']['IRIS_OBSERVABILITY']}}, 'console': {}},
                'networks': {}, 'volumes': {}}).encode()
        return b''
    monkeypatch.setenv('IRIS_OBSERVABILITY', 'untrusted-ambient-value')
    monkeypatch.setattr(os, 'chown', lambda *_: None)
    with monkeypatch.context() as scope:
        scope.setattr(deploy, 'validate_config', lambda _: None)  # Transport files have separate custody tests.
        scope.setattr(split_deploy, 'validate_split_config', lambda _: None)
        obj = (split_deploy.SplitDockerInstall if split else deploy.DockerInstall)(journal, runner)
    if split:
        obj.remote = lambda *_: None
        obj.transport_fingerprints = lambda: {'ssh': 'fixed-test-boundary'}
    original = copy.deepcopy(record)
    obj.prepare()
    expected = '1' if value is True else ''
    assert captured[0]['IRIS_OBSERVABILITY'] == expected
    generated = json.loads(obj.compose_file.read_text())
    assert generated['services']['iris']['environment']['IRIS_OBSERVABILITY'] == expected
    assert record == original
    before = obj.compose_file.read_bytes()
    obj.prepare()
    assert len(captured) == 1 and obj.compose_file.read_bytes() == before


@pytest.mark.parametrize('value', ['legacy', False, True])
def test_actual_kubernetes_manifest_records_server_only_opt_in(tmp_path, monkeypatch, value):
    obj = kube_install(tmp_path)
    if value != 'legacy': obj.config['observability'] = value
    (tmp_path / 'roots').mkdir()
    for name, key in [('a', 'AAAA'), ('b', 'BBBB')]:
        (tmp_path / 'roots' / (name + '.pub')).write_text('ssh-ed25519 ' + key + '\n')
    (tmp_path / 'age.txt').write_bytes(b'identity')
    custody = {}
    for name in ('ca.crt', 'client.crt', 'client.key'):
        custody[name] = tmp_path / name
        custody[name].write_bytes(name.encode())
    from iris_installer import lifecycle_network
    monkeypatch.setattr(lifecycle_network, 'prepare_network_custody', lambda *_: custody)
    obj._certificate = lambda *_: {'tls.key': b'key', 'tls.crt': b'certificate'}
    obj.command = lambda *_, **__: ('age1' + 'q' * 58).encode()
    original = copy.deepcopy(obj.config)
    rows = obj.manifests()
    server = next(row for row in rows if row['kind'] == 'ConfigMap' and row['metadata']['name'] == 'iris-seed-server')
    assert server['data']['IRIS_OBSERVABILITY'] == ('1' if value is True else '')
    console = next(row for row in rows if row['kind'] == 'Deployment' and row['metadata']['name'] == 'iris-console')
    assert all(row['name'] != 'IRIS_OBSERVABILITY' for row in console['spec']['template']['spec']['containers'][0]['env'])
    assert obj.manifests() == rows and obj.config == original


@pytest.mark.parametrize('value', ['legacy', False, True])
def test_upgrade_renders_both_release_templates_with_same_recorded_selection(tmp_path, monkeypatch, value):
    record = config()
    if value != 'legacy': record['observability'] = value
    calls = []
    def runner(argv, **kwargs):
        assert kwargs['capture'] is True
        if argv == ['age-keygen', '-y', str(tmp_path / 'age.txt')]:
            return ('age1' + 'q' * 58).encode()
        assert argv[:2] == ['docker', 'compose']
        calls.append((argv, kwargs['env']))
        return json.dumps({'services': {'iris': {'environment': {
            'IRIS_OBSERVABILITY': kwargs['env']['IRIS_OBSERVABILITY']}}, 'console': {}}}).encode()
    monkeypatch.setenv('IRIS_OBSERVABILITY', 'untrusted-ambient-value')
    obj = SimpleNamespace(base=tmp_path, config=record, env=deploy.clean_env(), runner=runner)
    # Exercise the real command boundary used by template(), including argument
    # conversion and the explicitly selected environment, without host commands.
    obj.command = deploy.DockerInstall.command.__get__(obj)
    before = copy.deepcopy(record)
    sources = (tmp_path / 'old', tmp_path / 'new')
    rendered = [upgrade_candidate.template(obj, source) for source in sources]
    expected = '1' if value is True else ''
    assert len(calls) == 2 and calls[0][1] == calls[1][1]
    assert calls[0][1]['IRIS_OBSERVABILITY'] == expected and record == before
    for source, (argv, _env), result in zip(sources, calls, rendered):
        assert argv == ['docker', 'compose', '--env-file', str(tmp_path / 'compose.env'),
                        '-p', record['instance'], '-f', str(source / 'server/docker-compose.yml'),
                        'config', '--format', 'json']
        assert result['services']['iris']['environment']['IRIS_OBSERVABILITY'] == expected


@pytest.mark.skipif(os.geteuid() != 0, reason='Real root-owned journal custody')
@pytest.mark.parametrize('enabled', [False, True])
def test_new_install_persists_selection_and_resume_reads_it(tmp_path, monkeypatch, enabled):
    source, roots = tmp_path / 'input', tmp_path / 'roots'
    source.mkdir(); roots.mkdir()
    (source / 'code').write_bytes(b'code')
    (source / 'INSTALLER-SOURCE.json').write_text(json.dumps({'code': hashlib.sha256(b'code').hexdigest()}))
    for name, key in [('a', 'AAAA'), ('b', 'BBBB')]: (roots / (name + '.pub')).write_text('ssh-ed25519 ' + key + '\n')
    args = SimpleNamespace(**config(), observability=enabled, source=source, roots_dir=roots,
                           state_dir=tmp_path / 'state', accept_changes=True, certificate=None)
    monkeypatch.setattr(deploy.ubuntu, 'check_platform', lambda: None)
    monkeypatch.setattr(deploy.ubuntu, 'provision', lambda *_: None)
    monkeypatch.setattr(deploy, '_new_host_preflight', lambda *_: None)
    monkeypatch.setattr(deploy, 'run', lambda *_, **__: b'')
    seen = []
    def adapter(journal):
        seen.append(copy.deepcopy(journal.document['config']))
        return SimpleNamespace(resume=lambda *_: 20)
    monkeypatch.setattr(deploy, 'installation', adapter)
    assert deploy.start(args) == 20
    with Journal(args.state_dir).locked() as journal:
        assert journal.document['config']['observability'] is enabled
    # Resume's input cannot alter the recorded opt-in.
    args.observability = not enabled
    assert deploy.resume(args) == 20
    assert len(seen) == 2 and seen[0] == seen[1] and seen[0]['observability'] is enabled
