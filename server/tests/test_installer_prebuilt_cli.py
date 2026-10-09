# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Public selection contract and startup ordering; no real host mutations."""

import json
import os
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import cli, device_context, guest_inputs, local_setup, prebuilt_install, release_kit
from iris_installer.state import InstallError
from test_installer_initialization import setup


OPTIONS = ['--release-kit', '/release', '--release-tag', 'v2026.10.09',
           '--release-commit', 'a' * 40, '--release-verifier', '/usr/bin/gh',
           '--release-trusted-root', '/etc/iris/trusted-root.json', '--offline',
           '--ioxclient', '/licensed/ioxclient']


@pytest.mark.parametrize('command', ['install', 'setup'])
def test_public_prebuilt_options_survive_interactive_helper_forwarding(command):
    args = cli.parser().parse_args([command, *OPTIONS])
    forwarded = cli.parser().parse_args(local_setup.install_arguments(args))
    for name in ('release_kit', 'release_tag', 'release_commit', 'release_verifier',
                 'release_trusted_root', 'offline', 'ioxclient', 'kubectl'):
        assert getattr(forwarded, name) == getattr(args, name)


def test_source_selection_has_no_kit_or_offline_fallback(tmp_path):
    args = cli.parser().parse_args(['install'])
    assert prebuilt_install.prepare_selection(args, {}, tmp_path) == {
        'input_selection': release_kit.selection()}
    for name in ('release_tag', 'release_commit', 'release_verifier',
                 'release_trusted_root', 'offline', 'ioxclient', 'kubectl'):
        changed = SimpleNamespace(**vars(args))
        setattr(changed, name, True)
        with pytest.raises(InstallError, match='require --release-kit'):
            prebuilt_install.prepare_selection(changed, {}, tmp_path)


@pytest.mark.parametrize('option', ['--release-tag', '--release-commit'])
def test_empty_prebuilt_only_option_never_selects_source_builds(tmp_path, option):
    args = cli.parser().parse_args(['install', option, ''])
    with pytest.raises(InstallError, match='require --release-kit'):
        prebuilt_install.prepare_selection(args, {}, tmp_path)


@pytest.mark.parametrize('missing', ['release_tag', 'release_commit', 'ioxclient'])
def test_identity_and_tool_required_before_authentication(tmp_path, monkeypatch, missing):
    args = cli.parser().parse_args(['install', *OPTIONS])
    setattr(args, missing, None)
    monkeypatch.setattr(release_kit, 'verify_kit', lambda *a, **kw: pytest.fail('Incomplete selection'))
    with pytest.raises(InstallError, match='requires --release-tag'):
        prebuilt_install.prepare_selection(args, {}, tmp_path)


@pytest.fixture
def kit(tmp_path):
    return release_kit.VerifiedKit(tmp_path, 'v2026.10.09', 'a' * 40,
                                  'b' * 64, 'c' * 64, 'd' * 64, 'e' * 64, True, ())


def test_authentication_failure_never_reads_packaging_inputs(tmp_path, monkeypatch):
    args = cli.parser().parse_args(['install', *OPTIONS])
    def refuse(*args, **kwargs):
        raise InstallError('unauthenticated release')
    monkeypatch.setattr(release_kit, 'verify_kit', refuse)
    monkeypatch.setattr(prebuilt_install, 'bind_source', lambda *a: pytest.fail('Authenticate first'))
    with pytest.raises(InstallError, match='unauthenticated'):
        prebuilt_install.prepare_selection(args, {}, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_selection_binds_source_and_pinned_tool_before_returning_journal_fields(tmp_path, monkeypatch, kit):
    from iris_installer import packaging_inputs
    args = cli.parser().parse_args(['install', *OPTIONS])
    events = []
    def verify(path, **kwargs):
        assert path == '/release'
        assert kwargs == dict(tag='v2026.10.09', commit='a' * 40, verifier='/usr/bin/gh',
                              trusted_root='/etc/iris/trusted-root.json', offline=True)
        events.append('authenticate')
        return kit
    monkeypatch.setattr(release_kit, 'verify_kit', verify)
    monkeypatch.setattr(prebuilt_install, 'bind_source', lambda *a: events.append('source'))
    def guest(value, source, manifest):
        assert value is kit and source == args.source and manifest == {'source': '0' * 64}
        events.append('guest')
    monkeypatch.setattr(guest_inputs, 'verify_guest_inputs', guest)
    monkeypatch.setattr(packaging_inputs, 'prepare_packaging_inputs',
                        lambda value, path: events.append('packaging') or SimpleNamespace(ioxclient_sha256='f' * 64))
    def tool(path, output, **kwargs):
        assert path == Path('/licensed/ioxclient') and kwargs == {'expected_sha256': 'f' * 64}
        assert output.parent.stat().st_mode & 0o777 == 0o700
        events.append('licensed-tool')
    monkeypatch.setattr(device_context, 'prepare_ioxclient', tool)
    selected = prebuilt_install.prepare_selection(args, {'source': '0' * 64}, tmp_path)
    assert events == ['authenticate', 'source', 'guest', 'packaging', 'licensed-tool']
    assert selected['input_selection'] == release_kit.selection('prebuilt', kit=kit, offline=True)
    assert selected['prebuilt_ioxclient'] == '/licensed/ioxclient'
    assert selected['release_kit'] == {'directory': '/release', 'verifier': '/usr/bin/gh',
                                       'trusted_root': '/etc/iris/trusted-root.json'}
    assert list(tmp_path.iterdir()) == []


def test_guest_input_failure_stops_before_licensed_tool_access(tmp_path, monkeypatch, kit):
    args = cli.parser().parse_args(['install', *OPTIONS])
    monkeypatch.setattr(release_kit, 'verify_kit', lambda *a, **kw: kit)
    monkeypatch.setattr(prebuilt_install, 'bind_source', lambda *a: None)
    def refuse(*args):
        raise InstallError('Guest inputs do not match')
    monkeypatch.setattr(guest_inputs, 'verify_guest_inputs', refuse)
    monkeypatch.setattr(prebuilt_install, 'validate_packaging_tool',
                        lambda *a: pytest.fail('Guest references must match first'))
    with pytest.raises(InstallError, match='Guest inputs'):
        prebuilt_install.prepare_selection(args, {}, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_local_kubernetes_input_is_checked_before_selection_is_recorded(tmp_path, monkeypatch, kit):
    from iris_installer import ubuntu
    args = cli.parser().parse_args(['install', *OPTIONS, '--target', 'kubernetes', '--kubectl', '/local/kubectl'])
    events = []
    monkeypatch.setattr(release_kit, 'verify_kit', lambda *a, **kw: kit)
    monkeypatch.setattr(prebuilt_install, 'bind_source', lambda *a: events.append('source'))
    monkeypatch.setattr(guest_inputs, 'verify_guest_inputs', lambda *a: events.append('guest'))
    monkeypatch.setattr(prebuilt_install, 'validate_packaging_tool', lambda *a: events.append('packaging'))
    monkeypatch.setattr(ubuntu, 'validate_kubernetes_input', lambda path: events.append(str(path)))
    result = prebuilt_install.prepare_selection(args, {}, tmp_path)
    assert result['prebuilt_kubectl'] == '/local/kubectl'
    assert events == ['source', 'guest', 'packaging', '/local/kubectl']
    forwarded = cli.parser().parse_args(local_setup.install_arguments(args))
    assert forwarded.kubectl == args.kubectl


def test_local_kubernetes_input_requires_kubernetes_target(tmp_path, monkeypatch):
    args = cli.parser().parse_args(['install', *OPTIONS, '--kubectl', '/local/kubectl'])
    monkeypatch.setattr(release_kit, 'verify_kit', lambda *a, **kw: pytest.fail('Invalid target'))
    with pytest.raises(InstallError, match='Kubernetes target'):
        prebuilt_install.prepare_selection(args, {}, tmp_path)


@pytest.mark.skipif(os.geteuid() != 0, reason='real installer journal ownership requires root')
def test_prebuilt_start_authenticates_before_host_checks_and_records_selection(setup, monkeypatch, kit):
    from iris_installer import deploy
    args, deployments = setup
    events = []
    selection = {'input_selection': release_kit.selection('prebuilt', kit=kit, offline=True),
                 'release_kit': {'directory': '/release', 'verifier': '/usr/bin/gh', 'trusted_root': '/trusted'},
                 'prebuilt_ioxclient': '/licensed/ioxclient'}
    monkeypatch.setattr(prebuilt_install, 'prepare_selection', lambda *a: events.append('authenticate') or selection)
    monkeypatch.setattr(deploy.ubuntu, 'preflight_prebuilt', lambda target: events.append(target))
    monkeypatch.setattr(deploy.ubuntu, 'provision', lambda *a: pytest.fail('No apt or source build fallback'))
    assert deploy.start(args) == 20
    assert events == ['authenticate', 'docker']
    for name, value in selection.items():
        assert deployments[0][name] == value


@pytest.mark.skipif(os.geteuid() != 0, reason='real installer journal ownership requires root')
def test_rejected_prebuilt_inputs_stop_before_host_changes_or_snapshot(setup, monkeypatch):
    from iris_installer import deploy
    args, deployments = setup
    def refuse(*a):
        raise InstallError('untrusted prebuilt input')
    monkeypatch.setattr(prebuilt_install, 'prepare_selection', refuse)
    monkeypatch.setattr(deploy.ubuntu, 'provision', lambda *a: pytest.fail('No dependency mutation'))
    monkeypatch.setattr(deploy.ubuntu, 'preflight_prebuilt', lambda *a: pytest.fail('Authenticate first'))
    with pytest.raises(InstallError, match='untrusted'):
        deploy.start(args)
    assert deployments == []
    assert {path.name for path in args.state_dir.iterdir()} == {'lock'}


@pytest.mark.skipif(os.geteuid() != 0, reason='real installer journal ownership requires root')
def test_initialization_resume_reauthenticates_before_copying_reserved_inputs(setup, monkeypatch):
    from iris_installer import deploy
    args, deployments = setup
    original = deploy.complete_initialization
    def interrupt(journal):
        raise InstallError('interrupted initialization')
    monkeypatch.setattr(deploy, 'complete_initialization', interrupt)
    with pytest.raises(InstallError, match='interrupted'):
        deploy.start(args)
    record = json.loads((args.state_dir / 'installation.json').read_bytes())
    assert record['state'] == 'INITIALIZING'
    events = []
    monkeypatch.setattr(prebuilt_install, 'verify_selected', lambda journal: events.append('authenticate') or object())
    monkeypatch.setattr(prebuilt_install, 'bind_source', lambda *a: events.append('source'))
    def complete(journal):
        assert events == ['authenticate', 'source']
        return original(journal)
    monkeypatch.setattr(deploy, 'complete_initialization', complete)
    assert deploy.resume(args) == 20


@pytest.fixture
def recorded_prebuilt(kit):
    return {'input_selection': release_kit.selection('prebuilt', kit=kit, offline=True),
            'release_kit': {'directory': '/release', 'verifier': '/usr/bin/gh',
                            'trusted_root': '/etc/iris/trusted-root.json'},
            'prebuilt_ioxclient': '/licensed/ioxclient'}


def test_setup_status_exposes_only_validated_public_selection(tmp_path, monkeypatch, recorded_prebuilt):
    document = {**deepcopy(recorded_prebuilt), 'id': 'example', 'state': 'INITIALIZED',
                'completed': {'never-export': 'PRIVATE'},
                'config': {'target': 'docker', 'instance': 'iris', 'host': '192.0.2.10',
                           'console_bind': '127.0.0.1', 'console_port': 8080,
                           'peer_tls': 'required', 'recovery_recipient': 'age1' + 'q' * 58}}
    journal = SimpleNamespace(directory=tmp_path, document=document, locked=nullcontext)
    monkeypatch.setattr(local_setup, 'Journal', lambda path: journal)
    monkeypatch.setattr(local_setup.os, 'geteuid', lambda: 0)
    result = local_setup.public_status(tmp_path)
    assert set(result) == {'present', 'id', 'state', 'config', *recorded_prebuilt}
    assert {name: result[name] for name in recorded_prebuilt} == recorded_prebuilt
    assert 'PRIVATE' not in json.dumps(result)
    assert 'recovery_recipient' not in result['config']
    result['input_selection']['kit']['commit'] = 'f' * 40
    result['release_kit']['directory'] = '/different'
    assert document['input_selection'] == recorded_prebuilt['input_selection']
    assert document['release_kit'] == recorded_prebuilt['release_kit']


@pytest.mark.parametrize('field,value', [
    ('input_selection', None), ('input_selection', {'mode': 'source'}),
    ('release_kit', {'directory': '/release', 'verifier': '/usr/bin/gh',
                     'trusted_root': None, 'private': 'never-export'}),
    ('prebuilt_ioxclient', 'relative'), ('prebuilt_ioxclient', '/path\nPRIVATE'),
])
def test_public_selection_rejects_malformed_fields(recorded_prebuilt, field, value):
    recorded_prebuilt[field] = value
    with pytest.raises(InstallError):
        prebuilt_install.public_selection(recorded_prebuilt)


@pytest.mark.parametrize('field', ['directory', 'verifier', 'trusted_root'])
@pytest.mark.parametrize('value', ['relative', '/path\x00hidden', '/' + 'x' * 4096, 1])
def test_public_selection_requires_bounded_absolute_locations(recorded_prebuilt, field, value):
    recorded_prebuilt['release_kit'][field] = value
    with pytest.raises(InstallError, match='location or verifier'):
        prebuilt_install.public_selection(recorded_prebuilt)


@pytest.mark.parametrize('options', [[], OPTIONS, ['--offline'], ['--release-tag', 'v2026.10.09']])
def test_setup_resume_accepts_matching_or_omitted_constraints(recorded_prebuilt, options):
    args = cli.parser().parse_args(['setup', *options])
    prebuilt_install.assert_setup_selection(args, recorded_prebuilt)


@pytest.mark.parametrize('option,value', [
    ('--release-kit', '/different'), ('--release-tag', 'v2026.10.10'),
    ('--release-tag', ''), ('--release-commit', 'f' * 40), ('--release-commit', ''),
    ('--release-verifier', '/other/gh'), ('--release-trusted-root', '/other/root'),
    ('--ioxclient', '/other/ioxclient'),
])
def test_setup_resume_rejects_changed_explicit_constraints(recorded_prebuilt, option, value):
    args = cli.parser().parse_args(['setup', option, value])
    with pytest.raises(InstallError, match=option + ' differs'):
        prebuilt_install.assert_setup_selection(args, recorded_prebuilt)


def test_setup_resume_refuses_new_offline_constraint_for_recorded_online_kit(recorded_prebuilt):
    recorded_prebuilt['input_selection']['kit']['offline'] = False
    args = cli.parser().parse_args(['setup', '--offline'])
    with pytest.raises(InstallError, match='--offline differs'):
        prebuilt_install.assert_setup_selection(args, recorded_prebuilt)
    prebuilt_install.assert_setup_selection(cli.parser().parse_args(['setup']), recorded_prebuilt)


def test_setup_resume_preserves_optional_recorded_kubernetes_client(recorded_prebuilt):
    recorded_prebuilt['prebuilt_kubectl'] = '/local/kubectl'
    assert prebuilt_install.public_selection(recorded_prebuilt)['prebuilt_kubectl'] == '/local/kubectl'
    for options in ([], ['--kubectl', '/local/kubectl']):
        prebuilt_install.assert_setup_selection(cli.parser().parse_args(['setup', *options]), recorded_prebuilt)
    with pytest.raises(InstallError, match='--kubectl differs'):
        prebuilt_install.assert_setup_selection(cli.parser().parse_args(['setup', '--kubectl', '/different']), recorded_prebuilt)
    recorded_prebuilt['prebuilt_kubectl'] = None
    with pytest.raises(InstallError, match='Kubernetes client location'):
        prebuilt_install.public_selection(recorded_prebuilt)


@pytest.mark.parametrize('options', [['--offline'], ['--release-kit', '/release'],
                                    ['--release-tag', ''], ['--release-commit', ''],
                                    ['--release-verifier', '/usr/bin/gh'],
                                    ['--release-trusted-root', '/trusted'],
                                    ['--ioxclient', '/licensed/ioxclient']])
@pytest.mark.parametrize('recorded', [{}, {'input_selection': release_kit.selection()}])
def test_setup_resume_source_cannot_ignore_prebuilt_or_offline_options(recorded, options):
    with pytest.raises(InstallError, match='uses source builds'):
        prebuilt_install.assert_setup_selection(cli.parser().parse_args(['setup', *options]), recorded)


@pytest.mark.parametrize('prebuilt', [False, True])
def test_interactive_resume_checks_constraints_before_privileged_resume(
        tmp_path, monkeypatch, recorded_prebuilt, prebuilt):
    args = cli.parser().parse_args(['setup', '--state-dir', str(tmp_path / 'state'), *OPTIONS])
    status = {'present': True, 'id': 'same-id', 'config': {
        'instance': 'recorded', 'console_bind': '127.0.0.1', 'console_port': 8080}}
    if prebuilt:
        status.update(recorded_prebuilt)
    calls = []
    def controller(command, capture=False):
        calls.append(command)
        return status if capture else 0
    monkeypatch.setattr(local_setup.os, 'geteuid', lambda: 1000)
    monkeypatch.setattr(local_setup.sys, 'stdin', SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(local_setup, 'confirm', lambda question: True)
    monkeypatch.setattr(local_setup, 'controller', controller)
    monkeypatch.setattr(local_setup, 'prepare_keys', lambda *a: pytest.fail('No new keys'))
    if prebuilt:
        assert local_setup.run_setup(args) == 0
        assert [call[0] for call in calls] == ['setup-status', 'resume', 'setup-status']
    else:
        with pytest.raises(InstallError, match='uses source builds'):
            local_setup.run_setup(args)
        assert [call[0] for call in calls] == ['setup-status']
