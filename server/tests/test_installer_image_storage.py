# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""External image admission and recoverable one-host mount changes."""

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import backup, cli, deploy, image_storage, restore
from iris_installer.state import InstallError, Journal, atomic_write


@pytest.mark.parametrize('path', ['/', '/opt', '/etc/images', '/var/lib/docker/images',
                                 '/opt/../images', '/opt//images', 'images', '/opt/$IMAGE'])
def test_unsafe_external_paths_are_rejected(path):
    with pytest.raises(InstallError):
        image_storage.validate_name(path)


def test_external_storage_never_changes_modes_and_refuses_links_or_state_overlap(tmp_path):
    root = tmp_path / 'library'
    root.mkdir(mode=0o755)
    image = root / 'example.bin'
    image.write_bytes(b'example')
    image.chmod(0o664)
    install = SimpleNamespace(base=tmp_path / 'state', config={'image_root': str(root)})
    assert image_storage.image_root(install) == root
    assert image.stat().st_mode & 0o777 == 0o664
    (root / 'alias').symlink_to(image)
    with pytest.raises(InstallError, match='links'):
        image_storage.image_root(install)
    (root / 'alias').unlink()
    install.config['image_root'] = str(install.base / 'images')
    with pytest.raises(InstallError, match='separate'):
        image_storage.image_root(install)


def test_cli_path_is_explicit_and_kubernetes_rejects_host_imports():
    args = cli.parser().parse_args(['image-root', '--state-dir', '/var/lib/iris-installer/demo',
                                   '--path', '/opt/images', '--allow-downtime'])
    assert args.path == Path('/opt/images') and args.allow_downtime
    with pytest.raises(InstallError, match='Kubernetes uses'):
        deploy.validate_config({'target': 'kubernetes', 'image_root': '/opt/images'})


@pytest.fixture
def change(tmp_path, monkeypatch):
    base, library = tmp_path / 'state', tmp_path / 'library'
    library.mkdir()
    (library / 'image.bin').write_bytes(b'read-only image')
    config = dict(target='docker', instance='test', host='192.0.2.10', console_bind='127.0.0.1',
                  console_port=18080, recovery_recipient='age1' + 'q' * 58, peer_tls='required')
    with Journal(base).locked(create=True) as journal:
        (base / 'images').mkdir()
        compose = {'services': {'iris': {'volumes': [dict(type='bind', source=str(base / 'images'),
                                                       target='/opt/images', read_only=True)]}}}
        atomic_write(base / 'compose.json', json.dumps(compose).encode())
        journal.document = dict(schema=1, id='fixture', config=config,
            completed={'prepared': deploy.digest(base / 'compose.json')})
        journal.save()
    original = (base / 'installation.json').read_bytes(), (base / 'compose.json').read_bytes()
    calls = []
    monkeypatch.setattr(image_storage, 'require_approval', lambda args: None)
    monkeypatch.setattr(image_storage, 'check_readable', lambda adapter, path: None)
    monkeypatch.setattr(backup, 'capture_plan', lambda adapter: calls.append('preflight'))
    monkeypatch.setattr(backup, 'docker_capture_plan', lambda adapter: calls.append('postflight'))
    monkeypatch.setattr(deploy.DockerInstall, 'compose', lambda self, *args, **kwargs: calls.append(args))
    args = SimpleNamespace(state_dir=base, path=library, allow_downtime=True)
    return args, original, calls


def test_change_preserves_uploads_and_records_the_exact_mount(change):
    args, original, calls = change
    assert image_storage.change(args) == 0
    document = json.loads((args.state_dir / 'installation.json').read_bytes())
    compose = json.loads((args.state_dir / 'compose.json').read_bytes())
    assert document['config']['image_root'] == str(args.path)
    assert document['completed']['prepared'] == deploy.digest(args.state_dir / 'compose.json')
    assert compose['services']['iris']['volumes'] == [dict(type='bind', source=str(args.path), target='/opt/images', read_only=True)]
    assert calls[-1] == 'postflight'
    assert not (args.state_dir / 'image-root-change.json').exists()


def test_nonempty_previous_folder_is_never_hidden(change):
    args, original, calls = change
    (args.state_dir / 'images/current.bin').write_bytes(b'keep me')
    with pytest.raises(InstallError, match='must be empty'):
        image_storage.change(args)
    assert (args.state_dir / 'compose.json').read_bytes() == original[1]
    assert calls == ['preflight']


def test_failed_restart_rolls_back_config_and_mount(change, monkeypatch):
    args, original, calls = change
    count = [0]
    def compose(self, *argv, **kwargs):
        if argv[0] == 'up':
            count[0] += 1
            if count[0] == 1:
                raise InstallError('fixture health failure')
    monkeypatch.setattr(deploy.DockerInstall, 'compose', compose)
    with pytest.raises(InstallError, match='fixture health'):
        image_storage.change(args)
    assert (args.state_dir / 'installation.json').read_bytes() == original[0]
    assert (args.state_dir / 'compose.json').read_bytes() == original[1]
    assert not (args.state_dir / 'image-root-change.json').exists()


def test_pending_image_change_blocks_backups_and_restore(tmp_path):
    atomic_write(tmp_path / 'image-root-change.json', b'{}')
    with pytest.raises(InstallError, match='Image-folder change'):
        restore.guard(tmp_path)


def test_failed_rollback_is_recovered_by_rerunning_same_command(change, monkeypatch):
    args, original, calls = change
    count = [0]
    def compose(self, *argv, **kwargs):
        if argv[0] == 'up':
            count[0] += 1
            if count[0] <= 2:
                raise InstallError('fixture restart and rollback unavailable')
    monkeypatch.setattr(deploy.DockerInstall, 'compose', compose)
    with pytest.raises(InstallError):
        image_storage.change(args)
    assert (args.state_dir / 'image-root-change.json').is_file()
    assert image_storage.change(args) == 0
    assert not (args.state_dir / 'image-root-change.json').exists()
    assert json.loads((args.state_dir / 'installation.json').read_bytes())['config']['image_root'] == str(args.path)


def test_downtime_requires_explicit_approval(monkeypatch):
    monkeypatch.setattr(image_storage.os, 'geteuid', lambda: 0)
    with pytest.raises(InstallError, match='allow-downtime'):
        image_storage.require_approval(SimpleNamespace(allow_downtime=False))


def test_readability_probe_is_isolated_and_uses_pinned_image(tmp_path):
    compose = tmp_path / 'compose.json'
    compose.write_text(json.dumps({'services': {'iris': {'image': 'server-tag'}}}))
    calls = []
    adapter = SimpleNamespace(compose_file=compose,
        journal=SimpleNamespace(document={'completed': {'images': {'server-tag': 'sha256:pinned'}}}),
        command=lambda argv, **kwargs: calls.append((argv, kwargs)))
    image_storage.check_readable(adapter, Path('/opt/images'))
    argv, options = calls[0]
    assert argv[argv.index('--network') + 1] == 'none'
    assert argv[argv.index('--user') + 1] == '10001:10001'
    assert '--read-only' in argv and 'sha256:pinned' in argv
    assert argv[argv.index('--mount') + 1].endswith(',readonly')
    compile(argv[-1], '<read-only probe>', 'exec')
    def denied(*args, **kwargs):
        raise InstallError('runtime probe failed')
    adapter.command = denied
    with pytest.raises(InstallError, match='no permissions were changed'):
        image_storage.check_readable(adapter, Path('/opt/images'))
