# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real temporary-workspace cleanup with simulated service/archive boundaries."""
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import backup
from iris_installer.state import InstallError


@pytest.fixture
def capture(tmp_path, monkeypatch):
    state, data, recovery = [tmp_path / name for name in ('state', 'data', 'recovery')]
    for path in (state, data, recovery):
        path.mkdir()
    mirror = state / 'owned-snapshot'
    unrelated = state / 'unrelated'
    unrelated.write_bytes(b'preserve')
    events = []
    control = {'fail': None}

    def event(name):
        events.append(name)
        if control['fail'] == name:
            raise InstallError('injected ' + name)

    document = {'id': 'ee8a615c-87a3-492b-9b8a-e0fe8853e722',
                'config': {'recovery_recipient': 'synthetic'},
                'completed': {'images': {'server': 'sha256:' + 'a' * 64}}}
    journal = SimpleNamespace(document=document, directory=state)

    @contextmanager
    def locked():
        yield journal

    def plan(_install, *, cleanup_on_failure):
        assert cleanup_on_failure is True
        mirror.mkdir()
        (mirror / 'manifest').write_bytes(b'synthetic topology snapshot')
        return {'kubernetes-resources': mirror / 'manifest'}, {}, [
            {'service': 'console', 'running': True}, {'service': 'iris', 'running': True}]

    def clean(sources):
        event('cleanup')
        assert sources['kubernetes-resources'] == mirror / 'manifest'
        shutil.rmtree(mirror)

    def export(path):
        event('export')
        path.write_bytes(b'synthetic image archive')

    def archive(_sources, destination, *_args, **_kwargs):
        event('recovery-archive' if destination.parent == recovery else 'data-archive')
        destination.mkdir()
        (destination / 'captured').write_bytes(b'synthetic encrypted archive')

    install = SimpleNamespace(base=state, journal=journal, config={'target': 'kubernetes'},
        backup_export_images=export, cleanup_snapshot_sources=clean,
        capture_backup_extras=lambda _sources: event('snapshot'))
    monkeypatch.setattr(backup.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(backup, 'Journal', lambda _state: SimpleNamespace(locked=locked))
    monkeypatch.setattr(backup, '_installation', lambda _journal: install)
    monkeypatch.setattr(backup, 'capture_plan', plan)
    monkeypatch.setattr(backup, 'capacity_preflight', lambda *_args: event('capacity'))
    monkeypatch.setattr(backup, 'initialize', lambda *_args: (event('signer'), state / 'signer')[1])
    monkeypatch.setattr(backup, 'stop_writers', lambda *_args: event('stop'))
    monkeypatch.setattr(backup, 'restart_writer', lambda *_args: event('restart'))
    monkeypatch.setattr(backup.backup_archive, 'private_directory', lambda path: path)
    monkeypatch.setattr(backup.backup_archive, 'create', archive)
    args = SimpleNamespace(state_dir=state, output=data / 'set',
                           recovery_output=recovery / 'set', allow_downtime=True)
    return SimpleNamespace(args=args, state=state, mirror=mirror, unrelated=unrelated,
                           events=events, control=control, install=install)


@pytest.mark.parametrize('failure', [None, 'capacity', 'signer', 'export', 'stop',
    'snapshot', 'recovery-archive', 'data-archive', 'restart'])
def test_capture_always_releases_exact_temporary_mirror(capture, failure):
    capture.control['fail'] = failure
    if failure:
        with pytest.raises(InstallError):
            backup.create(capture.args)
    else:
        assert backup.create(capture.args) == 0
    assert capture.events.count('cleanup') == 1
    assert not capture.mirror.exists()
    assert capture.unrelated.read_bytes() == b'preserve'
    operation = capture.state / 'backup-operation.json'
    if failure in ('capacity', 'signer', 'export'):
        assert 'stop' not in capture.events and 'restart' not in capture.events
        assert not operation.exists()
    else:
        assert capture.events.count('restart') == 2
        status = json.loads(operation.read_bytes())
        assert status['state'] == ('captured' if failure in (None, 'restart') else 'failed')
        assert status['restart_required'] == (['iris', 'console'] if failure == 'restart' else [])
    if failure in (None, 'restart'):
        assert (capture.args.output / 'captured').exists()
        assert (capture.args.recovery_output / 'captured').exists()
    elif failure == 'data-archive':
        assert (capture.args.recovery_output / 'captured').exists()


def test_cleanup_failure_is_not_reported_as_success(capture, capsys):
    capture.control['fail'] = 'cleanup'
    with pytest.raises(InstallError, match='cleanup'):
        backup.create(capture.args)
    assert capture.mirror.exists()
    assert capture.events.count('cleanup') == 1
    assert json.loads((capture.state / 'backup-operation.json').read_bytes())['state'] == 'captured'
    assert 'Captured encrypted' not in capsys.readouterr().out


def test_plain_docker_without_snapshot_hook_remains_supported(capture):
    del capture.install.cleanup_snapshot_sources
    assert backup.create(capture.args) == 0
    assert 'cleanup' not in capture.events


@pytest.mark.parametrize('failure', ['cache-refused', 'component-collision'])
@pytest.mark.parametrize('standalone_capture', [True, False])
def test_cache_validation_failure_cleans_only_standalone_capture(tmp_path, monkeypatch,
                                                                failure, standalone_capture):
    from iris_installer import prebuilt_backup
    mirror = tmp_path / 'owned-snapshot'
    sources = {'kubernetes-resources': mirror / 'manifest'}
    cleanup_calls = []

    def topology():
        mirror.mkdir()
        (mirror / 'manifest').write_bytes(b'synthetic topology')
        return sources, {}, []

    def cleanup(actual):
        assert actual == sources
        cleanup_calls.append(True)
        shutil.rmtree(mirror)

    def caches(*_args, **_kwargs):
        if failure == 'cache-refused':
            raise InstallError('cache refused')
        return dict(sources)

    monkeypatch.setattr(prebuilt_backup, 'capture_sources', caches)
    install = SimpleNamespace(base=tmp_path, capture_plan=topology,
                              journal=SimpleNamespace(document={'id': 'ac9e6839-49db-4a0d-8a5d-d4f9465b7ab2'}),
                              cleanup_snapshot_sources=cleanup)
    with pytest.raises(InstallError):
        backup.capture_plan(install, cleanup_on_failure=standalone_capture)
    assert cleanup_calls == ([True] if standalone_capture else [])
    assert mirror.exists() is not standalone_capture
