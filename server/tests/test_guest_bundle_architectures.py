# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Dual-architecture publication prerequisites and actual installer ordering."""
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import deploy, kube_deploy, ubuntu
from iris_installer.state import InstallError


@pytest.mark.parametrize('target', ['docker', 'kubernetes'])
@pytest.mark.parametrize('registration_enabled', [True, False])
def test_actual_source_resume_provisions_and_verifies_arm_before_server_build(tmp_path, monkeypatch, target, registration_enabled):
    registration = Path('/proc/sys/fs/binfmt_misc/qemu-aarch64')
    enabled = registration_enabled
    events = []
    original_exists, original_read = Path.exists, Path.read_text
    monkeypatch.setattr(Path, 'exists', lambda path: True if path == registration else original_exists(path))
    monkeypatch.setattr(Path, 'read_text', lambda path, *a, **k:
        ('enabled\n' if enabled else 'disabled\n') if path == registration else original_read(path, *a, **k))
    monkeypatch.setattr(ubuntu, 'check_platform', lambda: events.append('platform'))
    monkeypatch.setattr(ubuntu, 'command_ok', lambda *_: True)
    monkeypatch.setattr(ubuntu, 'missing_packages', lambda: [] if enabled else ['binfmt-support', 'qemu-user-static'])
    def command(argv, **kwargs):
        nonlocal enabled
        events.append(tuple(map(str, argv)))
        if argv[:2] == ['update-binfmts', '--enable']: enabled = True
        return b''
    selected = SimpleNamespace(base=tmp_path, source=tmp_path / 'source', command=command,
        journal=SimpleNamespace(directory=tmp_path, document={'id': '12345678-1234-4234-8234-123456789abc'}),
        prebuilt=lambda: False, verify_inputs=lambda: events.append('verify-inputs'),
        provision_host=lambda: ubuntu.provision(command),
        verify_resource_ownership=lambda: events.append('ownership'), prepare=lambda: events.append('prepare'),
        bootstrap=lambda: events.append('bootstrap'), signing=lambda *_: True,
        packages=lambda: events.append('packages'), finish=lambda: 'finished')
    def build():
        assert enabled is True
        events.append('build')
    selected.build = build
    monkeypatch.setattr(ubuntu, 'provision_kubernetes_client', lambda *_: events.append('kubernetes-client'))
    cls = kube_deploy.KubeInstall if target == 'kubernetes' else deploy.DockerInstall
    assert cls.resume(selected) == 'finished'
    assert events.index('platform') < events.index('build')
    if not registration_enabled:
        assert events.index(('update-binfmts', '--enable', 'qemu-aarch64')) < events.index('build')


def test_failed_arm_registration_refuses_before_any_build(monkeypatch):
    registration = Path('/proc/sys/fs/binfmt_misc/qemu-aarch64')
    monkeypatch.setattr(ubuntu, 'check_platform', lambda: None)
    monkeypatch.setattr(ubuntu, 'command_ok', lambda *_: True)
    monkeypatch.setattr(ubuntu, 'missing_packages', lambda: [])
    original_exists, original_read = Path.exists, Path.read_text
    monkeypatch.setattr(Path, 'exists', lambda path: True if path == registration else original_exists(path))
    monkeypatch.setattr(Path, 'read_text', lambda path, *a, **k:
        'disabled\n' if path == registration else original_read(path, *a, **k))
    calls = []
    with pytest.raises(InstallError, match='ARM64 emulation registration failed'):
        ubuntu.provision(lambda argv, **kwargs: calls.append(argv))
    assert calls == [['update-binfmts', '--enable', 'qemu-aarch64']]


def test_server_image_bakes_both_pinned_clients_and_helpers_before_runtime_publication():
    root = Path(__file__).resolve().parents[2]
    docker = (root / 'server/Dockerfile').read_text()
    for source in ('ssh-verifier-arm64', 'instruction-crypto-arm64'):
        assert 'FROM --platform=linux/arm64 ' in docker
        assert 'COPY --from=' + source in docker
    for name in ('aria2c-arm64', 'ssh-keygen-arm64', 'iris-aead-arm64'):
        assert '/opt/iris/bin/' + name in docker
    assert 'r.split()[1]=="aarch64"' in docker
    start = (root / 'tools/start-compose-server.sh').read_text()
    assert start.index("grep -q '^enabled$' /proc/sys/fs/binfmt_misc/qemu-aarch64") < start.index('"${COMPOSE[@]}" build')
