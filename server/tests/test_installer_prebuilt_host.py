# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Prepared-host checks never acquire dependencies or substitute source builds."""

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import ubuntu
from iris_installer.state import InstallError


@pytest.fixture
def prepared(monkeypatch):
    calls, looked_up = [], []
    monkeypatch.setattr(ubuntu, 'check_platform', lambda: None)

    def which(name, *, path):
        assert path == ubuntu.SYSTEM_PATH
        looked_up.append(name)
        return '/usr/bin/' + name

    def command_ok(command):
        calls.append(command)
        return True

    monkeypatch.setattr(ubuntu.shutil, 'which', which)
    monkeypatch.setattr(ubuntu, 'command_ok', command_ok)
    return calls, looked_up


@pytest.mark.parametrize('target', ['docker', 'docker-split', 'kubernetes'])
def test_prebuilt_preflight_only_checks_local_dependencies(prepared, target):
    calls, looked_up = prepared
    report = ubuntu.preflight_prebuilt(target)
    assert report['profile'] == 'prepared-host'
    assert report['target'] == target
    assert calls == [['/usr/bin/docker', 'info'], ['/usr/bin/docker', 'compose', 'version']]
    assert not {'curl', 'git', 'qemu-aarch64', 'buildx'} & set(looked_up)
    assert ('ssh' in looked_up) == (target == 'docker-split')
    assert ('ip' in looked_up) == (target == 'kubernetes')
    assert report['kubernetes_client'] == (['/usr/bin/kubectl'] if target == 'kubernetes' else None)


@pytest.mark.parametrize('missing', ['age', 'age-keygen', 'skopeo', 'rpmbuild', 'docker', 'systemctl'])
def test_missing_tool_fails_before_any_command(prepared, monkeypatch, missing):
    original = ubuntu.shutil.which
    monkeypatch.setattr(ubuntu.shutil, 'which',
                        lambda name, **kwargs: None if name == missing else original(name, **kwargs))
    with pytest.raises(InstallError, match='missing: ' + missing):
        ubuntu.preflight_prebuilt('docker')
    assert prepared[0] == []


@pytest.mark.parametrize('failed', ['info', 'compose'])
def test_no_provisioning_when_docker_or_compose_is_unavailable(prepared, monkeypatch, failed):
    calls = []

    def command_ok(command):
        calls.append(command)
        return failed not in command

    monkeypatch.setattr(ubuntu, 'command_ok', command_ok)
    with pytest.raises(InstallError, match='unavailable; no dependencies were installed'):
        ubuntu.preflight_prebuilt('docker')
    assert all(command[1] in ('info', 'compose') for command in calls)
    assert len(calls) == (1 if failed == 'info' else 2)


def test_local_k3s_client_is_preserved_without_download(prepared, monkeypatch):
    original = ubuntu.shutil.which
    monkeypatch.setattr(ubuntu.shutil, 'which',
                        lambda name, **kwargs: None if name == 'kubectl' else original(name, **kwargs))
    assert ubuntu.preflight_prebuilt('kubernetes')['kubernetes_client'] == ['/usr/bin/k3s', 'kubectl']


def test_missing_kubernetes_client_stops_before_commands(prepared, monkeypatch):
    original = ubuntu.shutil.which
    monkeypatch.setattr(ubuntu.shutil, 'which',
                        lambda name, **kwargs: None if name in ('kubectl', 'k3s') else original(name, **kwargs))
    with pytest.raises(InstallError, match='kubectl or k3s'):
        ubuntu.preflight_prebuilt('kubernetes')
    assert prepared[0] == []


@pytest.mark.parametrize('target', ['', 'auto', None])
def test_unknown_target_fails_before_platform_or_tool_access(monkeypatch, target):
    monkeypatch.setattr(ubuntu, 'check_platform', lambda: pytest.fail('No platform access'))
    with pytest.raises(InstallError, match='Unknown prebuilt'):
        ubuntu.preflight_prebuilt(target)
