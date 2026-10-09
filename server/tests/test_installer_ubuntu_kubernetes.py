# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Verified client-only Kubernetes dependency provisioning and version fences."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import ubuntu
from iris_installer.state import InstallError


@pytest.mark.parametrize('available,expected', [('kubectl', ('kubectl',)), ('k3s', ('k3s', 'kubectl'))])
def test_existing_client_is_preserved_without_download(monkeypatch, available, expected):
    monkeypatch.setattr(ubuntu.shutil, 'which', lambda command, **kwargs: '/usr/bin/' + command if command == available else None)
    assert ubuntu.provision_kubernetes_client(lambda *_args, **_kwargs: pytest.fail('No mutation for installed client')) == expected


@pytest.mark.parametrize('client,server', [('v1.36.4', 'v1.36.4+k3s1'), ('v1.35.9', 'v1.36.4'), ('v1.37.0', 'v1.36.4')])
def test_official_one_minor_skew_is_supported(client, server):
    ubuntu.validate_kubernetes_versions({'clientVersion': {'gitVersion': client}, 'serverVersion': {'gitVersion': server}})


@pytest.mark.parametrize('report', [{}, None, {'clientVersion': {'gitVersion': 'v1.36.4'}},
    {'clientVersion': None, 'serverVersion': {}}, {'clientVersion': {'gitVersion': 123}},
    {'clientVersion': {'gitVersion': 'v1.34.0'}, 'serverVersion': {'gitVersion': 'v1.36.4'}},
    {'clientVersion': {'gitVersion': 'v2.36.0'}, 'serverVersion': {'gitVersion': 'v1.36.4'}},
    {'clientVersion': {'gitVersion': 'latest'}, 'serverVersion': {'gitVersion': 'v1.36.4'}}])
def test_unestablished_or_unsupported_skew_is_rejected(report):
    with pytest.raises(InstallError):
        ubuntu.validate_kubernetes_versions(report)


def setup_download(tmp_path, monkeypatch):
    monkeypatch.setattr(ubuntu.shutil, 'which', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ubuntu.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(ubuntu, 'check_platform', lambda: None)
    destination = tmp_path / 'kubectl'
    monkeypatch.setattr(ubuntu, 'KUBECTL_DESTINATION', destination)
    original = Path.lstat
    def lstat(path):
        info = original(path)
        # Simulate trusted root-owned ancestors without elevating unit tests.
        if path == tmp_path or path in tmp_path.parents:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        return info
    monkeypatch.setattr(Path, 'lstat', lstat)
    binary = b'fixture verified client'
    monkeypatch.setattr(ubuntu, 'KUBECTL_SHA256', hashlib.sha256(binary).hexdigest())
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[0] == 'curl':
            Path(args[args.index('--output') + 1]).write_bytes(binary)
            return b''
        return json.dumps({'clientVersion': {'gitVersion': ubuntu.KUBECTL_VERSION}}).encode()
    return destination, calls, run


def test_absent_client_is_verified_then_atomically_published(tmp_path, monkeypatch):
    destination, calls, run = setup_download(tmp_path, monkeypatch)
    assert ubuntu.provision_kubernetes_client(run) == ('kubectl',)
    assert destination.read_bytes() == b'fixture verified client'
    assert stat.S_IMODE(destination.stat().st_mode) == 0o755
    assert calls[0][-1] == 'https://dl.k8s.io/release/v1.36.4/bin/linux/amd64/kubectl'
    assert '--proto-redir' in calls[0] and '=https' in calls[0]
    assert not list(tmp_path.glob('.iris-kubectl-*'))


def test_bad_checksum_is_never_executed_or_published(tmp_path, monkeypatch):
    destination, calls, run = setup_download(tmp_path, monkeypatch)
    monkeypatch.setattr(ubuntu, 'KUBECTL_SHA256', '0' * 64)
    with pytest.raises(InstallError, match='checksum'):
        ubuntu.provision_kubernetes_client(run)
    assert len(calls) == 1 and not destination.exists()


def test_existing_nonexecutable_is_not_overwritten(tmp_path, monkeypatch):
    destination, calls, run = setup_download(tmp_path, monkeypatch)
    destination.write_bytes(b'operator-owned')
    with pytest.raises(InstallError, match='not executable'):
        ubuntu.provision_kubernetes_client(run)
    assert destination.read_bytes() == b'operator-owned' and calls == []


def test_publication_race_never_replaces_the_other_executable(tmp_path, monkeypatch):
    destination, calls, run = setup_download(tmp_path, monkeypatch)
    def link(*args, **kwargs):
        destination.write_bytes(b'operator-race')
        raise FileExistsError()
    monkeypatch.setattr(ubuntu.os, 'link', link)
    with pytest.raises(InstallError, match='appeared'):
        ubuntu.provision_kubernetes_client(run)
    assert destination.read_bytes() == b'operator-race'


def test_local_client_is_pinned_then_published_without_download(tmp_path, monkeypatch):
    destination, calls, run = setup_download(tmp_path, monkeypatch)
    source = tmp_path / 'local-client'
    source.write_bytes(b'fixture verified client')
    ubuntu.validate_kubernetes_input(source)
    assert calls == []
    assert ubuntu.provision_kubernetes_client(run, local_source=source) == ('kubectl',)
    assert destination.read_bytes() == source.read_bytes()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o755
    assert len(calls) == 1 and calls[0][1:] == ['version', '--client', '-o', 'json']
    assert not list(tmp_path.glob('.iris-kubectl-*'))


@pytest.mark.parametrize('content', [b'', b'untrusted client'])
def test_bad_local_client_never_executes_or_falls_back_to_download(tmp_path, monkeypatch, content):
    destination, calls, run = setup_download(tmp_path, monkeypatch)
    source = tmp_path / 'local-client'
    source.write_bytes(content)
    with pytest.raises(InstallError):
        ubuntu.validate_kubernetes_input(source)
    with pytest.raises(InstallError):
        ubuntu.provision_kubernetes_client(run, local_source=source)
    assert calls == [] and not destination.exists()
    assert not list(tmp_path.glob('.iris-kubectl-*'))


def test_local_client_symlink_is_not_followed(tmp_path, monkeypatch):
    destination, calls, run = setup_download(tmp_path, monkeypatch)
    source = tmp_path / 'local-client'
    source.write_bytes(b'fixture verified client')
    link = tmp_path / 'linked-client'
    link.symlink_to(source)
    with pytest.raises(InstallError, match='symbolic links'):
        ubuntu.provision_kubernetes_client(run, local_source=link)
    assert calls == [] and not destination.exists()


@pytest.mark.parametrize('available,expected', [('kubectl', ('kubectl',)), ('k3s', ('k3s', 'kubectl'))])
def test_local_input_never_replaces_an_existing_client(monkeypatch, available, expected):
    monkeypatch.setattr(ubuntu.shutil, 'which', lambda command, **kw: '/usr/bin/' + command if command == available else None)
    assert ubuntu.provision_kubernetes_client(
        lambda *a, **kw: pytest.fail('No client mutation'), local_source='/not-needed') == expected
