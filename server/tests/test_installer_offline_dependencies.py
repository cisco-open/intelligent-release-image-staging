# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Actual signed local apt metadata, resolver checks, and mutation refusal."""

from datetime import datetime, timezone
from email.utils import format_datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import offline_dependencies as dependencies
from iris_installer.state import InstallError


def command(arguments):
    return subprocess.run(arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def inventory(directory, manifest):
    manifest['files'] = {path.relative_to(directory).as_posix(): {
        'sha256': dependencies._digest(path), 'size': path.stat().st_size}
        for path in directory.rglob('*') if path.is_file() and path.name != dependencies.MANIFEST}
    path = directory / dependencies.MANIFEST
    path.write_text(json.dumps(manifest, sort_keys=True))
    return dependencies._digest(path)


@pytest.fixture(scope='module')
def signed_repository(tmp_path_factory):
    if any(shutil.which(tool) is None for tool in ('apt-get', 'dpkg-deb', 'gpg', 'gpgv')):
        pytest.skip('Local apt and GnuPG tools are required')
    base = tmp_path_factory.mktemp('offline-dependency-fixture')
    home = base / 'gnupg'
    home.mkdir(mode=0o700)
    command(['gpg', '--homedir', str(home), '--batch', '--passphrase', '', '--quick-generate-key',
             'IRIS isolated dependency test', 'ed25519', 'sign', '0'])
    keyring = base / 'independent-test-keyring.gpg'
    keyring.write_bytes(command(['gpg', '--homedir', str(home), '--export']))
    keyring.chmod(0o600)
    directory = base / 'payload'
    directory.mkdir(mode=0o700)
    packages, entries = [], []
    for name in sorted({*dependencies.ROOT_PACKAGES, 'iris-test-transitive'}):
        package = base / ('build-' + name)
        (package / 'DEBIAN').mkdir(parents=True)
        version = '3.12.1' if name == 'python3' else '1.0'
        control = f'Package: {name}\nVersion: {version}\nArchitecture: amd64\nMaintainer: IRIS test\nDescription: dependency closure test fixture\n'
        if name == 'rpm':
            control += 'Depends: iris-test-transitive (= 1.0)\n'
        (package / 'DEBIAN/control').write_text(control)
        filename = f'pool/main/{name}_{version}_amd64.deb'
        target = directory / 'repositories/archive' / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        command(['dpkg-deb', '--root-owner-group', '--build', str(package), str(target)])
        entries.append(control + f'Filename: {filename}\nSize: {target.stat().st_size}\nSHA256: {dependencies._digest(target)}\n')
        packages.append({'name': name, 'version': version, 'architecture': 'amd64', 'repository': 'archive',
                         'suite': 'noble', 'component': 'main', 'filename': filename})
    for repository, suite, _ in dependencies.REPOSITORIES:
        release = directory / 'repositories' / repository / 'dists' / suite
        hashes = []
        for component in dependencies.COMPONENTS:
            relative = component + '/binary-amd64/Packages'
            target = release / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('\n'.join(entries) if suite == 'noble' and component == 'main' else
                              'Package: unused-metadata-fixture\nVersion: 1.0\nArchitecture: amd64\nDescription: unused test entry\n\n')
            hashes.append(' ' + dependencies._digest(target) + ' ' + str(target.stat().st_size) + ' ' + relative)
        unsigned = base / (suite + '-Release')
        unsigned.write_text(f'Origin: Ubuntu\nLabel: Ubuntu\nSuite: {suite}\nCodename: noble\nArchitectures: amd64\nComponents: main universe\nDate: '
                            + format_datetime(datetime.now(timezone.utc)) + '\nSHA256:\n' + '\n'.join(hashes) + '\n')
        command(['gpg', '--homedir', str(home), '--batch', '--yes', '--output', str(release / 'InRelease'), '--clearsign', str(unsigned)])
    manifest = {'schema': dependencies.SCHEMA, 'host': {'os': 'ubuntu', 'version': '24.04', 'architecture': 'amd64'},
                'docker_provider': 'docker.io', 'roots': {p['name']: p['version'] for p in packages if p['name'] in dependencies.ROOT_PACKAGES},
                'packages': packages, 'files': {}}
    digest = inventory(directory, manifest)
    return directory, keyring, digest


@pytest.fixture
def payload(signed_repository, tmp_path):
    source, keyring, digest = signed_repository
    directory = tmp_path / 'payload'
    shutil.copytree(source, directory)
    return directory, keyring, digest


def test_real_signed_local_repository_proves_transitive_closure(signed_repository):
    directory, keyring, digest = signed_repository
    with dependencies.validate_closure(directory, digest, keyring=keyring) as closure:
        assert set(closure.packages) == {*dependencies.ROOT_PACKAGES, 'iris-test-transitive'}
        assert closure.directory != directory
        assert set(path.name for path in (closure.config.parent / 'methods').iterdir()) == {'copy', 'file', 'gpgv', 'store'}
        configuration = dependencies._run(['/usr/bin/apt-config', 'dump'], config=closure.config)
        assert 'Post-Invoke' not in configuration and 'Pre-Invoke' not in configuration
        assert 'AllowUnauthenticated "false"' in configuration
        private = closure.directory
    assert not private.exists()


def test_complete_closure_before_readonly_host_plan(signed_repository, tmp_path, monkeypatch):
    directory, keyring, digest = signed_repository
    status = tmp_path / 'empty-status'
    status.write_text('')
    monkeypatch.setattr(dependencies.shutil, 'which', lambda *args, **kwargs: None)
    with dependencies.validate_closure(directory, digest, keyring=keyring) as closure:
        plan = dependencies.plan_dependencies(closure, status=status)
        assert {p['name'] for p in plan['packages']} == set(closure.packages)
        assert plan['closure_sha256'] == digest
        assert plan['status_sha256'] == hashlib.sha256(b'').hexdigest()
        assert status.read_text() == ''


def test_full_authenticated_closure_supports_narrow_console_roots(signed_repository, tmp_path, monkeypatch):
    directory, keyring, digest = signed_repository
    status = tmp_path / 'empty-status'
    status.write_text('')
    monkeypatch.setattr(dependencies.shutil, 'which', lambda *args, **kwargs: None)
    roots = {'docker.io', 'docker-compose-v2', 'openssl'}
    with dependencies.validate_closure(directory, digest, keyring=keyring) as closure:
        plan = dependencies.plan_dependencies(closure, status=status, required_roots=roots)
        assert {p['name'] for p in plan['packages']} == roots
        assert plan['required_roots'] == sorted(roots)
        assert len(closure.packages) > len(roots)
        assert status.read_text() == ''


@pytest.mark.parametrize('roots', [[], ['unsupported'], ['age', 'age'], 'age', [None], [['age']]])
def test_unsupported_root_subset_fails_before_apt(roots, monkeypatch):
    monkeypatch.setattr(dependencies, '_run', lambda *a, **kw: pytest.fail('Invalid subset reached apt'))
    with pytest.raises(InstallError, match='supported subset'):
        dependencies.plan_dependencies(None, required_roots=roots)


def test_apply_revalidates_the_exact_accepted_root_subset(monkeypatch):
    plan = {'required_roots': ['openssl'], 'packages': []}
    monkeypatch.setattr(dependencies.os, 'geteuid', lambda: 0)
    def planning(closure, **kwargs):
        assert kwargs == {'required_roots': ['openssl']}
        return plan
    monkeypatch.setattr(dependencies, 'plan_dependencies', planning)
    assert dependencies.apply_dependencies(None, plan, accept_changes=True) == plan


@pytest.mark.parametrize('change', ['missing', 'altered', 'extra', 'symlink'])
def test_payload_changes_fail_before_apt(payload, monkeypatch, change):
    directory, keyring, digest = payload
    deb = next(directory.rglob('*.deb'))
    if change == 'missing':
        deb.unlink()
    elif change == 'altered':
        deb.write_bytes(b'altered')
    elif change == 'extra':
        (directory / 'extra.deb').write_bytes(b'extra')
    else:
        deb.unlink()
        deb.symlink_to(keyring)
    calls = []
    monkeypatch.setattr(dependencies, '_run', lambda *args, **kwargs: calls.append(args))
    with pytest.raises(InstallError):
        dependencies.validate_closure(directory, digest, keyring=keyring)
    assert calls == []


def test_manifest_must_be_bound_to_authenticated_outer_inventory(payload):
    directory, keyring, _ = payload
    with pytest.raises(InstallError, match='authenticated inventory'):
        dependencies.validate_closure(directory, 'f' * 64, keyring=keyring)


def test_keyring_cannot_come_from_payload(payload):
    directory, keyring, digest = payload
    with pytest.raises(InstallError, match='independently installed'):
        dependencies.validate_closure(directory, digest, keyring=next(directory.rglob('*.deb')))


def test_attested_index_still_requires_independent_ubuntu_signature(payload):
    directory, keyring, _ = payload
    release = next(directory.rglob('InRelease'))
    release.write_text(release.read_text().replace('Origin: Ubuntu', 'Origin: Other'))
    manifest = json.loads((directory / dependencies.MANIFEST).read_text())
    digest = inventory(directory, manifest)
    with pytest.raises(InstallError, match='command failed: gpgv'):
        dependencies.validate_closure(directory, digest, keyring=keyring)


def test_attested_package_still_requires_signed_index_hash(payload):
    directory, keyring, _ = payload
    next(directory.rglob('*.deb')).write_bytes(b'not an official package')
    manifest = json.loads((directory / dependencies.MANIFEST).read_text())
    digest = inventory(directory, manifest)
    with pytest.raises(InstallError, match='signed Ubuntu index'):
        dependencies.validate_closure(directory, digest, keyring=keyring)


def test_missing_transitive_package_fails_actual_apt_resolver(payload):
    directory, keyring, _ = payload
    manifest = json.loads((directory / dependencies.MANIFEST).read_text())
    removed = next(p for p in manifest['packages'] if p['name'] == 'iris-test-transitive')
    manifest['packages'].remove(removed)
    (directory / 'repositories/archive' / removed['filename']).unlink()
    digest = inventory(directory, manifest)
    with pytest.raises(InstallError, match='outside the authenticated closure'):
        dependencies.validate_closure(directory, digest, keyring=keyring)


@pytest.mark.parametrize('operation', ['Remv package [1.0]', 'Purg package [1.0]', 'Inst unexpected-format'])
def test_apt_solution_refuses_remove_purge_and_unknown_operation(operation):
    with pytest.raises(InstallError):
        dependencies._simulation(operation)


@pytest.mark.parametrize('existing,new,held,message', [('2.0', '1.0', False, 'downgrade'), ('1.0', '2.0', True, 'held')])
def test_solution_refuses_downgrade_and_held_changes(existing, new, held, message):
    solution = [{'name': 'example', 'version': new, 'old_version': existing, 'architecture': 'amd64'}]
    installed = {'example': {'Version': existing, 'Status': ('hold' if held else 'install') + ' ok installed'}}
    with pytest.raises(InstallError, match=message):
        dependencies._check_solution(solution, {'example': {'version': new, 'architecture': 'amd64'}}, installed=installed)


def test_solution_accepts_safe_version_increase():
    dependencies._check_solution([{'name': 'example', 'version': '2.0'}], {'example': {'version': '2.0'}},
                                 installed={'example': {'Version': '1.0', 'Status': 'install ok installed'}})


@pytest.mark.parametrize('package', sorted(dependencies.ENGINE_PACKAGES))
def test_existing_provider_cannot_be_changed(package):
    with pytest.raises(InstallError, match='existing Docker provider'):
        dependencies._check_solution([{'name': package, 'version': '1.0'}], {package: {'version': '1.0'}}, preserve_engine=True)


def test_apply_requires_acceptance_before_inspection(monkeypatch):
    monkeypatch.setattr(dependencies, 'plan_dependencies', lambda _: pytest.fail('Must not inspect before acceptance'))
    with pytest.raises(InstallError, match='explicit acceptance'):
        dependencies.apply_dependencies(None, {})


def test_apply_rejects_any_plan_change(monkeypatch):
    monkeypatch.setattr(dependencies.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(dependencies, 'plan_dependencies', lambda _, **kw: {'status_sha256': 'changed'})
    monkeypatch.setattr(dependencies, '_run', lambda *args, **kwargs: pytest.fail('Must not apply a changed plan'))
    with pytest.raises(InstallError, match='state changed'):
        dependencies.apply_dependencies(None, {'status_sha256': 'before'}, accept_changes=True)


def test_apply_resimulates_exact_packages_before_mutation(monkeypatch, tmp_path):
    operation = {'name': 'example', 'version': '1.0', 'old_version': None, 'architecture': 'amd64'}
    plan = {'packages': [operation], 'status_sha256': 'a' * 64}
    calls = []
    monkeypatch.setattr(dependencies.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(dependencies, 'plan_dependencies', lambda _, **kw: plan)
    monkeypatch.setattr(dependencies, '_installed', lambda _: {'example': {'Version': '1.0'}})
    def run(command, **kwargs):
        calls.append(command)
        return 'Inst example (1.0 Ubuntu:24.04/noble [amd64])' if '--simulate' in command else ''
    monkeypatch.setattr(dependencies, '_run', run)
    dependencies.apply_dependencies(SimpleNamespace(config=Path('/private/apt.conf'), directory=tmp_path), plan, accept_changes=True)
    assert len(calls) == 2 and '--simulate' in calls[0] and '--yes' in calls[1]
    assert all('--no-download' in c and '--no-remove' in c and 'example=1.0' in c for c in calls)
    assert any(option.startswith('DPkg::Pre-Invoke::=') for option in calls[1])


def test_unfinished_dpkg_state_requires_recovery(tmp_path):
    status = tmp_path / 'status'
    status.write_text('Package: example\nVersion: 1.0\nStatus: install ok unpacked\n')
    with pytest.raises(InstallError, match='unfinished package operations'):
        dependencies._installed(status)


def test_foreign_architecture_is_rejected_before_simulation(tmp_path):
    status = tmp_path / 'status'
    status.write_text('Package: example\nVersion: 1.0\nArchitecture: i386\nStatus: install ok installed\n')
    with pytest.raises(InstallError, match='foreign-architecture'):
        dependencies._installed(status)


def test_manifest_rejects_nonstring_identity_without_type_errors(signed_repository):
    directory, _, _ = signed_repository
    manifest = json.loads((directory / dependencies.MANIFEST).read_text())
    manifest['packages'][0]['suite'] = []
    with pytest.raises(InstallError, match='package identity'):
        dependencies._validate_manifest(manifest)


def test_simulation_handles_apt_predependency_marker():
    result = dependencies._simulation('Inst libc6 (2.39-0ubuntu8.9 Ubuntu:24.04/noble-updates [amd64]) []')
    assert result[0]['name'] == 'libc6' and result[0]['version'] == '2.39-0ubuntu8.9'


def test_simulation_retains_architecture_independent_package_identity():
    result = dependencies._simulation('Inst ubuntu-keyring (2023.11.28.1 Ubuntu:24.04/noble [all])')
    assert result[0]['architecture'] == 'all'


def test_dpkg_reinstallation_error_requires_recovery(tmp_path):
    status = tmp_path / 'status'
    status.write_text('Package: example\nVersion: 1.0\nArchitecture: amd64\nStatus: install reinstreq installed\n')
    with pytest.raises(InstallError, match='unfinished package operations'):
        dependencies._installed(status)


@pytest.mark.parametrize('changed', [False, True])
def test_real_apt_guard_blocks_changed_status_before_any_dpkg(signed_repository, tmp_path, changed):
    directory, keyring, digest = signed_repository
    with dependencies.validate_closure(directory, digest, keyring=keyring) as closure:
        application = tmp_path / 'application'
        application.mkdir(mode=0o700)
        status = closure.config.parent / 'status'
        guard = dependencies._application_guard(application, dependencies._digest(status), status=status)
        if changed:
            status.write_text('Package: concurrent-test\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\nDescription: fixture\n\n')
        # Real apt runs its hook and prints the dpkg commands. Its diagnostic
        # switch suppresses all dpkg execution, while every apt state path is
        # private. This test cannot install or remove a host package.
        command = ['/usr/bin/apt-get', '--yes', 'install', '--no-download', '--no-remove',
                   '-o', 'Debug::pkgDPkgPM=true', '-o', 'Debug::NoLocking=true',
                   '-o', 'DPkg::Pre-Invoke::=' + guard, '-o', 'DPkg::Pre-Invoke::=' + guard, 'age=1.0']
        result = subprocess.run(command, env={**dependencies.ENV, 'APT_CONFIG': str(closure.config)},
                                capture_output=True, text=True, timeout=30)
        if changed:
            assert result.returncode != 0 and 'Host package state changed after review' in result.stderr
            assert not (application / 'apt-operation.json').exists()
        else:
            assert result.returncode == 0, result.stderr
            assert (application / 'apt-operation.json').is_file()
            reused = subprocess.run(command, env={**dependencies.ENV, 'APT_CONFIG': str(closure.config)},
                                    capture_output=True, text=True, timeout=30)
            assert reused.returncode != 0 and 'different apt operation' in reused.stderr
