# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authenticated profile dispatch and bounded dependency archive consumption."""

import copy
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import offline_inputs as inputs, offline_dependencies as dependencies, release_kit
from iris_installer.state import InstallError
from test_installer_offline_dependencies import signed_repository
from test_installer_release_kit import release, seal, verify, TAG, COMMIT


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(rows, *, suffix=b''):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:', format=tarfile.USTAR_FORMAT) as target:
        for name, data, kind, mode in rows:
            member = tarfile.TarInfo(name)
            member.type, member.mode = kind, mode
            member.size = len(data) if data is not None else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = 'dependency-manifest.json'
            target.addfile(member, io.BytesIO(data) if data is not None else None)
    return gzip.compress(buffer.getvalue() + suffix, mtime=0)


def directory_archive(directory):
    return archive([(path.relative_to(directory).as_posix(), path.read_bytes(), tarfile.REGTYPE, 0o644)
                    for path in sorted(directory.rglob('*')) if path.is_file()])


@pytest.fixture
def dependency_rows():
    files, packages = {}, []
    for repository, suite, _ in dependencies.REPOSITORIES:
        files[f'repositories/{repository}/dists/{suite}/InRelease'] = b'fixture signed metadata is not authenticated'
        for component in dependencies.COMPONENTS:
            files[f'repositories/{repository}/dists/{suite}/{component}/binary-amd64/Packages'] = b'fixture package index'
    for name in sorted(dependencies.ROOT_PACKAGES):
        filename = 'pool/main/' + name + '_1.0_amd64.deb'
        files['repositories/archive/' + filename] = ('fixture package ' + name).encode()
        packages.append({'name': name, 'version': '1.0', 'architecture': 'amd64',
                         'repository': 'archive', 'suite': 'noble', 'component': 'main', 'filename': filename})
    manifest = {'schema': dependencies.SCHEMA, 'host': dict(release_kit.HOST), 'docker_provider': 'docker.io',
                'roots': {name: '1.0' for name in dependencies.ROOT_PACKAGES}, 'packages': packages,
                'files': {name: {'sha256': sha(data), 'size': len(data)} for name, data in files.items()}}
    raw = json.dumps(manifest, sort_keys=True).encode()
    files[dependencies.MANIFEST] = raw
    return [(name, data, tarfile.REGTYPE, 0o644) for name, data in sorted(files.items())], sha(raw)


def verified_kit(tmp_path, data, manifest_digest, *, profile='ubuntu-dependencies'):
    directory = tmp_path / 'kit'
    directory.mkdir(mode=0o700)
    name = 'ubuntu-dependencies.tar.gz'
    (directory / name).write_bytes(data)
    asset = release_kit.Asset('ubuntu-dependencies', name, len(data), sha(data), 'tar.gz',
                              dependency_manifest_sha256=manifest_digest)
    return release_kit.VerifiedKit(directory, TAG, COMMIT, 'b' * 64, 'c' * 64, 'd' * 64,
                                   'e' * 64, True, (asset,), profile)


def add_profile(release, dependency_rows):
    rows, digest = dependency_rows
    data = archive(rows)
    name = 'ubuntu-dependencies.tar.gz'
    (release.directory / name).write_bytes(data)
    release.manifest['profile'] = 'ubuntu-dependencies'
    release.manifest['assets']['ubuntu-dependencies'] = {
        'name': name, 'sha256': sha(data), 'size': len(data), 'format': 'tar.gz',
        'dependency_manifest_sha256': digest}
    seal(release)
    return digest


def test_complete_profile_authenticates_the_additional_asset_and_binds_resume(release, dependency_rows):
    digest = add_profile(release, dependency_rows)
    kit = verify(release)
    assert kit.profile == 'ubuntu-dependencies'
    assert kit.asset('ubuntu-dependencies').dependency_manifest_sha256 == digest
    assert len(kit.assets) == 7
    receipt = release_kit.selection('prebuilt', kit=kit, offline=True)
    assert receipt['kit']['profile'] == 'ubuntu-dependencies'
    release_kit.assert_resume_selection(receipt, copy.deepcopy(receipt))
    changed = copy.deepcopy(receipt)
    changed['kit']['profile'] = 'prepared-host'
    with pytest.raises(InstallError, match='changed'):
        release_kit.assert_resume_selection(receipt, changed)


@pytest.mark.parametrize('change', ['missing-role', 'prepared-role', 'missing-digest', 'bad-digest',
                                  'digest-other-role', 'wrong-format', 'invalid-profile'])
def test_profile_and_manifest_identity_are_exact(release, dependency_rows, change):
    add_profile(release, dependency_rows)
    asset = release.manifest['assets']['ubuntu-dependencies']
    if change == 'missing-role':
        del release.manifest['assets']['ubuntu-dependencies']
    elif change == 'prepared-role':
        release.manifest['profile'] = 'prepared-host'
    elif change == 'missing-digest':
        del asset['dependency_manifest_sha256']
    elif change == 'bad-digest':
        asset['dependency_manifest_sha256'] = 'bad'
    elif change == 'digest-other-role':
        release.manifest['assets']['source']['dependency_manifest_sha256'] = 'f' * 64
    elif change == 'wrong-format':
        asset['format'] = 'docker-archive'
    else:
        release.manifest['profile'] = []
    seal(release)
    with pytest.raises(InstallError):
        verify(release)


def test_archive_inspection_is_pure_and_extraction_uses_private_regular_files(tmp_path, dependency_rows, monkeypatch):
    rows, digest = dependency_rows
    path = tmp_path / 'dependencies.tar.gz'
    rows = [(name, data, kind, 0o6755) for name, data, kind, _ in rows]
    rows.append(('repositories', None, tarfile.DIRTYPE, 0o777))
    path.write_bytes(archive(rows))
    monkeypatch.setattr(dependencies, '_run', lambda *a, **k: pytest.fail('Pure inspection executed a command'))
    destination = tmp_path / 'private-payload'
    result = inputs.inspect_dependency_archive(path, destination=destination)
    assert result['manifest_sha256'] == digest
    assert destination.stat().st_mode & 0o777 == 0o700
    for file in destination.rglob('*'):
        if file.is_file():
            assert file.stat().st_mode & 0o777 == 0o600 and file.stat().st_nlink == 1
    with pytest.raises(InstallError):
        inputs.inspect_dependency_archive(path, destination=destination)


@pytest.mark.parametrize('replace', ['parent', 'output'])
def test_extraction_parent_substitution_cannot_write_or_clean_replacement(tmp_path, dependency_rows, monkeypatch, replace):
    rows, digest = dependency_rows
    path = tmp_path / 'dependencies.tar.gz'
    path.write_bytes(archive(rows))
    parent = tmp_path / 'parent'
    parent.mkdir(mode=0o700)
    destination = parent / 'payload'
    original, replaced = inputs._output_file, []
    def substitute(descriptor, name):
        if not replaced:
            target = parent if replace == 'parent' else destination
            target.rename(tmp_path / 'moved')
            target.mkdir(mode=0o700)
            sentinel = target / 'sentinel'
            sentinel.write_bytes(b'keep replacement')
            replaced.append(sentinel)
        return original(descriptor, name)
    monkeypatch.setattr(inputs, '_output_file', substitute)
    with pytest.raises(InstallError, match='directory changed'):
        inputs.inspect_dependency_archive(path, expected_manifest_sha256=digest, destination=destination)
    assert replaced[0].read_bytes() == b'keep replacement'
    assert list(replaced[0].parent.iterdir()) == replaced
    assert not list((tmp_path / 'moved').rglob('*'))


@pytest.mark.parametrize('replace_at', ['extraction', 'validation', 'caller'])
def test_consumer_work_substitution_never_cleans_same_name_replacement(tmp_path, dependency_rows, monkeypatch, replace_at):
    rows, digest = dependency_rows
    kit = verified_kit(tmp_path, archive(rows), digest)
    monkeypatch.setattr(inputs.tempfile, 'gettempdir', lambda: str(tmp_path))
    moved, sentinel = tmp_path / 'moved', None
    def substitute(work):
        nonlocal sentinel
        work.rename(moved)
        work.mkdir(mode=0o700)
        sentinel = work / 'sentinel'
        sentinel.write_bytes(b'keep replacement')
    original_inspect = inputs.inspect_dependency_archive
    def inspect(path, **kwargs):
        result = original_inspect(path, **kwargs)
        if replace_at == 'extraction':
            substitute(path.parent)
        return result
    @contextmanager
    def validate(payload, expected):
        if replace_at == 'validation':
            substitute(payload.parent)
        yield payload
    monkeypatch.setattr(inputs, 'inspect_dependency_archive', inspect)
    monkeypatch.setattr(dependencies, 'validate_closure', validate)
    with pytest.raises(InstallError, match='directory changed'):
        with inputs.prepare_dependencies(kit) as payload:
            assert replace_at == 'caller'
            substitute(payload.parent)
    assert sentinel.read_bytes() == b'keep replacement'
    assert list(sentinel.parent.iterdir()) == [sentinel]
    assert not list(moved.iterdir())


@pytest.mark.parametrize('change', ['missing', 'extra', 'extra-directory', 'duplicate', 'symlink', 'hardlink',
                                  'fifo', 'traversal', 'altered', 'trailing', 'truncated', 'sparse'])
def test_unsafe_or_inconsistent_archives_fail_before_closure_validation(tmp_path, dependency_rows, change):
    rows, digest = dependency_rows
    rows = list(rows)
    suffix = b''
    if change == 'missing':
        rows.pop()
    elif change == 'extra':
        rows.append(('extra', b'x', tarfile.REGTYPE, 0o644))
    elif change == 'extra-directory':
        rows.append(('extra', None, tarfile.DIRTYPE, 0o755))
    elif change == 'duplicate':
        rows.append(rows[0])
    elif change in ('symlink', 'hardlink', 'fifo', 'sparse'):
        kind = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE, 'fifo': tarfile.FIFOTYPE,
                'sparse': tarfile.GNUTYPE_SPARSE}[change]
        rows.append(('unsafe', None, kind, 0o644))
    elif change == 'traversal':
        rows.append(('../escape', b'x', tarfile.REGTYPE, 0o644))
    elif change == 'altered':
        name, data, kind, mode = rows[-1]
        rows[-1] = (name, b'altered bytes', kind, mode)
    elif change == 'trailing':
        suffix = b'hidden payload'
    data = archive(rows, suffix=suffix)
    if change == 'truncated':
        raw = gzip.decompress(data)
        with tarfile.open(fileobj=io.BytesIO(raw)) as parsed:
            list(parsed)
            raw = raw[:parsed.offset + 512]
        data = gzip.compress(raw)
    path = tmp_path / 'dependencies.tar.gz'
    path.write_bytes(data)
    with pytest.raises(InstallError):
        inputs.inspect_dependency_archive(path, expected_manifest_sha256=digest)
    assert not (tmp_path.parent / 'escape').exists()


def test_compression_expansion_is_bounded(tmp_path, monkeypatch):
    path = tmp_path / 'bomb.tar.gz'
    path.write_bytes(gzip.compress(b'\0' * 4096))
    monkeypatch.setattr(inputs, 'MAX_EXPANDED', 2048)
    with pytest.raises(InstallError, match='expansion limit'):
        inputs.inspect_dependency_archive(path)


@pytest.mark.parametrize('profile', ['prepared-host', 'unknown'])
def test_consumer_never_falls_back_from_an_incompatible_profile(tmp_path, dependency_rows, profile):
    rows, digest = dependency_rows
    kit = verified_kit(tmp_path, archive(rows), digest, profile=profile)
    with pytest.raises(InstallError, match='authenticated ubuntu-dependencies profile'):
        with inputs.prepare_dependencies(kit):
            pytest.fail('An incompatible profile yielded a dependency closure')


def test_consumer_refuses_unverified_authority():
    with pytest.raises(InstallError, match='authenticated ubuntu-dependencies profile'):
        with inputs.prepare_dependencies({'profile': 'ubuntu-dependencies'}):
            pytest.fail('Unverified input yielded a dependency closure')


@pytest.mark.parametrize('changed', ['outer-bytes', 'inner-digest'])
def test_consumer_binds_both_outer_copy_and_inner_manifest(tmp_path, dependency_rows, monkeypatch, changed):
    rows, digest = dependency_rows
    kit = verified_kit(tmp_path, archive(rows), 'f' * 64 if changed == 'inner-digest' else digest)
    if changed == 'outer-bytes':
        (kit.directory / kit.assets[0].name).write_bytes(b'changed after authentication')
    monkeypatch.setattr(dependencies, 'validate_closure', lambda *a, **k: pytest.fail('Unbound bytes reached validation'))
    with pytest.raises(InstallError):
        with inputs.prepare_dependencies(kit):
            pytest.fail('Changed authenticated bytes yielded a closure')


@pytest.mark.parametrize('caller_raises', [False, True])
def test_consumer_runs_real_signature_and_resolver_validation_then_cleans_up(tmp_path, signed_repository, monkeypatch, caller_raises):
    directory, independent_test_keyring, digest = signed_repository
    kit = verified_kit(tmp_path, directory_archive(directory), digest)
    original = dependencies.validate_closure
    copied, payloads = [], []
    original_copy = release_kit.VerifiedKit.copy_asset
    def checked_copy(self, role, destination):
        copied.append(role)
        return original_copy(self, role, destination)
    def validate(payload, expected):
        assert expected == digest and not payload.is_relative_to(kit.directory)
        payloads.append(payload)
        return original(payload, expected, keyring=independent_test_keyring)
    monkeypatch.setattr(release_kit.VerifiedKit, 'copy_asset', checked_copy)
    monkeypatch.setattr(dependencies, 'validate_closure', validate)
    monkeypatch.setattr(dependencies, 'plan_dependencies', lambda *a, **k: pytest.fail('Consumer planned host changes'))
    monkeypatch.setattr(dependencies, 'apply_dependencies', lambda *a, **k: pytest.fail('Consumer applied host changes'))
    class CallerError(Exception):
        pass
    try:
        with inputs.prepare_dependencies(kit) as closure:
            assert closure.digest == digest and len(closure.packages) == len(dependencies.ROOT_PACKAGES) + 1
            private = closure.directory
            if caller_raises:
                raise CallerError()
    except CallerError:
        assert caller_raises
    assert copied == ['ubuntu-dependencies']
    assert not private.exists() and all(not path.exists() for path in payloads)
