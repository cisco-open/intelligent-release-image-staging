# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pinned public packaging inputs retain notices and external-tool custody."""

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import packaging_inputs as p, release_kit
from iris_installer.state import InstallError


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_rows():
    rows = [(name, (b'#!/bin/sh\nexit 99\n' if name in p.EXECUTABLES else
                    ('public fixture ' + name + '\n').encode()), name in p.EXECUTABLES)
            for name in p.SOURCE_FILES]
    return [*rows, ('release_configs', None, False),
            (p.APPMGR_METADATA, p.f._json(p._appmgr_metadata()), False)]


def bundle(rows=None, change=None):
    appmgr = p._gzip(p._tar_bytes(source_rows() if rows is None else rows))
    metadata = {'format': 'iris-packaging-tools-v1',
                'ioxclient': {'version': p.IOXCLIENT_VERSION, 'platform': 'linux/amd64',
                              'delivery': 'operator-supplied', 'sha256': p._ioxclient_pin()},
                'appmgr': {'archive': p.APPMGR_ARCHIVE, 'size': len(appmgr), 'sha256': sha(appmgr),
                           'source_repository': p.APPMGR_REPOSITORY, 'source_revision': p.APPMGR_REVISION}}
    if change:
        change(metadata)
    return p._gzip(p._tar_bytes([('tools.json', p.f._json(metadata), False),
                                 (p.APPMGR_ARCHIVE, appmgr, False)]))


def kit_for(tmp_path, data):
    directory = tmp_path / 'kit'
    directory.mkdir(exist_ok=True, mode=0o700)
    (directory / p.BUNDLE).write_bytes(data)
    asset = release_kit.Asset('packaging-tools', p.BUNDLE, len(data), sha(data), 'tar.gz')
    return release_kit.VerifiedKit(directory, 'v2026.10.08', 'a' * 40,
        'b' * 64, 'c' * 64, 'd' * 64, None, True, (asset,))


def prepare(tmp_path, data=None):
    return p.prepare_packaging_inputs(kit_for(tmp_path, bundle() if data is None else data),
                                      tmp_path / 'output')


def unpack(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        return {row.name: (archive.extractfile(row).read() if row.isfile() else None)
                for row in archive}


def test_consumer_uses_authenticated_copy_and_publishes_private_inputs_without_execution(tmp_path, monkeypatch):
    kit = kit_for(tmp_path, bundle())
    original = release_kit.VerifiedKit.copy_asset
    calls = []

    def copied(self, role, destination):
        calls.append(role)
        return original(self, role, destination)

    monkeypatch.setattr(release_kit.VerifiedKit, 'copy_asset', copied)
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('consumer executed a program'))
    result = p.prepare_packaging_inputs(kit, tmp_path / 'output')
    assert calls == ['packaging-tools']
    assert result.appmgr_archive == tmp_path / 'output' / p.APPMGR_ARCHIVE
    assert result.appmgr_revision == p.APPMGR_REVISION
    assert sha(result.appmgr_archive.read_bytes()) == result.appmgr_sha256
    assert result.ioxclient_sha256 == p._ioxclient_pin()
    assert result.kit_receipt == kit.receipt()
    assert (tmp_path / 'output').stat().st_mode & 0o777 == 0o700
    assert {path.name for path in (tmp_path / 'output').iterdir()} == {'tools.json', p.APPMGR_ARCHIVE}
    assert all(path.stat().st_mode & 0o777 == 0o444 for path in (tmp_path / 'output').iterdir())
    assert set(unpack(result.appmgr_archive.read_bytes())) == p.SOURCE_FILES | {'release_configs', p.APPMGR_METADATA}


@pytest.mark.parametrize('identity', [None, {}, {'sha256': 'a' * 64}, Path('/tmp/self-supplied-tools')])
def test_consumer_rejects_self_supplied_authority(tmp_path, identity):
    with pytest.raises(InstallError, match='authenticated release kit'):
        p.prepare_packaging_inputs(identity, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


@pytest.mark.parametrize('where,field,value', [
    ('root', 'format', 'unknown'), ('root', 'extra', True),
    ('ioxclient', 'version', '1.17.0.0'), ('ioxclient', 'platform', 'linux/arm64'),
    ('ioxclient', 'delivery', 'bundled'), ('ioxclient', 'sha256', '0' * 64),
    ('ioxclient', 'sha256', 'a' * 64 + '\n'), ('ioxclient', 'extra', True),
    ('appmgr', 'source_revision', 'b' * 40), ('appmgr', 'source_repository', 'https://other.invalid/repo'),
    ('appmgr', 'archive', '../unsafe'), ('appmgr', 'sha256', 'a' * 64),
    ('appmgr', 'size', True), ('appmgr', 'size', 1), ('appmgr', 'extra', True),
])
def test_authenticated_but_wrong_pins_or_metadata_are_refused(tmp_path, where, field, value):
    def change(metadata):
        (metadata if where == 'root' else metadata[where])[field] = value
    with pytest.raises(InstallError, match='metadata differs'):
        prepare(tmp_path, bundle(change=change))
    assert not (tmp_path / 'output').exists()


@pytest.mark.parametrize('kind', ['duplicate', 'missing', 'extra', 'private-key', 'metadata', 'mode', 'directory'])
def test_inner_xr_archive_has_only_required_source_and_notices(tmp_path, kind):
    rows = source_rows()
    if kind == 'duplicate': rows.append(rows[0])
    elif kind == 'missing': rows = [row for row in rows if row[0] != 'LICENSE']
    elif kind == 'extra': rows.append(('examples/private.key', b'fixture', False))
    elif kind == 'private-key':
        rows = [(name, b'-----BEGIN OPENSSH PRIVATE KEY-----\n' if name == 'README.md' else data, mode)
                for name, data, mode in rows]
    elif kind == 'metadata':
        rows = [(name, b'{}' if name == p.APPMGR_METADATA else data, mode) for name, data, mode in rows]
    elif kind == 'mode':
        rows = [(name, data, False if name == 'appmgr_build' else mode) for name, data, mode in rows]
    else:
        rows = [(name, b'wrong' if name == 'release_configs' else data, mode) for name, data, mode in rows]
    with pytest.raises(InstallError):
        prepare(tmp_path, bundle(rows))
    assert not (tmp_path / 'output').exists()


def unsafe_tar(kind, *, inner):
    values = source_rows() if inner else [(name, data, False) for name, data in unpack(bundle()).items()]
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w:') as archive:
        for name, data, executable in values:
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if executable or data is None else 0o644
            if data is None: member.type = tarfile.DIRTYPE
            else: member.size = len(data)
            archive.addfile(member, None if data is None else io.BytesIO(data))
        member = tarfile.TarInfo('../escape' if kind == 'path' else 'extra')
        member.type = {'link': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE,
                       'fifo': tarfile.FIFOTYPE}.get(kind, tarfile.REGTYPE)
        member.linkname = 'appmgr_build'
        archive.addfile(member)
    return p._gzip(raw.getvalue())


@pytest.mark.parametrize('inner', [False, True])
@pytest.mark.parametrize('kind', ['path', 'link', 'hardlink', 'fifo', 'extra'])
def test_unsafe_archive_entries_are_never_extracted(tmp_path, kind, inner):
    data = unsafe_tar(kind, inner=inner)
    if inner:
        outer = unpack(bundle())
        metadata = json.loads(outer['tools.json'])
        metadata['appmgr'].update(size=len(data), sha256=sha(data))
        data = p._gzip(p._tar_bytes([('tools.json', p.f._json(metadata), False),
                                     (p.APPMGR_ARCHIVE, data, False)]))
    with pytest.raises(InstallError):
        prepare(tmp_path, data)
    assert not (tmp_path / 'output').exists()
    assert not (tmp_path / 'escape').exists()


def test_outer_duplicate_metadata_and_trailing_payload_are_rejected(tmp_path):
    rows = unpack(bundle())
    data = p._tar_bytes([(name, value, False) for name, value in rows.items()])
    for malformed in (p._gzip(data + b'hidden payload'),
                      p._gzip(p._tar_bytes([('tools.json', b'{}', False)] * 2))):
        with pytest.raises(InstallError):
            prepare(tmp_path, malformed)


def test_archive_expansion_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(p, 'MAX_ARCHIVE', 65536)
    with pytest.raises(InstallError, match='expansion limit'):
        prepare(tmp_path, gzip.compress(b'x' * 65537))
    assert not (tmp_path / 'output').exists()


@pytest.mark.parametrize('kind', ['changed', 'symlink', 'copy-race'])
def test_outer_authentication_refuses_changed_or_racing_bytes(tmp_path, monkeypatch, kind):
    kit = kit_for(tmp_path, bundle())
    asset = kit.directory / p.BUNDLE
    if kind == 'changed': asset.write_bytes(b'changed outer bytes')
    elif kind == 'symlink':
        asset.rename(kit.directory / 'actual')
        asset.symlink_to(kit.directory / 'actual')
    else:
        original = release_kit._hash
        def raced(*args, **kwargs):
            result = original(*args, **kwargs)
            asset.write_bytes(asset.read_bytes() + b'x')
            return result
        monkeypatch.setattr(release_kit, '_hash', raced)
    with pytest.raises((InstallError, OSError)):
        p.prepare_packaging_inputs(kit, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


@pytest.mark.parametrize('kind', ['existing', 'symlink', 'unsafe-parent', 'publication-race'])
def test_output_ownership_is_exclusive_and_preserves_owner_files(tmp_path, monkeypatch, kind):
    parent = tmp_path / 'parent'
    parent.mkdir(mode=0o700)
    output = parent / 'output'
    if kind == 'existing': output.mkdir()
    elif kind == 'symlink': output.symlink_to(tmp_path, target_is_directory=True)
    elif kind == 'unsafe-parent': parent.chmod(0o777)
    else:
        original = p.f._publish
        def raced(fd, stage_name, output_name):
            output.mkdir()
            (output / 'keep').write_text('owner data')
            return original(fd, stage_name, output_name)
        monkeypatch.setattr(p.f, '_publish', raced)
    with pytest.raises(InstallError):
        p.prepare_packaging_inputs(kit_for(tmp_path, bundle()), output)
    if kind == 'publication-race': assert (output / 'keep').read_text() == 'owner data'
    assert not list(parent.glob('.iris-packaging-*'))


def test_parent_substitution_cannot_redirect_publication_or_cleanup(tmp_path, monkeypatch):
    parent = tmp_path / 'parent'
    parent.mkdir(mode=0o700)
    original = os.fsync
    changed = False
    def replaced(fd):
        nonlocal changed
        result = original(fd)
        if not changed and list(parent.glob('.iris-packaging-*')):
            changed = True
            parent.rename(tmp_path / 'held-parent')
            parent.mkdir(mode=0o700)
            (parent / 'keep').write_text('owner data')
        return result
    monkeypatch.setattr(os, 'fsync', replaced)
    with pytest.raises(InstallError, match='parent changed'):
        p.prepare_packaging_inputs(kit_for(tmp_path, bundle()), parent / 'output')
    assert list((tmp_path / 'held-parent').iterdir()) == []
    assert (parent / 'keep').read_text() == 'owner data'


@pytest.fixture
def repository(tmp_path, monkeypatch):
    repository = tmp_path / 'repository'
    repository.mkdir()
    for name, data, executable in source_rows():
        if name == p.APPMGR_METADATA or data is None:
            continue
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if executable else 0o644)
    examples = repository / 'examples'
    examples.mkdir()
    (examples / 'private.key').write_text('upstream example excluded')
    (examples / 'sample.tar.gz').write_bytes(b'irrelevant sample')
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repository), *args], stderr=subprocess.DEVNULL).decode().strip()
    git('init', '-q')
    git('add', '.')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'Fixture source')
    monkeypatch.setattr(p, 'APPMGR_REVISION', git('rev-parse', 'HEAD'))
    return repository, git


def test_producer_uses_pinned_git_objects_retains_notices_and_excludes_worktree_changes(tmp_path, repository):
    source, git = repository
    before = git('show', p.APPMGR_REVISION + ':appmgr_build').encode() + b'\n'
    (source / 'appmgr_build').write_text('changed uncommitted build code')
    (source / 'untracked').write_text('untracked owner file')
    first = p.build_packaging_inputs(source, tmp_path / 'first')
    second = p.build_packaging_inputs(source, tmp_path / 'second')
    assert first.read_bytes() == second.read_bytes()
    outer = unpack(first.read_bytes())
    assert set(outer) == {'tools.json', p.APPMGR_ARCHIVE}
    inner = unpack(outer[p.APPMGR_ARCHIVE])
    assert set(inner) == p.SOURCE_FILES | {'release_configs', p.APPMGR_METADATA}
    assert inner['appmgr_build'] == before
    assert inner['LICENSE'] == (source / 'LICENSE').read_bytes()
    assert not any('examples' in name or name.endswith('.key') for name in inner)
    assert json.loads(inner[p.APPMGR_METADATA]) == p._appmgr_metadata()
    result = prepare(tmp_path, first.read_bytes())
    assert result.appmgr_archive.read_bytes() == outer[p.APPMGR_ARCHIVE]


@pytest.mark.parametrize('kind', ['unknown-commit', 'export-ignore', 'private-key'])
def test_producer_refuses_missing_or_modified_pinned_source(tmp_path, repository, monkeypatch, kind):
    source, git = repository
    if kind == 'unknown-commit': monkeypatch.setattr(p, 'APPMGR_REVISION', '0' * 40)
    elif kind == 'export-ignore':
        (source / '.git/info/attributes').write_text('LICENSE export-ignore\n')
    else:
        (source / 'README.md').write_text('-----BEGIN RSA PRIVATE KEY-----\n')
        git('add', 'README.md')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'Bad source')
        monkeypatch.setattr(p, 'APPMGR_REVISION', git('rev-parse', 'HEAD'))
    with pytest.raises(InstallError):
        p.build_packaging_inputs(source, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_partial_git_clone_cannot_fetch_missing_source_objects(tmp_path, repository):
    source, git = repository
    git('config', 'uploadpack.allowFilter', 'true')
    partial = tmp_path / 'partial.git'
    subprocess.run(['git', 'clone', '-q', '--bare', '--filter=blob:none', source.as_uri(), str(partial)],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    packs = {path.name: sha(path.read_bytes()) for path in (partial / 'objects/pack').iterdir()}
    with pytest.raises(InstallError, match='pinned XR source could not be read'):
        p.build_packaging_inputs(partial, tmp_path / 'output')
    assert {path.name: sha(path.read_bytes()) for path in (partial / 'objects/pack').iterdir()} == packs
    assert not (tmp_path / 'output').exists()


@pytest.mark.parametrize('kind', ['silent', 'overflow', 'closed-stdout'])
def test_git_read_and_wait_share_one_bounded_deadline(tmp_path, monkeypatch, kind):
    original = subprocess.Popen
    processes = []
    code = ('import time; time.sleep(30)' if kind == 'silent' else
            'import sys,time; sys.stdout.write("x"*4096); sys.stdout.flush(); time.sleep(30)'
            if kind == 'overflow' else
            'import os,time; os.close(1); time.sleep(30)')
    def child(_command, **kwargs):
        process = original([sys.executable, '-c', code], **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(p.subprocess, 'Popen', child)
    monkeypatch.setattr(p, 'GIT_SECONDS', 0.5)
    started = time.monotonic()
    with pytest.raises(InstallError, match='size limit' if kind == 'overflow' else 'deadline'):
        p._git(tmp_path, ['irrelevant'], 1024)
    assert time.monotonic() - started < 3
    assert len(processes) == 1 and processes[0].poll() is not None


def test_git_source_read_ignores_ambient_configuration(tmp_path, repository, monkeypatch):
    source, git = repository
    original = p.subprocess.Popen
    observed = []
    def run(command, **kwargs):
        observed.append(kwargs['env'])
        return original(command, **kwargs)
    monkeypatch.setenv('GIT_CONFIG_COUNT', '1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0', 'protocol.file.allow')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', 'always')
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', '/not/an/input')
    monkeypatch.setattr(p.subprocess, 'Popen', run)
    assert p._git(source, ['rev-parse', p.APPMGR_REVISION], 128).decode().strip() == p.APPMGR_REVISION
    assert len(observed) == 1
    assert observed[0]['GIT_ALLOW_PROTOCOL'] == ''
    assert observed[0]['GIT_CONFIG_GLOBAL'] == '/dev/null'
    assert 'GIT_CONFIG_COUNT' not in observed[0]


def test_source_pin_is_exact_and_installed_layout_takes_precedence(tmp_path, monkeypatch):
    module = tmp_path / 'lib/iris_installer/packaging_inputs.py'
    module.parent.mkdir(parents=True)
    source = tmp_path / 'lib/source/tools'
    source.mkdir(parents=True)
    (source / 'ioxclient.sha256').write_text('a' * 64 + '  ' + p.IOXCLIENT_VERSION + '\n')
    (tmp_path / 'lib/ioxclient.sha256').write_text('b' * 64 + '  ' + p.IOXCLIENT_VERSION + '\n')
    monkeypatch.setattr(p, '__file__', str(module))
    assert p._ioxclient_pin() == 'a' * 64
    (source / 'ioxclient.sha256').write_text(('a' * 64 + '  ' + p.IOXCLIENT_VERSION + '\n') * 2)
    with pytest.raises(InstallError, match='pin is invalid'):
        p._ioxclient_pin()


def test_producer_cli_reports_missing_local_repository_without_traceback(tmp_path):
    script = Path(p.__file__).parents[1] / 'build-packaging-inputs.py'
    result = subprocess.run([sys.executable, str(script), '--appmgr-repository', str(tmp_path / 'absent'),
                             '--output-dir', str(tmp_path / 'output')], capture_output=True, text=True)
    assert result.returncode == 1 and 'pinned XR source could not be read' in result.stderr
    assert 'Traceback' not in result.stderr and not (tmp_path / 'output').exists()
