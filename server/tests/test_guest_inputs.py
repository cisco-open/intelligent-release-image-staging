# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Guest inputs bind public references without publishing deployment trust."""

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import guest_inputs as g, release_kit
from iris_installer.state import InstallError


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def source(tmp_path):
    directory = tmp_path / 'source'
    directory.mkdir(mode=0o700)
    files = {name: ('public fixture ' + name + '\n').encode() for name in g.FIXED_FILES}
    files.update({'device/agent/iris_agent.py': b'# agent\n',
                  'device/agent/runtime_verifier.py': b'# verifier\n',
                  'device/agent/tests/test_private.py': b'# not a shipping input\n'})
    files['bin/aria2c'] = files['deliverables/aria2c-x86_64']
    files['tools/aria2c.sha256'] = '# Public pin comment: architecture → SHA256\n'.encode() + ''.join(
        sha(files['deliverables/aria2c-' + arch]) + '  ' + arch + '\n'
        for arch in ('x86_64', 'aarch64')).encode()
    for name, data in files.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o755 if name.startswith(('bin/', 'deliverables/')) else 0o644)
    return directory, {name: sha(data) for name, data in files.items()}


def kit_for(tmp_path, data):
    directory = tmp_path / 'kit'
    directory.mkdir(exist_ok=True, mode=0o700)
    (directory / g.BUNDLE).write_bytes(data)
    asset = release_kit.Asset('guest-inputs', g.BUNDLE, len(data), sha(data), 'tar.gz')
    return release_kit.VerifiedKit(directory, 'v2026.10.09', 'a' * 40,
        'b' * 64, 'c' * 64, 'd' * 64, None, True, (asset,))


def manifest(source):
    return g._source_metadata(*source)


def verify(tmp_path, source, metadata=None):
    raw = g.f._json(manifest(source) if metadata is None else metadata)
    return g.verify_guest_inputs(kit_for(tmp_path, g._bundle(raw)), *source)


def test_candidate_is_deterministic_manifest_only_and_preserves_both_architectures_and_notices(tmp_path, source, monkeypatch):
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('must not execute'))
    first = g.build_guest_inputs(*source, tmp_path / 'first')
    second = g.build_guest_inputs(*source, tmp_path / 'second')
    assert first.read_bytes() == second.read_bytes()
    assert first.name == g.BUNDLE
    assert first.parent.stat().st_mode & 0o777 == 0o700
    assert first.stat().st_mode & 0o777 == 0o444
    value = json.loads(g._unpack(first.read_bytes()))
    assert value == manifest(source)
    assert set(value['files']) == g.FIXED_FILES | {
        'device/agent/iris_agent.py', 'device/agent/runtime_verifier.py'}
    assert value['compiled_helpers'] == 'authenticated-server-image'
    assert value['deployment_trust'] == 'runtime-public-roots'
    assert {'LICENSE', 'NOTICE', 'tools/aria2c-source/COPYING3',
            'deliverables/aria2c-x86_64', 'deliverables/aria2c-aarch64'} <= value['files'].keys()
    assert all(set(entry) == {'sha256', 'mode', 'size'} for entry in value['files'].values())
    assert b'public fixture' not in first.read_bytes()


def test_consumer_copies_authenticated_asset_then_binds_actual_sources_without_execution(tmp_path, source, monkeypatch):
    calls, original = [], release_kit.VerifiedKit.copy_asset
    def copied(self, role, destination):
        calls.append(role)
        return original(self, role, destination)
    monkeypatch.setattr(release_kit.VerifiedKit, 'copy_asset', copied)
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('must not execute'))
    raw = g.f._json(manifest(source))
    kit = kit_for(tmp_path, g._bundle(raw))
    result = g.verify_guest_inputs(kit, *source)
    assert calls == ['guest-inputs']
    assert result == {'schema': 1, 'kit_receipt': kit.receipt(),
                      'manifest_sha256': sha(raw), 'input_count': len(g.FIXED_FILES) + 2}
    assert set(path.name for path in tmp_path.iterdir()) == {'source', 'kit'}


@pytest.mark.parametrize('authority', [None, {}, Path('/self-supplied')])
def test_consumer_requires_verified_kit(tmp_path, source, authority):
    with pytest.raises(InstallError, match='authenticated release kit'):
        g.verify_guest_inputs(authority, *source)


@pytest.mark.parametrize('field,value', [
    ('format', 'iris-guest-inputs-v2'), ('delivery', 'ready-bundle'),
    ('compiled_helpers', 'source'), ('deployment_trust', 'bundled-roots'),
    ('runtime_publisher', 'other.sh'), ('aria2', {'linux/amd64': 'bin/aria2c'}),
    ('extra', 'private-data'), ('files', {}),
])
def test_authenticated_metadata_cannot_change_contract(tmp_path, source, field, value):
    metadata = manifest(source)
    metadata[field] = value
    with pytest.raises(InstallError, match='authenticated references differ'):
        verify(tmp_path, source, metadata)


@pytest.mark.parametrize('field,value', [
    ('sha256', 'f' * 64), ('sha256', 'a' * 64 + '\n'), ('size', True),
    ('size', 0), ('mode', 0o600), ('mode', True), ('extra', 'private'),
])
def test_authenticated_file_metadata_matches_exact_bytes_and_types(tmp_path, source, field, value):
    metadata = manifest(source)
    metadata['files']['LICENSE'][field] = value
    with pytest.raises(InstallError, match='authenticated references differ'):
        verify(tmp_path, source, metadata)


@pytest.mark.parametrize('kind', ['missing', 'extra', 'trust', 'tests'])
def test_manifest_file_set_is_exact(tmp_path, source, kind):
    metadata = manifest(source)
    if kind == 'missing':
        del metadata['files']['LICENSE']
    else:
        metadata['files'][{'extra': 'device/agent/extra.py',
                           'trust': 'iris-root.allowed_signers',
                           'tests': 'device/agent/tests/test_private.py'}[kind]] = metadata['files']['LICENSE']
    with pytest.raises(InstallError, match='authenticated references differ'):
        verify(tmp_path, source, metadata)


@pytest.mark.parametrize('kind', ['missing-license', 'wrong-hash', 'bad-digest', 'bad-path', 'empty'])
def test_installer_inventory_cannot_be_ignored(tmp_path, source, kind):
    metadata = manifest(source)
    inventory = dict(source[1])
    if kind == 'missing-license': del inventory['LICENSE']
    elif kind == 'wrong-hash': inventory['LICENSE'] = '0' * 64
    elif kind == 'bad-digest': inventory['LICENSE'] += '\n'
    elif kind == 'bad-path': inventory['../outside'] = '0' * 64
    else: inventory = {}
    with pytest.raises(InstallError):
        verify(tmp_path, (source[0], inventory), metadata)


@pytest.mark.parametrize('kind', ['bytes', 'mode', 'symlink', 'hardlink', 'fifo', 'ancestor-link', 'missing'])
def test_local_source_substitution_is_rejected(tmp_path, source, kind):
    metadata = manifest(source)
    target = source[0] / 'LICENSE'
    if kind == 'bytes': target.write_bytes(b'changed')
    elif kind == 'mode': target.chmod(0o600)
    elif kind == 'hardlink': os.link(target, source[0] / 'alias')
    elif kind == 'ancestor-link':
        original = source[0] / 'device'
        original.rename(source[0] / 'elsewhere')
        original.symlink_to('elsewhere', target_is_directory=True)
    else:
        target.unlink()
        if kind == 'symlink': target.symlink_to('NOTICE')
        elif kind == 'fifo': os.mkfifo(target)
    with pytest.raises((InstallError, OSError)):
        verify(tmp_path, source, metadata)


@pytest.mark.parametrize('kind', ['extra', 'missing', 'invalid-name'])
def test_actual_direct_agent_glob_matches_inventory(tmp_path, source, kind):
    metadata = manifest(source)
    path = source[0] / 'device/agent'
    if kind == 'missing': (path / 'runtime_verifier.py').unlink()
    else: (path / ('extra.py' if kind == 'extra' else '.hidden.py')).write_bytes(b'# extra')
    with pytest.raises(InstallError, match='agent files differ'):
        verify(tmp_path, source, metadata)


@pytest.mark.parametrize('kind', ['alias', 'wrong-pin', 'missing-pin', 'duplicate-pin', 'bad-pin'])
def test_both_committed_aria_architectures_and_alias_are_bound(tmp_path, source, kind):
    path = source[0] / ('bin/aria2c' if kind == 'alias' else 'tools/aria2c.sha256')
    data = path.read_bytes()
    pin = next(line for line in data.splitlines() if not line.startswith(b'#'))
    if kind == 'alias': data = b'wrong architecture'
    elif kind == 'wrong-pin': data = data.replace(pin[:64], b'f' * 64)
    elif kind == 'missing-pin': data = pin + b'\n'
    elif kind == 'duplicate-pin': data += pin + b'\n'
    else: data = b'bad pin\n'
    path.write_bytes(data)
    source[1][str(path.relative_to(source[0]))] = sha(data)
    with pytest.raises(InstallError, match='aria2'):
        g.build_guest_inputs(*source, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def custom_archive(raw, kind):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:') as archive:
        item = tarfile.TarInfo('../outside' if kind == 'path' else g.MANIFEST)
        item.size, item.mode = len(raw), 0o644
        if kind in ('symlink', 'hardlink', 'fifo', 'directory'):
            item.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE,
                         'fifo': tarfile.FIFOTYPE, 'directory': tarfile.DIRTYPE}[kind]
            item.linkname, item.size = 'outside', 0
        if kind == 'mode': item.mode = 0o755
        if kind == 'owner': item.uid = 1
        if kind == 'owner-name': item.uname = 'extra payload'
        if kind == 'mtime': item.mtime = 1
        archive.addfile(item, io.BytesIO(raw) if item.isfile() else None)
        if kind == 'duplicate': archive.addfile(item, io.BytesIO(raw))
        if kind == 'extra': archive.addfile(tarfile.TarInfo('extra'))
    value = stream.getvalue()
    if kind == 'trailing': value += b'hidden archive'
    if kind == 'truncated':
        with tarfile.open(fileobj=io.BytesIO(value)) as archive:
            list(archive)
            value = value[:archive.offset + 512]
    return gzip.compress(value)


@pytest.mark.parametrize('kind', ['path', 'symlink', 'hardlink', 'fifo', 'directory', 'mode',
                                 'owner', 'owner-name', 'mtime', 'duplicate', 'extra', 'trailing', 'truncated'])
def test_unsafe_or_extra_archive_entries_are_never_extracted(tmp_path, source, kind):
    data = custom_archive(g.f._json(manifest(source)), kind)
    with pytest.raises(InstallError):
        g.verify_guest_inputs(kit_for(tmp_path, data), *source)
    assert not (tmp_path / 'outside').exists()


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'\xff', b'{' ])
def test_strict_json_metadata(tmp_path, source, raw):
    with pytest.raises(InstallError):
        g.verify_guest_inputs(kit_for(tmp_path, g._bundle(raw)), *source)


def test_changed_kit_after_authentication_is_refused(tmp_path, source):
    kit = kit_for(tmp_path, g._bundle(g.f._json(manifest(source))))
    (kit.directory / g.BUNDLE).write_bytes(b'changed')
    with pytest.raises(InstallError, match='changed'):
        g.verify_guest_inputs(kit, *source)


def test_expansion_is_bounded(tmp_path, source):
    data = gzip.compress(b'\0' * (g.MAX_ARCHIVE + 1))
    with pytest.raises(InstallError, match='expansion limit'):
        g.verify_guest_inputs(kit_for(tmp_path, data), *source)


@pytest.mark.parametrize('kind', ['rewrite', 'new-agent'])
def test_source_mutation_during_read_is_refused(tmp_path, source, monkeypatch, kind):
    original = g._read_source
    def changed(path, **kwargs):
        result = original(path, **kwargs)
        if path.name == 'VERSION':
            target = source[0] / ('LICENSE' if kind == 'rewrite' else 'device/agent/new.py')
            target.write_bytes(b'changed during read')
        return result
    monkeypatch.setattr(g, '_read_source', changed)
    with pytest.raises(InstallError, match='changed'):
        g.build_guest_inputs(*source, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_output_collision_keeps_existing_files(tmp_path, source):
    output = tmp_path / 'output'
    output.mkdir()
    (output / 'owner').write_bytes(b'keep')
    with pytest.raises(InstallError, match='already exists'):
        g.build_guest_inputs(*source, output)
    assert (output / 'owner').read_bytes() == b'keep'


def test_parent_replacement_never_redirects_temporary_cleanup(tmp_path, source, monkeypatch):
    parent = tmp_path / 'parent'
    parent.mkdir(mode=0o700)
    moved = tmp_path / 'retained-parent'
    original = g._bundle
    sentinel = []
    def replaced(raw):
        stage = next(parent.glob('.iris-guest-*')).name
        parent.rename(moved)
        parent.mkdir(mode=0o700)
        foreign = parent / stage
        foreign.mkdir()
        marker = foreign / 'owner'
        marker.write_bytes(b'keep')
        sentinel.append(marker)
        return original(raw)
    monkeypatch.setattr(g, '_bundle', replaced)
    with pytest.raises(InstallError, match='parent changed'):
        g.build_guest_inputs(*source, parent / 'output')
    assert sentinel[0].read_bytes() == b'keep'
    assert list(moved.iterdir()) == []
    assert not (parent / 'output').exists()


def test_cli_accepts_installer_inventory_and_sanitizes_filesystem_failure(tmp_path, source, capsys):
    inventory = tmp_path / 'INSTALLER-SOURCE.json'
    inventory.write_text(json.dumps(source[1]))
    arguments = ['--source-dir', str(source[0]), '--source-manifest', str(inventory),
                 '--output-dir', str(tmp_path / 'output')]
    assert g.main(arguments) == 0
    assert str(tmp_path / 'output' / g.BUNDLE) in capsys.readouterr().out
    inventory.unlink()
    with pytest.raises(SystemExit) as error:
        g.main(arguments)
    assert error.value.code == 1
    assert 'source or filesystem operation failed' in capsys.readouterr().err
