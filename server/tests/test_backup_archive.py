# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real age/OpenSSH round trips of private disposable backup fixtures."""

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import backup_archive as archive
from iris_installer.state import InstallError


@pytest.fixture
def recovery(tmp_path):
    tmp_path.chmod(0o700)
    identity, signer = tmp_path / 'recovery-key', tmp_path / 'signer'
    subprocess.run(['age-keygen', '-o', str(identity)], check=True, capture_output=True)
    recipient = subprocess.check_output(['age-keygen', '-y', str(identity)], text=True).strip()
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(signer)], check=True)
    source = tmp_path / 'source'
    source.mkdir(mode=0o700)
    (source / 'config.age').write_bytes(b'encrypted configuration fixture')
    (source / 'images').mkdir()
    (source / 'images' / 'example.bin').write_bytes(b'image bytes' * 10000)
    return {'directory': tmp_path, 'source': source, 'identity': identity,
            'signer': signer, 'recipient': recipient, 'public': Path(str(signer) + '.pub')}


def capture(recovery, name='backup'):
    destination = recovery['directory'] / name
    archive.create({'state': recovery['source']}, destination,
                   recovery['recipient'], recovery['signer'], metadata={'instance': 'fixture'})
    return destination


def test_signed_encrypted_roundtrip_and_restrictive_restore(recovery):
    backup = capture(recovery)
    assert b'image bytes' not in (backup / 'payload.tar.age').read_bytes()
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in backup.iterdir())
    report = archive.read(backup, recovery['identity'], recovery['public'])
    assert report['state'] == 'verified-files'
    assert report['cutover_permitted'] is False
    restored = recovery['directory'] / 'restore'
    result = archive.read(backup, recovery['identity'], recovery['public'], destination=restored)
    assert result['state'] == 'verified-isolated-files'
    for path in recovery['source'].rglob('*'):
        relative = path.relative_to(recovery['source'])
        if path.is_file():
            assert (restored / 'state' / relative).read_bytes() == path.read_bytes()
            assert (restored / 'state' / relative).stat().st_mode & 0o777 == 0o600
    assert (restored / 'RESTORE-INVENTORY.json').exists()


def test_bounded_pax_preserves_long_unicode_paths(recovery):
    name = 'long-' + 'image-' * 20 + 'å.bin'
    (recovery['source'] / name).write_bytes(b'long unicode name')
    backup = capture(recovery)
    destination = recovery['directory'] / 'restore'
    archive.read(backup, recovery['identity'], recovery['public'], destination=destination)
    assert (destination / 'state' / name).read_bytes() == b'long unicode name'


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo'])
def test_capture_rejects_links_and_special_files(recovery, kind):
    path = recovery['source'] / 'unsafe'
    if kind == 'symlink': path.symlink_to(recovery['identity'])
    if kind == 'hardlink': os.link(recovery['identity'], path)
    if kind == 'fifo': os.mkfifo(path)
    with pytest.raises(InstallError):
        capture(recovery)
    assert not (recovery['directory'] / 'backup').exists()
    assert not list(recovery['directory'].glob('.iris-backup-*'))


def test_rejects_existing_destinations_and_output_inside_source(recovery):
    backup = capture(recovery)
    with pytest.raises(InstallError, match='exists'):
        capture(recovery)
    with pytest.raises(InstallError, match='outside'):
        archive.create({'state': recovery['source']}, recovery['source'] / 'recursive',
                       recovery['recipient'], recovery['signer'])
    restored = recovery['directory'] / 'existing'
    restored.mkdir()
    with pytest.raises(InstallError, match='must not exist'):
        archive.read(backup, recovery['identity'], recovery['public'], destination=restored)


@pytest.mark.parametrize('target', ['manifest.json', 'manifest.json.sig', 'payload.tar.age'])
def test_tamper_fails_before_extraction(recovery, target):
    backup = capture(recovery)
    (backup / target).write_bytes((backup / target).read_bytes() + b'tamper')
    restored = recovery['directory'] / 'restore'
    with pytest.raises(InstallError):
        archive.read(backup, recovery['identity'], recovery['public'], destination=restored)
    assert not restored.exists()


def test_wrong_recovery_identity_and_size_limit(recovery):
    backup = capture(recovery)
    other = recovery['directory'] / 'wrong-key'
    subprocess.run(['age-keygen', '-o', str(other)], check=True, capture_output=True)
    for identity, limit in [(other, 1024**4), (recovery['identity'], 1)]:
        restored = recovery['directory'] / 'restore'
        with pytest.raises(InstallError):
            archive.read(backup, identity, recovery['public'], destination=restored, max_bytes=limit)
        assert not restored.exists()
        assert not list(recovery['directory'].glob('.iris-restore-*'))


def test_archive_cannot_supply_its_own_trust(recovery):
    backup = capture(recovery)
    other = recovery['directory'] / 'other-signer'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)], check=True)
    with pytest.raises(InstallError, match='trusted signer'):
        archive.read(backup, recovery['identity'], Path(str(other) + '.pub'))


def test_ciphertext_replacement_after_authentication_is_rejected(recovery, monkeypatch):
    first = capture(recovery, 'first')
    source = recovery['source'] / 'config.age'
    source.write_bytes(source.read_bytes().upper())
    second = capture(recovery, 'second')
    replacement = (second / 'payload.tar.age').read_bytes()
    assert len(replacement) == (first / 'payload.tar.age').stat().st_size
    original = archive.authenticate
    def replace_after_check(backup, public):
        result = original(backup, public)
        (first / 'payload.tar.age').write_bytes(replacement)
        return result
    monkeypatch.setattr(archive, 'authenticate', replace_after_check)
    destination = recovery['directory'] / 'restore'
    with pytest.raises(InstallError, match='changed during verification'):
        archive.read(first, recovery['identity'], recovery['public'], destination=destination)
    assert not destination.exists()


@pytest.mark.parametrize('fields', [{'GNU.sparse.map': ''}, {'GNU.sparse.size': '0'},
                                   {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0'}])
def test_pax_sparse_maps_rejected_before_expansion(recovery, fields):
    header = tarfile.TarInfo('sparse')
    header.pax_headers = fields
    backup = forged_archive(recovery, [(header, b'')])
    with pytest.raises(InstallError, match='Sparse archive extensions'):
        archive.read(backup, recovery['identity'], recovery['public'], max_bytes=1)


def forged_archive(recovery, members):
    """A validly signed but structurally malicious fixture."""
    backup = recovery['directory'] / 'crafted'
    backup.mkdir(mode=0o700)
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w') as tar:
        for header, body in members:
            tar.addfile(header, io.BytesIO(body))
    encrypted = subprocess.check_output(['age', '-r', recovery['recipient']], input=payload.getvalue())
    (backup / 'payload.tar.age').write_bytes(encrypted)
    import hashlib
    metadata = {'schema': archive.SCHEMA, 'created_at': 0, 'payload_sha256': hashlib.sha256(encrypted).hexdigest(),
                'payload_bytes': len(encrypted), 'recipient': recovery['recipient']}
    (backup / 'manifest.json').write_text(json.dumps(metadata))
    subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(recovery['signer']), '-n', archive.NAMESPACE,
                    str(backup / 'manifest.json')], check=True, capture_output=True)
    return backup


@pytest.mark.parametrize('name,type_', [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                                       ('.', tarfile.DIRTYPE),
                                       ('RESTORE-INVENTORY.json', tarfile.REGTYPE),
                                       ('link', tarfile.SYMTYPE), ('device', tarfile.CHRTYPE),
                                       ('a//b', tarfile.REGTYPE)])
def test_malicious_signed_archive_cannot_escape(recovery, name, type_):
    header = tarfile.TarInfo(name)
    header.type, header.linkname = type_, '/etc/passwd'
    backup = forged_archive(recovery, [(header, b'')])
    destination = recovery['directory'] / 'restore'
    with pytest.raises(InstallError):
        archive.read(backup, recovery['identity'], recovery['public'], destination=destination)
    assert not destination.exists()


@pytest.mark.parametrize('kind', ['oversized', 'chained', 'global', 'gnu-longname', 'sparse'])
def test_metadata_is_bounded_before_tarfile_expansion(recovery, kind):
    header = tarfile.TarInfo('extension')
    header.type = {'global': tarfile.XGLTYPE, 'gnu-longname': tarfile.GNUTYPE_LONGNAME,
                   'sparse': tarfile.GNUTYPE_SPARSE}.get(kind, tarfile.XHDTYPE)
    body = b'\x00' * (archive.MAX_EXTENSION + 1) if kind == 'oversized' else b''
    header.size = len(body)
    members = [(header, body)]
    if kind == 'chained':
        members.append((header, b''))
    members.append((tarfile.TarInfo('empty'), b''))
    backup = forged_archive(recovery, members)
    destination = recovery['directory'] / 'restore'
    with pytest.raises(InstallError, match='archive extension|header type'):
        archive.read(backup, recovery['identity'], recovery['public'],
                     destination=destination, max_bytes=1)
    assert not destination.exists()
