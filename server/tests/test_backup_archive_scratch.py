# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real OpenSSH/age checks: authentication and verification leave no named output."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile

import pytest

from test_backup_archive import archive, capture, recovery
from iris_installer.state import InstallError


@pytest.mark.parametrize('fallback', [False, True])
def test_openssh_uses_only_unlinked_private_metadata_descriptors(recovery, monkeypatch, fallback):
    backup = capture(recovery)
    before = set(recovery['directory'].iterdir())
    if fallback:
        # Exercise stdlib's actual open/unlink fallback, not a fake file object.
        monkeypatch.setattr(tempfile, '_O_TMPFILE_WORKS', False)
    original = subprocess.run
    observed = []

    def inspect(argv, **kwargs):
        assert argv[:3] == ['ssh-keygen', '-Y', 'verify']
        descriptors = kwargs['pass_fds']
        assert len(descriptors) == 2 and len(set(descriptors)) == 2
        assert argv[argv.index('-f') + 1] == '/proc/self/fd/' + str(descriptors[0])
        assert argv[argv.index('-s') + 1] == '/proc/self/fd/' + str(descriptors[1])
        for descriptor in descriptors:
            info = os.fstat(descriptor)
            assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            assert info.st_uid == os.geteuid() and info.st_nlink == 0
            assert not os.get_inheritable(descriptor)
        observed.extend(descriptors)
        return original(argv, **kwargs)

    monkeypatch.setattr(subprocess, 'run', inspect)
    assert archive.authenticate(backup, recovery['public'])['schema'] == archive.SCHEMA
    assert set(recovery['directory'].iterdir()) == before
    assert len(observed) == 2
    for descriptor in observed:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_openssh_cannot_open_metadata_without_explicit_descriptor_inheritance(recovery, monkeypatch):
    backup = capture(recovery)
    before = set(recovery['directory'].iterdir())
    original = subprocess.run

    def omit(argv, **kwargs):
        kwargs.pop('pass_fds')
        return original(argv, **kwargs)

    monkeypatch.setattr(subprocess, 'run', omit)
    with pytest.raises(InstallError, match='not valid for the trusted signer'):
        archive.authenticate(backup, recovery['public'])
    assert set(recovery['directory'].iterdir()) == before


def test_metadata_creation_failure_closes_first_descriptor_without_named_fallback(recovery, monkeypatch):
    backup = capture(recovery)
    before = set(recovery['directory'].iterdir())
    original = tempfile.TemporaryFile
    opened = []

    def fail_second(**kwargs):
        if opened:
            raise OSError('private host-path canary must not be exposed')
        opened.append(original(**kwargs))
        return opened[0]

    monkeypatch.setattr(tempfile, 'TemporaryFile', fail_second)
    with pytest.raises(InstallError, match='not valid for the trusted signer') as error:
        archive.authenticate(backup, recovery['public'])
    assert 'canary' not in str(error.value) and opened[0].closed
    assert set(recovery['directory'].iterdir()) == before


def test_linked_metadata_is_refused_before_openssh(recovery, monkeypatch):
    backup = capture(recovery)
    before = set(recovery['directory'].iterdir())
    monkeypatch.setattr(tempfile, 'TemporaryFile', tempfile.NamedTemporaryFile)
    monkeypatch.setattr(subprocess, 'run', lambda *_a, **_k: pytest.fail('linked metadata reached OpenSSH'))
    with pytest.raises(InstallError, match='anonymous private metadata'):
        archive.authenticate(backup, recovery['public'])
    assert set(recovery['directory'].iterdir()) == before


@pytest.mark.parametrize('valid_identity', [False, True])
def test_verify_only_age_reads_never_allocate_a_directory(recovery, monkeypatch, valid_identity):
    backup = capture(recovery)
    identity = recovery['identity']
    if not valid_identity:
        identity = recovery['directory'] / 'wrong-identity'
        subprocess.run(['age-keygen', '-o', str(identity)], check=True, capture_output=True)
    before = set(recovery['directory'].iterdir())
    monkeypatch.setattr(tempfile, 'TemporaryDirectory', lambda **_kwargs: pytest.fail('verification allocated a stage'))
    if valid_identity:
        assert archive.read(backup, identity, recovery['public'])['state'] == 'verified-files'
    else:
        with pytest.raises(InstallError):
            archive.read(backup, identity, recovery['public'])
    assert set(recovery['directory'].iterdir()) == before


def test_real_extraction_still_uses_private_sibling_stage_and_atomic_publication(recovery, monkeypatch):
    backup = capture(recovery)
    destination = recovery['directory'] / 'isolated'
    original = tempfile.TemporaryDirectory
    stages = []

    def inspect(**kwargs):
        assert kwargs == {'prefix': '.iris-restore-', 'dir': recovery['directory']}
        stage = original(**kwargs)
        assert stat.S_IMODE(os.stat(stage.name).st_mode) == 0o700
        assert not destination.exists()
        stages.append(stage.name)
        return stage

    monkeypatch.setattr(tempfile, 'TemporaryDirectory', inspect)
    result = archive.read(backup, recovery['identity'], recovery['public'], destination=destination)
    assert result['state'] == 'verified-isolated-files' and result['cutover_permitted'] is False
    assert len(stages) == 1 and not os.path.exists(stages[0])
    assert (destination / 'RESTORE-INVENTORY.json').is_file()
    assert (destination / 'state/images/example.bin').read_bytes() == (recovery['source'] / 'images/example.bin').read_bytes()


def test_docs_distinguish_output_free_reads_from_retained_extraction_and_legacy_files():
    root = Path(__file__).resolve().parents[2]
    public = (root / 'docs/zensical/admin-guide/backups.md').read_text()
    developer = (root / 'docs/dev/installer.md').read_text()
    assert 'Verification and initial restore checks leave no temporary output' in public
    assert 'Partial\nextraction files remain private' in public
    assert 'Unrecognized files remain in place' in public
    for phrase in ('anonymous, mode-0600 public metadata', '`/proc/self/fd`',
                   'without creating a directory', 'private sibling stage',
                   'older attempts remain unadopted'):
        assert phrase in developer
