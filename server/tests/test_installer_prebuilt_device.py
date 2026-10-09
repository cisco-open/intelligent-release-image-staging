# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real neutral finalization and crash recovery with synthetic public fixtures."""

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import device_finalize, prebuilt_device as subject, release_kit
from iris_installer.state import InstallError, Journal
from test_device_finalize import image_bytes, roots  # public-only synthetic fixture


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def installation(tmp_path, roots):
    tmp_path.chmod(0o700)
    payload = image_bytes()[0]
    source = tmp_path / 'neutral.oci.tar'
    source.write_bytes(payload)
    neutral = device_finalize.inspect_neutral(source, expected_archive_sha256=digest(payload))
    asset = release_kit.Asset('device-runtime', source.name, len(payload), digest(payload),
                             'oci-archive', ('linux/amd64', 'linux/arm64'), neutral['index_digest'], 'a' * 64)
    kit = release_kit.VerifiedKit(tmp_path, 'v2026.10.08', 'b' * 40, 'c' * 64, 'd' * 64,
                                  'e' * 64, 'f' * 64, True, (asset,))
    journal = Journal(tmp_path)
    journal.document = {'schema': 1, 'id': '12345678-1234-1234-1234-123456789abc', 'config': {},
                        'completed': {}, 'input_selection': release_kit.selection('prebuilt', kit=kit, offline=True),
                        'root_digests': {path.name: digest(path.read_bytes()) for path in roots.iterdir()},
                        'source_manifest': {
                            'tools/iris_installer/device_finalize.py': digest(Path(device_finalize.__file__).read_bytes()),
                            'server/instruction_keys.py': digest(Path(device_finalize.instruction_module().__file__).read_bytes())}}
    journal.save()
    return SimpleNamespace(base=tmp_path, journal=journal, _verified_kit=kit)


def test_finalization_records_exact_inputs_outputs_and_reuses_without_rebuild(installation, monkeypatch):
    directory, receipt_hash = subject.prepare_runtime(installation)
    assert directory == installation.base / subject.OUTPUT
    assert digest((directory / subject.RECEIPT).read_bytes()) == receipt_hash
    saved = installation.journal.document['completed']['prebuilt-device-runtime']
    assert saved['finalization_sha256'] == receipt_hash
    receipt = json.loads((directory / subject.RECEIPT).read_bytes())
    assert receipt['root_files_sha256'] == installation.journal.document['root_digests']
    assert receipt['neutral_source_sha256'] == 'a' * 64
    assert set(receipt['platforms']) == {'amd64', 'arm64'}
    monkeypatch.setattr(device_finalize, 'finalize', lambda *a, **k: pytest.fail('Recorded output must be reused'))
    assert subject.prepare_runtime(installation) == (directory, receipt_hash)


def interrupt_checkpoint(installation, monkeypatch):
    checkpoint = installation.journal.checkpoint

    def interrupted(stage, evidence):
        if stage == 'prebuilt-device-runtime':
            raise InstallError('simulated failure after atomic finalization')
        return checkpoint(stage, evidence)

    monkeypatch.setattr(installation.journal, 'checkpoint', interrupted)
    with pytest.raises(InstallError, match='simulated failure'):
        subject.prepare_runtime(installation)
    monkeypatch.setattr(installation.journal, 'checkpoint', checkpoint)
    assert 'prebuilt-device-intent' in installation.journal.document['completed']
    assert 'prebuilt-device-runtime' not in installation.journal.document['completed']
    return installation.base / subject.OUTPUT


def test_interrupted_publication_reproduces_exact_bytes_before_adopting(installation, monkeypatch):
    directory = interrupt_checkpoint(installation, monkeypatch)
    before = {path.name: path.read_bytes() for path in directory.iterdir()}
    original = device_finalize.finalize
    calls = []

    def reproduced(*args, **kwargs):
        calls.append(args[2])
        return original(*args, **kwargs)

    monkeypatch.setattr(device_finalize, 'finalize', reproduced)
    assert subject.prepare_runtime(installation)[0] == directory
    assert len(calls) == 1 and calls[0] != directory
    assert {path.name: path.read_bytes() for path in directory.iterdir()} == before
    assert not list(installation.base.glob('device-finalization-*'))


def test_interrupted_finalization_recovers_from_reloaded_durable_journal(installation, monkeypatch):
    directory = interrupt_checkpoint(installation, monkeypatch)
    original_hash = digest((directory / subject.RECEIPT).read_bytes())
    with Journal(installation.base).locked() as reloaded:
        assert reloaded is not installation.journal
        assert 'prebuilt-device-runtime' not in reloaded.document['completed']
        resumed = SimpleNamespace(base=installation.base, journal=reloaded, _verified_kit=installation._verified_kit)
        assert subject.prepare_runtime(resumed) == (directory, original_hash)
    with Journal(installation.base).locked() as reloaded:
        assert reloaded.document['completed']['prebuilt-device-runtime']['finalization_sha256'] == original_hash


def test_interrupted_output_is_never_replaced_if_changed(installation, monkeypatch):
    directory = interrupt_checkpoint(installation, monkeypatch)
    target = directory / subject.ARCHIVE
    target.chmod(0o600)
    target.write_bytes(b'changed output')
    with pytest.raises(InstallError, match='differs from its receipt'):
        subject.prepare_runtime(installation)
    assert target.read_bytes() == b'changed output'
    assert 'prebuilt-device-runtime' not in installation.journal.document['completed']


@pytest.mark.parametrize('change', ['archive', 'receipt', 'extra', 'symlink', 'directory-mode'])
def test_recorded_cache_drift_refuses_reuse(installation, change):
    directory, _ = subject.prepare_runtime(installation)
    if change in ('archive', 'receipt'):
        target = directory / (subject.ARCHIVE if change == 'archive' else subject.RECEIPT)
        target.chmod(0o600)
        target.write_bytes(b'changed')
    elif change == 'extra':
        (directory / 'unexpected').write_bytes(b'other')
    elif change == 'symlink':
        original = directory / subject.ARCHIVE
        moved = installation.base / 'moved.oci.tar'
        original.rename(moved)
        original.symlink_to(moved)
    else:
        directory.chmod(0o755)
    with pytest.raises((InstallError, OSError)):
        subject.prepare_runtime(installation)


@pytest.mark.parametrize('change', ['roots', 'recorded-roots', 'source', 'kit'])
def test_changed_inputs_refuse_reuse(installation, change):
    directory, _ = subject.prepare_runtime(installation)
    if change in ('roots', 'recorded-roots'):
        target = installation.base / 'roots/root-a.pub'
        target.write_bytes(target.read_bytes().replace(b'fixture public root', b'changed public comment'))
        if change == 'recorded-roots':
            installation.journal.document['root_digests'][target.name] = digest(target.read_bytes())
    elif change == 'source':
        installation.journal.document['source_manifest']['tools/iris_installer/device_finalize.py'] = '0' * 64
    else:
        installation.journal.document['input_selection']['kit']['manifest_sha256'] = '1' * 64
    with pytest.raises(InstallError):
        subject.prepare_runtime(installation)
    assert directory.is_dir()


def test_unrecorded_output_is_not_adopted(installation):
    output = installation.base / subject.OUTPUT
    output.mkdir(mode=0o700)
    (output / 'owner').write_bytes(b'preserve')
    with pytest.raises(InstallError, match='unrecorded'):
        subject.prepare_runtime(installation)
    assert (output / 'owner').read_bytes() == b'preserve'
    assert not installation.journal.document['completed']


def test_completed_output_without_original_intent_is_refused(installation):
    subject.prepare_runtime(installation)
    installation.journal.document['completed'].pop('prebuilt-device-intent')
    with pytest.raises(InstallError, match='Recorded device finalization'):
        subject.prepare_runtime(installation)


def test_archive_failure_preserves_intent_but_does_not_claim_completion(installation, monkeypatch):
    def failed(*args, **kwargs):
        raise InstallError('invalid neutral runtime')

    monkeypatch.setattr(device_finalize, 'finalize', failed)
    with pytest.raises(InstallError, match='invalid neutral'):
        subject.prepare_runtime(installation)
    assert set(installation.journal.document['completed']) == {'prebuilt-device-intent'}
    assert not (installation.base / subject.OUTPUT).exists()
    assert not list(installation.base.glob('device-finalization-*'))
