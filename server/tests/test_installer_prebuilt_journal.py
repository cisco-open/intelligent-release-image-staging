# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Prebuilt acquisition checkpoints; synthetic kits are not signing evidence."""

import copy
import hashlib
import io
from pathlib import Path
import sys
import tarfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import prebuilt_install as subject, release_kit
from iris_installer.prebuilt_images import core_image_intent
from iris_installer.state import InstallError, Journal


INSTANCE = '12345678-1234-1234-1234-123456789abc'
IMAGE_ID = 'sha256:' + '9' * 64


@pytest.fixture
def kit(tmp_path):
    assets = tuple(release_kit.Asset(role, role + '.tar', 1, 'a' * 64,
                                    'docker-archive', ('linux/amd64',), 'sha256:' + 'b' * 64)
                   for role in ('server-image', 'console-image'))
    return release_kit.VerifiedKit(tmp_path, 'v2026.10.08', 'c' * 40,
                                   'd' * 64, 'e' * 64, 'f' * 64, '1' * 64, True, assets)


@pytest.fixture
def installation(tmp_path, kit):
    tmp_path.chmod(0o700)
    journal = Journal(tmp_path)
    journal.document = {'schema': 1, 'id': INSTANCE, 'completed': {},
                        'input_selection': release_kit.selection('prebuilt', kit=kit, offline=True),
                        'release_kit': {'directory': str(tmp_path / 'kit'),
                                        'verifier': '/usr/bin/gh', 'trusted_root': '/etc/iris-trust.json'}}
    journal.save()
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        assert argv[:3] == ['docker', 'image', 'ls']
        return b''

    return SimpleNamespace(journal=journal, base=tmp_path, _verified_kit=kit,
                           command=command, calls=calls)


def specs(installation, *services):
    return {service: {'image': subject.image_tag(installation, service), 'pull_policy': 'never'}
            for service in services}


def test_legacy_and_explicit_source_selection():
    assert not subject.selected({})
    assert not subject.selected({'input_selection': release_kit.selection()})


@pytest.mark.parametrize('selection', [None, {}, {'mode': 'prebuilt'}, {'schema': 'bad', 'mode': 'source'}])
def test_malformed_selection_never_falls_back_to_source(selection):
    with pytest.raises(InstallError):
        subject.selected({'input_selection': selection})


def test_source_mode_refuses_kit_locator():
    with pytest.raises(InstallError, match='conflicting'):
        subject.selected({'release_kit': {}})


def test_resume_authenticates_exact_recorded_kit(installation, kit, monkeypatch):
    calls = []

    def verify(directory, **kwargs):
        calls.append((directory, kwargs))
        return kit

    monkeypatch.setattr(release_kit, 'verify_kit', verify)
    assert subject.verify_selected(installation.journal) is kit
    assert calls == [(str(installation.base / 'kit'), {
        'tag': 'v2026.10.08', 'commit': 'c' * 40, 'verifier': '/usr/bin/gh',
        'trusted_root': '/etc/iris-trust.json', 'offline': True})]


def test_changed_authenticated_receipt_refuses_resume(installation, kit, monkeypatch):
    installation.journal.document['input_selection']['kit']['inventory_sha256'] = '2' * 64
    monkeypatch.setattr(release_kit, 'verify_kit', lambda *a, **k: kit)
    with pytest.raises(InstallError, match='changed'):
        subject.verify_selected(installation.journal)


@pytest.mark.parametrize('change', [{}, {'directory': 5}, {'unknown': 'field'}, {'trusted_root': []}])
def test_invalid_locator_stops_before_verification(installation, monkeypatch, change):
    if change:
        installation.journal.document['release_kit'].update(change)
    else:
        installation.journal.document.pop('release_kit')
    monkeypatch.setattr(release_kit, 'verify_kit', lambda *a, **k: pytest.fail('must not verify'))
    with pytest.raises(InstallError, match='location or verifier'):
        subject.verify_selected(installation.journal)


def test_import_intent_is_durable_before_mutation_and_resume_reuses_evidence(installation, monkeypatch):
    completed = installation.journal.document['completed']
    imports = []

    def import_image(kit, role, identity, workspace, runner, *, previous, intent):
        service = 'iris' if role == 'server-image' else 'console'
        from json import loads
        saved = loads(installation.journal.path.read_bytes())['completed']
        expected = core_image_intent(kit, role, identity)
        assert saved['prebuilt-intent-' + service] == expected
        assert workspace == installation.base and runner == installation.command
        if previous is None:
            assert intent == expected
        else:
            assert previous == saved['prebuilt-import-' + service]
            assert intent is None
        imports.append((role, previous))
        return dict(expected, image_id=IMAGE_ID)

    monkeypatch.setattr(subject, 'import_core_image', import_image)
    value = subject.acquire_images(installation, specs(installation, 'iris', 'console'))
    assert len(value) == 2 and set(value.values()) == {IMAGE_ID}
    assert completed['images'] == value
    first = copy.deepcopy(completed)
    assert subject.acquire_images(installation, specs(installation, 'iris', 'console')) == value
    assert completed == first
    assert len(imports) == 4 and all(previous for _, previous in imports[2:])


def test_interruption_retains_intent_without_claiming_completion(installation, monkeypatch):
    def interrupted(*args, **kwargs):
        raise InstallError('simulated interrupted import')

    monkeypatch.setattr(subject, 'import_core_image', interrupted)
    with pytest.raises(InstallError, match='interrupted'):
        subject.acquire_images(installation, specs(installation, 'iris'))
    completed = installation.journal.document['completed']
    assert set(completed) == {'prebuilt-intent-iris'}


def test_unrecorded_existing_tag_is_refused_before_intent(installation, monkeypatch):
    installation.command = lambda *a, **k: IMAGE_ID.encode()
    monkeypatch.setattr(subject, 'import_core_image', lambda *a, **k: pytest.fail('must not import'))
    with pytest.raises(InstallError, match='already exists'):
        subject.acquire_images(installation, specs(installation, 'iris'))
    assert installation.journal.document['completed'] == {}


def test_existing_intent_can_recover_without_fresh_adoption(installation, monkeypatch):
    intent = core_image_intent(installation._verified_kit, 'server-image', INSTANCE)
    installation.journal.document['completed']['prebuilt-intent-iris'] = intent
    installation.command = lambda *a, **k: pytest.fail('importer verifies pending recovery')

    def recover(*a, **kwargs):
        assert kwargs['intent'] == intent and kwargs['previous'] is None
        return dict(intent, image_id=IMAGE_ID)

    monkeypatch.setattr(subject, 'import_core_image', recover)
    assert subject.acquire_images(installation, specs(installation, 'iris')) == {intent['tag']: IMAGE_ID}


@pytest.mark.parametrize('change', [
    {'build': '.'}, {'pull_policy': 'always'}, {'image': 'owner:latest'},
])
def test_prebuilt_service_cannot_build_pull_or_replace_owner_tag(installation, change):
    value = specs(installation, 'iris')
    value['iris'].update(change)
    with pytest.raises(InstallError, match='disable builds'):
        subject.acquire_images(installation, value)
    assert not installation.calls
    assert not installation.journal.document['completed']


def test_unknown_image_checkpoint_is_not_adopted(installation):
    installation.journal.document['completed']['images'] = {'owner:latest': IMAGE_ID}
    with pytest.raises(InstallError, match='unfamiliar'):
        subject.acquire_images(installation, specs(installation, 'iris'))
    assert not installation.calls


def test_attached_kit_cannot_differ_from_journal_selection(installation):
    value = specs(installation, 'iris')
    installation.journal.document['input_selection']['kit']['manifest_sha256'] = '8' * 64
    with pytest.raises(InstallError, match='changed'):
        subject.acquire_images(installation, value)
    assert not installation.calls
    assert not installation.journal.document['completed']


@pytest.fixture
def source_kit(monkeypatch):
    runtime = Path(subject.__file__).parent
    files = {'tools/iris_installer/' + path.name: path.read_bytes() for path in runtime.glob('*.py')}
    files['VERSION'] = b'2026.10.08\n'
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}

    def make(changes=None, duplicate=False, link=False):
        content = dict(files)
        content.update(changes or {})
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            for name, value in content.items():
                if value is None:
                    continue
                member = tarfile.TarInfo('iris/' + name)
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
            if duplicate:
                archive.addfile(member, io.BytesIO(value))
            if link:
                member = tarfile.TarInfo('iris/unexpected')
                member.type, member.linkname = tarfile.SYMTYPE, '/etc/passwd'
                archive.addfile(member)

        def copy_asset(role, destination):
            assert role == 'source'
            destination.write_bytes(data.getvalue())

        return SimpleNamespace(copy_asset=copy_asset)

    return manifest, make


def test_source_and_installed_controller_must_match_authenticated_payload(tmp_path, source_kit):
    manifest, make = source_kit
    subject.bind_source(make(), manifest, tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('change', [{'VERSION': b'wrong\n'}, {'VERSION': None}])
def test_mixed_source_release_is_refused(tmp_path, source_kit, change):
    manifest, make = source_kit
    with pytest.raises(InstallError, match='differs|omits'):
        subject.bind_source(make(change), manifest, tmp_path)


@pytest.mark.parametrize('options', [{'duplicate': True}, {'link': True}])
def test_source_archive_cannot_alias_paths(tmp_path, source_kit, options):
    manifest, make = source_kit
    with pytest.raises(InstallError, match='unsupported'):
        subject.bind_source(make(**options), manifest, tmp_path)


def test_supplied_source_cannot_upgrade_installed_controller(tmp_path, source_kit):
    manifest, make = source_kit
    name = 'tools/iris_installer/prebuilt_install.py'
    replacement = b'not the installed controller\n'
    manifest[name] = hashlib.sha256(replacement).hexdigest()
    with pytest.raises(InstallError, match='matching installer'):
        subject.bind_source(make({name: replacement}), manifest, tmp_path)
