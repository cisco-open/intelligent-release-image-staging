# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Only authenticated core image bytes enter a new owned Docker tag."""

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer.prebuilt_images import core_image_intent, import_core_image
from iris_installer.state import InstallError


INSTANCE = '12345678-1234-1234-1234-123456789abc'
CONFIG = json.dumps({'os': 'linux', 'architecture': 'amd64', 'rootfs': {}}).encode()
CONFIG_DIGEST = 'sha256:' + hashlib.sha256(CONFIG).hexdigest()
# A containerd image ID need not equal the image config digest.
IMAGE_ID = 'sha256:' + '7' * 64


class Kit:
    def __init__(self):
        self.copied = []

    def asset(self, role):
        assert role in ('server-image', 'console-image')
        return SimpleNamespace(format='docker-archive', platforms=('linux/amd64',),
                               config_digest=CONFIG_DIGEST)

    def receipt(self):
        return {'commit': 'a' * 40, 'offline': True}

    def copy_asset(self, role, destination):
        assert destination.parent.stat().st_mode & 0o777 == 0o700
        assert not destination.exists()
        destination.write_bytes(b'authenticated archive fixture')
        self.copied.append(destination)


@pytest.fixture
def importer(tmp_path):
    tmp_path.chmod(0o700)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[:3] == ['docker', 'image', 'ls']:
            return b''
        if command[:3] == ['docker', 'image', 'inspect']:
            return IMAGE_ID.encode() + b'\n'
        if command[:4] == ['skopeo', 'inspect', '--config', '--raw']:
            return CONFIG
        assert command[:2] == ['skopeo', 'copy']
        assert command[2].startswith('docker-archive:')
        assert command[3].startswith('docker-daemon:iris-installer-prebuilt:')
        return b''

    return Kit(), tmp_path, run, calls


@pytest.mark.parametrize('role', ['server-image', 'console-image'])
def test_import_uses_explicit_owned_tag_not_archive_tags(importer, role):
    kit, work, run, calls = importer
    receipt = import_core_image(kit, role, INSTANCE, work, run)
    assert receipt['image_id'] == IMAGE_ID
    assert receipt['config_digest'] == CONFIG_DIGEST
    assert receipt['kit'] == kit.receipt()
    assert len(kit.copied) == 1 and not kit.copied[0].exists()
    assert list(work.iterdir()) == []
    assert not any('load' in command or 'pull' in command or 'build' in command for command in calls)
    assert sum(command[:2] == ['skopeo', 'copy'] for command in calls) == 1


def test_recorded_import_is_verified_without_copy_or_mutation(importer):
    kit, work, run, calls = importer
    receipt = import_core_image(kit, 'server-image', INSTANCE, work, run)
    calls.clear()
    assert import_core_image(kit, 'server-image', INSTANCE, work, run, previous=receipt) == receipt
    assert len(kit.copied) == 1
    assert all(command[:3] == ['docker', 'image', 'inspect'] or command[:2] == ['skopeo', 'inspect']
               for command in calls)


def test_unrecorded_existing_tag_is_not_overwritten(importer):
    kit, work, _, _ = importer
    with pytest.raises(InstallError, match='refusing replacement'):
        import_core_image(kit, 'server-image', INSTANCE, work, lambda *_a, **_k: IMAGE_ID.encode())
    assert not kit.copied


def test_journaled_intent_recovers_import_before_completed_checkpoint(importer):
    kit, work, run, calls = importer
    intent = core_image_intent(kit, 'server-image', INSTANCE)

    def existing(command, **kwargs):
        if command[:3] == ['docker', 'image', 'ls']:
            return IMAGE_ID.encode()
        return run(command, **kwargs)

    receipt = import_core_image(kit, 'server-image', INSTANCE, work, existing, intent=intent)
    assert receipt == dict(intent, image_id=IMAGE_ID)
    assert not kit.copied
    assert not any(command[:2] == ['skopeo', 'copy'] for command in calls)


def test_changed_pending_intent_fails_before_any_mutation(importer):
    kit, work, run, calls = importer
    intent = core_image_intent(kit, 'console-image', INSTANCE)
    with pytest.raises(InstallError, match='Pending image import differs'):
        import_core_image(kit, 'server-image', INSTANCE, work, run, intent=intent)
    assert not calls and not kit.copied


@pytest.mark.parametrize('changed', ['kit', 'config_digest', 'tag', 'extra'])
def test_resume_rejects_changed_identity_before_daemon_access(importer, changed):
    kit, work, run, _ = importer
    previous = import_core_image(kit, 'server-image', INSTANCE, work, run)
    previous[changed] = 'changed'
    with pytest.raises(InstallError, match='selection changed'):
        import_core_image(kit, 'server-image', INSTANCE, work,
                          lambda *_a, **_k: pytest.fail('No daemon call'), previous=previous)


@pytest.mark.parametrize('bad', [b'{}', CONFIG + b'\n', b'not-json'])
def test_changed_archive_configuration_stops_before_import(importer, bad):
    kit, work, run, calls = importer

    def changed(command, **kwargs):
        if command[:2] == ['skopeo', 'inspect']:
            return bad
        return run(command, **kwargs)

    with pytest.raises(InstallError, match='configuration differs'):
        import_core_image(kit, 'server-image', INSTANCE, work, changed)
    assert not any(command[:2] == ['skopeo', 'copy'] for command in calls)
    assert list(work.iterdir()) == []


def test_import_id_drift_fails_without_deleting_unproven_image(importer):
    kit, work, run, calls = importer
    reads = []

    def changed(command, **kwargs):
        if command[:3] == ['docker', 'image', 'inspect']:
            reads.append(command)
            return (IMAGE_ID if len(reads) == 1 else 'sha256:' + '8' * 64).encode()
        return run(command, **kwargs)

    with pytest.raises(InstallError, match='changed during verification'):
        import_core_image(kit, 'server-image', INSTANCE, work, changed)
    assert not any('rm' in command for command in calls)


def test_unsafe_workspace_refused_before_payload_copy(importer):
    kit, work, run, calls = importer
    work.chmod(0o755)
    with pytest.raises(InstallError, match='mode-0700'):
        import_core_image(kit, 'server-image', INSTANCE, work, run)
    assert not kit.copied and not calls


@pytest.mark.parametrize('identity', ['', 'server', '../other', INSTANCE.upper()])
def test_invalid_installation_identity_refused(importer, identity):
    kit, work, run, calls = importer
    with pytest.raises(InstallError, match='recorded installation identity'):
        import_core_image(kit, 'server-image', identity, work, run)
    assert not calls
