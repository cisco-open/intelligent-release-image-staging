# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bind authenticated prebuilt inputs to the existing installation journal.

Acquisition changes only: topology adapters retain ownership, signing, runtime
verification and account-claim responsibilities. No kit code is imported here.
"""

import hashlib
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

from . import release_kit
from .prebuilt_images import core_image_intent, import_core_image
from .state import InstallError


SERVICE_ROLES = {'iris': 'server-image', 'console': 'console-image'}


def selected(document):
    """Old journals remain source builds; malformed new selections never do."""
    value = document.get('input_selection', release_kit.selection())
    release_kit.assert_resume_selection(value, value)
    if value['mode'] == 'source' and 'release_kit' in document:
        raise InstallError('Source-build journal contains a conflicting release kit')
    return value['mode'] == 'prebuilt'


def verify_selected(journal):
    if not selected(journal.document):
        return None
    locator = journal.document.get('release_kit')
    if (not isinstance(locator, dict) or set(locator) != {'directory', 'verifier', 'trusted_root'}
            or any(not isinstance(locator[key], str) for key in ('directory', 'verifier'))
            or (locator['trusted_root'] is not None and not isinstance(locator['trusted_root'], str))):
        raise InstallError('Recorded release kit location or verifier is invalid')
    previous = journal.document['input_selection']
    receipt = previous['kit']
    kit = release_kit.verify_kit(
        locator['directory'], tag=receipt['tag'], commit=receipt['commit'],
        verifier=locator['verifier'], trusted_root=locator['trusted_root'], offline=receipt['offline'])
    release_kit.assert_resume_selection(previous, release_kit.selection('prebuilt', kit=kit, offline=kit.offline))
    return kit


def bind_source(kit, manifest, workspace):
    """Require the installed source snapshot to match the authenticated source.

    This reads bounded archive members without extracting them. The separate
    source snapshot verifier checks their on-disk bytes before any execution.
    """
    if not isinstance(manifest, dict) or not manifest:
        raise InstallError('Prebuilt installation needs the matching installer source inventory')
    seen, matched = set(), set()
    with tempfile.TemporaryDirectory(prefix='kit-source-', dir=workspace) as directory:
        archive_path = Path(directory) / 'source.tar.gz'
        kit.copy_asset('source', archive_path)
        try:
            with tarfile.open(archive_path, mode='r:gz') as archive:
                total = 0
                for member in archive:
                    path = PurePosixPath(member.name)
                    name = str(path)
                    if (name in seen or len(seen) >= 100000 or path.is_absolute()
                            or '..' in path.parts or not path.parts or path.parts[0] != 'iris'
                            or member.name.rstrip('/') != name
                            or not (member.isdir() or member.isfile()) or member.size < 0):
                        raise InstallError('Authenticated source archive has unsupported entries')
                    seen.add(name)
                    total += member.size
                    if total > 16 * 1024 ** 3:
                        raise InstallError('Authenticated source archive exceeds supported bounds')
                    relative = '/'.join(path.parts[1:])
                    if relative not in manifest:
                        continue
                    if not member.isfile():
                        raise InstallError('Installer source differs from the selected release')
                    stream = archive.extractfile(member)
                    with stream:
                        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                    if digest != manifest[relative]:
                        raise InstallError('Installer source differs from the selected release')
                    matched.add(relative)
        except (OSError, EOFError, tarfile.TarError):
            raise InstallError('Authenticated source archive could not be checked') from None
    if matched != set(manifest):
        raise InstallError('Release kit omits files required by this installer')
    # A different installed controller must not execute a newer kit's scripts
    # merely because its source tree was supplied separately.
    runtime = Path(__file__).resolve().parent
    actual = {path.name for path in runtime.glob('*.py')}
    expected = {PurePosixPath(name).name for name in manifest
                if str(PurePosixPath(name).parent) == 'tools/iris_installer' and name.endswith('.py')}
    if actual != expected:
        raise InstallError('Release kit requires its matching installer package')
    for name in sorted(actual):
        with (runtime / name).open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != manifest['tools/iris_installer/' + name]:
                raise InstallError('Release kit requires its matching installer package')


def _kit(installation):
    kit = getattr(installation, '_verified_kit', None)
    if kit is None or not selected(installation.journal.document):
        raise InstallError('Authenticate the selected prebuilt kit before image import')
    release_kit.assert_resume_selection(
        installation.journal.document['input_selection'],
        release_kit.selection('prebuilt', kit=kit, offline=kit.offline))
    return kit


def image_tag(installation, service):
    role = SERVICE_ROLES.get(service)
    if role is None:
        raise InstallError('Unknown prebuilt core service')
    kit = _kit(installation)
    return core_image_intent(kit, role, installation.journal.document['id'])['tag']


def acquire_images(installation, specs):
    """Write import intent first, then verified completion; resume never builds."""
    kit = _kit(installation)
    completed = installation.journal.document['completed']
    saved = completed.get('images', {})
    allowed_tags = {image_tag(installation, service) for service in SERVICE_ROLES}
    if not isinstance(saved, dict) or set(saved) - allowed_tags:
        raise InstallError('Prebuilt image checkpoint contains an unfamiliar image')
    images = dict(saved)
    if not isinstance(specs, dict) or not specs or set(specs) - SERVICE_ROLES.keys():
        raise InstallError('Unsupported prebuilt service selection')
    for service, spec in specs.items():
        if (not isinstance(spec, dict) or spec.get('image') != image_tag(installation, service)
                or 'build' in spec or spec.get('pull_policy') != 'never'):
            raise InstallError('Prebuilt service configuration must disable builds and image pulls')
    for service in sorted(specs):
        role = SERVICE_ROLES[service]
        stage, pending = 'prebuilt-import-' + service, 'prebuilt-intent-' + service
        previous = completed.get(stage)
        intent = core_image_intent(kit, role, installation.journal.document['id'])
        if pending in completed and completed[pending] != intent:
            raise InstallError('Pending prebuilt import differs from the selected release')
        if previous is None and pending not in completed:
            # A new intent may not retroactively grant custody of an existing
            # image tag. Only an already-recorded attempt can recover it.
            if installation.command(['docker', 'image', 'ls', '--no-trunc', '--quiet', intent['tag']],
                                    capture=True, timeout=30).strip():
                raise InstallError('Prebuilt image tag already exists without an import record')
            installation.journal.checkpoint(pending, intent)
        evidence = import_core_image(
            kit, role, installation.journal.document['id'], installation.base,
            installation.command, previous=previous, intent=intent if previous is None else None)
        tag, identity = evidence['tag'], evidence['image_id']
        if tag in images and images[tag] != identity:
            raise InstallError('Recorded deployment image differs from the authenticated import')
        installation.journal.checkpoint(stage, evidence)
        images[tag] = identity
        installation.journal.checkpoint('images', images)
    return images
