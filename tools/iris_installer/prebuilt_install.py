# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bind authenticated prebuilt inputs to the existing installation journal.

Acquisition changes only: topology adapters retain ownership, signing, runtime
verification and account-claim responsibilities. No kit code is imported here.
"""

import hashlib
import os
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

from . import release_kit
from .prebuilt_images import core_image_intent, import_core_image
from .state import InstallError


SERVICE_ROLES = {'iris': 'server-image', 'console': 'console-image'}


def prepare_selection(args, manifest, workspace):
    """Authenticate inputs and check the licensed tool before any host changes.

    Only the receipt and public input locations go into the protected journal.
    The source route never silently consumes prebuilt-only options.
    """
    directory = getattr(args, 'release_kit', None)
    names = ('release_tag', 'release_commit', 'release_verifier',
             'release_trusted_root', 'ioxclient')
    if directory is None:
        if (any(getattr(args, name, None) is not None for name in names)
                or getattr(args, 'offline', False)):
            raise InstallError('Prebuilt release options require --release-kit')
        return {'input_selection': release_kit.selection()}
    if not all(getattr(args, name, None) for name in ('release_tag', 'release_commit', 'ioxclient')):
        raise InstallError('A prebuilt install requires --release-tag, --release-commit and --ioxclient')
    locator = {
        'directory': str(Path(directory).absolute()),
        'verifier': str(Path(getattr(args, 'release_verifier', None) or '/usr/bin/gh').absolute()),
        'trusted_root': (str(Path(args.release_trusted_root).absolute())
                         if getattr(args, 'release_trusted_root', None) else None),
    }
    kit = release_kit.verify_kit(
        locator['directory'], tag=args.release_tag, commit=args.release_commit,
        verifier=locator['verifier'], trusted_root=locator['trusted_root'],
        offline=bool(getattr(args, 'offline', False)))
    bind_source(kit, manifest, workspace)
    tool = Path(args.ioxclient).absolute()
    validate_packaging_tool(kit, tool, workspace)
    return {'input_selection': release_kit.selection('prebuilt', kit=kit, offline=kit.offline),
            'release_kit': locator, 'prebuilt_ioxclient': str(tool)}


def validate_packaging_tool(kit, tool, workspace):
    """Check bounded authenticated inputs and snapshot the tool without running it."""
    from .device_context import prepare_ioxclient
    from .packaging_inputs import prepare_packaging_inputs
    if not _public_path(str(tool)):
        raise InstallError('Recorded licensed ioxclient location is invalid')
    descriptor = release_kit._protected_directory(workspace)
    try:
        # Cleanup follows the held directory even if its visible parent moves.
        with tempfile.TemporaryDirectory(prefix='prebuilt-tool-check-',
                                         dir=Path('/proc/self/fd') / str(descriptor)) as directory:
            scratch = Path(directory).resolve()
            inputs = prepare_packaging_inputs(kit, scratch / 'inputs')
            prepare_ioxclient(tool, scratch / 'ioxclient', expected_sha256=inputs.ioxclient_sha256)
    finally:
        os.close(descriptor)


def selected(document):
    """Old journals remain source builds; malformed new selections never do."""
    value = document.get('input_selection', release_kit.selection())
    release_kit.assert_resume_selection(value, value)
    if value['mode'] == 'source' and any(name in document for name in ('release_kit', 'prebuilt_ioxclient')):
        raise InstallError('Source-build journal contains a conflicting release kit')
    return value['mode'] == 'prebuilt'


def _public_path(value):
    return (isinstance(value, str) and 0 < len(value) <= 4096
            and not any(ord(char) < 32 or ord(char) == 127 for char in value)
            and Path(value).is_absolute())


def _recorded_locator(document):
    locator = document.get('release_kit')
    if (not isinstance(locator, dict) or set(locator) != {'directory', 'verifier', 'trusted_root'}
            or any(not _public_path(locator[key]) for key in ('directory', 'verifier'))
            or (locator['trusted_root'] is not None and not _public_path(locator['trusted_root']))):
        raise InstallError('Recorded release kit location or verifier is invalid')
    return dict(locator)


def public_selection(document):
    """Project validated public acquisition fields, never arbitrary journal data."""
    if not selected(document):
        return {'input_selection': release_kit.selection()}
    value = document['input_selection']
    tool = document.get('prebuilt_ioxclient')
    if not _public_path(tool):
        raise InstallError('Recorded licensed ioxclient location is invalid')
    return {'input_selection': {**value, 'kit': dict(value['kit'])},
            'release_kit': _recorded_locator(document), 'prebuilt_ioxclient': tool}


def assert_setup_selection(args, status):
    """Explicit setup options constrain resume; omitted options keep the journal."""
    recorded = public_selection(status)
    value = recorded['input_selection']
    paths = {'release_kit': 'directory', 'release_verifier': 'verifier',
             'release_trusted_root': 'trusted_root', 'ioxclient': None}
    options = (*paths, 'release_tag', 'release_commit')
    supplied = {name: getattr(args, name, None) for name in options
                if getattr(args, name, None) is not None}
    offline = getattr(args, 'offline', False)
    if value['mode'] == 'source':
        if supplied or offline:
            raise InstallError('Recorded installation uses source builds; prebuilt and offline options cannot resume it')
        return
    expected = {'release_tag': value['kit']['tag'], 'release_commit': value['kit']['commit'],
                'ioxclient': recorded['prebuilt_ioxclient']}
    expected.update({name: recorded['release_kit'][field] for name, field in paths.items() if field})
    for name, supplied_value in supplied.items():
        actual = str(Path(supplied_value).absolute()) if name in paths else supplied_value
        if actual != expected[name]:
            raise InstallError('--' + name.replace('_', '-') + ' differs from the recorded installation; keep its original inputs')
    if offline and not value['kit']['offline']:
        raise InstallError('--offline differs from the recorded installation; keep its original inputs')


def verify_selected(journal):
    if not selected(journal.document):
        return None
    locator = _recorded_locator(journal.document)
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
