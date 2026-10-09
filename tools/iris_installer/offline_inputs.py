# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Inspect and open authenticated dependency inputs without applying packages.

The producer can inspect archive structure, schema and inventory with no external
command. The consumer additionally requires a verified release kit, the system's
independent Ubuntu archive keyring, and the existing local-only apt validator.
"""

from contextlib import contextmanager, ExitStack
import gzip
import hashlib
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import stat
import tarfile
import tempfile
import zlib

from . import offline_dependencies as dependencies, release_kit
from .state import InstallError


ROLE = 'ubuntu-dependencies'
MAX_MANIFEST = 4 * 1024 ** 2
MAX_EXPANDED = dependencies.MAX_TOTAL + 32 * 1024 ** 2
MAX_MEMBERS = 8192


def _same_directory(path, descriptor):
    try:
        named, held = path.lstat(), os.fstat(descriptor)
        valid = (release_kit._path(path) == path and stat.S_ISDIR(named.st_mode)
                 and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino))
    except OSError:
        valid = False
    if not valid:
        raise InstallError('Ubuntu dependency working directory changed during preparation')


@contextmanager
def _new_directory(destination, *, remove=False):
    """Hold creation and cleanup authority even if a pathname is substituted."""
    destination = release_kit._path(destination)
    parent = release_kit._protected_directory(destination.parent)
    directory, complete = None, False
    try:
        os.mkdir(destination.name, mode=0o700, dir_fd=parent)
        directory = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
        _same_directory(destination.parent, parent)
        _same_directory(destination, directory)
        yield directory
        _same_directory(destination.parent, parent)
        _same_directory(destination, directory)
        complete = True
    finally:
        try:
            if directory is not None:
                try:
                    if remove or not complete:
                        # Never descend via the original name: it may now identify
                        # a different directory. shutil uses its safe FD traversal.
                        for name in os.listdir(directory):
                            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                            if stat.S_ISDIR(info.st_mode):
                                shutil.rmtree(name, dir_fd=directory)
                            else:
                                os.unlink(name, dir_fd=directory)
                        try:
                            named = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            held = os.fstat(directory)
                            if (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino):
                                os.rmdir(destination.name, dir_fd=parent)
                finally:
                    os.close(directory)
        finally:
            os.close(parent)


def _output_file(directory, name):
    """Create only below the held extraction root, never through path aliases."""
    descriptor = os.dup(directory)
    try:
        parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        output = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=descriptor)
        return os.fdopen(output, 'wb')
    finally:
        os.close(descriptor)


def _copy(source, output, maximum):
    digest, size = hashlib.sha256(), 0
    while data := source.read(release_kit.CHUNK):
        size += len(data)
        if size > maximum:
            raise InstallError('Ubuntu dependency archive exceeds its expansion limit')
        digest.update(data)
        if output is not None:
            output.write(data)
    return digest.hexdigest(), size


def inspect_dependency_archive(path, *, expected_manifest_sha256=None, destination=None):
    """Check a closed regular-file archive and its exact manifest inventory.

    Inputs must already be privately snapshotted by the producer or copied with
    VerifiedKit.copy_asset. Optional extraction creates a new private directory
    and writes regular files with fixed permissions, never archive permissions.
    This inspection alone does not authenticate Ubuntu signatures or a release.
    """
    if expected_manifest_sha256 is not None:
        release_kit._sha(expected_manifest_sha256)
    fd, before = release_kit._open(Path(path), dependencies.MAX_TOTAL)
    try:
        with os.fdopen(os.dup(fd), 'rb') as compressed, tempfile.TemporaryFile() as plain:
            try:
                with gzip.GzipFile(fileobj=compressed) as expanded:
                    _copy(expanded, plain, MAX_EXPANDED)
                total_size = plain.tell()
                plain.seek(0)
                with tarfile.open(fileobj=plain, mode='r:', tarinfo=release_kit._BoundedTarInfo) as archive, ExitStack() as extraction:
                    members, expanded_size = {}, 0
                    for member in archive:
                        name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
                        dependencies._relative(name)
                        if name in members or len(members) >= MAX_MEMBERS:
                            raise InstallError('Ubuntu dependency archive contains duplicate or excessive entries')
                        if (not (member.isfile() or member.isdir()) or member.size < 0
                                or member.size > dependencies.MAX_FILE
                                or (member.isdir() and member.size)
                                or any(key.startswith('GNU.sparse') for key in member.pax_headers)):
                            raise InstallError('Ubuntu dependency archive contains unsupported entries')
                        expanded_size += member.size
                        if expanded_size > dependencies.MAX_TOTAL + MAX_MANIFEST:
                            raise InstallError('Ubuntu dependency archive exceeds its expansion limit')
                        members[name] = member
                    # A full end marker and zero padding close this one archive.
                    # Hidden concatenated tar payloads and truncated terminators fail.
                    if total_size % 512 or total_size - archive.offset < 1024:
                        raise InstallError('Ubuntu dependency archive is not completely terminated')
                    plain.seek(archive.offset)
                    while tail := plain.read(release_kit.CHUNK):
                        if tail.strip(b'\0'):
                            raise InstallError('Ubuntu dependency archive has trailing payload')
                    manifest_member = members.get(dependencies.MANIFEST)
                    if (manifest_member is None or not manifest_member.isfile()
                            or not 0 < manifest_member.size <= MAX_MANIFEST):
                        raise InstallError('Ubuntu dependency archive lacks its bounded manifest')
                    raw = archive.extractfile(manifest_member).read(MAX_MANIFEST + 1)
                    manifest_digest = hashlib.sha256(raw).hexdigest()
                    if expected_manifest_sha256 is not None and manifest_digest != expected_manifest_sha256:
                        raise InstallError('Ubuntu dependency manifest differs from authenticated release metadata')
                    manifest = release_kit._json(raw)
                    dependencies._validate_manifest(manifest)
                    files = {name for name, member in members.items() if member.isfile()}
                    if files != {dependencies.MANIFEST, *manifest['files']}:
                        raise InstallError('Ubuntu dependency archive has missing or unlisted files')
                    parents = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != '.'}
                    if any(name not in parents for name, member in members.items() if member.isdir()):
                        raise InstallError('Ubuntu dependency archive has unlisted directories')
                    if files & parents:
                        raise InstallError('Ubuntu dependency archive traverses a non-directory')
                    if destination is not None:
                        descriptor = extraction.enter_context(_new_directory(destination))
                    for name in sorted(files):
                        member = members[name]
                        expected = ({'sha256': manifest_digest, 'size': len(raw)} if name == dependencies.MANIFEST
                                    else manifest['files'][name])
                        if member.size != expected['size']:
                            raise InstallError('Ubuntu dependency member size differs from its inventory')
                        source = archive.extractfile(member)
                        if destination is None:
                            digest, size = _copy(source, None, expected['size'])
                        else:
                            with _output_file(descriptor, name) as output:
                                digest, size = _copy(source, output, expected['size'])
                        if digest != expected['sha256'] or size != expected['size']:
                            raise InstallError('Ubuntu dependency member differs from its manifest inventory')
                    if release_kit._identity(before) != release_kit._identity(os.fstat(fd)):
                        raise InstallError('Ubuntu dependency archive changed during inspection')
                    return {'manifest_sha256': manifest_digest, 'manifest': manifest}
            except (OSError, ValueError, tarfile.TarError, EOFError, zlib.error):
                raise InstallError('Ubuntu dependency archive is invalid') from None
    finally:
        os.close(fd)


@contextmanager
def prepare_dependencies(kit):
    """Yield an authenticated, Ubuntu-verified closure; never apply a host plan."""
    if not isinstance(kit, release_kit.VerifiedKit) or kit.profile != ROLE:
        raise InstallError('Ubuntu dependency preparation requires the authenticated ubuntu-dependencies profile')
    asset = kit.asset(ROLE)
    if asset.format != 'tar.gz' or not 0 < asset.size <= dependencies.MAX_TOTAL:
        raise InstallError('Ubuntu dependency asset is unsupported or oversized')
    release_kit._sha(asset.dependency_manifest_sha256)
    work = Path(tempfile.gettempdir()) / ('iris-offline-inputs-' + secrets.token_hex(16))
    with _new_directory(work, remove=True) as descriptor:
        snapshot = work / 'ubuntu-dependencies.tar.gz'
        kit.copy_asset(ROLE, snapshot)
        payload = work / 'payload'
        inspect_dependency_archive(snapshot, expected_manifest_sha256=asset.dependency_manifest_sha256,
                                   destination=payload)
        _same_directory(work, descriptor)
        with dependencies.validate_closure(payload, asset.dependency_manifest_sha256) as closure:
            _same_directory(work, descriptor)
            yield closure
