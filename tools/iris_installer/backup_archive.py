# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded encrypted file-set capture and isolated extraction, never cutover.

The caller must quiesce all writers. A captured file set is not itself proof of
deployment completeness or safe producer recovery. Archive authentication uses
an independently trusted OpenSSH backup signer, NOT a key supplied by the archive.
"""

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import threading
import time

from .deploy import clean_env
from .state import InstallError, atomic_write, regular_bytes

NAMESPACE = "iris-backup-v1"
SCHEMA = "iris-encrypted-files/v1"
MAX_MANIFEST = 16 * 1024 * 1024
MAX_FILES = 100000
CHUNK = 1024 * 1024


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def private_directory(path):
    path = Path(path).absolute()
    if path.resolve() != path or path == Path('/'):
        raise InstallError("Use a dedicated directory without symlinks")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise InstallError("Backup workspace must be caller-owned with mode 0700")
    return path


def _name(value):
    path = PurePosixPath(value)
    if (not value or value == '.' or path.is_absolute() or '..' in path.parts
            or str(path) != value or any(ord(c) < 32 for c in value)
            or len(value.encode('utf-8')) > 4096):
        raise InstallError("Unsafe archive member")
    return value


def _digest(path):
    value = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise InstallError("Expected a regular backup file")
        for data in iter(lambda: stream.read(CHUNK), b''):
            value.update(data)
    return value.hexdigest()


class _HashReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()

    def read(self, size):
        data = self.stream.read(size)
        self.digest.update(data)
        return data


def _capture(archive, parent_fd, name, member, records):
    if len(records) >= MAX_FILES:
        raise InstallError("Backup file count exceeds the supported limit")
    _name(member)
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise InstallError("Backup sources contain a link or special file")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if stat.S_ISDIR(info.st_mode):
        flags |= os.O_DIRECTORY
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_mode) != (info.st_dev, info.st_ino, info.st_mode):
            raise InstallError("Backup source changed during capture")
        if stat.S_ISREG(before.st_mode) and before.st_nlink != 1:
            raise InstallError("Backup sources contain hard-linked files")
        header = tarfile.TarInfo(member)
        header.mode = stat.S_IMODE(before.st_mode) & 0o777
        header.uid, header.gid = before.st_uid, before.st_gid
        header.mtime = int(before.st_mtime)
        record = {'name': member, 'mode': header.mode, 'uid': header.uid,
                  'gid': header.gid, 'size': 0, 'sha256': None, 'type': 'directory'}
        records.append(record)
        if stat.S_ISDIR(before.st_mode):
            header.type = tarfile.DIRTYPE
            archive.addfile(header)
            for child in sorted(os.listdir(fd)):
                _capture(archive, fd, child, member + '/' + child, records)
        else:
            header.size = before.st_size
            with os.fdopen(os.dup(fd), 'rb') as stream:
                reader = _HashReader(stream)
                archive.addfile(header, reader)
            record.update(type='file', size=header.size, sha256=reader.digest.hexdigest())
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InstallError("Backup source changed; stop all writers before capture")
    finally:
        os.close(fd)


def create(sources, output, recipient, signing_key, *, metadata=None):
    """Publish a signed encrypted set into a NEW directory under a private parent."""
    output = Path(output).absolute()
    parent = private_directory(output.parent)
    if output.exists() or output.is_symlink():
        raise InstallError("Backup destination already exists; nothing overwritten")
    if not re.fullmatch(r'age1[0-9a-z]{58}', recipient):
        raise InstallError("Supply an age X25519 public recovery recipient")
    key_info = Path(signing_key).lstat()
    if (not stat.S_ISREG(key_info.st_mode) or key_info.st_uid != os.geteuid()
            or key_info.st_mode & 0o077):
        raise InstallError("Backup signing key must be a private caller-owned regular file")
    if not sources or len(sources) > 128:
        raise InstallError("Choose between one and 128 explicit capture roots")
    for name in sources:
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name):
            raise InstallError("Invalid backup component name")
    # Prevent capturing this output recursively, including during encryption.
    for source in sources.values():
        source = Path(source).absolute()
        if source.resolve() != source or parent == source or source in parent.parents:
            raise InstallError("Backup destination must be outside the capture sources")
    with tempfile.TemporaryDirectory(prefix='.iris-backup-', dir=parent) as temporary:
        stage = Path(temporary)
        encrypted = stage / 'payload.tar.age'
        records = []
        with encrypted.open('xb') as dest:
            os.fchmod(dest.fileno(), 0o600)
            process = subprocess.Popen(['age', '-r', recipient], stdin=subprocess.PIPE,
                                       stdout=dest, stderr=subprocess.DEVNULL, env=clean_env())
            try:
                with tarfile.open(fileobj=process.stdin, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                    for name, source in sorted(sources.items()):
                        source = Path(source).absolute()
                        directory_fd = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                        try:
                            _capture(archive, directory_fd, source.name, name, records)
                        finally:
                            os.close(directory_fd)
                    inventory = json.dumps({'schema': SCHEMA, 'files': records,
                                            'metadata': metadata or {}}, sort_keys=True).encode()
                    if len(inventory) > MAX_MANIFEST:
                        raise InstallError("Backup inventory exceeds the supported limit")
                    header = tarfile.TarInfo('inventory.json')
                    header.size, header.mode = len(inventory), 0o600
                    archive.addfile(header, io.BytesIO(inventory))
                process.stdin.close()
                if process.wait(timeout=120) != 0:
                    raise InstallError("Backup encryption failed")
                dest.flush()
                os.fsync(dest.fileno())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                try:
                    process.stdin.close()
                except OSError:
                    # Aborted capture can leave buffered plaintext destined for
                    # the now-terminated age process. Preserve the real capture
                    # error rather than replacing it with a broken-pipe error.
                    pass
        envelope = {'schema': SCHEMA, 'created_at': int(time.time()),
                    'payload_sha256': _digest(encrypted), 'payload_bytes': encrypted.stat().st_size,
                    'recipient': recipient}
        atomic_write(stage / 'manifest.json', (json.dumps(envelope, sort_keys=True) + '\n').encode())
        try:
            subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(signing_key),
                            '-n', NAMESPACE, str(stage / 'manifest.json')],
                           check=True, capture_output=True, timeout=30, env=clean_env())
        except (OSError, subprocess.SubprocessError):
            raise InstallError("Backup signing failed; use an unattended deployment backup key, not a root custodian key") from None
        # A new private reservation prevents replacing even an empty destination.
        output.mkdir(mode=0o700)
        for name in ('payload.tar.age', 'manifest.json.sig', 'manifest.json'):
            os.chmod(stage / name, 0o600)
            descriptor = os.open(stage / name, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.link(stage / name, output / name)
        _sync_directory(output)
        _sync_directory(parent)
    return envelope


def authenticate(backup, trusted_public_key):
    """Verify against independently supplied public trust BEFORE decryption."""
    backup = private_directory(backup)
    raw = regular_bytes(backup / 'manifest.json', 16384)
    signature = regular_bytes(backup / 'manifest.json.sig', 16384)
    if (not signature.startswith(b'-----BEGIN SSH SIGNATURE-----\n')
            or not signature.endswith(b'-----END SSH SIGNATURE-----\n')):
        raise InstallError("Backup signature has an invalid encoding")
    public = regular_bytes(trusted_public_key, 4096).decode('ascii').strip().split()
    if len(public) < 2 or public[0] != 'ssh-ed25519' or '\n' in public[1]:
        raise InstallError("Expected an independently trusted Ed25519 backup public key")
    with tempfile.TemporaryDirectory(prefix='.iris-verify-', dir=backup.parent) as temporary:
        directory = Path(temporary)
        atomic_write(directory / 'allowed', ('iris-backup namespaces="' + NAMESPACE + '" ' +
                                           ' '.join(public[:2]) + '\n').encode())
        atomic_write(directory / 'signature', signature)
        try:
            subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(directory / 'allowed'),
                            '-I', 'iris-backup', '-n', NAMESPACE, '-s', str(directory / 'signature')],
                           input=raw, capture_output=True, timeout=30, check=True, env=clean_env())
        except (OSError, subprocess.SubprocessError):
            raise InstallError("Backup signature is not valid for the trusted signer") from None
    try:
        manifest = json.loads(raw)
        if (set(manifest) != {'schema', 'created_at', 'payload_sha256', 'payload_bytes', 'recipient'}
                or manifest['schema'] != SCHEMA or type(manifest['payload_bytes']) is not int
                or manifest['payload_bytes'] < 0
                or manifest['payload_sha256'] != _digest(backup / 'payload.tar.age')
                or manifest['payload_bytes'] != (backup / 'payload.tar.age').stat().st_size):
            raise ValueError()
    except (ValueError, TypeError):
        raise InstallError("Backup manifest or payload integrity check failed") from None
    return manifest


def read(backup, identity, trusted_public_key, *, destination=None, max_bytes=1024 ** 4):
    """Verify all decrypted bytes; optionally extract into a new isolated directory.

    Never loads container images, contacts devices, restores services or overwrites
    existing files. Ownership is recorded but deliberately not applied here.
    """
    backup = private_directory(backup)
    manifest = authenticate(backup, trusted_public_key)
    if type(max_bytes) is not int or max_bytes < 1:
        raise InstallError("Restore byte limit must be positive")
    parent = private_directory(Path(destination).absolute().parent) if destination else backup.parent
    if destination and (Path(destination).exists() or Path(destination).is_symlink()):
        raise InstallError("Restore destination must not exist")
    records, total, inventory = [], 0, None
    with tempfile.TemporaryDirectory(prefix='.iris-restore-', dir=parent) as temporary:
        stage = Path(temporary)
        # Use an opened descriptor, not a path age could reopen after validation.
        fd = os.open(backup / 'payload.tar.age', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as encrypted:
            if not stat.S_ISREG(os.fstat(encrypted.fileno()).st_mode):
                raise InstallError("Expected a regular encrypted payload")
            process = subprocess.Popen(['age', '-d', '-i', str(identity)], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=clean_env())
            # Hash the EXACT ciphertext fed to age. A preliminary path hash
            # alone would allow a replacement between verification and use.
            fed_digest, feed_errors = hashlib.sha256(), []
            def feed():
                fed = 0
                try:
                    while True:
                        data = encrypted.read(min(CHUNK, manifest['payload_bytes'] - fed + 1))
                        if not data:
                            break
                        fed += len(data)
                        if fed > manifest['payload_bytes']:
                            raise InstallError("Encrypted payload grew during verification")
                        fed_digest.update(data)
                        process.stdin.write(data)
                    if fed != manifest['payload_bytes']:
                        raise InstallError("Encrypted payload size changed")
                except (OSError, ValueError, InstallError):
                    feed_errors.append('ciphertext-feed-failed')
                finally:
                    try:
                        process.stdin.close()
                    except OSError:
                        feed_errors.append('ciphertext-feed-failed')
            feeder = threading.Thread(target=feed, daemon=True)
            feeder.start()
            try:
                names, directories = set(), set()
                with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                    for header in archive:
                        name = _name(header.name)
                        if name == 'RESTORE-INVENTORY.json':
                            raise InstallError("Reserved recovery output name")
                        if inventory is not None or name in names or len(names) > MAX_FILES:
                            raise InstallError("Duplicate, excessive or trailing archive member")
                        names.add(name)
                        if not (header.isfile() or header.isdir()) or header.size < 0:
                            raise InstallError("Archive contains a link or special member")
                        if name == 'inventory.json':
                            if not header.isfile() or header.size > MAX_MANIFEST:
                                raise InstallError("Invalid archive inventory")
                            inventory = json.load(archive.extractfile(header))
                            continue
                        total += header.size
                        if total > max_bytes:
                            raise InstallError("Restore exceeds the configured byte limit")
                        if (header.mode & ~0o777 or header.uid < 0 or header.gid < 0
                                or (header.isdir() and header.size != 0)):
                            raise InstallError("Unsafe archive metadata")
                        record = {'name': name, 'mode': header.mode, 'uid': header.uid,
                                  'gid': header.gid, 'size': header.size, 'sha256': None,
                                  'type': 'directory' if header.isdir() else 'file'}
                        path = stage / name
                        if '/' in name and str(PurePosixPath(name).parent) not in directories:
                            raise InstallError("Archive parent is missing or out of order")
                        if header.isdir():
                            directories.add(name)
                            if destination:
                                path.mkdir(mode=0o700)
                        else:
                            value = hashlib.sha256()
                            stream = archive.extractfile(header)
                            out = path.open('xb') if destination else None
                            try:
                                if out:
                                    os.fchmod(out.fileno(), 0o600)
                                for chunk in iter(lambda: stream.read(CHUNK), b''):
                                    value.update(chunk)
                                    if out:
                                        out.write(chunk)
                                if out:
                                    out.flush()
                                    os.fsync(out.fileno())
                            finally:
                                if out:
                                    out.close()
                            record['sha256'] = value.hexdigest()
                        records.append(record)
                    trailing = 0
                    for remaining in iter(lambda: archive.fileobj.read(CHUNK), b''):
                        trailing += len(remaining)
                        if remaining.strip(b'\x00') or trailing > 1024 * 1024:
                            raise InstallError("Unexpected bytes after archive")
                # Finish AEAD authentication, including the final chunk. Tar can
                # finish before age does; a truncated ciphertext is NOT success.
                for remaining in iter(lambda: process.stdout.read(CHUNK), b''):
                    if remaining.strip(b'\x00'):
                        raise InstallError("Unexpected bytes after archive")
                if process.wait(timeout=120) != 0:
                    raise InstallError("Backup decryption failed; check the recovery identity")
                feeder.join(timeout=5)
                if feeder.is_alive() or feed_errors or fed_digest.hexdigest() != manifest['payload_sha256']:
                    raise InstallError("Encrypted payload changed during verification")
            except (tarfile.TarError, ValueError, UnicodeError):
                raise InstallError("Decrypted backup archive is invalid") from None
            finally:
                process.stdout.close()
                if process.poll() is None:
                    process.kill()
                    process.wait()
                feeder.join(timeout=5)
        if (not isinstance(inventory, dict) or set(inventory) != {'schema', 'files', 'metadata'}
                or inventory['schema'] != SCHEMA or inventory['files'] != records
                or not isinstance(inventory['metadata'], dict)):
            raise InstallError("Archive inventory does not match captured files")
        if destination:
            # Restrictive modes remain in place. This is extraction evidence,
            # not an executable/restarted deployment or an ownership repair.
            atomic_write(stage / 'RESTORE-INVENTORY.json', json.dumps(inventory, sort_keys=True).encode())
            for record in reversed(records):
                if record['type'] == 'directory':
                    _sync_directory(stage / record['name'])
            _sync_directory(stage)
            os.mkdir(destination, mode=0o700)
            for child in stage.iterdir():
                os.rename(child, Path(destination) / child.name)
            _sync_directory(destination)
            _sync_directory(parent)
        return {'state': 'verified-isolated-files' if destination else 'verified-files',
                'files': len(records), 'bytes': total, 'metadata': inventory['metadata'],
                'cutover_permitted': False}
