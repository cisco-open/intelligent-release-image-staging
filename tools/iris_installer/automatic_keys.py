# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Automatic local custody; colocated keys and passwords are not independent custody."""

from contextlib import contextmanager
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import struct
import subprocess
import tempfile

from . import key_setup
from .state import InstallError, atomic_write, regular_bytes

MARKER = 'automatic-root.json'
LOCK = '.automatic-root.lock'
ASKPASS = Path(__file__).with_name('automatic_askpass.py')
SECONDS = 30
MANUAL = ('This key uses a manually chosen passphrase or has no automatic-custody record. '
          'Rerun setup with --key-mode manual. Existing keys were kept')


def _fail(message):
    raise InstallError('Automatic key setup: ' + message)


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _same(directory, descriptor):
    try:
        current, held = directory.lstat(), os.fstat(descriptor)
        if (directory.resolve() != directory or
                (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)):
            _fail('private storage changed; existing files were kept')
    except OSError:
        _fail('private storage changed; existing files were kept')


def _read(descriptor, name, mode=0o600, limit=32768):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    try:
        return _read_fd(fd, mode, limit)
    finally:
        os.close(fd)


def _read_fd(fd, mode=0o600, limit=32768):
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1
            or before.st_size > limit):
        _fail('a holder file has unsafe ownership, permissions or type')
    os.lseek(fd, 0, os.SEEK_SET)
    data = os.read(fd, limit + 1)
    after = os.fstat(fd)
    if (len(data) != before.st_size or
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        _fail('a holder file changed while reading')
    return data


@contextmanager
def _key(descriptor, name, expected_hash):
    """Validate and use the SAME opened inode, not a later pathname lookup."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    try:
        if _hash(_read_fd(fd)) != expected_hash:
            _fail('private key changed before use')
        yield fd
        if _hash(_read_fd(fd)) != expected_hash:
            _fail('private key changed during use')
    finally:
        os.close(fd)


def _exists(descriptor, name):
    try:
        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _publish(descriptor, name, data, mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 mode, dir_fd=descriptor)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(descriptor)


def _record(descriptor, record):
    atomic_write(Path('/proc/self/fd') / str(descriptor) / MARKER,
                 (json.dumps(record, sort_keys=True) + '\n').encode())


def _load(descriptor, name):
    try:
        record = json.loads(_read(descriptor, MARKER, limit=4096))
    except (ValueError, OSError):
        _fail('automatic-custody record is missing or invalid; files were kept')
    if (not isinstance(record, dict) or set(record) !=
            {'schema', 'name', 'phase', 'passphrase_sha256', 'private_sha256', 'public_key'}
            or type(record['schema']) is not int or record['schema'] != 1
            or record['name'] != name or record['phase'] not in ('initializing', 'complete')):
        _fail('automatic-custody record is invalid')
    for field in ('passphrase_sha256', 'private_sha256'):
        value = record[field]
        if value is not None and (not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value)):
            _fail('automatic-custody digest is invalid')
    if record['phase'] == 'initializing':
        if record['private_sha256'] is not None or record['public_key'] is not None:
            _fail('incomplete automatic-custody record is invalid')
    elif (record['passphrase_sha256'] is None or record['private_sha256'] is None
          or not isinstance(record['public_key'], str)):
        _fail('completed automatic-custody record is incomplete')
    elif key_setup.public_key(record['public_key'].encode('ascii')).decode('ascii') != record['public_key']:
        _fail('recorded public key is invalid')
    return record


@contextmanager
def _holder(directory, name, *, create=False):
    if name not in ('root-a', 'root-b'):
        _fail('choose root-a or root-b')
    directory = Path(directory).absolute()
    if create:
        key_setup.private_directory(directory)
    if directory.resolve() != directory:
        _fail('private storage must not traverse symbolic links')
    parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = lock = None
    try:
        descriptor = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            _fail('private storage must be caller-owned with permissions 0700')
        _same(directory.parent, parent)
        _same(directory, descriptor)
        names = set(os.listdir(descriptor))
        if MARKER not in names and names - {LOCK}:
            raise InstallError(MANUAL)
        allowed = {MARKER, LOCK, name, name + '.pub', name + '.passphrase'}
        if names - allowed:
            _fail('private storage contains unknown files; nothing was adopted')
        lock = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        _read_fd(lock, limit=0)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _fail('another key operation is using this holder')
        if not _exists(descriptor, MARKER):
            if not create:
                raise InstallError(MANUAL)
            _publish(descriptor, MARKER, (json.dumps({
                'schema': 1, 'name': name, 'phase': 'initializing',
                'passphrase_sha256': None, 'private_sha256': None, 'public_key': None,
            }, sort_keys=True) + '\n').encode(), 0o600)
        yield directory, descriptor, _load(descriptor, name)
        _same(directory.parent, parent)
        _same(directory, descriptor)
    except (OSError, UnicodeError, ValueError):
        _fail('holder files are missing or unsafe; existing files were kept')
    finally:
        if lock is not None:
            os.close(lock)
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _secret(descriptor, name, record, *, create=False):
    filename = name + '.passphrase'
    if not _exists(descriptor, filename):
        if (not create or record['passphrase_sha256'] is not None
                or _exists(descriptor, name) or _exists(descriptor, name + '.pub')):
            _fail('the generated passphrase is missing; existing keys were kept')
        _publish(descriptor, filename, (secrets.token_urlsafe(48) + '\n').encode('ascii'), 0o600)
    data = _read(descriptor, filename, limit=65)
    if not re.fullmatch(rb'[A-Za-z0-9_-]{64}\n', data):
        _fail('generated passphrase file is invalid')
    if record['passphrase_sha256'] is None:
        if not create or _exists(descriptor, name) or _exists(descriptor, name + '.pub'):
            _fail('key appeared before its passphrase was recorded; files were kept')
        record['passphrase_sha256'] = _hash(data)
        _record(descriptor, record)
    if record['passphrase_sha256'] != _hash(data):
        _fail('generated passphrase changed; existing keys were kept')


def _run(arguments, directory, descriptor, *, extra_fds=()):
    _same(directory, descriptor)
    helper = ASKPASS.absolute()
    info = helper.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022 or not info.st_mode & 0o111):
        _fail('packaged passphrase helper is unavailable or unsafe')
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
           'SSH_ASKPASS': str(helper), 'SSH_ASKPASS_REQUIRE': 'force',
           'IRIS_AUTOMATIC_PASSPHRASE': '/proc/' + str(os.getpid()) + '/fd/' + str(descriptor) +
           '/' + arguments[0] + '.passphrase'}
    process = subprocess.Popen(['/usr/bin/ssh-keygen', *arguments[1:]],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, start_new_session=True, pass_fds=(descriptor, *extra_fds), umask=0o022)
    try:
        stdout, _ = process.communicate(timeout=SECONDS)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        _fail('key operation timed out; existing files were kept')
    if process.returncode:
        _fail('key operation failed; existing files were kept')
    _same(directory, descriptor)
    return stdout


def _private(descriptor, name):
    data = _read(descriptor, name)
    try:
        lines = data.splitlines()
        if lines[0] != b'-----BEGIN OPENSSH PRIVATE KEY-----' or lines[-1] != b'-----END OPENSSH PRIVATE KEY-----':
            raise ValueError
        wire = base64.b64decode(b''.join(lines[1:-1]), validate=True)
        if not wire.startswith(b'openssh-key-v1\x00'):
            raise ValueError
        length = struct.unpack('>I', wire[15:19])[0]
        cipher = wire[19:19 + length]
        offset = 19 + length
        kdf_length = struct.unpack('>I', wire[offset:offset + 4])[0]
        if not cipher or cipher == b'none' or wire[offset + 4:offset + 4 + kdf_length] != b'bcrypt':
            raise ValueError
    except (ValueError, IndexError, struct.error):
        _fail('automatic root is not a passphrase-protected OpenSSH key')
    return data


def _public(directory, descriptor, name, record):
    _secret(descriptor, name, record)
    private = _private(descriptor, name)
    if record['phase'] == 'complete' and _hash(private) != record['private_sha256']:
        _fail('private key changed from its automatic-custody record')
    with _key(descriptor, name, _hash(private)) as key:
        data = key_setup.public_key(_run([name, '-y', '-f', '/proc/self/fd/' + str(key)],
                                        directory, descriptor, extra_fds=(key,)))
    if _private(descriptor, name) != private:
        _fail('private key changed during use')
    public_exists = _exists(descriptor, name + '.pub')
    if record['phase'] == 'complete':
        if not public_exists or data.decode('ascii') != record['public_key']:
            _fail('completed public key is missing or changed')
    if public_exists:
        if key_setup.public_key(_read(descriptor, name + '.pub', 0o644, 16384)) != data:
            _fail('public and private keys do not match')
    else:
        _publish(descriptor, name + '.pub', data, 0o644)
    if record['phase'] == 'initializing':
        record.update(phase='complete', private_sha256=_hash(private), public_key=data.decode('ascii'))
        _record(descriptor, record)
    return data


def create_root(name, directory):
    """Create or reuse this explicitly managed automatic root; return its .pub path."""
    with _holder(directory, name, create=True) as (directory, descriptor, record):
        _secret(descriptor, name, record, create=True)
        if not _exists(descriptor, name):
            if record['phase'] == 'complete' or _exists(descriptor, name + '.pub'):
                _fail('private key is missing; existing files were kept')
            _run([name, '-q', '-t', 'ed25519', '-C', 'iris-' + name, '-f',
                  '/proc/self/fd/' + str(descriptor) + '/' + name], directory, descriptor)
        _public(directory, descriptor, name, record)
        return directory / (name + '.pub')


def root_public(root):
    """Decrypt and validate a completed automatic root without a terminal prompt."""
    root = Path(root).absolute()
    with _holder(root.parent, root.name) as (directory, descriptor, record):
        if record['phase'] != 'complete':
            _fail('root creation is incomplete; rerun setup before signing')
        return _public(directory, descriptor, root.name, record)


def is_managed(root):
    """Distinguish manual keys without silently ignoring damaged automatic custody."""
    root = Path(root).absolute()
    marker = root.parent / MARKER
    secret = root.with_name(root.name + '.passphrase')
    if not marker.exists() and not marker.is_symlink():
        if secret.exists() or secret.is_symlink():
            _fail('automatic-custody record is missing; existing keys were kept')
        return False
    with _holder(root.parent, root.name) as (directory, descriptor, record):
        if record['phase'] != 'complete':
            _fail('root creation is incomplete; rerun setup before signing')
        _public(directory, descriptor, root.name, record)
    return True


def run_for_root(root, command):
    """Run the existing custody certificate/SSHSIG command with a managed root."""
    root = Path(root).absolute()
    command = list(map(str, command))
    if (len(command) == 10 and command[:2] == ['ssh-keygen', '-s']
            and command[3:9] == ['-I', 'iris-online', '-n', 'iris-server', '-V', '+0s:+30d']):
        position = 2
    elif (len(command) == 8 and command[:4] == ['ssh-keygen', '-Y', 'sign', '-f']
          and command[5:7] == ['-n', 'iris-keylist-v1']):
        position = 4
    else:
        _fail('unsupported automatic signing command')
    if len(command) <= position or Path(command[position]).absolute() != root:
        _fail('signing command does not select this managed root')
    with _holder(root.parent, root.name) as (directory, descriptor, record):
        if record['phase'] != 'complete':
            _fail('root creation is incomplete; rerun setup before signing')
        _public(directory, descriptor, root.name, record)
        with _key(descriptor, root.name, record['private_sha256']) as key:
            command[position] = '/proc/self/fd/' + str(key)
            result = _run([root.name, *command[1:]], directory, descriptor, extra_fds=(key,))
        if _hash(_private(descriptor, root.name)) != record['private_sha256']:
            _fail('private key changed during signing')
        _secret(descriptor, root.name, record)
        return subprocess.CompletedProcess(command, 0, stdout=result, stderr=b'')


def sign_online(root, public_request, output):
    """Sign only a public Ed25519 request with the unchanged manual certificate policy."""
    public = key_setup.public_key(regular_bytes(public_request, 16384))
    root, output = Path(root).absolute(), Path(output).absolute()
    if output.parent.resolve() != output.parent:
        _fail('certificate destination must not traverse symbolic links')
    destination = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(destination)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            _fail('certificate parent must be caller-owned and protected')
        if _exists(destination, output.name):
            _fail('certificate destination already exists; choose a new path')
        with _holder(root.parent, root.name) as (directory, descriptor, record):
            if record['phase'] != 'complete':
                _fail('root creation is incomplete; rerun setup before signing')
            _public(directory, descriptor, root.name, record)
            with tempfile.TemporaryDirectory(prefix='iris-auto-sign-', dir='/proc/self/fd/' + str(descriptor)) as temporary:
                request = Path(temporary) / 'online.pub'
                request.write_bytes(public)
                with _key(descriptor, root.name, record['private_sha256']) as key:
                    _run([root.name, '-s', '/proc/self/fd/' + str(key), '-I', 'iris-online',
                          '-n', 'iris-server', '-V', '+0s:+30d', str(request)], directory,
                         descriptor, extra_fds=(key,))
                if _hash(_private(descriptor, root.name)) != record['private_sha256']:
                    _fail('private key changed during signing')
                certificate = regular_bytes(Path(temporary) / 'online-cert.pub', 65536)
                _same(output.parent, destination)
                _same(directory, descriptor)
                _publish(destination, output.name, certificate, 0o644)
        return output
    finally:
        os.close(destination)
