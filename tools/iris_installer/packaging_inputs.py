# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Produce and consume authenticated inputs for native device packaging.

The public bundle contains selected XR build source and tool identities.
ioxclient is supplied separately by the operator. No vendor program is run,
and consumers derive authority only from a previously authenticated release kit.
"""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import zlib

from . import device_finalize as f, release_kit
from .state import InstallError, regular_bytes


BUNDLE = 'iris-packaging-tools.tar.gz'
APPMGR_ARCHIVE = 'xr-appmgr-build.tar.gz'
APPMGR_METADATA = 'iris-appmgr-source.json'
APPMGR_REPOSITORY = 'https://github.com/ios-xr/xr-appmgr-build.git'
APPMGR_REVISION = '37d79607a32a129107819f08fb3a74187efd2d47'
IOXCLIENT_VERSION = '1.18.0.0'
SOURCE_FILES = frozenset((
    'appmgr_build', 'build_rpm.sh', 'LICENSE', 'README.md', 'CONTRIBUTING.md',
    'release_configs/ThinXR.ini', 'release_configs/eXR.ini',
    'release_configs/owner-pscript.ini', 'release_configs/owner.ini',
    'release_configs/partner-pscript.ini', 'release_configs/partner.ini',
    'release_configs/pscript.ini',
))
EXECUTABLES = frozenset(('appmgr_build', 'build_rpm.sh'))
MAX_ARCHIVE = 16 * 1024**2
MAX_SOURCE_FILE = 1024**2
MAX_METADATA = 16384
GIT_SECONDS = 30


def fail(message):
    raise InstallError('Packaging inputs: ' + message)


def _pin_path():
    base = Path(__file__).resolve().parents[1]
    installed = base / 'source/tools/ioxclient.sha256'
    return installed if installed.exists() or installed.is_symlink() else base / 'ioxclient.sha256'


def _ioxclient_pin():
    """Read the matching controller/source pin, never a pin supplied by a tool."""
    pins = {}
    try:
        lines = regular_bytes(_pin_path(), MAX_METADATA).decode('ascii').splitlines()
    except (OSError, UnicodeError):
        fail('matching source ioxclient pin is unavailable')
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'([0-9a-f]{64})  ([0-9]+(?:\.[0-9]+){3})', line)
        if match is None or match[2] in pins:
            fail('matching source ioxclient pin is invalid')
        pins[match[2]] = match[1]
    if IOXCLIENT_VERSION not in pins:
        fail('matching source omits the supported ioxclient version')
    return pins[IOXCLIENT_VERSION]


def _appmgr_metadata():
    return {'format': 'iris-appmgr-source-v1', 'source_repository': APPMGR_REPOSITORY,
            'source_revision': APPMGR_REVISION}


@contextmanager
def _publication(destination):
    """Publish once through a protected directory FD without replacing data."""
    output = f._path(destination)
    descriptor = release_kit._protected_directory(output.parent)
    stage = None
    published = False
    try:
        before = os.fstat(descriptor)
        if before.st_uid != os.geteuid() or before.st_mode & 0o022:
            fail('output parent must be caller-owned and protected')
        if output.exists() or output.is_symlink():
            fail('output already exists')
        stage = Path(tempfile.mkdtemp(prefix='.iris-packaging-',
            dir=Path('/proc/self/fd') / str(descriptor)))
        yield stage, output
        for path in stage.iterdir():
            path.chmod(0o444)
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
        directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        current = output.parent.lstat()
        if (f._path(output.parent) != output.parent
                or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)):
            fail('output parent changed during preparation')
        f._publish(descriptor, stage.name, output.name)
        published = True
    finally:
        if stage is not None and not published and stage.exists():
            shutil.rmtree(stage)
        os.close(descriptor)


def _tar_bytes(entries):
    """Canonical plain tar; supplied entries contain only bounded public data."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
        for name, data, executable in sorted(entries):
            item = tarfile.TarInfo(name)
            item.mode = 0o755 if executable else 0o644
            if data is None:
                item.type, item.mode = tarfile.DIRTYPE, 0o755
            else:
                item.size = len(data)
            archive.addfile(item, None if data is None else io.BytesIO(data))
    return buffer.getvalue()


def _gzip(data):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', filename='', mtime=0) as stream:
        stream.write(data)
    return buffer.getvalue()


def _members(raw):
    if len(raw) > MAX_ARCHIVE:
        fail('archive exceeds its expansion limit')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:', tarinfo=f._TarInfo) as archive:
        members = f._members(archive)
        if len(members) > 64:
            fail('archive has too many entries')
        values = {}
        for name, member in members.items():
            if member.isfile():
                if not 0 < member.size <= MAX_ARCHIVE:
                    fail('archive member is empty or oversized')
                data = archive.extractfile(member).read(MAX_ARCHIVE + 1)
                if len(data) != member.size:
                    fail('archive member is truncated')
                values[name] = (data, member.mode)
            else:
                values[name] = (None, member.mode)
        return values


def _unpack(data):
    if not 0 < len(data) <= MAX_ARCHIVE:
        fail('compressed archive exceeds its size limit')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            raw = stream.read(MAX_ARCHIVE + 1)
            if len(raw) > MAX_ARCHIVE:
                fail('archive exceeds its expansion limit')
        return _members(raw)
    except (OSError, tarfile.TarError, EOFError, zlib.error, ValueError):
        fail('compressed source archive is invalid')


def _source_entries(entries, *, metadata):
    expected = SOURCE_FILES | {'release_configs'} | ({APPMGR_METADATA} if metadata else set())
    if set(entries) != expected or entries['release_configs'][0] is not None:
        fail('XR archive must contain exactly the selected source and notices')
    for name in SOURCE_FILES:
        data, mode = entries[name]
        expected_mode = 0o755 if name in EXECUTABLES else 0o644
        if data is None or len(data) > MAX_SOURCE_FILE or mode != expected_mode:
            fail('XR source member has invalid type, size or permissions')
        if re.search(br'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----', data):
            fail('XR source contains private-key material')
    if metadata:
        data, mode = entries[APPMGR_METADATA]
        if (data is None or len(data) > MAX_METADATA or mode != 0o644
                or f._load(data) != _appmgr_metadata()):
            fail('XR source metadata differs from the pinned revision')
    return entries


def _git(repository, arguments, maximum):
    command = ['git', '--no-replace-objects', '-c', 'tar.umask=0022',
               '-c', 'core.hooksPath=/dev/null', '-c', 'gc.auto=0', '-C', str(repository), *arguments]
    # Partial clones must fail on missing objects instead of acquiring them.
    # The protocol allowlist also enforces this on older Git versions that do
    # not recognize GIT_NO_LAZY_FETCH, regardless of per-remote configuration.
    environment = {key: os.environ[key] for key in ('PATH',) if key in os.environ}
    environment.update(LC_ALL='C', GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='',
                       GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                       GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=environment, start_new_session=True) as process:
        try:
            deadline, result = time.monotonic() + GIT_SECONDS, bytearray()
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                while ready.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        fail('pinned Git operation exceeded its deadline')
                    for key, _ in ready.select(remaining):
                        data = os.read(key.fileobj.fileno(), min(65536, maximum + 1 - len(result)))
                        if not data:
                            ready.unregister(key.fileobj)
                        result.extend(data)
                        if len(result) > maximum:
                            fail('pinned Git output exceeds its size limit')
            if process.wait(timeout=max(0.001, deadline - time.monotonic())):
                fail('pinned XR source could not be read from the local repository')
            return bytes(result)
        except subprocess.TimeoutExpired:
            fail('pinned Git operation exceeded its deadline')
        finally:
            # A subprocess retaining stdout belongs to this isolated group too.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _committed_source(repository):
    repository = f._path(repository)
    inventory = _git(repository, ['ls-tree', '-r', '-z', APPMGR_REVISION, '--',
                                 *sorted(SOURCE_FILES)], MAX_METADATA)
    expected = {}
    for row in inventory.split(b'\0'):
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, kind, blob = metadata.decode('ascii').split()
        name = name.decode('ascii')
        if kind != 'blob' or mode not in ('100644', '100755') or name in expected:
            fail('pinned XR source contains unsupported Git entries')
        expected[name] = (int(mode, 8) & 0o777, blob)
    if set(expected) != SOURCE_FILES:
        fail('pinned XR source omits required files or notices')
    # Archiving the tree avoids Git's global commit PAX header; the fixed full
    # commit still selects the tree. Every resulting blob is checked below.
    raw = _git(repository, ['archive', '--format=tar', APPMGR_REVISION + '^{tree}',
                           '--', *sorted(SOURCE_FILES)], MAX_ARCHIVE)
    entries = _source_entries(_members(raw), metadata=False)
    for name, (mode, blob) in expected.items():
        data, actual_mode = entries[name]
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if actual != blob or actual_mode != mode:
            fail('archived XR source differs from its pinned Git objects')
    return entries


def build_packaging_inputs(appmgr_repository, output_dir):
    """Create the public bundle from fixed local Git objects and the source pin."""
    entries = _committed_source(appmgr_repository)
    entries[APPMGR_METADATA] = (f._json(_appmgr_metadata()), 0o644)
    appmgr = _gzip(_tar_bytes((name, data, mode == 0o755)
                             for name, (data, mode) in entries.items()))
    metadata = {'format': 'iris-packaging-tools-v1',
                'ioxclient': {'version': IOXCLIENT_VERSION, 'platform': 'linux/amd64',
                              'delivery': 'operator-supplied', 'sha256': _ioxclient_pin()},
                'appmgr': {'archive': APPMGR_ARCHIVE, 'size': len(appmgr),
                           'sha256': hashlib.sha256(appmgr).hexdigest(),
                           'source_repository': APPMGR_REPOSITORY, 'source_revision': APPMGR_REVISION}}
    bundle = _gzip(_tar_bytes([('tools.json', f._json(metadata), False),
                               (APPMGR_ARCHIVE, appmgr, False)]))
    with _publication(output_dir) as (stage, output):
        (stage / BUNDLE).write_bytes(bundle)
    return output / BUNDLE


@dataclass(frozen=True)
class PackagingInputs:
    appmgr_archive: Path
    appmgr_sha256: str
    appmgr_revision: str
    ioxclient_sha256: str
    kit_receipt: dict


def prepare_packaging_inputs(kit, output_dir):
    """Publish verified local inputs from an authenticated kit, without execution."""
    if not isinstance(kit, release_kit.VerifiedKit):
        fail('an authenticated release kit is required')
    asset = kit.asset('packaging-tools')
    if asset.format != 'tar.gz' or not 0 < asset.size <= MAX_ARCHIVE:
        fail('authenticated packaging asset is unsupported or oversized')
    with tempfile.TemporaryDirectory(prefix='iris-packaging-read-') as temporary:
        snapshot = Path(temporary) / BUNDLE
        kit.copy_asset('packaging-tools', snapshot)
        entries = _unpack(regular_bytes(snapshot, MAX_ARCHIVE))
    if set(entries) != {'tools.json', APPMGR_ARCHIVE}:
        fail('bundle must contain exactly tool metadata and the XR source archive')
    if any(data is None or mode != 0o644 for data, mode in entries.values()):
        fail('bundle entries must be regular, nonexecutable files')
    raw = entries['tools.json'][0]
    if len(raw) > MAX_METADATA:
        fail('tool metadata exceeds its size limit')
    metadata = f._load(raw)
    expected_iox = {'version': IOXCLIENT_VERSION, 'platform': 'linux/amd64',
                    'delivery': 'operator-supplied', 'sha256': _ioxclient_pin()}
    appmgr = entries[APPMGR_ARCHIVE][0]
    expected_appmgr = {'archive': APPMGR_ARCHIVE, 'size': len(appmgr),
                      'sha256': hashlib.sha256(appmgr).hexdigest(),
                      'source_repository': APPMGR_REPOSITORY, 'source_revision': APPMGR_REVISION}
    if metadata != {'format': 'iris-packaging-tools-v1', 'ioxclient': expected_iox,
                    'appmgr': expected_appmgr} or type(metadata.get('appmgr', {}).get('size')) is not int:
        fail('tool metadata differs from the pinned source or bundled bytes')
    _source_entries(_unpack(appmgr), metadata=True)
    with _publication(output_dir) as (stage, output):
        (stage / APPMGR_ARCHIVE).write_bytes(appmgr)
        (stage / 'tools.json').write_bytes(raw)
    return PackagingInputs(output / APPMGR_ARCHIVE, expected_appmgr['sha256'],
                           APPMGR_REVISION, expected_iox['sha256'], kit.receipt())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--appmgr-repository', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_packaging_inputs(args.appmgr_repository, args.output_dir)
    except InstallError as exc:
        parser.exit(1, str(exc) + '\n')
    except (OSError, ValueError, tarfile.TarError, EOFError, zlib.error, subprocess.SubprocessError):
        parser.exit(1, 'Packaging inputs: source archive or filesystem operation failed\n')
    print(result)
    return 0
