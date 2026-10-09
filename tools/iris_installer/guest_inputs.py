# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bind Guest Shell source references to an authenticated release kit.

This small role does not duplicate the source asset or contain a ready bundle.
The authenticated server image supplies compiled verifier/AEAD helpers. Its
existing runtime publisher adds deployment public trust and verifies the served
bundle. Local production creates an unauthenticated candidate, not a signature.
"""

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import zlib

from . import device_finalize as f, release_kit
from .state import InstallError, regular_bytes


BUNDLE = 'iris-guest-inputs.tar.gz'
MANIFEST = 'guest-inputs.json'
MAX_METADATA = 64 * 1024
MAX_ARCHIVE = 128 * 1024
MAX_SOURCE = 32 * 1024**2
FIXED_FILES = frozenset((
    'VERSION', 'LICENSE', 'NOTICE',
    'device/agent/peer-transfer-hook.sh', 'device/bootstrap.sh',
    'device/guestshell-start.sh', 'device/rotate-logs.sh', 'device/verify_image.py',
    'server/pack-agent-bundle.sh', 'server/provision-served.sh', 'server/instruction_keys.py',
    'bin/aria2c', 'deliverables/aria2c-x86_64', 'deliverables/aria2c-aarch64',
    'tools/aria2c.sha256', 'tools/aria2c-source/COPYING3',
    'tools/aria2c-source/LICENSE-DISTRIBUTION.md', 'tools/aria2c-source/IRIS-MODIFICATIONS.md',
    'tools/aria2c-source/BUNDLE-README.md', 'tools/aria2c-source/source.sha256',
))
AGENT = re.compile(r'device/agent/[a-z][a-z0-9_]*\.py\Z')
IDENTITY = {
    'format': 'iris-guest-inputs-v1',
    'delivery': 'installer-source-references',
    'runtime_publisher': 'server/provision-served.sh',
    'compiled_helpers': 'authenticated-server-image',
    'deployment_trust': 'runtime-public-roots',
    'aria2': {'linux/amd64': 'deliverables/aria2c-x86_64',
              'linux/arm64': 'deliverables/aria2c-aarch64'},
}


def fail(message):
    raise InstallError('Guest inputs: ' + message)


def _selected(source_manifest):
    if not isinstance(source_manifest, dict) or not 0 < len(source_manifest) <= 100000:
        fail('the matching installer source inventory is required')
    for name, digest in source_manifest.items():
        f._name(name)
        if not isinstance(digest, str) or not f.HEX.fullmatch(digest):
            fail('source inventory has an invalid digest')
    agents = {name for name in source_manifest if AGENT.fullmatch(name)}
    selected = FIXED_FILES | agents
    if ('device/agent/iris_agent.py' not in agents or len(selected) > 128
            or not selected <= source_manifest.keys()):
        fail('source inventory omits required Guest Shell inputs or notices')
    return selected


def _read_source(path, *, keep=False):
    path = f._path(path)
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_SOURCE
                or stat.S_IMODE(info.st_mode) not in (0o644, 0o755)
                or f._fingerprint(info) != f._fingerprint(before)):
            fail('source input must be a bounded unchanged regular file with canonical permissions')
        data = io.BytesIO() if keep else None
        digest, size = f._copy(stream, data, MAX_SOURCE)
        if f._fingerprint(os.fstat(stream.fileno())) != f._fingerprint(info):
            fail('source input changed while being read')
    f._unchanged(path, info)
    return ({'sha256': digest, 'size': size, 'mode': stat.S_IMODE(info.st_mode)},
            data.getvalue() if data else None, (path, info))


def _source_metadata(source_dir, source_manifest):
    names = _selected(source_manifest)
    source = f._path(source_dir)
    root = source.lstat()
    if not stat.S_ISDIR(root.st_mode):
        fail('source directory is required')
    # pack-agent-bundle.sh includes every direct *.py, not the tests subtree.
    agent_dir = f._path(source / 'device/agent')
    agent_info = agent_dir.lstat()
    actual_agents = {'device/agent/' + path.name for path in agent_dir.iterdir()
                     if path.name.endswith('.py')}
    if actual_agents != {name for name in names if AGENT.fullmatch(name)}:
        fail('source agent files differ from the installer inventory')
    files, observations, content = {}, [], {}
    for name in sorted(names):
        metadata, data, observation = _read_source(source / name, keep=name == 'tools/aria2c.sha256')
        if metadata['sha256'] != source_manifest[name]:
            fail('source bytes differ from the installer inventory')
        files[name] = metadata
        observations.append(observation)
        if data is not None:
            content[name] = data
    pins = {}
    try:
        for line in content['tools/aria2c.sha256'].decode('utf-8').splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            match = re.fullmatch(r'([a-f0-9]{64})  (x86_64|aarch64)', line)
            if match is None or match[2] in pins:
                fail('aria2 source pins are invalid')
            pins[match[2]] = match[1]
    except UnicodeError:
        fail('aria2 source pins are invalid')
    if set(pins) != {'x86_64', 'aarch64'}:
        fail('both committed aria2 architectures must be pinned')
    for architecture, digest in pins.items():
        item = files['deliverables/aria2c-' + architecture]
        if item['sha256'] != digest or item['mode'] != 0o755:
            fail('committed aria2 bytes differ from the source pins')
    if files['bin/aria2c'] != files['deliverables/aria2c-x86_64']:
        fail('server aria2 alias differs from the committed amd64 input')
    for path, info in observations:
        f._unchanged(path, info)
    f._unchanged(agent_dir, agent_info)
    current = source.lstat()
    if f._path(source) != source or (current.st_dev, current.st_ino) != (root.st_dev, root.st_ino):
        fail('source directory changed during verification')
    return {**IDENTITY, 'files': files}


def _bundle(raw):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
            item = tarfile.TarInfo(MANIFEST)
            item.mode, item.size = 0o644, len(raw)
            archive.addfile(item, io.BytesIO(raw))
    return buffer.getvalue()


def _unpack(data):
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            raw = stream.read(MAX_ARCHIVE + 1)
        if len(raw) > MAX_ARCHIVE:
            fail('archive exceeds its expansion limit')
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:', tarinfo=f._TarInfo) as archive:
            members = f._members(archive)
            if len(raw) % 512 or len(raw) - archive.offset < 1024:
                fail('reference archive is not completely terminated')
            if set(members) != {MANIFEST}:
                fail('archive must contain exactly the reference manifest')
            item = members[MANIFEST]
            if (not item.isfile() or item.mode != 0o644 or item.uid or item.gid
                    or item.mtime != 0 or item.pax_headers or item.linkname or item.uname or item.gname
                    or not 0 < item.size <= MAX_METADATA):
                fail('reference manifest has invalid type, size or metadata')
            result = archive.extractfile(item).read(MAX_METADATA + 1)
            if len(result) != item.size:
                fail('reference manifest is truncated')
            return result
    except (OSError, ValueError, EOFError, tarfile.TarError, zlib.error):
        fail('reference archive is invalid')


@contextmanager
def _publication(destination):
    output = f._path(destination)
    descriptor = release_kit._protected_directory(output.parent)
    stage, published = None, False
    try:
        before = os.fstat(descriptor)
        if before.st_uid != os.geteuid() or before.st_mode & 0o022:
            fail('output parent must be caller-owned and protected')
        if output.exists() or output.is_symlink():
            fail('output already exists')
        stage = Path(tempfile.mkdtemp(prefix='.iris-guest-',
            dir=Path('/proc/self/fd') / str(descriptor)))
        yield stage, output
        artifact = stage / BUNDLE
        artifact.chmod(0o444)
        with artifact.open('rb') as stream:
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


def build_guest_inputs(source_dir, source_manifest, output_dir):
    """Produce a candidate from local inventoried files; never build or fetch."""
    raw = f._json(_source_metadata(source_dir, source_manifest))
    if len(raw) > MAX_METADATA:
        fail('reference manifest exceeds its size limit')
    with _publication(output_dir) as (stage, output):
        (stage / BUNDLE).write_bytes(_bundle(raw))
    return output / BUNDLE


def verify_guest_inputs(kit, source_dir, source_manifest):
    """Bind authenticated references to the matching installed source snapshot.

    The caller separately authenticates source_manifest against the source role
    and retains runtime publication/doctor checks. This receipt is not evidence
    that a deployment-specific Guest Shell bundle has been published.
    """
    if not isinstance(kit, release_kit.VerifiedKit):
        fail('an authenticated release kit is required')
    asset = kit.asset('guest-inputs')
    if asset.format != 'tar.gz' or not 0 < asset.size <= MAX_ARCHIVE:
        fail('authenticated guest asset is unsupported or oversized')
    with tempfile.TemporaryDirectory(prefix='iris-guest-read-') as temporary:
        snapshot = Path(temporary) / BUNDLE
        kit.copy_asset('guest-inputs', snapshot)
        raw = _unpack(regular_bytes(snapshot, MAX_ARCHIVE))
    metadata = f._load(raw)
    expected = _source_metadata(source_dir, source_manifest)
    # Canonical JSON comparison also rejects bool-as-int metadata substitutions.
    if f._json(metadata) != f._json(expected):
        fail('authenticated references differ from the installed source inputs')
    return {'schema': 1, 'kit_receipt': kit.receipt(),
            'manifest_sha256': hashlib.sha256(raw).hexdigest(),
            'input_count': len(expected['files'])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--source-manifest', type=Path, required=True,
                        help='INSTALLER-SOURCE.json path-to-SHA256 inventory')
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        inventory = f._load(regular_bytes(args.source_manifest, f.MAX_JSON))
        result = build_guest_inputs(args.source_dir, inventory, args.output_dir)
    except InstallError as exc:
        parser.exit(1, str(exc) + '\n')
    except (OSError, ValueError, tarfile.TarError, EOFError, zlib.error):
        parser.exit(1, 'Guest inputs: source or filesystem operation failed\n')
    print(result)
    return 0
