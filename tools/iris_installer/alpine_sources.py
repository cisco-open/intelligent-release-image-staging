# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Collect exact Alpine port and checksum-listed source bytes without executing recipes."""

import argparse
from contextlib import contextmanager
from functools import lru_cache
import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import secrets
import tarfile
import tempfile
import zlib

from . import device_finalize as f, release_kit as kit
from .offline_inputs import _new_directory, _output_file, _same_directory
from .packaging_inputs import _publication
from .state import InstallError


SCHEMA = 'iris-alpine-sources-v1'
BUNDLE = 'iris-alpine-sources.tar.gz'
MANIFEST = 'source-manifest.json'
MAX_METADATA = 64 * 1024**2
MAX_GIT = 16 * 1024**2
MAX_GIT_TOTAL = 128 * 1024**2
MAX_FILE = 2 * 1024**3
MAX_TOTAL = 16 * 1024**3
MAX_MEMBERS = 50000
SHA1 = re.compile('[a-f0-9]{40}\\Z')
SHA512 = re.compile('[a-f0-9]{128}\\Z')
ATOM = re.compile('[a-zA-Z0-9][a-zA-Z0-9+_.~-]{0,159}\\Z')
# These exact reviewed recipes generate their content without external sources.
# Absence of a checksum declaration is never a general source-less exemption.
SOURCELESS = {
    ('alpine-base', '3.24.2-r0', 'd9d560d5de74ff9a7a73f3c903d6f126a0bf3142'):
        '5f3e6446e3e80b20e0f9986760b9f151e47e723e57d32c108bce617846d05b52',
    ('krb5-conf', '1.0-r2', '4a46b2cb955e25fd6d6f913794d35bc6d876aea9'):
        '7962206597c478b726f46b0392a73bec21bfa70afa56c62ccb043d1ade3d6286',
}
README = b'''Alpine source-only companion

The externally pinned image inventory selects every Alpine origin/version and
aports commit, including all retained layers and architectures. evidence/git/
contains raw Git commit/tree objects; their object hashes bind the complete
selected port directories. ports/ preserves each regular file and executable
mode. A Git symlink is stored as a regular file containing its target text;
port_files explicitly records git_mode 120000 and that inert representation.
No archive symlink is created or followed. Review original recipes before use.

sources/sha512/ contains every file in each complete literal APKBUILD SHA512
inventory, including other-architecture inputs. Matching port-local patches
come from the pinned Git tree; other source blobs come from explicit local
inputs. No source URL, shell expansion, package recipe or build is executed.
The two reviewed source-less recipes generate only metadata/configuration.

This is source-byte and Git-content evidence, not a publisher attestation,
reproducible-binary proof, complete-image source/notices coverage, or legal
approval. Copied runtimes, non-Alpine components and image notice sufficiency
remain separate. Original source licenses and build instructions are retained
inside upstream archives and port directories, not reinterpreted here.
'''


def fail(message):
    raise InstallError('Alpine source companion: ' + message)


def _relative(name):
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_./+@%:~-]+', name)
            or len(name) > 4096 or any(len(part) > 255 for part in name.split('/'))):
        fail('unsafe source path')
    return f._name(name)


def _object_hash(kind, data):
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data,
                        usedforsecurity=False).hexdigest()


@lru_cache(maxsize=1)
def _candidate():
    base = Path(__file__).resolve().parents[1]
    path = base / 'source/tools/build-release-candidate.py'
    if not path.exists():
        path = base / 'build-release-candidate.py'
    spec = importlib.util.spec_from_file_location('iris_alpine_local_git', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git_object(repository, kind, digest):
    if kind not in ('commit', 'tree', 'blob') or not SHA1.fullmatch(digest):
        fail('invalid Git object identity')
    # Reuse the bounded/deadline-controlled reader, with no inherited Git
    # environment, owner configuration authority, transport or lazy fetching.
    environment = {'PATH': os.defpath, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_NO_REPLACE_OBJECTS': '1',
        'GIT_NO_LAZY_FETCH': '1', 'GIT_ALLOW_PROTOCOL': '', 'GIT_TERMINAL_PROMPT': '0'}
    data = _candidate()._git(repository, ['cat-file', kind, digest], environment)
    if len(data) > MAX_GIT or _object_hash(kind, data) != digest:
        fail('local Git object differs from its selected content hash')
    return data


def _tree(data):
    result, cursor = {}, 0
    while cursor < len(data):
        end = data.find(b'\0', cursor)
        if end < 0 or end + 21 > len(data) or len(result) >= MAX_MEMBERS:
            fail('invalid Git tree encoding')
        try:
            mode, name = data[cursor:end].decode('ascii').split(' ', 1)
        except (UnicodeError, ValueError):
            fail('unsupported Git tree name')
        _relative(name)
        if '/' in name or name in result or mode not in ('40000', '100644', '100755', '120000', '160000'):
            fail('invalid or repeated Git tree entry')
        result[name] = (mode, data[end + 1:end + 21].hex())
        cursor = end + 21
    return result


@contextmanager
def _external(path, maximum):
    path = f._path(path)
    descriptor, before = kit._open(path, maximum)
    try:
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            yield stream
        if kit._identity(before) != kit._identity(os.fstat(descriptor)):
            fail('input changed during its private read')
        f._unchanged(path, before)
    finally:
        os.close(descriptor)


def _inventory(path, expected):
    kit._sha(expected)
    with _external(path, MAX_METADATA) as stream:
        data = stream.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA or hashlib.sha256(data).hexdigest() != expected:
        fail('external image inventory differs from its expected digest')
    value = kit._json(data)
    if (not isinstance(value, dict) or value.get('format') != 'iris-image-component-inventory-v1'
            or not isinstance(value.get('images'), dict) or not 1 <= len(value['images']) <= 16):
        fail('unsupported image inventory')
    required, virtual, count = {}, [], 0
    for role, image in sorted(value['images'].items()):
        _relative(role)
        if not isinstance(image, dict):
            fail('invalid image record')
        kit._sha(image.get('archive_sha256'))
        views = image.get('platforms', [image])
        if not isinstance(views, list) or not 1 <= len(views) <= 8:
            fail('invalid image platform inventory')
        for view in views:
            if not isinstance(view, dict):
                fail('invalid platform record')
            platform, config = view.get('platform'), view.get('config_digest')
            if platform not in ('linux/amd64', 'linux/arm64') or not isinstance(config, str) or not re.fullmatch('sha256:[a-f0-9]{64}', config):
                fail('invalid image platform identity')
            layers = view.get('layers')
            if not isinstance(layers, list) or not 1 <= len(layers) <= 256:
                fail('invalid retained layer inventory')
            occurrences = [('merged', None, view.get('merged'))]
            for index, layer in enumerate(layers):
                if (not isinstance(layer, dict) or type(layer.get('index')) is not int
                        or layer['index'] != index or not isinstance(layer.get('diff_id'), str)
                        or not re.fullmatch('sha256:[a-f0-9]{64}', layer['diff_id'])):
                    fail('invalid retained layer identity')
                occurrences.append((index, layer['diff_id'], layer.get('inventory')))
            for index, diff_id, summary in occurrences:
                if not isinstance(summary, dict) or not isinstance(summary.get('package_databases'), list):
                    fail('missing package database inventory')
                for database in summary['package_databases']:
                    if not isinstance(database, dict):
                        fail('invalid package database record')
                    if database.get('ecosystem') != 'alpine':
                        continue
                    if database.get('path') != 'lib/apk/db/installed' or not isinstance(database.get('packages'), list):
                        fail('unsupported Alpine database inventory')
                    kit._sha(database.get('sha256'))
                    for package in database['packages']:
                        if not isinstance(package, dict):
                            fail('invalid package record')
                        count += 1
                        if count > MAX_MEMBERS:
                            fail('excessive package occurrence inventory')
                        name, version, architecture = (package.get(key) for key in ('package', 'version', 'architecture'))
                        if (not isinstance(name, str) or not isinstance(version, str) or not ATOM.fullmatch(version)
                                or architecture not in ('noarch', 'x86_64' if platform == 'linux/amd64' else 'aarch64')
                                or type(package.get('virtual')) is not bool):
                            fail('invalid Alpine package identity')
                        occurrence = {'image': role, 'archive_sha256': image['archive_sha256'],
                            'platform': platform, 'config_digest': config, 'layer': index,
                            'diff_id': diff_id, 'database_sha256': database['sha256'],
                            'package': name, 'architecture': architecture}
                        if package['virtual']:
                            if name != '.python-rundeps' or package.get('origin') is not None or package.get('aports_commit') is not None or package.get('declared_file_count') != 0:
                                fail('unsupported virtual package')
                            virtual.append(dict(occurrence, version=version))
                            continue
                        origin, revision = package.get('origin'), package.get('aports_commit')
                        if (not ATOM.fullmatch(name) or not isinstance(origin, str) or not ATOM.fullmatch(origin)
                                or not isinstance(revision, str) or not SHA1.fullmatch(revision)):
                            fail('missing exact Alpine source identity')
                        required.setdefault((origin, version, revision), []).append(occurrence)
    if not required or len(required) > 1024:
        fail('no bounded Alpine source closure was selected')
    return required, virtual


def _recipe(data, identity):
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        fail('APKBUILD is not UTF-8')
    if len(data) > 1024**2 or '\0' in text:
        fail('APKBUILD exceeds supported bounds')
    fields = {}
    for key in ('pkgname', 'pkgver', 'pkgrel'):
        values = re.findall(r'^' + key + r'=([^\n]*)$', text, re.M)
        if len(values) != 1 or not ATOM.fullmatch(values[0]):
            fail('APKBUILD package identity must be an exact literal')
        fields[key] = values[0]
    if (fields['pkgname'], fields['pkgver'] + '-r' + fields['pkgrel']) != identity[:2]:
        fail('APKBUILD version differs from the image package identity')
    if identity in SOURCELESS:
        if hashlib.sha256(data).hexdigest() != SOURCELESS[identity]:
            fail('source-less recipe differs from its reviewed identity')
        return {}
    # Source URLs may use shell loops and version expressions. Do not evaluate
    # them: retain every literal checksum operand, even for unselected arches.
    declarations = re.findall(r'(?m)^\s*(?:export\s+)?(?:md5sums|sha256sums|sha512sums|b2sums)\s*\+?=', text)
    matches = list(re.finditer(r'(?m)^sha512sums="([^"$`\\]*)"[ \t]*(?:#[^\n]*)?(?:\n|\Z)', text))
    if len(declarations) != 1 or len(matches) != 1:
        fail('APKBUILD needs one complete literal SHA512 inventory')
    remainder = text[:matches[0].start()] + text[matches[0].end():]
    remainder = '\n'.join(line for line in remainder.splitlines() if not line.lstrip().startswith('#'))
    if re.search(r'\b(?:md5sums|sha256sums|sha512sums|b2sums)\b', remainder):
        fail('additional checksum computation or mutation is unsupported')
    result = {}
    for line in matches[0][1].splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or not SHA512.fullmatch(parts[0]):
            fail('unsupported or skipped APKBUILD source checksum')
        digest, name = parts
        _relative(name)
        if '/' in name or name in result or len(result) >= 4096:
            fail('duplicate or unsupported source checksum filename')
        result[name] = digest
    if not result:
        fail('empty source checksum inventory is not source-less evidence')
    return result


class _Sink:
    def __init__(self, loader, directory=None, actual=None):
        self.loader, self.directory, self.actual = loader, directory, actual
        self.files, self.data, self.total, self.git_total = {}, {}, 0, 0

    def record(self, name, digest, size, mode):
        _relative(name)
        row = {'sha256': digest, 'size': size, 'mode': mode}
        if name in self.files:
            if self.files[name] != row:
                fail('conflicting shared source file')
            return
        if self.actual is not None and self.actual.get(name) != row:
            fail('source archive bytes differ from independently selected inputs')
        self.total += size
        if self.total > MAX_TOTAL or len(self.files) >= MAX_MEMBERS:
            fail('source companion exceeds its limits')
        self.files[name] = row

    def add(self, name, data, mode=0o644):
        digest = hashlib.sha256(data).hexdigest()
        self.record(name, digest, len(data), mode)
        if name not in self.data:
            self.git_total += len(data)
            if self.git_total > MAX_GIT_TOTAL:
                fail('Git/source metadata exceeds its total bound')
            self.data[name] = data

    def source(self, checksum, local=None):
        name = 'sources/sha512/' + checksum
        if name in self.files:
            return name
        if local is not None:
            if hashlib.sha512(local).hexdigest() != checksum:
                fail('port-local source differs from its APKBUILD checksum')
            self.add(name, local)
            return name
        sha256, sha512, size = hashlib.sha256(), hashlib.sha512(), 0
        with self.loader(checksum) as source:
            output = _output_file(self.directory, checksum) if self.directory is not None else None
            try:
                while block := source.read(kit.CHUNK):
                    size += len(block)
                    if size > MAX_FILE or size + self.total > MAX_TOTAL:
                        fail('source blob exceeds its size limit')
                    sha256.update(block)
                    sha512.update(block)
                    if output is not None:
                        output.write(block)
            finally:
                if output is not None:
                    output.close()
        if not size or sha512.hexdigest() != checksum:
            fail('source blob differs from its APKBUILD checksum')
        self.record(name, sha256.hexdigest(), size, 0o644)
        return name


def _assemble(required, virtual, inventory_sha256, get_object, get_blob, sink):
    cache = {}

    def object_bytes(kind, digest):
        key = kind, digest
        if key not in cache:
            data = get_object(kind, digest)
            if len(data) > MAX_GIT or _object_hash(kind, data) != digest:
                fail('Git proof object differs from its selected content hash')
            sink.add('evidence/git/' + digest + '.' + kind, data)
            cache[key] = data
        return cache[key]

    def tree(digest):
        return _tree(object_bytes('tree', digest))

    records = []
    for identity, occurrences in sorted(required.items()):
        origin, version, revision = identity
        commit = object_bytes('commit', revision)
        root_line = commit.split(b'\n', 1)[0]
        if re.fullmatch(b'tree [a-f0-9]{40}', root_line) is None:
            fail('Git commit omits its exact root tree')
        root = tree(root_line[5:].decode())
        choices = []
        for section in ('main', 'community', 'testing'):
            if section in root:
                mode, digest = root[section]
                if mode != '40000':
                    fail('aports section is not a directory')
                ports = tree(digest)
                if origin in ports:
                    choices.append((section, *ports[origin]))
        if len(choices) != 1 or choices[0][1] != '40000':
            fail('pinned source port is missing or ambiguous')
        section, _, port_digest = choices[0]
        prefix = 'ports/' + origin + '/' + version + '/' + revision + '/'
        files, pending = {}, [('', port_digest, 0)]
        while pending:
            parent, digest, depth = pending.pop()
            if depth > 16:
                fail('port tree nesting exceeds its bound')
            for name, (mode, blob) in sorted(tree(digest).items()):
                relative = parent + name
                if mode == '40000':
                    pending.append((relative + '/', blob, depth + 1))
                    continue
                if mode not in ('100644', '100755', '120000') or len(files) >= 4096:
                    fail('port has an unsupported Git entry')
                path = prefix + relative
                data = get_blob(blob, path)
                if len(data) > MAX_GIT or _object_hash('blob', data) != blob:
                    fail('port file differs from its Git blob')
                if mode == '120000' and (not data or len(data) > 4096 or b'\0' in data):
                    fail('invalid inert Git symlink representation')
                sink.add(path, data, 0o755 if mode == '100755' else 0o644)
                files[relative] = {'path': path, 'blob': blob, 'git_mode': mode,
                    'representation': 'symlink-target-text' if mode == '120000' else 'regular-file', '_data': data}
        if 'APKBUILD' not in files or files['APKBUILD']['git_mode'] != '100644':
            fail('port omits a regular APKBUILD')
        checksums = _recipe(files['APKBUILD']['_data'], identity)
        inputs = []
        for name, checksum in sorted(checksums.items()):
            local = files.get(name)
            if local is not None and local['git_mode'] == '120000':
                fail('checksum-listed source cannot be an unresolved port symlink')
            path = sink.source(checksum, local['_data'] if local is not None else None)
            inputs.append({'filename': name, 'sha512': checksum, 'path': path,
                           'origin': 'port' if local is not None else 'local-source-pool'})
        records.append({'origin': origin, 'version': version, 'aports_commit': revision,
            'port': section + '/' + origin, 'source_less': not checksums,
            'port_files': {name: {key: val for key, val in row.items() if key != '_data'} for name, row in sorted(files.items())},
            'inputs': inputs, 'occurrences': sorted(occurrences, key=f._json)})
    sink.add('README.txt', README)
    return {'schema': SCHEMA, 'inventory_sha256': inventory_sha256,
        'scope': 'alpine-port-and-literal-checksum-inputs-only', 'authenticated': False,
        'source_coverage_complete': False, 'sources': records,
        'virtual_packages': sorted(virtual, key=f._json), 'files': dict(sorted(sink.files.items()))}


@contextmanager
def _private_archive(path, *, descriptor=None):
    # Snapshot before parsing and keep both compressed and expanded bytes on
    # anonymous held files. No extraction path or archive program is involved.
    with tempfile.TemporaryFile() as snapshot, tempfile.TemporaryFile() as plain:
        context = _external(path, MAX_TOTAL) if descriptor is None else os.fdopen(os.dup(descriptor), 'rb')
        with context as stream:
            f._copy(stream, snapshot, MAX_TOTAL)
        snapshot.seek(0)
        with gzip.GzipFile(fileobj=snapshot) as expanded:
            f._copy(expanded, plain, MAX_TOTAL + MAX_METADATA)
        length = plain.tell()
        plain.seek(0)
        with tarfile.open(fileobj=plain, mode='r:', tarinfo=kit._BoundedTarInfo) as archive:
            actual, members, manifest, total = {}, {}, None, 0
            for member in archive:
                name = _relative(member.name)
                if (not member.isfile() or name in members or len(members) >= MAX_MEMBERS
                        or not 0 <= member.size <= MAX_FILE or member.mode not in (0o644, 0o755)
                        or member.uid or member.gid or member.uname or member.gname or member.mtime
                        or any(key != 'path' for key in member.pax_headers)):
                    fail('unsupported source archive member')
                total += member.size
                if total > MAX_TOTAL:
                    fail('source archive exceeds its total size bound')
                source = archive.extractfile(member)
                if name == MANIFEST:
                    if member.size > MAX_METADATA or member.mode != 0o644:
                        fail('source manifest exceeds supported bounds')
                    manifest = kit._json(source.read(MAX_METADATA + 1))
                else:
                    digest, size = f._copy(source, None, MAX_FILE)
                    actual[name] = {'sha256': digest, 'size': size, 'mode': member.mode}
                members[name] = member
            if length % 512 or length - archive.offset < 1024:
                fail('source archive is not completely terminated')
            plain.seek(archive.offset)
            while tail := plain.read(kit.CHUNK):
                if tail.strip(b'\0'):
                    fail('source archive contains trailing payload')
            if not isinstance(manifest, dict) or manifest.get('files') != actual:
                fail('source archive is not a closed file inventory')
            yield archive, members, manifest, actual


def validate_source_archive(archive, inventory, inventory_sha256):
    """Recompute Git/source evidence using the external image inventory as authority."""
    return _validate_archive(archive, inventory, inventory_sha256)


def _validate_archive(archive, inventory, inventory_sha256, *, descriptor=None):
    required, virtual = _inventory(inventory, inventory_sha256)
    with _private_archive(archive, descriptor=descriptor) as (stream, members, manifest, actual):
        def read(name):
            if name not in members or members[name].size > MAX_GIT:
                fail('missing or oversized Git evidence')
            return stream.extractfile(members[name]).read(MAX_GIT + 1)

        @contextmanager
        def source(checksum):
            name = 'sources/sha512/' + checksum
            if name not in members:
                fail('missing checksum-selected source blob')
            with stream.extractfile(members[name]) as value:
                yield value

        sink = _Sink(source, actual=actual)
        expected = _assemble(required, virtual, inventory_sha256,
            lambda kind, digest: read('evidence/git/' + digest + '.' + kind),
            lambda digest, path: read(path), sink)
        if f._json(expected) != f._json(manifest):
            fail('source evidence differs from independent inventory/Git reconstruction')
        return expected


def build_sources(inventory, inventory_sha256, aports_repository, source_pool, output_dir):
    """Publish a deterministic new companion using only explicit local inputs."""
    required, virtual = _inventory(inventory, inventory_sha256)
    repository, pool = f._path(aports_repository), f._path(source_pool)
    work = Path('/tmp') / ('iris-alpine-source-' + secrets.token_hex(16))
    with _publication(output_dir) as (stage, output), _new_directory(work, remove=True) as descriptor:
        sink = _Sink(lambda checksum: _external(pool / checksum, MAX_FILE), descriptor)
        manifest = _assemble(required, virtual, inventory_sha256,
            lambda kind, digest: _git_object(repository, kind, digest),
            lambda digest, path: _git_object(repository, 'blob', digest), sink)
        encoded = f._json(manifest)
        if len(encoded) > MAX_METADATA:
            fail('source manifest exceeds its size limit')
        candidate = stage / BUNDLE
        with candidate.open('xb') as raw, gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name in sorted([MANIFEST, *sink.files]):
                    info = tarfile.TarInfo(name)
                    info.size = len(encoded) if name == MANIFEST else sink.files[name]['size']
                    info.mode = 0o644 if name == MANIFEST else sink.files[name]['mode']
                    if name == MANIFEST or name in sink.data:
                        with io.BytesIO(encoded if name == MANIFEST else sink.data[name]) as source:
                            archive.addfile(info, source)
                    else:
                        held = os.open(name.rsplit('/', 1)[1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                        with os.fdopen(held, 'rb') as source:
                            archive.addfile(info, source)
        _same_directory(work, descriptor)
        # Independently validate the exact staged archive before publication.
        # A held file below FD-anchored staging is not an external /proc locator.
        with candidate.open('rb') as stream:
            _validate_archive(None, inventory, inventory_sha256, descriptor=stream.fileno())
            stream.seek(0)
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        (stage / MANIFEST).write_bytes(encoded)
        result = {'archive': str(output / BUNDLE), 'sha256': digest,
            'manifest_sha256': hashlib.sha256(encoded).hexdigest(), 'inventory_sha256': inventory_sha256,
            'sources': len(manifest['sources']), 'authenticated': False, 'source_coverage_complete': False}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--inventory-sha256', required=True)
    parser.add_argument('--aports-repository', type=Path, required=True)
    parser.add_argument('--source-pool', type=Path, required=True,
                        help='local files named by their complete lowercase SHA512')
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_sources(**vars(args))
    except (InstallError, OSError, ValueError, tarfile.TarError, EOFError, zlib.error):
        parser.exit(1, 'Alpine source collection failed; no recipe was executed or output replaced.\n')
    print(f._json(result).decode(), end='')
    return 0
