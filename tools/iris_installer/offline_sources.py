# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Assemble authenticated Ubuntu corresponding-source inputs without fetching.

Historical metadata is explicitly limited to this source-only producer. It is
never passed to apt or the installer dependency consumer. No source recipe runs.
"""

from datetime import datetime, timedelta, timezone
from contextlib import ExitStack
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import secrets
import selectors
import subprocess
import tarfile
import tempfile
import time
import zlib

from . import offline_dependencies as dependencies, offline_inputs, release_kit
from .state import InstallError, regular_bytes


SCHEMA = 'iris-ubuntu-sources-v1'
INPUT_SCHEMA = 'iris-ubuntu-source-inputs-v1'
MANIFEST = 'source-manifest.json'
MAX_FILE = 2 * 1024**3
MAX_TOTAL = 16 * 1024**3
MAX_INDEX = 64 * 1024**2
MAX_EXPANDED_INDEX = 512 * 1024**2
MAX_MEMBERS = 50000
INDEX_FIELDS = {'repository', 'suite', 'component', 'inrelease', 'sources', 'historical'}
LOCATIONS = {(repository, suite, component) for repository, suite, _ in dependencies.REPOSITORIES
             for component in dependencies.COMPONENTS}
README = b'''Ubuntu source and notice companion

source-manifest.json binds the exact binary dependency-manifest SHA-256. Use
that binary bundle to verify the binary-to-source relationship independently.
The binaries list names each direct Source and incorporated Built-Using (and,
when present, Static-Built-Using) source version. The sources list maps those
exact identities to original Ubuntu pool files, including each .dsc and all
original tar archives, packaging changes, signatures and other indexed files.

evidence/ contains Ubuntu-signed InRelease documents and matching Sources.xz
indexes. Explicit historical evidence is source-only; it cannot authorize an
installer package version or relax any apt trust/freshness policy. SHA-256 file
inventories cover every member except the manifest itself. Authenticate this
companion's outer release asset before relying on it as a release receipt.

notices/ preserves copyright and common-license bytes from the binary packages.
The notice_aliases mapping records original documentation/license links without
creating archive links. Each binary's copyright path names its resolved notice.
Consult the original source packages for upstream notices and build instructions.
On a separately prepared build host, Debian source tooling can unpack the listed
.dsc and adjacent source files; review debian/ and upstream build instructions.
This producer does not install build dependencies, run recipes, or claim a
reproducible rebuild. Original component terms remain applicable. This inventory
is not legal approval or a claim that every component has identical obligations.
'''


def _canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def _relative(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_./+%:~@-]+', value)
            or PurePosixPath(value).is_absolute() or '..' in PurePosixPath(value).parts
            or str(PurePosixPath(value)) != value or len(value.encode()) > 4096
            or any(len(part) > 255 for part in PurePosixPath(value).parts)):
        raise InstallError('Ubuntu source path is unsafe or exceeds supported bounds')
    return value


def _record(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def _bytes(path, maximum):
    descriptor, before = release_kit._open(Path(path), maximum)
    try:
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            data = stream.read(maximum + 1)
        if len(data) != before.st_size or release_kit._identity(before) != release_kit._identity(os.fstat(descriptor)):
            raise InstallError('Ubuntu source metadata changed during inspection')
        return data
    finally:
        os.close(descriptor)


def _write(directory, name, data, files):
    name = _relative(name)
    with offline_inputs._output_file(directory, name) as output:
        output.write(data)
    files[name] = _record(data)


def _copy(source, directory, name, files, *, maximum=MAX_FILE, expected=None):
    name = _relative(name)
    descriptor, before = release_kit._open(Path(source), maximum)
    try:
        with offline_inputs._output_file(directory, name) as output:
            digest, size = release_kit._hash(descriptor, maximum, output)
        if release_kit._identity(before) != release_kit._identity(os.fstat(descriptor)) or size != before.st_size:
            raise InstallError('Ubuntu source input changed during its private copy')
        result = {'sha256': digest, 'size': size}
        if expected is not None and result != expected:
            raise InstallError('Ubuntu source file differs from signed metadata: ' + name)
        files[name] = result
        return result
    finally:
        os.close(descriptor)


def load_index_inputs(path):
    value = release_kit._json(regular_bytes(path, 1024**2))
    release_kit._keys(value, {'schema', 'indexes'})
    if value['schema'] != INPUT_SCHEMA:
        raise InstallError('Unsupported Ubuntu source input descriptor')
    return _input_descriptors(value['indexes'])


def _input_descriptors(values):
    if not isinstance(values, list) or not 6 <= len(values) <= 64:
        raise InstallError('Supply all six current Ubuntu source indexes and bounded historical inputs')
    current, unique = set(), set()
    for value in values:
        release_kit._keys(value, INDEX_FIELDS)
        location = tuple(value[key] for key in ('repository', 'suite', 'component'))
        if (any(not isinstance(item, str) for item in location) or location not in LOCATIONS
                or type(value['historical']) is not bool):
            raise InstallError('Unsupported Ubuntu source repository or historical policy')
        for key in ('inrelease', 'sources'):
            if not isinstance(value[key], str):
                raise InstallError('Ubuntu source index locators must be absolute paths')
            release_kit._path(Path(value[key]))
        identity = (*location, value['inrelease'], value['sources'])
        if identity in unique or (not value['historical'] and location in current):
            raise InstallError('Duplicate Ubuntu source index descriptor')
        unique.add(identity)
        if not value['historical']:
            current.add(location)
    if current != LOCATIONS:
        raise InstallError('Current Ubuntu source index coverage is incomplete')
    return values


def _source(binary, field):
    match = re.fullmatch(r'([a-z0-9][a-z0-9+.-]*)(?: \(([^()\s]+)\))?', field or binary['name'])
    if match is None:
        raise InstallError('Unsupported Ubuntu source identity')
    return {'name': match[1], 'version': match[2] or binary['version']}


def _using(field):
    result = []
    for item in field.split(','):
        if not item.strip():
            continue
        match = re.fullmatch(r'\s*([a-z0-9][a-z0-9+.-]*)\s*\(=\s*([^()\s]+)\)\s*', item)
        if match is None:
            raise InstallError('Ubuntu incorporated sources need exact versions')
        result.append({'name': match[1], 'version': match[2]})
    if len({(row['name'], row['version']) for row in result}) != len(result):
        raise InstallError('Duplicate incorporated source identity')
    return sorted(result, key=lambda row: (row['name'], row['version']))


def _binary_sources(closure):
    wanted = {tuple(row[key] for key in ('repository', 'suite', 'component', 'name', 'version', 'architecture')): row
              for row in closure.manifest['packages']}
    found = {}
    for repository, suite, component in sorted(LOCATIONS):
        path = closure.directory / 'repositories' / repository / 'dists' / suite / component / 'binary-amd64/Packages'
        with path.open(encoding='utf-8') as stream:
            for row in dependencies._paragraphs(stream):
                identity = repository, suite, component, row.get('Package'), row.get('Version'), row.get('Architecture')
                if identity not in wanted:
                    continue
                if identity in found:
                    raise InstallError('Ambiguous signed binary source identity')
                binary = wanted[identity]
                control = dependencies._run(['/usr/bin/dpkg-deb', '--field',
                    str(closure.directory / 'repositories' / repository / binary['filename'])])
                records = list(dependencies._paragraphs(io.StringIO(control)))
                if len(records) != 1:
                    raise InstallError('Invalid binary source control metadata')
                result = {key: binary[key] for key in ('name', 'version', 'architecture')}
                result['source'] = _source(binary, row.get('Source'))
                if result['source'] != _source(binary, records[0].get('Source')):
                    raise InstallError('Signed index and binary Source fields disagree')
                for field, key in (('Built-Using', 'built_using'), ('Static-Built-Using', 'static_built_using')):
                    result[key] = _using(row.get(field, ''))
                    if result[key] != _using(records[0].get(field, '')):
                        raise InstallError('Signed index and incorporated binary sources disagree')
                found[identity] = result
    if set(found) != set(wanted):
        raise InstallError('Incomplete signed binary source mapping')
    return sorted(found.values(), key=lambda row: (row['name'], row['architecture']))


def _checksums(field, *, filenames=False, allow_empty=False, maximum=MAX_FILE):
    result = {}
    for line in field.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3:
            raise InstallError('Malformed Ubuntu source checksum record')
        digest, size, name = parts
        release_kit._sha(digest)
        _relative(name)
        if (name in result or (filenames and '/' in name) or not size.isdecimal()
                or not (0 if allow_empty else 1) <= int(size) <= maximum or len(result) >= MAX_MEMBERS):
            raise InstallError('Invalid or duplicate Ubuntu source checksum entry')
        result[name] = {'sha256': digest, 'size': int(size)}
    if not result:
        raise InstallError('Missing SHA-256 Ubuntu source inventory')
    return result


def _expand_index(data):
    # Ubuntu indexes can append an empty XZ stream. Decode every stream under
    # one aggregate limit, then compare the entire plaintext to signed SHA-256.
    parts, size = [], 0
    try:
        for _ in range(64):
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_EXPANDED_INDEX)
            part = decoder.decompress(data, max_length=MAX_EXPANDED_INDEX + 1 - size)
            size += len(part)
            if not decoder.eof or size > MAX_EXPANDED_INDEX:
                raise InstallError('Ubuntu source index is truncated or exceeds its expansion bound')
            parts.append(part)
            data = decoder.unused_data
            padding = len(data) - len(data.lstrip(b'\0'))
            if padding % 4:
                raise InstallError('Ubuntu source index has invalid XZ stream padding')
            data = data[padding:]
            if not data:
                return b''.join(parts)
    except lzma.LZMAError:
        raise InstallError('Ubuntu source index encoding is invalid or exceeds its memory bound') from None
    raise InstallError('Ubuntu source index has excessive XZ streams')


def _index(value, closure, payload, directory, files, required):
    signed_bytes = _bytes(value['inrelease'], 1024**2)
    digest = hashlib.sha256(signed_bytes).hexdigest()
    prefix = 'evidence/' + digest
    signed_name = prefix + '/InRelease'
    if signed_name not in files:
        _write(directory, signed_name, signed_bytes, files)
    if not value['historical']:
        binary_name = 'repositories/' + value['repository'] + '/dists/' + value['suite'] + '/InRelease'
        if files[signed_name] != closure.manifest['files'][binary_name]:
            raise InstallError('Current source index must use the binary closure InRelease')
    plain = dependencies._run(['/usr/bin/gpgv', '--keyring', str(closure.keyring), '--output', '-', str(payload / signed_name)])
    records = list(dependencies._paragraphs(plain.splitlines()))
    if len(records) != 1:
        raise InstallError('Invalid signed Ubuntu source Release')
    release = records[0]
    if (release.get('Origin') != 'Ubuntu' or release.get('Label') != 'Ubuntu'
            or release.get('Suite') != value['suite'] or release.get('Codename') != 'noble'
            or 'amd64' not in release.get('Architectures', '').split()
            or value['component'] not in release.get('Components', '').split()):
        raise InstallError('Signed Ubuntu source Release identity is unsupported')
    try:
        now = datetime.now(timezone.utc)
        date = parsedate_to_datetime(release['Date'])
        expiry = parsedate_to_datetime(release['Valid-Until']) if 'Valid-Until' in release else None
        if date > now + timedelta(days=1) or (expiry is not None and
                (expiry < date or (not value['historical'] and expiry < now))):
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise InstallError('Invalid Ubuntu source Release dates') from None
    hashes = _checksums(release.get('SHA256', ''), allow_empty=True, maximum=MAX_TOTAL)
    relative = value['component'] + '/source/Sources'
    index_name = prefix + '/' + relative + '.xz'
    if relative not in hashes or relative + '.xz' not in hashes:
        raise InstallError('Signed Ubuntu source index hashes are missing')
    if index_name in files:
        raise InstallError('Repeated source evidence index')
    _copy(value['sources'], directory, index_name, files, maximum=MAX_INDEX, expected=hashes[relative + '.xz'])
    # Decompress into bounded memory; metadata alone cannot trigger disk extraction.
    expanded = _expand_index(_bytes(payload / index_name, MAX_INDEX))
    if len(expanded) > MAX_EXPANDED_INDEX or _record(expanded) != hashes[relative]:
        raise InstallError('Expanded Ubuntu source index differs from its signed hash')
    matches = {}
    for row in dependencies._paragraphs(io.StringIO(expanded.decode('utf-8'))):
        identity = row.get('Package'), row.get('Version')
        if identity not in required:
            continue
        pool = _relative(row.get('Directory', ''))
        if not pool.startswith('pool/' + value['component'] + '/'):
            raise InstallError('Ubuntu source directory is outside its signed component')
        entries = _checksums(row.get('Checksums-Sha256', ''), filenames=True)
        if sum(name.endswith('.dsc') for name in entries) != 1:
            raise InstallError('Ubuntu source package needs exactly one indexed descriptor')
        result = {pool + '/' + name: details for name, details in sorted(entries.items())}
        if identity in matches:
            raise InstallError('Duplicate exact Ubuntu source record')
        matches[identity] = result
    evidence = {key: value[key] for key in ('repository', 'suite', 'component', 'historical')}
    evidence.update(inrelease=signed_name, sources=index_name, signed_date=release['Date'],
                    valid_until=release.get('Valid-Until'), expanded=hashes[relative])
    return evidence, matches


def _cleartext(data):
    text = data.decode('utf-8')
    if not text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n'):
        return text
    head, separator, body = text.partition('\n\n')
    content, marker, signature = body.partition('-----BEGIN PGP SIGNATURE-----\n')
    if (not separator or not marker or not signature.rstrip().endswith('-----END PGP SIGNATURE-----')
            or any(not line.startswith('Hash: ') for line in head.splitlines()[1:])):
        raise InstallError('Malformed authenticated source descriptor signature envelope')
    return '\n'.join(line[2:] if line.startswith('- ') else line for line in content.splitlines()) + '\n'


def _dsc(path, identity, source_files):
    records = list(dependencies._paragraphs(io.StringIO(_cleartext(regular_bytes(path, 4 * 1024**2)))))
    if (len(records) != 1 or (records[0].get('Source'), records[0].get('Version')) != identity):
        raise InstallError('Source descriptor identity differs from signed Sources')
    expected = {PurePosixPath(name).name: details for name, details in source_files.items() if not name.endswith('.dsc')}
    if _checksums(records[0].get('Checksums-Sha256', ''), filenames=True) != expected:
        raise InstallError('Source descriptor file inventory differs from signed Sources')


class _DebTarInfo(release_kit._BoundedTarInfo):
    def _proc_member(self, archive):
        if self.type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            return tarfile.TarInfo._proc_member(self, archive)
        return super()._proc_member(archive)


class _Pipe:
    def __init__(self, stream):
        self.stream, self.size, self.deadline = stream, 0, time.monotonic() + 120

    def read(self, size):
        remaining = self.deadline - time.monotonic()
        with selectors.DefaultSelector() as selector:
            selector.register(self.stream, selectors.EVENT_READ)
            if remaining <= 0 or not selector.select(remaining):
                raise InstallError('Binary notice inspection timed out')
        data = os.read(self.stream.fileno(), min(size, 1024**2))
        self.size += len(data)
        if self.size > 4 * 1024**3:
            raise InstallError('Binary notice archive exceeds supported bounds')
        return data


def _notices(closure, directory, files, binaries):
    contents, links, total = {}, {}, 0
    for package in closure.manifest['packages']:
        path = closure.directory / 'repositories' / package['repository'] / package['filename']
        process = subprocess.Popen(['/usr/bin/dpkg-deb', '--fsys-tarfile', str(path)], env=dependencies.ENV,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            count = 0
            pipe = _Pipe(process.stdout)
            with tarfile.open(fileobj=pipe, mode='r|', tarinfo=_DebTarInfo) as archive:
                for member in archive:
                    count += 1
                    if count > 100000 or member.size < 0:
                        raise InstallError('Binary notice archive has unsupported entries')
                    name = member.name.removeprefix('./').rstrip('/')
                    if name in ('', '.'):
                        continue
                    normalized = PurePosixPath(name)
                    if (str(normalized) != name or normalized.is_absolute() or '..' in normalized.parts
                            or len(name.encode()) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in name)):
                        raise InstallError('Unsafe binary notice archive path')
                    if not name.startswith(('usr/share/doc/', 'usr/share/common-licenses/')):
                        continue
                    if member.issym() or member.islnk():
                        target = (member.linkname.removeprefix('./') if member.islnk() else
                                  posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname)))
                        _relative(target)
                        if not target.startswith(('usr/share/doc/', 'usr/share/common-licenses/')):
                            raise InstallError('Notice alias escapes documentation or license files')
                        if name in links and links[name] != target:
                            raise InstallError('Conflicting notice alias')
                        links[name] = target
                    elif member.isfile() and (name.endswith('/copyright') or name.startswith('usr/share/common-licenses/')):
                        if member.size > 4 * 1024**2:
                            raise InstallError('Copyright notice exceeds supported bounds')
                        data = archive.extractfile(member).read()
                        if name in contents and contents[name] != data:
                            raise InstallError('Conflicting copyright notice bytes')
                        if name not in contents:
                            total += len(data)
                            if total > 64 * 1024**2:
                                raise InstallError('Copyright inventory exceeds supported bounds')
                            contents[name] = data
            # dpkg-deb can still be writing tar padding after tarfile reaches EOF.
            while pipe.read(1024**2):
                pass
            if process.wait(timeout=30):
                raise InstallError('Binary notice inspection failed')
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
    if set(contents) & set(links):
        raise InstallError('Notice path has both file and alias definitions')
    for name, data in sorted(contents.items()):
        _write(directory, 'notices/' + name, data, files)
    for binary in binaries:
        original = name = 'usr/share/doc/' + binary['name'] + '/copyright'
        for _ in range(32):
            prefix = next((value for value in (name, *map(str, PurePosixPath(name).parents)) if value in links), None)
            if prefix is None:
                break
            name = links[prefix] + name[len(prefix):]
        else:
            raise InstallError('Copyright alias loop')
        if name not in contents:
            raise InstallError('Binary copyright is absent from authenticated closure: ' + binary['name'])
        binary['copyright'] = {'original': original, 'path': 'notices/' + name}
    return dict(sorted(links.items()))


def inspect_source_archive(path, *, expected_binary_manifest_sha256=None, destination=None):
    """Check the closed candidate inventory; outer release trust is separate."""
    fd, before = release_kit._open(Path(path), MAX_TOTAL)
    try:
        actual, manifest, total, members = {}, None, 0, {}
        with os.fdopen(os.dup(fd), 'rb') as stream, tempfile.TemporaryFile() as plain:
            with gzip.GzipFile(fileobj=stream) as expanded:
                offline_inputs._copy(expanded, plain, MAX_TOTAL + 64 * 1024**2)
            total_size = plain.tell()
            plain.seek(0)
            with tarfile.open(fileobj=plain, mode='r:', tarinfo=release_kit._BoundedTarInfo) as archive, ExitStack() as extraction:
                for member in archive:
                    name = _relative(member.name)
                    if (not member.isfile() or name in actual or len(actual) >= MAX_MEMBERS
                            or not 0 < member.size <= MAX_FILE or member.mode != 0o644
                            or member.uid or member.gid or member.mtime
                            or any(key != 'path' for key in member.pax_headers)):
                        raise InstallError('Unsupported source companion archive member')
                    total += member.size
                    if total > MAX_TOTAL:
                        raise InstallError('Source companion exceeds expansion bound')
                    source = archive.extractfile(member)
                    if name == MANIFEST:
                        if member.size > 16 * 1024**2:
                            raise InstallError('Source companion manifest is too large')
                        data = source.read()
                        manifest = release_kit._json(data)
                        actual[name] = _record(data)
                    else:
                        digest, size = offline_inputs._copy(source, None, MAX_FILE)
                        actual[name] = {'sha256': digest, 'size': size}
                    members[name] = member
                if total_size % 512 or total_size - archive.offset < 1024:
                    raise InstallError('Source companion is not completely terminated')
                plain.seek(archive.offset)
                while tail := plain.read(release_kit.CHUNK):
                    if tail.strip(b'\0'):
                        raise InstallError('Source companion contains trailing payload')
                release_kit._keys(manifest, {'schema', 'binary_manifest_sha256', 'binaries', 'sources', 'evidence', 'notice_aliases', 'files'})
                if manifest['schema'] != SCHEMA:
                    raise InstallError('Unsupported source companion manifest')
                release_kit._sha(manifest['binary_manifest_sha256'])
                if expected_binary_manifest_sha256 is not None and manifest['binary_manifest_sha256'] != expected_binary_manifest_sha256:
                    raise InstallError('Source companion belongs to another binary closure')
                if not isinstance(manifest['files'], dict) or {name: row for name, row in actual.items() if name != MANIFEST} != manifest['files']:
                    raise InstallError('Source companion has missing, altered or unlisted files')
                if destination is not None:
                    directory = extraction.enter_context(offline_inputs._new_directory(Path(destination)))
                    for name, member in members.items():
                        with offline_inputs._output_file(directory, name) as output:
                            digest, size = offline_inputs._copy(archive.extractfile(member), output, member.size)
                        if actual[name] != {'sha256': digest, 'size': size}:
                            raise InstallError('Source companion changed during private extraction')
                if release_kit._identity(before) != release_kit._identity(os.fstat(fd)):
                    raise InstallError('Source companion changed during inspection')
        if release_kit._identity(before) != release_kit._identity(os.fstat(fd)):
            raise InstallError('Source companion changed during inspection')
        return manifest
    except (OSError, ValueError, tarfile.TarError, EOFError, zlib.error):
        raise InstallError('Source companion archive is invalid') from None
    finally:
        os.close(fd)


def _assemble(closure, values, source_pool, payload, directory, guard):
    binaries = _binary_sources(closure)
    required = {(row['name'], row['version']) for binary in binaries
                for row in [binary['source'], *binary['built_using'], *binary['static_built_using']]}
    files, evidence, sources = {}, [], {}
    for value in sorted(values, key=lambda row: (row['historical'], row['repository'], row['suite'], row['component'], row['inrelease'])):
        guard()
        item, matches = _index(value, closure, payload, directory, files, required)
        evidence.append(item)
        for identity, source_files in matches.items():
            if identity in sources and sources[identity]['files'] != source_files:
                raise InstallError('Conflicting signed records for an exact source version')
            record = sources.setdefault(identity, {'files': source_files, 'evidence': []})
            record['evidence'].append(item['sources'])
    if set(sources) != required:
        missing = ', '.join(name + '=' + version for name, version in sorted(required - set(sources)))
        raise InstallError('Missing exact authenticated Ubuntu source versions: ' + missing)
    source_records = []
    for identity, record in sorted(sources.items()):
        for name, expected in sorted(record['files'].items()):
            target = 'sources/' + name
            if target in files:
                if files[target] != expected:
                    raise InstallError('Conflicting shared Ubuntu source file')
            else:
                if sum(row['size'] for row in files.values()) + expected['size'] > MAX_TOTAL:
                    raise InstallError('Source companion exceeds supported total size')
                _copy(source_pool / name, directory, target, files, expected=expected)
        descriptor = next(name for name in record['files'] if name.endswith('.dsc'))
        _dsc(payload / 'sources' / descriptor, identity, record['files'])
        source_records.append({'name': identity[0], 'version': identity[1],
            'files': ['sources/' + name for name in sorted(record['files'])],
            'evidence': sorted(record['evidence'])})
    aliases = _notices(closure, directory, files, binaries)
    _write(directory, 'README.txt', README, files)
    guard()
    return {'schema': SCHEMA, 'binary_manifest_sha256': closure.digest,
        'binaries': binaries, 'sources': source_records,
        'evidence': sorted(evidence, key=lambda row: row['sources']), 'notice_aliases': aliases, 'files': files}


def validate_source_archive(archive, binary_closure, expected_manifest_sha256, *, keyring=dependencies.KEYRING):
    """Independently prove actual source/notices coverage against the binary closure.

    A syntactically consistent self-declared manifest is insufficient. Recompute
    its complete contents from Ubuntu-authenticated metadata and original debs.
    """
    work = Path('/tmp') / ('iris-source-verify-' + secrets.token_hex(16))
    with offline_inputs._new_directory(work, remove=True) as work_fd:
        extracted = work / 'extracted'
        manifest = inspect_source_archive(archive, expected_binary_manifest_sha256=expected_manifest_sha256, destination=extracted)
        if not isinstance(manifest['evidence'], list) or not 6 <= len(manifest['evidence']) <= 64:
            raise InstallError('Source companion evidence coverage is invalid')
        values = []
        for row in manifest['evidence']:
            release_kit._keys(row, {'repository', 'suite', 'component', 'historical', 'inrelease', 'sources', 'signed_date', 'valid_until', 'expanded'})
            value = {key: row[key] for key in ('repository', 'suite', 'component', 'historical')}
            for key in ('inrelease', 'sources'):
                name = _relative(row[key])
                if name not in manifest['files'] or not name.startswith('evidence/'):
                    raise InstallError('Source companion evidence references an unlisted file')
                value[key] = str(extracted / name)
            values.append(value)
        _input_descriptors(values)
        with dependencies.validate_closure(Path(binary_closure), expected_manifest_sha256, keyring=keyring) as closure:
            payload = work / 'verified'
            with offline_inputs._new_directory(payload) as directory:
                expected = _assemble(closure, values, extracted / 'sources', payload, directory,
                                     lambda: offline_inputs._same_directory(work, work_fd))
                if _canonical(expected) != _canonical(manifest):
                    raise InstallError('Source companion coverage differs from independently authenticated inputs')
        offline_inputs._same_directory(work, work_fd)
        return manifest


def build_sources(binary_closure, expected_manifest_sha256, index_inputs, source_pool, output, *, keyring=dependencies.KEYRING):
    """Verify local inputs and exclusively publish a deterministic source archive."""
    values = _input_descriptors(index_inputs)
    source_pool, output = release_kit._path(Path(source_pool)), release_kit._path(Path(output))
    parent = release_kit._protected_directory(output.parent)
    work = Path('/tmp') / ('iris-offline-sources-' + secrets.token_hex(16))
    try:
        if output.exists() or output.is_symlink():
            raise InstallError('Refusing to replace an existing source companion')
        with offline_inputs._new_directory(work, remove=True) as work_fd:
            with dependencies.validate_closure(Path(binary_closure), expected_manifest_sha256, keyring=keyring) as closure:
                payload = work / 'payload'
                with offline_inputs._new_directory(payload) as directory:
                    manifest = _assemble(closure, values, source_pool, payload, directory,
                                         lambda: offline_inputs._same_directory(work, work_fd))
                    files = manifest['files']
                    data = _canonical(manifest)
                    with offline_inputs._output_file(directory, MANIFEST) as stream:
                        stream.write(data)
                    offline_inputs._same_directory(work, work_fd)
                    # Stage on the destination filesystem; publication is exclusive.
                    stage = output.parent / ('.iris-source-publish-' + secrets.token_hex(16))
                    with offline_inputs._new_directory(stage, remove=True) as stage_fd:
                        with offline_inputs._output_file(stage_fd, 'candidate.tar.gz') as raw:
                            with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
                                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                                    for name in sorted([MANIFEST, *files]):
                                        info = tarfile.TarInfo(name)
                                        info.size = len(data) if name == MANIFEST else files[name]['size']
                                        info.mode = 0o644
                                        with (payload / name).open('rb') as source:
                                            archive.addfile(info, source)
                            raw.flush()
                            os.fsync(raw.fileno())
                        candidate = stage / 'candidate.tar.gz'
                        inspect_source_archive(candidate, expected_binary_manifest_sha256=closure.digest)
                        offline_inputs._same_directory(work, work_fd)
                        offline_inputs._same_directory(payload, directory)
                        offline_inputs._same_directory(output.parent, parent)
                        offline_inputs._same_directory(stage, stage_fd)
                        digest = dependencies._digest(candidate)
                        os.chmod('candidate.tar.gz', 0o644, dir_fd=stage_fd, follow_symlinks=False)
                        os.link('candidate.tar.gz', output.name, src_dir_fd=stage_fd, dst_dir_fd=parent, follow_symlinks=False)
                        os.fsync(parent)
                    return {'archive': str(output), 'sha256': digest, 'manifest_sha256': hashlib.sha256(data).hexdigest(),
                            'binary_manifest_sha256': closure.digest, 'binaries': len(manifest['binaries']), 'sources': len(manifest['sources']),
                            'authenticated': False}
    finally:
        os.close(parent)
