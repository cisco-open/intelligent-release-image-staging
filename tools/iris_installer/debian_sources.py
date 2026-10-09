# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local Debian image source inputs, independent of notice/publication approval."""

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import tarfile
import tempfile
import zlib

from . import image_components as images, offline_dependencies as deb
from . import offline_inputs as custody, offline_sources as sources, release_kit as kit
from .state import InstallError


SCHEMA = 'iris-debian-image-sources-v1'
INPUT_SCHEMA = 'iris-debian-source-inputs-v1'
MANIFEST = 'source-manifest.json'
LOCATIONS = {('debian', 'trixie', 'main'), ('debian', 'trixie-updates', 'main'),
             ('security', 'trixie-security', 'main')}
FIELDS = {'repository', 'suite', 'component', 'inrelease', 'sources'}
README = b'''Debian image source-only companion

source-manifest.json binds the externally selected image inventory SHA-256.
The binaries list retains every observed Debian package database record in
every distributed image layer, including versions hidden by later layers.
Each direct source, Built-Using and Static-Built-Using identity maps to exact
Debian source pool files and independently signed Sources index evidence.
The original .dsc and all indexed source files are preserved without execution.
On a separately prepared build host, Debian source tooling can unpack the .dsc;
review upstream and debian/ instructions before building. No recipe was run and
no reproducible rebuild is claimed.

This is source-only evidence. Binary notices are not collected here. Alpine,
copied runtimes, static helpers, web assets and other non-Debian components need
separate evidence. Image source coverage remains incomplete. The external
inventory pin and independent Debian archive keyring are required to validate
this companion; its own manifest is not binary or publisher authority.
No legal approval, redistribution clearance or release authentication is given.
'''


def fail(message):
    raise InstallError('Debian image sources: ' + message)


def _identity(name, version):
    if (not isinstance(name, str) or not re.fullmatch('[a-z0-9][a-z0-9+.-]{0,159}', name)
            or not isinstance(version, str) or not images.VERSION.fullmatch(version)):
        fail('invalid exact source identity')
    return name, version


def _inventory(path, expected):
    kit._sha(expected)
    raw = sources._bytes(path, images.MAX_RECEIPT)
    if hashlib.sha256(raw).hexdigest() != expected:
        fail('inventory differs from the externally expected SHA-256')
    value = kit._json(raw)
    kit._keys(value, {'format', 'scope', 'authenticated', 'source_coverage_complete', 'commit',
                     'commit_scope', 'attribution_policy', 'images'})
    if (value['format'] != 'iris-image-component-inventory-v1' or value['scope'] != 'inventory-only'
            or value['authenticated'] is not False or value['source_coverage_complete'] is not False
            or value['commit_scope'] != 'core-revision-labels-only'
            or not isinstance(value['commit'], str) or not re.fullmatch('[a-f0-9]{40}', value['commit'])):
        fail('unsupported externally pinned image inventory')
    kit._keys(value['images'], {'server-image', 'console-image', 'device-runtime'})
    binaries, bindings = [], []
    for role, image in sorted(value['images'].items()):
        if not isinstance(image, dict):
            fail('invalid image identity')
        kit._sha(image.get('archive_sha256'))
        platforms = image.get('platforms') if role == 'device-runtime' else [image]
        if not isinstance(platforms, list) or not 1 <= len(platforms) <= 8:
            fail('invalid image platforms')
        seen_platforms = set()
        for platform in platforms:
            if not isinstance(platform, dict):
                fail('invalid image platform')
            name = platform.get('platform')
            if name not in ('linux/amd64', 'linux/arm64') or name in seen_platforms:
                fail('unsupported or repeated platform')
            seen_platforms.add(name)
            config = platform.get('config_digest')
            if not isinstance(config, str) or not config.startswith('sha256:'):
                fail('missing image configuration digest')
            kit._sha(config[7:])
            layers = platform.get('layers')
            if not isinstance(layers, list) or not 1 <= len(layers) <= 1024:
                fail('invalid retained layers')
            layer_bindings = []
            for index, layer in enumerate(layers):
                if not isinstance(layer, dict) or not isinstance(layer.get('inventory'), dict):
                    fail('invalid retained layer inventory')
                if type(layer.get('index')) is not int or layer['index'] != index:
                    fail('duplicate or unordered layer index')
                kit._sha(layer.get('blob_sha256'))
                diff = layer.get('diff_id')
                if not isinstance(diff, str) or not diff.startswith('sha256:'):
                    fail('invalid layer diffID')
                kit._sha(diff[7:])
                layer_bindings.append({'index': index, 'blob_sha256': layer['blob_sha256'], 'diff_id': diff})
                databases = layer.get('inventory', {}).get('package_databases')
                if not isinstance(databases, list) or len(databases) > 2:
                    fail('invalid layer package database inventory')
                seen_databases = set()
                for database in databases:
                    kit._keys(database, {'ecosystem', 'path', 'sha256', 'size', 'packages'})
                    ecosystem, path = database['ecosystem'], database['path']
                    if (ecosystem not in ('debian', 'alpine') or path in seen_databases
                            or path != images.DATABASES[0 if ecosystem == 'debian' else 1]):
                        fail('invalid or duplicate package database')
                    seen_databases.add(path)
                    kit._sha(database['sha256'])
                    if type(database['size']) is not int or not 0 < database['size'] <= images.MAX_FILE_METADATA:
                        fail('invalid package database size')
                    packages = database['packages']
                    if not isinstance(packages, list) or len(packages) > images.MAX_PACKAGES:
                        fail('invalid package record list')
                    if ecosystem != 'debian':
                        continue
                    seen_packages = set()
                    for package in packages:
                        kit._keys(package, {'package', 'version', 'architecture', 'status', 'source',
                                            'source_version', 'built_using', 'static_built_using'})
                        _identity(package['package'], package['version'])
                        direct = _identity(package['source'], package['source_version'])
                        arch, status = package['architecture'], package['status']
                        if (arch not in ('amd64', 'arm64', 'all') or arch not in (name[6:], 'all')
                                or not isinstance(status, str) or not re.fullmatch('[a-z-]+ [a-z-]+ [a-z-]+', status)
                                or (package['package'], arch) in seen_packages):
                            fail('invalid or repeated binary record')
                        seen_packages.add((package['package'], arch))
                        row = {'image': role, 'platform': name, 'layer': index, 'diff_id': diff,
                               'database_sha256': database['sha256'], 'package': package['package'],
                               'version': package['version'], 'architecture': arch, 'status': status,
                               'source': {'name': direct[0], 'version': direct[1]}}
                        for field in ('built_using', 'static_built_using'):
                            items = package[field]
                            if not isinstance(items, list) or len(items) > images.MAX_PACKAGES:
                                fail('invalid incorporated source list')
                            identities = set()
                            for item in items:
                                kit._keys(item, {'source', 'version'})
                                identity = _identity(item['source'], item['version'])
                                if identity in identities:
                                    fail('duplicate incorporated source identity')
                                identities.add(identity)
                            row[field] = [{'name': a, 'version': b} for a, b in sorted(identities)]
                        binaries.append(row)
                        if len(binaries) > sources.MAX_MEMBERS:
                            fail('too many retained binary mappings')
            bindings.append({'image': role, 'platform': name, 'archive_sha256': image['archive_sha256'],
                             'config_digest': config, 'layers': layer_bindings})
    if not binaries:
        fail('inventory contains no retained Debian packages')
    return raw, bindings, sorted(binaries, key=lambda row: (row['image'], row['platform'], row['layer'], row['package'], row['architecture']))


def _descriptors(values):
    if not isinstance(values, list) or len(values) != 3:
        fail('all three current Debian source indexes are required')
    seen = set()
    for value in values:
        kit._keys(value, FIELDS)
        location = tuple(value[key] for key in ('repository', 'suite', 'component'))
        if any(not isinstance(part, str) for part in location) or location not in LOCATIONS or location in seen:
            fail('unsupported or repeated Debian source location')
        seen.add(location)
        for key in ('inrelease', 'sources'):
            if not isinstance(value[key], str):
                fail('source index locators must be absolute paths')
            kit._path(Path(value[key]))
    return values


def load_index_inputs(path):
    value = kit._json(sources._bytes(path, 1024**2))
    kit._keys(value, {'schema', 'indexes'})
    if value['schema'] != INPUT_SCHEMA:
        fail('unsupported source input descriptor')
    return _descriptors(value['indexes'])


def _index(value, keyring, payload, directory, files, required, *, archived_integrity=False):
    signed = sources._bytes(value['inrelease'], 1024**2)
    prefix = 'evidence/' + hashlib.sha256(signed).hexdigest()
    signed_name = prefix + '/InRelease'
    sources._write(directory, signed_name, signed, files)
    records = list(deb._paragraphs(deb._run(['/usr/bin/gpgv', '--keyring', str(keyring),
                                           '--output', '-', str(payload / signed_name)]).splitlines()))
    if len(records) != 1:
        fail('invalid signed Debian Release')
    release = records[0]
    suite, security = value['suite'], value['repository'] == 'security'
    expected_suite = {'trixie': 'stable', 'trixie-updates': 'stable-updates', 'trixie-security': 'stable-security'}[suite]
    if (release.get('Origin') != 'Debian' or release.get('Label') != ('Debian-Security' if security else 'Debian')
            or release.get('Codename') != suite or release.get('Suite') != expected_suite
            or 'amd64' not in release.get('Architectures', '').split()
            or ('updates/main' if security else 'main') not in release.get('Components', '').split()):
        fail('signed Debian Release identity is unsupported')
    try:
        now = datetime.now(timezone.utc)
        date = parsedate_to_datetime(release['Date'])
        expiry = parsedate_to_datetime(release['Valid-Until']) if 'Valid-Until' in release else None
        if (date > now + timedelta(days=1)
                or (suite != 'trixie' and expiry is None)
                or (expiry is not None and (expiry < date or (not archived_integrity and expiry < now)))):
            raise ValueError()
    except (KeyError, TypeError, ValueError, OverflowError):
        fail('signed Debian Release has invalid or expired dates')
    hashes = sources._checksums(release.get('SHA256', ''), allow_empty=True, maximum=sources.MAX_TOTAL)
    relative = 'main/source/Sources'
    if relative not in hashes or relative + '.xz' not in hashes:
        fail('signed compressed and expanded source index hashes are required')
    index_name = prefix + '/' + relative + '.xz'
    sources._copy(value['sources'], directory, index_name, files,
                  maximum=sources.MAX_INDEX, expected=hashes[relative + '.xz'])
    expanded = sources._expand_index(sources._bytes(payload / index_name, sources.MAX_INDEX))
    if sources._record(expanded) != hashes[relative]:
        fail('expanded Sources differs from signed metadata')
    matches = {}
    for row in deb._paragraphs(io.StringIO(expanded.decode('utf-8'))):
        identity = row.get('Package'), row.get('Version')
        if identity not in required:
            continue
        pool = sources._relative(row.get('Directory', ''))
        if not pool.startswith('pool/updates/main/' if security else 'pool/main/'):
            fail('source directory is outside the signed component')
        entries = sources._checksums(row.get('Checksums-Sha256', ''), filenames=True)
        if sum(name.endswith('.dsc') for name in entries) != 1 or identity in matches:
            fail('ambiguous exact source record or descriptor')
        matches[identity] = {pool + '/' + name: row for name, row in sorted(entries.items())}
    evidence = {key: value[key] for key in ('repository', 'suite', 'component')}
    evidence.update(inrelease=signed_name, sources=index_name, signed_date=release['Date'],
                    valid_until=release.get('Valid-Until'), expanded=hashes[relative])
    return evidence, matches


def _assemble(raw, bindings, binaries, expected, values, pool, keyring, payload, directory, guard,
              *, archived_integrity=False):
    required = {(item['name'], item['version']) for binary in binaries
                for item in [binary['source'], *binary['built_using'], *binary['static_built_using']]}
    files, evidence, found = {}, [], {}
    for value in sorted(values, key=lambda row: (row['repository'], row['suite'], row['component'])):
        guard()
        item, matches = _index(value, keyring, payload, directory, files, required,
                               archived_integrity=archived_integrity)
        evidence.append(item)
        for identity, entries in matches.items():
            content = {PurePosixPath(name).name: details for name, details in entries.items()}
            if identity in found and found[identity]['content'] != content:
                fail('conflicting signed exact source version')
            found.setdefault(identity, {'content': content, 'locations': []})['locations'].append(
                {'index': item['sources'], 'files': entries})
    if set(found) != required:
        fail('missing exact signed source versions: ' + ', '.join(a + '=' + b for a, b in sorted(required - set(found))))
    records = []
    for identity, row in sorted(found.items()):
        locations = []
        for location in row['locations']:
            for name, details in sorted(location['files'].items()):
                target = 'sources/' + name
                if target in files:
                    if files[target] != details:
                        fail('conflicting shared source file')
                    continue
                if sum(item['size'] for item in files.values()) + details['size'] > sources.MAX_TOTAL:
                    fail('source companion exceeds total bound')
                sources._copy(pool / name, directory, target, files, expected=details)
            descriptor = next(name for name in location['files'] if name.endswith('.dsc'))
            sources._dsc(payload / 'sources' / descriptor, identity, location['files'])
            locations.append({'index': location['index'],
                              'files': ['sources/' + name for name in sorted(location['files'])]})
        records.append({'name': identity[0], 'version': identity[1],
                        'files': sorted({name for location in locations for name in location['files']}),
                        'locations': sorted(locations, key=lambda item: item['index'])})
    sources._write(directory, 'image-components.json', raw, files)
    sources._write(directory, 'README.txt', README, files)
    guard()
    return {'schema': SCHEMA, 'inventory_sha256': expected, 'scope': 'debian-source-only',
            'notices': 'not-collected', 'source_coverage_complete': False, 'images': bindings,
            'binaries': binaries, 'sources': records, 'evidence': sorted(evidence, key=lambda row: row['sources']), 'files': files}


def inspect_source_archive(path, *, expected_inventory_sha256=None, destination=None):
    """Bounded closed inventory inspection; not independent source validation."""
    if expected_inventory_sha256 is not None:
        kit._sha(expected_inventory_sha256)
    fd, before = kit._open(Path(path), sources.MAX_TOTAL)
    try:
        with os.fdopen(os.dup(fd), 'rb') as compressed, tempfile.TemporaryFile() as plain:
            with gzip.GzipFile(fileobj=compressed) as expanded:
                custody._copy(expanded, plain, sources.MAX_TOTAL + 64 * 1024**2)
            length = plain.tell()
            plain.seek(0)
            actual, members, manifest, total = {}, {}, None, 0
            with tarfile.open(fileobj=plain, mode='r:', tarinfo=kit._BoundedTarInfo) as archive, ExitStack() as extraction:
                for member in archive:
                    name = sources._relative(member.name)
                    if (not member.isfile() or name in members or len(members) >= sources.MAX_MEMBERS
                            or not 0 < member.size <= sources.MAX_FILE or member.mode != 0o644
                            or member.uid or member.gid or member.mtime
                            or any(key != 'path' for key in member.pax_headers)):
                        fail('unsupported companion archive member')
                    total += member.size
                    if total > sources.MAX_TOTAL:
                        fail('companion exceeds expansion bound')
                    stream = archive.extractfile(member)
                    if name == MANIFEST:
                        if member.size > images.MAX_RECEIPT:
                            fail('manifest exceeds bound')
                        data = stream.read()
                        manifest, actual[name] = kit._json(data), sources._record(data)
                    else:
                        digest, size = custody._copy(stream, None, sources.MAX_FILE)
                        actual[name] = {'sha256': digest, 'size': size}
                    members[name] = member
                if length % 512 or length - archive.offset < 1024:
                    fail('archive is not completely terminated')
                plain.seek(archive.offset)
                while tail := plain.read(kit.CHUNK):
                    if tail.strip(b'\0'):
                        fail('archive contains trailing payload')
                kit._keys(manifest, {'schema', 'inventory_sha256', 'scope', 'notices', 'source_coverage_complete',
                                     'images', 'binaries', 'sources', 'evidence', 'files'})
                if (manifest['schema'] != SCHEMA or manifest['scope'] != 'debian-source-only'
                        or manifest['notices'] != 'not-collected' or manifest['source_coverage_complete'] is not False):
                    fail('unsupported companion manifest or coverage claim')
                kit._sha(manifest['inventory_sha256'])
                if expected_inventory_sha256 is not None and manifest['inventory_sha256'] != expected_inventory_sha256:
                    fail('companion belongs to another image inventory')
                if {name: row for name, row in actual.items() if name != MANIFEST} != manifest['files']:
                    fail('companion has missing, altered or unlisted files')
                if destination is not None:
                    directory = extraction.enter_context(custody._new_directory(Path(destination)))
                    for name, member in members.items():
                        with custody._output_file(directory, name) as output:
                            digest, size = custody._copy(archive.extractfile(member), output, member.size)
                        if actual[name] != {'sha256': digest, 'size': size}:
                            fail('archive changed during extraction')
                if kit._identity(before) != kit._identity(os.fstat(fd)):
                    fail('archive changed during inspection')
            return manifest
    except (OSError, ValueError, tarfile.TarError, EOFError, zlib.error):
        fail('invalid source companion archive')
    finally:
        os.close(fd)


def validate_source_archive(archive, inventory, expected_inventory_sha256, *, keyring,
                            archived_integrity=False):
    """Rebuild source integrity from independent inventory and archive trust.

    Default validation requires current repository metadata. An explicit caller
    may select archived integrity to allow past Valid-Until only. Signatures,
    identities, date ordering, future-date bounds and every hash remain checked.
    This is not current publication readiness, a producer option, or a policy
    the companion can select for itself. Canonical v1 README bytes stay stable.
    """
    if type(archived_integrity) is not bool:
        fail('archived integrity must be an explicit boolean')
    raw, bindings, binaries = _inventory(inventory, expected_inventory_sha256)
    work = Path('/tmp') / ('iris-debian-source-verify-' + secrets.token_hex(16))
    with custody._new_directory(work, remove=True) as held:
        sources._copy(keyring, held, 'keyring.gpg', {}, maximum=16 * 1024**2)
        extracted = work / 'extracted'
        manifest = inspect_source_archive(archive, expected_inventory_sha256=expected_inventory_sha256, destination=extracted)
        if not isinstance(manifest['evidence'], list) or len(manifest['evidence']) != 3:
            fail('invalid source evidence inventory')
        values = []
        for row in manifest['evidence']:
            kit._keys(row, FIELDS | {'signed_date', 'valid_until', 'expanded'})
            value = {key: row[key] for key in ('repository', 'suite', 'component')}
            for key in ('inrelease', 'sources'):
                name = sources._relative(row[key])
                if name not in manifest['files'] or not name.startswith('evidence/'):
                    fail('unlisted source evidence')
                value[key] = str(extracted / name)
            values.append(value)
        _descriptors(values)
        payload = work / 'verified'
        with custody._new_directory(payload) as directory:
            expected = _assemble(raw, bindings, binaries, expected_inventory_sha256, values,
                                 extracted / 'sources', work / 'keyring.gpg', payload, directory,
                                 lambda: custody._same_directory(work, held),
                                 archived_integrity=archived_integrity)
            if sources._canonical(manifest) != sources._canonical(expected):
                fail('manifest differs from independently verified source inputs')
        custody._same_directory(work, held)
        return manifest


def build_sources(inventory, expected_inventory_sha256, index_inputs, source_pool, output, *, keyring):
    """Verify local inputs and publish one exclusive deterministic source archive."""
    raw, bindings, binaries = _inventory(inventory, expected_inventory_sha256)
    values = _descriptors(index_inputs)
    pool, output = kit._path(Path(source_pool)), kit._path(Path(output))
    parent = kit._protected_directory(output.parent)
    work = Path('/tmp') / ('iris-debian-sources-' + secrets.token_hex(16))
    try:
        if output.exists() or output.is_symlink():
            fail('refusing to replace an existing companion')
        with custody._new_directory(work, remove=True) as held:
            sources._copy(keyring, held, 'keyring.gpg', {}, maximum=16 * 1024**2)
            payload = work / 'payload'
            with custody._new_directory(payload) as directory:
                manifest = _assemble(raw, bindings, binaries, expected_inventory_sha256, values, pool,
                                     work / 'keyring.gpg', payload, directory,
                                     lambda: custody._same_directory(work, held))
                data = sources._canonical(manifest)
                if len(data) > images.MAX_RECEIPT:
                    fail('manifest exceeds bound')
                with custody._output_file(directory, MANIFEST) as stream:
                    stream.write(data)
                stage = output.parent / ('.iris-debian-source-publish-' + secrets.token_hex(16))
                with custody._new_directory(stage, remove=True) as stage_fd:
                    with custody._output_file(stage_fd, 'candidate.tar.gz') as stream:
                        with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
                            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                                for name in sorted([MANIFEST, *manifest['files']]):
                                    info = tarfile.TarInfo(name)
                                    info.size = len(data) if name == MANIFEST else manifest['files'][name]['size']
                                    info.mode = 0o644
                                    with (payload / name).open('rb') as source:
                                        archive.addfile(info, source)
                        stream.flush()
                        os.fsync(stream.fileno())
                    candidate = stage / 'candidate.tar.gz'
                    inspect_source_archive(candidate, expected_inventory_sha256=expected_inventory_sha256)
                    custody._same_directory(work, held)
                    custody._same_directory(payload, directory)
                    custody._same_directory(output.parent, parent)
                    custody._same_directory(stage, stage_fd)
                    digest = deb._digest(candidate)
                    os.chmod('candidate.tar.gz', 0o644, dir_fd=stage_fd, follow_symlinks=False)
                    os.link('candidate.tar.gz', output.name, src_dir_fd=stage_fd, dst_dir_fd=parent, follow_symlinks=False)
                    os.fsync(parent)
                return {'archive': str(output), 'sha256': digest, 'inventory_sha256': expected_inventory_sha256,
                        'manifest_sha256': hashlib.sha256(data).hexdigest(), 'sources': len(manifest['sources']),
                        'binary_layer_records': len(binaries), 'authenticated': False, 'source_coverage_complete': False}
    finally:
        os.close(parent)
