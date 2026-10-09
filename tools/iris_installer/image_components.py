# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Inventory exact image bytes without executing them or claiming source coverage."""

import argparse
from email.parser import BytesHeaderParser
import gzip
import hashlib
import importlib.util
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import tarfile

from . import device_finalize as f, release_kit as kit
from .offline_inputs import _new_directory, _same_directory
from .packaging_inputs import _publication
from .state import InstallError


MAX_MEMBERS = 100000
MAX_FILES = 250000
MAX_METADATA = 16 * 1024**2
MAX_FILE_METADATA = 4 * 1024**2
MAX_PACKAGES = 10000
MAX_RECEIPT = 64 * 1024**2
DATABASES = ('var/lib/dpkg/status', 'lib/apk/db/installed')
PACKAGE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,159}\Z')
VERSION = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9+.~:_-]{0,255}\Z')
ARCHITECTURE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z')
KNOWN_HELPERS = {'opt/iris/bin/aria2c': 'aria2', 'opt/iris/bin/iris-aead': 'iris-aead',
                 'opt/iris/bin/iris-aead-amd64': 'iris-aead',
                 'opt/iris/bin/iris-aead-arm64': 'iris-aead',
                 'opt/iris/bin/ssh-keygen-amd64': 'static-openssh',
                 'opt/iris/bin/ssh-keygen-arm64': 'static-openssh'}


def fail(message):
    raise InstallError('Image component inventory: ' + message)


def _name(value, *, directory=False):
    value = value[:-1] if directory and value.endswith('/') else value
    if (not isinstance(value, str) or not value or len(value.encode('utf-8')) > 4096
            or '\\' in value or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        fail('unsafe layer path')
    path = PurePosixPath(value)
    if value == '.' and directory:
        return value  # A normal tar root-directory header, never an output path.
    if path.is_absolute() or '..' in path.parts or str(path) != value or value == '.':
        fail('unsafe layer path')
    if any(part.startswith('.wh.') for part in path.parts[:-1]):
        fail('layer path traverses a whiteout')
    return value


def _link(name, target, *, symbolic):
    if (not target or len(target.encode('utf-8')) > 4096 or '\\' in target
            or any(ord(char) < 32 or ord(char) == 127 for char in target)):
        fail('unsafe layer link')
    parts = list(PurePosixPath(name).parent.parts) if symbolic and not target.startswith('/') else []
    for part in target.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            if not parts:
                fail('layer link escapes image root')
            parts.pop()
        else:
            parts.append(part)
    return '/'.join(parts)


def _text(raw):
    if len(raw) > MAX_FILE_METADATA or b'\0' in raw:
        fail('package metadata exceeds bounds or contains NUL')
    try:
        return raw.decode('utf-8')
    except UnicodeError:
        fail('package metadata is not UTF-8')


def _debian_fields(raw):
    records = []
    for paragraph in _text(raw).strip().split('\n\n'):
        if not paragraph:
            continue
        fields, key = {}, None
        for line in paragraph.splitlines():
            if line.startswith((' ', '\t')):
                if key is None:
                    fail('invalid folded Debian field')
                fields[key].append(line.strip())
                continue
            key, separator, value = line.partition(':')
            if (not separator or not re.fullmatch('[A-Za-z][A-Za-z0-9-]{0,79}', key)
                    or key in fields or len(fields) >= 128):
                fail('invalid or repeated Debian field')
            fields[key] = [value.strip()]
        records.append({name: ' '.join(parts) for name, parts in fields.items()})
        if len(records) > MAX_PACKAGES:
            fail('too many package records')
    return records


def _source_reference(value):
    match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9+_.-]{0,159})(?: \(([^() ]+)\))?', value)
    if match is None or match[2] is not None and not VERSION.fullmatch(match[2]):
        fail('invalid Debian source identity')
    return match[1], match[2]


def _built_using(value):
    if not value:
        return []
    result, seen = [], set()
    for item in value.split(','):
        match = re.fullmatch(r'\s*([A-Za-z0-9][A-Za-z0-9+_.-]{0,159})\s+\(=\s*([^()\s]+)\)\s*', item)
        if match is None or not VERSION.fullmatch(match[2]) or len(result) >= MAX_PACKAGES:
            fail('invalid Built-Using source identity')
        row = {'source': match[1], 'version': match[2]}
        identity = (match[1], match[2])
        if identity in seen:
            fail('duplicate Built-Using source identity')
        seen.add(identity)
        result.append(row)
    return result


def _debian(raw):
    result, seen = [], set()
    for fields in _debian_fields(raw):
        name, version, architecture = (fields.get(key, '') for key in ('Package', 'Version', 'Architecture'))
        if (not PACKAGE.fullmatch(name) or not VERSION.fullmatch(version)
                or not ARCHITECTURE.fullmatch(architecture) or (name, architecture) in seen):
            fail('invalid or repeated Debian package identity')
        seen.add((name, architecture))
        source, source_version = _source_reference(fields.get('Source', name))
        status = fields.get('Status', '')
        if not re.fullmatch('[a-z-]+ [a-z-]+ [a-z-]+', status):
            fail('invalid Debian package status')
        result.append({'package': name, 'version': version, 'architecture': architecture,
                       'status': status, 'source': source, 'source_version': source_version or version,
                       'built_using': _built_using(fields.get('Built-Using', '')),
                       'static_built_using': _built_using(fields.get('Static-Built-Using', ''))})
    return result


def _alpine(raw):
    result, seen = [], set()
    for paragraph in _text(raw).strip().split('\n\n'):
        if not paragraph:
            continue
        fields, file_count = {}, 0
        for line in paragraph.splitlines():
            if len(line) < 2 or line[1] != ':':
                fail('invalid APK record')
            key, value = line[0], line[2:]
            if key == 'R':
                file_count += 1
            if key in 'PVAocLD':
                if key in fields:
                    fail('repeated APK identity field')
                fields[key] = value
        name, version, architecture = (fields.get(key, '') for key in 'PVA')
        virtual = name == '.python-rundeps' and not fields.get('o') and not fields.get('c') and file_count == 0
        if (not (PACKAGE.fullmatch(name) or virtual) or not VERSION.fullmatch(version)
                or not ARCHITECTURE.fullmatch(architecture) or (name, architecture) in seen
                or len(result) >= MAX_PACKAGES):
            fail('invalid or repeated APK package identity')
        seen.add((name, architecture))
        origin, revision = fields.get('o'), fields.get('c')
        if not virtual and (not isinstance(origin, str) or not PACKAGE.fullmatch(origin)
                            or not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision)):
            fail('APK origin or exact aports revision is unavailable')
        license_text = fields.get('L', '')
        if len(license_text) > 4096 or any(ord(char) < 32 for char in license_text):
            fail('APK license metadata is invalid')
        result.append({'package': name, 'version': version, 'architecture': architecture,
                       'origin': origin, 'aports_commit': revision, 'license_expression': license_text,
                       'virtual': virtual, 'declared_file_count': file_count})
    return result


def _notice(name):
    return (PurePosixPath(name).name.lower().startswith(('copyright', 'license', 'licence', 'copying', 'notice'))
            or name.endswith('.LICENCE') or '/licenses/' in name or '/common-licenses/' in name)


def _component(name):
    if name in KNOWN_HELPERS:
        return KNOWN_HELPERS[name]
    if re.search(r'/site-packages/(?:pip/|pip-[^/]+\.dist-info/)', name):
        return 'pip-and-vendored-components'
    if '/site-packages/' in name:
        return 'python-distribution-unresolved'
    if (re.fullmatch(r'usr/local/(?:bin/python[0-9.]+|lib/libpython[^/]+)', name)
            or name.startswith(('usr/local/lib/python', 'usr/local/include/python'))):
        return 'cpython-runtime'
    if name.startswith('opt/iris/server/webroot/assets/') or name.endswith('/dist/swarmmap.html'):
        return 'bundled-web-runtime'
    return None


def _metadata(name):
    return (name in DATABASES or name.endswith('/patchlevel.h') and name.startswith('usr/local/include/python')
            or '/site-packages/' in name and name.endswith(('/METADATA', '/vendor.txt')))


def _public_file(name, record):
    result = {'path': name, **{key: value for key, value in record.items() if not key.startswith('_')}}
    if '_link_target' in record and 'sha256' not in record:
        result = {'path': name, 'type': 'unresolved-hardlink', 'target': record['_link_target']}
    result['source_attribution'] = 'unresolved'
    component = _component(name)
    if component:
        result['observed_component_path'] = component
    return result


def _summary(files):
    databases, executables, notices, copied, runtime = [], [], [], [], []
    for name, record in sorted(files.items()):
        if name in DATABASES:
            if record['type'] != 'file' or '_data' not in record:
                fail('package database is not a regular metadata file')
            parser = _debian if name == DATABASES[0] else _alpine
            databases.append({'path': name, 'sha256': record['sha256'], 'size': record['size'],
                              'ecosystem': 'debian' if name == DATABASES[0] else 'alpine',
                              'packages': parser(record['_data'])})
        if record['type'] == 'file' and record.get('mode', 0) & 0o111:
            executables.append(_public_file(name, record))
        if _notice(name) and record['type'] != 'directory':
            notices.append({**_public_file(name, record),
                            'availability': 'regular-file' if record['type'] == 'file' and 'sha256' in record else 'link-target-not-assessed'})
        if _component(name) and record['type'] == 'file':
            copied.append(_public_file(name, record))
        if '_data' in record and name not in DATABASES and not record.get('_extra_metadata', False):
            value = {'path': name, 'sha256': record['sha256'], 'source_attribution': 'unresolved'}
            if name.endswith('/patchlevel.h'):
                match = re.search(r'^#define\s+PY_VERSION\s+"([0-9.]+)"\s*$', _text(record['_data']), re.M)
                if match is None:
                    fail('CPython version header is unsupported')
                value.update(component='cpython', version=match[1])
            elif name.endswith('/METADATA'):
                headers = BytesHeaderParser().parsebytes(record['_data'])
                if len(headers.get_all('Name', [])) != 1 or len(headers.get_all('Version', [])) != 1:
                    fail('Python distribution identity is ambiguous')
                if not PACKAGE.fullmatch(headers['Name']) or not VERSION.fullmatch(headers['Version']):
                    fail('Python distribution identity is invalid')
                value.update(component='python-distribution', name=headers['Name'], version=headers['Version'])
            else:
                value.update(component='vendored-dependency-inventory', interpretation='not-assessed')
            runtime.append(value)
    return {'package_databases': databases, 'package_metadata_state': 'present' if databases else 'absent',
            'executables': executables, 'notice_files': notices, 'runtime_metadata': runtime,
            'copied_component_files': copied,
            'unknown_executables': [row['path'] for row in executables if 'observed_component_path' not in row]}


def _layer(path, filesystem, *, retain_metadata=None):
    """Inspect a layer; optional bounded inert metadata stays out of public rows."""
    entries, whiteouts, metadata_size = {}, [], 0
    with tarfile.open(path, 'r:', tarinfo=f._TarInfo) as archive:
        expanded = 0
        for member in archive:
            name = _name(member.name, directory=member.isdir())
            if name in entries or len(entries) >= MAX_MEMBERS:
                fail('layer contains duplicate or excessive members')
            if (not 0 <= member.size <= kit.MAX_ASSET or not math.isfinite(member.mtime)
                    or not 0 <= member.mode <= 0o7777 or min(member.uid, member.gid) < 0
                    or any(key.startswith('GNU.sparse') for key in member.pax_headers)
                    or not member.isfile() and member.size):
                fail('unsupported layer metadata')
            expanded += member.size
            if expanded > kit.MAX_ASSET:
                fail('layer expanded size exceeds limit')
            leaf = PurePosixPath(name).name
            if leaf.startswith('.wh.'):
                if not member.isfile() or member.size or leaf == '.wh.':
                    fail('invalid whiteout')
                whiteouts.append(name)
                entries[name] = None
                continue
            record = {'type': 'directory'}
            if member.issym() or member.islnk():
                record = {'type': 'symlink' if member.issym() else 'hardlink',
                          'target': _link(name, member.linkname, symbolic=member.issym())}
            elif member.isfile():
                record = {'type': 'file', 'mode': member.mode, 'size': member.size}
                retain = _metadata(name) or retain_metadata is not None and retain_metadata(name)
                originally_selected = bool(member.mode & 0o111) or _notice(name) or _metadata(name) or _component(name)
                selected = originally_selected or retain
                if selected:
                    stream = archive.extractfile(member)
                    if retain:
                        if member.size > MAX_FILE_METADATA:
                            fail('individual metadata file exceeds limit')
                        record['_data'] = stream.read(MAX_FILE_METADATA + 1)
                        if not _metadata(name):
                            record['_extra_metadata'] = True
                        metadata_size += len(record['_data'])
                        if metadata_size > MAX_METADATA or len(record['_data']) != member.size:
                            fail('layer metadata exceeds limits')
                        record['sha256'] = hashlib.sha256(record['_data']).hexdigest()
                        if not originally_selected:
                            record['_retained_sha256'] = record.pop('sha256')
                    else:
                        record['sha256'], size = f._copy(stream, None, kit.MAX_ASSET)
                        if size != member.size:
                            fail('layer member is truncated')
            entries[name] = record
        length = path.stat().st_size
        if length % 512 or length - archive.offset < 1024:
            fail('layer is not completely terminated')
        archive.fileobj.seek(archive.offset)
        while tail := archive.fileobj.read(kit.CHUNK):
            if tail.strip(b'\0'):
                fail('layer contains trailing payload')
    # Whiteouts affect lower layers only, irrespective of tar member order.
    for name in whiteouts:
        parent, leaf = PurePosixPath(name).parent, PurePosixPath(name).name
        target = str(parent) if leaf == '.wh..wh..opq' else str(parent / leaf[4:])
        prefix = '' if target == '.' else target + '/'
        for old in list(filesystem):
            if old.startswith(prefix) or leaf != '.wh..wh..opq' and old == target:
                del filesystem[old]
    added = {name: record for name, record in entries.items() if record is not None}
    for name, record in added.items():
        # Normal entries apply in tar order after lower-layer whiteouts. A
        # hardlink captures the then-current inode, not a later replacement.
        if record['type'] == 'hardlink':
            target = filesystem.get(record['target'])
            if record['target'] == name or target is None or target['type'] != 'file':
                fail('hard link must identify an earlier regular image file')
            record = dict(target, _link_target=record['target'])
            added[name] = record
        if record['type'] != 'directory':
            for old in list(filesystem):
                if old.startswith(name + '/'):
                    del filesystem[old]
        filesystem[name] = record
    if len(filesystem) > MAX_FILES:
        fail('merged image contains too many entries')
    if sum(len(record.get('_data', b'')) for record in filesystem.values()) > MAX_METADATA:
        fail('merged image metadata exceeds limits')
    for name, record in filesystem.items():
        for parent in PurePosixPath(name).parents:
            prior = filesystem.get(str(parent))
            if prior is not None and prior['type'] != 'directory':
                fail('layer path traverses a non-directory')
    return _summary(added), _summary(filesystem)


def _producer():
    base = Path(__file__).resolve().parents[1]
    path = base / 'source/tools/build-release-kit.py'
    if not path.exists():
        path = base / 'build-release-kit.py'
    spec = importlib.util.spec_from_file_location('iris_component_docker_inspector', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _inspect_layers(archive, rows, work, descriptor):
    filesystem, layers, total, evidence_size = {}, [], 0, 0
    for index, row in enumerate(rows):
        _same_directory(work, descriptor)
        path = Path('/proc/self/fd') / str(descriptor) / ('layer-' + str(index) + '.tar')
        stream = archive.extractfile(row['member'])
        prefix = stream.read(2)
        stream.seek(0)
        content = gzip.GzipFile(fileobj=stream) if prefix == b'\x1f\x8b' else stream
        try:
            with path.open('xb') as output:
                digest, size = f._copy(content, output, kit.MAX_ASSET)
            total += size
            if total > kit.MAX_ASSET or 'sha256:' + digest != row['diff_id']:
                fail('layer differs from its verified diffID or exceeds bounds')
            changes, merged = _layer(path, filesystem)
            _same_directory(work, descriptor)
            evidence_size += len(f._json(changes))
            if evidence_size > MAX_RECEIPT:
                fail('layer inventory evidence exceeds bounds')
            layers.append({**row, 'index': index, 'expanded_size': size, 'inventory': changes})
        finally:
            content.close()
            stream.close()
            if path.exists():
                path.unlink()
    return {'layers': layers, 'merged': merged}


def _terminated(path):
    with tarfile.open(path, 'r:', tarinfo=kit._BoundedTarInfo) as archive:
        for _ in archive:
            pass  # The prior outer-envelope guard bounded all members.
        length = path.stat().st_size
        if length % 512 or length - archive.offset < 1024:
            fail('image envelope is not completely terminated')
        archive.fileobj.seek(archive.offset)
        while tail := archive.fileobj.read(kit.CHUNK):
            if tail.strip(b'\0'):
                fail('image envelope contains trailing payload')


def _docker(path, commit, work, descriptor):
    config_digest = _producer().docker_config(path, commit)
    with tarfile.open(path, 'r:', tarinfo=kit._BoundedTarInfo) as archive:
        manifest = kit._json(archive.extractfile('manifest.json').read(kit.MAX_METADATA + 1))[0]
        config = kit._json(archive.extractfile(manifest['Config']).read(kit.MAX_METADATA + 1))
        labels = config.get('config', {}).get('Labels')
        if not isinstance(labels, dict) or labels.get('org.opencontainers.image.revision') != commit:
            fail('core image must declare the exact selected commit')
        rows = []
        for name, diff_id in zip(manifest['Layers'], config['rootfs']['diff_ids']):
            digest, size = f._copy(archive.extractfile(name), None, kit.MAX_ASSET)
            rows.append({'member': name, 'blob_sha256': digest, 'blob_size': size, 'diff_id': diff_id})
        result = _inspect_layers(archive, rows, work, descriptor)
    return {'platform': 'linux/amd64', 'config_digest': config_digest, 'revision_label': commit, **result}


def _neutral(path, checksum, work, descriptor):
    inspected = f.inspect_neutral(path, expected_archive_sha256=checksum)
    results = []
    with tarfile.open(path, 'r:', tarinfo=kit._BoundedTarInfo) as archive:
        for architecture, identity in sorted(inspected['platforms'].items()):
            name = 'blobs/sha256/' + identity['layer_digest'].split(':')[1]
            rows = [{'member': name, 'blob_sha256': identity['layer_digest'].split(':')[1],
                     'blob_size': archive.getmember(name).size, 'diff_id': identity['diff_id']}]
            results.append({'platform': 'linux/' + architecture, 'config_digest': identity['config_digest'],
                            'manifest_digest': identity['manifest_digest'], **_inspect_layers(archive, rows, work, descriptor)})
    return {'index_digest': inspected['index_digest'], 'source_commit_binding': 'not-assessed', 'platforms': results}


def inspect_components(*, server_archive, server_sha256, console_archive, console_sha256,
                       neutral_archive, neutral_sha256, commit, output_dir):
    if not isinstance(commit, str) or not re.fullmatch('[a-f0-9]{40}', commit):
        fail('an exact source commit is required')
    inputs = {'server-image': (server_archive, server_sha256), 'console-image': (console_archive, console_sha256),
              'device-runtime': (neutral_archive, neutral_sha256)}
    for _, checksum in inputs.values():
        kit._sha(checksum)
    receipt = {'format': 'iris-image-component-inventory-v1', 'scope': 'inventory-only',
               'authenticated': False, 'source_coverage_complete': False, 'commit': commit,
               'commit_scope': 'core-revision-labels-only',
               'attribution_policy': 'Observed paths and package metadata are evidence, not source or license approval.',
               'images': {}}
    work = Path('/tmp') / ('iris-image-inventory-' + secrets.token_hex(16))
    with _publication(output_dir) as (stage, output), _new_directory(work, remove=True) as descriptor:
        for role, (source, expected) in inputs.items():
            _same_directory(work, descriptor)
            snapshot = work / (role + '.tar')
            anchored = Path('/proc/self/fd') / str(descriptor) / snapshot.name
            if kit._snapshot(f._path(source), anchored, kit.MAX_ASSET) != expected:
                fail('image archive differs from the expected digest')
            _same_directory(work, descriptor)
            fd, info = kit._open(snapshot, kit.MAX_ASSET)
            try:
                kit._archive(fd, 'oci-archive' if role == 'device-runtime' else 'docker-archive')
            finally:
                os.close(fd)
            _terminated(snapshot)
            result = (_neutral(snapshot, expected, work, descriptor) if role == 'device-runtime'
                      else _docker(snapshot, commit, work, descriptor))
            receipt['images'][role] = {'archive_sha256': expected, 'archive_size': info.st_size, **result}
            _same_directory(work, descriptor)
        encoded = f._json(receipt)
        if len(encoded) > MAX_RECEIPT:
            fail('inventory receipt exceeds its size limit')
        (stage / 'image-components.json').write_bytes(encoded)
    return output / 'image-components.json'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ('server', 'console', 'neutral'):
        parser.add_argument('--' + role + '-archive', type=Path, required=True)
        parser.add_argument('--' + role + '-sha256', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        path = inspect_components(**vars(args))
    except (InstallError, OSError, ValueError, tarfile.TarError, EOFError):
        parser.exit(1, 'Image inventory failed; no image was executed or output replaced.\n')
    print('Inventory only; source coverage and redistribution approval remain separate: ' + str(path))
    return 0
