# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Retain neutral Python/XML and static-helper source inputs without executing them."""

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import io
import math
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
import zlib

from . import alpine_sources as alpine, core_python_sources as python
from . import device_finalize as f, image_components as images, offline_sources as shared
from . import release_kit as kit
from .packaging_inputs import _publication
from .state import InstallError


SCHEMA = 'iris-runtime-source-inputs-v1'
BUNDLE = 'iris-runtime-sources.tar.gz'
MANIFEST = 'source-manifest.json'
SCOPE = 'neutral-cpython-xml-and-static-helpers'
MAX_FILE = 64 * 1024**2
MAX_ARCHIVE = 512 * 1024**2
MAX_TOTAL = 128 * 1024**2
MAX_MEMBERS = 50000
SOURCES = {
    'Python-3.12.14.tar.xz': '5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a',
    'cpython-expat-backport.patch': 'ff8e455739170216c358d2fdbf2782a8257a4dc7230179a31ba62a54a4ded384',
    'openssh-10.5p1.tar.gz': 'd44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11',
}
# This is a deliberately closed, reviewed recipe profile, not a shell parser.
# New recipes require review; changing a pin cannot silently invent new support.
CONTROLS = {
    'device/container/Dockerfile': '95632059ab4d3349d2c9b401fe4dad20126b46a0e1b904efce8028289cbdf380',
    'device/container/rebuild-xml.py': 'ade8d7c1006aa57b7bfdd1b0df1b1bf2096053cce0269a4e3fbc63c801671436',
    'server/Dockerfile': '78a8d09c9ddbc4f3ed33df8c19fb7d0e79fa2981de9fe6a4bebdeb032983bfe1',
    'tools/build-device-image.sh': '8a0d84d2a997b4a0b3c03e99605e10b387547879f6c6322c2d130603f61f379c',
    'tools/build-ssh-verifier.sh': 'e4b95f3ee2849f33c35557bfc26bb0a5a32990d3d4242eb05ce05ec7e0c4016b',
    'tools/build-instruction-crypto-inner.sh': 'ff9b2fb38841661ccd5df9f1f58a1ad9ded7d66dccf92f59d69aa9fb9276a976',
    'tools/iris-aead.c': '75fff094855d4232cd79722e0f89f499bc8f62fe64ee62eb46720b02c29bf3f4',
    'tools/licenses/musl-COPYRIGHT': 'b870108ec5e7790e9f9919064f1b9421d62d5f9b0e6c230c6adf7ea2da62e97b',
}
ALPINE = {
    'musl': ('1.2.6-r2', 'f5640d3a10f664c9119720c60515265d3d6f6d01'),
    'openssl': ('3.5.9-r0', '29b9ec24b1b5b39aeef51fa2a044210e2ec5258e'),
}
BASE = 'sha256:c4634f578a412db396771b61b064c6e546c9d6414c7fb5b1b05d5871f1885f7b'
PATCH_COMMIT = '278c3c2f0733e06613cf3e7a1d9c8c3c03248638'
README = b'''Neutral Python/XML and static-helper source inputs

Externally pinned local-candidate.json and image inventory select the source
archive, installer source inventory, image bytes and neutral build-context hash.
The local candidate is not publisher authenticated. Commit is the selected
candidate identity, not an independently reconstructed Git object proof.

sources/ retains the original CPython 3.12.14 and OpenSSH 10.5p1 archives and
exact CPython XML patch. controls/ contains exact canonical committed build
controls. Review their original build instructions before any separate rebuild.
notices/ retains source notices and exact observed/composed runtime notices.
evidence/ preserves installed Python build configuration and image configuration
as inert data: no Python module, patch, shell, Makefile or image was executed.

The referenced Alpine companion must accompany this archive. Its exact musl
1.2.6-r2 and OpenSSL 3.5.9-r0 source and port inputs are independently validated;
they are not duplicated here. Static linkage is a declared recipe relationship,
not proof of every linked byte. The original Python base OCI history was removed
by flattening and is not reconstructed from its tag or installed configuration.

Observed generated binaries/bytecode are identified but not reproduced. Exact
source/data matches are distinguished from generated or unmapped files. Other
image components, unknown executable paths, aria, core Python/pip, OS packages
and web assets have separate evidence. No complete-image coverage, legal approval,
publisher authentication or reproducible-binary claim is made.
'''


def fail(message):
    raise InstallError('Runtime source inputs: ' + message)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


@contextmanager
def _snapshot(path, expected, maximum=MAX_ARCHIVE):
    """One bounded anonymous snapshot, before parsing or using any content."""
    kit._sha(expected)
    with tempfile.TemporaryFile() as private:
        with alpine._external(path, maximum) as source:
            digest, _ = f._copy(source, private, maximum)
        if digest != expected:
            fail('input differs from its externally selected digest')
        private.seek(0)
        yield private


def _read(path, expected, maximum=MAX_FILE):
    with _snapshot(path, expected, maximum) as stream:
        return stream.read(maximum + 1)


class _GitCommentTarInfo(kit._BoundedTarInfo):
    """Pinned musl/OpenSSL tars have one inert Git-comment global PAX header."""
    def _proc_member(self, archive):
        if self.type == tarfile.XGLTYPE:
            if not 0 < self.size <= 256 or getattr(archive, '_git_global', False):
                fail('unsupported upstream global metadata')
            archive._git_global = True
            result = tarfile.TarInfo._proc_member(self, archive)
            if (set(archive.pax_headers) != {'comment'}
                    or not re.fullmatch('[a-f0-9]{40}', archive.pax_headers['comment'])):
                fail('upstream global metadata must be one inert Git comment')
            return result
        return super()._proc_member(archive)


@contextmanager
def _tar(source, *, compression=None, maximum=MAX_ARCHIVE, links=False, strict=False, git_comment=False):
    """Bound and close every tar, without extracting a member onto the filesystem."""
    with tempfile.TemporaryFile() as plain:
        if compression == 'xz':
            data = shared._expand_index(source.read(MAX_FILE + 1))
            if len(data) > maximum:
                fail('expanded source exceeds its bound')
            plain.write(data)
        elif compression == 'gz':
            with gzip.GzipFile(fileobj=source) as expanded:
                f._copy(expanded, plain, maximum)
        else:
            f._copy(source, plain, maximum)
        length = plain.tell()
        plain.seek(0)
        info = _GitCommentTarInfo if git_comment else f._TarInfo if links else kit._BoundedTarInfo
        with tarfile.open(fileobj=plain, mode='r:', tarinfo=info) as archive:
            members = {}
            for member in archive:
                name = images._name(member.name.rstrip('/') if member.isdir() else member.name,
                                    directory=member.isdir())
                if (name in members or len(members) >= MAX_MEMBERS or not 0 <= member.size <= maximum
                        or not math.isfinite(member.mtime) or any(key.startswith('GNU.sparse') for key in member.pax_headers)
                        or not (member.isfile() or member.isdir() or links and (member.issym() or member.islnk()))
                        or not member.isfile() and member.size):
                    fail('unsupported or repeated tar member')
                if strict and (not member.isfile() or member.mode != 0o644 or member.uid or member.gid
                               or member.uname or member.gname or member.mtime
                               or any(key != 'path' for key in member.pax_headers)):
                    fail('unsupported companion metadata')
                if member.issym() or member.islnk():
                    images._link(name, member.linkname, symbolic=member.issym())
                members[name] = member
            for name in members:
                if any(str(parent) in members and not members[str(parent)].isdir()
                       for parent in PurePosixPath(name).parents if str(parent) != '.'):
                    fail('tar path traverses a non-directory')
            if length % 512 or length - archive.offset < 1024:
                fail('tar is not completely terminated')
            plain.seek(archive.offset)
            while tail := plain.read(kit.CHUNK):
                if tail.strip(b'\0'):
                    fail('tar has trailing payload')
            yield archive, members


def _member(archive, members, name, maximum=MAX_FILE):
    member = members.get(name)
    if member is None or not member.isfile() or member.size > maximum:
        fail('required regular evidence file is absent or oversized: ' + name)
    return archive.extractfile(member).read(maximum + 1)


def _record(value):
    return {**shared._record(value), 'mode': 0o644}


def _candidate(directory, expected):
    directory = f._path(directory)
    raw = _read(directory / 'local-candidate.json', expected, kit.MAX_METADATA)
    value = kit._json(raw)
    if (not isinstance(value, dict) or value.get('format') != 'iris-local-release-candidate-v1'
            or value.get('authenticated') is not False or not isinstance(value.get('commit'), str)
            or not re.fullmatch('[a-f0-9]{40}', value['commit']) or not isinstance(value.get('version'), str)
            or not re.fullmatch(r'20\d\d\.\d\d\.\d\d(?:\.\d+)?', value['version'])
            or value.get('tag') != 'v' + value['version'] or value.get('profile') not in kit.PROFILES
            or not isinstance(value.get('files'), dict) or not 1 <= len(value['files']) <= 128):
        fail('unsupported externally selected local candidate')
    for name, record in value['files'].items():
        kit._name(name)
        kit._keys(record, {'sha256', 'size'})
        kit._sha(record['sha256'])
        if type(record['size']) is not int or not 0 <= record['size'] <= kit.MAX_ASSET:
            fail('invalid candidate asset size')
    return raw, value


@contextmanager
def _asset(directory, candidate, name, maximum=MAX_ARCHIVE):
    record = candidate['files'].get(name)
    if record is None or record['size'] > maximum:
        fail('candidate omits a bounded required asset')
    with _snapshot(directory / name, record['sha256'], maximum) as stream:
        if stream.seek(0, 2) != record['size']:
            fail('candidate asset size differs')
        stream.seek(0)
        yield stream


def _canonical_source(directory, candidate):
    names = [name for name in candidate['files'] if name.endswith('.deb.source.json')]
    if len(names) != 1:
        fail('candidate needs one installer source inventory')
    with _asset(directory, candidate, names[0], kit.MAX_METADATA) as stream:
        sidecar_raw = stream.read()
    sidecar = kit._json(sidecar_raw)
    kit._keys(sidecar, {'schema', 'commit', 'files'})
    if (sidecar['schema'] != 1 or sidecar['commit'] != candidate['commit']
            or not isinstance(sidecar['files'], dict) or not 1 <= len(sidecar['files']) <= MAX_MEMBERS):
        fail('installer source inventory differs from selected commit')
    for name, digest in sidecar['files'].items():
        shared._relative(name)
        kit._sha(digest)
    selected, records = {}, {}
    with _asset(directory, candidate, 'iris.tgz') as stream, _tar(stream, compression='gz') as (archive, members):
        actual = {name[5:] for name, row in members.items() if row.isfile() and name.startswith('iris/')}
        extras = actual - set(sidecar['files'])
        if (set(sidecar['files']) - actual or extras - {'MANIFEST.txt', 'artifacts/.gitkeep'}
                or any(name != 'iris' and not name.startswith('iris/') for name in members)):
            fail('canonical source archive differs from installer source inventory')
        for name, digest in sidecar['files'].items():
            row = members['iris/' + name]
            if not row.isfile() or row.mode not in (0o644, 0o755):
                fail('canonical source mode is unsupported')
            data = _member(archive, members, 'iris/' + name)
            if _sha(data) != digest:
                fail('canonical source file differs from installer inventory')
            records[name] = {'sha256': digest, 'size': len(data), 'mode': row.mode}
            if (name in CONTROLS or name == 'VERSION' or name.startswith('device/agent/')
                    or name in ('device/verify_image.py', 'device/container/entrypoint.sh', 'device/container/reconcile.sh',
                                'deliverables/aria2c-x86_64', 'deliverables/aria2c-aarch64')):
                selected[name] = data
        if 'artifacts/.gitkeep' in extras and _member(archive, members, 'iris/artifacts/.gitkeep'):
            fail('generated empty artifact marker changed')
    if selected.get('VERSION') != (candidate['version'] + '\n').encode():
        fail('source VERSION differs from the selected candidate')
    if any(_sha(selected.get(name, b'')) != digest for name, digest in CONTROLS.items()):
        fail('unknown build recipe or source pin; this profile requires review')
    return selected, records, sidecar_raw


def _context(source, records):
    mapping = {'agent/' + name.rsplit('/', 1)[1]: name for name in source
               if name.startswith('device/agent/') and name.count('/') == 2 and name.endswith('.py')}
    mapping.update({'agent/verify_image.py': 'device/verify_image.py',
        'agent/peer-transfer-hook.sh': 'device/agent/peer-transfer-hook.sh', 'agent/VERSION': 'VERSION',
        'Dockerfile': 'device/container/Dockerfile', 'entrypoint.sh': 'device/container/entrypoint.sh',
        'reconcile.sh': 'device/container/reconcile.sh', 'rebuild-xml.py': 'device/container/rebuild-xml.py',
        'iris-aead.c': 'tools/iris-aead.c', 'build-instruction-crypto-inner.sh': 'tools/build-instruction-crypto-inner.sh',
        'musl-COPYRIGHT': 'tools/licenses/musl-COPYRIGHT',
        'agent_bin/aria2c-amd64': 'deliverables/aria2c-x86_64',
        'agent_bin/aria2c-arm64': 'deliverables/aria2c-aarch64'})
    inputs = {name: {'source': path, **records[path], 'classification': 'canonical-source-exact'}
              for name, path in mapping.items()}
    for name in ('agent/iris-signers.allowed_signers', 'agent/iris-root.allowed_signers'):
        inputs[name] = {'source': None, 'sha256': _sha(b''), 'size': 0, 'classification': 'generated-empty-neutral-input'}
    encoded = ''.join(row['sha256'] + '  ' + name + '\n' for name, row in sorted(inputs.items())).encode()
    return {'source_sha256': _sha(encoded), 'inputs': inputs, 'hash_includes_modes': False,
            'binding': 'context-digest-matched', 'base_index_declared': BASE,
            'original_base_history': 'not-retained', 'binary_reproduction': 'not-assessed'}


def _upstream(data, root, compression, *, git_comment=False):
    records, notices = {}, {}
    with _tar(io.BytesIO(data), compression=compression, git_comment=git_comment) as (archive, members):
        if any(name != root and not name.startswith(root + '/') for name in members):
            fail('upstream archive has an unexpected source root')
        for name, member in members.items():
            if not member.isfile():
                continue
            relative = name[len(root) + 1:]
            digest, size = f._copy(archive.extractfile(member), None, MAX_FILE)
            records[relative] = {'sha256': digest, 'size': size}
            if python._notice(relative) or relative == 'Include/patchlevel.h':
                notices[relative] = _member(archive, members, name, images.MAX_FILE_METADATA)
    return records, notices


def _alpine(archive, expected, inventory, inventory_sha256):
    # Validate exactly the private bytes whose external archive digest was checked.
    with _snapshot(archive, expected, alpine.MAX_TOTAL) as stream:
        value = alpine._validate_archive(None, inventory, inventory_sha256, descriptor=stream.fileno())
        chosen = {}
        for origin, (version, commit) in ALPINE.items():
            matches = [row for row in value['sources'] if (row['origin'], row['version'], row['aports_commit']) == (origin, version, commit)]
            if len(matches) != 1:
                fail('validated Alpine companion lacks an exact linked source recipe')
            chosen[origin] = matches[0]
        sources = {}
        for origin, filename in (('openssl', 'openssl-3.5.9.tar.gz'), ('musl', 'musl-1.2.6.tar.gz')):
            matches = [row for row in chosen[origin]['inputs'] if row['filename'] == filename]
            if len(matches) != 1:
                fail('Alpine recipe lacks its exact upstream input')
            sources[origin] = matches[0]['path']
        stream.seek(0)
        with _tar(stream, compression='gz', maximum=alpine.MAX_TOTAL) as (tar, members):
            openssl_data = _member(tar, members, sources['openssl'])
            musl_data = _member(tar, members, sources['musl'])
        _, notices = _upstream(openssl_data, 'openssl-3.5.9', 'gz', git_comment=True)
        license_data = notices.get('LICENSE.txt')
        if license_data is None or _sha(license_data) != '7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a':
            fail('OpenSSL source license differs from the canonical build pin')
        _, musl_notices = _upstream(musl_data, 'musl-1.2.6', 'gz', git_comment=True)
        musl_notice = musl_notices.get('COPYRIGHT')
        if musl_notice is None or _sha(musl_notice) != CONTROLS['tools/licenses/musl-COPYRIGHT']:
            fail('musl source COPYRIGHT differs from the canonical notice')
    return {'archive_sha256': expected, 'schema': alpine.SCHEMA, 'sources': chosen,
            'delivery': 'same-exact-companion-required-alongside'}, license_data, musl_notice


def _configuration(name):
    return (name == 'usr/local/include/python3.12/pyconfig.h'
            or re.fullmatch(r'usr/local/lib/python3\.12/_sysconfigdata__linux_(?:x86_64|aarch64)-linux-musl\.py', name) is not None
            or re.fullmatch(r'usr/local/lib/python3\.12/config-3\.12-(?:x86_64|aarch64)-linux-musl/(?:Makefile|Setup|Setup.local|Setup.bootstrap|Setup.stdlib|config.c|python-config.py)', name) is not None)


def _python_source(name):
    if name == 'usr/local/lib/python3.12/LICENSE.txt':
        return 'LICENSE'
    match = re.fullmatch(r'usr/local/lib/python3\.12/config-3\.12-(?:x86_64|aarch64)-linux-musl/(config.c.in|install-sh|makesetup)', name)
    if match:
        return {'config.c.in': 'Modules/config.c.in', 'install-sh': 'install-sh', 'makesetup': 'Modules/makesetup'}[match[1]]
    for prefix, replacement in (('usr/local/lib/python3.12/', 'Lib/'), ('usr/local/include/python3.12/', 'Include/')):
        if name.startswith(prefix):
            return replacement + name[len(prefix):]
    return None


def _observed(view, role, python_records):
    result, wanted = [], {}
    for index, layer in enumerate(view['layers']):
        if layer.get('index') != index:
            fail('image layer ordering differs')
        kit._sha(layer.get('diff_id'), 'sha256:')
        rows = layer.get('inventory', {}).get('copied_component_files')
        if not isinstance(rows, list) or len(rows) > images.MAX_FILES:
            fail('missing copied-runtime layer inventory')
        seen = set()
        for row in rows:
            name = row.get('path')
            images._name(name)
            if name in seen:
                fail('duplicate observed runtime path')
            seen.add(name)
            component = row.get('observed_component_path')
            if component not in ('iris-aead', 'static-openssh') and not (role == 'device-runtime' and component == 'cpython-runtime'):
                continue
            kit._sha(row.get('sha256'))
            if row.get('type') != 'file' or type(row.get('size')) is not int or not 0 <= row['size'] <= MAX_FILE:
                fail('unsupported runtime file observation')
            classification = 'observed-generated-binary-not-reproduced'
            source = None
            if component == 'cpython-runtime':
                if _configuration(name):
                    classification = 'observed-generated-build-configuration'
                    wanted.setdefault(index, {})[name] = row
                elif name.endswith(('.pyc', '.pyo')):
                    classification = 'observed-generated-bytecode-not-reproduced'
                elif re.fullmatch(r'usr/local/lib/python3\.12/lib2to3/(?:Pattern)?Grammar3\.12\.14\.final\.0\.pickle', name):
                    classification = 'observed-generated-grammar-data-not-reproduced'
                else:
                    possible = _python_source(name)
                    if possible in python_records:
                        if python_records[possible] != {key: row[key] for key in ('sha256', 'size')}:
                            fail('observed Python source/data differs from selected source')
                        source, classification = possible, 'upstream-source-data-exact'
                    if source is None and not name.endswith(('.so', '.a', '.o', 'python3.12')) and '/libpython3' not in name:
                        classification = 'unmapped-runtime-file-not-source-equal'
            result.append({'image': role, 'platform': view['platform'], 'layer': index,
                'diff_id': layer['diff_id'], 'path': name, 'sha256': row['sha256'], 'size': row['size'],
                'component': component, 'classification': classification, 'source': source})
    return result, wanted


def _image_evidence(stream, view, role, wanted, expected_notices, add):
    """Read only verified image data; no overlay extraction or container execution."""
    notices, configurations = [], []
    with _tar(stream) as (outer, members):
        config_name = 'blobs/sha256/' + view['config_digest'].split(':')[1]
        if role == 'server-image':
            index = kit._json(_member(outer, members, 'manifest.json', kit.MAX_METADATA))
            if not isinstance(index, list) or len(index) != 1:
                fail('ambiguous Docker image manifest')
            config_name = index[0]['Config']
        config = _member(outer, members, config_name, kit.MAX_METADATA)
        if 'sha256:' + _sha(config) != view['config_digest']:
            fail('raw image configuration differs from external inventory')
        prefix = 'evidence/' + role + '/' + view['platform'].split('/')[1] + '/'
        add(prefix + 'config.json', config)
        for index, layer in enumerate(view['layers']):
            selected = dict(wanted.get(index, {}))
            for row in layer['inventory']['notice_files']:
                if row['path'] in expected_notices:
                    selected[row['path']] = row
            if not selected:
                continue
            compressed = _member(outer, members, layer['member'], MAX_ARCHIVE)
            if _sha(compressed) != layer['blob_sha256'] or len(compressed) != layer['blob_size']:
                fail('retained layer differs from external inventory')
            with _tar(io.BytesIO(compressed), compression='gz' if compressed.startswith(b'\x1f\x8b') else None,
                      links=True) as (tar, files):
                tar.fileobj.seek(0)
                digest, _ = f._copy(tar.fileobj, None, MAX_ARCHIVE)
                if 'sha256:' + digest != layer['diff_id']:
                    fail('retained layer differs from its diffID')
                for name, row in sorted(selected.items()):
                    data = _member(tar, files, name, images.MAX_FILE_METADATA)
                    if shared._record(data) != {key: row[key] for key in ('sha256', 'size')}:
                        fail('observed evidence differs from the exact image layer')
                    target = prefix + 'layer-' + str(index) + '/' + name
                    add(target, data)
                    if name in expected_notices:
                        if data != expected_notices[name]:
                            fail('observed runtime notice differs from exact source/composition')
                        notices.append({'image': role, 'platform': view['platform'], 'layer': index,
                                        'runtime_path': name, 'path': target, 'binding': 'source-notice-composition-exact'})
                    else:
                        configurations.append(name)
        if role == 'device-runtime' and (len(configurations) != 9 or len(set(configurations)) != 9):
            fail('neutral image lacks the complete supported installed build configuration')
        if {row['runtime_path'] for row in notices} != set(expected_notices):
            fail('image omits a required original/composed runtime notice')
    return notices


def _assemble(candidate_dir, candidate_sha256, inventory, inventory_sha256, load_source,
              alpine_sources, alpine_sources_sha256):
    directory = f._path(candidate_dir)
    candidate_raw, candidate = _candidate(directory, candidate_sha256)
    inventory_raw = _read(inventory, inventory_sha256, images.MAX_RECEIPT)
    value = kit._json(inventory_raw)
    if (not isinstance(value, dict) or value.get('format') != 'iris-image-component-inventory-v1'
            or value.get('scope') != 'inventory-only' or value.get('authenticated') is not False
            or value.get('source_coverage_complete') is not False or value.get('commit') != candidate['commit']
            or not isinstance(value.get('images'), dict) or set(value['images']) != set(kit.IMAGES)):
        fail('external image inventory does not match the candidate')
    for role, name in (('server-image', 'iris-server-amd64.docker.tar'), ('console-image', 'iris-console-amd64.docker.tar'),
                       ('device-runtime', 'iris-device-neutral.oci.tar')):
        record = candidate['files'].get(name)
        if not record or any(value['images'][role].get(field) != record[key]
                             for field, key in (('archive_sha256', 'sha256'), ('archive_size', 'size'))):
            fail('candidate image identity differs from external inventory')
    source, source_records, source_raw = _canonical_source(directory, candidate)
    context = _context(source, source_records)
    with _asset(directory, candidate, 'iris-device-neutral.oci.tar.manifest', kit.MAX_METADATA) as stream:
        neutral_raw = stream.read()
    try:
        lines = [line.split('=', 1) for line in neutral_raw.decode('ascii').splitlines()]
        neutral = dict(lines)
    except (UnicodeError, ValueError):
        fail('invalid neutral sidecar')
    expected_neutral = {'format': 'iris-device-neutral-oci-v1', 'trust_mode': 'neutral',
        'source_sha256': context['source_sha256'], 'index_digest': value['images']['device-runtime']['index_digest'],
        'archive_sha256': value['images']['device-runtime']['archive_sha256'], 'platforms': 'linux/amd64,linux/arm64'}
    if neutral != expected_neutral or len(lines) != len(neutral):
        fail('neutral sidecar differs from the exact reconstructed context/image')
    payload, total = {}, 0

    def add(name, data):
        nonlocal total
        shared._relative(name)
        if name in payload or len(data) > MAX_FILE or len(payload) >= MAX_MEMBERS:
            fail('duplicate or oversized companion payload')
        total += len(data)
        if total > MAX_TOTAL:
            fail('companion payload exceeds aggregate bound')
        payload[name] = data

    for name in sorted(CONTROLS):
        add('controls/' + name, source[name])
    upstream = {}
    for name, digest in SOURCES.items():
        data = load_source(name, digest)
        if len(data) > MAX_FILE or _sha(data) != digest:
            fail('upstream source differs from reviewed canonical recipe pin')
        add('sources/' + name, data)
        upstream[name] = {'path': 'sources/' + name, 'sha256': digest, 'authority': 'reviewed-canonical-recipe-pin'}
    python_records, python_notices = _upstream(payload['sources/Python-3.12.14.tar.xz'], 'Python-3.12.14', 'xz')
    _, ssh_notices = _upstream(payload['sources/openssh-10.5p1.tar.gz'], 'openssh-10.5p1', 'gz')
    if not re.search(rb'^#define\s+PY_VERSION\s+"3\.12\.14"\s*$', python_notices.get('Include/patchlevel.h', b''), re.M):
        fail('CPython source version header differs')
    if not payload['sources/cpython-expat-backport.patch'].startswith(('From ' + PATCH_COMMIT + ' ').encode()):
        fail('XML patch omits the pinned upstream commit')
    alpine_reference, openssl_notice, musl_notice = _alpine(alpine_sources, alpine_sources_sha256, inventory, inventory_sha256)
    if musl_notice != source['tools/licenses/musl-COPYRIGHT']:
        fail('canonical musl notice differs from the independently selected source')
    original = {'cpython': python_notices, 'openssh': ssh_notices, 'openssl': {'LICENSE.txt': openssl_notice},
                'musl': {'COPYRIGHT': musl_notice}}
    notices = []
    for component, entries in original.items():
        for name, data in sorted(entries.items()):
            if python._notice(name):
                path = 'notices/' + component + '/' + name
                add(path, data)
                notices.append({'component': component, 'source': name, 'path': path, 'binding': 'original-source-notice'})
    try:
        suffix = b'\n\nStatically linked musl libc 1.2.6:\n\n' + source['tools/licenses/musl-COPYRIGHT']
        aead_notice = openssl_notice + suffix
        ssh_notice = ssh_notices['LICENCE'] + suffix
        py_notice, expat_notice = python_notices['LICENSE'], python_notices['Modules/expat/COPYING']
    except KeyError:
        fail('upstream source omits original notices')
    observed = []
    neutral_views = value['images']['device-runtime'].get('platforms')
    if (not isinstance(neutral_views, list) or len(neutral_views) != 2
            or {row.get('platform') for row in neutral_views} != {'linux/amd64', 'linux/arm64'}):
        fail('both neutral platforms are required')
    for role, views, filename, expected_notices in (
        ('device-runtime', neutral_views, 'iris-device-neutral.oci.tar', {
            'usr/local/share/licenses/iris-aead.LICENCE': aead_notice,
            'usr/local/share/licenses/iris-python/PYTHON-LICENSE': py_notice,
            'usr/local/share/licenses/iris-python/EXPAT-COPYING': expat_notice}),
        ('server-image', [value['images']['server-image']], 'iris-server-amd64.docker.tar', {
            'opt/iris/bin/iris-aead.LICENCE': aead_notice, 'opt/iris/bin/ssh-keygen.LICENCE': ssh_notice})):
        with _asset(directory, candidate, filename) as stream:
            for view in sorted(views, key=lambda row: row['platform']):
                rows, wanted = _observed(view, role, python_records)
                components = {row['component'] for row in rows}
                if not {'iris-aead', 'cpython-runtime' if role == 'device-runtime' else 'static-openssh'} <= components:
                    fail('image omits a required runtime/helper observation')
                observed.extend(rows)
                stream.seek(0)
                notices.extend(_image_evidence(stream, view, role, wanted, expected_notices, add))
    add('evidence/local-candidate.json', candidate_raw)
    add('evidence/image-components.json', inventory_raw)
    add('evidence/installer-source.json', source_raw)
    add('evidence/neutral.manifest', neutral_raw)
    add('README.txt', README)
    component_inputs = {
        'cpython-runtime': {'sources': ['sources/Python-3.12.14.tar.xz'],
            'controls': ['controls/device/container/Dockerfile'],
            'alpine_sources': [], 'relationship': 'declared-base-source-and-observed-source-data'},
        'cpython-xml-extensions': {'sources': ['sources/Python-3.12.14.tar.xz', 'sources/cpython-expat-backport.patch'],
            'controls': ['controls/device/container/Dockerfile', 'controls/device/container/rebuild-xml.py'],
            'alpine_sources': ['musl'], 'relationship': 'declared-paired-extension-rebuild'},
        'static-openssh': {'sources': ['sources/openssh-10.5p1.tar.gz'],
            'controls': ['controls/server/Dockerfile', 'controls/tools/build-ssh-verifier.sh'],
            'alpine_sources': ['musl'], 'relationship': 'declared-static-linkage-without-openssl'},
        'iris-aead': {'sources': ['controls/tools/iris-aead.c'],
            'controls': ['controls/server/Dockerfile', 'controls/device/container/Dockerfile',
                         'controls/tools/build-instruction-crypto-inner.sh'],
            'alpine_sources': ['musl', 'openssl'], 'relationship': 'declared-static-linkage'},
    }
    manifest = {'schema': SCHEMA, 'scope': SCOPE, 'authenticated': False, 'source_coverage_complete': False,
        'rebuild_verified': False, 'candidate_sha256': candidate_sha256, 'inventory_sha256': inventory_sha256,
        'commit': candidate['commit'], 'version': candidate['version'], 'context': context,
        'upstream_sources': upstream, 'alpine_reference': alpine_reference, 'component_inputs': component_inputs,
        'observed_files': observed, 'notices': notices, 'files': {name: _record(data) for name, data in sorted(payload.items())}}
    return manifest, payload


def _validate(stream, candidate_dir, candidate_sha256, inventory, inventory_sha256,
              alpine_sources, alpine_sources_sha256):
    with _tar(stream, compression='gz', maximum=MAX_TOTAL, strict=True) as (archive, members):
        manifest = kit._json(_member(archive, members, MANIFEST))
        def load(name, _):
            return _member(archive, members, 'sources/' + name)
        expected, payload = _assemble(candidate_dir, candidate_sha256, inventory, inventory_sha256,
                                      load, alpine_sources, alpine_sources_sha256)
        if f._json(manifest) != f._json(expected) or set(members) != set(payload) | {MANIFEST}:
            fail('companion differs from independently selected source/evidence inventory')
        for name, data in payload.items():
            if _member(archive, members, name) != data:
                fail('companion payload differs from independently reconstructed evidence')
        return manifest


def validate_source_archive(archive, candidate_dir, candidate_sha256, inventory, inventory_sha256,
                            alpine_sources, alpine_sources_sha256):
    """Derive all claims again from external candidate/inventory and source pins."""
    with alpine._external(archive, MAX_TOTAL) as source, tempfile.TemporaryFile() as private:
        f._copy(source, private, MAX_TOTAL)
        private.seek(0)
        return _validate(private, candidate_dir, candidate_sha256, inventory, inventory_sha256,
                         alpine_sources, alpine_sources_sha256)


def build_sources(candidate_dir, candidate_sha256, inventory, inventory_sha256,
                  source_pool, alpine_sources, alpine_sources_sha256, output_dir):
    """Publish one new deterministic source companion from explicit local inputs."""
    pool = f._path(source_pool)
    manifest, payload = _assemble(candidate_dir, candidate_sha256, inventory, inventory_sha256,
        lambda name, expected: _read(pool / name, expected), alpine_sources, alpine_sources_sha256)
    encoded = f._json(manifest)
    if len(encoded) > MAX_FILE:
        fail('manifest exceeds its bound')
    with _publication(output_dir) as (stage, output):
        candidate = stage / BUNDLE
        with candidate.open('xb') as raw, gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name in sorted([MANIFEST, *payload]):
                    data = encoded if name == MANIFEST else payload[name]
                    row = tarfile.TarInfo(name)
                    row.mode, row.size = 0o644, len(data)
                    archive.addfile(row, io.BytesIO(data))
        with candidate.open('rb') as stream:
            _validate(stream, candidate_dir, candidate_sha256, inventory, inventory_sha256,
                      alpine_sources, alpine_sources_sha256)
            stream.seek(0)
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        (stage / MANIFEST).write_bytes(encoded)
    return {'archive': str(output / BUNDLE), 'sha256': digest, 'manifest_sha256': _sha(encoded),
        'candidate_sha256': candidate_sha256, 'inventory_sha256': inventory_sha256,
        'scope': SCOPE, 'authenticated': False, 'source_coverage_complete': False, 'rebuild_verified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-dir', type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True, help='External SHA256 of local-candidate.json')
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--inventory-sha256', required=True)
    parser.add_argument('--alpine-sources', type=Path, required=True)
    parser.add_argument('--alpine-sources-sha256', required=True)
    parser.add_argument('--source-pool', type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--output-dir', type=Path)
    action.add_argument('--verify-bundle', type=Path)
    args = vars(parser.parse_args(argv))
    archive, pool, output = (args.pop(name) for name in ('verify_bundle', 'source_pool', 'output_dir'))
    try:
        if archive is not None:
            if pool is not None:
                parser.error('--verify-bundle uses bundled source bytes')
            manifest = validate_source_archive(archive, **args)
            result = {key: manifest[key] for key in ('schema', 'scope', 'candidate_sha256', 'inventory_sha256',
                                                    'source_coverage_complete', 'rebuild_verified')}
        else:
            if pool is None:
                parser.error('--output-dir requires --source-pool')
            result = build_sources(source_pool=pool, output_dir=output, **args)
    except (InstallError, OSError, ValueError, TypeError, KeyError, tarfile.TarError, EOFError, zlib.error):
        parser.exit(1, 'Runtime source collection failed; no code was executed or output replaced.\n')
    print(f._json(result).decode(), end='')
    return 0
