# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Reconstruct image ownership and original notices, without executing images.

Companion references are closed-byte, externally selected references. Release
completion separately validates their source evidence; this catalogue never
turns package ownership or declared license metadata into legal/rebuild proof.
"""

import argparse
from contextlib import ExitStack, contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
import zipfile
import zlib

from . import device_finalize as f, image_components as images, release_kit as kit
from . import offline_sources as shared, runtime_sources as runtime
from .packaging_inputs import _publication
from .state import InstallError


SCHEMA = 'iris-image-source-notices-v1'
BUNDLE = 'iris-image-source-notices.tar.gz'
MANIFEST = 'source-manifest.json'
ROLES = {'debian', 'alpine', 'core-python', 'runtime', 'aria2'}
MAX_TOTAL = 64 * 1024**2
MAX_UPSTREAM = 1024**3
MAX_MEMBERS = 100000
POLICY = {'source': 'e0de18ca949b5ceef4a6e8c012f40800eb9c5d1750f446f1a4b0fd9301a7fde2',
          'license': '372996c5080b9f7f74c6c4b888af414fd3eb392264b4e8a96bd519d953657598'}
POLICY_COMMIT = '308cd89b8f84045d51f7e7f78d9e7ee98c1ab92a'
SCRIPTS = {'usr/local/bin/' + name for name in ('2to3-3.12', 'idle3.12', 'pydoc3.12',
           'python3.12-config', 'pip3', 'pip3.12')} | {'usr/sbin/policy-rc.d'}
WEB_BUNDLES = {'opt/iris/server/webroot/assets/console.js', 'opt/iris/server/console-ui/dist/swarmmap.html'}
SPECIAL = {
    'alpine-base': '5f3e6446e3e80b20e0f9986760b9f151e47e723e57d32c108bce617846d05b52',
    'alpine-baselayout': 'aef255516b71e39109860b92eb027a0986d90197427fb93ec91ebcd04bf59763',
    'alpine-keys': 'cb352e13b9e481b424763bd36d3afdb81ac308e508abed15eb7175530050bd3f',
    'krb5-conf': '7962206597c478b726f46b0392a73bec21bfa70afa56c62ccb043d1ade3d6286'}
EMBEDDED = {'ca-certificates-20260909/certdata.txt':
            'beb7e6dfe6499926e52c075c27bcfbe4c957f8609c575b3860273ae2806f63eb',
            'ca-certificates-20260909/c_rehash.c':
            'a68fedc0edd976b9f35ecfdcb252d80dc12084b1bc4e945be7dc42c437d8b540'}
README = b'''Image ownership and original notice catalogue

The externally selected candidate, image inventory and companion digests bind
this inert catalogue. Original image notices and package ownership metadata are
retained with their exact layer/path/byte identities, including lower layers.
Multiple owners remain explicit. Ownership is attribution, not binary/source
equivalence. Script template comparisons identify exact interpreted source;
configured substitutions and generated files are not reproduced binaries.

Alpine source notices are indexed inside the already carried complete sources.
Recipe-declared metadata is distinguished from original notice bytes. A missing
standalone license filename does not establish a missing source or license grant.
The policy script's reviewed upstream source and MIT notice use newly observed
HTTPS hashes, not an older committed trust pin or upstream signature.

The caller must independently validate the referenced source companions using
the same archive hashes. This catalogue's validator reconstructs only ownership,
notice bytes and reference identities. Complete source approval, redistribution
review, release authentication, rebuild proof, topology qualification and owner
publication approval are separate. No source recipe or image is executed.
'''


def fail(message):
    raise InstallError('Image source notices: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Sink:
    def __init__(self):
        self.data = {}
        self.total = 0

    def add(self, body):
        name = 'data/' + sha(body)
        if name not in self.data:
            self.total += len(body)
            if self.total > MAX_TOTAL or len(self.data) >= MAX_MEMBERS:
                fail('retained notice evidence exceeds bounds')
            self.data[name] = body
        return {'member': name, **shared._record(body)}


@contextmanager
def _companion(path, expected, role):
    with runtime._snapshot(path, expected, kit.MAX_TOTAL) as stream, runtime._tar(
            stream, compression='gz', maximum=kit.MAX_TOTAL) as (archive, members):
        if role == 'aria2':
            yield archive, members, {'scope': 'externally selected aria2 source reference'}
            return
        manifest = kit._json(runtime._member(archive, members, MANIFEST, images.MAX_RECEIPT))
        if not isinstance(manifest, dict) or not isinstance(manifest.get('files'), dict):
            fail('companion lacks a closed file inventory')
        actual = {}
        for name, row in members.items():
            if not row.isfile() or row.mode not in (0o644, 0o755):
                fail('source companion has unsupported member metadata')
            if name == MANIFEST:
                continue
            digest, size = f._copy(archive.extractfile(row), None, kit.MAX_TOTAL)
            record = manifest['files'].get(name)
            if (not isinstance(record, dict) or set(record) not in ({'sha256', 'size'}, {'sha256', 'size', 'mode'})
                    or record.get('sha256') != digest or type(record.get('size')) is not int or record['size'] != size
                    or 'mode' in record and record['mode'] != row.mode):
                fail('source companion differs from its closed file inventory')
            actual[name] = record
        if actual != manifest['files']:
            fail('source companion omits inventoried files')
        yield archive, members, manifest


def _resolve(path, filesystem):
    for _ in range(32):
        parts = path.split('/')
        for index in range(1, len(parts) + 1):
            row = filesystem.get('/'.join(parts[:index]))
            if row is not None and row['type'] == 'symlink':
                path = '/'.join([row['target'], *parts[index:]])
                break
        else:
            return path, filesystem.get(path)
    fail('image link chain exceeds bound')


def _owners(filesystem, sink):
    owners, packages = {}, {}
    def own(name, package, evidence, kind):
        normalized = name.removeprefix('/').rstrip('/')
        if normalized in ('', '.'):
            return
        images._name(normalized)
        resolved, _ = _resolve(normalized, filesystem)
        row = {'package': package, 'metadata': evidence, 'kind': kind, 'listed_path': normalized}
        for path in {normalized, resolved}:
            if row not in owners.setdefault(path, []):
                owners[path].append(row)
    if 'var/lib/dpkg/status' in filesystem:
        raw = filesystem['var/lib/dpkg/status']['_data']
        database = sink.add(raw)
        for item in images._debian(raw):
            packages[item['package']] = packages[item['package'] + ':' + item['architecture']] = item
        for path, row in filesystem.items():
            if re.fullmatch(r'var/lib/dpkg/info/[^/]+\.list', path):
                identity = packages.get(PurePosixPath(path).name[:-5])
                if identity is None or row['type'] != 'file' or '_data' not in row:
                    fail('dpkg ownership list lacks a package or regular metadata')
                evidence = {'path': path, **sink.add(row['_data']), 'database': database}
                for name in images._text(row['_data']).splitlines():
                    own(name, identity, evidence, 'dpkg-file-list')
            match = re.fullmatch(r'var/lib/dpkg/info/([^/]+)\.(preinst|postinst|prerm|postrm|config)', path)
            if match and match[1] in packages:
                own(path, packages[match[1]], {'path': path, 'database': database}, 'dpkg-maintainer-script-name')
    elif 'lib/apk/db/installed' in filesystem:
        raw = filesystem['lib/apk/db/installed']['_data']
        database = sink.add(raw)
        parsed = images._alpine(raw)
        for paragraph, identity in zip(images._text(raw).strip().split('\n\n'), parsed):
            directory = None
            for line in paragraph.splitlines():
                key, value = line[0], line[2:]
                if key == 'F':
                    directory = value
                elif key == 'R':
                    if directory is None or not value or '/' in value:
                        fail('invalid APK ownership path')
                    own(directory + '/' + value, identity, {'path': 'lib/apk/db/installed', **database}, 'apk-file-list')
    return owners


def _retain(name):
    return (images._notice(name) or re.fullmatch(r'var/lib/dpkg/info/[^/]+\.list', name) is not None
            or name in SCRIPTS or name.startswith(('opt/iris/server/webroot/fonts/', 'opt/iris/docs/zensical/swagger/'))
            or name == 'opt/iris/server/webroot/index.html'
            or name.endswith(('/console.js', '/swarmmap.html')))


def _notice(path, filesystem, sink):
    resolved, record = _resolve(path, filesystem)
    result = {'path': path, 'resolved_path': resolved}
    if record is not None and record['type'] == 'file' and '_data' in record:
        result.update(status='original-bytes-retained', **sink.add(record['_data']))
    else:
        result['status'] = 'unresolved-original-notice'
    return result


def _source_refs(package, manifests):
    if 'source' in package:
        identities = {(package['source'], package['source_version'])}
        identities.update((row['source'], row['version']) for key in ('built_using', 'static_built_using') for row in package[key])
        records = {(row['name'], row['version']): row for row in manifests['debian']['sources']}
        if not identities <= records.keys():
            fail('Debian package source identity is absent from selected companion')
        return [{'companion': 'debian', 'name': name, 'version': version, 'files': records[name, version]['files']}
                for name, version in sorted(identities)]
    if package['virtual']:
        return []
    matches = [row for row in manifests['alpine']['sources'] if
               (row['origin'], row['version'], row['aports_commit']) ==
               (package['origin'], package['version'], package['aports_commit'])]
    if len(matches) != 1:
        fail('Alpine package origin is absent or ambiguous in selected companion')
    return [{'companion': 'alpine', 'origin': package['origin'], 'version': package['version'],
             'aports_commit': package['aports_commit']}]


def _script(path, body, templates, sink):
    if path == 'usr/sbin/policy-rc.d':
        source = templates['policy']
        match = re.search(rb"<<-'EOF'\n(.*?)\n\t*EOF", source, re.DOTALL)
        if match is None:
            fail('reviewed policy source delimiter changed')
        expected = b'\n'.join(line.lstrip(b'\t') for line in match[1].split(b'\n')) + b'\n'
        if expected != body:
            fail('policy script differs from reviewed literal source')
        return {'kind': 'literal-interpreted-source', 'upstream_commit': POLICY_COMMIT,
                'source': sink.add(source), 'notice': sink.add(templates['policy-license'])}
    basename = path.rsplit('/', 1)[-1]
    version = templates['version']
    source_name = {'2to3-3.12': 'Tools/scripts/2to3', 'idle3.12': 'Tools/scripts/idle3',
                   'pydoc3.12': 'Tools/scripts/pydoc3'}.get(basename)
    if source_name:
        source = templates[source_name]
        expected = source.replace(b'#!/usr/bin/env python3\n', b'#!/usr/local/bin/python3.12\n', 1)
        if expected != body:
            fail('installed Python script differs from exact source/shebang mapping')
        return {'kind': 'installed-shebang', 'source': source_name, 'python_version': version,
                'source_bytes': sink.add(source)}
    if basename == 'python3.12-config':
        source = templates['Misc/python-config.sh.in'].decode('utf-8')
        pattern = re.sub(r'@[A-Za-z_]+@', lambda _: '(.*?)', re.escape(source))
        match = re.fullmatch(pattern, body.decode('utf-8'), re.DOTALL)
        if match is None:
            fail('installed Python configuration differs from its source template')
        return {'kind': 'configured-interpreted-source', 'source': 'Misc/python-config.sh.in',
                'python_version': version, 'source_bytes': sink.add(source.encode()),
                'substitutions': list(zip(re.findall(r'@([A-Za-z_]+)@', source), match.groups()))}
    source = templates['pip-template']
    match = re.search(rb"SCRIPT_TEMPLATE = r'''(.*?)'''", source, re.DOTALL)
    if match is None:
        fail('pip source template is unavailable')
    expected = b'#!/usr/local/bin/python3.12\n' + match[1] % {
        b'module': b'pip._internal.cli.main', b'import_name': b'main', b'func': b'main'}
    if expected != body:
        fail('pip launcher differs from exact distlib entrypoint template')
    return {'kind': 'pip-distlib-entrypoint', 'source': 'pip/_vendor/distlib/scripts.py',
            'source_bytes': sink.add(source)}


def _templates(companions, policy, license_body):
    result = {}
    for role, version in [('core-python', '3.12.15'), ('runtime', '3.12.14')]:
        outer, members, _ = companions[role]
        raw = runtime._member(outer, members, 'sources/Python-' + version + '.tar.xz')
        with runtime._tar(io.BytesIO(raw), compression='xz', maximum=256 * 1024**2) as (archive, rows):
            values = {name: runtime._member(archive, rows, 'Python-' + version + '/' + name) for name in
                      ('Tools/scripts/2to3', 'Tools/scripts/idle3', 'Tools/scripts/pydoc3', 'Misc/python-config.sh.in')}
        result[role] = {**values, 'version': version, 'policy': policy, 'policy-license': license_body}
    outer, members, _ = companions['core-python']
    raw = runtime._member(outer, members, 'sources/pip-25.0.1.tar.gz')
    with runtime._tar(io.BytesIO(raw), compression='gz', maximum=256 * 1024**2) as (archive, rows):
        result['core-python']['pip-template'] = runtime._member(archive, rows, 'pip-25.0.1/src/pip/_vendor/distlib/scripts.py')
    return result


def _view(role, view, layer, summary, filesystem, sources, templates, manifests, sink, result, *, web_paths=None):
    context = {'image': role, 'platform': view['platform'], 'layer': layer,
               'diff_id': view['layers'][layer]['diff_id'] if type(layer) is int else None}
    owners = _owners(filesystem, sink)
    executables = {row['path']: row for row in summary['executables']}
    for path in summary['unknown_executables']:
        observed = executables[path]
        row = {**context, 'path': path, 'sha256': observed['sha256'], 'size': observed['size']}
        if path in owners:
            row.update(classification='package-metadata-owned', owners=owners[path])
            for owner in row['owners']:
                owner['source_references'] = _source_refs(owner['package'], manifests)
        else:
            source = path.removeprefix('opt/iris/') if path.startswith('opt/iris/') else None
            if role == 'device-runtime':
                source = ('device/container/entrypoint.sh' if path == 'entrypoint.sh' else
                          'device/agent/' + path.removeprefix('opt/iris/agent/') if path.startswith('opt/iris/agent/') else None)
            if source and sources.get(source, {}).get('sha256') == row['sha256']:
                row.update(classification='canonical-project-source-exact', source=source)
            elif path in SCRIPTS and '_data' in filesystem[path]:
                body = filesystem[path]['_data']
                row.update(classification='interpreted-source-mapped', retained_source=sink.add(body),
                           mapping=_script(path, body, templates['runtime' if role == 'device-runtime' else 'core-python'], sink))
            else:
                row['classification'] = 'unresolved-observed-executable'
        result['executables'].append(row)
    for row in summary['notice_files']:
        result['notices'].append({**context, 'observed': row, **_notice(row['path'], filesystem, sink)})
    for db in summary['package_databases']:
        for package in db['packages']:
            row = {**context, 'ecosystem': db['ecosystem'], 'package': package,
                   'source_references': _source_refs(package, manifests)}
            row['notice'] = (_notice('usr/share/doc/' + package['package'] + '/copyright', filesystem, sink)
                             if db['ecosystem'] == 'debian' else
                             {'status': 'virtual-metadata-only' if package['virtual'] else 'see-alpine-origin-notices',
                              'origin': package['origin']})
            result['packages'].append(row)
    # Fixed shipped web locations: original source/data equality, not a new
    # requirement to collect editable fonts or reproduce bundled JavaScript.
    for path, record in filesystem.items():
        if web_paths is not None and path not in web_paths:
            continue
        if '_data' not in record or not (path.startswith(('opt/iris/server/webroot/', 'opt/iris/docs/zensical/swagger/'))
                                         or path in ('opt/iris/LICENSE', 'opt/iris/NOTICE') or path.endswith('/swarmmap.html')):
            continue
        relative = path.removeprefix('opt/iris/')
        digest = record.get('sha256', record.get('_retained_sha256'))
        if sources.get(relative, {}).get('sha256') == digest:
            result['web_files'].append({**context, 'path': path, 'source': relative,
                                        'sha256': digest, 'size': record['size']})
            if path.endswith(('Inter-OFL.txt', 'LICENSE', 'NOTICE', '.LICENSE.txt')):
                result['notices'].append({**context, **_notice(path, filesystem, sink)})
        if path in WEB_BUNDLES:
            body = record['_data']
            begin = body.find(b'/*! Bundled third-party notices')
            end = body.find(b'*/', begin)
            if begin < 0 or end < begin:
                fail('bundled web runtime omits its original notice block')
            notice = body[begin:end]
            packages = [name for name in ('react', 'react-dom', 'scheduler') if ('\n\n' + name + '\n').encode() in notice]
            if (len(packages) != 3 or notice.count(b'Permission is hereby granted, free of charge') != 3
                    or notice.count(b'THE SOFTWARE IS PROVIDED "AS IS"') != 3):
                fail('bundled web notice block differs from the supported component profile')
            result['notices'].append({**context, 'path': path, 'sha256': record['sha256'],
                                     'kind': 'embedded-bundled-third-party-notices', 'packages': packages,
                                     'notice': sink.add(notice)})


def _images(candidate_dir, candidate, inventory, sources, templates, manifests, sink):
    result = {'executables': [], 'notices': [], 'packages': [], 'web_files': []}
    for role in ('console-image', 'server-image', 'device-runtime'):
        image = inventory['images'][role]
        matches = [name for name, row in candidate['files'].items() if row['sha256'] == image['archive_sha256']]
        if len(matches) != 1:
            fail('image inventory archive is absent or ambiguous in selected candidate')
        with runtime._asset(candidate_dir, candidate, matches[0], kit.MAX_ASSET) as stream, runtime._tar(
                stream, maximum=kit.MAX_ASSET) as (outer, members):
            for view in image.get('platforms', [image]):
                filesystem = {}
                for index, layer in enumerate(view['layers']):
                    row = members.get(layer['member'])
                    if row is None or not row.isfile():
                        fail('image layer is unavailable')
                    with outer.extractfile(row) as raw, tempfile.TemporaryFile() as plain:
                        prefix = raw.read(2)
                        raw.seek(0)
                        expanded = gzip.GzipFile(fileobj=raw) if prefix == b'\x1f\x8b' else raw
                        digest, size = f._copy(expanded, plain, kit.MAX_ASSET)
                        if expanded is not raw:
                            expanded.close()
                        if 'sha256:' + digest != layer['diff_id'] or size != layer['expanded_size']:
                            fail('image layer differs from externally selected inventory')
                        plain.flush()
                        previous = dict(filesystem)
                        changes, merged = images._layer(Path('/proc/self/fd') / str(plain.fileno()), filesystem,
                                                         retain_metadata=_retain)
                        changed_paths = {name for name, record in filesystem.items() if record is not previous.get(name)}
                    if f._json(changes) != f._json(layer['inventory']):
                        fail('reconstructed layer inventory differs from external inventory')
                    _view(role, view, index, changes, filesystem, sources, templates, manifests, sink, result,
                          web_paths=changed_paths)
                if f._json(merged) != f._json(view['merged']):
                    fail('reconstructed merged inventory differs from external inventory')
                _view(role, view, 'merged', merged, filesystem, sources, templates, manifests, sink, result)
    return result


class _NoticeTarInfo(f._TarInfo):
    def _proc_member(self, archive):
        if self.type == tarfile.XGLTYPE:
            if not 0 < self.size <= 16384 or getattr(archive, '_notice_global', False):
                fail('excessive source archive global metadata')
            archive._notice_global = True
            value = tarfile.TarInfo._proc_member(self, archive)
            if set(archive.pax_headers) - {'comment', 'mtime'}:
                fail('unsupported source archive global metadata')
            return value
        return super()._proc_member(archive)


def _nested_notices(stream, filename, sink):
    """Read bounded original notice/header members, never extract archive paths."""
    rows = []
    def selected(name):
        return (PurePosixPath(name).name.lower().startswith(('license', 'licence', 'copying', 'copyright', 'notice'))
                or name in EMBEDDED)
    def retain(name, body):
        if name in EMBEDDED and sha(body) != EMBEDDED[name]:
            fail('reviewed embedded source notice changed')
        rows.append({'source_input': filename, 'source_member': name,
                     'kind': 'embedded-source-header' if name in EMBEDDED else 'original-source-notice', **sink.add(body)})
    if filename.endswith('.zip'):
        with zipfile.ZipFile(stream) as archive:
            seen, total = set(), 0
            for member in archive.infolist():
                name = images._name(member.filename.rstrip('/'), directory=member.is_dir())
                if name in seen or len(seen) >= MAX_MEMBERS or member.flag_bits & 1:
                    fail('unsafe or excessive ZIP source entries')
                seen.add(name)
                total += member.file_size
                if total > MAX_UPSTREAM:
                    fail('ZIP source expansion exceeds bound')
                if not member.is_dir() and selected(name):
                    if member.file_size > images.MAX_FILE_METADATA:
                        fail('source notice exceeds bound')
                    retain(name, archive.read(member))
        return rows
    if not filename.endswith(('.tar.gz', '.tgz', '.tar.xz', '.tar.bz2')):
        return rows  # Literal patches/data are preserved by the source companion.
    import bz2
    opener = bz2.BZ2File if filename.endswith('.bz2') else lambda source: gzip.GzipFile(fileobj=source)
    # The existing XZ decoder constrains dictionary memory as well as output.
    expanded = io.BytesIO(shared._expand_index(stream.read(MAX_UPSTREAM + 1))) if filename.endswith('.xz') else opener(stream)
    with expanded, tempfile.TemporaryFile() as plain:
        f._copy(expanded, plain, MAX_UPSTREAM)
        length = plain.tell()
        plain.seek(0)
        with tarfile.open(fileobj=plain, mode='r:', tarinfo=_NoticeTarInfo) as archive:
            seen = set()
            for member in archive:
                name = member.name.removeprefix('./').rstrip('/') if member.isdir() else member.name.removeprefix('./')
                images._name(name or '.', directory=member.isdir())
                if name in seen or len(seen) >= MAX_MEMBERS or not 0 <= member.size <= MAX_UPSTREAM:
                    fail('repeated or excessive source archive entry')
                seen.add(name)
                if member.issym() or member.islnk():
                    images._link(name, member.linkname, symbolic=member.issym())
                if member.isfile() and selected(name):
                    if member.size > images.MAX_FILE_METADATA:
                        fail('source notice exceeds bound')
                    retain(name, archive.extractfile(member).read())
            if length % 512 or length - archive.offset < 1024:
                fail('source archive is not completely terminated')
            plain.seek(archive.offset)
            if any(block.strip(b'\0') for block in iter(lambda: plain.read(kit.CHUNK), b'')):
                fail('source archive has trailing payload')
    return rows


def _alpine_notices(companion, sink):
    archive, members, manifest = companion
    result = []
    for source in manifest['sources']:
        origin = source['origin']
        row = {'origin': origin, 'version': source['version'], 'aports_commit': source['aports_commit'],
               'notices': [], 'metadata_only': False}
        recipe_path = source['port_files']['APKBUILD']['path']
        recipe = runtime._member(archive, members, recipe_path)
        row['recipe'] = {'companion_member': recipe_path, **sink.add(recipe)}
        if origin in SPECIAL:
            if sha(recipe) != SPECIAL[origin]:
                fail('reviewed metadata-only Alpine recipe changed')
            row.update(metadata_only=True, review='Recipe-declared terms and original files retained; no separate original grant inferred.')
        for item in source['inputs']:
            path = item['path']
            if path not in members:
                fail('Alpine source reference is absent')
            with archive.extractfile(members[path]) as stream:
                notices = _nested_notices(stream, item['filename'], sink)
            for notice in notices:
                notice.update(companion_member=path, source_sha512=item['sha512'])
            row['notices'].extend(notices)
            if origin == 'alpine-baselayout' and item['filename'] in ('protocols-6.4', 'services-6.4'):
                body = runtime._member(archive, members, path)
                row.setdefault('data_headers', []).append({'companion_member': path, 'source_sha512': item['sha512'],
                                                          'kind': 'original-data-with-IANA-header', **sink.add(body)})
        if origin == 'ca-certificates':
            if {notice['source_member'] for notice in row['notices']} != set(EMBEDDED):
                fail('required embedded certificate-source notices are absent')
        if not row['notices'] and not row['metadata_only']:
            row['review'] = 'No named original notice found; source files remain retained for explicit review.'
        result.append(row)
    return result


def _assemble(candidate_dir, candidate_sha256, inventory_path, inventory_sha256, companions, policy, license_body):
    if sha(policy) != POLICY['source'] or sha(license_body) != POLICY['license']:
        fail('policy source or original notice differs from reviewed external pins')
    if not isinstance(companions, dict) or set(companions) != ROLES:
        fail('exact selected companion roles are required')
    raw, inventory = runtime.python._inventory(inventory_path, inventory_sha256)
    _, candidate = runtime._candidate(candidate_dir, candidate_sha256)
    if inventory['commit'] != candidate['commit']:
        fail('candidate and inventory commits differ')
    _, sources, _ = runtime._canonical_source(candidate_dir, candidate)
    sink = Sink()
    sink.add(policy)
    sink.add(license_body)
    with ExitStack() as stack:
        opened, references, manifests = {}, {}, {}
        for role, selection in sorted(companions.items()):
            if not isinstance(selection, dict) or set(selection) != {'path', 'sha256'}:
                fail('companion selection needs an external path and SHA256')
            opened[role] = stack.enter_context(_companion(selection['path'], selection['sha256'], role))
            manifest = opened[role][2]
            if role != 'aria2' and manifest.get('inventory_sha256') != inventory_sha256:
                fail('source companion belongs to another image inventory')
            manifests[role] = manifest
            references[role] = {'archive_sha256': selection['sha256'],
                                'scope': manifest.get('scope'),
                                'manifest_canonical_sha256': sha(f._json(manifest)) if role != 'aria2' else None,
                                'full_source_validation': 'required-separately-by-completion'}
        templates = _templates(opened, policy, license_body)
        observations = _images(candidate_dir, candidate, inventory, sources, templates, manifests, sink)
        alpine = _alpine_notices(opened['alpine'], sink)
    data = {'README.txt': README, 'policy/source': policy, 'policy/LICENSE': license_body, **sink.data}
    result = {'schema': SCHEMA, 'scope': 'observed-image-ownership-original-notices-and-source-references',
              'authenticated': False, 'source_coverage_complete': False, 'rebuild_verified': False,
              'candidate_sha256': candidate_sha256, 'inventory_sha256': inventory_sha256,
              'commit': candidate['commit'], 'companions': references, **observations, 'alpine_origins': alpine,
              'remaining_reviews': ['recipe-metadata-only notice associations', 'redistribution approval',
                                    'independent source-companion validation', 'release authentication',
                                    'topology qualification', 'owner publication approval'],
              'files': {name: shared._record(body) for name, body in sorted(data.items())}}
    if len(f._json(result)) > images.MAX_RECEIPT:
        fail('catalogue manifest exceeds bound')
    return result, data


def _validate(stream, candidate_dir, candidate_sha256, inventory, inventory_sha256, companions):
    with runtime._tar(stream, compression='gz', maximum=MAX_TOTAL + images.MAX_RECEIPT, strict=True) as (archive, members):
        manifest = kit._json(runtime._member(archive, members, MANIFEST, images.MAX_RECEIPT))
        expected, data = _assemble(candidate_dir, candidate_sha256, inventory, inventory_sha256, companions,
            runtime._member(archive, members, 'policy/source'), runtime._member(archive, members, 'policy/LICENSE'))
        if f._json(manifest) != f._json(expected) or set(members) != {MANIFEST, *data}:
            fail('catalogue differs from independently reconstructed evidence')
        for name, body in data.items():
            if runtime._member(archive, members, name, MAX_TOTAL) != body:
                fail('catalogue original bytes differ from independent inputs')
        return expected


def validate_catalog(archive, candidate_dir, candidate_sha256, inventory, inventory_sha256, companions):
    """Reconstruct catalogue claims; source-companion validation stays separate."""
    with runtime.alpine._external(archive, MAX_TOTAL + images.MAX_RECEIPT) as source, tempfile.TemporaryFile() as private:
        f._copy(source, private, MAX_TOTAL + images.MAX_RECEIPT)
        private.seek(0)
        return _validate(private, candidate_dir, candidate_sha256, inventory, inventory_sha256, companions)


def build_catalog(candidate_dir, candidate_sha256, inventory, inventory_sha256, companions,
                  policy_source, policy_license, output_dir):
    """Publish once from pinned local bytes; never rebuild or execute an image."""
    with _publication(output_dir) as (stage, output):
        manifest, data = _assemble(candidate_dir, candidate_sha256, inventory, inventory_sha256, companions,
                                  runtime._read(policy_source, POLICY['source']), runtime._read(policy_license, POLICY['license']))
        path = stage / BUNDLE
        with path.open('xb') as raw, gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name, body in sorted({MANIFEST: f._json(manifest), **data}.items()):
                    item = tarfile.TarInfo(name)
                    item.mode, item.size = 0o644, len(body)
                    archive.addfile(item, io.BytesIO(body))
        with path.open('rb') as stream:
            _validate(stream, candidate_dir, candidate_sha256, inventory, inventory_sha256, companions)
        (stage / MANIFEST).write_bytes(f._json(manifest))
    return output / BUNDLE


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-dir', type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--inventory-sha256', required=True)
    for role in sorted(ROLES):
        parser.add_argument('--' + role, type=Path, required=True)
        parser.add_argument('--' + role + '-sha256', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output-dir', type=Path)
    mode.add_argument('--verify-bundle', type=Path)
    parser.add_argument('--policy-source', type=Path)
    parser.add_argument('--policy-license', type=Path)
    args = vars(parser.parse_args(argv))
    companions = {role: {'path': args.pop(role.replace('-', '_')),
                          'sha256': args.pop(role.replace('-', '_') + '_sha256')} for role in sorted(ROLES)}
    output, bundle = args.pop('output_dir'), args.pop('verify_bundle')
    policy, license_body = args.pop('policy_source'), args.pop('policy_license')
    if bundle is None and (policy is None or license_body is None) or bundle is not None and (policy is not None or license_body is not None):
        parser.error('new output requires both policy inputs; verification uses the retained pinned originals')
    try:
        if bundle is not None:
            validate_catalog(bundle, companions=companions, **args)
        else:
            build_catalog(companions=companions, policy_source=policy, policy_license=license_body, output_dir=output, **args)
    except (InstallError, OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, zlib.error, EOFError):
        parser.exit(1, 'Image notice catalogue validation failed; no image was executed or published.\n')
    print('Image ownership/notice catalogue checked; source validation and publication reviews remain separate.')
    return 0
