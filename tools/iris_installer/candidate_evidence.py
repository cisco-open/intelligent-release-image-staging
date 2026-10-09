# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Join sealed local candidate bytes and independently checked source evidence.

This is a build-free, unauthenticated preparation step. Source inventory parity
is not proof of Git provenance, reproducible builds, or full image attribution.
"""

import argparse
import gzip
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import tarfile
import tempfile
import zlib

from . import alpine_sources as alpine, core_python_sources as core_python, debian_sources as debian
from . import image_components
from . import offline_bootstrap, offline_inputs, offline_sources, release_kit as kit
from .device_finalize import _json as canonical
from .packaging_inputs import _publication
from .state import InstallError, regular_bytes


SCHEMA = 'iris-local-candidate-evidence-v1'
ORIGINAL = 'local-candidate.json'
MANIFEST = 'candidate-evidence.json'
COMPANIONS = {'debian': 'iris-debian-sources.tar.gz', 'alpine': 'iris-alpine-sources.tar.gz',
              'core-python': 'iris-core-python-sources.tar.gz', 'runtime': 'iris-runtime-sources.tar.gz',
              'ubuntu': 'iris-ubuntu-sources.tar.gz', 'image-notices': 'iris-image-source-notices.tar.gz'}
MAX_SOURCE = 2 * 1024**3


def fail(message):
    raise InstallError('Candidate evidence: ' + message)


def _helper(filename):
    # Only helper code adjacent to this trusted module; never candidate code.
    base = Path(__file__).resolve().parents[1]
    path = base / 'source/tools' / filename
    if not path.exists():
        path = base / filename
    spec = importlib.util.spec_from_file_location('iris_evidence_' + filename.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _file(path, maximum=kit.MAX_ASSET):
    descriptor, info = kit._open(path, maximum)
    try:
        digest, size = kit._hash(descriptor, maximum)
        if size != info.st_size or kit._identity(info) != kit._identity(os.fstat(descriptor)):
            fail('input changed while being read')
        return {'sha256': digest, 'size': size}
    finally:
        os.close(descriptor)


def _sealed(directory, expected, private, anchor, tag, commit):
    directory = kit._path(directory)
    descriptor = kit._protected_directory(directory)
    try:
        os.mkdir(anchor, 0o700)
        checksum = kit._snapshot(directory / ORIGINAL, anchor / ORIGINAL, kit.MAX_METADATA)
        if checksum != expected:
            fail('local candidate differs from the external selection digest')
        value = kit._json(regular_bytes(anchor / ORIGINAL, kit.MAX_METADATA))
        required = {'format', 'authenticated', 'scope', 'commit', 'tag', 'version', 'profile', 'source_match', 'files'}
        if (not isinstance(value, dict) or not required <= value.keys()
                or value.keys() - required - {'ubuntu_source_coverage', 'aria2_source_binding'}
                or value['format'] != 'iris-local-release-candidate-v1' or value['authenticated'] is not False
                or (value['tag'], value['commit'], value['version']) != (tag, commit, tag[1:])
                or not isinstance(value['profile'], str) or value['profile'] not in kit.PROFILES):
            fail('unsupported or mismatched original candidate identity')
        records = value['files']
        if not isinstance(records, dict) or not 1 <= len(records) <= kit.MAX_ASSETS:
            fail('original candidate inventory is invalid')
        total = 0
        for name, row in records.items():
            kit._name(name)
            kit._keys(row, {'sha256', 'size'})
            kit._sha(row['sha256'])
            if name in {ORIGINAL, MANIFEST} or type(row['size']) is not int or not 0 < row['size'] <= kit.MAX_ASSET:
                fail('original candidate inventory has an invalid entry')
            total += row['size']
        if total > kit.MAX_TOTAL or set(os.listdir(descriptor)) != {*records, ORIGINAL}:
            fail('original candidate is not a bounded closed file set')
        for name, row in sorted(records.items()):
            if (kit._snapshot(directory / name, anchor / name, kit.MAX_ASSET) != row['sha256']
                    or (anchor / name).stat().st_size != row['size']):
                fail('candidate asset differs from its sealed inventory')
        offline_inputs._same_directory(directory, descriptor)
        if set(os.listdir(descriptor)) != {*records, ORIGINAL}:
            fail('candidate file set changed during snapshot')
    finally:
        os.close(descriptor)
    manifest = kit._json(regular_bytes(anchor / 'release-kit.json', kit.MAX_METADATA))
    assets = {asset.role: asset for asset in kit._kit_manifest(manifest, kit._auth(), tag, commit, records)}
    if manifest['profile'] != value['profile']:
        fail('kit profile differs from the original candidate')
    package = 'iris-installer_' + tag[1:] + '+installer.0.g' + commit[:12] + '_amd64.deb'
    required_names = {asset.name for asset in assets.values()} | {'release-kit.json', package,
                     package + '.sha256', package + '.source.json', assets['device-runtime'].name + '.manifest'}
    # Existing source companions may already be sealed by the original builder.
    # Their self-reported validation fields are deliberately not authority.
    optional = {COMPANIONS['ubuntu']} | {name for name in records
                if re.fullmatch(r'aria2c-[A-Za-z0-9._-]+-source\.tar\.gz', name)}
    if not required_names <= records.keys() or records.keys() - required_names - optional:
        fail('candidate contains an unsupported or missing asset')
    if value['profile'] != 'ubuntu-dependencies' and COMPANIONS['ubuntu'] in records:
        fail('Ubuntu sources require the Ubuntu dependency profile')
    return value, assets, private / package


def _source_archive(path, package):
    """Check every retained canonical source byte and mode, plus a closed tar."""
    expected = package['source']
    seen, files, matched, extras, total = set(), set(), set(), {}, 0
    with path.open('rb') as raw, tempfile.TemporaryFile() as plain:
        with gzip.GzipFile(fileobj=raw) as expanded:
            offline_inputs._copy(expanded, plain, MAX_SOURCE)
        length = plain.tell()
        plain.seek(0)
        with tarfile.open(fileobj=plain, mode='r:', tarinfo=kit._BoundedTarInfo) as archive:
            for member in archive:
                name = image_components._name(member.name, directory=member.isdir())
                if (name in seen or len(seen) >= 100000 or not (member.isdir() or member.isfile())
                        or member.size < 0 or member.isdir() and member.size != 0
                        or member.mode not in (0o644, 0o755)
                        or name != 'iris' and not name.startswith('iris/')):
                    fail('unsupported source archive member')
                seen.add(name)
                total += member.size
                if total > MAX_SOURCE:
                    fail('source archive exceeds its expansion limit')
                relative = name.removeprefix('iris/')
                if member.isdir():
                    if relative in expected:
                        fail('source inventory file is a directory in the tar')
                    continue
                files.add(name)
                digest, size = offline_inputs._copy(archive.extractfile(member), None, MAX_SOURCE)
                if relative in expected:
                    original = package['files'][offline_bootstrap.SOURCE + relative]
                    if digest != expected[relative] or size != original['size'] or member.mode != original['mode']:
                        fail('release tar differs from the installer source inventory')
                    matched.add(relative)
                else:
                    if (relative not in {'MANIFEST.txt', 'artifacts/.gitkeep'} or member.mode != 0o644
                            or relative == 'artifacts/.gitkeep' and size != 0):
                        fail('source archive contains an unsupported generated extra file')
                    extras[relative] = {'sha256': digest, 'size': size, 'mode': member.mode}
            if length % 512 or length - archive.offset < 1024:
                fail('source archive is not completely terminated')
            plain.seek(archive.offset)
            while tail := plain.read(kit.CHUNK):
                if tail.strip(b'\0'):
                    fail('source archive has trailing payload')
    if any(str(parent) in files for name in seen for parent in PurePosixPath(name).parents):
        fail('source archive traverses a regular file')
    parents = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != '.'}
    if seen - files - parents:
        fail('source archive contains an unlisted directory')
    if matched != set(expected):
        fail('source archive omits canonical installer files')
    return extras


def _source_agreement(candidate, assets, package_path, work, anchor, descriptor, tag, commit):
    loader = _helper('bootstrap-offline.py')
    try:
        for role, option in (('data', '--fsys-tarfile'), ('control', '--ctrl-tarfile')):
            target = anchor / (role + '.tar')
            loader._command_to_file(['/usr/bin/dpkg-deb', option, str(package_path)], target,
                                    MAX_SOURCE if role == 'data' else kit.MAX_METADATA)
            # dpkg-deb only emits bytes. No maintainer programs are executed.
            loader.extract(target, anchor / role, control=role == 'control')
            with tarfile.open(target, 'r:', tarinfo=loader._TarInfo) as stream:
                for _ in stream:
                    pass
                length = target.stat().st_size
                if length % 512 or length - stream.offset < 1024:
                    fail('installer package tar is not completely terminated')
                stream.fileobj.seek(stream.offset)
                while tail := stream.fileobj.read(kit.CHUNK):
                    if tail.strip(b'\0'):
                        fail('installer package tar has trailing payload')
        offline_inputs._same_directory(work, descriptor)
        package = offline_bootstrap.inspect_package(work / 'data', work / 'control/control', tag, commit)
    except loader.BootstrapError as error:
        fail(str(error))
    sidecar = kit._json(regular_bytes(Path(str(package_path) + '.source.json'), kit.MAX_METADATA))
    if (canonical(sidecar) != canonical({'schema': 1, 'commit': commit, 'files': package['source']})
            or regular_bytes(Path(str(package_path) + '.sha256'), 1024)
            != (candidate['files'][package_path.name]['sha256'] + '  ' + package_path.name + '\n').encode()):
        fail('installer package sidecars differ from the selected source inventory or package bytes')
    extras = _source_archive(package_path.parent / assets['source'].name, package)
    source = work / 'data' / offline_bootstrap.SOURCE
    return source, {'scope': 'retained installer source inventory, package runtime copies, and release tar byte/mode parity',
                    'git_provenance_verified': False, 'commit_label': commit,
                    'source_inventory_sha256': _file(source / 'INSTALLER-SOURCE.json')['sha256'],
                    'canonical_file_count': len(package['source']), 'additional_tar_files': extras}


def _images(candidate, assets, directory, work, anchor, descriptor, commit):
    arguments = {}
    for short, role in (('server', 'server-image'), ('console', 'console-image'), ('neutral', 'device-runtime')):
        arguments[short + '_archive'] = directory / assets[role].name
        arguments[short + '_sha256'] = assets[role].sha256
    path = image_components.inspect_components(**arguments, commit=commit, output_dir=work / 'inventory')
    inventory = kit._json(regular_bytes(path, image_components.MAX_RECEIPT))
    configs = {}
    for role in ('server-image', 'console-image'):
        observed = inventory['images'][role]
        if observed['config_digest'] != assets[role].image_digest:
            fail('observed core image configuration differs from the kit')
        with tarfile.open(directory / assets[role].name, 'r:', tarinfo=kit._BoundedTarInfo) as archive:
            manifest = kit._json(archive.extractfile('manifest.json').read(kit.MAX_METADATA + 1))[0]
            raw = archive.extractfile(manifest['Config']).read(kit.MAX_METADATA + 1)
        if len(raw) > kit.MAX_METADATA or 'sha256:' + hashlib.sha256(raw).hexdigest() != assets[role].image_digest:
            fail('raw core configuration differs from the kit')
        name = 'iris-' + role + '-config.json'
        (anchor / name).write_bytes(raw)
        configs[role] = work / name
    neutral = assets['device-runtime']
    observed = inventory['images']['device-runtime']
    if observed['index_digest'] != neutral.image_digest:
        fail('observed neutral index differs from the kit')
    source_hash = image_components._producer().neutral_provenance(
        directory / (neutral.name + '.manifest'), neutral.sha256, observed)
    if source_hash != neutral.neutral_source_sha256:
        fail('retained neutral source context differs from the kit')
    offline_inputs._same_directory(work, descriptor)
    return path, _file(path)['sha256'], inventory, configs


def _aria_observations(inventory, pins):
    result = []
    images = [('server-image', inventory['images']['server-image'])]
    images.extend(('device-runtime', image) for image in inventory['images']['device-runtime']['platforms'])
    for role, image in images:
        architecture = {'linux/amd64': 'x86_64', 'linux/arm64': 'aarch64'}.get(image['platform'])
        if architecture is None:
            fail('unsupported aria2 image architecture')
        observations = 0
        for layer in image['layers']:
            for row in layer['inventory']['copied_component_files']:
                if row['path'] == 'opt/iris/bin/aria2c':
                    if row.get('sha256') != pins[architecture]:
                        fail('retained image aria2 bytes differ from the selected client pin')
                    result.append({'image': role, 'platform': image['platform'], 'layer': layer['index'],
                                   'diff_id': layer['diff_id'], 'path': row['path'], 'sha256': row['sha256']})
                    observations += 1
        merged = [row for row in image['merged']['copied_component_files'] if row['path'] == 'opt/iris/bin/aria2c']
        if not observations or len(merged) != 1 or merged[0]['sha256'] != pins[architecture]:
            fail('required image aria2 client is unavailable or changed')
    return result


def _validate_runtime(*arguments):
    from .runtime_sources import validate_source_archive
    return validate_source_archive(*arguments)


def _validate_notices(*arguments):
    from .image_source_notices import validate_catalog
    return validate_catalog(*arguments)


def assemble(candidate_dir, candidate_sha256, output_dir, *, tag, commit, aria2_sources,
             debian_sources, alpine_sources, core_python_sources, runtime_sources,
             image_notices, debian_keyring, pip_sdist_sha256, ubuntu_sources=None):
    """Freeze, inspect, and publish once. No image builds, loads or execution."""
    kit._sha(candidate_sha256)
    kit._sha(pip_sdist_sha256)
    kit._auth().validate_tag(tag)
    if not isinstance(commit, str) or not re.fullmatch('[a-f0-9]{40}', commit):
        fail('an exact external commit is required')
    supplied = {'debian': debian_sources, 'alpine': alpine_sources, 'core-python': core_python_sources,
                'runtime': runtime_sources, 'aria2': aria2_sources, 'image-notices': image_notices}
    if ubuntu_sources is not None:
        supplied['ubuntu'] = ubuntu_sources
    work = Path('/tmp') / ('iris-candidate-evidence-' + secrets.token_hex(16))
    with _publication(output_dir) as (stage, output), offline_inputs._new_directory(work, remove=True) as descriptor:
        anchor = Path('/proc/self/fd') / str(descriptor)
        private = work / 'candidate'
        candidate, assets, package = _sealed(candidate_dir, candidate_sha256, private, anchor / 'candidate', tag, commit)
        if ('ubuntu' in supplied) != (candidate['profile'] == 'ubuntu-dependencies'):
            fail('Ubuntu dependency profile requires its source companion; other profiles must omit it')
        snapshots, hashes = {}, {}
        for role, path in supplied.items():
            name = 'input-' + role + '.tar.gz'
            hashes[role] = kit._snapshot(kit._path(path), anchor / name, kit.MAX_ASSET)
            snapshots[role] = work / name
        keyring_hash = kit._snapshot(kit._path(debian_keyring), anchor / 'debian-keyring.gpg', kit.MAX_METADATA)
        offline_inputs._same_directory(work, descriptor)
        source, agreement = _source_agreement(candidate, assets, package, work, anchor, descriptor, tag, commit)
        inventory_path, inventory_hash, inventory, configs = _images(
            candidate, assets, private, work, anchor, descriptor, commit)
        aria, aria_proof = _helper('build-release-candidate.py')._prepare_aria_sources(anchor, source, snapshots['aria2'])
        aria = work / aria.name
        if any(re.fullmatch(r'aria2c-[A-Za-z0-9._-]+-source\.tar\.gz', name)
               and name != aria_proof['asset'] for name in candidate['files']):
            fail('original candidate contains an unselected aria2 source companion')
        aria_proof['observed_image_clients'] = _aria_observations(inventory, aria_proof['binary_sha256'])
        aria_proof['scope'] = 'pinned aria2 clients and exact retained image embeddings only'
        validated = {}
        # Always default freshness; archival-integrity verification is not a
        # candidate preparation policy or an input-controlled exception.
        validated['debian'] = debian.validate_source_archive(
            snapshots['debian'], inventory_path, inventory_hash, keyring=work / 'debian-keyring.gpg')
        validated['alpine'] = alpine.validate_source_archive(
            snapshots['alpine'], inventory_path, inventory_hash)
        validated['core-python'] = core_python.validate_source_archive(
            snapshots['core-python'], inventory_path, inventory_hash, configs, pip_sdist_sha256=pip_sdist_sha256)
        validated['runtime'] = _validate_runtime(snapshots['runtime'], private, candidate_sha256,
            inventory_path, inventory_hash, snapshots['alpine'], hashes['alpine'])
        if 'ubuntu' in snapshots:
            inner = assets['ubuntu-dependencies'].dependency_manifest_sha256
            closure = work / 'ubuntu-closure'
            offline_inputs.inspect_dependency_archive(private / assets['ubuntu-dependencies'].name,
                                                       expected_manifest_sha256=inner, destination=closure)
            validated['ubuntu'] = offline_sources.validate_source_archive(snapshots['ubuntu'], closure, inner)
        references = {role: {'path': snapshots[role], 'sha256': hashes[role]}
                      for role in ('debian', 'alpine', 'core-python', 'runtime', 'aria2')}
        validated['image-notices'] = _validate_notices(snapshots['image-notices'], private, candidate_sha256,
                                                      inventory_path, inventory_hash, references)
        offline_inputs._same_directory(work, descriptor)
        proofs = {'aria2': aria_proof}
        products = {name: private / name for name in [*candidate['files'], ORIGINAL]}
        expected_products = {name: row['sha256'] for name, row in candidate['files'].items()}
        expected_products[ORIGINAL] = candidate_sha256
        additions = {'image-components.json': inventory_path, aria_proof['asset']: aria,
                     **{path.name: path for path in configs.values()}}
        expected_additions = {'image-components.json': inventory_hash, aria_proof['asset']: aria_proof['archive_sha256'],
                              **{path.name: inventory['images'][role]['config_digest'].removeprefix('sha256:')
                                 for role, path in configs.items()}}
        for role, manifest in validated.items():
            name = COMPANIONS[role]
            additions[name] = snapshots[role]
            expected_additions[name] = hashes[role]
            proofs[role] = {'asset': name, 'archive_sha256': hashes[role],
                            'validated_manifest_canonical_sha256': hashlib.sha256(canonical(manifest)).hexdigest(),
                            'scope': manifest.get('scope', 'exact Ubuntu binary/source and carried notice mapping')}
        for name, path in additions.items():
            if name in products and (expected_products[name] != expected_additions[name]
                                     or _file(products[name]) != _file(path)):
                fail('new companion would replace different original candidate bytes')
            products[name] = path
            expected_products[name] = expected_additions[name]
        inventory_out, total_out = {}, 0
        for name, path in sorted(products.items()):
            record = _file(path)
            if record['sha256'] != expected_products[name]:
                fail('validated product changed after independent inspection')
            total_out += record['size']
            if total_out > kit.MAX_TOTAL or len(products) > kit.MAX_ASSETS:
                fail('augmented candidate exceeds the release inventory limits')
            if kit._snapshot(path, stage / name, kit.MAX_ASSET) != record['sha256']:
                fail('validated product changed before publication')
            inventory_out[name] = record
        receipt = {'format': SCHEMA, 'authenticated': False, 'source_coverage_complete': False,
                   'rebuild_verified': False, 'original_candidate_sha256': candidate_sha256,
                   'tag': tag, 'commit': commit, 'profile': candidate['profile'],
                   'image_inventory_sha256': inventory_hash, 'source_agreement': agreement,
                   'neutral_source_sha256': assets['device-runtime'].neutral_source_sha256,
                   'external_pins': {'debian_keyring_sha256': keyring_hash, 'pip_sdist_sha256': pip_sdist_sha256},
                   'companions': proofs, 'files': inventory_out,
                   'mechanical_evidence': 'independently validated source companions and reconstructed image ownership/notice catalog',
                   'remaining_gates': ['human source-sufficiency and redistribution review',
                                       'release authentication', 'topology qualification', 'owner publication approval']}
        (stage / MANIFEST).write_bytes(canonical(receipt))
        offline_inputs._same_directory(work, descriptor)
    return output / MANIFEST


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-dir', type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True, help='External SHA256 of original local-candidate.json')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    for name in ('aria2', 'debian', 'alpine', 'core-python', 'runtime', 'ubuntu'):
        parser.add_argument('--' + name + '-sources', type=Path, required=name != 'ubuntu')
    parser.add_argument('--image-notices', type=Path, required=True,
                        help='Ownership and original-notice catalog bound to the five image source companions')
    parser.add_argument('--debian-keyring', type=Path, required=True, help='Independently trusted archive keyring')
    parser.add_argument('--pip-sdist-sha256', required=True, help='Explicit external source pin')
    args = parser.parse_args(argv)
    try:
        result = assemble(**vars(args))
    except (InstallError, OSError, ValueError, tarfile.TarError, EOFError, zlib.error):
        parser.exit(1, 'Candidate evidence validation failed; no candidate was rebuilt or replaced.\n')
    print('Unauthenticated candidate evidence; source-sufficiency and redistribution review remain pending: ' + str(result))
    return 0
