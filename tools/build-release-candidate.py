#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Assemble a local, unauthenticated prepublication candidate from one commit.

Docker builds may acquire their declared build dependencies. Installation is
not performed. No Git tag, attestation or external publication is created;
source/notices and redistribution approval remain separate release gates.
"""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time

from iris_installer import device_finalize as f, release_kit as kit
from iris_installer.offline_inputs import _new_directory, _same_directory
from iris_installer.packaging_inputs import _publication
from iris_installer.state import InstallError, regular_bytes


MAX_TREE = 16 * 1024**2
GIT_SECONDS = 120
MAX_SOURCE_FILE = 512 * 1024**2
BUILDERS = ('build-release-candidate.py', 'build-installer-package.py',
            'make-release.sh', 'build-device-image.sh', 'build-guest-inputs.py',
            'build-packaging-inputs.py', 'build-release-kit.py')
NAMES = {'server-image': 'iris-server-amd64.docker.tar',
         'console-image': 'iris-console-amd64.docker.tar',
         'device-runtime': 'iris-device-neutral.oci.tar',
         'guest-inputs': 'iris-guest-inputs.tar.gz',
         'packaging-tools': 'iris-packaging-tools.tar.gz', 'source': 'iris.tgz'}
UBUNTU_SOURCES_NAME = 'iris-ubuntu-sources.tar.gz'


def fail(message):
    raise InstallError('Local release candidate: ' + message)


def _environment(work, builder):
    # Docker's explicitly selected host/context may need its normal connection
    # configuration. None of that configuration enters the source/build context.
    allowed = ('PATH', 'HOME', 'DOCKER_CONFIG', 'DOCKER_CONTEXT', 'DOCKER_HOST',
               'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'SSH_AUTH_SOCK')
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(LC_ALL='C', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
        GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='',
        GIT_TERMINAL_PROMPT='0', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
        TMPDIR=str(work / 'tmp'))
    if builder is not None:
        environment['BUILDX_BUILDER'] = builder
    return environment


def _git(repo, arguments, environment):
    command = ['git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
               '-c', 'gc.auto=0', '-C', str(repo), *arguments]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=environment, umask=0o022, start_new_session=True) as process:
        try:
            deadline, result = time.monotonic() + GIT_SECONDS, bytearray()
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                while ready.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        fail('local Git operation exceeded its deadline')
                    for key, _ in ready.select(remaining):
                        data = os.read(key.fileobj.fileno(), min(65536, MAX_TREE + 1 - len(result)))
                        if not data:
                            ready.unregister(key.fileobj)
                        result.extend(data)
                        if len(result) > MAX_TREE:
                            fail('local Git metadata exceeds its limit')
            if process.wait(timeout=max(0.001, deadline - time.monotonic())):
                fail('exact local committed source is unavailable')
            return bytes(result)
        finally:
            # A file-transport upload-pack is part of this owned process group.
            # Stop it too if a child retains stdout after its parent exits.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _tree(repo, commit, environment):
    records = {}
    for row in _git(repo, ['ls-tree', '-r', '-z', '--full-tree', commit], environment).split(b'\0'):
        if not row:
            continue
        try:
            metadata, name = row.split(b'\t', 1)
            mode, kind, blob = metadata.decode('ascii').split()
            name = name.decode('utf-8')
        except (ValueError, UnicodeError):
            fail('committed source tree is invalid')
        f._name(name)
        if (mode not in ('100644', '100755') or kind != 'blob'
                or not re.fullmatch('[0-9a-f]{40}', blob) or name in records
                or len(records) >= 100000):
            fail('committed source must contain only bounded regular files')
        records[name] = {'mode': int(mode, 8) & 0o777, 'blob': blob}
    if not records or not {'VERSION', *(f'tools/{name}' for name in BUILDERS)} <= records.keys():
        fail('commit omits the candidate helper or a required builder')
    return records


def _file(path, *, maximum=MAX_SOURCE_FILE):
    path = f._path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 <= before.st_size <= maximum):
            fail('expected a bounded regular file without aliases')
        blob = hashlib.sha1(('blob ' + str(before.st_size) + '\0').encode(), usedforsecurity=False)
        digest, size = hashlib.sha256(), 0
        while data := os.read(descriptor, kit.CHUNK):
            size += len(data)
            if size > maximum:
                fail('source file grew during verification')
            blob.update(data)
            digest.update(data)
        if kit._identity(before) != kit._identity(os.fstat(descriptor)) or size != before.st_size:
            fail('source file changed during verification')
        f._unchanged(path, before)
        return {'sha256': digest.hexdigest(), 'size': size,
                'mode': stat.S_IMODE(before.st_mode), 'blob': blob.hexdigest()}
    finally:
        os.close(descriptor)


def _verify_checkout(source, tree):
    for name, expected in tree.items():
        actual = _file(source / name)
        if actual['blob'] != expected['blob'] or actual['mode'] != expected['mode']:
            fail('checkout bytes or modes differ from the selected commit')


def _checkout(repository, source, commit, environment):
    if _git(repository, ['rev-parse', '--verify', commit + '^{commit}'], environment).strip().decode() != commit:
        fail('source must identify the exact requested local commit')
    source.mkdir(mode=0o700)
    _git(source, ['init', '--template='], environment)
    # A new repository has no owner hooks, filter configuration, replacement
    # refs or ignored files. Only the explicit local commit is transferred.
    # Only this client may use file transport. Source upload-pack must deny
    # even file-backed promisor acquisition: older Git ignores NO_LAZY_FETCH.
    _git(source, ['fetch', '--no-tags', '--depth=1', '--no-write-fetch-head',
                  '--upload-pack=env GIT_ALLOW_PROTOCOL= GIT_NO_LAZY_FETCH=1 git-upload-pack',
                  str(repository), commit], dict(environment, GIT_ALLOW_PROTOCOL='file'))
    tree = _tree(source, commit, environment)
    _git(source, ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
                  'checkout', '--detach', commit], environment)
    _verify_checkout(source, tree)  # Before executing any committed builder.
    epoch = _git(source, ['show', '-s', '--format=%ct', commit], environment).strip().decode('ascii')
    if not epoch.isdigit():
        fail('commit timestamp is invalid')
    return tree, epoch


def _source_proof(source, tree, canonical, package, archive, commit, version):
    inventory_path = canonical / 'INSTALLER-SOURCE.json'
    inventory = kit._json(regular_bytes(inventory_path, kit.MAX_METADATA))
    sidecar = kit._json(regular_bytes(package.with_suffix('.deb.source.json'), kit.MAX_METADATA))
    if (not isinstance(inventory, dict) or not inventory or len(inventory) > 100000
            or sidecar != {'schema': 1, 'commit': commit, 'files': inventory}):
        fail('installer source inventory or commit differs')
    checksum = _file(package, maximum=kit.MAX_ASSET)['sha256'] + '  ' + package.name + '\n'
    if regular_bytes(package.with_suffix('.deb.sha256'), 1024) != checksum.encode('ascii'):
        fail('installer package checksum sidecar differs')
    actual_names = {str(path.relative_to(canonical)) for path in canonical.rglob('*') if not path.is_dir()}
    if actual_names != set(inventory) | {'INSTALLER-SOURCE.json'}:
        fail('canonical installed source differs from its inventory')
    for name, digest in inventory.items():
        f._name(name)
        kit._sha(digest)
        if name not in tree:
            fail('installer contains source outside the selected commit')
        actual = _file(canonical / name)
        if (actual['sha256'] != digest or actual['blob'] != tree[name]['blob']
                or actual['mode'] != tree[name]['mode']):
            fail('canonical installed source differs from committed bytes or modes')
    if regular_bytes(canonical / 'VERSION') != regular_bytes(source / 'VERSION'):
        fail('installer version differs from committed VERSION')
    matched, seen, total = set(), set(), 0
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream:
            path = PurePosixPath(member.name)
            if (member.name.rstrip('/') != str(path) or path.is_absolute() or '..' in path.parts
                    or not path.parts or path.parts[0] != 'iris' or member.name in seen
                    or not (member.isdir() or member.isfile()) or member.size < 0
                    or len(seen) >= 100000):
                fail('source archive has unsupported members')
            seen.add(member.name)
            total += member.size
            if total > kit.MAX_ASSET:
                fail('source archive exceeds its size limit')
            name = '/'.join(path.parts[1:])
            if name in inventory:
                if not member.isfile() or member.mode != tree[name]['mode']:
                    fail('release source differs from canonical installed source')
                digest, size = f._copy(stream.extractfile(member), None, MAX_SOURCE_FILE)
                if digest != inventory[name] or size != member.size:
                    fail('release source differs from canonical installed source')
                matched.add(name)
    if matched != set(inventory):
        fail('release source omits installer source files')
    return {'commit': commit, 'version': version, 'file_count': len(inventory),
            'installer_source_sha256': _file(inventory_path)['sha256'],
            'canonical_source_matches': True}


def _run(command, *, environment, cwd):
    subprocess.run([str(value) for value in command], env=environment, cwd=cwd, check=True)


def _prepare_ubuntu_inputs(work, ubuntu_dependencies, ubuntu_sources):
    """Snapshot and independently prove optional source coverage before builders."""
    if ubuntu_sources is not None and ubuntu_dependencies is None:
        fail('--ubuntu-sources requires --ubuntu-dependencies')
    if ubuntu_dependencies is None:
        return None, None, None
    from iris_installer.offline_inputs import inspect_dependency_archive
    from iris_installer.offline_sources import validate_source_archive
    closure = work / 'ubuntu-dependencies.tar.gz'
    dependency_digest = kit._snapshot(f._path(ubuntu_dependencies), closure, kit.MAX_ASSET)
    companion = None
    if ubuntu_sources is not None:
        companion = work / 'ubuntu-sources.tar.gz'
        companion_digest = kit._snapshot(f._path(ubuntu_sources), companion, kit.MAX_ASSET)
    if companion is None:
        inspect_dependency_archive(closure)
        return closure, None, None
    payload = work / 'ubuntu-dependency-payload'
    inspected = inspect_dependency_archive(closure, destination=payload)
    digest = inspected['manifest_sha256']
    verified = validate_source_archive(companion, payload, digest)
    proof = {'format': 'iris-local-ubuntu-source-coverage-v1',
             'binary_manifest_sha256': digest, 'dependency_archive_sha256': dependency_digest,
             'companion_archive_sha256': companion_digest, 'asset': UBUNTU_SOURCES_NAME,
             'binaries': len(verified['binaries']), 'sources': len(verified['sources'])}
    return closure, companion, proof


def assemble(repository, output_dir, *, commit, tag, appmgr_repository,
             ubuntu_dependencies=None, ubuntu_sources=None, builder=None, runner=None):
    if not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{40}', commit):
        fail('a full lowercase commit SHA is required')
    kit._auth().validate_tag(tag)
    if builder is not None and not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', builder):
        fail('builder name is invalid')
    if ubuntu_sources is not None and ubuntu_dependencies is None:
        fail('--ubuntu-sources requires --ubuntu-dependencies')
    repository, appmgr_repository = f._path(repository), f._path(appmgr_repository)
    runner = runner or _run
    # All commands operate in this independently owned workspace, not the input
    # checkout or its existing release directory. Cleanup follows held FDs.
    work = Path('/tmp') / ('iris-candidate-' + secrets.token_hex(16))
    with _publication(output_dir) as (stage, output), _new_directory(work, remove=True) as descriptor:
        (work / 'tmp').mkdir(mode=0o700)
        environment = _environment(work, builder)
        source = work / 'source'
        tree, epoch = _checkout(repository, source, commit, environment)
        environment['SOURCE_DATE_EPOCH'] = epoch
        version = regular_bytes(source / 'VERSION', 128).decode('ascii').strip()
        if tag != 'v' + version:
            fail('tag does not match the selected committed VERSION')
        products, assets = work / 'products', work / 'assets'
        products.mkdir(mode=0o700)
        assets.mkdir(mode=0o700)

        def run(arguments):
            _same_directory(work, descriptor)
            runner(arguments, environment=environment, cwd=source)
            _same_directory(work, descriptor)

        def python(name, *arguments):
            run([sys.executable, '-B', source / 'tools' / name, *arguments])

        # Fail early on unavailable pinned tooling/closure and source parity,
        # before spending time on image builds. Neither producer runs ioxclient.
        closure, companion, ubuntu_proof = _prepare_ubuntu_inputs(work, ubuntu_dependencies, ubuntu_sources)
        _same_directory(work, descriptor)
        python('build-packaging-inputs.py', '--appmgr-repository', appmgr_repository,
               '--output-dir', work / 'packaging')
        python('build-installer-package.py', '--repo', source, '--out', products)
        package = products / ('iris-installer_' + version + '+installer.0.g' + commit[:12] + '_amd64.deb')
        run(['dpkg-deb', '--extract', package, work / 'installed'])
        canonical = work / 'installed/usr/lib/iris-installer/source'
        run(['bash', source / 'tools/make-release.sh'])
        proof = _source_proof(source, tree, canonical, package, source / 'release/iris.tgz', commit, version)
        python('build-guest-inputs.py', '--source-dir', canonical,
               '--source-manifest', canonical / 'INSTALLER-SOURCE.json', '--output-dir', work / 'guest')
        _verify_checkout(source, tree)
        for role, dockerfile in (('server-image', 'Dockerfile'), ('console-image', 'Dockerfile.console')):
            command = ['docker', 'buildx', 'build', '--platform', 'linux/amd64', '--pull',
                       '--provenance=false', '--sbom=false',
                       '--label', 'org.opencontainers.image.revision=' + commit,
                       '--label', 'org.opencontainers.image.version=' + version,
                       '--build-arg', 'IRIS_VERSION=' + version,
                       '--output', 'type=docker,dest=' + str(products / NAMES[role]),
                       '--file', source / 'server' / dockerfile]
            if builder:
                command.extend(['--builder', builder])
            run([*command, source])
        (work / 'device-context').mkdir(mode=0o700)
        neutral = products / NAMES['device-runtime']
        run(['bash', source / 'tools/build-device-image.sh', '--context', work / 'device-context',
             '--output', neutral, '--neutral-trust'])
        inputs = {**{role: products / NAMES[role] for role in ('server-image', 'console-image', 'device-runtime')},
                  'source': source / 'release/iris.tgz', 'guest-inputs': work / 'guest' / NAMES['guest-inputs'],
                  'packaging-tools': work / 'packaging' / NAMES['packaging-tools']}
        arguments = ['--tag', tag, '--commit', commit, '--out', assets,
                     '--device-runtime-receipt', Path(str(neutral) + '.manifest')]
        for role, path in sorted(inputs.items()):
            arguments.extend(['--' + role, path])
        if closure is not None:
            arguments.extend(['--ubuntu-dependencies', closure])
        python('build-release-kit.py', *arguments)
        _verify_checkout(source, tree)
        # Include package evidence and the neutral builder's exact receipt.
        for path in (package, package.with_suffix('.deb.sha256'), package.with_suffix('.deb.source.json'),
                     Path(str(neutral) + '.manifest')):
            kit._snapshot(path, assets / path.name, kit.MAX_ASSET)
        expected_names = {*NAMES.values(), 'release-kit.json', package.name, package.name + '.sha256',
                          package.name + '.source.json', neutral.name + '.manifest'}
        if closure is not None:
            expected_names.add('iris-ubuntu-dependencies.tar.gz')
        if companion is not None:
            if kit._snapshot(companion, assets / UBUNTU_SOURCES_NAME, kit.MAX_ASSET) != ubuntu_proof['companion_archive_sha256']:
                fail('source companion changed after independent coverage validation')
            expected_names.add(UBUNTU_SOURCES_NAME)
        if {path.name for path in assets.iterdir()} != expected_names:
            fail('builder produced an unexpected candidate asset set')
        profile = 'ubuntu-dependencies' if closure is not None else 'prepared-host'
        manifest = kit._json(regular_bytes(assets / 'release-kit.json', kit.MAX_METADATA))
        if (not isinstance(manifest, dict)
                or (manifest.get('commit'), manifest.get('tag'), manifest.get('profile')) != (commit, tag, profile)):
            fail('release kit identity differs from the candidate')
        inventory = {}
        for name in sorted(expected_names):
            record = _file(assets / name, maximum=kit.MAX_ASSET)
            inventory[name] = {key: record[key] for key in ('sha256', 'size')}
            expected = ({UBUNTU_SOURCES_NAME: ubuntu_proof['companion_archive_sha256'],
                         'iris-ubuntu-dependencies.tar.gz': ubuntu_proof['dependency_archive_sha256']}
                        if ubuntu_proof is not None else {})
            if name in expected and record['sha256'] != expected[name]:
                fail('Ubuntu candidate bytes changed after independent source validation')
            if kit._snapshot(assets / name, stage / name, kit.MAX_ASSET) != record['sha256']:
                fail('candidate changed before publication')
        receipt = {'format': 'iris-local-release-candidate-v1', 'authenticated': False,
                   'scope': 'local candidate only; source/notices and redistribution gates remain separate',
                   'commit': commit, 'tag': tag, 'version': version, 'profile': profile,
                   'source_match': proof, 'files': inventory}
        if ubuntu_proof is not None:
            receipt['ubuntu_source_coverage'] = ubuntu_proof
        (stage / 'local-candidate.json').write_bytes(f._json(receipt))
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--commit', required=True, help='Full local committed source SHA; never a branch name')
    parser.add_argument('--tag', required=True, help='Candidate label matching VERSION; no Git tag is created')
    parser.add_argument('--appmgr-repository', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True, help='New private candidate directory')
    parser.add_argument('--ubuntu-dependencies', type=Path, help='Optional already-produced Ubuntu closure')
    parser.add_argument('--ubuntu-sources', type=Path,
                        help='Optional source/notices companion; requires --ubuntu-dependencies')
    parser.add_argument('--builder', help='Existing buildx builder supporting amd64 and arm64')
    args = parser.parse_args(argv)
    previous_umask = os.umask(0o022)
    try:
        result = assemble(args.repo, args.output_dir, commit=args.commit, tag=args.tag,
                          appmgr_repository=args.appmgr_repository,
                          ubuntu_dependencies=args.ubuntu_dependencies,
                          ubuntu_sources=args.ubuntu_sources, builder=args.builder)
    except (InstallError, OSError, ValueError, UnicodeError, tarfile.TarError, EOFError, subprocess.SubprocessError) as exc:
        parser.exit(1, 'Local candidate preparation failed: ' + str(exc) + '\n')
    finally:
        os.umask(previous_umask)
    print('Prepared local, unauthenticated candidate: ' + str(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
