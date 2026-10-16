#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Acquire a complete official Ubuntu dependency closure in isolated apt state.

Run on Ubuntu 24.04 amd64. This downloads into private directories only and never
installs packages or changes the host's apt configuration. The resulting archive
is an unauthenticated candidate until the release workflow attests it.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from iris_installer import offline_dependencies as dependencies
from iris_installer.state import InstallError
from iris_installer.ubuntu import check_platform


def build(output, *, keyring=dependencies.KEYRING):
    check_platform()
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise InstallError('Refusing to replace an existing dependency archive')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='iris-dependencies-build-') as temporary:
        work = Path(temporary)
        trusted = work / 'ubuntu-archive-keyring.gpg'
        dependencies._trusted_snapshot(Path(keyring), trusted)
        payload = work / 'payload'
        payload.mkdir(mode=0o700)
        config = dependencies._apt_workspace(work / 'apt', payload, trusted, online=True)
        dependencies._run(['/usr/bin/apt-get', 'update'], config=config)
        roots = sorted(dependencies.ROOT_PACKAGES)
        report = dependencies._run(['/usr/bin/apt-get', '--simulate', 'install', '--no-remove',
                                    '--no-install-recommends', '--no-install-suggests', *roots], config=config)
        solution = dependencies._simulation(report)
        versions = {package['name']: package['version'] for package in solution}
        if not dependencies.ROOT_PACKAGES <= set(versions):
            raise InstallError('Apt did not resolve all required offline dependency roots')
        dependencies._run(['/usr/bin/apt-get', '--yes', '--download-only', 'install', '--no-remove',
                           '--no-install-recommends', '--no-install-suggests',
                           *(name + '=' + versions[name] for name in roots)], config=config, timeout=3600)
        targets = dependencies._run(['/usr/bin/apt-get', 'indextargets', '--format',
                                     '$(RELEASE)|$(COMPONENT)|$(ARCHITECTURE)|$(FILENAME)|$(IDENTIFIER)'], config=config)
        for line in targets.splitlines():
            suite, component, architecture, filename, identifier = line.split('|')
            if identifier != 'Packages' or component not in dependencies.COMPONENTS or architecture != 'amd64':
                continue
            matches = [repository for repository, expected_suite, _ in dependencies.REPOSITORIES if expected_suite == suite]
            if len(matches) != 1:
                raise InstallError('Apt selected an unexpected Ubuntu package source')
            destination = payload / 'repositories' / matches[0] / 'dists' / suite
            index = destination / component / 'binary-amd64' / 'Packages'
            index.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(filename, index)
            prefix = Path(filename).name.split('_dists_' + suite + '_', 1)[0]
            release = Path(filename).parent / (prefix + '_dists_' + suite + '_InRelease')
            if not (destination / 'InRelease').exists():
                shutil.copyfile(release, destination / 'InRelease')
        indexes = dependencies._release_indexes(payload, trusted)
        candidates = {}
        for (repository, suite, component), path in indexes.items():
            with path.open(encoding='utf-8') as stream:
                for entry in dependencies._paragraphs(stream):
                    name = entry.get('Package')
                    if name not in versions or entry.get('Version') != versions[name] or entry.get('Architecture') not in ('amd64', 'all'):
                        continue
                    candidates.setdefault(name, []).append((repository, suite, component, entry))
        archives = {}
        for path in (config.parent / 'archives').glob('*.deb'):
            identity = dependencies._run(['/usr/bin/dpkg-deb', '--show', '--showformat=${Package}\t${Version}\t${Architecture}', str(path)]).split('\t')
            if len(identity) != 3 or identity[0] in archives or versions.get(identity[0]) != identity[1]:
                raise InstallError('Downloaded package identity differs from apt solution')
            archives[identity[0]] = (path, identity)
        if set(archives) != set(versions):
            raise InstallError('Apt download did not produce the complete dependency closure')
        packages = []
        for name in sorted(archives):
            path, identity = archives[name]
            digest = dependencies._digest(path)
            matches = [candidate for candidate in candidates.get(name, ())
                       if candidate[3].get('SHA256') == digest and candidate[3].get('Size') == str(path.stat().st_size)
                       and candidate[3]['Architecture'] == identity[2]]
            if not matches:
                raise InstallError('Downloaded package is absent from signed Ubuntu indexes')
            repository, suite, component, entry = matches[0]
            filename = dependencies._relative(entry['Filename'])
            destination = payload / 'repositories' / repository / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            packages.append({'name': name, 'version': identity[1], 'architecture': identity[2],
                             'repository': repository, 'suite': suite, 'component': component, 'filename': filename})
        files = {path.relative_to(payload).as_posix(): {'sha256': dependencies._digest(path), 'size': path.stat().st_size}
                 for path in sorted(payload.rglob('*')) if path.is_file()}
        manifest = {'schema': dependencies.SCHEMA, 'host': {'os': 'ubuntu', 'version': '24.04', 'architecture': 'amd64'},
                    'docker_provider': 'docker.io', 'roots': {name: versions[name] for name in roots},
                    'packages': packages, 'files': files}
        data = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
        (payload / dependencies.MANIFEST).write_bytes(data)
        manifest_digest = hashlib.sha256(data).hexdigest()
        # The producer exercises exactly the consumer's signature, inventory,
        # deb identity and empty-status resolver checks before publishing bytes.
        with dependencies.validate_closure(payload, manifest_digest, keyring=keyring):
            pass
        candidate = work / 'ubuntu-dependencies.tar.gz'
        with tarfile.open(candidate, 'w:gz') as archive:
            for path in sorted(payload.rglob('*')):
                if path.is_file():
                    info = archive.gettarinfo(str(path), arcname=path.relative_to(payload).as_posix())
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    info.mode = 0o644
                    with path.open('rb') as stream:
                        archive.addfile(info, stream)
        # Keep verification beneath protected /tmp ancestry; publish on the
        # destination filesystem so an exclusive hard link also works across mounts.
        with tempfile.TemporaryDirectory(prefix='.iris-dependencies-publish-', dir=output.parent) as publish:
            staged = Path(publish) / output.name
            shutil.copyfile(candidate, staged)
            os.link(staged, output)
        output.chmod(0o644)
        return {'archive': str(output), 'sha256': dependencies._digest(output),
                'manifest_sha256': manifest_digest, 'packages': len(packages), 'authenticated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='Exclusive output .tar.gz path')
    arguments = parser.parse_args()
    try:
        print(json.dumps(build(arguments.out), sort_keys=True))
    except (InstallError, OSError, ValueError) as error:
        print('Offline dependency producer: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
