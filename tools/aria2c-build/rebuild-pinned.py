#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Rebuild the matching aria2 source using a retained, checksum-locked APK cache."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent if (HERE.parent / 'inputs.json').is_file() else HERE.parent / 'aria2c-source'
ARCHES = {'x86_64': 'linux/amd64', 'aarch64': 'linux/arm64'}


def load_helper(name):
    spec = importlib.util.spec_from_file_location('aria2_' + name, SOURCE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def safe_directory(path):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError('Cache path must not traverse symbolic links')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('Cache must be caller-owned and not writable by other users')
    return path


def check_file(path, checksum, size=None):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError('Linked input rejected: ' + path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or (size is not None and info.st_size != size):
            raise ValueError('Input type or size mismatch: ' + path.name)
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != checksum:
        raise ValueError('Input checksum mismatch: ' + path.name)
    return path


def lock_data():
    lock = json.loads((HERE / 'apk-lock.json').read_text())
    if lock.get('schema') != 1 or set(lock.get('packages', {})) != set(ARCHES):
        raise ValueError('Unsupported APK lock')
    if not re.fullmatch(r'alpine:[0-9.]+@sha256:[0-9a-f]{64}', lock.get('base_image', '')):
        raise ValueError('Build base must be digest-pinned')
    if not lock.get('mirrors') or any(not url.startswith('https://') or not url.endswith('/') for url in lock['mirrors']):
        raise ValueError('Package mirrors must use HTTPS')
    for packages in lock['packages'].values():
        if not isinstance(packages, dict) or not 1 <= len(packages) <= 256:
            raise ValueError('Invalid APK set')
        for name, record in packages.items():
            if (not re.fullmatch(r'[a-z0-9][a-z0-9+_.-]*-[0-9][A-Za-z0-9._]*-r[0-9]+\.apk', name)
                    or not re.fullmatch(r'[0-9a-f]{64}', record.get('sha256', ''))
                    or type(record.get('bytes')) is not int or not 0 < record['bytes'] <= 256 * 1024 * 1024):
                raise ValueError('Invalid APK identity')
    return lock


def cached_package(cache, architecture, name, record, mirrors, *, offline=False):
    directory = safe_directory(cache / architecture)
    destination = directory / name
    if destination.exists() or destination.is_symlink():
        return check_file(destination, record['sha256'], record['bytes'])
    if offline:
        raise ValueError('Required cached package is missing: ' + architecture + '/' + name)
    for mirror in mirrors:
        url = mirror + architecture + '/' + name
        fd, temporary_name = tempfile.mkstemp(prefix='.apk-download-', dir=directory)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, 'wb') as output:
                with urllib.request.urlopen(url, timeout=30) as response:
                    if not response.geturl().startswith('https://'):
                        raise ValueError('Package redirect must keep HTTPS')
                    length = 0
                    while chunk := response.read(1024 * 1024):
                        length += len(chunk)
                        if length > record['bytes']:
                            raise ValueError('Downloaded package exceeds pinned size')
                        output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            check_file(temporary, record['sha256'], record['bytes'])
            try:
                os.link(temporary, destination)
            except FileExistsError:
                # Another builder may have filled the cache. Never replace it.
                check_file(destination, record['sha256'], record['bytes'])
            return destination
        except (urllib.error.URLError, TimeoutError):
            continue
        finally:
            temporary.unlink(missing_ok=True)
    raise ValueError('Pinned package unavailable; retain existing caches: ' + architecture + '/' + name)


def offline_recipe(original, base):
    """Change acquisition only; retain the verified source and compiler commands."""
    if 'FROM ' + base + ' AS toolchain\n' not in original:
        raise ValueError('Source recipe and APK lock use different base images')
    pattern = r'^RUN apk add --no-cache \\\n(?:.*\\\n)*[^\n]*\n'
    replacement = (
        'COPY apk-cache/ /iris-build-apks/\n'
        'RUN cd /iris-build-apks && sha256sum -c SHA256SUMS && apk verify *.apk && '
        'apk --no-network --no-cache --repositories-file /dev/null add /iris-build-apks/*.apk && '
        'rm -r /iris-build-apks\n')
    result, count = re.subn(pattern, lambda match: replacement, original, flags=re.MULTILINE)
    if count != 1:
        raise ValueError('Expected exactly one pinned toolchain installation block')
    return result


def source_tree(archive_path, destination):
    lines = [line.split() for line in (SOURCE / 'source.sha256').read_text().splitlines()
             if line and not line.startswith('#')]
    if len(lines) != 1:
        raise ValueError('Expected one source pin')
    checksum, _filename = lines[0]
    archive_path = Path(archive_path).absolute()
    if archive_path.resolve() != archive_path:
        raise ValueError('Linked source archive rejected')
    # Extract the exact private snapshot whose whole-file hash was checked.
    # Never reopen the caller's archive after authenticating it.
    snapshot = destination.parent / 'checked-source.tar.gz'
    fd = os.open(archive_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source, snapshot.open('xb') as output:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 512 * 1024 * 1024:
            raise ValueError('Invalid source archive type or size')
        remaining = info.st_size
        while chunk := source.read(min(1024 * 1024, remaining + 1)):
            remaining -= len(chunk)
            if remaining < 0:
                raise ValueError('Source archive grew while copying')
            output.write(chunk)
    check_file(snapshot, checksum)
    bundle = load_helper('build-source-bundle')
    with tarfile.open(snapshot, 'r:gz') as archive:
        bundle.safe_extract(archive, destination)
    entries = list(destination.iterdir())
    if len(entries) != 1 or not entries[0].is_dir():
        raise ValueError('Unexpected source archive layout')
    load_helper('rebuild').verify(entries[0])
    return entries[0]


def source_directory(directory, destination):
    """Snapshot a complete extracted source bundle without following links."""
    directory = Path(directory).absolute()
    if directory.resolve() != directory:
        raise ValueError('Linked source directory rejected')
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    total = count = 0

    def copy_tree(fd, target, depth=0):
        nonlocal total, count
        if depth > 64:
            raise ValueError('Extracted source exceeds directory depth limit')
        target.mkdir()
        with os.scandir(fd) as entries:
            names = []
            for entry in entries:
                count += 1
                if count > 20000:
                    raise ValueError('Extracted source exceeds entry limit')
                names.append(entry.name)
        for name in sorted(names):
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                        raise ValueError('Source directory changed during snapshot')
                    copy_tree(child, target / name, depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(before.st_mode):
                total += before.st_size
                if total > 2 * 1024 * 1024 * 1024:
                    raise ValueError('Extracted source exceeds snapshot limit')
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                with os.fdopen(child, 'rb') as source, (target / name).open('xb') as output:
                    opened = os.fstat(source.fileno())
                    if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                        raise ValueError('Source file changed during snapshot')
                    remaining = before.st_size
                    while chunk := source.read(min(1024 * 1024, remaining + 1)):
                        remaining -= len(chunk)
                        if remaining < 0:
                            raise ValueError('Source file grew during snapshot')
                        output.write(chunk)
                    if remaining:
                        raise ValueError('Source file shrank during snapshot')
                (target / name).chmod(0o755 if before.st_mode & 0o111 else 0o644)
            else:
                raise ValueError('Linked or non-regular source input rejected')

    try:
        identity = os.fstat(root)
        output = destination / 'checked-source'
        copy_tree(root, output)
        current = directory.stat(follow_symlinks=False)
        if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError('Source directory replaced during snapshot')
    finally:
        os.close(root)
    load_helper('rebuild').verify(output)
    return output


def build(args):
    if not 1 <= args.jobs <= 256:
        raise ValueError('jobs must be between 1 and 256')
    output = args.output.absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError('Output must be new and its parent must exist')
    if output.parent.resolve() != output.parent:
        raise ValueError('Output path must not traverse symbolic links')
    lock = lock_data()
    cache = safe_directory(args.cache)
    with tempfile.TemporaryDirectory(prefix='iris-aria2-pinned-', dir=output.parent) as temporary:
        context = Path(temporary)
        extracted = context / 'source-bundle'
        extracted.mkdir()
        directory = getattr(args, 'source_directory', None)
        root = source_directory(directory, extracted) if directory is not None else source_tree(args.source_archive, extracted)
        manifest = json.loads((root / 'inputs.json').read_text())
        recipe = check_file(root / 'current-recipe/Dockerfile', manifest['current_recipe_sha256']['Dockerfile']).read_text()
        (context / 'Dockerfile').write_text(offline_recipe(recipe, lock['base_image']))
        load_helper('rebuild').reconstruct(root, context / 'aria2-next', manifest)
        (context / 'aria2-next/AGENTS.md').unlink(missing_ok=True)
        apks = context / 'apk-cache'
        apks.mkdir()
        packages = lock['packages'][args.architecture]
        for name, record in packages.items():
            source = cached_package(cache, args.architecture, name, record, lock['mirrors'], offline=args.offline)
            shutil.copyfile(source, apks / name)
            check_file(apks / name, record['sha256'], record['bytes'])
        (apks / 'SHA256SUMS').write_text(''.join(record['sha256'] + '  ' + name + '\n' for name, record in packages.items()))
        (context / '.dockerignore').write_text('source-bundle\nchecked-source.tar.gz\nartifacts\naria2-next/.git\naria2-next/docs/media\n')
        artifacts = context / 'artifacts'
        command = ['docker', 'buildx', 'build', '--platform', ARCHES[args.architecture],
                   '--network', 'none', '--build-arg', 'SOURCE_DATE_EPOCH=' + str(manifest['source_date_epoch']),
                   '--build-arg', 'ARIA2C_BUILD_JOBS=' + str(args.jobs), '--target', 'artifact',
                   '--output', 'type=local,dest=' + str(artifacts), '--progress', 'plain', str(context)]
        if args.no_cache:
            command.insert(3, '--no-cache')
        subprocess.run(command, check=True)
        expected = manifest['binary_sha256'][args.architecture]
        check_file(artifacts / 'aria2-next', expected)
        (artifacts / 'aria2-next').rename(artifacts / 'aria2c')
        evidence = {'architecture': args.architecture, 'binary_sha256': expected,
                    'apk_lock_sha256': hashlib.sha256((HERE / 'apk-lock.json').read_bytes()).hexdigest(),
                    'packages': len(packages)}
        evidence['source_directory_snapshotted' if directory is not None else 'source_archive_unchanged'] = True
        (artifacts / 'rebuild-evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
        output.mkdir()  # Exclusive publication, never adopt an existing directory.
        for artifact in artifacts.iterdir():
            shutil.move(str(artifact), output / artifact.name)
        return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('architecture', choices=tuple(ARCHES))
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--source-archive', type=Path)
    source.add_argument('--source-directory', type=Path, help='complete extracted bundle with SHA256SUMS')
    parser.add_argument('--cache', type=Path, required=True, help='retain this directory for future rebuilds')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--offline', action='store_true', help='use retained APKs only; base image must also be available')
    parser.add_argument('--no-cache', action='store_true', help='disable Docker build-layer reuse')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build(args), sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        parser.exit(1, 'Pinned rebuild failed: ' + str(exc) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
