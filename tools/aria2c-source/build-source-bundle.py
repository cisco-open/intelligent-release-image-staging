#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Package pinned corresponding-source inputs without executing their recipes."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def copy_source(source, destination):
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)


def checked_file(root, name, expected):
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe input path')
    path = root / name
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Symlink input rejected: ' + name)
    require(path.is_file(), 'Missing input: ' + name)
    require(digest(path) == expected, 'Input checksum mismatch: ' + name)
    return path


def tree_files(directory):
    result = {}
    for path in directory.rglob('*'):
        relative = path.relative_to(directory)
        if '.git' in relative.parts:
            continue
        require(not path.is_symlink(), 'Source symlink rejected: ' + str(relative))
        if path.is_file():
            result[relative.as_posix()] = path
    return result


def safe_extract(archive, target):
    """Reject links/devices/traversal before extracting any member (Python3.11+)."""
    members = archive.getmembers()
    seen = set()
    for member in members:
        path = PurePosixPath(member.name)
        require(not path.is_absolute() and '..' not in path.parts and '.git' not in path.parts,
                'Unsafe archive path: ' + member.name)
        require(member.isfile() or member.isdir(), 'Unsupported archive member: ' + member.name)
        require(member.name not in seen, 'Duplicate archive member: ' + member.name)
        seen.add(member.name)
    for member in members:
        path = target / member.name
        if member.isdir():
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, path.open('wb') as output:
                shutil.copyfileobj(source, output)
            path.chmod(0o755 if member.mode & 0o111 else 0o644)


def verify_tree(root):
    manifest = root / 'SHA256SUMS'
    expected = {}
    for line in manifest.read_text().splitlines():
        checksum, name = line.split('  ', 1)
        require(name not in expected, 'Duplicate checksum path')
        checked_file(root, name, checksum)
        expected[name] = checksum
    require(set(tree_files(root)) == set(expected) | {'SHA256SUMS'}, 'Archive file set mismatch')
    return len(expected)


def write_archive(root, destination, name, epoch):
    with destination.open('wb') as raw:
        with gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for relative, path in sorted(tree_files(root).items()):
                    member = tarfile.TarInfo(name + '/' + relative)
                    member.size = path.stat().st_size
                    member.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                    member.mtime = epoch
                    with path.open('rb') as source:
                        archive.addfile(member, source)


def publish(candidate, destination, checksum):
    """Expose complete files exclusively; roll back only a link created here."""
    sidecar = destination.with_name(destination.name + '.sha256')
    staged = candidate.with_name(candidate.name + '.sha256')
    staged.write_text(checksum + '  ' + destination.name + '\n')
    os.link(staged, sidecar)
    try:
        os.link(candidate, destination)
    except BaseException:
        if sidecar.exists() and os.path.samefile(staged, sidecar):
            sidecar.unlink()
        raise


def build(inputs, upstream, destination, recipe):
    manifest = json.loads((HERE / 'inputs.json').read_text())
    require(not destination.exists() and not destination.is_symlink(), 'Output already exists')
    sidecar = destination.with_name(destination.name + '.sha256')
    require(not sidecar.exists() and not sidecar.is_symlink(), 'Checksum output already exists')
    require(destination.parent.is_dir(), 'Output parent must exist')
    require(digest(upstream) == manifest['upstream_archive_sha256'], 'Upstream archive checksum mismatch')
    selected = {name: checked_file(inputs, name, sha) for name, sha in manifest['files'].items()}
    current = {name: checked_file(recipe, name, sha) for name, sha in manifest['current_recipe_sha256'].items()}
    checked_file(HERE, 'COPYING3', manifest['gpl3_sha256'])
    with tempfile.TemporaryDirectory(prefix='iris-source-', dir=destination.parent) as temporary:
        temp = Path(temporary)
        payload = temp / 'payload'
        payload.mkdir()
        for name, source in selected.items():
            target = payload / name
            target.parent.mkdir(parents=True, exist_ok=True)
            copy_source(source, target)
        (payload / 'upstream').mkdir()
        shutil.copyfile(upstream, payload / 'upstream' / 'aria2-next.tar')
        original = temp / 'original-source'
        original.mkdir()
        with tarfile.open(upstream) as archive:
            safe_extract(archive, original)
        before = {name: digest(path) for name, path in tree_files(original).items()}
        # A private repository prevents git apply from using an enclosing ignored worktree.
        subprocess.run(['git', '-C', str(original), 'init', '-q'], check=True)
        for patch in manifest['patches']:
            path = (payload / 'original-producer-recipe/patches' / patch['file']).resolve()
            require(digest(path) == patch['sha256'], 'Patch checksum mismatch')
            subprocess.run(['git', '-C', str(original), 'apply', '--check', str(path)], check=True)
            subprocess.run(['git', '-C', str(original), 'apply', str(path)], check=True)
        # Only this newly generated private metadata directory is removed.
        shutil.rmtree(original / '.git')
        after = tree_files(original)
        changed = sorted(name for name, path in after.items() if before.get(name) != digest(path))
        require(len(changed) == manifest['notice_count'], 'Unexpected patched file count')
        notices = payload / 'notice-added-source'
        shutil.copytree(original, notices)
        for name in changed:
            target = notices / name
            prefix = '# ' if name.endswith('.cmake') else '// '
            notice = prefix + 'Modified for IRIS on ' + manifest['notice_date'] + ': patches 0001-0010; see IRIS-MODIFICATIONS.md.\n'
            target.write_bytes(notice.encode() + target.read_bytes())
        shutil.copyfile(HERE / 'IRIS-MODIFICATIONS.md', notices / 'IRIS-MODIFICATIONS.md')
        (payload / 'current-recipe').mkdir()
        for name, source in current.items():
            copy_source(source, payload / 'current-recipe' / name)
        for name in ('COPYING3', 'LICENSE-DISTRIBUTION.md', 'BUNDLE-README.md', 'rebuild.py', 'inputs.json'):
            copy_source(HERE / name, payload / ('README.md' if name == 'BUNDLE-README.md' else name))
        (payload / 'source-verification.json').write_text(json.dumps({'pin': manifest['source_pin'], 'changed_files': changed,
            'original_and_notice_added_source_are_distinct': True, 'binary_sha256': manifest['binary_sha256']}, indent=2) + '\n')
        files = tree_files(payload)
        require(not any(name.endswith(('.apk', '.log')) for name in files), 'Unexpected binary/log input')
        (payload / 'SHA256SUMS').write_text(''.join(digest(path) + '  ' + name + '\n' for name, path in sorted(files.items())))
        require(verify_tree(payload) == len(files), 'Payload verification failed')
        candidate = temp / 'source.tar.gz'
        write_archive(payload, candidate, manifest['name'], manifest['source_date_epoch'])
        extracted = temp / 'verified'
        extracted.mkdir()
        with tarfile.open(candidate, 'r:gz') as archive:
            safe_extract(archive, extracted)
        require(verify_tree(extracted / manifest['name']) == len(files), 'Extraction verification failed')
        checksum = digest(candidate)
        publish(candidate, destination, checksum)
        return {'archive': str(destination), 'sha256': checksum, 'bytes': destination.stat().st_size,
                'files_verified': len(files), 'modified_files': len(changed)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--upstream-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--current-recipe', type=Path, default=HERE.parent / 'aria2c-build')
    args = parser.parse_args()
    try:
        result = build(args.inputs.resolve(), args.upstream_archive.resolve(), args.output.absolute(), args.current_recipe.resolve())
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        parser.exit(1, 'Source bundle failed: ' + str(exc) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
