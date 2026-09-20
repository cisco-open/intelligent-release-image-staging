#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Rebuild an extracted source bundle with Docker buildx; no source git checkout."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile


def verify(root):
    expected = set()
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        checksum, name = line.split('  ', 1)
        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts or name in expected:
            raise ValueError('Unsafe checksum manifest')
        path = root / name
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
            raise ValueError('Missing or linked source input: ' + name)
        with path.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != checksum:
                raise ValueError('Source checksum mismatch: ' + name)
        expected.add(name)
    actual = set()
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Source symlink rejected')
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != expected | {'SHA256SUMS'}:
        raise ValueError('Source file set mismatch')
    return len(expected)


def reconstruct(root, target, manifest):
    """Reconstruct historical input in a private directory, not a source checkout."""
    target.mkdir()
    with tarfile.open(root / 'upstream/aria2-next.tar') as archive:
        members = archive.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or '.git' in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe upstream archive member')
        for member in members:
            path = target / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, path.open('wb') as output:
                    shutil.copyfileobj(source, output)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
    subprocess.run(['git', '-C', str(target), 'init', '-q'], check=True)
    for patch in manifest['patches']:
        source = root / 'original-producer-recipe/patches' / patch['file']
        subprocess.run(['git', '-C', str(target), 'apply', '--check', str(source)], check=True)
        subprocess.run(['git', '-C', str(target), 'apply', str(source)], check=True)
    shutil.rmtree(target / '.git')  # Only metadata just generated in this private temporary tree.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('architecture', choices=('x86_64', 'aarch64'))
    parser.add_argument('--output', type=Path, required=True, help='New output directory; must not exist')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    try:
        if args.jobs < 1 or args.jobs > 256:
            raise ValueError('jobs must be between 1 and 256')
        count = verify(root)
        if args.verify_only:
            print(json.dumps({'source_files_verified': count}))
            return
        output = args.output.absolute()
        if output.exists() or output.is_symlink() or not output.parent.is_dir():
            raise ValueError('Output must be new and its parent must exist')
        manifest = json.loads((root / 'inputs.json').read_text())
        platform = 'linux/amd64' if args.architecture == 'x86_64' else 'linux/arm64'
        with tempfile.TemporaryDirectory(prefix='iris-aria2-build-', dir=output.parent) as temporary:
            context = Path(temporary)
            reconstruct(root, context / 'aria2-next', manifest)
            (context / 'aria2-next/AGENTS.md').unlink(missing_ok=True)
            (context / '.dockerignore').write_text('aria2-next/.git\naria2-next/docs/media\n')
            artifacts = context / 'artifacts'
            subprocess.run(['docker', 'buildx', 'build', '--platform', platform,
                '--build-arg', 'SOURCE_DATE_EPOCH=' + str(manifest['source_date_epoch']),
                '--build-arg', 'ARIA2C_BUILD_JOBS=' + str(args.jobs), '--target', 'artifact',
                '--output', 'type=local,dest=' + str(artifacts), '--progress', 'plain',
                '-f', str(root / 'current-recipe/Dockerfile'), str(context)], check=True)
            binary = artifacts / 'aria2-next'
            with binary.open('rb') as stream:
                checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
            if checksum != manifest['binary_sha256'][args.architecture]:
                raise ValueError('Rebuilt binary differs from distributed artifact; no output adopted')
            binary.rename(artifacts / 'aria2c')
            # Exclusive mkdir avoids overwriting another process's output directory.
            output.mkdir()
            for artifact in artifacts.iterdir():
                shutil.move(str(artifact), output / artifact.name)
            print(json.dumps({'architecture': args.architecture, 'sha256': checksum, 'output': str(output)}))
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, 'Rebuild failed: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
