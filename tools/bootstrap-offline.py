#!/usr/bin/python3 -I
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bootstrap an authenticated installer on an offline Ubuntu 24.04 server.

Provision this loader, Python 3.12, Ubuntu apt/dpkg/gpgv/keyring and an
independently trusted GitHub CLI/root before use. A bare image without Python
cannot run this loader. Package code is imported only after attestation and
bounded extraction; no package maintainer program is executed during extraction.
"""

import argparse
from contextlib import contextmanager
import hashlib
import importlib
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import time


REPOSITORY = 'cisco-open/intelligent-release-image-staging'
WORKFLOW = REPOSITORY + '/.github/workflows/release.yml'
MAX_DEB = 2 * 1024**3
MAX_DATA = 4 * 1024**3
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'DEBIAN_FRONTEND': 'noninteractive'}
LINKS = {'usr/bin/irisctl': '../lib/iris-installer/irisctl',
         'usr/bin/iris-key-setup': '../lib/iris-installer/iris-key-setup'}


class BootstrapError(Exception):
    """A bounded, public bootstrap failure."""


def _path(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise BootstrapError('Use absolute paths without symbolic links')
    return path


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _snapshot(source, destination, maximum, *, trusted=False, executable=False):
    source = _path(source)
    if trusted:
        for parent in source.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise BootstrapError('Independent trust requires root-owned protected ancestry')
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= maximum
                or (trusted and (before.st_uid != 0 or before.st_mode & 0o022))
                or (executable and not before.st_mode & 0o111)):
            raise BootstrapError('Bootstrap input is not a bounded, protected regular file')
        digest, size = hashlib.sha256(), 0
        with destination.open('xb') as output:
            os.fchmod(output.fileno(), 0o500 if executable else 0o400)
            while data := os.read(descriptor, 1024 * 1024):
                size += len(data)
                if size > maximum:
                    raise BootstrapError('Bootstrap input exceeds its size limit')
                digest.update(data)
                output.write(data)
        if _identity(before) != _identity(os.fstat(descriptor)) or size != before.st_size:
            raise BootstrapError('Bootstrap input changed during its private copy')
        return {'sha256': digest.hexdigest(), 'size': size}
    finally:
        os.close(descriptor)


def verify_command(verifier, artifact, tag, commit, bundle, root):
    """The fixed first trust step; kept in parity with release-auth.py."""
    if (not re.fullmatch(r'v20\d{2}\.\d{2}\.\d{2}(?:\.\d+)?', tag)
            or not re.fullmatch(r'[a-f0-9]{40}', commit)):
        raise BootstrapError('Select an exact release tag and full commit')
    return [str(verifier), 'attestation', 'verify', str(artifact), '--repo', REPOSITORY,
        '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
        '--cert-identity', 'https://github.com/' + WORKFLOW + '@refs/tags/' + tag,
        '--signer-workflow', WORKFLOW, '--source-ref', 'refs/tags/' + tag,
        '--source-digest', commit, '--signer-digest', commit, '--deny-self-hosted-runners',
        '--bundle', str(bundle), '--custom-trusted-root', str(root)]


def _command_to_file(command, destination, limit, *, pass_fds=()):
    """Cap decompressed output as it arrives; never extract through dpkg-deb."""
    process = subprocess.Popen(command, env=ENV, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=pass_fds)
    try:
        deadline, size = time.monotonic() + 120, 0
        with destination.open('xb') as output, selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise BootstrapError('Installer package inspection timed out')
                data = os.read(process.stdout.fileno(), min(1024 * 1024, limit + 1 - size))
                if not data:
                    break
                size += len(data)
                if size > limit:
                    raise BootstrapError('Installer package exceeds its extraction limit')
                output.write(data)
        if process.wait(timeout=max(0.001, deadline - time.monotonic())):
            raise BootstrapError('Installer package inspection failed')
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


class _TarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        if self.type in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            if not 0 < self.size <= 16384 or getattr(archive, '_extension', False):
                raise BootstrapError('Oversized or chained package archive metadata')
            archive._extension = True
            try:
                return super()._proc_member(archive)
            finally:
                archive._extension = False
        if self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE):
            raise BootstrapError('Unsupported package archive entry')
        return super()._proc_member(archive)


def extract(archive_path, destination, *, control=False):
    """Extract canonical bounded files; only the two package command links exist."""
    destination.mkdir(mode=0o700)
    seen, total = set(), 0
    with tarfile.open(archive_path, 'r:', tarinfo=_TarInfo) as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            if not name or name == '.':
                if not member.isdir():
                    raise BootstrapError('Invalid package archive root')
                continue
            path = PurePosixPath(name)
            if (str(path) != name or path.is_absolute() or '..' in path.parts
                    or any(ord(char) < 32 or ord(char) == 127 for char in name)
                    or len(name) > 4096 or name in seen or len(seen) >= 100000
                    or member.uid != 0 or member.gid != 0 or member.size < 0
                    or member.mode not in ((0o777,) if member.issym() else (0o644, 0o755))
                    or (control and (name != 'control' or not member.isfile()))
                    or (not control and path.parts[0] != 'usr')
                    or any(key not in ('path', 'mtime') for key in member.pax_headers)):
                raise BootstrapError('Installer package contains an unsupported path, mode or control hook')
            seen.add(name)
            total += member.size
            if total > (1024 * 1024 if control else MAX_DATA):
                raise BootstrapError('Installer package expanded size exceeds its limit')
            target = destination / name
            if any((destination / Path(*path.parts[:end])).is_symlink() for end in range(1, len(path.parts))):
                raise BootstrapError('Installer package traverses a link')
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
            elif member.issym():
                if control or LINKS.get(name) != member.linkname or member.size:
                    raise BootstrapError('Installer package contains an unsupported link')
                target.symlink_to(member.linkname)
            else:
                if not member.isfile():
                    raise BootstrapError('Unsupported installer package entry')
                with archive.extractfile(member) as source, target.open('xb') as output:
                    while data := source.read(1024 * 1024):
                        output.write(data)
            if not member.issym():
                target.chmod(member.mode)
    if control and seen != {'control'}:
        raise BootstrapError('Installer package must contain control metadata and no maintainer hooks')


@contextmanager
def _workspace():
    """Private writes and cleanup follow held FDs, never a substituted name."""
    parent_path = Path('/tmp')
    parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory = None
    name = 'iris-offline-bootstrap-' + secrets.token_hex(16)
    visible = parent_path / name
    try:
        info = os.fstat(parent)
        if info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise BootstrapError('Bootstrap scratch parent must be protected or root-owned sticky')
        os.mkdir(name, 0o700, dir_fd=parent)
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        anchor = Path('/proc/self/fd') / str(directory)

        def check():
            try:
                for path, descriptor in ((parent_path, parent), (visible, directory)):
                    held, named = os.fstat(descriptor), path.lstat()
                    if path.resolve() != path or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
                        raise BootstrapError('Bootstrap working directory changed')
            except OSError:
                raise BootstrapError('Bootstrap working directory changed') from None

        check()
        yield visible, anchor, directory, check
        check()
    finally:
        if directory is not None:
            try:
                for item in os.listdir(directory):
                    info = os.stat(item, dir_fd=directory, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        shutil.rmtree(item, dir_fd=directory)
                    else:
                        os.unlink(item, dir_fd=directory)
                try:
                    named, held = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(directory)
                except FileNotFoundError:
                    pass
                else:
                    if (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino):
                        os.rmdir(name, dir_fd=parent)
            finally:
                os.close(directory)
        os.close(parent)


def bootstrap(args):
    if sys.version_info < (3, 12) or os.geteuid() != 0:
        raise BootstrapError('Offline bootstrap requires root and the Ubuntu 24.04 Python 3.12 baseline')
    kit = _path(args.release_kit)
    for path in (args.release_verifier, args.release_trusted_root):
        if _path(path).is_relative_to(kit):
            raise BootstrapError('The release kit cannot supply its own verifier or trust root')
    with _workspace() as (visible, work, descriptor, check):
        package = work / 'installer.deb'
        package_record = _snapshot(args.deb, package, MAX_DEB)
        verifier_record = _snapshot(args.release_verifier, work / 'gh', 256 * 1024**2,
                                    trusted=True, executable=True)
        root_record = _snapshot(args.release_trusted_root, work / 'trusted-root.json', 8 * 1024**2, trusted=True)
        _snapshot(kit / 'attestations.jsonl', work / 'attestations.jsonl', 32 * 1024**2)
        environment = dict(ENV, GH_CONFIG_DIR=str(work), HOME=str(work),
                           GH_PROMPT_DISABLED='1', GH_NO_UPDATE_NOTIFIER='1')
        check()
        _command_to_file([str(work / 'gh'), '--version'], work / 'verifier-version', 4096, pass_fds=(descriptor,))
        if not re.match(rb'gh version [0-9]+\.[0-9]+\.[0-9]+\b', (work / 'verifier-version').read_bytes()):
            raise BootstrapError('Select an independently installed GitHub CLI verifier')
        subprocess.run(verify_command(work / 'gh', package, args.release_tag, args.release_commit,
                       work / 'attestations.jsonl', work / 'trusted-root.json'), env=environment,
                       check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       pass_fds=(descriptor,))
        check()
        for role, flag, limit in (('control', '--ctrl-tarfile', 1024 * 1024),
                                  ('payload', '--fsys-tarfile', MAX_DATA)):
            archive = work / (role + '.tar')
            _command_to_file(['/usr/bin/dpkg-deb', flag, str(package)], archive, limit, pass_fds=(descriptor,))
            extract(archive, work / role, control=role == 'control')
            check()
        # The only non-stdlib import is from the authenticated, private package.
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(work / 'payload/usr/lib/iris-installer'))
        controller = importlib.import_module('iris_installer.offline_bootstrap')
        check()
        return controller.run(args, visible / 'installer.deb', visible / 'payload', visible / 'control/control',
                              package_record, verifier_record['sha256'], root_record['sha256'], workspace_guard=check)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('deb', 'release-kit', 'release-verifier', 'release-trusted-root', 'state-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--release-tag', required=True)
    parser.add_argument('--release-commit', required=True)
    parser.add_argument('--accept-changes', action='store_true',
                        help='Persist and apply the exact local prerequisite/package plan')
    args = parser.parse_args(argv)
    try:
        bootstrap(args)
    except Exception as error:
        # Imported controller errors are intentionally public InstallError text.
        safe = isinstance(error, BootstrapError) or type(error).__name__ == 'InstallError'
        parser.exit(1, (str(error) if safe else 'Offline bootstrap failed; preserve its state and inputs') + '\n')


if __name__ == '__main__':
    if not sys.flags.isolated:
        raise SystemExit('Run this trusted loader with /usr/bin/python3 -I')
    main()
