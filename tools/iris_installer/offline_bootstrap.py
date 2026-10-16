# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authenticated pre-package bootstrap with separate, same-host acceptance.

Imported only from a privately extracted, independently attested installer.
Dependency resolution, Ubuntu authentication and interrupted-apply proof reuse
the installer APIs. This journal grants no deployment or replacement-host rights.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

from . import offline_dependencies as dependencies, offline_inputs, prebuilt_dependencies as plans, release_kit, ubuntu
from .prebuilt_install import bind_source
from .state import InstallError, atomic_write, regular_bytes


SCHEMA = 'iris-offline-bootstrap-v1'
ROOTS = frozenset(('python3', 'age', 'ca-certificates', 'openssh-client'))
LIB = 'usr/lib/iris-installer'
SOURCE = LIB + '/source/'
OWNED = (LIB, 'usr/share/doc/iris-installer', 'usr/bin/irisctl', 'usr/bin/iris-key-setup')
LINKS = {'usr/bin/irisctl': '../lib/iris-installer/irisctl',
         'usr/bin/iris-key-setup': '../lib/iris-installer/iris-key-setup'}
SYSTEM_ROOT = Path('/')
DPKG = Path('/var/lib/dpkg')
CONFIG = Path('/etc/dpkg')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _file(path):
    release_kit._path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= 2 * 1024**3:
            raise InstallError('Installer file must be bounded and have no aliases')
        digest, md5, size = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
        while data := os.read(descriptor, 1024 * 1024):
            size += len(data)
            if size > 2 * 1024**3:
                raise InstallError('Installer file exceeds its size limit')
            digest.update(data)
            md5.update(data)
        if release_kit._identity(before) != release_kit._identity(os.fstat(descriptor)):
            raise InstallError('Installer file changed during inspection')
        return {'sha256': digest.hexdigest(), 'md5': md5.hexdigest(),
                'size': size, 'mode': stat.S_IMODE(before.st_mode)}
    finally:
        os.close(descriptor)


def inspect_package(payload, control, tag, commit):
    """Check the exact shipping layout and every source/runtime byte before apply."""
    fields = list(dependencies._paragraphs(io.StringIO(regular_bytes(control).decode('utf-8'))))
    expected_fields = {'Package', 'Version', 'Architecture', 'Maintainer', 'Section', 'Priority', 'Depends', 'Description'}
    version = tag[1:] + '+installer.0.g' + commit[:12]
    if (len(fields) != 1 or set(fields[0]) != expected_fields or fields[0]['Package'] != 'iris-installer'
            or fields[0]['Version'] != version or fields[0]['Architecture'] != 'amd64'
            or fields[0]['Depends'] != 'python3 (>= 3.12), age, ca-certificates, openssh-client'):
        raise InstallError('Authenticated installer package identity or prerequisites are unsupported')
    manifest_path = payload / (SOURCE + 'INSTALLER-SOURCE.json')
    manifest = release_kit._json(regular_bytes(manifest_path, 8 * 1024**2))
    if not isinstance(manifest, dict) or not manifest or len(manifest) > 100000:
        raise InstallError('Installer source inventory is invalid')
    for name, digest in manifest.items():
        relative = PurePosixPath(name)
        if (not isinstance(name, str) or str(relative) != name or relative.is_absolute()
                or '..' in relative.parts or not relative.parts):
            raise InstallError('Installer source inventory path is unsafe')
        release_kit._sha(digest)
    expected = {SOURCE + name for name in manifest} | {SOURCE + 'INSTALLER-SOURCE.json'} | set(LINKS)
    copies = {LIB + '/irisctl': 'tools/irisctl', LIB + '/iris-key-setup': 'tools/iris-key-setup',
              'usr/share/doc/iris-installer/copyright': 'LICENSE',
              'usr/share/doc/iris-installer/README.md': 'docs/dev/installer.md'}
    copies.update({LIB + '/iris_installer/' + name.removeprefix('tools/iris_installer/'): name
                   for name in manifest if name.startswith('tools/iris_installer/')})
    expected.update(copies)
    directories = {str(parent) for name in expected for parent in PurePosixPath(name).parents if str(parent) != '.'}
    actual, records = set(), {}
    for path in payload.rglob('*'):
        name, info = str(path.relative_to(payload)), path.lstat()
        actual.add(name)
        if info.st_uid != os.geteuid() or info.st_gid != os.getegid():
            raise InstallError('Private installer package ownership changed')
        if stat.S_ISDIR(info.st_mode):
            if name not in directories or stat.S_IMODE(info.st_mode) != 0o755:
                raise InstallError('Installer package contains an unsupported directory')
            continue
        if name not in expected:
            raise InstallError('Installer package contains an unlisted file')
        if name in LINKS:
            if not stat.S_ISLNK(info.st_mode) or os.readlink(path) != LINKS[name]:
                raise InstallError('Installer command link differs from its shipping layout')
            records[name] = {'link': LINKS[name]}
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in (0o644, 0o755):
            raise InstallError('Installer package contains unsafe file metadata')
        record = _file(path)
        original = copies.get(name, name.removeprefix(SOURCE))
        if name != SOURCE + 'INSTALLER-SOURCE.json' and record['sha256'] != manifest.get(original):
            raise InstallError('Installer source or controller bytes differ from their inventory')
        records[name] = record
    if actual != expected | directories:
        raise InstallError('Installer package has missing or unexpected shipping paths')
    if regular_bytes(payload / (SOURCE + 'VERSION'), 100).decode().strip() != tag[1:]:
        raise InstallError('Installer source version differs from the selected release')
    return {'version': version, 'files': records, 'directories': sorted(directories), 'source': manifest}


@contextmanager
def _journal(directory):
    """Hold both protected parent and private journal descriptors through writes."""
    directory = release_kit._path(directory)
    if len(directory.parts) < 3:
        raise InstallError('Choose a dedicated bootstrap state directory')
    parent = release_kit._protected_directory(directory.parent)
    descriptor = lock = None
    try:
        created = False
        try:
            os.mkdir(directory.name, 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
        descriptor = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        before = os.fstat(descriptor)
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o700:
            raise InstallError('Bootstrap state must be caller-owned with mode 0700')
        lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise InstallError('Unsafe bootstrap lock')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError('Another offline bootstrap holds this state directory') from None
        if set(os.listdir(descriptor)) - {'lock', 'bootstrap.json'}:
            raise InstallError('Bootstrap state contains unknown entries; preserve them')
        held = Path('/proc/self/fd') / str(descriptor)
        path = held / 'bootstrap.json'
        document = None
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise InstallError('Unsafe bootstrap journal')
            document = release_kit._json(regular_bytes(path, 16 * 1024**2))
            if not isinstance(document, dict):
                raise InstallError('Existing bootstrap journal is invalid; no new plan was authorized')
        elif not created:
            raise InstallError('Existing bootstrap state has no receipt; preserve it instead of accepting a new plan')

        def save(value):
            named = directory.lstat()
            if (directory.resolve() != directory or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino)):
                raise InstallError('Bootstrap state directory changed; nothing was adopted')
            atomic_write(path, _canonical(value) + b'\n')

        yield document, save
    finally:
        for fd in (lock, descriptor, parent):
            if fd is not None:
                os.close(fd)


def _host():
    ubuntu.check_platform()
    machine = regular_bytes(SYSTEM_ROOT / 'etc/machine-id', 128)
    if not re.fullmatch(rb'[a-f0-9]{32}\n?', machine):
        raise InstallError('Offline bootstrap needs this host\'s stable machine identity')
    return _sha(machine.rstrip(b'\n'))


def _status():
    raw = regular_bytes(DPKG / 'status', 64 * 1024**2)
    records = list(dependencies._paragraphs(io.StringIO(raw.decode('utf-8'))))
    values = {}
    for record in records:
        name = record.get('Package')
        if (not isinstance(name, str) or name in values
                or not re.fullmatch(r'(?:install|hold|deinstall|purge|unknown) ok (?:installed|not-installed|config-files)',
                                    record.get('Status', ''))):
            raise InstallError('Host package state is partial or invalid; preserve bootstrap evidence')
        values[name] = record
    package = values.pop('iris-installer', None)
    return _sha(raw), _sha(_canonical(values)), package


def _absent():
    for name in OWNED:
        path = SYSTEM_ROOT / name
        descriptor = release_kit._protected_directory(path.parent)
        os.close(descriptor)
        if path.exists() or path.is_symlink():
            raise InstallError('Installer destination already exists; bootstrap cannot adopt or overwrite it')
    if list((DPKG / 'info').glob('iris-installer.*')) or list((DPKG / 'info').glob('iris-installer:*')):
        raise InstallError('Unfamiliar installer package metadata already exists')


def _installed(package):
    """Prove the exact owned inventory; never repair an interrupted extraction."""
    actual, directories = set(), set()
    for name in OWNED:
        path = SYSTEM_ROOT / name
        paths = [path, *path.rglob('*')] if path.is_dir() and not path.is_symlink() else [path]
        for item in paths:
            relative = str(item.relative_to(SYSTEM_ROOT))
            info = item.lstat()
            if info.st_uid != os.geteuid() or info.st_gid != os.getegid():
                raise InstallError('Installed package ownership differs from authenticated bytes')
            if stat.S_ISDIR(info.st_mode):
                if relative not in package['directories'] or stat.S_IMODE(info.st_mode) != 0o755:
                    raise InstallError('Installed package directory changed')
                directories.add(relative)
                continue
            actual.add(relative)
            expected = package['files'].get(relative)
            if expected is None:
                raise InstallError('Installed package contains unknown files')
            if 'link' in expected:
                if not stat.S_ISLNK(info.st_mode) or os.readlink(item) != expected['link']:
                    raise InstallError('Installed package command link changed')
            elif not stat.S_ISREG(info.st_mode) or _file(item) != expected:
                raise InstallError('Installed package bytes or permissions changed')
    if actual != set(package['files']):
        raise InstallError('Installed package is incomplete; no automatic repair was attempted')
    expected = {name for name in package['directories'] if any(name == root or name.startswith(root + '/') for root in OWNED)}
    if directories != expected:
        raise InstallError('Installed package directory inventory is incomplete')
    info = DPKG / 'info'
    metadata = set(info.glob('iris-installer.*')) | set(info.glob('iris-installer:*'))
    if metadata != {info / 'iris-installer.list', info / 'iris-installer.md5sums'}:
        raise InstallError('Installed package metadata contains missing or unexpected hooks')
    for path in metadata:
        details = path.lstat()
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid() or details.st_nlink != 1
                or stat.S_IMODE(details.st_mode) != 0o644):
            raise InstallError('Installed package metadata is unsafe')
    paths = regular_bytes(info / 'iris-installer.list', 16 * 1024**2).decode('utf-8').splitlines()
    if (len(paths) != len(set(paths))
            or set(paths) != {'/.'} | {'/' + name for name in (*package['files'], *package['directories'])}):
        raise InstallError('Installed dpkg path inventory differs from authenticated package')
    checksums = regular_bytes(info / 'iris-installer.md5sums', 16 * 1024**2).decode('utf-8').splitlines()
    expected_sums = {record['md5'] + '  ' + name for name, record in package['files'].items() if 'md5' in record}
    if len(checksums) != len(set(checksums)) or set(checksums) != expected_sums:
        raise InstallError('Installed dpkg checksum inventory differs from authenticated package')


def _dpkg_config():
    """Do not inherit hooks, path filters, forced overwrites or foreign roots."""
    files = [CONFIG / 'dpkg.cfg']
    extra = CONFIG / 'dpkg.cfg.d'
    if extra.exists():
        files += sorted(extra.iterdir())
    for path in files:
        if not path.exists():
            continue
        data = regular_bytes(path, 1024 * 1024).decode('utf-8')
        for line in data.splitlines():
            option = line.strip()
            if option and not option.startswith('#') and option not in (
                    'no-debsig', 'log /var/log/dpkg.log', 'force-unsafe-io'):
                raise InstallError('Offline bootstrap requires default dpkg configuration without hooks or path filters')


@contextmanager
def _frontend_lock():
    descriptor = os.open(DPKG / 'lock-frontend', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise InstallError('Unsafe dpkg frontend lock')
        try:
            fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError('Another package manager holds the dpkg frontend lock') from None
        yield
    finally:
        os.close(descriptor)


def _install_deb(path):
    subprocess.run(['/usr/bin/dpkg', '--no-triggers', '--install', str(path)],
        env=dict(dependencies.ENV, DPKG_FRONTEND_LOCKED='1', HOME='/nonexistent'),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=True, timeout=600)


def _package_step(document, save, package, deb, *, workspace_guard=lambda: None):
    with _frontend_lock():
        _dpkg_config()
        status, unrelated, existing = _status()
        record = document['package']
        if record is None:
            if existing is not None:
                raise InstallError('An installer package already exists; bootstrap does not upgrade or adopt it')
            _absent()
            record = {'phase': 'accepted', 'status_sha256': status, 'unrelated_sha256': unrelated}
            document['package'] = record
            save(document)
        if (not isinstance(record, dict) or set(record) != {'phase', 'status_sha256', 'unrelated_sha256'}
                or record['phase'] not in ('accepted', 'complete')):
            raise InstallError('Installer package acceptance is invalid; preserve bootstrap state')
        for field in ('status_sha256', 'unrelated_sha256'):
            release_kit._sha(record[field])
        if record['phase'] == 'accepted' and existing is None:
            if status != record['status_sha256'] or unrelated != record['unrelated_sha256']:
                raise InstallError('Host package state changed after installer acceptance')
            _absent()
            identity = _file(deb)
            if {key: identity[key] for key in ('sha256', 'size')} != document['authority']['deb']:
                raise InstallError('Authenticated installer package changed before dpkg')
            workspace_guard()
            _install_deb(deb)
            status, unrelated, existing = _status()
        if (not isinstance(existing, dict) or existing.get('Status') != 'install ok installed'
                or existing.get('Version') != package['version'] or existing.get('Architecture') != 'amd64'
                or (record['phase'] == 'accepted' and unrelated != record['unrelated_sha256'])):
            raise InstallError('Installer package effect is incomplete or unrelated package state changed')
        _installed(package)
        if record['phase'] == 'accepted':
            document['package'] = dict(record, phase='complete')
            save(document)


def run(args, deb, payload, control, deb_record, verifier_sha, root_sha, *, workspace_guard=lambda: None):
    """Authenticate kit/source, accept prerequisite plan, then install exact bytes."""
    if os.geteuid() != 0:
        raise InstallError('Offline bootstrap requires root')
    workspace_guard()
    host = _host()
    _dpkg_config()
    package = inspect_package(payload, control, args.release_tag, args.release_commit)
    kit = release_kit.verify_kit(args.release_kit, tag=args.release_tag, commit=args.release_commit,
        verifier=args.release_verifier, trusted_root=args.release_trusted_root, offline=True)
    if (kit.profile != 'ubuntu-dependencies' or kit.verifier_sha256 != verifier_sha
            or kit.trusted_root_sha256 != root_sha):
        raise InstallError('Bootstrap requires the authenticated dependency profile and original independent trust')
    raw = regular_bytes(Path(args.release_kit) / 'release.json', 8 * 1024**2)
    if _sha(raw) != kit.inventory_sha256:
        raise InstallError('Authenticated release inventory changed before package binding')
    if release_kit._json(raw)['assets'].get(Path(args.deb).name) != deb_record:
        raise InstallError('Selected installer package is not the authenticated release asset')
    bind_source(kit, package['source'], payload.parent)
    workspace_guard()
    authority = {'kit': kit.receipt(), 'host': host, 'deb': deb_record,
                 'package_sha256': _sha(_canonical(package))}
    with offline_inputs.prepare_dependencies(kit) as closure:
        if not args.accept_changes:
            if Path(args.state_dir).exists():
                raise InstallError('Resume an accepted bootstrap with --accept-changes and its original inputs')
            if _status()[2] is not None:
                raise InstallError('An installer package already exists; bootstrap does not adopt it')
            _absent()
            plan = dependencies.plan_dependencies(closure, required_roots=ROOTS)
            print(json.dumps({'prerequisites': plan, 'installer': package['version'], 'accepted': False}, sort_keys=True))
            return
        with _journal(args.state_dir) as (document, save):
            if document is None:
                if _status()[2] is not None:
                    raise InstallError('An installer package already exists; bootstrap does not adopt it')
                _absent()
                plan = dependencies.plan_dependencies(closure, required_roots=ROOTS)
                document = {'schema': SCHEMA, 'authority': authority,
                    'dependencies': {'phase': 'accepted', 'plan': plan, 'evidence': plans.evidence_for_plan(plan)},
                    'package': None}
                save(document)
            if (not isinstance(document, dict) or set(document) != {'schema', 'authority', 'dependencies', 'package'}
                    or document['schema'] != SCHEMA or document['authority'] != authority):
                raise InstallError('Bootstrap host or authenticated input authority changed')
            record = document['dependencies']
            keys = {'phase', 'plan', 'evidence'} | ({'result'} if isinstance(record, dict) and record.get('phase') == 'complete' else set())
            if (not isinstance(record, dict) or set(record) != keys or record['phase'] not in ('accepted', 'complete')
                    or not isinstance(record['plan'], dict) or record['plan'].get('required_roots') != sorted(ROOTS)
                    or (record['phase'] == 'accepted' and document['package'] is not None)):
                raise InstallError('Bootstrap prerequisite acceptance is invalid')
            if record['phase'] == 'complete':
                release_kit._keys(record['result'], {'status_sha256'})
                release_kit._sha(record['result']['status_sha256'])
                plans.validate_completed_plan(closure, record['plan'], record['evidence'])
            else:
                workspace_guard()
                result = plans.apply_accepted_plan(closure, record['plan'], record['evidence'], accept_changes=True)
                document['dependencies'] = dict(record, phase='complete', result=result)
                save(document)
            workspace_guard()
            _package_step(document, save, package, deb, workspace_guard=workspace_guard)
    print('Authenticated installer package installed; bootstrap evidence retained at ' + str(args.state_dir))
