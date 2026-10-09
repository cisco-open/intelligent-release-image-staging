# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authenticated Ubuntu package closure and isolated, local-only apt operations.

The caller authenticates the outer release before supplying its manifest digest.
Ubuntu signatures independently authenticate package provenance. This module uses
only the Python standard library so reviewed source can bootstrap the installer.
It assumes Ubuntu's apt/dpkg/Python base, not an arbitrary minimal root filesystem.
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shlex
import shutil
import subprocess
import tempfile

from .state import InstallError
from .release_kit import _json, _snapshot, _trusted_snapshot, _protected_directory


SCHEMA = 'iris-ubuntu-dependencies-v1'
MANIFEST = 'dependency-manifest.json'
KEYRING = Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
ROOT_PACKAGES = frozenset((
    'apt', 'dpkg', 'gpgv', 'ubuntu-keyring', 'python3', 'age', 'ca-certificates',
    'openssh-client', 'bash', 'openssl', 'tar', 'gzip', 'xz-utils', 'file',
    'skopeo', 'rpm', 'python3-yaml', 'systemd', 'iproute2', 'docker.io',
    'docker-compose-v2',
))
ENGINE_PACKAGES = frozenset((
    'docker.io', 'docker-ce', 'docker-ce-cli', 'containerd', 'containerd.io',
    'runc', 'moby-engine', 'moby-cli', 'moby-containerd', 'moby-runc',
))
REPOSITORIES = (
    ('archive', 'noble', 'https://archive.ubuntu.com/ubuntu'),
    ('archive', 'noble-updates', 'https://archive.ubuntu.com/ubuntu'),
    ('security', 'noble-security', 'https://security.ubuntu.com/ubuntu'),
)
COMPONENTS = ('main', 'universe')
MAX_FILE = 1024 ** 3
MAX_TOTAL = 8 * 1024 ** 3
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'DEBIAN_FRONTEND': 'noninteractive'}


def _run(command, *, config=None, timeout=900):
    env = dict(ENV)
    if config is not None:
        env['APT_CONFIG'] = str(config)
    try:
        result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        raise InstallError('Offline dependency command could not complete') from None
    if result.returncode:
        raise InstallError('Offline dependency command failed: ' + Path(command[0]).name)
    return result.stdout


def _digest(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _relative(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_./+%:~-]+', value)
            or PurePosixPath(value).is_absolute() or '..' in PurePosixPath(value).parts
            or str(PurePosixPath(value)) != value):
        raise InstallError('Offline dependency path is unsafe')
    return value


def _fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise InstallError('Offline dependency manifest has unsupported fields')


def _paragraphs(lines):
    """Read Debian control metadata; dependency expressions remain apt's job."""
    fields, key = {}, None
    for line in lines:
        line = line.rstrip('\n')
        if not line:
            if fields:
                yield fields
            fields, key = {}, None
        elif line[0].isspace():
            if key is None:
                raise InstallError('Malformed Ubuntu package metadata')
            fields[key] += '\n' + line[1:]
        else:
            key, separator, value = line.partition(':')
            if not separator or not re.fullmatch(r'[A-Za-z0-9-]+', key) or key in fields:
                raise InstallError('Malformed or duplicate Ubuntu metadata field')
            fields[key] = value.lstrip()
    if fields:
        yield fields


def _validate_manifest(value):
    _fields(value, ('schema', 'host', 'docker_provider', 'roots', 'packages', 'files'))
    if (value['schema'] != SCHEMA or value['host'] !=
            {'os': 'ubuntu', 'version': '24.04', 'architecture': 'amd64'}
            or value['docker_provider'] != 'docker.io'):
        raise InstallError('Unsupported offline dependency platform or provider')
    roots, files, packages = value['roots'], value['files'], value['packages']
    if not isinstance(roots, dict) or set(roots) != ROOT_PACKAGES:
        raise InstallError('Offline dependency roots do not cover the installer and finalizer')
    if not isinstance(files, dict) or not 1 <= len(files) <= 4096:
        raise InstallError('Offline dependency inventory is invalid')
    total = 0
    for name, details in files.items():
        _relative(name)
        _fields(details, ('sha256', 'size'))
        if (not isinstance(details['sha256'], str)
                or not re.fullmatch(r'[a-f0-9]{64}', details['sha256'])
                or type(details['size']) is not int or not 0 < details['size'] <= MAX_FILE):
            raise InstallError('Offline dependency inventory digest or size is invalid')
        total += details['size']
    if total > MAX_TOTAL or not isinstance(packages, list) or not 1 <= len(packages) <= 4000:
        raise InstallError('Offline dependency closure exceeds its limit')
    identities, expected = {}, set()
    for repository, suite, _ in REPOSITORIES:
        expected.add(f'repositories/{repository}/dists/{suite}/InRelease')
        for component in COMPONENTS:
            expected.add(f'repositories/{repository}/dists/{suite}/{component}/binary-amd64/Packages')
    for package in packages:
        _fields(package, ('name', 'version', 'architecture', 'repository', 'suite', 'component', 'filename'))
        name, version, architecture = (package[key] for key in ('name', 'version', 'architecture'))
        if (any(not isinstance(field, str) for field in package.values())
                or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', name)
                or not isinstance(version, str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', version)
                or architecture not in ('amd64', 'all') or name in identities
                or (package['repository'], package['suite']) not in
                {(repository, suite) for repository, suite, _ in REPOSITORIES}
                or package['component'] not in COMPONENTS):
            raise InstallError('Offline dependency package identity is invalid or duplicated')
        filename = _relative(package['filename'])
        if not filename.startswith('pool/') or not filename.endswith('.deb'):
            raise InstallError('Offline dependency package filename is invalid')
        identities[name] = package
        expected.add('repositories/' + package['repository'] + '/' + filename)
    if set(files) != expected:
        raise InstallError('Offline dependency inventory has missing or extra files')
    if any(name not in identities or identities[name]['version'] != version for name, version in roots.items()):
        raise InstallError('Offline dependency root versions are missing or inconsistent')
    return identities


def _release_indexes(directory, keyring):
    indexes = {}
    for repository, suite, _ in REPOSITORIES:
        base = directory / 'repositories' / repository / 'dists' / suite
        plain = _run(['/usr/bin/gpgv', '--keyring', str(keyring), '--output', '-', str(base / 'InRelease')])
        records = list(_paragraphs(plain.splitlines()))
        if len(records) != 1:
            raise InstallError('Ubuntu signed release metadata is invalid')
        release = records[0]
        if (release.get('Origin') != 'Ubuntu' or release.get('Label') != 'Ubuntu'
                or release.get('Suite') != suite or release.get('Codename') != 'noble'
                or 'amd64' not in release.get('Architectures', '').split()):
            raise InstallError('Ubuntu signed release identity differs from the supported platform')
        try:
            now = datetime.now(timezone.utc)
            if parsedate_to_datetime(release['Date']) > now + timedelta(days=1):
                raise ValueError()
            if 'Valid-Until' in release and parsedate_to_datetime(release['Valid-Until']) < now:
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise InstallError('Ubuntu signed release metadata has an invalid validity period') from None
        hashes = {}
        for line in release.get('SHA256', '').splitlines():
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) != 3 or fields[2] in hashes:
                raise InstallError('Ubuntu signed release hashes are malformed')
            hashes[fields[2]] = fields[:2]
        for component in COMPONENTS:
            relative = component + '/binary-amd64/Packages'
            path = base / relative
            if hashes.get(relative) != [_digest(path), str(path.stat().st_size)]:
                raise InstallError('Ubuntu package index differs from its signed release')
            indexes[(repository, suite, component)] = path
    return indexes


def _verify_packages(directory, manifest, indexes):
    remaining = {(p['repository'], p['suite'], p['component'], p['name'], p['version'], p['architecture']): p
                 for p in manifest['packages']}
    for location, index in indexes.items():
        with index.open(encoding='utf-8') as stream:
            for entry in _paragraphs(stream):
                identity = (*location, entry.get('Package'), entry.get('Version'), entry.get('Architecture'))
                if identity not in remaining:
                    continue
                package = remaining.pop(identity)
                filename = 'repositories/' + package['repository'] + '/' + package['filename']
                expected = manifest['files'][filename]
                if (entry.get('Filename') != package['filename'] or entry.get('SHA256') != expected['sha256']
                        or entry.get('Size') != str(expected['size'])):
                    raise InstallError('Offline package differs from signed Ubuntu index')
                info = _run(['/usr/bin/dpkg-deb', '--show', '--showformat=${Package}\t${Version}\t${Architecture}',
                             str(directory / filename)])
                if info != '\t'.join(identity[-3:]):
                    raise InstallError('Offline package control identity differs from signed Ubuntu index')
    if remaining:
        raise InstallError('Offline package is absent from signed Ubuntu metadata')


def _quoted(value):
    value = str(value)
    if any(character in value for character in ('"', '\\', '\n', '\r', '\0')):
        raise InstallError('Unsafe apt configuration path')
    return '"' + value + '"'


def _apt_workspace(directory, repository, keyring, *, online=False, status=None):
    """Create entirely private apt configuration; system hooks are not loaded."""
    directory.mkdir(mode=0o700)
    for name in ('lists', 'lists/partial', 'archives', 'archives/partial', 'methods', 'empty'):
        (directory / name).mkdir(mode=0o700)
    (directory / 'status').write_text('')
    (directory / 'extended_states').write_text('')
    sources = []
    for name, suite, url in REPOSITORIES:
        uri = url if online else (repository / 'repositories' / name).as_uri()
        sources.append('deb [arch=amd64 signed-by=' + str(keyring) + '] ' + uri + ' ' + suite + ' ' + ' '.join(COMPONENTS))
    (directory / 'sources.list').write_text('\n'.join(sources) + '\n')
    for method in ('file', 'copy', 'store', 'gpgv', *(('http', 'https') if online else ())):
        (directory / 'methods' / method).symlink_to('/usr/lib/apt/methods/' + method)
    settings = {
        'Dir::Etc::main': '/dev/null', 'Dir::Etc::parts': directory / 'empty',
        'Dir::Etc::sourcelist': directory / 'sources.list', 'Dir::Etc::sourceparts': directory / 'empty',
        'Dir::Etc::preferences': '-', 'Dir::Etc::preferencesparts': directory / 'empty',
        'Dir::Etc::trusted': '-', 'Dir::Etc::trustedparts': directory / 'empty',
        'Dir::State::status': status or directory / 'status', 'Dir::State::lists': directory / 'lists',
        'Dir::State::extended_states': directory / 'extended_states',
        'Dir::Cache::archives': directory / 'archives', 'Dir::Cache::pkgcache': directory / 'pkgcache.bin',
        'Dir::Cache::srcpkgcache': directory / 'srcpkgcache.bin', 'Dir::Log': directory,
        'Dir::Bin::methods': directory / 'methods', 'APT::Architecture': 'amd64',
        'APT::Install-Recommends': 'false', 'APT::Install-Suggests': 'false',
        'APT::Get::AllowUnauthenticated': 'false', 'APT::Get::allow-downgrades': 'false',
        'APT::Get::allow-change-held-packages': 'false', 'Acquire::AllowInsecureRepositories': 'false',
        'Acquire::AllowDowngradeToInsecureRepositories': 'false', 'Acquire::Check-Valid-Until': 'true',
        'Acquire::Languages': 'none', 'Acquire::GzipIndexes': 'false',
        'Acquire::IndexTargets::deb::DEP-11::DefaultEnabled': 'false',
        'Acquire::IndexTargets::deb::CNF::DefaultEnabled': 'false',
        'Acquire::Retries': '0', 'Acquire::http::Timeout': '60', 'Acquire::https::Timeout': '60',
        'APT::Update::Error-Mode': 'any', 'APT::Get::List-Cleanup': 'false',
        'APT::Sandbox::User': pwd.getpwuid(os.geteuid()).pw_name,
    }
    config = directory / 'apt.conf'
    config.write_text('\n'.join(key + ' ' + _quoted(value) + ';' for key, value in settings.items())
                      + '\n#clear APT::Architectures;\nAPT::Architectures { "amd64"; };\n'
                      + ('' if online else 'Acquire::IndexTargets::deb::Packages::CompressionTypes "uncompressed";\nAcquire::By-Hash "false";\n'))
    return config


def _simulation(text):
    solution = []
    for line in text.splitlines():
        if line.startswith(('Remv ', 'Purg ')):
            raise InstallError('Offline dependency solution would remove installed packages')
        if line.startswith('Inst '):
            match = re.fullmatch(r'Inst ([a-z0-9][a-z0-9+.-]+)(?::(?:amd64|all))?(?: \[([^\]]+)\])? \(([^ ]+) (?:.* )?\[(amd64|all)\]\)(?: \[[^\]]*\])?', line)
            if not match:
                raise InstallError('Cannot establish the exact apt dependency solution')
            name, old_version, version, architecture = match.groups()
            solution.append({'name': name, 'version': version, 'old_version': old_version,
                             'architecture': architecture})
    if len({p['name'] for p in solution}) != len(solution):
        raise InstallError('Apt returned duplicate package operations')
    return sorted(solution, key=lambda package: package['name'])


def _apt_install(config, specifications, *, simulate=True):
    return _run(['/usr/bin/apt-get', '--simulate' if simulate else '--yes', 'install',
                 '--no-download', '--no-remove', '--no-install-recommends',
                 '--no-install-suggests', *specifications], config=config, timeout=1800)


def _check_solution(solution, packages, *, installed=None, preserve_engine=False):
    for operation in solution:
        package = packages.get(operation['name'])
        if (package is None or operation['version'] != package['version']
                or operation.get('architecture') != package.get('architecture')):
            raise InstallError('Apt requires a package version outside the authenticated closure')
        old = (installed or {}).get(operation['name'])
        if old:
            if old['Status'].startswith('hold '):
                raise InstallError('Offline dependency solution would change a held package')
            result = subprocess.run(['/usr/bin/dpkg', '--compare-versions', old['Version'], 'gt', operation['version']],
                                    env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=10, check=False)
            if result.returncode not in (0, 1):
                raise InstallError('Cannot compare installed Ubuntu package versions')
            if result.returncode == 0:
                raise InstallError('Offline dependency solution would downgrade an installed package')
        if preserve_engine and operation['name'] in ENGINE_PACKAGES:
            raise InstallError('Offline dependency solution would change an existing Docker provider')


@dataclass
class VerifiedClosure:
    directory: Path
    digest: str
    manifest: dict
    packages: dict
    keyring: Path
    config: Path
    temporary: object

    def close(self):
        self.temporary.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        self.close()


def validate_closure(directory, expected_manifest_sha256, *, keyring=KEYRING):
    """Snapshot authenticated bytes, verify Ubuntu provenance and complete closure."""
    directory = Path(directory)
    if not isinstance(expected_manifest_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', expected_manifest_sha256):
        raise InstallError('An authenticated dependency manifest digest is required')
    descriptor = _protected_directory(directory)
    os.close(descriptor)
    temporary = tempfile.TemporaryDirectory(prefix='iris-offline-dependencies-')
    snapshot = Path(temporary.name)
    try:
        digest = _snapshot(directory / MANIFEST, snapshot / MANIFEST, 4 * 1024 * 1024)
        if digest != expected_manifest_sha256:
            raise InstallError('Offline dependency manifest differs from authenticated inventory')
        manifest = _json((snapshot / MANIFEST).read_bytes())
        packages = _validate_manifest(manifest)
        actual = set()
        for path in directory.rglob('*'):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise InstallError('Offline dependency payload contains unsafe entries')
            if path.is_file():
                actual.add(path.relative_to(directory).as_posix())
        if actual != {MANIFEST, *manifest['files']}:
            raise InstallError('Offline dependency payload has missing or extra files')
        for name, expected in manifest['files'].items():
            destination = snapshot / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = _snapshot(directory / name, destination, MAX_FILE)
            if digest != expected['sha256'] or destination.stat().st_size != expected['size']:
                raise InstallError('Offline dependency file differs from authenticated inventory')
        trusted = snapshot / 'ubuntu-archive-keyring.gpg'
        if Path(keyring).resolve().is_relative_to(directory):
            raise InstallError('Ubuntu archive keyring must be independently installed')
        _trusted_snapshot(Path(keyring), trusted)
        indexes = _release_indexes(snapshot, trusted)
        _verify_packages(snapshot, manifest, indexes)
        config = _apt_workspace(snapshot / 'apt', snapshot, trusted)
        _run(['/usr/bin/apt-get', 'update'], config=config)
        for package in manifest['packages']:
            filename = package['name'] + '_' + package['version'].replace(':', '%3a') + '_' + package['architecture'] + '.deb'
            source = snapshot / 'repositories' / package['repository'] / package['filename']
            shutil.copyfile(source, config.parent / 'archives' / filename)
        solution = _simulation(_apt_install(config, [name + '=' + version for name, version in sorted(manifest['roots'].items())]))
        _check_solution(solution, packages)
        if {p['name'] for p in solution} != set(packages):
            raise InstallError('Offline payload is not the exact complete apt dependency closure')
        return VerifiedClosure(snapshot, expected_manifest_sha256, manifest, packages, trusted, config, temporary)
    except BaseException:
        temporary.cleanup()
        raise


def _installed(path):
    with path.open(encoding='utf-8') as stream:
        records = list(_paragraphs(stream))
    if any(not re.fullmatch(r'(?:install|hold|deinstall|purge|unknown) ok (?:installed|not-installed|config-files)',
                           record.get('Status', '')) for record in records):
        raise InstallError('Host has unfinished package operations; recover them before offline dependency installation')
    if any(record.get('Architecture') not in ('amd64', 'all') for record in records
           if record.get('Status', '').endswith(' installed')):
        raise InstallError('Offline dependency installation requires an amd64 host without foreign-architecture packages')
    return {record['Package']: record for record in records if record.get('Status', '').endswith(' installed')}


def plan_dependencies(closure, *, status=Path('/var/lib/dpkg/status')):
    """Return a JSON receipt after local-only apt simulation; never install."""
    from .ubuntu import check_platform
    check_platform()
    status_hash = _digest(status)
    installed = _installed(status)
    with status.open(encoding='utf-8') as stream:
        held = {record['Package'] for record in _paragraphs(stream) if record.get('Status', '').startswith('hold ')}
    provider = sorted(ENGINE_PACKAGES & set(installed))
    docker = shutil.which('docker', path=ENV['PATH'])
    preserve_engine = bool(provider or docker)
    roots = [name + '=' + version for name, version in sorted(closure.manifest['roots'].items()) if name not in installed]
    if preserve_engine:
        roots = [specification for specification in roots if specification.split('=')[0] != 'docker.io']
        if 'docker.io' not in installed:
            # An independently supplied provider must already include Compose.
            if not docker:
                raise InstallError('An existing Docker provider is incomplete; it cannot be replaced offline')
            _run([docker, 'compose', 'version'])
            roots = [specification for specification in roots if specification.split('=')[0] != 'docker-compose-v2']
    config = closure.config
    solution = _simulation(_run(['/usr/bin/apt-get', '-o', 'Dir::State::status=' + str(status), '--simulate',
                                'install', '--no-download', '--no-remove', '--no-install-recommends',
                                '--no-install-suggests', *roots], config=config))
    _check_solution(solution, closure.packages, installed=installed, preserve_engine=preserve_engine)
    if any(operation['name'] in held for operation in solution):
        raise InstallError('Offline dependency solution would change a held package')
    if _digest(status) != status_hash:
        raise InstallError('Host package status changed during dependency planning')
    return {'schema': 'iris-offline-dependency-plan-v1', 'closure_sha256': closure.digest,
            'status_sha256': status_hash, 'provider': provider, 'docker_path': docker,
            'roots': roots, 'packages': solution}


def _application_guard(directory, expected_status, *, status=Path('/var/lib/dpkg/status')):
    """Check under apt's frontend lock, before its first dpkg operation.

    This code is generated by the independently trusted installer, never read
    from a kit. Repeated hooks must belong to the same apt PID and start time.
    A private per-application receipt permits legitimate later dpkg batches.
    """
    script = directory / 'check-package-state.py'
    script.write_text('''# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import hashlib, json, os, pathlib, sys
pid = os.getppid()
identity = None
receipt = pathlib.Path(sys.argv[3])
for _ in range(8):
    process = pathlib.Path('/proc') / str(pid)
    fields = (process / 'stat').read_text().rsplit(')', 1)[1].split()
    executable = os.readlink(process / 'exe')
    if executable == '/usr/bin/apt-get' or (executable == '/usr/bin/apt-get (deleted)' and receipt.exists()):
        identity = [pid, fields[19]]
        break
    pid = int(fields[1])
if identity is None:
    sys.exit('Offline package guard must run under apt')
if receipt.exists():
    if json.loads(receipt.read_text()) != identity:
        sys.exit('Offline package guard belongs to a different apt operation')
else:
    digest = hashlib.sha256()
    with open(sys.argv[1], 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != sys.argv[2]:
        sys.exit('Host package state changed after review; no package operation was authorized')
    with receipt.open('x') as stream:
        json.dump(identity, stream)
''')
    script.chmod(0o600)
    return shlex.join(['/usr/bin/python3', '-I', str(script), str(status), expected_status,
                       str(directory / 'apt-operation.json')])


def apply_dependencies(closure, plan, *, accept_changes=False):
    """Apply only the acknowledged exact solution, after host-state revalidation."""
    if not accept_changes:
        raise InstallError('Offline dependency application requires explicit acceptance')
    if os.geteuid() != 0:
        raise InstallError('Offline dependency application requires root')
    current = plan_dependencies(closure)
    if plan != current:
        raise InstallError('Offline dependency plan or host package state changed; review a new plan')
    if not plan['packages']:
        return plan
    specifications = [package['name'] + '=' + package['version'] for package in plan['packages']]
    command = ['/usr/bin/apt-get', '-o', 'Dir::State::status=/var/lib/dpkg/status', '--yes', 'install',
               '--no-download', '--no-remove', '--no-install-recommends', '--no-install-suggests', *specifications]
    exact = _simulation(_run([*command[:3], '--simulate', *command[4:]], config=closure.config))
    if exact != plan['packages']:
        raise InstallError('Exact offline package application differs from the reviewed solution')
    # apt holds its frontend lock when it calls this hook. A concurrent apt
    # operation finishing after simulation therefore cannot broaden this plan.
    with tempfile.TemporaryDirectory(prefix='apply-', dir=closure.directory) as temporary:
        guard = _application_guard(Path(temporary), plan['status_sha256'])
        command += ['-o', 'DPkg::Pre-Invoke::=' + guard]
        _run(command, config=closure.config, timeout=1800)
    installed = _installed(Path('/var/lib/dpkg/status'))
    if any(installed.get(package['name'], {}).get('Version') != package['version'] for package in plan['packages']):
        raise InstallError('Offline dependency application is incomplete; inspect package state before resuming')
    return plan
