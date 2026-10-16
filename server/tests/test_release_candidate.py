# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise real private Git snapshots with mocked builders; no Docker builds."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from iris_installer.state import InstallError
from test_installer_offline_sources import original as source_repository

SPEC = importlib.util.spec_from_file_location('iris_release_candidate', ROOT / 'tools/build-release-candidate.py')
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
TAG = 'v2026.10.09'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *arguments):
    return subprocess.check_output(['git', '-C', str(repo), *arguments], stderr=subprocess.DEVNULL).decode().strip()


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / 'owner'
    repo.mkdir()
    git(repo, 'init')
    git(repo, 'config', 'user.name', 'Candidate fixture')
    git(repo, 'config', 'user.email', 'fixture@example.invalid')
    files = {'VERSION': b'2026.10.09\n', 'LICENSE': b'license\n', 'NOTICE': b'notice\n',
             '.gitignore': b'release/\ncreds/\n', 'source.txt': b'committed source\n',
             'empty': b'', 'server/Dockerfile': b'FROM scratch\n',
             'server/Dockerfile.console': b'FROM scratch\n',
             **{'tools/' + name: b'# committed builder fixture\n' for name in c.BUILDERS}}
    for name, data in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if name.endswith('.sh') else 0o644)
    git(repo, 'add', '.')
    git(repo, 'commit', '-m', 'Committed source fixture')
    return repo, git(repo, 'rev-parse', 'HEAD'), files


class Builders:
    def __init__(self, commit, files, change=None):
        self.commit, self.files, self.change = commit, files, change
        self.calls, self.environments, self.source = [], [], None

    def __call__(self, arguments, *, environment, cwd):
        args = list(map(str, arguments))
        self.calls.append(args)
        self.environments.append(dict(environment))
        self.source = cwd
        assert c._git(cwd, ['rev-parse', 'HEAD'], environment).decode().strip() == self.commit
        assert not (cwd / 'creds').exists()
        assert (cwd / 'source.txt').read_bytes() == self.files['source.txt']

        def option(name):
            return Path(args[args.index(name) + 1])

        script = Path(args[2]).name if args[1:2] == ['-B'] else Path(args[1]).name
        if script == 'build-packaging-inputs.py':
            output = option('--output-dir')
            output.mkdir()
            (output / c.NAMES['packaging-tools']).write_bytes(b'XR source with license, no binary')
        elif script == 'build-installer-package.py':
            output = option('--out')
            self.package = output / ('iris-installer_2026.10.09+installer.0.g' + self.commit[:12] + '_amd64.deb')
            self.package.write_bytes(b'mocked installer archive')
            self.inventory = {name: sha(data) for name, data in self.files.items()}
            self.package.with_suffix('.deb.source.json').write_text(json.dumps(
                {'schema': 1, 'commit': self.commit, 'files': self.inventory}))
            self.package.with_suffix('.deb.sha256').write_text(sha(self.package.read_bytes()) + '  ' + self.package.name + '\n')
            if self.change == 'package-checksum':
                self.package.with_suffix('.deb.sha256').write_text('wrong\n')
            if self.change == 'package-commit':
                self.package.with_suffix('.deb.source.json').write_text(json.dumps(
                    {'schema': 1, 'commit': '0' * 40, 'files': self.inventory}))
        elif args[0] == 'dpkg-deb':
            canonical = Path(args[-1]) / 'usr/lib/iris-installer/source'
            for name in self.files:
                path = canonical / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(cwd / name, path)
                path.chmod((cwd / name).stat().st_mode & 0o777)
            (canonical / 'INSTALLER-SOURCE.json').write_text(json.dumps(self.inventory))
            if self.change == 'installed-bytes':
                (canonical / 'source.txt').write_text('different')
            elif self.change == 'installed-mode':
                (canonical / 'source.txt').chmod(0o755)
            elif self.change == 'installed-extra':
                (canonical / 'unlisted').write_text('unlisted')
            elif self.change == 'installed-link':
                (canonical / 'source.txt').unlink()
                (canonical / 'source.txt').symlink_to(cwd / 'source.txt')
        elif script == 'make-release.sh':
            release = cwd / 'release'
            release.mkdir()
            with tarfile.open(release / 'iris.tgz', 'w:gz') as archive:
                for name, data in self.files.items():
                    if self.change == 'source-omission' and name == 'source.txt':
                        continue
                    if self.change == 'source-bytes' and name == 'source.txt':
                        data = b'changed source'
                    item = tarfile.TarInfo('iris/' + name)
                    item.size = len(data)
                    item.mode = (cwd / name).stat().st_mode & 0o777
                    if self.change == 'source-mode' and name == 'source.txt':
                        item.mode = 0o755
                    archive.addfile(item, io.BytesIO(data))
        elif script == 'build-guest-inputs.py':
            assert option('--source-dir') == cwd.parent / 'installed/usr/lib/iris-installer/source'
            assert option('--source-manifest') == option('--source-dir') / 'INSTALLER-SOURCE.json'
            output = option('--output-dir')
            output.mkdir()
            (output / c.NAMES['guest-inputs']).write_bytes(b'guest references')
        elif args[0] == 'docker':
            Path(str(option('--output')).split('dest=', 1)[1]).write_bytes(b'core docker archive')
            if self.change == 'tracked-mutation':
                (cwd / 'NOTICE').write_text('changed after build')
        elif script == 'build-device-image.sh':
            output = option('--output')
            output.write_bytes(b'neutral both-platform OCI')
            Path(str(output) + '.manifest').write_text('neutral builder receipt\n')
        elif script == 'build-release-kit.py':
            if self.change == 'late-failure':
                raise InstallError('mocked late build failure')
            output = option('--out')
            for role, name in c.NAMES.items():
                shutil.copyfile(option('--' + role), output / name)
            profile = 'prepared-host'
            if '--ubuntu-dependencies' in args:
                profile = 'ubuntu-dependencies'
                shutil.copyfile(option('--ubuntu-dependencies'), output / 'iris-ubuntu-dependencies.tar.gz')
            (output / 'release-kit.json').write_text(json.dumps(
                {'commit': self.commit, 'tag': TAG, 'profile': profile}))
            if self.change == 'unexpected-asset':
                (output / 'attestations.jsonl').write_text('not an attestation')
            elif self.change == 'kit-identity':
                (output / 'release-kit.json').write_text(json.dumps({'commit': '0' * 40, 'tag': TAG, 'profile': profile}))
        else:
            pytest.fail('Unexpected command: ' + str(args))


def assemble(tmp_path, repository, *, builders=None, **kwargs):
    repo, commit, files = repository
    builders = builders or Builders(commit, files)
    output = c.assemble(repo, tmp_path / 'candidate', commit=commit, tag=TAG,
                        appmgr_repository=repo, runner=builders, **kwargs)
    return output, builders


def test_exact_commit_sequence_and_local_only_receipt(tmp_path, repository, monkeypatch):
    for name in ('IRIS_INSTRUCTION_ROOTS_DIR', 'ARIA2C_BIN_x86_64', 'IRIS_FORCE_DEVICE_IMAGE_BUILD',
                 'SCRUB_PASS', 'SCRUB_USER', 'PYTHONPATH', 'BASH_ENV', 'GIT_CONFIG_COUNT', 'BUILDX_BUILDER'):
        monkeypatch.setenv(name, 'ignored ambient value')
    output, builders = assemble(tmp_path, repository, builder='native-builder')
    receipt = json.loads((output / 'local-candidate.json').read_bytes())
    assert receipt['format'] == 'iris-local-release-candidate-v1'
    assert receipt['authenticated'] is False
    assert receipt['commit'] == repository[1] and receipt['tag'] == TAG
    assert receipt['version'] == TAG[1:] and receipt['profile'] == 'prepared-host'
    assert receipt['source_match']['canonical_source_matches'] is True
    assert receipt['source_match']['file_count'] == len(repository[2])
    assert 'redistribution gates remain separate' in receipt['scope']
    assert set(receipt['files']) == {path.name for path in output.iterdir()} - {'local-candidate.json'}
    assert 'release.json' not in receipt['files'] and 'attestations.jsonl' not in receipt['files']
    for name, record in receipt['files'].items():
        assert record == {'sha256': sha((output / name).read_bytes()), 'size': (output / name).stat().st_size}
        assert (output / name).stat().st_mode & 0o777 == 0o444
    assert output.stat().st_mode & 0o777 == 0o700
    assert len(builders.calls) == 9
    assert 'build-packaging-inputs.py' in builders.calls[0][2]
    assert 'build-release-kit.py' in builders.calls[-1][2]
    docker = [args for args in builders.calls if args[0] == 'docker']
    assert len(docker) == 2
    for args in docker:
        assert args[args.index('--platform') + 1] == 'linux/amd64'
        assert args[args.index('--builder') + 1] == 'native-builder'
        assert 'org.opencontainers.image.revision=' + repository[1] in args
        assert '--load' not in args and '--push' not in args
    neutral = builders.calls[-2]
    assert neutral[-1] == '--neutral-trust'
    assert '--instruction-roots-dir' not in neutral
    for env in builders.environments:
        assert env['BUILDX_BUILDER'] == 'native-builder'
        assert env['GIT_NO_REPLACE_OBJECTS'] == env['GIT_NO_LAZY_FETCH'] == '1'
        assert env['GIT_ALLOW_PROTOCOL'] == ''
        assert env['PYTHONNOUSERSITE'] == '1'
        assert not any(name.startswith(('IRIS_', 'ARIA2C_', 'SCRUB_')) for name in env)
        assert 'PYTHONPATH' not in env and 'BASH_ENV' not in env and 'GIT_CONFIG_COUNT' not in env
    assert not builders.source.parent.exists()


def test_dirty_owner_and_ignored_credentials_and_release_are_preserved(tmp_path, repository):
    repo, commit, files = repository
    (repo / 'source.txt').write_bytes(b'owner uncommitted edits')
    (repo / 'creds').mkdir()
    (repo / 'creds/private').write_text('ignored credential sentinel')
    (repo / 'release').mkdir()
    (repo / 'release/iris.tgz').write_text('owner previous release sentinel')
    before = git(repo, 'status', '--porcelain=v1', '--untracked-files=all')
    refs = git(repo, 'show-ref')
    assemble(tmp_path, repository)
    assert (repo / 'source.txt').read_bytes() == b'owner uncommitted edits'
    assert (repo / 'creds/private').read_text() == 'ignored credential sentinel'
    assert (repo / 'release/iris.tgz').read_text() == 'owner previous release sentinel'
    assert git(repo, 'status', '--porcelain=v1', '--untracked-files=all') == before
    assert git(repo, 'show-ref') == refs
    assert git(repo, 'rev-parse', 'HEAD') == commit


def test_owner_filters_hooks_and_replacement_refs_do_not_execute_or_change_snapshot(tmp_path, repository):
    repo, commit, files = repository
    (repo / '.gitattributes').write_text('*.txt filter=unsafe\n')
    git(repo, 'add', '.gitattributes')
    git(repo, 'commit', '-m', 'Declare filter without copying owner configuration')
    commit = git(repo, 'rev-parse', 'HEAD')
    files = {**files, '.gitattributes': b'*.txt filter=unsafe\n'}
    marker = tmp_path / 'must-not-execute'
    git(repo, 'config', 'filter.unsafe.smudge', 'touch ' + str(marker))
    git(repo, 'config', 'filter.unsafe.clean', 'cat')
    git(repo, 'config', 'filter.unsafe.required', 'true')
    hook = repo / '.git/hooks/post-checkout'
    hook.write_text('#!/bin/sh\ntouch ' + str(marker) + '\n')
    hook.chmod(0o755)
    (repo / 'source.txt').write_text('replacement source')
    git(repo, 'add', 'source.txt')
    git(repo, 'commit', '-m', 'Different replacement')
    git(repo, 'replace', commit, git(repo, 'rev-parse', 'HEAD'))
    assemble(tmp_path, (repo, commit, files))
    assert not marker.exists()


@pytest.mark.parametrize('change', ['package-checksum', 'package-commit', 'installed-bytes', 'installed-mode',
    'installed-extra', 'installed-link', 'source-omission', 'source-bytes', 'source-mode', 'late-failure',
    'unexpected-asset', 'kit-identity', 'tracked-mutation'])
def test_bad_or_failed_builder_never_publishes(tmp_path, repository, change):
    builders = Builders(repository[1], repository[2], change)
    with pytest.raises((InstallError, OSError)):
        assemble(tmp_path, repository, builders=builders)
    assert not (tmp_path / 'candidate').exists()
    assert not builders.source.parent.exists()
    if change.startswith(('package-', 'installed-', 'source-')):
        assert not any(args[0] == 'docker' for args in builders.calls)


@pytest.mark.parametrize('target', ['existing-directory', 'existing-file', 'symlink'])
def test_existing_output_never_runs_builds_or_changes_owner_bytes(tmp_path, repository, target):
    output = tmp_path / 'candidate'
    if target == 'existing-directory':
        output.mkdir()
        (output / 'sentinel').write_text('owner')
    elif target == 'existing-file':
        output.write_text('owner')
    else:
        output.symlink_to(tmp_path / 'not-created')
    with pytest.raises(InstallError, match='already exists|symbolic links'):
        assemble(tmp_path, repository, builders=lambda *_a, **_k: pytest.fail('must not build'))
    assert output.is_symlink() if target == 'symlink' else (output / 'sentinel' if output.is_dir() else output).read_text() == 'owner'


@pytest.mark.parametrize('commit', ['HEAD', 'a' * 12, 'A' * 40, 'a' * 40 + '\n', '0' * 40])
def test_nonexact_or_missing_commit_refuses_before_builds(tmp_path, repository, commit):
    with pytest.raises(InstallError):
        c.assemble(repository[0], tmp_path / 'candidate', commit=commit, tag=TAG,
                   appmgr_repository=repository[0], runner=lambda *_a, **_k: pytest.fail('must not build'))
    assert not (tmp_path / 'candidate').exists()


def test_tag_mismatch_refuses_before_builds(tmp_path, repository):
    with pytest.raises(InstallError, match='VERSION'):
        c.assemble(repository[0], tmp_path / 'candidate', commit=repository[1], tag='v2026.10.08',
                   appmgr_repository=repository[0], runner=lambda *_a, **_k: pytest.fail('must not build'))


def test_committed_link_refuses_before_checkout_or_builder(tmp_path, repository):
    repo, _, _ = repository
    (repo / 'link').symlink_to('/etc/passwd')
    git(repo, 'add', 'link')
    git(repo, 'commit', '-m', 'Unsupported link')
    with pytest.raises(InstallError, match='regular files'):
        c.assemble(repo, tmp_path / 'candidate', commit=git(repo, 'rev-parse', 'HEAD'), tag=TAG,
                   appmgr_repository=repo, runner=lambda *_a, **_k: pytest.fail('must not build'))


def test_partial_source_never_lazily_fetches_missing_blobs_or_mutates_owner(tmp_path, repository):
    repo, commit, _ = repository
    git(repo, 'config', 'uploadpack.allowFilter', 'true')
    partial = tmp_path / 'partial'
    subprocess.run(['git', 'clone', '--filter=blob:none', '--no-checkout',
                    repo.as_uri(), str(partial)], check=True, capture_output=True)
    packs = partial / '.git/objects/pack'
    assert list(packs.glob('*.promisor'))
    before = {path.name: path.read_bytes() for path in packs.iterdir()}
    with pytest.raises(InstallError, match='exact local committed source'):
        c.assemble(partial, tmp_path / 'candidate', commit=commit, tag=TAG,
                   appmgr_repository=repo, runner=lambda *_a, **_k: pytest.fail('must not build'))
    assert {path.name: path.read_bytes() for path in packs.iterdir()} == before
    assert not (tmp_path / 'candidate').exists()


@pytest.mark.parametrize('kind', ['silent', 'over-limit'])
def test_git_deadline_and_output_limit_terminate_the_owned_child(tmp_path, monkeypatch, kind):
    original, children = subprocess.Popen, []
    code = 'import time; time.sleep(30)' if kind == 'silent' else (
        'import sys,time; sys.stdout.buffer.write(b"x"*2048); sys.stdout.flush(); time.sleep(30)')
    def child(_command, **kwargs):
        process = original([sys.executable, '-c', code], **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(c.subprocess, 'Popen', child)
    monkeypatch.setattr(c, 'GIT_SECONDS', 0.1)
    monkeypatch.setattr(c, 'MAX_TREE', 1024)
    started = time.monotonic()
    with pytest.raises(InstallError, match='deadline' if kind == 'silent' else 'metadata exceeds'):
        c._git(tmp_path, ['irrelevant'], dict(os.environ))
    assert time.monotonic() - started < 3
    assert len(children) == 1 and children[0].poll() is not None


def test_uncommitted_required_helper_cannot_be_built(tmp_path, repository):
    repo, _, _ = repository
    git(repo, 'rm', 'tools/build-release-candidate.py')
    git(repo, 'commit', '-m', 'Commit without candidate helper')
    with pytest.raises(InstallError, match='omits'):
        c.assemble(repo, tmp_path / 'candidate', commit=git(repo, 'rev-parse', 'HEAD'), tag=TAG,
                   appmgr_repository=repo, runner=lambda *_a, **_k: pytest.fail('must not build'))


def test_checkout_transform_is_detected_before_any_builder(tmp_path, repository, monkeypatch):
    original = c._git
    def changed(repo, arguments, environment):
        result = original(repo, arguments, environment)
        if 'checkout' in arguments:
            (repo / 'source.txt').write_text('transformed bytes')
        return result
    monkeypatch.setattr(c, '_git', changed)
    with pytest.raises(InstallError, match='checkout bytes'):
        assemble(tmp_path, repository, builders=lambda *_a, **_k: pytest.fail('must not build'))


def test_optional_closure_is_snapshotted_before_use(tmp_path, repository, monkeypatch):
    from iris_installer import offline_inputs
    original = tmp_path / 'closure.tar.gz'
    original.write_bytes(b'closure candidate')
    checked = []
    def inspect(path):
        assert path != original and path.read_bytes() == b'closure candidate'
        original.write_bytes(b'changed original')
        checked.append(path)
    monkeypatch.setattr(offline_inputs, 'inspect_dependency_archive', inspect)
    output, builders = assemble(tmp_path, repository, ubuntu_dependencies=original)
    assert len(checked) == 1
    assert (output / 'iris-ubuntu-dependencies.tar.gz').read_bytes() == b'closure candidate'
    assert json.loads((output / 'local-candidate.json').read_bytes())['profile'] == 'ubuntu-dependencies'


@pytest.fixture
def companions(source_repository, tmp_path, monkeypatch):
    from iris_installer import offline_dependencies, offline_sources
    monkeypatch.setattr(offline_dependencies, 'ROOT_PACKAGES', frozenset(('age',)))
    binary = source_repository.base / 'binary'
    dependency = tmp_path / 'dependencies.tar.gz'
    with tarfile.open(dependency, 'w:gz') as archive:
        for path in sorted(binary.rglob('*')):
            if path.is_file():
                archive.add(path, arcname=str(path.relative_to(binary)))
    source = tmp_path / 'sources.tar.gz'
    offline_sources.build_sources(binary, source_repository.digest, source_repository.indexes,
        source_repository.base / 'pool', source, keyring=source_repository.keyring)
    validate = offline_sources.validate_source_archive
    def verify(archive, payload, digest):
        return validate(archive, payload, digest, keyring=source_repository.keyring)
    monkeypatch.setattr(offline_sources, 'validate_source_archive', verify)
    return dependency, source, source_repository.digest


def test_source_companion_requires_dependency_archive_before_workspace(tmp_path, repository, monkeypatch):
    monkeypatch.setattr(c, '_publication', lambda *a: pytest.fail('Invalid pairing created a workspace'))
    with pytest.raises(InstallError, match='requires --ubuntu-dependencies'):
        assemble(tmp_path, repository, ubuntu_sources=tmp_path / 'source.tar.gz')


def test_real_source_companion_is_verified_before_builders_and_is_not_a_kit_role(tmp_path, repository, companions):
    dependency, source, digest = companions
    builders = Builders(repository[1], repository[2])
    def run(arguments, **kwargs):
        private = kwargs['cwd'].parent
        assert (private / 'ubuntu-dependency-payload/dependency-manifest.json').is_file()
        assert (private / 'ubuntu-sources.tar.gz').read_bytes() == source.read_bytes()
        assert '--ubuntu-sources' not in list(map(str, arguments))
        builders(arguments, **kwargs)
    output, _ = assemble(tmp_path, repository, builders=run, ubuntu_dependencies=dependency, ubuntu_sources=source)
    receipt = json.loads((output / 'local-candidate.json').read_bytes())
    assert receipt['authenticated'] is False
    assert receipt['profile'] == 'ubuntu-dependencies'
    assert receipt['ubuntu_source_coverage'] == {
        'format': 'iris-local-ubuntu-source-coverage-v1', 'binary_manifest_sha256': digest,
        'dependency_archive_sha256': sha(dependency.read_bytes()), 'companion_archive_sha256': sha(source.read_bytes()),
        'asset': c.UBUNTU_SOURCES_NAME, 'binaries': 1, 'sources': 2}
    assert (output / c.UBUNTU_SOURCES_NAME).read_bytes() == source.read_bytes()
    assert (output / c.UBUNTU_SOURCES_NAME).stat().st_mode & 0o777 == 0o444
    assert c.UBUNTU_SOURCES_NAME in receipt['files']
    assert '--ubuntu-sources' not in builders.calls[-1]


@pytest.mark.parametrize('change', ['wrong-closure', 'incomplete', 'tampered', 'malformed-dependency'])
def test_companion_refusals_precede_all_builders(tmp_path, repository, companions, change):
    from test_installer_offline_sources import archive_bytes, contents
    dependency, source, _ = companions
    if change == 'malformed-dependency':
        dependency.write_bytes(b'not a dependency archive')
    else:
        files = contents(source)
        manifest = json.loads(files['source-manifest.json'])
        if change == 'wrong-closure':
            manifest['binary_manifest_sha256'] = '0' * 64
        elif change == 'incomplete':
            manifest['sources'].pop()
        else:
            files['README.txt'] = b'changed notice instructions'
        files['source-manifest.json'] = json.dumps(manifest).encode()
        source.write_bytes(archive_bytes(files))
    with pytest.raises((InstallError, OSError, tarfile.TarError)):
        assemble(tmp_path, repository, ubuntu_dependencies=dependency, ubuntu_sources=source,
                 builders=lambda *a, **kw: pytest.fail('Invalid companion reached a builder'))
    assert not (tmp_path / 'candidate').exists()


def test_both_ubuntu_inputs_are_snapshotted_before_validation(tmp_path, monkeypatch):
    from iris_installer import offline_inputs, offline_sources
    dependency, source, work = tmp_path / 'deps.tar.gz', tmp_path / 'sources.tar.gz', tmp_path / 'work'
    dependency.write_bytes(b'original dependencies')
    source.write_bytes(b'original sources')
    work.mkdir(mode=0o700)
    calls = []
    def inspect(path, *, destination):
        assert path == work / 'ubuntu-dependencies.tar.gz'
        assert path.read_bytes() == b'original dependencies'
        assert (work / 'ubuntu-sources.tar.gz').read_bytes() == b'original sources'
        dependency.write_bytes(b'changed original dependencies')
        source.write_bytes(b'changed original sources')
        destination.mkdir()
        calls.append('extract')
        return {'manifest_sha256': 'a' * 64}
    def validate(path, payload, digest):
        assert calls == ['extract'] and digest == 'a' * 64
        assert path.read_bytes() == b'original sources'
        assert payload == work / 'ubuntu-dependency-payload'
        calls.append('validate')
        return {'binaries': [{}], 'sources': [{}, {}]}
    monkeypatch.setattr(offline_inputs, 'inspect_dependency_archive', inspect)
    monkeypatch.setattr(offline_sources, 'validate_source_archive', validate)
    private_dependency, private_source, proof = c._prepare_ubuntu_inputs(work, dependency, source)
    assert private_dependency.read_bytes() == b'original dependencies'
    assert private_source.read_bytes() == b'original sources'
    assert proof['dependency_archive_sha256'] == sha(b'original dependencies')
    assert proof['companion_archive_sha256'] == sha(b'original sources')
    assert calls == ['extract', 'validate']


@pytest.mark.parametrize('filename', ['ubuntu-sources.tar.gz', 'ubuntu-dependencies.tar.gz'])
def test_ubuntu_inputs_cannot_change_after_coverage_validation(tmp_path, repository, companions, filename):
    dependency, source, _ = companions
    builders = Builders(repository[1], repository[2])
    def run(arguments, **kwargs):
        builders(arguments, **kwargs)
        if str(arguments[0]) == 'docker':
            (kwargs['cwd'].parent / filename).write_bytes(b'changed after source validation')
    with pytest.raises(InstallError, match='changed after independent'):
        assemble(tmp_path, repository, ubuntu_dependencies=dependency, ubuntu_sources=source, builders=run)
    assert not (tmp_path / 'candidate').exists()


def test_publication_race_preserves_new_owner_directory(tmp_path, repository, monkeypatch):
    original = c.kit._snapshot
    def racing(source, destination, maximum):
        result = original(source, destination, maximum)
        if '/proc/self/fd/' in str(destination) and not (tmp_path / 'candidate').exists():
            (tmp_path / 'candidate').mkdir()
            (tmp_path / 'candidate/sentinel').write_text('owner')
        return result
    monkeypatch.setattr(c.kit, '_snapshot', racing)
    with pytest.raises(InstallError, match='already exists'):
        assemble(tmp_path, repository)
    assert (tmp_path / 'candidate/sentinel').read_text() == 'owner'
    assert set((tmp_path / 'candidate').iterdir()) == {tmp_path / 'candidate/sentinel'}


@pytest.fixture
def aria_repository(tmp_path, repository):
    repo, _, files = repository
    archive = tmp_path / 'supplied-aria-source.tar.gz'
    archive.write_bytes(b'reviewed exact aria source archive fixture')
    name = 'aria2c-2.5.6-p10-source.tar.gz'
    binaries = {'x86_64': b'amd64 client', 'aarch64': b'arm64 client'}
    pins = {arch: sha(data) for arch, data in binaries.items()}
    files.update({
        'tools/aria2c-source/source.sha256': (sha(archive.read_bytes()) + '  ' + name + '\n').encode(),
        'tools/aria2c.sha256': ('# Client pins — both architectures\n' + ''.join(
            digest + '  ' + arch + '\n' for arch, digest in pins.items())).encode(),
        'tools/aria2c-source/inputs.json': json.dumps({'binary_sha256': pins}).encode(),
        'bin/aria2c': binaries['x86_64'],
        **{'deliverables/aria2c-' + arch: data for arch, data in binaries.items()},
    })
    for path, data in files.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    git(repo, 'add', '.')
    git(repo, 'commit', '-m', 'Pin fixture aria sources and both clients')
    return (repo, git(repo, 'rev-parse', 'HEAD'), files), archive, name, pins


def test_aria_companion_is_bound_to_both_clients_before_builds(tmp_path, aria_repository):
    repository, archive, name, pins = aria_repository
    original = archive.read_bytes()
    builders = Builders(repository[1], repository[2])
    def run(arguments, **kwargs):
        assert (kwargs['cwd'].parent / name).read_bytes() == original
        archive.write_bytes(b'changed original after snapshot')
        builders(arguments, **kwargs)
    output, _ = assemble(tmp_path, repository, builders=run, aria2_sources=archive)
    record = json.loads((output / 'local-candidate.json').read_bytes())
    assert record['authenticated'] is False
    assert (output / name).read_bytes() == original
    assert (output / name).stat().st_mode & 0o777 == 0o444
    assert record['aria2_source_binding'] == {
        'format': 'iris-local-aria2-source-binding-v1', 'asset': name,
        'archive_sha256': sha(original), 'binary_sha256': pins,
        'inputs_sha256': sha(repository[2]['tools/aria2c-source/inputs.json']),
        'scope': 'committed clients; image embedding and full image source coverage remain separate'}
    assert name in record['files']
    assert all('--aria2-sources' not in args for args in builders.calls)


@pytest.mark.parametrize('change', [
    'wrong-archive', 'archive-symlink', 'archive-hardlink', 'missing-archive',
    'wrong-amd64', 'wrong-arm64', 'wrong-server', 'inputs-mismatch',
    'duplicate-source-pin', 'unsafe-source-name', 'malformed-source-pin',
    'duplicate-binary-pin',
])
def test_aria_companion_refusals_precede_all_builders(tmp_path, aria_repository, change):
    repository, archive, name, _ = aria_repository
    repo, commit, files = repository
    if change == 'wrong-archive':
        archive.write_bytes(b'not the pinned source')
    elif change in ('archive-symlink', 'archive-hardlink'):
        other = tmp_path / 'alias'
        if change == 'archive-symlink':
            other.symlink_to(archive)
        else:
            os.link(archive, other)
        archive = other
    elif change == 'missing-archive':
        archive = tmp_path / 'missing'
    else:
        if change.startswith('wrong-'):
            filename = {'wrong-amd64': 'deliverables/aria2c-x86_64',
                        'wrong-arm64': 'deliverables/aria2c-aarch64',
                        'wrong-server': 'bin/aria2c'}[change]
            (repo / filename).write_bytes(b'changed binary')
        elif change == 'inputs-mismatch':
            (repo / 'tools/aria2c-source/inputs.json').write_text('{"binary_sha256": {}}')
        elif change == 'duplicate-binary-pin':
            path = repo / 'tools/aria2c.sha256'
            duplicate = next(line for line in path.read_text().splitlines() if not line.startswith('#'))
            path.write_text(path.read_text() + duplicate + '\n')
        else:
            path = repo / 'tools/aria2c-source/source.sha256'
            value = path.read_text()
            path.write_text(value + value if change == 'duplicate-source-pin'
                else value.replace(name, '../' + name) if change == 'unsafe-source-name'
                else 'not-a-digest ' + name + '\n')
        git(repo, 'add', '.')
        git(repo, 'commit', '-m', 'Invalid committed source binding fixture')
        commit = git(repo, 'rev-parse', 'HEAD')
    with pytest.raises((InstallError, OSError, ValueError)):
        c.assemble(repo, tmp_path / 'candidate', commit=commit, tag=TAG,
                   appmgr_repository=repo, aria2_sources=archive,
                   runner=lambda *a, **k: pytest.fail('Invalid aria source reached a builder'))
    assert not (tmp_path / 'candidate').exists()


@pytest.mark.parametrize('location', ['private', 'candidate-asset'])
def test_aria_companion_cannot_drift_after_pin_validation(tmp_path, aria_repository, monkeypatch, location):
    repository, archive, name, _ = aria_repository
    builders = Builders(repository[1], repository[2])
    def run(arguments, **kwargs):
        builders(arguments, **kwargs)
        if location == 'private' and str(arguments[0]) == 'docker':
            (kwargs['cwd'].parent / name).write_bytes(b'changed private source')
    original = c.kit._snapshot
    def snapshot(source, destination, maximum):
        result = original(source, destination, maximum)
        if location == 'candidate-asset' and destination.parent.name == 'assets' and destination.name == name:
            destination.write_bytes(b'changed candidate source')
        return result
    monkeypatch.setattr(c.kit, '_snapshot', snapshot)
    with pytest.raises(InstallError, match='changed after'):
        assemble(tmp_path, repository, builders=run, aria2_sources=archive)
    assert not (tmp_path / 'candidate').exists()


def test_publication_parent_replacement_never_cleans_replacement(tmp_path, repository, monkeypatch):
    parent = tmp_path / 'output-parent'
    parent.mkdir(mode=0o700)
    original = c.kit._snapshot
    changed = False
    def substituted(source, destination, maximum):
        nonlocal changed
        result = original(source, destination, maximum)
        if '/proc/self/fd/' in str(destination) and not changed:
            changed = True
            temporary_name = destination.parent.name
            parent.rename(tmp_path / 'original-parent')
            parent.mkdir(mode=0o700)
            replacement = parent / temporary_name
            replacement.mkdir()
            (replacement / 'sentinel').write_text('owner')
        return result
    monkeypatch.setattr(c.kit, '_snapshot', substituted)
    with pytest.raises(InstallError, match='parent changed'):
        c.assemble(repository[0], parent / 'candidate', commit=repository[1], tag=TAG,
                   appmgr_repository=repository[0], runner=Builders(repository[1], repository[2]))
    assert [p.read_text() for p in parent.glob('*/sentinel')] == ['owner']
    assert not (parent / 'candidate').exists()


def test_helper_is_in_source_allowlist_and_cli_requires_explicit_inputs():
    assert 'tools/build-release-candidate.py' in (ROOT / 'tools/make-release.sh').read_text()
    with pytest.raises(SystemExit) as caught:
        c.main([])
    assert caught.value.code == 2
