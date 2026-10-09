# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Build-free local fixtures: no image builder, package install or network."""

from copy import deepcopy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import candidate_evidence as subject, offline_bootstrap, release_kit as kit
from iris_installer.state import InstallError


TAG, COMMIT = 'v2026.10.09', 'a' * 40


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def encoded(value):
    return subject.canonical(value)


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:', format=tarfile.USTAR_FORMAT) as stream:
        for name, raw in entries.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(raw)
            stream.addfile(member, io.BytesIO(raw))
    return output.getvalue()


@pytest.fixture
def candidate(tmp_path):
    tmp_path.chmod(0o700)
    directory = tmp_path / 'candidate'
    directory.mkdir(mode=0o700)
    companion = b'exact aria source archive'
    clients = {'x86_64': b'amd64 client', 'aarch64': b'arm64 client'}
    pins = {name: sha(raw) for name, raw in clients.items()}
    source = {'VERSION': TAG[1:].encode() + b'\n', 'LICENSE': b'license\n',
              'docs/dev/installer.md': b'guide\n', 'tools/irisctl': b'controller\n',
              'tools/iris-key-setup': b'key helper\n', 'tools/iris_installer/__init__.py': b'# module\n',
              'bin/.gitkeep': b'', 'bin/aria2c': clients['x86_64'],
              **{'deliverables/aria2c-' + name: raw for name, raw in clients.items()},
              'tools/aria2c.sha256': ''.join(digest + '  ' + name + '\n' for name, digest in pins.items()).encode(),
              'tools/aria2c-source/inputs.json': encoded({'binary_sha256': pins}),
              'tools/aria2c-source/source.sha256': (sha(companion) + '  aria2c-fixture-source.tar.gz\n').encode()}
    inventory = {name: sha(raw) for name, raw in source.items()}
    payload = tmp_path / 'payload'
    for name, raw in source.items():
        write(payload / offline_bootstrap.SOURCE / name, raw)
    write(payload / offline_bootstrap.SOURCE / 'INSTALLER-SOURCE.json', encoded(inventory))
    copies = {offline_bootstrap.LIB + '/irisctl': 'tools/irisctl',
              offline_bootstrap.LIB + '/iris-key-setup': 'tools/iris-key-setup',
              offline_bootstrap.LIB + '/iris_installer/__init__.py': 'tools/iris_installer/__init__.py',
              'usr/share/doc/iris-installer/copyright': 'LICENSE',
              'usr/share/doc/iris-installer/README.md': 'docs/dev/installer.md'}
    for name, original in copies.items():
        write(payload / name, source[original])
    for name, target in offline_bootstrap.LINKS.items():
        (payload / name).parent.mkdir(parents=True, exist_ok=True)
        (payload / name).symlink_to(target)
    package = 'iris-installer_' + TAG[1:] + '+installer.0.g' + COMMIT[:12] + '_amd64.deb'
    control = ('Package: iris-installer\nVersion: ' + TAG[1:] + '+installer.0.g' + COMMIT[:12]
               + '\nArchitecture: amd64\nMaintainer: fixture\nSection: admin\nPriority: optional\n'
               'Depends: python3 (>= 3.12), age, ca-certificates, openssh-client\nDescription: fixture\n')
    write(payload / 'DEBIAN/control', control.encode())
    for path in payload.rglob('*'):
        if path.is_dir():
            path.chmod(0o755)
    subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(payload), str(directory / package)],
                   check=True, stdout=subprocess.DEVNULL)
    write(directory / (package + '.sha256'), (sha((directory / package).read_bytes()) + '  ' + package + '\n').encode())
    write(directory / (package + '.source.json'), encoded({'schema': 1, 'commit': COMMIT, 'files': inventory}))
    source_tar = archive({'iris/' + name: raw for name, raw in source.items()})
    write(directory / 'iris.tgz', gzip.compress(source_tar, mtime=0))
    assets = {}
    for role in sorted(kit.ROLES):
        image = role in kit.IMAGES
        name = 'iris.tgz' if role == 'source' else role + ('.tar' if image else '.tar.gz')
        if role != 'source':
            write(directory / name, ('fixture ' + role).encode())
        row = {'name': name, **subject._file(directory / name),
               'format': 'oci-archive' if role == 'device-runtime' else 'docker-archive' if image else 'tar.gz'}
        if image:
            row.update(platforms=['linux/amd64', 'linux/arm64'] if role == 'device-runtime' else ['linux/amd64'],
                       image_digest='sha256:' + 'c' * 64)
        if role == 'device-runtime':
            row['neutral_source_sha256'] = 'd' * 64
        assets[role] = row
    write(directory / 'device-runtime.tar.manifest', b'neutral metadata')
    auth = kit._auth()
    release = {'schema': kit.SCHEMA, 'repository': auth.REPOSITORY, 'workflow': auth.WORKFLOW,
               'tag': TAG, 'commit': COMMIT, 'host': kit.HOST, 'profile': 'prepared-host', 'assets': assets}
    write(directory / 'release-kit.json', encoded(release))
    value = {'format': 'iris-local-release-candidate-v1', 'authenticated': False, 'scope': 'fixture',
             'tag': TAG, 'commit': COMMIT, 'version': TAG[1:], 'profile': 'prepared-host',
             'source_match': {'canonical_source_matches': False},
             'files': {path.name: subject._file(path) for path in directory.iterdir()}}
    def seal():
        write(directory / subject.ORIGINAL, encoded(value))
        return sha(encoded(value))
    result = SimpleNamespace(directory=directory, value=value, seal=seal, source=source, source_tar=source_tar,
                             package=package, release=release, pins=pins, payload=payload, tmp=tmp_path)
    result.digest = seal()
    for role in ('aria2', 'debian', 'alpine', 'core-python', 'runtime', 'image-notices'):
        path = tmp_path / (role + '-sources.tar.gz')
        write(path, companion if role == 'aria2' else role.encode())
        setattr(result, role.replace('-', '_'), path)
    result.keyring = tmp_path / 'debian-keyring.gpg'
    write(result.keyring, b'external trust')
    return result


def invocation(c):
    return dict(candidate_dir=c.directory, candidate_sha256=c.digest, output_dir=c.tmp / 'output', tag=TAG, commit=COMMIT,
                aria2_sources=c.aria2, debian_sources=c.debian, alpine_sources=c.alpine,
                core_python_sources=c.core_python, runtime_sources=c.runtime, debian_keyring=c.keyring,
                image_notices=c.image_notices, pip_sdist_sha256='e' * 64)


@pytest.fixture
def pipeline(candidate, monkeypatch):
    calls = []
    def image(platform, digest):
        row = {'path': 'opt/iris/bin/aria2c', 'sha256': digest}
        return {'platform': platform, 'config_digest': 'sha256:' + sha(b'{}'),
                'layers': [{'index': 0, 'diff_id': 'sha256:' + 'f' * 64,
                'inventory': {'copied_component_files': [row]}}], 'merged': {'copied_component_files': [row]}}
    inventory = {'images': {'server-image': image('linux/amd64', candidate.pins['x86_64']),
                 'console-image': {'config_digest': 'sha256:' + sha(b'{}')},
                 'device-runtime': {'platforms': [image('linux/amd64', candidate.pins['x86_64']),
                                                  image('linux/arm64', candidate.pins['aarch64'])]}}}
    def images(_candidate, assets, private, work, anchor, descriptor, commit):
        path = work / 'image-components.json'
        write(anchor / path.name, encoded(inventory))
        configs = {}
        for role in ('server-image', 'console-image'):
            configs[role] = work / ('iris-' + role + '-config.json')
            write(anchor / configs[role].name, b'{}')
        return path, sha(encoded(inventory)), inventory, configs
    monkeypatch.setattr(subject, '_images', images)
    def validator(role):
        def check(*arguments, **keywords):
            calls.append((role, arguments, keywords))
            assert arguments[0] not in (candidate.debian, candidate.alpine, candidate.core_python, candidate.runtime)
            candidate_bound = role in ('runtime', 'image-notices')
            assert sha(arguments[3 if candidate_bound else 1].read_bytes()) == arguments[4 if candidate_bound else 2]
            assert keywords.get('archived_integrity') is None
            return {'schema': role + '-fixture', 'scope': role + '-only', 'files': {}}
        return check
    for role, module in [('debian', subject.debian), ('alpine', subject.alpine), ('core-python', subject.core_python)]:
        monkeypatch.setattr(module, 'validate_source_archive', validator(role))
    monkeypatch.setattr(subject, '_validate_runtime', validator('runtime'))
    monkeypatch.setattr(subject, '_validate_notices', validator('image-notices'))
    return SimpleNamespace(candidate=candidate, calls=calls, inventory=inventory)


def test_closed_output_preserves_original_and_disclaims_unproved_authority(pipeline):
    c = pipeline.candidate
    path = subject.assemble(**invocation(c))
    result = kit._json(path.read_bytes())
    assert result['format'] == subject.SCHEMA
    assert result['authenticated'] is result['source_coverage_complete'] is result['rebuild_verified'] is False
    assert result['source_agreement']['git_provenance_verified'] is False
    assert result['remaining_gates'][0] == 'human source-sufficiency and redistribution review'
    assert 'reconstructed image ownership/notice catalog' in result['mechanical_evidence']
    assert result['source_agreement']['canonical_file_count'] == len(c.source)
    assert result['neutral_source_sha256'] == 'd' * 64
    assert result['original_candidate_sha256'] == c.digest
    assert set(p.name for p in path.parent.iterdir()) == {*result['files'], subject.MANIFEST}
    for name, record in result['files'].items():
        assert subject._file(path.parent / name) == record
        assert (path.parent / name).stat().st_mode & 0o777 == 0o444
    for name in [*c.value['files'], subject.ORIGINAL]:
        assert (path.parent / name).read_bytes() == (c.directory / name).read_bytes()
    assert [row[0] for row in pipeline.calls] == ['debian', 'alpine', 'core-python', 'runtime', 'image-notices']
    runtime = pipeline.calls[-2][1]
    assert runtime[2] == c.digest
    assert runtime[6] == sha(c.alpine.read_bytes())
    assert pipeline.calls[0][2]['keyring'] != c.keyring
    assert pipeline.calls[2][2] == {'pip_sdist_sha256': 'e' * 64}
    notices = pipeline.calls[-1][1]
    assert notices[2] == c.digest and notices[4] == result['image_inventory_sha256']
    assert set(notices[5]) == {'debian', 'alpine', 'core-python', 'runtime', 'aria2'}
    for role, reference in notices[5].items():
        assert set(reference) == {'path', 'sha256'}
        original = getattr(c, role.replace('-', '_'))
        assert reference['path'] != original
        assert reference['sha256'] == sha(original.read_bytes())
    assert len(result['companions']['aria2']['observed_image_clients']) == 3


@pytest.mark.parametrize('fault', ['digest', 'commit', 'tag', 'extra', 'missing', 'tamper', 'symlink', 'hardlink',
                                  'null-files', 'boolean-size', 'unknown-field', 'authenticated', 'kit-profile',
                                  'kit-commit', 'source-sidecar', 'deb-checksum', 'tar-mismatch', 'tar-missing',
                                  'aria-source', 'unlisted-asset', 'null-profile'])
def test_candidate_faults_refuse_without_output(pipeline, fault):
    c, kwargs = pipeline.candidate, invocation(pipeline.candidate)
    if fault == 'digest':
        kwargs['candidate_sha256'] = '0' * 64
    elif fault == 'commit':
        kwargs['commit'] = 'b' * 40
    elif fault == 'tag':
        kwargs['tag'] = 'v2026.10.08'
    elif fault == 'extra':
        write(c.directory / 'owner-data', b'preserve')
    elif fault == 'missing':
        (c.directory / 'iris.tgz').unlink()
    elif fault == 'tamper':
        write(c.directory / 'iris.tgz', b'tamper')
    elif fault in ('symlink', 'hardlink'):
        path = c.directory / 'iris.tgz'
        old = c.tmp / 'original.tar.gz'
        path.rename(old)
        path.symlink_to(old) if fault == 'symlink' else os.link(old, path)
    elif fault == 'null-files':
        c.value['files'] = None
    elif fault == 'boolean-size':
        c.value['files']['iris.tgz']['size'] = True
    elif fault == 'unknown-field':
        c.value['trusted'] = True
    elif fault == 'authenticated':
        c.value['authenticated'] = True
    elif fault == 'null-profile':
        c.value['profile'] = None
    elif fault in ('kit-profile', 'kit-commit'):
        c.release['profile' if fault == 'kit-profile' else 'commit'] = 'ubuntu-dependencies' if fault == 'kit-profile' else 'b' * 40
        write(c.directory / 'release-kit.json', encoded(c.release))
        c.value['files']['release-kit.json'] = subject._file(c.directory / 'release-kit.json')
    elif fault in ('source-sidecar', 'deb-checksum'):
        name = c.package + ('.source.json' if fault == 'source-sidecar' else '.sha256')
        write(c.directory / name, b'{}' if fault == 'source-sidecar' else b'bad\n')
        c.value['files'][name] = subject._file(c.directory / name)
    elif fault in ('tar-mismatch', 'tar-missing'):
        source = dict(c.source)
        if fault == 'tar-mismatch':
            source['LICENSE'] = b'changed'
        else:
            del source['LICENSE']
        write(c.directory / 'iris.tgz', gzip.compress(archive({'iris/' + n: raw for n, raw in source.items()})))
        c.value['files']['iris.tgz'] = subject._file(c.directory / 'iris.tgz')
        c.release['assets']['source'].update(c.value['files']['iris.tgz'])
        write(c.directory / 'release-kit.json', encoded(c.release))
        c.value['files']['release-kit.json'] = subject._file(c.directory / 'release-kit.json')
    elif fault == 'aria-source':
        write(c.aria2, b'changed')
    elif fault == 'unlisted-asset':
        write(c.directory / 'extra-source.tar.gz', b'extra')
        c.value['files']['extra-source.tar.gz'] = subject._file(c.directory / 'extra-source.tar.gz')
    if fault not in ('digest', 'commit', 'tag'):
        kwargs['candidate_sha256'] = c.seal()
    with pytest.raises((InstallError, OSError, ValueError)):
        subject.assemble(**kwargs)
    assert not kwargs['output_dir'].exists()


@pytest.mark.parametrize('role', ['debian', 'alpine', 'core-python', 'runtime', 'image-notices'])
def test_every_companion_is_required_and_independently_validated(pipeline, monkeypatch, role):
    def refuse(*args, **kwargs):
        raise InstallError('independent validator refuses')
    if role in ('runtime', 'image-notices'):
        monkeypatch.setattr(subject, '_validate_runtime' if role == 'runtime' else '_validate_notices', refuse)
    else:
        monkeypatch.setattr({'debian': subject.debian, 'alpine': subject.alpine,
                             'core-python': subject.core_python}[role], 'validate_source_archive', refuse)
    with pytest.raises(InstallError, match='independent validator'):
        subject.assemble(**invocation(pipeline.candidate))
    assert not (pipeline.candidate.tmp / 'output').exists()


@pytest.mark.parametrize('kind', ['tail', 'truncated-gzip', 'truncated-tar', 'traversal', 'duplicate', 'ancestor-file',
                                  'extra-file', 'nonempty-marker', 'extra-directory', 'directory-data'])
def test_source_archive_closed_termination_and_namespace(candidate, kind):
    raw = candidate.source_tar
    if kind == 'tail':
        raw += archive({'hidden': b'payload'})
    elif kind == 'truncated-tar':
        raw = raw[:512]
    elif kind == 'traversal':
        raw = archive({'iris/../escape': b'bad'})
    elif kind == 'duplicate':
        raw = raw[:raw.find(b'\0' * 1024)] + raw
    elif kind == 'ancestor-file':
        raw = archive({'iris/file': b'x', 'iris/file/child': b'x'})
    elif kind in ('extra-file', 'nonempty-marker'):
        raw = archive({**{'iris/' + n: b for n, b in candidate.source.items()},
                       'iris/' + ('unreviewed.py' if kind == 'extra-file' else 'artifacts/.gitkeep'): b'x'})
    elif kind in ('extra-directory', 'directory-data'):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:') as stream:
            for name, body in candidate.source.items():
                member = tarfile.TarInfo('iris/' + name)
                member.mode, member.size = 0o644, len(body)
                stream.addfile(member, io.BytesIO(body))
            member = tarfile.TarInfo('iris/unlisted' if kind == 'extra-directory' else 'iris/tools')
            member.type, member.mode = tarfile.DIRTYPE, 0o755
            member.size = 1 if kind == 'directory-data' else 0
            stream.addfile(member, io.BytesIO(b'x') if member.size else None)
        raw = output.getvalue()
    compressed = gzip.compress(raw)
    if kind == 'truncated-gzip':
        compressed = compressed[:-5]
    path = candidate.tmp / 'bad.tar.gz'
    write(path, compressed)
    package = {'source': {n: sha(b) for n, b in candidate.source.items()}, 'files': {
        offline_bootstrap.SOURCE + n: {'size': len(b), 'mode': 0o644} for n, b in candidate.source.items()}}
    with pytest.raises((InstallError, tarfile.TarError, EOFError)):
        subject._source_archive(path, package)


@pytest.mark.parametrize('fault', ['retained', 'merged', 'missing'])
def test_aria_inventory_checks_retained_and_final_bytes(pipeline, fault):
    image = pipeline.inventory['images']['device-runtime']['platforms'][1]
    if fault == 'missing':
        image['layers'][0]['inventory']['copied_component_files'].clear()
    elif fault == 'retained':
        image['layers'][0]['inventory']['copied_component_files'] = [{'path': 'opt/iris/bin/aria2c', 'sha256': '0' * 64}]
    else:
        image['merged']['copied_component_files'] = [{'path': 'opt/iris/bin/aria2c', 'sha256': '0' * 64}]
    with pytest.raises(InstallError, match='aria2'):
        subject.assemble(**invocation(pipeline.candidate))


def test_optional_ubuntu_companion_refuses_prepared_profile_before_validation(pipeline):
    kwargs = invocation(pipeline.candidate)
    kwargs['ubuntu_sources'] = pipeline.candidate.debian
    with pytest.raises(InstallError, match='profile'):
        subject.assemble(**kwargs)
    assert not pipeline.calls


@pytest.mark.parametrize('missing', [False, True])
def test_ubuntu_profile_binds_inner_manifest_and_source_validation(pipeline, monkeypatch, missing):
    c = pipeline.candidate
    name = 'iris-ubuntu-dependencies.tar.gz'
    write(c.directory / name, b'closure')
    inner = '1' * 64
    c.value['profile'] = c.release['profile'] = 'ubuntu-dependencies'
    c.value['files'][name] = subject._file(c.directory / name)
    c.release['assets']['ubuntu-dependencies'] = {'name': name, **c.value['files'][name],
        'format': 'tar.gz', 'dependency_manifest_sha256': inner}
    write(c.directory / 'release-kit.json', encoded(c.release))
    c.value['files']['release-kit.json'] = subject._file(c.directory / 'release-kit.json')
    c.digest = c.seal()
    kwargs, called = invocation(c), []
    def inspect(path, **keywords):
        assert path.read_bytes() == b'closure'
        assert keywords['expected_manifest_sha256'] == inner
        keywords['destination'].mkdir()
        called.append('inspect')
    def validate(path, closure, expected):
        assert called == ['inspect'] and closure.is_dir() and expected == inner
        assert path != c.debian and path.read_bytes() == b'debian'
        called.append('validate')
        return {'scope': 'exact Ubuntu fixture', 'binary_manifest_sha256': expected}
    monkeypatch.setattr(subject.offline_inputs, 'inspect_dependency_archive', inspect)
    monkeypatch.setattr(subject.offline_sources, 'validate_source_archive', validate)
    if missing:
        with pytest.raises(InstallError, match='requires its source companion'):
            subject.assemble(**kwargs)
        assert not called and not pipeline.calls
    else:
        kwargs['ubuntu_sources'] = c.debian
        result = kit._json(subject.assemble(**kwargs).read_bytes())
        assert called == ['inspect', 'validate']
        assert result['companions']['ubuntu']['asset'] == subject.COMPANIONS['ubuntu']
        assert result['files'][subject.COMPANIONS['ubuntu']]['sha256'] == sha(b'debian')


def test_original_unselected_aria_companion_refuses(pipeline):
    c = pipeline.candidate
    name = 'aria2c-unselected-source.tar.gz'
    write(c.directory / name, b'unvalidated companion')
    c.value['files'][name] = subject._file(c.directory / name)
    c.digest = c.seal()
    with pytest.raises(InstallError, match='unselected aria2'):
        subject.assemble(**invocation(c))
    assert not pipeline.calls


def test_original_selected_companion_is_preserved_only_when_identical(pipeline):
    c = pipeline.candidate
    name = 'aria2c-fixture-source.tar.gz'
    write(c.directory / name, c.aria2.read_bytes())
    c.value['files'][name] = subject._file(c.directory / name)
    c.digest = c.seal()
    result = subject.assemble(**invocation(c))
    assert (result.parent / name).read_bytes() == c.aria2.read_bytes()


def test_original_selected_companion_cannot_be_silently_replaced(pipeline):
    c = pipeline.candidate
    name = 'aria2c-fixture-source.tar.gz'
    write(c.directory / name, b'other bytes')
    c.value['files'][name] = subject._file(c.directory / name)
    c.digest = c.seal()
    with pytest.raises(InstallError, match='replace different original'):
        subject.assemble(**invocation(c))


def test_workspace_replacement_preserves_foreign_sentinel(pipeline, monkeypatch):
    original = subject._images
    substitutions = []
    def replaced(*args):
        result = original(*args)
        work = args[3]
        moved = work.with_name(work.name + '-held')
        work.rename(moved)
        work.mkdir(mode=0o700)
        write(work / 'owner-sentinel', b'preserve')
        substitutions.append((work, moved))
        return result
    monkeypatch.setattr(subject, '_images', replaced)
    try:
        with pytest.raises((InstallError, OSError)):
            subject.assemble(**invocation(pipeline.candidate))
        work, moved = substitutions[0]
        assert (work / 'owner-sentinel').read_bytes() == b'preserve'
        assert set(work.iterdir()) == {work / 'owner-sentinel'}
        assert not list(moved.iterdir())
        assert not (pipeline.candidate.tmp / 'output').exists()
    finally:
        for work, moved in substitutions:
            shutil.rmtree(work)
            moved.rmdir()


def test_output_parent_replacement_preserves_foreign_sentinel(pipeline, monkeypatch):
    c = pipeline.candidate
    original = subject._validate_runtime
    moved = c.tmp.with_name(c.tmp.name + '-held')
    def replaced(*args):
        result = original(*args)
        c.tmp.rename(moved)
        c.tmp.mkdir(mode=0o700)
        write(c.tmp / 'owner-sentinel', b'preserve')
        return result
    monkeypatch.setattr(subject, '_validate_runtime', replaced)
    try:
        with pytest.raises(InstallError, match='parent changed'):
            subject.assemble(**invocation(c))
        assert (c.tmp / 'owner-sentinel').read_bytes() == b'preserve'
        assert set(c.tmp.iterdir()) == {c.tmp / 'owner-sentinel'}
        assert not (moved / 'output').exists()
    finally:
        shutil.rmtree(c.tmp)
        moved.rename(c.tmp)


def test_output_is_absent_only_and_owner_bytes_survive(pipeline):
    output = pipeline.candidate.tmp / 'output'
    output.mkdir()
    write(output / 'owner-data', b'preserve')
    with pytest.raises(InstallError, match='already exists'):
        subject.assemble(**invocation(pipeline.candidate))
    assert (output / 'owner-data').read_bytes() == b'preserve'


def test_no_builder_or_candidate_program_is_executed(pipeline, monkeypatch):
    original = subprocess.Popen
    commands = []
    def guarded(command, *args, **kwargs):
        commands.append(command)
        assert command[0] == '/usr/bin/dpkg-deb'
        assert command[1] in ('--fsys-tarfile', '--ctrl-tarfile')
        return original(command, *args, **kwargs)
    monkeypatch.setattr(subprocess, 'Popen', guarded)
    subject.assemble(**invocation(pipeline.candidate))
    assert len(commands) == 2


def test_cli_malformed_input_has_concise_failure(candidate, capsys):
    kwargs = invocation(candidate)
    kwargs['candidate_sha256'] = 'invalid'
    arguments = [item for key, value in kwargs.items() for item in ('--' + key.replace('_', '-'), str(value))]
    with pytest.raises(SystemExit) as stopped:
        subject.main(arguments)
    assert stopped.value.code == 1
    message = capsys.readouterr().err
    assert 'validation failed' in message and 'Traceback' not in message


@pytest.mark.parametrize('fault', [None, 'core-digest', 'config-bytes', 'neutral-index', 'neutral-source', 'neutral-sidecar'])
def test_recomputed_inventory_raw_configs_and_original_neutral_context(candidate, monkeypatch, fault):
    c = candidate
    assets = {}
    inventory = {'images': {}}
    for role in ('server-image', 'console-image'):
        raw = encoded({'architecture': 'amd64', 'os': 'linux', 'config': {'Labels': {'revision': COMMIT}}})
        digest = 'sha256:' + sha(raw)
        path = c.directory / (role + '.tar')
        write(path, archive({'manifest.json': encoded([{'Config': 'config.json', 'Layers': []}]),
                             'config.json': b'{}' if fault == 'config-bytes' and role == 'server-image' else raw}))
        assets[role] = SimpleNamespace(name=path.name, sha256=sha(path.read_bytes()), image_digest=digest)
        inventory['images'][role] = {'config_digest': 'sha256:' + '0' * 64 if fault == 'core-digest' else digest}
    index = 'sha256:' + '1' * 64
    assets['device-runtime'] = SimpleNamespace(name='neutral.tar', sha256='2' * 64,
        image_digest=index, neutral_source_sha256='3' * 64)
    inventory['images']['device-runtime'] = {'index_digest': 'sha256:' + '0' * 64 if fault == 'neutral-index' else index}
    write(c.directory / 'neutral.tar.manifest', ('format=iris-device-neutral-oci-v1\ntrust_mode=neutral\n'
        'source_sha256=' + ('0' if fault == 'neutral-source' else '3') * 64 + '\nindex_digest=' + index
        + '\narchive_sha256=' + ('0' if fault == 'neutral-sidecar' else '2') * 64
        + '\nplatforms=linux/amd64,linux/arm64\n').encode())
    def inspect(**kwargs):
        assert kwargs['commit'] == COMMIT
        kwargs['output_dir'].mkdir()
        path = kwargs['output_dir'] / 'image-components.json'
        write(path, encoded(inventory))
        return path
    monkeypatch.setattr(subject.image_components, 'inspect_components', inspect)
    work = c.tmp / 'images-work'
    with subject.offline_inputs._new_directory(work, remove=True) as fd:
        anchor = Path('/proc/self/fd') / str(fd)
        if fault:
            with pytest.raises(InstallError):
                subject._images({}, assets, c.directory, work, anchor, fd, COMMIT)
        else:
            path, digest, actual, configs = subject._images({}, assets, c.directory, work, anchor, fd, COMMIT)
            assert digest == sha(path.read_bytes()) and actual == inventory
            for role, path in configs.items():
                assert 'sha256:' + sha(path.read_bytes()) == assets[role].image_digest


def test_augmented_total_is_bounded(pipeline, monkeypatch):
    c = pipeline.candidate
    original_size = sum(row['size'] for row in c.value['files'].values())
    monkeypatch.setattr(kit, 'MAX_TOTAL', original_size + 1)
    with pytest.raises(InstallError, match='augmented candidate'):
        subject.assemble(**invocation(c))


@pytest.mark.parametrize('kind', ['original', 'companion', 'inventory', 'config'])
def test_post_validation_change_never_gets_a_new_output_identity(pipeline, monkeypatch, kind):
    original = subject._validate_notices
    def changed(*args):
        result = original(*args)
        if kind == 'original':
            path = args[1] / pipeline.candidate.package
        elif kind == 'companion':
            path = args[5]['debian']['path']
        elif kind == 'inventory':
            path = args[3]
        else:
            path = args[1].parent / 'iris-server-image-config.json'
        write(path, b'changed after validation')
        return result
    monkeypatch.setattr(subject, '_validate_notices', changed)
    with pytest.raises(InstallError, match='changed after independent inspection'):
        subject.assemble(**invocation(pipeline.candidate))
    assert not (pipeline.candidate.tmp / 'output').exists()
