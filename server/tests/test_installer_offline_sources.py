# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real signed private metadata and local source files; no network or install."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import offline_dependencies as dependencies, offline_sources as subject
from iris_installer.state import InstallError


def command(args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def signed(home, plain, path):
    unsigned = path.with_name(path.name + '.unsigned')
    write(unsigned, plain.encode())
    command(['gpg', '--homedir', str(home), '--batch', '--yes', '--output', str(path), '--clearsign', str(unsigned)])
    unsigned.unlink()


def checksums(files):
    return '\n'.join(' ' + sha(data) + ' ' + str(len(data)) + ' ' + name for name, data in sorted(files.items()))


@pytest.fixture(autouse=True)
def one_root(monkeypatch):
    # Keep real signature and apt closure proof while reducing fixture packages.
    monkeypatch.setattr(dependencies, 'ROOT_PACKAGES', frozenset(('age',)))


@pytest.fixture(scope='module')
def original(tmp_path_factory):
    if any(shutil.which(tool) is None for tool in ('apt-get', 'dpkg-deb', 'gpg', 'gpgv')):
        pytest.skip('Local apt and GnuPG are required for signed source fixtures')
    base = tmp_path_factory.mktemp('source-fixture')
    home = base / 'gnupg'
    home.mkdir(mode=0o700)
    command(['gpg', '--homedir', str(home), '--batch', '--passphrase', '', '--quick-generate-key',
             'IRIS private source fixture', 'ed25519', 'sign', '0'])
    keyring = base / 'keyring.gpg'
    keyring.write_bytes(command(['gpg', '--homedir', str(home), '--export']))
    keyring.chmod(0o600)
    payload, pool = base / 'binary', base / 'pool'
    package = base / 'package'
    control = ('Package: age\nVersion: 1.0\nArchitecture: amd64\nMaintainer: IRIS fixture\n'
        'Description: isolated source fixture\nSource: fixture-source (2.0)\nBuilt-Using: embedded (= 3.0)\n')
    write(package / 'DEBIAN/control', control.encode())
    write(package / 'usr/share/doc/age/copyright', b'Fixture notices refer to /usr/share/common-licenses/GPL\n')
    write(package / 'usr/share/common-licenses/GPL-2', b'fixture license bytes\n')
    (package / 'usr/share/common-licenses/GPL').symlink_to('GPL-2')
    filename = 'pool/main/a/age/age_1.0_amd64.deb'
    deb = payload / 'repositories/archive' / filename
    deb.parent.mkdir(parents=True)
    command(['dpkg-deb', '--root-owner-group', '--build', str(package), str(deb)])
    binary_row = control + f'Filename: {filename}\nSize: {deb.stat().st_size}\nSHA256: {sha(deb.read_bytes())}\n'
    source_rows = {}
    for name, version in [('fixture-source', '2.0'), ('embedded', '3.0')]:
        files = {name + '_' + version + '.orig.tar.gz': b'local original source fixture ' + name.encode(),
                 name + '_' + version + '.debian.tar.xz': b'local packaging fixture ' + name.encode()}
        dsc = ('Format: 3.0 (quilt)\nSource: ' + name + '\nVersion: ' + version
               + '\nChecksums-Sha256:\n' + checksums(files) + '\n').encode()
        files[name + '_' + version + '.dsc'] = dsc
        directory = 'pool/main/' + name[0] + '/' + name
        for item, data in files.items():
            write(pool / directory / item, data)
        source_rows[name] = ('Package: ' + name + '\nVersion: ' + version + '\nDirectory: ' + directory
                            + '\nChecksums-Sha256:\n' + checksums(files) + '\n\n').encode()
    now, values = datetime.now(timezone.utc), []
    for repository, suite, _ in dependencies.REPOSITORIES:
        release = payload / 'repositories' / repository / 'dists' / suite
        files = {}
        for component in dependencies.COMPONENTS:
            relative = component + '/binary-amd64/Packages'
            data = (binary_row + '\n').encode() if suite == 'noble' and component == 'main' else b'Package: unused\nVersion: 1\nArchitecture: amd64\n\n'
            write(release / relative, data)
            files[relative] = data
            source = source_rows['fixture-source'] if suite == 'noble' and component == 'main' else b'Package: unused\nVersion: 1\n\n'
            relative = component + '/source/Sources'
            files[relative], files[relative + '.xz'] = source, lzma.compress(source)
            source_path = base / 'indexes' / suite / component / 'Sources.xz'
            write(source_path, files[relative + '.xz'])
            values.append({'repository': repository, 'suite': suite, 'component': component,
                'inrelease': str(release / 'InRelease'), 'sources': str(source_path), 'historical': False})
        text = (f'Origin: Ubuntu\nLabel: Ubuntu\nSuite: {suite}\nCodename: noble\nArchitectures: amd64\nComponents: main universe\nDate: '
                + format_datetime(now) + '\nSHA256:\n' + checksums(files) + '\n')
        signed(home, text, release / 'InRelease')
    historical = base / 'historical'
    source = source_rows['embedded']
    write(historical / 'Sources.xz', lzma.compress(source))
    text = ('Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble-updates\nCodename: noble\nArchitectures: amd64\nComponents: main universe\nDate: '
        + format_datetime(now - timedelta(days=10)) + '\nValid-Until: ' + format_datetime(now - timedelta(days=5))
        + '\nSHA256:\n' + checksums({'main/source/Sources': source, 'main/source/Sources.xz': lzma.compress(source)}) + '\n')
    signed(home, text, historical / 'InRelease')
    values.append({'repository': 'archive', 'suite': 'noble-updates', 'component': 'main',
        'inrelease': str(historical / 'InRelease'), 'sources': str(historical / 'Sources.xz'), 'historical': True})
    manifest = {'schema': dependencies.SCHEMA, 'host': {'os': 'ubuntu', 'version': '24.04', 'architecture': 'amd64'},
        'docker_provider': 'docker.io', 'roots': {'age': '1.0'}, 'packages': [{'name': 'age', 'version': '1.0',
        'architecture': 'amd64', 'repository': 'archive', 'suite': 'noble', 'component': 'main', 'filename': filename}],
        'files': {str(path.relative_to(payload)): subject._record(path.read_bytes()) for path in payload.rglob('*') if path.is_file()}}
    write(payload / dependencies.MANIFEST, json.dumps(manifest, sort_keys=True).encode())
    for path in base.rglob('*'):
        if path.is_dir() and not path.is_symlink():
            path.chmod(0o700)
    return SimpleNamespace(base=base, keyring=keyring, digest=sha((payload / dependencies.MANIFEST).read_bytes()), indexes=values)


@pytest.fixture
def fixture(original, tmp_path):
    base = tmp_path / 'inputs'
    shutil.copytree(original.base, base, symlinks=True, ignore=shutil.ignore_patterns('S.gpg-agent*'))
    indexes = [{key: value.replace(str(original.base), str(base)) if isinstance(value, str) else value
                for key, value in row.items()} for row in original.indexes]
    return SimpleNamespace(base=base, payload=base / 'binary', pool=base / 'pool', keyring=base / 'keyring.gpg',
                           indexes=indexes, digest=original.digest, output=tmp_path / 'sources.tar.gz')


def build(fixture, output=None):
    return subject.build_sources(fixture.payload, fixture.digest, fixture.indexes, fixture.pool,
                                 output or fixture.output, keyring=fixture.keyring)


def test_real_signed_source_closure_and_deterministic_companion(fixture):
    first = build(fixture)
    second = build(fixture, fixture.output.with_name('again.tar.gz'))
    assert first['sha256'] == second['sha256']
    assert first['sources'] == 2 and first['binaries'] == 1 and not first['authenticated']
    manifest = subject.inspect_source_archive(fixture.output, expected_binary_manifest_sha256=fixture.digest)
    assert manifest['binaries'][0]['source'] == {'name': 'fixture-source', 'version': '2.0'}
    assert manifest['binaries'][0]['built_using'] == [{'name': 'embedded', 'version': '3.0'}]
    assert sum(row['historical'] for row in manifest['evidence']) == 1
    assert manifest['notice_aliases']['usr/share/common-licenses/GPL'] == 'usr/share/common-licenses/GPL-2'
    assert 'README.txt' in manifest['files']
    assert not list(fixture.output.parent.glob('.iris-source-publish-*'))


@pytest.mark.parametrize('change', ['missing', 'altered', 'symlink', 'hardlink'])
def test_source_bytes_are_verified_and_never_adopted(fixture, change):
    path = next(fixture.pool.rglob('*.orig.tar.gz'))
    if change == 'missing':
        path.unlink()
    elif change == 'altered':
        path.write_bytes(b'changed source')
    elif change == 'symlink':
        moved = path.with_name('external')
        path.rename(moved)
        path.symlink_to(moved)
    else:
        os.link(path, path.with_name('external'))
    with pytest.raises((InstallError, OSError)):
        build(fixture)
    assert not fixture.output.exists()


@pytest.mark.parametrize('change', ['missing-historical', 'changed-index', 'changed-signature', 'foreign-binary-digest'])
def test_incomplete_or_changed_provenance_cannot_produce_bundle(fixture, change):
    if change == 'missing-historical':
        fixture.indexes.pop()
    elif change == 'changed-index':
        Path(fixture.indexes[0]['sources']).write_bytes(lzma.compress(b'changed'))
    elif change == 'changed-signature':
        path = Path(fixture.indexes[-1]['inrelease'])
        path.write_bytes(path.read_bytes().replace(b'Origin: Ubuntu', b'Origin: Changed'))
    else:
        fixture.digest = 'f' * 64
    with pytest.raises(InstallError):
        build(fixture)
    assert not fixture.output.exists()


@pytest.mark.parametrize('change', ['flag', 'missing-current', 'duplicate', 'relative', 'extra-field', 'wrong-suite'])
def test_input_descriptor_is_strict_and_historical_is_explicit(fixture, change):
    if change == 'flag':
        fixture.indexes[-1]['historical'] = 'yes'
    elif change == 'missing-current':
        fixture.indexes.pop(0)
    elif change == 'duplicate':
        fixture.indexes.append(deepcopy(fixture.indexes[0]))
    elif change == 'relative':
        fixture.indexes[0]['sources'] = 'relative/Sources.xz'
    elif change == 'extra-field':
        fixture.indexes[0]['trusted'] = True
    else:
        fixture.indexes[0]['suite'] = 'jammy'
    with pytest.raises(InstallError):
        build(fixture)


def test_past_expiry_does_not_enter_current_metadata_policy(fixture):
    fixture.indexes[2] = dict(fixture.indexes[-1], historical=False)
    fixture.indexes.pop()
    with pytest.raises(InstallError, match='binary closure InRelease'):
        build(fixture)


def test_existing_output_is_preserved_without_validation_or_source_copy(fixture, monkeypatch):
    fixture.output.write_bytes(b'owner sentinel')
    monkeypatch.setattr(dependencies, 'validate_closure', lambda *a, **kw: pytest.fail('Existing output reached validation'))
    with pytest.raises(InstallError, match='replace'):
        build(fixture)
    assert fixture.output.read_bytes() == b'owner sentinel'


@pytest.mark.parametrize('source,expected', [(None, {'name': 'binary', 'version': '1'}),
    ('different', {'name': 'different', 'version': '1'}), ('different (2)', {'name': 'different', 'version': '2'})])
def test_exact_source_field_defaulting(source, expected):
    assert subject._source({'name': 'binary', 'version': '1'}, source) == expected


@pytest.mark.parametrize('value', ['source (>= 1)', 'source', 'source (= 1) | other (= 2)', 'source (= 1), source (= 1)'])
def test_incorporated_sources_refuse_ambiguous_versions(value):
    with pytest.raises(InstallError):
        subject._using(value)


@pytest.mark.parametrize('change', ['identity', 'missing', 'hash', 'extra'])
def test_dsc_identity_and_full_source_inventory_are_required(tmp_path, change):
    files = {'pool/main/f/fixture/fixture_1.orig.tar.gz': {'sha256': 'a' * 64, 'size': 1},
             'pool/main/f/fixture/fixture_1.dsc': {'sha256': 'b' * 64, 'size': 1}}
    body = 'Format: 3.0 (quilt)\nSource: fixture\nVersion: 1\nChecksums-Sha256:\n ' + 'a' * 64 + ' 1 fixture_1.orig.tar.gz\n'
    if change == 'identity':
        body = body.replace('Version: 1', 'Version: 2')
    elif change == 'missing':
        body = body.split('Checksums-Sha256:')[0]
    elif change == 'hash':
        body = body.replace('a' * 64, 'f' * 64)
    else:
        body += ' ' + 'c' * 64 + ' 2 unlisted.tar.gz\n'
    path = tmp_path / 'test.dsc'
    path.write_text(body)
    with pytest.raises(InstallError):
        subject._dsc(path, ('fixture', '1'), files)


def test_index_descriptor_json_is_locator_not_authority(fixture, tmp_path):
    path = tmp_path / 'indexes.json'
    path.write_text(json.dumps({'schema': subject.INPUT_SCHEMA, 'indexes': fixture.indexes}))
    assert subject.load_index_inputs(path) == fixture.indexes
    path.write_text(json.dumps({'schema': subject.INPUT_SCHEMA, 'indexes': fixture.indexes, 'verified': True}))
    with pytest.raises(InstallError):
        subject.load_index_inputs(path)


def archive_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return gzip.compress(stream.getvalue(), mtime=0)


def contents(path):
    with tarfile.open(path, 'r:gz') as archive:
        return {member.name: archive.extractfile(member).read() for member in archive}


def test_independent_validator_rederives_full_coverage(fixture):
    build(fixture)
    manifest = subject.validate_source_archive(fixture.output, fixture.payload, fixture.digest, keyring=fixture.keyring)
    assert len(manifest['sources']) == 2 and len(manifest['binaries']) == 1
    assert manifest == subject.inspect_source_archive(fixture.output)


@pytest.mark.parametrize('change', ['source-claim', 'source-coverage', 'binary-coverage', 'notice', 'source-bytes',
                                   'missing-source', 'historical-claim', 'alias', 'readme', 'extra-file'])
def test_self_consistent_manifest_is_not_source_coverage_authority(fixture, change):
    build(fixture)
    files = contents(fixture.output)
    manifest = json.loads(files[subject.MANIFEST])
    if change == 'source-claim':
        manifest['binaries'][0]['source']['version'] = 'unrelated'
    elif change == 'source-coverage':
        manifest['sources'].pop()
    elif change == 'binary-coverage':
        manifest['binaries'] = []
    elif change == 'historical-claim':
        next(row for row in manifest['evidence'] if row['historical'])['signed_date'] = 'unverified date'
    elif change == 'alias':
        manifest['notice_aliases'] = {}
    elif change == 'missing-source':
        name = next(name for name in files if name.endswith('.orig.tar.gz'))
        files.pop(name)
        manifest['files'].pop(name)
    else:
        name = {'notice': 'notices/usr/share/doc/age/copyright', 'readme': 'README.txt',
                'extra-file': 'unlisted.txt'}.get(change)
        if name is None:
            name = next(name for name in files if name.endswith('.orig.tar.gz'))
        files[name] = b'self-consistent but unauthenticated replacement'
        manifest['files'][name] = subject._record(files[name])
    files[subject.MANIFEST] = subject._canonical(manifest)
    tampered = fixture.output.with_name('tampered.tar.gz')
    tampered.write_bytes(archive_bytes(files))
    # The closed file inventory is deliberately internally consistent.
    subject.inspect_source_archive(tampered)
    with pytest.raises((InstallError, OSError)):
        subject.validate_source_archive(tampered, fixture.payload, fixture.digest, keyring=fixture.keyring)


@pytest.mark.parametrize('change', ['extra', 'changed', 'traversal', 'trailing', 'truncated', 'gzip-footer', 'gzip-crc'])
def test_archive_is_closed_bounded_and_exact(fixture, change):
    build(fixture)
    files = contents(fixture.output)
    if change == 'extra':
        files['unlisted'] = b'extra'
    elif change == 'changed':
        files['README.txt'] = b'changed'
    elif change == 'traversal':
        files['../outside'] = b'escape'
    data = archive_bytes(files)
    if change == 'trailing':
        data = gzip.compress(gzip.decompress(data) + b'x' * 1024)
    elif change == 'truncated':
        plain = gzip.decompress(data)
        with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
            list(archive)
            data = gzip.compress(plain[:archive.offset + 512])
    elif change == 'gzip-footer':
        data = data[:-4]
    elif change == 'gzip-crc':
        data = data[:-8] + bytes([data[-8] ^ 1]) + data[-7:]
    candidate = fixture.output.with_name('invalid.tar.gz')
    candidate.write_bytes(data)
    with pytest.raises(InstallError):
        subject.inspect_source_archive(candidate)


def test_valid_release_hash_inventory_can_include_unused_large_and_at_paths():
    result = subject._checksums('a' * 64 + ' 3861471365 Contents-arm64\n' + 'b' * 64 + ' 0 main/icons@2.tar',
                                allow_empty=True, maximum=subject.MAX_TOTAL)
    assert result['main/icons@2.tar']['size'] == 0


def test_publication_parent_replacement_never_writes_or_cleans_substitute(fixture, monkeypatch):
    publish = fixture.output.parent / 'publication'
    publish.mkdir(mode=0o700)
    fixture.output = publish / 'sources.tar.gz'
    original = subject.inspect_source_archive
    moved = publish.with_name('held-publication')
    def substitute(*args, **kwargs):
        result = original(*args, **kwargs)
        publish.rename(moved)
        publish.mkdir(mode=0o700)
        (publish / 'sentinel').write_bytes(b'owner data')
        return result
    monkeypatch.setattr(subject, 'inspect_source_archive', substitute)
    with pytest.raises(InstallError, match='directory changed'):
        build(fixture)
    assert (publish / 'sentinel').read_bytes() == b'owner data'
    assert not fixture.output.exists()
    assert list(moved.iterdir()) == []


def resign_historical(fixture, text):
    item = fixture.indexes[-1]
    release = Path(item['inrelease'])
    plain = command(['gpgv', '--keyring', str(fixture.keyring), '--output', '-', str(release)]).decode()
    compressed = lzma.compress(text.encode())
    Path(item['sources']).write_bytes(compressed)
    prefix = plain.split('SHA256:')[0]
    signed(fixture.base / 'gnupg', prefix + 'SHA256:\n' + checksums({
        'main/source/Sources': text.encode(), 'main/source/Sources.xz': compressed}) + '\n', release)


def test_conflicting_signed_exact_source_records_refuse(fixture):
    original = lzma.decompress(Path(fixture.indexes[-1]['sources']).read_bytes()).decode()
    direct = lzma.decompress(Path(fixture.indexes[0]['sources']).read_bytes()).decode()
    digest = next(line.split()[0] for line in direct.splitlines() if line.startswith(' '))
    resign_historical(fixture, original + direct.replace(digest, 'f' * 64))
    with pytest.raises(InstallError, match='Conflicting signed records'):
        build(fixture)
    assert not fixture.output.exists()


def test_historical_source_dates_still_reject_future_signed_metadata(fixture):
    item = fixture.indexes[-1]
    path = Path(item['inrelease'])
    plain = command(['gpgv', '--keyring', str(fixture.keyring), '--output', '-', str(path)]).decode()
    future = format_datetime(datetime.now(timezone.utc) + timedelta(days=10))
    plain = '\n'.join('Date: ' + future if line.startswith('Date: ') else line
                      for line in plain.splitlines()) + '\n'
    signed(fixture.base / 'gnupg', plain, path)
    with pytest.raises(InstallError, match='Release dates'):
        build(fixture)


def test_malformed_gzip_cli_fails_concisely_without_traceback(fixture):
    path = fixture.output.with_name('broken.tar.gz')
    path.write_bytes(gzip.compress(b'fixture')[:-4])
    script = Path(__file__).resolve().parents[2] / 'tools/build-offline-sources.py'
    result = subprocess.run([sys.executable, str(script), '--binary-closure', str(fixture.payload),
        '--manifest-sha256', fixture.digest, '--verify-bundle', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode == 1 and result.stdout == b''
    assert b'Source companion archive is invalid' in result.stderr
    assert b'Traceback' not in result.stderr


def test_ubuntu_empty_xz_stream_suffix_and_padding_are_verified_together():
    assert subject._expand_index(lzma.compress(b'first') + lzma.compress(b'')) == b'first'
    assert subject._expand_index(lzma.compress(b'first') + b'\0' * 4 + lzma.compress(b'second')) == b'firstsecond'


@pytest.mark.parametrize('data', [lzma.compress(b'first')[:-1], lzma.compress(b'first') + b'x',
    lzma.compress(b'first') + b'\0', lzma.compress(b'') * 65])
def test_xz_streams_still_refuse_truncation_garbage_and_excessive_framing(data):
    with pytest.raises(InstallError):
        subject._expand_index(data)
