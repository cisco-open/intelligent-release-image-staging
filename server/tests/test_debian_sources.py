# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Private signed Debian fixtures; no network, package installation or recipes."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import debian_sources as subject, offline_sources as shared
from iris_installer.state import InstallError
from test_installer_offline_sources import command, checksums, signed, write


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def package(version):
    return {'package': 'binary', 'version': version + '+b1', 'architecture': 'amd64',
            'status': 'install ok installed', 'source': 'direct', 'source_version': version,
            'built_using': [{'source': 'incorporated', 'version': '3'}],
            'static_built_using': [{'source': 'static', 'version': '4'}]}


def image(layers, platform='linux/amd64'):
    return {'archive_sha256': 'a' * 64, 'archive_size': 10240, 'platform': platform,
            'config_digest': 'sha256:' + 'b' * 64,
            'layers': [{'index': index, 'blob_sha256': str(index) * 64, 'diff_id': 'sha256:' + str(index) * 64,
                        'inventory': {'package_databases': databases}} for index, databases in enumerate(layers)]}


def database(version):
    return {'ecosystem': 'debian', 'path': 'var/lib/dpkg/status', 'sha256': 'c' * 64,
            'size': 123, 'packages': [package(version)]}


@pytest.fixture(scope='module')
def original(tmp_path_factory):
    if any(shutil.which(tool) is None for tool in ('gpg', 'gpgv')):
        pytest.skip('Local GnuPG required for signed source fixture')
    base = tmp_path_factory.mktemp('debian-source-fixture')
    home = base / 'gnupg'
    home.mkdir(mode=0o700)
    command(['gpg', '--homedir', str(home), '--batch', '--passphrase', '', '--quick-generate-key',
             'IRIS private Debian source fixture', 'ed25519', 'sign', '0'])
    keyring = base / 'keyring.gpg'
    keyring.write_bytes(command(['gpg', '--homedir', str(home), '--export']))
    inventory = {'format': 'iris-image-component-inventory-v1', 'scope': 'inventory-only',
                 'authenticated': False, 'source_coverage_complete': False, 'commit': 'a' * 40,
                 'commit_scope': 'core-revision-labels-only', 'attribution_policy': 'Fixture evidence only',
                 'images': {'server-image': image([[database('1')], [database('2')]]),
                            'console-image': image([[database('2')]]),
                            'device-runtime': {'archive_sha256': 'd' * 64,
                                               'platforms': [image([[]]), image([[]], 'linux/arm64')]}}}
    write(base / 'inventory.json', encoded(inventory))
    source_files = {}
    for name, version in [('direct', '1'), ('direct', '2'), ('incorporated', '3'), ('static', '4')]:
        files = {name + '_' + version + '.orig.tar.gz': b'original bytes ' + name.encode() + version.encode(),
                 name + '_' + version + '.debian.tar.xz': b'packaging bytes ' + name.encode() + version.encode()}
        files[name + '_' + version + '.dsc'] = ('Format: 3.0 (quilt)\nSource: ' + name + '\nVersion: '
            + version + '\nChecksums-Sha256:\n' + checksums(files) + '\n').encode()
        source_files[(name, version)] = files
    now, indexes = datetime.now(timezone.utc), []
    for repository, suite, component in sorted(subject.LOCATIONS):
        security = repository == 'security'
        selected = {('direct', '2'): source_files[('direct', '2')]} if security else source_files if suite == 'trixie' else {}
        rows = []
        for (name, version), files in sorted(selected.items()):
            directory = ('pool/updates/main/' if security else 'pool/main/') + name[0] + '/' + name
            for filename, data in files.items():
                write(base / 'pool' / directory / filename, data)
            rows.append('Package: ' + name + '\nVersion: ' + version + '\nDirectory: ' + directory
                        + '\nChecksums-Sha256:\n' + checksums(files) + '\n\n')
        data = ''.join(rows).encode() or b'Package: unused\nVersion: 1\n\n'
        location = base / suite
        write(location / 'Sources.xz', lzma.compress(data))
        suite_label = {'trixie': 'stable', 'trixie-updates': 'stable-updates', 'trixie-security': 'stable-security'}[suite]
        plain = ('Origin: Debian\nLabel: ' + ('Debian-Security' if security else 'Debian')
                 + '\nSuite: ' + suite_label + '\nCodename: ' + suite + '\nArchitectures: amd64 arm64\nComponents: '
                 + ('updates/main' if security else 'main') + '\nDate: ' + format_datetime(now)
                 + '\nValid-Until: ' + format_datetime(now + timedelta(days=7))
                 + '\nSHA256:\n' + checksums({'main/source/Sources': data, 'main/source/Sources.xz': lzma.compress(data)}) + '\n')
        signed(home, plain, location / 'InRelease')
        write(location / 'Release.fixture', plain.encode())
        indexes.append({'repository': repository, 'suite': suite, 'component': component,
                        'inrelease': str(location / 'InRelease'), 'sources': str(location / 'Sources.xz')})
    return SimpleNamespace(base=base, indexes=indexes)


@pytest.fixture
def fixture(original, tmp_path):
    base = tmp_path / 'inputs'
    shutil.copytree(original.base, base, ignore=shutil.ignore_patterns('S.gpg-agent*'))
    indexes = [{key: value.replace(str(original.base), str(base)) for key, value in row.items()} for row in original.indexes]
    return SimpleNamespace(base=base, pool=base / 'pool', inventory=base / 'inventory.json', indexes=indexes,
                           keyring=base / 'keyring.gpg', output=tmp_path / 'sources.tar.gz',
                           digest=sha((base / 'inventory.json').read_bytes()))


def build(fixture, output=None):
    return subject.build_sources(fixture.inventory, fixture.digest, fixture.indexes,
                                 fixture.pool, output or fixture.output, keyring=fixture.keyring)


def validate(fixture):
    return subject.validate_source_archive(fixture.output, fixture.inventory, fixture.digest, keyring=fixture.keyring)


def inventory_change(fixture, change):
    value = json.loads(fixture.inventory.read_bytes())
    change(value)
    fixture.inventory.write_bytes(encoded(value))
    fixture.digest = sha(fixture.inventory.read_bytes())


def release_change(fixture, suite, change):
    path = fixture.base / suite
    signed(fixture.base / 'gnupg', change((path / 'Release.fixture').read_text()), path / 'InRelease')


def archive_rewrite(fixture, change):
    with tarfile.open(fixture.output, 'r:gz') as archive:
        files = {member.name: archive.extractfile(member).read() for member in archive}
    manifest = json.loads(files.pop(subject.MANIFEST))
    change(manifest, files)
    manifest['files'] = {name: shared._record(data) for name, data in files.items()}
    files[subject.MANIFEST] = shared._canonical(manifest)
    with fixture.output.open('wb') as output, gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.mode, info.size = 0o644, len(data)
                archive.addfile(info, io.BytesIO(data))


def test_real_signatures_all_retained_versions_and_determinism(fixture):
    first = build(fixture)
    second = build(fixture, fixture.output.with_name('again.tar.gz'))
    assert first['sha256'] == second['sha256']
    assert first['sources'] == 4 and first['binary_layer_records'] == 3
    assert first['authenticated'] is False and first['source_coverage_complete'] is False
    manifest = validate(fixture)
    assert {(row['name'], row['version']) for row in manifest['sources']} == {
        ('direct', '1'), ('direct', '2'), ('incorporated', '3'), ('static', '4')}
    assert len(next(row for row in manifest['sources'] if row['name'] == 'direct' and row['version'] == '2')['locations']) == 2
    assert manifest['notices'] == 'not-collected'
    assert manifest['files']['image-components.json']['sha256'] == fixture.digest
    assert not list(fixture.output.parent.glob('.iris-debian-source-publish-*'))


@pytest.mark.parametrize('target', ['inventory', 'keyring', 'source', 'index', 'signature'])
def test_tampered_inputs_refuse_without_publication(fixture, target):
    path = {'inventory': fixture.inventory, 'keyring': fixture.keyring,
            'source': next(fixture.pool.rglob('*.orig.tar.gz')), 'index': Path(fixture.indexes[0]['sources']),
            'signature': Path(fixture.indexes[0]['inrelease'])}[target]
    path.write_bytes(b'altered')
    with pytest.raises((InstallError, ValueError)):
        build(fixture)
    assert not fixture.output.exists()


@pytest.mark.parametrize('mutation', ['layer', 'database', 'package', 'using', 'platform', 'image', 'empty'])
def test_ambiguous_inventory_never_silently_overwrites(fixture, mutation):
    def change(value):
        server = value['images']['server-image']
        layer = server['layers'][0]
        db = layer['inventory']['package_databases'][0]
        if mutation == 'layer':
            server['layers'][1]['index'] = 0
        elif mutation == 'database':
            layer['inventory']['package_databases'].append(deepcopy(db))
        elif mutation == 'package':
            db['packages'].append(deepcopy(db['packages'][0]))
        elif mutation == 'using':
            db['packages'][0]['built_using'] *= 2
        elif mutation == 'platform':
            value['images']['device-runtime']['platforms'] *= 2
        elif mutation == 'image':
            value['images']['server-image'] = None
        elif mutation == 'empty':
            for role in ('server-image', 'console-image'):
                for item in value['images'][role]['layers']:
                    item['inventory']['package_databases'] = []
    inventory_change(fixture, change)
    with pytest.raises(InstallError):
        build(fixture)


@pytest.mark.parametrize('field,value', [('Origin', 'Ubuntu'), ('Label', 'Debian'), ('Suite', 'testing-security'),
                                      ('Codename', 'bookworm-security'), ('Components', 'main'),
                                      ('Date', format_datetime(datetime.now(timezone.utc) + timedelta(days=3))),
                                      ('Valid-Until', format_datetime(datetime.now(timezone.utc) - timedelta(days=3)))])
def test_signed_wrong_identity_or_date_refused(fixture, field, value):
    release_change(fixture, 'trixie-security', lambda text: '\n'.join(
        field + ': ' + value if line.startswith(field + ':') else line for line in text.split('\n')))
    with pytest.raises(InstallError):
        build(fixture)


def test_missing_updates_expiry_refused(fixture):
    release_change(fixture, 'trixie-updates', lambda text: '\n'.join(
        line for line in text.split('\n') if not line.startswith('Valid-Until:')))
    with pytest.raises(InstallError, match='dates'):
        build(fixture)


def test_signed_expanded_hash_independently_checked(fixture):
    data = lzma.decompress(Path(fixture.indexes[0]['sources']).read_bytes())
    release_change(fixture, fixture.indexes[0]['suite'], lambda text: text.replace(sha(data), 'f' * 64))
    with pytest.raises(InstallError, match='expanded Sources'):
        build(fixture)


@pytest.mark.parametrize('kind', ['missing', 'conflict', 'dsc-identity', 'dsc-files'])
def test_exact_sources_and_descriptor_inventory_required(fixture, kind):
    if kind == 'missing':
        inventory_change(fixture, lambda v: v['images']['server-image']['layers'][0]['inventory']['package_databases'][0]['packages'][0].update(source_version='999'))
    else:
        suite = 'trixie-security'
        location = fixture.base / suite
        source_files = {path.name: path.read_bytes() for path in (fixture.pool / 'pool/updates/main/d/direct').iterdir()}
        name = next(name for name in source_files if name.endswith('.dsc'))
        if kind == 'conflict':
            source_files[name] += b'\n'
        elif kind == 'dsc-identity':
            source_files[name] = source_files[name].replace(b'Version: 2', b'Version: 999')
        else:
            source_files[name] = source_files[name].replace(b'Checksums-Sha256:', b'Other-Field:')
        new = ('Package: direct\nVersion: 2\nDirectory: pool/updates/main/d/direct\nChecksums-Sha256:\n'
               + checksums(source_files) + '\n\n').encode()
        for name, data in source_files.items():
            (fixture.pool / 'pool/updates/main/d/direct' / name).write_bytes(data)
        (location / 'Sources.xz').write_bytes(lzma.compress(new))
        release_change(fixture, suite, lambda text: text[:text.index('SHA256:')] + 'SHA256:\n'
                       + checksums({'main/source/Sources': new, 'main/source/Sources.xz': lzma.compress(new)}) + '\n')
        if kind.startswith('dsc'):
            archive = fixture.base / 'trixie'
            index = lzma.decompress((archive / 'Sources.xz').read_bytes())
            blocks = [row for row in index.decode().split('\n\n') if row and '\nVersion: 2\n' not in row]
            new_index = ('\n\n'.join(blocks) + '\n\n').encode()
            (archive / 'Sources.xz').write_bytes(lzma.compress(new_index))
            release_change(fixture, 'trixie', lambda text: text[:text.index('SHA256:')] + 'SHA256:\n'
                           + checksums({'main/source/Sources': new_index, 'main/source/Sources.xz': lzma.compress(new_index)}) + '\n')
    with pytest.raises(InstallError):
        build(fixture)


@pytest.mark.parametrize('change', ['binaries', 'sources', 'images', 'evidence', 'readme', 'inventory', 'source', 'extra'])
def test_consistent_forged_companion_cannot_authorize_its_own_coverage(fixture, change):
    build(fixture)
    def mutate(manifest, files):
        if change in ('binaries', 'sources', 'images'):
            manifest[change].pop()
        elif change == 'evidence':
            manifest['evidence'][0]['signed_date'] = 'false date'
        elif change == 'readme':
            files['README.txt'] = b'complete coverage'
        elif change == 'inventory':
            files['image-components.json'] = b'{}'
        elif change == 'source':
            files[next(name for name in files if name.endswith('.orig.tar.gz'))] = b'forged source'
        elif change == 'extra':
            files['unlisted-by-reconstruction'] = b'extra'
    archive_rewrite(fixture, mutate)
    subject.inspect_source_archive(fixture.output, expected_inventory_sha256=fixture.digest)
    with pytest.raises(InstallError):
        validate(fixture)


@pytest.mark.parametrize('kind', ['footer', 'tail', 'link', 'traversal', 'duplicate'])
def test_closed_archive_refuses_hidden_or_aliased_content(fixture, kind):
    build(fixture)
    if kind == 'footer':
        fixture.output.write_bytes(fixture.output.read_bytes()[:-5])
    elif kind == 'tail':
        fixture.output.write_bytes(fixture.output.read_bytes() + gzip.compress(b'hidden payload'))
    else:
        plain = gzip.decompress(fixture.output.read_bytes())
        with tarfile.open(fileobj=io.BytesIO(plain)) as archive:
            last = list(archive)[-1]
            end = last.offset_data + ((last.size + 511) // 512) * 512
        info = tarfile.TarInfo('../escape' if kind == 'traversal' else 'README.txt' if kind == 'duplicate' else 'alias')
        info.mode, info.size = 0o644, 1
        if kind == 'link':
            info.type, info.linkname, info.size = tarfile.SYMTYPE, 'README.txt', 0
        extension = info.tobuf() + (b'x' + b'\0' * 511 if info.size else b'') + b'\0' * 1024
        fixture.output.write_bytes(gzip.compress(plain[:end] + extension))
    with pytest.raises(InstallError):
        validate(fixture)


def test_external_inventory_pin_required_even_for_existing_companion(fixture):
    build(fixture)
    fixture.digest = 'f' * 64
    with pytest.raises(InstallError, match='externally expected'):
        validate(fixture)


def test_existing_output_is_never_replaced(fixture):
    fixture.output.write_bytes(b'owner sentinel')
    with pytest.raises(InstallError, match='replace'):
        build(fixture)
    assert fixture.output.read_bytes() == b'owner sentinel'


def test_publication_parent_substitution_preserves_sentinel(fixture, monkeypatch):
    parent = fixture.output.parent / 'publication'
    parent.mkdir(mode=0o700)
    fixture.output = parent / 'result.tar.gz'
    original = subject.inspect_source_archive
    def substitute(*args, **kwargs):
        result = original(*args, **kwargs)
        parent.rename(parent.with_name('moved-publication'))
        parent.mkdir(mode=0o700)
        (parent / 'sentinel').write_bytes(b'owner')
        return result
    monkeypatch.setattr(subject, 'inspect_source_archive', substitute)
    with pytest.raises(InstallError, match='directory changed'):
        build(fixture)
    assert (parent / 'sentinel').read_bytes() == b'owner'
    assert not fixture.output.exists()


def test_cli_verifies_without_build_inputs_and_reports_malformed_archive_concisely(fixture):
    build(fixture)
    cli = Path(__file__).resolve().parents[2] / 'tools/build-debian-sources.py'
    args = [sys.executable, str(cli), '--inventory', str(fixture.inventory), '--inventory-sha256', fixture.digest,
            '--keyring', str(fixture.keyring), '--verify-bundle', str(fixture.output)]
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0 and json.loads(result.stdout)['scope'] == 'debian-source-only'
    fixture.output.write_bytes(fixture.output.read_bytes()[:-4])
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 1 and 'Traceback' not in result.stderr
    assert 'invalid source companion archive' in result.stderr


def test_descriptor_coverage_has_no_historical_override(fixture):
    path = fixture.base / 'indexes.json'
    write(path, encoded({'schema': subject.INPUT_SCHEMA, 'indexes': fixture.indexes}))
    assert subject.load_index_inputs(path) == fixture.indexes
    fixture.indexes[0]['historical'] = True
    with pytest.raises(InstallError):
        build(fixture)
