# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exact local Alpine source collection, Git proof and custody regressions."""

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import alpine_sources as a
from iris_installer.state import InstallError


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    return subprocess.check_output(['git', '-c', 'user.name=Source fixture',
        '-c', 'user.email=source@example.invalid', '-C', str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()


def recipe(name, sources):
    sums = ''.join(hashlib.sha512(raw).hexdigest() + '  ' + filename + '\n'
                   for filename, raw in sorted(sources.items()))
    return (f'pkgname={name}\npkgver=1.0\npkgrel=2\n'
            'source="https://example.invalid/$pkgname-$pkgver.tar.gz local.patch"\n'
            'package() { echo NEVER-EXECUTE; }\n'
            'sha512sums="\n' + sums + '"\n').encode()


def inventory(packages):
    db = {'path': 'lib/apk/db/installed', 'ecosystem': 'alpine',
          'sha256': '1' * 64, 'packages': packages}
    view = {'platform': 'linux/amd64', 'config_digest': 'sha256:' + '2' * 64,
            'layers': [{'index': 0, 'diff_id': 'sha256:' + '3' * 64,
                        'inventory': {'package_databases': [db]}}],
            'merged': {'package_databases': [db]}}
    return {'format': 'iris-image-component-inventory-v1',
            'images': {'device-runtime': {'archive_sha256': '4' * 64, 'platforms': [view]}}}


def package(name, revision):
    return {'package': name, 'version': '1.0-r2', 'architecture': 'x86_64',
            'origin': name, 'aports_commit': revision, 'virtual': False,
            'declared_file_count': 2}


@pytest.fixture
def inputs(tmp_path):
    repo, pool = tmp_path / 'repo', tmp_path / 'pool'
    repo.mkdir(); pool.mkdir()
    git(repo, 'init', '--template=')
    port = repo / 'main/demo'
    port.mkdir(parents=True)
    upstream, patch = b'original source archive\n', b'packaging patch\n'
    (port / 'APKBUILD').write_bytes(recipe('demo', {'demo-1.0.tar.gz': upstream, 'local.patch': patch}))
    (port / 'local.patch').write_bytes(patch)
    (port / 'post-install').write_text('#!/bin/sh\nexit 0\n')
    (port / 'post-install').chmod(0o755)
    (port / 'post-upgrade').symlink_to('post-install')
    (port / 'empty').write_bytes(b'')
    git(repo, 'add', '.')
    git(repo, 'commit', '-m', 'Source fixture')
    revision = git(repo, 'rev-parse', 'HEAD')
    checksum = hashlib.sha512(upstream).hexdigest()
    (pool / checksum).write_bytes(upstream)
    value = inventory([package('demo', revision)])
    path = tmp_path / 'inventory.json'
    path.write_bytes(a.f._json(value))
    return {'inventory': path, 'inventory_sha256': digest(path.read_bytes()),
            'aports_repository': repo, 'source_pool': pool,
            'output_dir': tmp_path / 'out', 'revision': revision,
            'checksum': checksum, 'value': value, 'port': port}


def build(inputs, **changes):
    fields = ('inventory', 'inventory_sha256', 'aports_repository', 'source_pool', 'output_dir')
    args = {key: inputs[key] for key in fields}
    args.update(changes)
    return a.build_sources(**args)


def validated(result, inputs):
    return a.validate_source_archive(Path(result['archive']), inputs['inventory'], inputs['inventory_sha256'])


def rewrite_inventory(inputs):
    inputs['inventory'].write_bytes(a.f._json(inputs['value']))
    inputs['inventory_sha256'] = digest(inputs['inventory'].read_bytes())


def archive_entries(path):
    with tarfile.open(path, 'r:gz') as tar:
        return {row.name: (tar.extractfile(row).read(), row.mode) for row in tar}


def repack(path, entries, *, update_manifest=False):
    if update_manifest:
        value = json.loads(entries[a.MANIFEST][0])
        value['files'] = {name: {'sha256': digest(data), 'size': len(data), 'mode': mode}
                          for name, (data, mode) in entries.items() if name != a.MANIFEST}
        entries[a.MANIFEST] = a.f._json(value), 0o644
    with path.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
            for name, (data, mode) in sorted(entries.items()):
                row = tarfile.TarInfo(name); row.size = len(data); row.mode = mode
                tar.addfile(row, io.BytesIO(data))


def test_round_trip_retains_every_port_file_and_inert_symlink(inputs):
    result = build(inputs)
    manifest = validated(result, inputs)
    assert result['sources'] == 1
    assert manifest['source_coverage_complete'] is False
    assert manifest['authenticated'] is False
    source = manifest['sources'][0]
    assert len(source['occurrences']) == 2
    assert set(source['port_files']) == {'APKBUILD', 'local.patch', 'post-install', 'post-upgrade', 'empty'}
    assert source['port_files']['post-upgrade']['representation'] == 'symlink-target-text'
    assert source['port_files']['post-upgrade']['git_mode'] == '120000'
    entries = archive_entries(Path(result['archive']))
    assert entries[source['port_files']['post-upgrade']['path']] == (b'post-install', 0o644)
    assert entries[source['port_files']['post-install']['path']][1] == 0o755
    assert len(source['inputs']) == 2
    assert (inputs['output_dir'] / a.BUNDLE).stat().st_mode & 0o777 == 0o444
    assert inputs['output_dir'].stat().st_mode & 0o777 == 0o700


def test_repeat_is_byte_identical(inputs):
    first = build(inputs)
    second = build(inputs, output_dir=inputs['output_dir'].with_name('repeat'))
    assert first['sha256'] == second['sha256']
    assert first['manifest_sha256'] == second['manifest_sha256']


def test_dirty_worktree_and_replace_refs_cannot_change_selected_objects(inputs):
    (inputs['port'] / 'local.patch').write_bytes(b'owner dirty edit')
    git(inputs['aports_repository'], 'add', '.')
    git(inputs['aports_repository'], 'commit', '-m', 'Different worktree source')
    replacement = git(inputs['aports_repository'], 'rev-parse', 'HEAD')
    git(inputs['aports_repository'], 'replace', inputs['revision'], replacement)
    result = build(inputs)
    assert validated(result, inputs)['sources'][0]['aports_commit'] == inputs['revision']
    assert (inputs['port'] / 'local.patch').read_bytes() == b'owner dirty edit'


@pytest.mark.parametrize('kind', ['pin', 'missing', 'changed', 'symlink', 'hardlink'])
def test_changed_or_unavailable_source_inputs_fail_closed(inputs, kind, tmp_path):
    source = inputs['source_pool'] / inputs['checksum']
    if kind == 'pin':
        inputs['inventory_sha256'] = '9' * 64
    elif kind == 'missing': source.unlink()
    elif kind == 'changed': source.write_bytes(b'changed')
    elif kind == 'symlink':
        source.rename(tmp_path / 'target'); source.symlink_to(tmp_path / 'target')
    else: os.link(source, tmp_path / 'alias')
    with pytest.raises((InstallError, OSError)):
        build(inputs)
    assert not inputs['output_dir'].exists()


def test_existing_output_is_never_replaced(inputs):
    inputs['output_dir'].mkdir()
    marker = inputs['output_dir'] / 'owner'; marker.write_text('keep')
    with pytest.raises(InstallError): build(inputs)
    assert marker.read_text() == 'keep'


@pytest.mark.parametrize('change', [
    lambda text: text.replace('pkgver=1.0', 'pkgver=$version'),
    lambda text: text.replace('pkgrel=2', 'pkgrel=3'),
    lambda text: text.replace('sha512sums="', 'sha512sums="$values'),
    lambda text: text + 'sha512sums="other"\n',
    lambda text: text.replace('sha512sums=', 'sha256sums='),
    lambda text: text.replace(hashlib.sha512(b'x').hexdigest(), 'SKIP'),
    lambda text: text.replace('  file', '  ../file'),
    lambda text: text.replace('  file', '  sub/file'),
])
def test_unsupported_recipe_metadata_refuses(change):
    raw = recipe('demo', {'file': b'x'}).decode()
    with pytest.raises(InstallError): a._recipe(change(raw).encode(), ('demo', '1.0-r2', '1'*40))


def test_source_url_programs_are_preserved_not_evaluated():
    raw = recipe('demo', {'file': b'x'})
    raw += b'while true; do source="$source $(touch /never-execute)"; done\n'
    assert a._recipe(raw, ('demo', '1.0-r2', '1'*40)) == {'file': hashlib.sha512(b'x').hexdigest()}


def test_absence_of_checksums_is_not_source_less_evidence():
    with pytest.raises(InstallError):
        a._recipe(b'pkgname=demo\npkgver=1.0\npkgrel=2\n', ('demo','1.0-r2','1'*40))


def test_source_less_recipe_requires_exact_reviewed_bytes(monkeypatch):
    identity = ('fixture', '1-r0', '1'*40)
    raw = b'pkgname=fixture\npkgver=1\npkgrel=0\n'
    monkeypatch.setitem(a.SOURCELESS, identity, digest(raw))
    assert a._recipe(raw, identity) == {}
    with pytest.raises(InstallError): a._recipe(raw + b'# changed\n', identity)


def test_all_retained_layers_and_platforms_stay_in_mapping(inputs):
    view = inputs['value']['images']['device-runtime']['platforms'][0]
    view['merged']['package_databases'] = []
    extra = json.loads(json.dumps(view)); extra['platform'] = 'linux/arm64'
    extra['layers'][0]['inventory']['package_databases'][0]['packages'][0]['architecture'] = 'aarch64'
    inputs['value']['images']['device-runtime']['platforms'].append(extra)
    rewrite_inventory(inputs)
    rows = validated(build(inputs), inputs)['sources'][0]['occurrences']
    assert {(row['platform'], row['layer']) for row in rows} == {('linux/amd64', 0), ('linux/arm64', 0)}


def test_virtual_record_is_explicit_not_a_source(inputs):
    virtual = {'package': '.python-rundeps', 'version': '20260920.010101', 'architecture': 'x86_64',
               'origin': None, 'aports_commit': None, 'virtual': True, 'declared_file_count': 0}
    inputs['value']['images']['device-runtime']['platforms'][0]['merged']['package_databases'][0]['packages'].append(virtual)
    rewrite_inventory(inputs)
    manifest = validated(build(inputs), inputs)
    assert len(manifest['sources']) == 1 and len(manifest['virtual_packages']) == 2


@pytest.mark.parametrize('part', ['commit', 'tree', 'port', 'blob', 'manifest', 'extra'])
def test_consistent_self_authored_archive_cannot_replace_external_authority(inputs, tmp_path, part):
    result = build(inputs)
    entries = archive_entries(Path(result['archive']))
    if part == 'manifest':
        value = json.loads(entries[a.MANIFEST][0]); value['source_coverage_complete'] = True
        entries[a.MANIFEST] = a.f._json(value), 0o644
    elif part == 'extra': entries['unrelated'] = b'extra', 0o644
    else:
        name = next(name for name in entries if
            (part in ('commit', 'tree') and name.endswith('.'+part)) or
            (part == 'port' and name.endswith('/post-install')) or
            (part == 'blob' and name.startswith('sources/')))
        entries[name] = entries[name][0] + b'changed', entries[name][1]
    candidate = tmp_path / 'forged.tar.gz'
    repack(candidate, entries, update_manifest=True)
    with pytest.raises(InstallError): validated({'archive': str(candidate)}, inputs)


def test_git_environment_is_clean_and_all_transports_denied(inputs, monkeypatch):
    data = b'local source'
    object_id = a._object_hash('blob', data)
    seen = []
    class Runner:
        def _git(self, repository, args, environment):
            seen.append((args, environment)); return data
    monkeypatch.setattr(a, '_candidate', lambda: Runner())
    monkeypatch.setenv('GIT_CONFIG_COUNT', '99')
    monkeypatch.setenv('GIT_OBJECT_DIRECTORY', '/outside')
    assert a._git_object(inputs['aports_repository'], 'blob', object_id) == data
    _, environment = seen[0]
    assert environment['GIT_ALLOW_PROTOCOL'] == ''
    assert environment['GIT_NO_LAZY_FETCH'] == '1'
    assert 'GIT_CONFIG_COUNT' not in environment and 'GIT_OBJECT_DIRECTORY' not in environment


def test_local_git_returned_bytes_must_match_object_id(inputs, monkeypatch):
    class Runner:
        def _git(self, *args): return b'wrong'
    monkeypatch.setattr(a, '_candidate', lambda: Runner())
    with pytest.raises(InstallError): a._git_object(inputs['aports_repository'], 'blob', '1'*40)


def test_output_parent_replacement_cannot_redirect_publication(inputs, monkeypatch, tmp_path):
    parent = tmp_path / 'publish'; parent.mkdir(mode=0o700)
    moved = tmp_path / 'original'
    original = a._assemble
    def replace(*args, **kwargs):
        result = original(*args, **kwargs)
        if not moved.exists():
            parent.rename(moved); parent.mkdir(mode=0o700)
            (parent / 'sentinel').write_text('keep')
        return result
    monkeypatch.setattr(a, '_assemble', replace)
    with pytest.raises(InstallError, match='output parent changed'): build(inputs, output_dir=parent / 'out')
    assert (parent / 'sentinel').read_text() == 'keep'
    assert not (parent / 'out').exists()
    assert not list(moved.iterdir())


def test_no_tar_terminator_or_trailing_payload(inputs, tmp_path):
    result = build(inputs)
    raw = gzip.decompress(Path(result['archive']).read_bytes())
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as stream:
        for _ in stream: pass
        end = stream.offset
    for index, changed in enumerate((raw[:end], raw + b'payload')):
        path = tmp_path / ('bad' + str(index) + '.gz'); path.write_bytes(gzip.compress(changed))
        with pytest.raises(InstallError): validated({'archive': str(path)}, inputs)


def test_cli_builds_local_source_companion(inputs):
    args = []
    for key in ('inventory', 'inventory_sha256', 'aports_repository', 'source_pool', 'output_dir'):
        args.extend(['--' + key.replace('_','-'), str(inputs[key])])
    assert a.main(args) == 0
    assert (inputs['output_dir'] / a.BUNDLE).is_file()


@pytest.mark.parametrize('extra', ['eval "sha512sums=$computed"', 'sha512sums+="$more"',
                                  'sha512sums=$(checksum)', 'export sha256sums="other"'])
def test_checksum_computation_outside_literal_inventory_refuses(extra):
    with pytest.raises(InstallError):
        a._recipe(recipe('demo', {'file': b'x'}) + extra.encode() + b'\n', ('demo', '1.0-r2', '1'*40))


@pytest.mark.parametrize('field', ['image', 'platform', 'layer', 'database', 'package', 'architecture'])
def test_malformed_external_inventory_refuses(inputs, field):
    image = inputs['value']['images']['device-runtime']
    view = image['platforms'][0]
    if field == 'image': inputs['value']['images']['device-runtime'] = None
    elif field == 'platform': image['platforms'][0] = None
    elif field == 'layer': view['layers'][0] = None
    elif field == 'database': view['merged']['package_databases'][0] = None
    elif field == 'package': view['merged']['package_databases'][0]['packages'][0] = None
    else: view['merged']['package_databases'][0]['packages'][0]['architecture'] = 'aarch64'
    rewrite_inventory(inputs)
    with pytest.raises(InstallError): build(inputs)
    assert not inputs['output_dir'].exists()


def test_generated_archive_is_independently_checked_before_publication(inputs, monkeypatch):
    calls = []
    original = a._validate_archive
    def validate(*args, **kwargs):
        assert not inputs['output_dir'].exists()
        assert kwargs['descriptor'] is not None
        calls.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(a, '_validate_archive', validate)
    build(inputs)
    assert calls == [True]


def test_staging_workspace_substitution_keeps_foreign_sentinel(inputs, monkeypatch, tmp_path):
    original, saved = a._assemble, {}
    def replace(*args, **kwargs):
        result = original(*args, **kwargs)
        sink = args[-1]
        if sink.directory is not None:
            work = Path(os.readlink('/proc/self/fd/' + str(sink.directory)))
            moved = tmp_path / 'held-original'
            work.rename(moved); work.mkdir(mode=0o700)
            (work / inputs['checksum']).write_text('keep')
            saved.update(work=work, moved=moved)
        return result
    monkeypatch.setattr(a, '_assemble', replace)
    with pytest.raises(InstallError): build(inputs)
    assert (saved['work'] / inputs['checksum']).read_text() == 'keep'
    assert not list(saved['moved'].iterdir())
    (saved['work'] / inputs['checksum']).unlink(); saved['work'].rmdir()
