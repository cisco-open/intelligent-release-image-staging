# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Static image inventories retain distributed layers without executing images."""

import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from iris_installer import image_components as c
from iris_installer.state import InstallError
from test_device_finalize import entry, image_bytes, tar_bytes

COMMIT = 'a' * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


def debian(version='1.0', extra=''):
    return ('Package: demo\nStatus: install ok installed\nArchitecture: amd64\nVersion: ' + version
            + '\nSource: upstream (' + version + ')\n' + extra + '\n').encode()


def alpine(architecture='x86_64'):
    return ('P:demo\nV:2.0-r1\nA:' + architecture + '\no:upstream\nc:' + 'b' * 40
            + '\nL:MIT\nF:usr/bin\nR:demo\n\nP:.python-rundeps\nV:20260101.123456\nA:noarch\nD:demo\n\n').encode()


def docker(layers, *, revision=COMMIT, compressed=False, diff_ids=None):
    config = json.dumps({'os': 'linux', 'architecture': 'amd64',
                         'config': {'Labels': {'org.opencontainers.image.revision': revision}},
                         'rootfs': {'type': 'layers', 'diff_ids': diff_ids or ['sha256:' + sha(x) for x in layers]}}).encode()
    names = ['layer' + str(index) + '.tar' for index in range(len(layers))]
    manifest = json.dumps([{'Config': 'config.json', 'Layers': names, 'RepoTags': ['untrusted:ignored']}]).encode()
    return tar_bytes([entry('manifest.json', manifest), entry('config.json', config),
                      *(entry(name, gzip.compress(data, mtime=0) if compressed else data)
                        for name, data in zip(names, layers))])


@pytest.fixture
def inputs(tmp_path):
    old = tar_bytes([entry('var/lib/dpkg/status', debian()),
                     entry('usr/share/doc/demo/copyright', b'old notice'),
                     entry('usr/bin/removed', b'old executable', mode=0o755)])
    new = tar_bytes([entry('var/lib/dpkg/status', debian('2.0',
                         'Built-Using: static-one (= 1:2.3),\n static-two (= 4.5)\nStatic-Built-Using: other (= 9.0)\n')),
                     entry('usr/share/doc/demo/.wh.copyright'), entry('usr/bin/.wh.removed'),
                     entry('opt/iris/bin/aria2c', b'pinned by another source contract', mode=0o755),
                     entry('usr/bin/mystery', b'unknown executable', mode=0o755),
                     entry('usr/local/include/python3.12/patchlevel.h', b'#define PY_VERSION "3.12.15"\n'),
                     entry('usr/local/lib/python3.12/site-packages/pip-25.0.1.dist-info/METADATA',
                           b'Metadata-Version: 2.1\nName: pip\nVersion: 25.0.1\n')])
    neutral, _ = image_bytes(mutate_layer=lambda entries, arch: entries.extend([
        entry('lib/apk/db/installed', alpine('x86_64' if arch == 'amd64' else 'aarch64')),
        entry('usr/local/share/licenses/helper.LICENCE', b'complete fixture notice')]))
    result = {'commit': COMMIT, 'output_dir': tmp_path / 'inventory'}
    for name, data in (('server', docker([old, new], compressed=True)),
                       ('console', docker([old])), ('neutral', neutral)):
        path = tmp_path / (name + '.tar')
        path.write_bytes(data)
        result[name + '_archive'], result[name + '_sha256'] = path, sha(data)
    return result


def test_exact_inventory_retains_lower_layer_versions_and_never_executes(inputs, monkeypatch):
    monkeypatch.setattr(subprocess, 'Popen', lambda *_a, **_k: pytest.fail('must not execute'))
    monkeypatch.setattr(subprocess, 'run', lambda *_a, **_k: pytest.fail('must not execute'))
    path = c.inspect_components(**inputs)
    receipt = json.loads(path.read_bytes())
    assert receipt['format'] == 'iris-image-component-inventory-v1'
    assert receipt['scope'] == 'inventory-only' and receipt['authenticated'] is False
    assert receipt['source_coverage_complete'] is False and receipt['commit'] == COMMIT
    assert receipt['commit_scope'] == 'core-revision-labels-only'
    assert receipt['images']['device-runtime']['source_commit_binding'] == 'not-assessed'
    server = receipt['images']['server-image']
    assert server['archive_sha256'] == inputs['server_sha256']
    assert [layer['inventory']['package_databases'][0]['packages'][0]['version'] for layer in server['layers']] == ['1.0', '2.0']
    latest = server['merged']['package_databases'][0]['packages'][0]
    assert latest['source'] == 'upstream' and latest['source_version'] == '2.0'
    assert latest['built_using'] == [{'source': 'static-one', 'version': '1:2.3'}, {'source': 'static-two', 'version': '4.5'}]
    assert latest['static_built_using'] == [{'source': 'other', 'version': '9.0'}]
    assert server['layers'][0]['inventory']['notice_files'][0]['availability'] == 'regular-file'
    assert server['merged']['notice_files'] == []
    assert server['merged']['unknown_executables'] == ['usr/bin/mystery']
    assert {row['source_attribution'] for row in server['merged']['executables']} == {'unresolved'}
    metadata = server['merged']['runtime_metadata']
    assert [(row['component'], row['version']) for row in metadata] == [('cpython', '3.12.15'), ('python-distribution', '25.0.1')]
    platforms = receipt['images']['device-runtime']['platforms']
    assert [row['platform'] for row in platforms] == ['linux/amd64', 'linux/arm64']
    for image in platforms:
        packages = image['merged']['package_databases'][0]['packages']
        assert packages[0]['origin'] == 'upstream' and packages[0]['aports_commit'] == 'b' * 40
        assert packages[0]['declared_file_count'] == 1
        assert packages[1]['virtual'] is True and packages[1]['origin'] is None
    assert path.stat().st_mode & 0o777 == 0o444 and path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize('before', [True, False])
def test_opaque_whiteouts_only_remove_lower_layer_members(tmp_path, before):
    first = tmp_path / 'first.tar'
    first.write_bytes(tar_bytes([entry('etc/old', b'old', mode=0o755), entry('elsewhere', b'keep', mode=0o755)]))
    second = tmp_path / 'second.tar'
    whiteout, addition = entry('etc/.wh..wh..opq'), entry('etc/new', b'new', mode=0o755)
    second.write_bytes(tar_bytes([whiteout, addition] if before else [addition, whiteout]))
    filesystem = {}
    c._layer(first, filesystem)
    changed, merged = c._layer(second, filesystem)
    assert {row['path'] for row in merged['executables']} == {'elsewhere', 'etc/new'}
    assert [row['path'] for row in changed['executables']] == ['etc/new']


def test_normal_tar_root_directory_header_is_supported(tmp_path):
    path = tmp_path / 'layer.tar'
    path.write_bytes(tar_bytes([entry('.', kind=tarfile.DIRTYPE), entry('bin/demo', b'demo', mode=0o755)]))
    _, merged = c._layer(path, {})
    assert merged['unknown_executables'] == ['bin/demo']


def test_regular_whiteout_and_same_layer_replacement_are_order_independent(tmp_path):
    path = tmp_path / 'layer.tar'
    path.write_bytes(tar_bytes([entry('usr/bin/demo', b'new', mode=0o755), entry('usr/bin/.wh.demo')]))
    filesystem = {'usr/bin/demo': {'type': 'file', 'mode': 0o755, 'size': 3, 'sha256': sha(b'old')}}
    _, merged = c._layer(path, filesystem)
    assert merged['executables'][0]['sha256'] == sha(b'new')


def test_hardlinks_copy_bytes_before_future_target_replacement(tmp_path):
    path = tmp_path / 'first.tar'
    path.write_bytes(tar_bytes([entry('bin/original', b'old', mode=0o755),
                              entry('bin/alias', kind=tarfile.LNKTYPE, target='bin/original')]))
    filesystem = {}
    c._layer(path, filesystem)
    path.write_bytes(tar_bytes([entry('bin/original', b'new', mode=0o755)]))
    _, merged = c._layer(path, filesystem)
    assert {row['path']: row['sha256'] for row in merged['executables']} == {'bin/original': sha(b'new'), 'bin/alias': sha(b'old')}


@pytest.mark.parametrize('link_first', [True, False])
def test_same_layer_hardlink_observes_tar_order(tmp_path, link_first):
    path = tmp_path / 'layer.tar'
    path.write_bytes(tar_bytes([entry('bin/original', b'old', mode=0o755)]))
    filesystem = {}
    c._layer(path, filesystem)
    alias = entry('bin/alias', kind=tarfile.LNKTYPE, target='bin/original')
    replacement = entry('bin/original', b'new', mode=0o755)
    path.write_bytes(tar_bytes([alias, replacement] if link_first else [replacement, alias]))
    _, merged = c._layer(path, filesystem)
    hashes = {row['path']: row['sha256'] for row in merged['executables']}
    assert hashes == {'bin/original': sha(b'new'), 'bin/alias': sha(b'old' if link_first else b'new')}


def test_forward_hardlink_is_refused_instead_of_inventing_bytes(tmp_path):
    path = tmp_path / 'layer.tar'
    path.write_bytes(tar_bytes([entry('bin/alias', kind=tarfile.LNKTYPE, target='bin/later'),
                              entry('bin/later', b'new', mode=0o755)]))
    with pytest.raises(InstallError, match='earlier regular'):
        c._layer(path, {})


def test_selected_hardlink_to_uncollected_bytes_is_explicitly_unresolved(tmp_path):
    path = tmp_path / 'layer.tar'
    path.write_bytes(tar_bytes([entry('ordinary', b'not captured by inventory selection'),
                              entry('usr/share/doc/demo/copyright', kind=tarfile.LNKTYPE, target='ordinary'),
                              entry('opt/iris/bin/aria2c', kind=tarfile.LNKTYPE, target='ordinary')]))
    _, inventory = c._layer(path, {})
    notice = inventory['notice_files'][0]
    assert notice['type'] == 'unresolved-hardlink'
    assert notice['availability'] == 'link-target-not-assessed' and 'sha256' not in notice
    assert inventory['copied_component_files'][0]['type'] == 'unresolved-hardlink'
    assert inventory['copied_component_files'][0]['source_attribution'] == 'unresolved'


@pytest.mark.parametrize('members', [
    [entry('../escape', b'x')], [entry('/absolute', b'x')], [entry('a/../b', b'x')], [entry('.', b'not a directory')],
    [entry('same', b'one'), entry('same', b'two')], [entry('sparse', b'x', pax_headers={'GNU.sparse.size': '1'})],
    [entry('bad', kind=tarfile.SYMTYPE, target='../../outside')],
    [entry('bad', kind=tarfile.LNKTYPE, target='missing')],
    [entry('parent', kind=tarfile.SYMTYPE, target='elsewhere'), entry('parent/child', b'x')],
    [entry('device', kind=tarfile.CHRTYPE)], [entry('.wh.')], [entry('.wh.file', b'nonempty')],
    [entry('.wh.parent/child', b'invalid')],
])
def test_unsafe_layers_are_rejected_without_extraction(tmp_path, members):
    path = tmp_path / 'bad.tar'
    path.write_bytes(tar_bytes(members))
    with pytest.raises(InstallError):
        c._layer(path, {})
    assert set(tmp_path.iterdir()) == {path}


@pytest.mark.parametrize('change', ['unterminated', 'trailing'])
def test_layer_termination_is_enforced(tmp_path, change):
    data = tar_bytes([entry('file', b'x')])
    data = data[:1024] if change == 'unterminated' else data + b'X' * 512
    path = tmp_path / 'bad.tar'
    path.write_bytes(data)
    with pytest.raises(InstallError, match='terminated|trailing'):
        c._layer(path, {})


@pytest.mark.parametrize('raw', [debian() + debian(), debian().replace(b'Package: demo', b'Package: demo\nPackage: other'),
    debian(extra='Built-Using: bad (>= 1.0)\n'), debian(extra='Source: duplicate\n'),
    debian().replace(b'Architecture: amd64', b'Architecture: ../bad'), b'\xff', b'\0'])
def test_malformed_debian_metadata_is_not_silently_accepted(raw):
    with pytest.raises(InstallError):
        c._debian(raw)


@pytest.mark.parametrize('raw', [alpine() + alpine(), alpine().replace(b'c:' + b'b' * 40, b'c:short'),
    alpine().replace(b'o:upstream\n', b''), alpine().replace(b'P:demo', b'P:demo\nP:other'),
    alpine().replace(b'P:.python-rundeps', b'P:.unrecognized-virtual'),
    alpine().replace(b'D:demo', b'D:demo\nF:usr/bin\nR:executable')])
def test_malformed_or_unattributable_apk_metadata_is_rejected(raw):
    with pytest.raises(InstallError):
        c._alpine(raw)


@pytest.mark.parametrize('role', ['server', 'console', 'neutral'])
def test_wrong_expected_digest_never_publishes(inputs, role):
    inputs[role + '_sha256'] = '0' * 64
    with pytest.raises(InstallError, match='expected digest'):
        c.inspect_components(**inputs)
    assert not inputs['output_dir'].exists()


def test_revision_and_diffid_mismatch_fail_before_inventory(inputs):
    path = inputs['server_archive']
    for data in (docker([tar_bytes([entry('x', b'x')])], revision='b' * 40),
                 docker([tar_bytes([entry('x', b'x')])], diff_ids=['sha256:' + '0' * 64])):
        path.write_bytes(data)
        inputs['server_sha256'] = sha(data)
        with pytest.raises(InstallError):
            c.inspect_components(**inputs)
        assert not inputs['output_dir'].exists()


def test_missing_revision_is_not_reported_as_proven_commit(inputs):
    path = inputs['server_archive']
    data = docker([tar_bytes([entry('x', b'x')])], revision=None)
    path.write_bytes(data)
    inputs['server_sha256'] = sha(data)
    with pytest.raises(InstallError, match='exact selected commit'):
        c.inspect_components(**inputs)
    assert not inputs['output_dir'].exists()


def test_outer_archive_termination_and_duplicate_members_fail(inputs):
    path = inputs['server_archive']
    original = path.read_bytes()
    for data in (original + b'X' * 512, tar_bytes([entry('same', b'x'), entry('same', b'y')])):
        path.write_bytes(data)
        inputs['server_sha256'] = sha(data)
        with pytest.raises(InstallError):
            c.inspect_components(**inputs)
        assert not inputs['output_dir'].exists()


def test_snapshot_is_private_and_original_substitution_does_not_change_evidence(inputs, monkeypatch):
    original = c.kit._snapshot
    expected = inputs['server_sha256']
    def changed(source, destination, maximum):
        result = original(source, destination, maximum)
        if source == inputs['server_archive']:
            source.write_bytes(b'changed after snapshot')
        return result
    monkeypatch.setattr(c.kit, '_snapshot', changed)
    receipt = json.loads(c.inspect_components(**inputs).read_bytes())
    assert receipt['images']['server-image']['archive_sha256'] == expected


def test_existing_output_is_unchanged(inputs):
    inputs['output_dir'].mkdir()
    (inputs['output_dir'] / 'sentinel').write_text('owner')
    with pytest.raises(InstallError, match='already exists'):
        c.inspect_components(**inputs)
    assert (inputs['output_dir'] / 'sentinel').read_text() == 'owner'


def test_output_parent_replacement_preserves_replacement_sentinel(inputs, monkeypatch):
    parent = inputs['output_dir'].parent / 'owned-parent'
    parent.mkdir(mode=0o700)
    inputs['output_dir'] = parent / 'inventory'
    original, replaced = c._docker, False
    def changed(path, commit, work, descriptor):
        nonlocal replaced
        result = original(path, commit, work, descriptor)
        if not replaced:
            replaced = True
            temporary_name = next(parent.iterdir()).name
            parent.rename(parent.with_name('moved-parent'))
            parent.mkdir(mode=0o700)
            (parent / temporary_name).mkdir()
            (parent / temporary_name / 'sentinel').write_text('owner')
        return result
    monkeypatch.setattr(c, '_docker', changed)
    with pytest.raises(InstallError, match='parent changed'):
        c.inspect_components(**inputs)
    assert [p.read_text() for p in parent.glob('*/sentinel')] == ['owner']
    assert not inputs['output_dir'].exists()


def test_workspace_replacement_cleanup_follows_owned_fd(inputs, monkeypatch):
    original, replacement = c._docker, []
    def changed(path, commit, work, descriptor):
        result = original(path, commit, work, descriptor)
        moved = work.with_name(work.name + '-moved')
        work.rename(moved)
        work.mkdir(mode=0o700)
        (work / 'sentinel').write_text('owner')
        replacement.extend((work, moved))
        return result
    monkeypatch.setattr(c, '_docker', changed)
    try:
        with pytest.raises(InstallError, match='working directory changed'):
            c.inspect_components(**inputs)
        assert (replacement[0] / 'sentinel').read_text() == 'owner'
        assert list(replacement[1].iterdir()) == []
    finally:
        if replacement:
            (replacement[0] / 'sentinel').unlink()
            replacement[0].rmdir()
            replacement[1].rmdir()


def test_layer_cleanup_cannot_delete_replacement_workspace_file(inputs, monkeypatch):
    original, replacement = c._layer, []
    def changed(path, filesystem):
        result = original(path, filesystem)
        work = path.resolve().parent
        moved = work.with_name(work.name + '-moved')
        work.rename(moved)
        work.mkdir(mode=0o700)
        (work / path.name).write_text('foreign layer sentinel')
        replacement.extend((work, moved, path.name))
        return result
    monkeypatch.setattr(c, '_layer', changed)
    try:
        with pytest.raises(InstallError, match='working directory changed'):
            c.inspect_components(**inputs)
        assert (replacement[0] / replacement[2]).read_text() == 'foreign layer sentinel'
        assert list(replacement[1].iterdir()) == []
    finally:
        if replacement:
            (replacement[0] / replacement[2]).unlink()
            replacement[0].rmdir()
            replacement[1].rmdir()


@pytest.mark.parametrize('bound', ['MAX_PACKAGES', 'MAX_MEMBERS', 'MAX_FILE_METADATA', 'MAX_METADATA', 'MAX_RECEIPT'])
def test_inventory_bounds_fail_closed(inputs, monkeypatch, bound):
    monkeypatch.setattr(c, bound, 1)
    with pytest.raises(InstallError):
        c.inspect_components(**inputs)
    assert not inputs['output_dir'].exists()


def test_notice_links_are_not_claimed_present_or_covered(tmp_path):
    path = tmp_path / 'layer.tar'
    path.write_bytes(tar_bytes([entry('usr/share/doc/pkg/copyright', kind=tarfile.SYMTYPE, target='../other/copyright')]))
    _, inventory = c._layer(path, {})
    assert inventory['notice_files'][0]['availability'] == 'link-target-not-assessed'
    assert inventory['notice_files'][0]['source_attribution'] == 'unresolved'


def test_python_distribution_paths_are_not_inferred_to_be_cpython_or_pip():
    assert c._component('usr/local/lib/python3.12/site-packages/pipenv/runtime.py') == 'python-distribution-unresolved'
    assert c._component('usr/local/lib/python3.12/site-packages/other/__init__.py') == 'python-distribution-unresolved'
    assert c._component('usr/local/lib/python3.12/site-packages/pip/__init__.py') == 'pip-and-vendored-components'


def test_cli_requires_explicit_pins_and_helper_ships():
    assert 'tools/inspect-image-components.py' in (ROOT / 'tools/make-release.sh').read_text()
    with pytest.raises(SystemExit) as caught:
        c.main([])
    assert caught.value.code == 2
