# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Retained exact dependencies must not change the shipped client or its source."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import urllib.error

import pytest

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pinned_rebuild', REPO / 'tools/aria2c-build/rebuild-pinned.py')
pinned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pinned)


def record(data=b'fixture package'):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def test_lock_contains_both_original_complete_toolchains():
    lock = pinned.lock_data()
    assert set(lock['packages']) == {'x86_64', 'aarch64'}
    assert set(lock['packages']['x86_64']) == set(lock['packages']['aarch64'])
    for packages in lock['packages'].values():
        assert len(packages) == 53
        for name in ('openssl-dev-3.5.8-r0.apk', 'openssl-libs-static-3.5.8-r0.apk',
                     'zlib-static-1.3.2-r0.apk', 'gcc-15.2.0-r5.apk', 'c-ares-dev-1.34.8-r0.apk'):
            assert name in packages
    recipe = (REPO / 'tools/aria2c-build/Dockerfile').read_text()
    assert 'FROM ' + lock['base_image'] + ' AS toolchain' in recipe


def test_recipe_changes_only_package_acquisition():
    original = (REPO / 'tools/aria2c-build/Dockerfile').read_text()
    result = pinned.offline_recipe(original, pinned.lock_data()['base_image'])
    marker = '# Record exactly what got installed'
    assert result[result.index(marker):] == original[original.index(marker):]
    assert 'apk verify *.apk' in result
    assert '--no-network --no-cache --repositories-file /dev/null' in result
    assert 'sha256sum -c SHA256SUMS' in result
    assert '--allow-untrusted' not in result
    with pytest.raises(ValueError, match='different base'):
        pinned.offline_recipe(original, 'different-base')
    with pytest.raises(ValueError, match='exactly one'):
        pinned.offline_recipe(result, pinned.lock_data()['base_image'])


@pytest.mark.parametrize('kind', ('changed', 'size', 'symlink', 'fifo'))
def test_changed_cache_is_preserved_not_silently_redownloaded(tmp_path, monkeypatch, kind):
    directory = pinned.safe_directory(tmp_path / 'x86_64')
    path = directory / 'package.apk'
    expected = record()
    if kind == 'symlink':
        target = tmp_path / 'target'
        target.write_bytes(b'fixture package')
        path.symlink_to(target)
    elif kind == 'fifo':
        os.mkfifo(path)
    else:
        path.write_bytes(b'fixture package' if kind == 'size' else b'changed package')
        if kind == 'size':
            expected['bytes'] = 5
    monkeypatch.setattr(pinned.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('must not fetch'))
    with pytest.raises(ValueError):
        pinned.cached_package(tmp_path, 'x86_64', 'package.apk', expected, ['https://example.invalid/'])
    assert path.exists()


def test_offline_requires_complete_cache_without_network(tmp_path, monkeypatch):
    monkeypatch.setattr(pinned.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('offline'))
    with pytest.raises(ValueError, match='missing'):
        pinned.cached_package(tmp_path, 'x86_64', 'package.apk', record(), [], offline=True)
    path = tmp_path / 'x86_64/package.apk'
    path.write_bytes(b'fixture package')
    assert pinned.cached_package(tmp_path, 'x86_64', 'package.apk', record(), [], offline=True) == path


class Download(io.BytesIO):
    def geturl(self):
        return 'https://mirror.example.invalid/package.apk'


def test_withdrawn_package_falls_back_and_publishes_exact_bytes(tmp_path, monkeypatch):
    urls = []

    def get(url, **kwargs):
        urls.append(url)
        if len(urls) == 1:
            raise urllib.error.HTTPError(url, 404, 'removed', None, None)
        return Download(b'fixture package')

    monkeypatch.setattr(pinned.urllib.request, 'urlopen', get)
    result = pinned.cached_package(tmp_path, 'aarch64', 'package.apk', record(),
                                   ['https://first.invalid/', 'https://second.invalid/'])
    assert result.read_bytes() == b'fixture package'
    assert urls == ['https://first.invalid/aarch64/package.apk', 'https://second.invalid/aarch64/package.apk']
    assert list(result.parent.iterdir()) == [result]


@pytest.mark.parametrize('data', (b'changed package', b'too large a package', b'partial'))
def test_bad_download_never_enters_cache(tmp_path, monkeypatch, data):
    monkeypatch.setattr(pinned.urllib.request, 'urlopen', lambda *a, **k: Download(data))
    with pytest.raises(ValueError):
        pinned.cached_package(tmp_path, 'x86_64', 'package.apk', record(), ['https://first.invalid/'])
    assert not list((tmp_path / 'x86_64').iterdir())


def test_download_never_overwrites_a_competing_cache_writer(tmp_path, monkeypatch):
    original_link = os.link

    def raced(source, destination):
        Path(destination).write_bytes(b'owner data')
        original_link(source, destination)

    monkeypatch.setattr(pinned.os, 'link', raced)
    monkeypatch.setattr(pinned.urllib.request, 'urlopen', lambda *a, **k: Download(b'fixture package'))
    with pytest.raises(ValueError):
        pinned.cached_package(tmp_path, 'x86_64', 'package.apk', record(), ['https://first.invalid/'])
    assert (tmp_path / 'x86_64/package.apk').read_bytes() == b'owner data'


def test_mutated_source_fails_before_any_extraction(tmp_path, monkeypatch):
    source = tmp_path / 'source.tar.gz'
    source.write_bytes(b'not the published archive')
    output = tmp_path / 'extracted'
    output.mkdir()
    monkeypatch.setattr(pinned, 'load_helper', lambda *a: pytest.fail('must not extract'))
    with pytest.raises(ValueError, match='checksum mismatch'):
        pinned.source_tree(source, output)
    assert not list(output.iterdir())


def source_bundle(tmp_path, executable=False):
    root = tmp_path / 'source'
    root.mkdir()
    path = root / 'input'
    path.write_bytes(b'complete source input')
    path.chmod(0o755 if executable else 0o644)
    (root / 'SHA256SUMS').write_text(record(path.read_bytes())['sha256'] + '  input\n')
    destination = tmp_path / 'private'
    destination.mkdir()
    return root, destination


@pytest.mark.parametrize('executable', (False, True))
def test_extracted_source_is_privately_snapshotted_and_verified(tmp_path, executable):
    root, destination = source_bundle(tmp_path, executable)
    result = pinned.source_directory(root, destination)
    assert result == destination / 'checked-source'
    assert (result / 'input').read_bytes() == b'complete source input'
    assert (result / 'input').stat().st_mode & 0o777 == (0o755 if executable else 0o644)
    (root / 'input').write_bytes(b'caller changes afterward')
    assert (result / 'input').read_bytes() == b'complete source input'


@pytest.mark.parametrize('kind', ('hash', 'extra', 'symlink', 'fifo', 'root-link'))
def test_extracted_source_refuses_changed_extra_or_linked_members(tmp_path, kind):
    root, destination = source_bundle(tmp_path)
    if kind == 'hash':
        (root / 'input').write_bytes(b'changed')
    elif kind == 'extra':
        (root / 'extra').write_bytes(b'not listed')
    elif kind == 'symlink':
        (root / 'extra').symlink_to(tmp_path / 'absent')
    elif kind == 'fifo':
        os.mkfifo(root / 'extra')
    else:
        linked = tmp_path / 'linked'
        linked.symlink_to(root, target_is_directory=True)
        root = linked
    with pytest.raises(ValueError):
        pinned.source_directory(root, destination)


def test_extracted_directory_replacement_refuses_without_reading_replacement(tmp_path, monkeypatch):
    root, destination = source_bundle(tmp_path)
    original_scandir = pinned.os.scandir
    replaced = False

    def replacement(fd):
        nonlocal replaced
        if not replaced:
            root.rename(tmp_path / 'original')
            root.mkdir()
            (root / 'sentinel').write_bytes(b'owner replacement')
            replaced = True
        return original_scandir(fd)

    monkeypatch.setattr(pinned.os, 'scandir', replacement)
    with pytest.raises(ValueError, match='replaced'):
        pinned.source_directory(root, destination)
    assert (root / 'sentinel').read_bytes() == b'owner replacement'
    assert not (destination / 'checked-source/sentinel').exists()


def test_packaged_helper_import_creates_no_unlisted_bytecode(tmp_path, monkeypatch):
    (tmp_path / 'fixture.py').write_text('VALUE = 23\n')
    monkeypatch.setattr(pinned, 'SOURCE', tmp_path)
    monkeypatch.setattr(pinned.sys, 'dont_write_bytecode', False)
    assert pinned.load_helper('fixture').VALUE == 23
    assert list(tmp_path.iterdir()) == [tmp_path / 'fixture.py']
    assert pinned.sys.dont_write_bytecode is False


@pytest.mark.parametrize('architecture', ('x86_64', 'aarch64'))
@pytest.mark.parametrize('matching', (True, False))
@pytest.mark.parametrize('source_kind', ('archive', 'directory'))
def test_rebuild_disables_network_and_adopts_only_the_distributed_hash(tmp_path, monkeypatch, architecture, matching, source_kind):
    recipe = (REPO / 'tools/aria2c-build/Dockerfile').read_bytes()
    lock = pinned.lock_data()
    lock['packages'] = {arch: {'fixture-1-r0.apk': record()} for arch in pinned.ARCHES}
    monkeypatch.setattr(pinned, 'lock_data', lambda: lock)
    manifest = {'source_date_epoch': 12345, 'current_recipe_sha256': {'Dockerfile': record(recipe)['sha256']},
                'binary_sha256': {architecture: record(b'exact binary')['sha256']}}

    def extract(source, destination):
        root = destination / 'fixture'
        (root / 'current-recipe').mkdir(parents=True)
        (root / 'current-recipe/Dockerfile').write_bytes(recipe)
        (root / 'inputs.json').write_text(json.dumps(manifest))
        return root

    monkeypatch.setattr(pinned, 'source_tree', extract)
    monkeypatch.setattr(pinned, 'source_directory', extract)
    monkeypatch.setattr(pinned, 'load_helper', lambda name: SimpleNamespace(reconstruct=lambda root, target, manifest: target.mkdir()))
    monkeypatch.setattr(pinned.urllib.request, 'urlopen', lambda *a, **k: Download(b'fixture package'))
    commands = []

    def build(command, **kwargs):
        commands.append(command)
        output_arg = command[command.index('--output') + 1]
        output = Path(output_arg.removeprefix('type=local,dest='))
        output.mkdir()
        (output / 'aria2-next').write_bytes(b'exact binary' if matching else b'different binary')

    monkeypatch.setattr(pinned.subprocess, 'run', build)
    args = SimpleNamespace(architecture=architecture, jobs=2, output=tmp_path / 'result',
                           source_archive=tmp_path / 'source.tar.gz', cache=tmp_path / 'cache', offline=False, no_cache=True)
    if source_kind == 'directory':
        args.source_directory = tmp_path / 'source'
    if matching:
        evidence = pinned.build(args)
        assert (args.output / 'aria2c').read_bytes() == b'exact binary'
        assert evidence['source_directory_snapshotted' if source_kind == 'directory' else 'source_archive_unchanged'] is True
        with pytest.raises(ValueError, match='must be new'):
            pinned.build(args)
    else:
        with pytest.raises(ValueError, match='checksum mismatch'):
            pinned.build(args)
        assert not args.output.exists()
    assert len(commands) == 1
    command = commands[0]
    assert command[command.index('--network') + 1] == 'none'
    assert command[command.index('--platform') + 1] == pinned.ARCHES[architecture]
    assert '--no-cache' in command
