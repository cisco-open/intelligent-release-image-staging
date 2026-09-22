# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Source-publication integrity and archive safety regressions."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

DIRECTORY = Path(__file__).resolve().parents[2] / 'tools/aria2c-source'


def module(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), DIRECTORY / filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


bundle = module('build-source-bundle.py')
rebuild = module('rebuild.py')


def test_manifest_pins_complete_inputs():
    manifest = json.loads((DIRECTORY / 'inputs.json').read_text())
    assert len(manifest['patches']) == 10
    assert len(manifest['components']) == 5
    assert sum(len(c['sources']) for c in manifest['components']) == 60
    assert manifest['notice_count'] == 38
    assert bundle.digest(DIRECTORY / 'COPYING3') == manifest['gpl3_sha256']
    for name, digest in manifest['current_recipe_sha256'].items():
        assert bundle.digest(DIRECTORY.parent / 'aria2c-build' / name) == digest


def test_source_manifest_matches_committed_clients_and_patches():
    manifest = json.loads((DIRECTORY / 'inputs.json').read_text())
    binary_pins = {}
    for line in (DIRECTORY.parent / 'aria2c.sha256').read_text().splitlines():
        if line and not line.startswith('#'):
            checksum, architecture = line.split()
            binary_pins[architecture] = checksum
    assert manifest['binary_sha256'] == binary_pins
    root = DIRECTORY.parents[1]
    for architecture, checksum in binary_pins.items():
        assert bundle.digest(root / 'deliverables' / ('aria2c-' + architecture)) == checksum
    assert bundle.digest(root / 'bin/aria2c') == binary_pins['x86_64']
    for patch in manifest['patches']:
        assert bundle.digest(DIRECTORY.parent / 'aria2c-patches' / patch['file']) == patch['sha256']
    source_pins = [line.split() for line in (DIRECTORY / 'source.sha256').read_text().splitlines()
                   if line and not line.startswith('#')]
    assert len(source_pins) == 1
    checksum, filename = source_pins[0]
    assert len(checksum) == 64 and all(c in '0123456789abcdef' for c in checksum)
    assert filename == manifest['name'] + '.tar.gz'


@pytest.mark.parametrize('name', ['../outside', '/absolute', 'dir/../../outside'])
def test_input_path_traversal_rejected(tmp_path, name):
    with pytest.raises(ValueError, match='Unsafe input path'):
        bundle.checked_file(tmp_path, name, '0' * 64)


def test_input_hash_and_symlink_rejected(tmp_path):
    source = tmp_path / 'source'
    source.write_bytes(b'changed')
    with pytest.raises(ValueError, match='checksum mismatch'):
        bundle.checked_file(tmp_path, 'source', '0' * 64)
    (tmp_path / 'link').symlink_to(source)
    with pytest.raises(ValueError, match='Symlink'):
        bundle.checked_file(tmp_path, 'link', bundle.digest(source))


@pytest.mark.parametrize('name,kind', [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
    ('.git/config', tarfile.REGTYPE), ('link', tarfile.SYMTYPE), ('hardlink', tarfile.LNKTYPE), ('device', tarfile.CHRTYPE)])
def test_tar_rejects_unsafe_members_before_extraction(tmp_path, name, kind):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as archive:
        archive.addfile(tarfile.TarInfo('safe'))
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = '../escape'
        archive.addfile(member)
    data.seek(0)
    with tarfile.open(fileobj=data) as archive, pytest.raises(ValueError):
        bundle.safe_extract(archive, tmp_path)
    assert not list(tmp_path.iterdir())


def test_checksum_verification_detects_changes_and_extra_files(tmp_path):
    (tmp_path / 'source').write_bytes(b'original')
    (tmp_path / 'SHA256SUMS').write_text(bundle.digest(tmp_path / 'source') + '  source\n')
    assert bundle.verify_tree(tmp_path) == rebuild.verify(tmp_path) == 1
    (tmp_path / 'extra').write_text('unexpected')
    with pytest.raises(ValueError, match='file set mismatch'):
        bundle.verify_tree(tmp_path)
    with pytest.raises(ValueError, match='file set mismatch'):
        rebuild.verify(tmp_path)
    (tmp_path / 'extra').unlink()
    (tmp_path / 'source').write_bytes(b'changed')
    with pytest.raises(ValueError, match='checksum mismatch'):
        rebuild.verify(tmp_path)


def test_deterministic_archive_and_extraction(tmp_path):
    payload = tmp_path / 'payload'
    payload.mkdir()
    (payload / 'source').write_text('hello')
    (payload / 'SHA256SUMS').write_text(bundle.digest(payload / 'source') + '  source\n')
    first, second = tmp_path / 'first.tar.gz', tmp_path / 'second.tar.gz'
    bundle.write_archive(payload, first, 'bundle', 1234)
    bundle.write_archive(payload, second, 'bundle', 1234)
    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first) as archive:
        bundle.safe_extract(archive, tmp_path / 'extracted')
    assert bundle.verify_tree(tmp_path / 'extracted/bundle') == 1


def test_optimized_python_still_rejects_bad_upstream(tmp_path):
    upstream = tmp_path / 'upstream.tar'
    upstream.write_bytes(b'not the pin')
    output = tmp_path / 'source.tar.gz'
    result = subprocess.run([sys.executable, '-O', str(DIRECTORY / 'build-source-bundle.py'),
        '--inputs', str(tmp_path), '--upstream-archive', str(upstream), '--output', str(output)], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'Upstream archive checksum mismatch' in result.stderr
    assert not output.exists()


def test_existing_output_preserved(tmp_path):
    output = tmp_path / 'source.tar.gz'
    output.write_bytes(b'owner data')
    with pytest.raises(ValueError, match='already exists'):
        bundle.build(tmp_path, tmp_path / 'absent', output, tmp_path)
    assert output.read_bytes() == b'owner data'


def test_packaged_script_executable_mode_preserved(tmp_path):
    source, destination = tmp_path / 'build.sh', tmp_path / 'copied.sh'
    source.write_text('#!/bin/sh\nexit 0\n')
    source.chmod(0o775)
    bundle.copy_source(source, destination)
    assert destination.read_bytes() == source.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o755


def test_existing_sidecar_rejected_before_archive_write(tmp_path):
    output = tmp_path / 'source.tar.gz'
    sidecar = tmp_path / 'source.tar.gz.sha256'
    sidecar.write_text('owner data')
    with pytest.raises(ValueError, match='Checksum output already exists'):
        bundle.build(tmp_path, tmp_path / 'absent', output, tmp_path)
    assert not output.exists()
    assert sidecar.read_text() == 'owner data'


def test_publish_failure_rolls_back_own_sidecar(tmp_path, monkeypatch):
    source, destination = tmp_path / 'ready', tmp_path / 'release'
    source.write_bytes(b'complete')
    original_link = bundle.os.link
    def fail_archive(src, dst):
        if dst == destination:
            raise OSError('simulated publication failure')
        return original_link(src, dst)
    monkeypatch.setattr(bundle.os, 'link', fail_archive)
    with pytest.raises(OSError, match='publication failure'):
        bundle.publish(source, destination, bundle.digest(source))
    assert not destination.exists()
    assert not (tmp_path / 'release.sha256').exists()


def test_rebuild_rejects_unlisted_symlink(tmp_path):
    (tmp_path / 'SHA256SUMS').write_text('')
    (tmp_path / 'extra').symlink_to('/etc/passwd')
    with pytest.raises(ValueError, match='symlink'):
        rebuild.verify(tmp_path)


@pytest.mark.parametrize('name', ['dependencies/musl/APKBUILD',
    'original-producer-recipe/Dockerfile', 'original-producer-recipe/patches/0001.patch'])
def test_changed_inputs_fail_before_any_archive_write(tmp_path, monkeypatch, name):
    manifest_dir = tmp_path / 'manifest'
    manifest_dir.mkdir()
    inputs = tmp_path / 'inputs'
    source = inputs / name
    source.parent.mkdir(parents=True)
    source.write_bytes(b'changed input')
    upstream = tmp_path / 'upstream.tar'
    upstream.write_bytes(b'upstream bytes checked before parsing')
    (manifest_dir / 'inputs.json').write_text(json.dumps({
        'upstream_archive_sha256': bundle.digest(upstream), 'files': {name: '0' * 64}}))
    monkeypatch.setattr(bundle, 'HERE', manifest_dir)
    output = tmp_path / 'release.tar.gz'
    with pytest.raises(ValueError, match='Input checksum mismatch'):
        bundle.build(inputs, upstream, output, tmp_path)
    assert not output.exists()
    assert not (tmp_path / 'release.tar.gz.sha256').exists()
