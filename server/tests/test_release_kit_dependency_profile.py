# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local release assembly binds an optional dependency profile without execution."""

import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer.state import InstallError
from test_installer_offline_inputs import archive, dependency_rows
from test_release_kit_producer import inputs, producer, TAG, COMMIT


def assemble(inputs, dependency_archive):
    paths, output = inputs
    return producer.assemble(paths, output, tag=TAG, commit=COMMIT,
                             neutral_receipt=paths['device-runtime'].parent / 'neutral.manifest',
                             ubuntu_dependencies=dependency_archive)


def test_producer_selects_complete_profile_and_binds_actual_manifest(inputs, dependency_rows):
    paths, output = inputs
    rows, digest = dependency_rows
    dependency_archive = paths['source'].parent / 'dependencies.tar.gz'
    data = archive(rows)
    dependency_archive.write_bytes(data)
    result = assemble(inputs, dependency_archive)
    assert result['profile'] == 'ubuntu-dependencies'
    assert set(result['assets']) == producer.kit.PROFILES['ubuntu-dependencies']
    assert result['assets']['ubuntu-dependencies']['dependency_manifest_sha256'] == digest
    assert (output / producer.DEPENDENCY_NAME).read_bytes() == data
    assert json.loads((output / 'release-kit.json').read_text()) == result
    assert not any(name.startswith('attestation') for name in (path.name for path in output.iterdir()))


@pytest.mark.parametrize('changed', ['missing', 'hash', 'schema', 'trailing'])
def test_producer_refuses_incomplete_dependency_inventory_before_publication(inputs, dependency_rows, changed):
    paths, output = inputs
    rows, _ = dependency_rows
    rows = list(rows)
    if changed == 'missing':
        rows.pop()
    elif changed == 'hash':
        name, data, kind, mode = rows[-1]
        rows[-1] = (name, b'changed', kind, mode)
    elif changed == 'schema':
        name, data, kind, mode = rows[0]
        manifest = json.loads(data)
        manifest['host']['architecture'] = 'arm64'
        rows[0] = (name, json.dumps(manifest).encode(), kind, mode)
    path = paths['source'].parent / 'dependencies.tar.gz'
    path.write_bytes(archive(rows, suffix=b'additional archive' if changed == 'trailing' else b''))
    with pytest.raises(InstallError):
        assemble(inputs, path)
    assert list(output.iterdir()) == []


def test_existing_dependency_asset_is_preserved(inputs, dependency_rows):
    paths, output = inputs
    rows, _ = dependency_rows
    path = paths['source'].parent / 'dependencies.tar.gz'
    path.write_bytes(archive(rows))
    existing = output / producer.DEPENDENCY_NAME
    existing.write_bytes(b'owner artifact')
    with pytest.raises(InstallError, match='never replaces'):
        assemble(inputs, path)
    assert existing.read_bytes() == b'owner artifact' and len(list(output.iterdir())) == 1
