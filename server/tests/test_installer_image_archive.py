# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Both Docker image-store identity formats retain immutable export binding."""

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer.kube_deploy import _archive_identity
from iris_installer.state import InstallError


def archive(path, entries):
    with tarfile.open(path, 'w') as output:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            output.addfile(member, io.BytesIO(data))


def test_classic_store_binds_config_digest(tmp_path):
    _archive_identity(tmp_path / 'unused', 'sha256:' + 'a' * 64, 'sha256:' + 'a' * 64)


@pytest.mark.parametrize('identity', [None, '', 'invalid'])
def test_missing_identity_cannot_match_missing_config(tmp_path, identity):
    with pytest.raises(InstallError):
        _archive_identity(tmp_path / 'unused', identity, identity)


@pytest.mark.parametrize('corruption', [None, 'blob', 'reference', 'duplicate', 'missing'])
def test_containerd_store_binds_actual_root_blob(tmp_path, corruption):
    root = b'{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}'
    identity = 'sha256:' + hashlib.sha256(root).hexdigest()
    name = 'blobs/sha256/' + identity.split(':')[1]
    reference = 'sha256:' + 'b' * 64 if corruption == 'reference' else identity
    entries = [('index.json', json.dumps({'manifests': [{'digest': reference}]}).encode()),
               (name, b'changed' if corruption == 'blob' else root)]
    if corruption == 'duplicate':
        entries.append(entries[-1])
    if corruption == 'missing':
        entries.pop()
    path = tmp_path / 'image.tar'
    archive(path, entries)
    if corruption is None:
        _archive_identity(path, identity, 'sha256:' + 'c' * 64)
    else:
        with pytest.raises(InstallError):
            _archive_identity(path, identity, 'sha256:' + 'c' * 64)
