# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Public inventory supports real projected files without relaxing key custody."""
import hashlib
import json
import os
from pathlib import Path
import ssl

import pytest

import certificate_lifecycle as lifecycle
import instruction_keys as keys
from test_setup_status import CERT_A


def projected(tmp_path, content=CERT_A):
    mount = tmp_path / 'management'
    generation = mount / '..2026_10_10_18_19_15.1623032529'
    generation.mkdir(parents=True)
    (generation / 'tls.crt').write_text(content)
    (mount / '..data').symlink_to(generation.name)
    (mount / 'tls.crt').symlink_to('..data/tls.crt')
    return mount / 'tls.crt', generation / 'tls.crt'


def observe(path):
    return lifecycle.x509_row('management-tls', 'Console-to-server TLS', path,
                             'Public observation only', 1_800_000_000)


def test_real_projected_secret_public_inventory_preserves_private_reader(tmp_path, monkeypatch):
    path, target = projected(tmp_path, CERT_A + '\nPRIVATE KEY sentinel-private-material\n')
    monkeypatch.setenv('IRIS_MANAGEMENT_API_CERT', str(path))
    monkeypatch.setenv('IRIS_CERT', str(tmp_path / 'missing-device-cert'))
    calls = []
    original = lifecycle.subprocess.run

    def openssl(argv, **kwargs):
        calls.append((argv, kwargs['input']))
        assert b'PRIVATE' not in kwargs['input'] and b'sentinel' not in kwargs['input']
        return original(argv, **kwargs)

    monkeypatch.setattr(lifecycle.subprocess, 'run', openssl)
    paths = keys.InstructionPaths(state_dir=str(tmp_path / 'state'),
                                  config_dir=str(tmp_path / 'config'),
                                  run_dir=str(tmp_path / 'run'))
    report = lifecycle.inventory(paths=paths, now=1_800_000_000)
    row = next(item for item in report['items'] if item['id'] == 'management-tls')
    assert report['scope'] == 'server-certificate-files'
    assert 'do not prove' in report['note']
    assert row['fingerprint_sha256'] == hashlib.sha256(ssl.PEM_cert_to_DER_cert(CERT_A)).hexdigest()
    assert row['state'] != 'unknown' and row['source'] == 'server-file'
    assert len(calls) == 1 and calls[0][0] == ['openssl', 'x509', '-noout', '-startdate', '-enddate']
    assert 'sentinel' not in json.dumps(report) and 'PRIVATE' not in json.dumps(report)
    assert path.is_symlink() and target.read_text().endswith('sentinel-private-material\n')
    with pytest.raises(keys.InstructionKeyError):
        keys._read_regular(path, 65536, unavailable='strict key custody', too_large='oversized')


@pytest.mark.parametrize('kind', ['generation', 'target', 'contents'])
def test_changed_projected_generation_or_file_is_unknown(tmp_path, monkeypatch, kind):
    path, target = projected(tmp_path)
    original = keys._read_regular

    def changed(selected, *args, **kwargs):
        raw = original(selected, *args, **kwargs)
        if kind == 'generation':
            next_generation = path.parent / '..2026_10_10_19_19_15.1623032529'
            next_generation.mkdir()
            (next_generation / 'tls.crt').write_text(CERT_A)
            pending = path.parent / '..data_tmp'
            pending.symlink_to(next_generation.name)
            os.replace(pending, path.parent / '..data')
        elif kind == 'target':
            replacement = target.with_name('replacement')
            replacement.write_text(CERT_A)
            os.replace(replacement, target)
        else:
            target.write_text(CERT_A + '\nchanged')
        return raw

    monkeypatch.setattr(keys, '_read_regular', changed)
    assert observe(path)['state'] == 'unknown'


@pytest.mark.parametrize('kind', ['fifo', 'directory', 'dangling', 'loop', 'oversized', 'not-certificate'])
def test_public_inventory_refuses_special_invalid_or_oversized_input(tmp_path, monkeypatch, kind):
    path = tmp_path / 'tls.crt'
    if kind == 'fifo': os.mkfifo(path)
    elif kind == 'directory': path.mkdir()
    elif kind == 'dangling': path.symlink_to('missing')
    elif kind == 'loop': path.symlink_to(path.name)
    elif kind == 'oversized': path.write_bytes(b'x' * (2 * 1024 * 1024 + 1))
    else: path.write_text('PRIVATE KEY not-a-certificate')
    monkeypatch.setattr(lifecycle.subprocess, 'run', lambda *args, **kwargs: pytest.fail('Invalid input reached OpenSSL'))
    row = observe(path)
    assert row['state'] == 'unknown' and row['fingerprint_sha256'] is None


def test_symlink_substituted_for_resolved_leaf_before_open_is_refused(tmp_path, monkeypatch):
    path, target = projected(tmp_path)
    other = tmp_path / 'other.pem'
    other.write_text(CERT_A)
    original = keys._read_regular

    def substituted(selected, *args, **kwargs):
        assert Path(selected) == target
        target.unlink()
        target.symlink_to(other)
        return original(selected, *args, **kwargs)

    monkeypatch.setattr(keys, '_read_regular', substituted)
    assert observe(path)['state'] == 'unknown'
