# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Only the protected Guest Shell storage alias is normalized for peer TLS."""
import hashlib
import json
import os
from pathlib import Path

import pytest

import peer_revocations as rev


@pytest.fixture
def flash(tmp_path, monkeypatch):
    alias, storage = tmp_path / 'flash', tmp_path / 'bootflash'
    storage.mkdir()
    stage = storage / 'guest-share' / 'iris'
    stage.mkdir(parents=True)
    alias.symlink_to(storage)
    monkeypatch.setattr(rev, '_FLASH_ALIAS', alias)
    monkeypatch.setattr(rev, '_FLASH_STORAGE', storage)
    # Real temporary symlinks, with only the two system-owned metadata facts
    # supplied by this fixture. Never create or modify the host's /flash.
    owners = {alias: 0, tmp_path: 0}
    original = Path.lstat
    def system_metadata(path):
        value = original(path)
        if path in owners:
            fields = list(value)
            fields[4] = owners[path]
            value = os.stat_result(fields)
        return value
    monkeypatch.setattr(Path, 'lstat', system_metadata)
    return alias, storage, owners


def test_only_fixed_protected_flash_prefix_is_normalized(flash):
    alias, storage, _ = flash
    for target in (str(storage), storage.name):
        alias.unlink()
        alias.symlink_to(target)
        assert rev.peer_root(alias / 'guest-share' / 'iris') == storage / 'guest-share' / 'iris' / 'peer-tls'
    assert rev.peer_root(storage / 'guest-share' / 'iris') == storage / 'guest-share' / 'iris' / 'peer-tls'


@pytest.mark.parametrize('change', ['wrong-target', 'alias-owner', 'parent-owner', 'writable-parent', 'storage-link', 'nested-link', 'peer-link'])
def test_alias_does_not_hide_untrusted_or_nested_links(flash, change):
    alias, storage, owners = flash
    stage = alias / 'guest-share' / 'iris'
    outside = storage.parent / 'outside'
    outside.mkdir()
    if change == 'wrong-target':
        alias.unlink()
        alias.symlink_to(outside)
    elif change == 'alias-owner':
        owners[alias] = 12345
    elif change == 'parent-owner':
        owners[alias.parent] = 12345
    elif change == 'writable-parent':
        alias.parent.chmod(0o777)
    elif change == 'storage-link':
        storage.rename(storage.with_name('original-storage'))
        storage.symlink_to(storage.with_name('original-storage'))
    elif change == 'nested-link':
        (storage / 'guest-share' / 'iris').rmdir()
        (storage / 'guest-share' / 'iris').symlink_to(outside)
    elif change == 'peer-link':
        (storage / 'guest-share' / 'iris' / 'peer-tls').symlink_to(outside)
    with pytest.raises(rev.RevocationError):
        rev.peer_root(stage)
    assert not (outside / 'peer-tls').exists()


def test_other_alias_and_unsafe_path_spellings_are_rejected(tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    alias = tmp_path / 'untrusted'
    alias.symlink_to(real)
    for path in (alias, 'relative', tmp_path / '..' / 'escape', str(real) + '\nline'):
        with pytest.raises(rev.RevocationError):
            rev.peer_root(path)


def test_alias_replacement_during_validation_is_rejected(flash, monkeypatch):
    alias, storage, _ = flash
    expected = storage / 'guest-share' / 'iris' / 'peer-tls'
    original = Path.resolve
    def changed(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == expected:
            alias.rename(alias.with_name('old-flash'))
            alias.symlink_to(storage)
        return result
    monkeypatch.setattr(Path, 'resolve', changed)
    with pytest.raises(rev.RevocationError, match='changed during validation'):
        rev.peer_root(alias / 'guest-share' / 'iris')


def test_canonical_root_publishes_lease_without_traversing_later_alias_change(flash):
    alias, storage, _ = flash
    root = rev.peer_root(alias / 'guest-share' / 'iris')
    root.mkdir(mode=0o700)
    ca = root / 'ca.crt'
    ca.write_text('-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n')
    authority = hashlib.sha256(b'abc').hexdigest()
    data = '\n'.join([rev.MAGIC, authority, '1', '1000', '1300', ''])
    outside = storage.parent / 'untrusted'
    outside.mkdir()
    class Client:
        def get_peer_revocations(self, device, nonce):
            alias.unlink()
            alias.symlink_to(outside)
            return {'schema': 1, 'nonce': nonce, 'snapshot': data}
    result = rev.refresh(root, ca, 'device-a', Client(), now_fn=lambda: 1000)
    assert result == str(root / 'revocations.txt')
    assert (root / 'revocations.txt').read_text() == data
    assert not list(outside.iterdir())


def test_configuration_refresh_uses_same_canonical_root_and_ca(flash, monkeypatch):
    import agent_config
    import catalog_client
    alias, storage, _ = flash
    root = rev.peer_root(alias / 'guest-share' / 'iris')
    root.mkdir(mode=0o700)
    manifest = root / 'current.json'
    manifest.write_text(json.dumps({'generation': 'a' * 64}))
    manifest.chmod(0o600)
    monkeypatch.setattr(agent_config, 'load', lambda _: {'stage_dir': str(alias / 'guest-share' / 'iris'),
        'peer_tls_mode': 'required', 'catalog_url': 'https://catalog.invalid', 'catalog_token': 'test',
        'catalog_ca': 'test-public-ca', 'device_id': 'device-a'})
    monkeypatch.delenv('IRIS_PEER_TLS_MODE', raising=False)
    monkeypatch.setattr(rev.ssl, 'create_default_context', lambda **_: object())
    monkeypatch.setattr(catalog_client, 'CatalogClient', lambda *_, **__: object())
    calls = []
    monkeypatch.setattr(rev, 'refresh', lambda *args: calls.append(args))
    assert rev.refresh_configuration('test.conf', expected_root=root) is True
    assert calls[0][:3] == (root, root / ('a' * 64) / 'ca.crt', 'device-a')
    assert rev.refresh_configuration('test.conf', expected_root=alias / 'guest-share' / 'iris' / 'peer-tls') is False


@pytest.mark.parametrize('linked', ['root', 'ca'])
def test_raw_refresh_still_refuses_noncanonical_paths(flash, linked):
    alias, storage, _ = flash
    stage = storage / 'guest-share' / 'iris'
    root = stage / 'peer-tls'
    root.mkdir(mode=0o700)
    ca = root / 'ca.crt'
    ca.write_text('unused')
    if linked == 'root':
        root = alias / 'guest-share' / 'iris' / 'peer-tls'
    else:
        ca = alias / 'guest-share' / 'iris' / 'peer-tls' / 'ca.crt'
    with pytest.raises(rev.RevocationError):
        rev.refresh(root, ca, 'device-a', None)
