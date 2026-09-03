# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import types
import time
from importlib.machinery import SourceFileLoader

import secrets_store

# ---------------------------------------------------------------------------
# Loader: import iris-revoke (no .py extension) via SourceFileLoader
# ---------------------------------------------------------------------------
_CLI_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "iris-revoke")


def _load_cli():
    loader = SourceFileLoader("iris_revoke", _CLI_PATH)
    mod = types.ModuleType("iris_revoke")
    mod.__file__ = _CLI_PATH
    loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store(tmp_path, device_id="dev-1"):
    """Create a secrets store with all three secret types minted."""
    sp = str(tmp_path / "secrets.json")
    now = time.time()
    store = secrets_store.load(sp)
    secrets_store.mint(store, device_id, "catalog_token", now)
    secrets_store.mint(store, device_id, "announce_token", now)
    secrets_store.mint(store, device_id, "rpc_secret", now)
    secrets_store.save(store, sp)
    return sp


# ---------------------------------------------------------------------------
# Task 6 tests
# ---------------------------------------------------------------------------

def test_revoke_sets_all_device_records(tmp_path, monkeypatch):
    """iris-revoke <device_id> sets revoked=True on all that device's records."""
    sp = _make_store(tmp_path, "dev-1")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")  # skip encrypt_from
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    rc = mod.main(["dev-1"])
    assert rc == 0

    store = secrets_store.load(sp)
    for secret_name, record in store["devices"]["dev-1"].items():
        assert record["revoked"] is True, "%s not revoked" % secret_name


def test_revoke_leaves_other_devices_untouched(tmp_path, monkeypatch):
    """Revoking dev-1 does not affect dev-2."""
    sp = str(tmp_path / "secrets.json")
    now = time.time()
    store = secrets_store.load(sp)
    secrets_store.mint(store, "dev-1", "catalog_token", now)
    secrets_store.mint(store, "dev-2", "catalog_token", now)
    secrets_store.save(store, sp)

    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    rc = mod.main(["dev-1"])
    assert rc == 0

    store2 = secrets_store.load(sp)
    assert store2["devices"]["dev-1"]["catalog_token"]["revoked"] is True
    assert store2["devices"]["dev-2"]["catalog_token"]["revoked"] is False


def test_revoke_unknown_device_returns_rc1(tmp_path, monkeypatch):
    """Revoking a device not in the store → rc 1."""
    sp = str(tmp_path / "secrets.json")
    secrets_store.save(secrets_store.load(sp), sp)
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    rc = mod.main(["no-such-device"])
    assert rc == 1


def test_revoke_no_args_returns_rc2(tmp_path, monkeypatch):
    """No arguments → usage error rc 2."""
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "secrets.json"))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    rc = mod.main([])
    assert rc == 2


def test_revoke_too_many_args_returns_rc2(tmp_path, monkeypatch):
    """Too many arguments → usage error rc 2."""
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "secrets.json"))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    rc = mod.main(["dev-1", "extra"])
    assert rc == 2


def test_revoke_refuses_corrupt_store(tmp_path, monkeypatch, capsys):
    """A present-but-unreadable store is refused, not treated as empty.

    Regression for IRIS-01-002: load() used to return the empty skeleton for a
    truncated store, so a revoke would re-encrypt that emptiness over the only
    durable copy of every device credential. The CLI must now stop with rc 1
    and a message that names the path but no file content.
    """
    sp = str(tmp_path / "secrets.json")
    with open(sp, "w") as f:
        f.write('{"devices": {"dev-1":')      # truncated JSON
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    rc = mod.main(["dev-1"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "unreadable" in err
    assert "dev-1\":" not in err               # never echoes file content
