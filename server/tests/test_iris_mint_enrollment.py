# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import os
import sys
import types
import time
from importlib.machinery import SourceFileLoader

import pytest

import secrets_store
import auth

# ---------------------------------------------------------------------------
# Loader: import iris-mint-enrollment (no .py extension) via SourceFileLoader
# ---------------------------------------------------------------------------
_CLI_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "iris-mint-enrollment")


def _load_cli():
    loader = SourceFileLoader("iris_mint_enrollment", _CLI_PATH)
    mod = types.ModuleType("iris_mint_enrollment")
    mod.__file__ = _CLI_PATH
    loader.exec_module(mod)
    return mod


def _instruction_record(value, created_at, expires_at, revoked=False):
    return {
        "value": value,
        "key_id": hashlib.sha256(bytes.fromhex(value)).hexdigest(),
        "created_at": created_at,
        "expires_at": expires_at,
        "revoked": revoked,
        "_scope": "instructions",
    }


# ---------------------------------------------------------------------------
# Task 7 tests
# ---------------------------------------------------------------------------

def test_mint_enrollment_prints_token(tmp_path, monkeypatch, capsys):
    """iris-mint-enrollment <device_id> prints the token to stdout."""
    sp = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    monkeypatch.setenv("IRIS_ENROLL_TTL", "3600")

    mod = _load_cli()
    rc = mod.main(["new-device"])
    assert rc == 0

    out = capsys.readouterr().out.strip()
    assert len(out) == 32, "expected 32-hex-char token, got %r" % out

    # Token in store matches stdout
    store = secrets_store.load(sp)
    record = store["devices"]["new-device"]["catalog_token"]
    assert record["value"] == out


def test_mint_enrollment_expires_at_uses_enroll_ttl(tmp_path, monkeypatch):
    """expires_at - created_at should equal IRIS_ENROLL_TTL (default 3600)."""
    sp = str(tmp_path / "secrets.json")
    enroll_ttl = 7200
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    monkeypatch.setenv("IRIS_ENROLL_TTL", str(enroll_ttl))

    mod = _load_cli()
    before = time.time()
    rc = mod.main(["dev-enroll"])
    after = time.time()
    assert rc == 0

    store = secrets_store.load(sp)
    record = store["devices"]["dev-enroll"]["catalog_token"]
    lifetime = record["expires_at"] - record["created_at"]
    assert abs(lifetime - enroll_ttl) < 5, (
        "expected lifetime ~%d, got %d" % (enroll_ttl, lifetime))


def test_mint_enrollment_not_revoked(tmp_path, monkeypatch):
    """The minted enrollment token must not be revoked."""
    sp = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    mod.main(["dev-enroll2"])

    store = secrets_store.load(sp)
    record = store["devices"]["dev-enroll2"]["catalog_token"]
    assert record["revoked"] is False


def test_mint_enrollment_provisions_announce_and_rpc(tmp_path, monkeypatch):
    """Enrollment also provisions the device's three stable secrets.

    The installer bakes neither; the agent fetches them on its first
    token-refresh, which returns whatever is in the device record. If
    enrollment only mints catalog_token, the refresh bag comes back with empty
    announce_token/rpc_secret and the agent can neither join the swarm nor talk
    to its on-box aria2c.
    """
    sp = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    assert mod.main(["dev-prov"]) == 0

    dev = secrets_store.load(sp)["devices"]["dev-prov"]
    assert dev.get("announce_token", {}).get("value"), \
        "enrollment did not provision a device announce_token"
    assert dev.get("rpc_secret", {}).get("value"), \
        "enrollment did not provision a device rpc_secret"
    instr = dev["instr_key"]
    assert secrets_store.validate_instruction_key_record(instr) is instr
    assert instr["key_id"] == hashlib.sha256(
        bytes.fromhex(instr["value"])).hexdigest()


def test_reenrollment_replaces_revoked_stable_secrets(tmp_path, monkeypatch):
    sp = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_cli()
    assert mod.main(["retired"]) == 0
    old = secrets_store.load(sp)["devices"]["retired"]
    old_announce = old["announce_token"]["value"]
    old_rpc = old["rpc_secret"]["value"]
    old_instr = old["instr_key"]["value"]
    store = secrets_store.load(sp)
    secrets_store.revoke(store, "retired")
    secrets_store.save(store, sp)
    assert mod.main(["retired"]) == 0
    store = secrets_store.load(sp)
    dev = store["devices"]["retired"]
    assert dev["announce_token"]["value"] != old_announce
    assert dev["rpc_secret"]["value"] != old_rpc
    assert dev["instr_key"]["value"] != old_instr
    assert "instr_key_prev" not in dev
    index = secrets_store.build_announce_index(store)
    context = auth.resolve_announce_principal(
        "announce_token=" + dev["announce_token"]["value"], index, store,
        now=time.time(), grace=0)
    assert context.principal == auth.Principal("device", "retired")


def test_valid_stable_secrets_are_retained(tmp_path, monkeypatch):
    sp = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_cli()
    assert mod.main(["existing"]) == 0
    before = secrets_store.load(sp)["devices"]["existing"]
    assert mod.main(["existing"]) == 0
    after = secrets_store.load(sp)["devices"]["existing"]
    assert after["announce_token"]["value"] == before["announce_token"]["value"]
    assert after["rpc_secret"]["value"] == before["rpc_secret"]["value"]
    assert after["instr_key"] == before["instr_key"]
    assert after["catalog_token"]["value"] != before["catalog_token"]["value"]


@pytest.mark.parametrize("damage", ["expired-current", "malformed-current",
                                    "malformed-previous", "revoked-previous",
                                    "expired-previous", "duplicate-previous",
                                    "live-previous"])
def test_reenrollment_repairs_instruction_lineage(
        tmp_path, monkeypatch, capsys, damage):
    sp = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_cli()
    assert mod.main(["repair"]) == 0
    capsys.readouterr()
    before = secrets_store.load(sp)["devices"]["repair"]["instr_key"]
    store = secrets_store.load(sp)
    dev = store["devices"]["repair"]
    now = int(time.time())
    previous = _instruction_record("de" * 32, now - 10, now + 1000)
    dev["instr_key_prev"] = previous
    if damage == "expired-current":
        dev["instr_key"]["created_at"] = 1
        dev["instr_key"]["expires_at"] = 1 + 2592000
    elif damage == "malformed-current":
        dev["instr_key"]["key_id"] = "bad"
    elif damage == "malformed-previous":
        dev["instr_key_prev"]["key_id"] = "bad"
    elif damage == "revoked-previous":
        dev["instr_key_prev"]["revoked"] = True
    elif damage == "expired-previous":
        dev["instr_key_prev"]["created_at"] = 1
        dev["instr_key_prev"]["expires_at"] = 2
    elif damage == "duplicate-previous":
        previous = dict(before)
        previous["expires_at"] = now + 1000
        dev["instr_key_prev"] = previous
    secrets_store.save(store, sp)

    persist_calls = []
    real_persist = mod.secretfs.persist_store

    def persist(*args, **kwargs):
        persist_calls.append(True)
        return real_persist(*args, **kwargs)

    monkeypatch.setattr(mod.secretfs, "persist_store", persist)

    assert mod.main(["repair"]) == 0
    output = capsys.readouterr()
    assert len(output.out.strip()) == 32
    assert output.err == ""
    assert persist_calls == [True]
    after = secrets_store.load(sp)["devices"]["repair"]
    assert output.out.strip() == after["catalog_token"]["value"]
    assert secrets_store.validate_instruction_key_record(after["instr_key"])
    if damage in ("expired-current", "malformed-current"):
        assert after["instr_key"]["value"] != before["value"]
        assert "instr_key_prev" not in after
    elif damage != "live-previous":
        assert after["instr_key"] == before
        assert "instr_key_prev" not in after
    else:
        assert after["instr_key"] == before
        assert after["instr_key_prev"] == previous


def test_reenrollment_clears_previous_catalog_recovery_token(
        tmp_path, monkeypatch):
    """An explicit re-enrollment starts a new catalog-token lineage."""
    sp = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_cli()
    assert mod.main(["existing"]) == 0

    store = secrets_store.load(sp)
    store["devices"]["existing"]["catalog_token_prev"] = {
        "value": "a" * 32,
        "created_at": int(time.time()) - 10,
        "expires_at": int(time.time()) + 120,
        "revoked": False,
    }
    secrets_store.save(store, sp)

    assert mod.main(["existing"]) == 0
    assert "catalog_token_prev" not in (
        secrets_store.load(sp)["devices"]["existing"])


def test_reserved_seeder_device_id_is_rejected(tmp_path, monkeypatch, capsys):
    sp = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    assert _load_cli().main(["seeder"]) == 2
    assert "reserved" in capsys.readouterr().err
    assert not os.path.exists(sp)


def test_mint_enrollment_no_args_returns_rc2(tmp_path, monkeypatch):
    """No arguments → usage error rc 2."""
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "secrets.json"))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    rc = mod.main([])
    assert rc == 2


def test_mint_enrollment_too_many_args_returns_rc2(tmp_path, monkeypatch):
    """Too many arguments → usage error rc 2."""
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "secrets.json"))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    rc = mod.main(["dev-1", "extra"])
    assert rc == 2


def test_mint_enrollment_refuses_corrupt_store(tmp_path, monkeypatch, capsys):
    """A present-but-unreadable store is refused, not treated as empty.

    Regression for IRIS-01-002: minting against a skeleton returned for a
    corrupt store would persist an otherwise-empty store over the durable
    ciphertext, destroying every other device's credentials.
    """
    sp = str(tmp_path / "secrets.json")
    with open(sp, "w") as f:
        f.write("not json at all")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))

    mod = _load_cli()
    rc = mod.main(["dev-1"])
    assert rc == 1
    assert "unreadable" in capsys.readouterr().err
