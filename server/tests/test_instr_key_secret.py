# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Instruction-secret custody, rotation and packaging contracts."""
import contextlib
import copy
import fcntl
import hashlib
import json
import os
import threading
from importlib.machinery import SourceFileLoader
from pathlib import Path
import types

import pytest

import auth
import secrets_store


SERVER_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_ROOT.parent
CLI_PATH = SERVER_ROOT / "iris-instr-key"
INSTR_FIELDS = {
    "value", "key_id", "created_at", "expires_at", "revoked", "_scope",
}


def _record(value="01" * 32, created_at=100, expires_at=None, revoked=False):
    if expires_at is None:
        expires_at = created_at + 2592000
    return {
        "value": value,
        "key_id": hashlib.sha256(bytes.fromhex(value)).hexdigest(),
        "created_at": created_at,
        "expires_at": expires_at,
        "revoked": revoked,
        "_scope": "instructions",
    }


def _store_with_device(now=100):
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "dev-1", "catalog_token", now)
    secrets_store.mint(store, "dev-1", "announce_token", now)
    secrets_store.mint(store, "dev-1", "rpc_secret", now)
    return store


def _load_cli():
    assert CLI_PATH.is_file(), "instruction-key rotation CLI is missing"
    loader = SourceFileLoader("iris_instr_key_test", str(CLI_PATH))
    module = types.ModuleType("iris_instr_key_test")
    module.__file__ = str(CLI_PATH)
    loader.exec_module(module)
    return module


def test_instruction_mint_uses_256_bits_and_closed_digest_record(monkeypatch):
    calls = []

    def entropy(nbytes):
        calls.append(nbytes)
        return "ab" * nbytes

    monkeypatch.setattr(secrets_store.secrets, "token_hex", entropy)
    store = {"devices": {}, "seeder": {}}
    value = secrets_store.mint(store, "dev-1", "instr_key", 123)
    record = store["devices"]["dev-1"]["instr_key"]

    assert secrets_store.SECRET_TYPES["instr_key"] == {
        "scope": "instructions", "ttl": 2592000, "auth": None, "bits": 256,
    }
    assert calls == [32]
    assert value == "ab" * 32
    assert set(record) == INSTR_FIELDS
    assert record == _record(value, created_at=123)


@pytest.mark.parametrize("bits", [0, -8, True, 128.0, "128", 127, 129, 255,
                                  257, 512])
def test_mint_rejects_unsupported_bits_before_entropy_or_mutation(
        monkeypatch, bits):
    store = {"devices": {}, "seeder": {}}
    before = copy.deepcopy(store)
    calls = []
    monkeypatch.setitem(
        secrets_store.SECRET_TYPES, "bad",
        {"scope": "bad", "ttl": 1, "auth": None, "bits": bits})
    monkeypatch.setattr(
        secrets_store.secrets, "token_hex",
        lambda nbytes: calls.append(nbytes) or "aa" * nbytes)

    with pytest.raises(secrets_store.CredentialMintError,
                       match="unsupported secret bit count"):
        secrets_store.mint(store, "dev-1", "bad", 1)
    assert calls == []
    assert store == before


@pytest.mark.parametrize(
    "secret_name,expected_expiry",
    [("catalog_token", 100 + secrets_store.SECRET_TYPES["catalog_token"]["ttl"]),
     ("announce_token", 0), ("rpc_secret", 0)],
)
def test_legacy_mint_record_and_entropy_are_unchanged(
        monkeypatch, secret_name, expected_expiry):
    calls = []
    monkeypatch.setattr(
        secrets_store.secrets, "token_hex",
        lambda nbytes: calls.append(nbytes) or "cd" * nbytes)
    store = {"devices": {}, "seeder": {}}
    value = secrets_store.mint(store, "dev-1", secret_name, 100.75)
    assert calls == [16]
    assert value == "cd" * 16
    assert store["devices"]["dev-1"][secret_name] == {
        "value": value, "created_at": 100,
        "expires_at": expected_expiry, "revoked": False,
    }


def test_malformed_instruction_record_does_not_break_legacy_mint(monkeypatch):
    store = {"devices": {"bad": {"instr_key": None}}, "seeder": {}}
    monkeypatch.setattr(secrets_store.secrets, "token_hex", lambda n: "ef" * n)
    value = secrets_store.mint(store, "good", "catalog_token", 100)
    assert value == "ef" * 16


def test_instruction_values_and_ids_never_enter_auth_indexes():
    store = _store_with_device()
    record = _record()
    store["devices"]["dev-1"]["instr_key"] = record
    store["devices"]["dev-1"]["instr_key_prev"] = _record(
        "02" * 32, expires_at=200)

    catalog_index = secrets_store.build_catalog_auth_index(store)
    announce_index = secrets_store.build_announce_index(store)
    for candidate in (record["value"], record["key_id"]):
        assert secrets_store.credential_for(catalog_index, candidate) is None
        assert secrets_store.credential_for(announce_index, candidate) is None
    catalog_value = store["devices"]["dev-1"]["catalog_token"]["value"]
    assert secrets_store.credential_for(catalog_index, catalog_value)[0] == (
        auth.Principal("device", "dev-1"))


def test_normal_rotation_preserves_old_identity_and_fixed_overlap(monkeypatch):
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    stable = copy.deepcopy(store["devices"]["dev-1"])
    old = copy.deepcopy(store["devices"]["dev-1"]["instr_key"])
    monkeypatch.setattr(secrets_store.secrets, "token_hex", lambda n: "03" * n)

    new_id = secrets_store.rotate_instruction_key(store, "dev-1", 500)
    dev = store["devices"]["dev-1"]
    assert new_id == dev["instr_key"]["key_id"]
    assert dev["instr_key"] == _record("03" * 32, created_at=500)
    expected_prev = dict(old, expires_at=500 + 604800)
    assert dev["instr_key_prev"] == expected_prev
    for name in ("catalog_token", "announce_token", "rpc_secret"):
        assert dev[name] == stable[name]


def test_expired_current_rotates_but_live_previous_blocks_repeat(monkeypatch):
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record(
        created_at=0, expires_at=2592000)
    monkeypatch.setattr(secrets_store.secrets, "token_hex", lambda n: "04" * n)
    secrets_store.rotate_instruction_key(store, "dev-1", 2592001)
    before = copy.deepcopy(store)
    with pytest.raises(secrets_store.InstructionKeyError,
                       match="previous instruction key overlap is active"):
        secrets_store.rotate_instruction_key(store, "dev-1", 2592002)
    assert store == before


def test_expired_previous_is_replaced_and_boundary_is_strict(monkeypatch):
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record("05" * 32)
    store["devices"]["dev-1"]["instr_key_prev"] = _record(
        "06" * 32, created_at=10, expires_at=500)
    monkeypatch.setattr(secrets_store.secrets, "token_hex", lambda n: "07" * n)
    secrets_store.rotate_instruction_key(store, "dev-1", 500)
    assert store["devices"]["dev-1"]["instr_key_prev"]["value"] == "05" * 32


def test_no_overlap_rotation_keeps_only_fresh_current(monkeypatch):
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record("08" * 32)
    store["devices"]["dev-1"]["instr_key_prev"] = _record(
        "09" * 32, expires_at=1000)
    monkeypatch.setattr(secrets_store.secrets, "token_hex", lambda n: "0a" * n)
    secrets_store.rotate_instruction_key(
        store, "dev-1", 500, no_overlap=True)
    assert store["devices"]["dev-1"]["instr_key"]["value"] == "0a" * 32
    assert "instr_key_prev" not in store["devices"]["dev-1"]


@pytest.mark.parametrize(
    "no_overlap,previous_expiry",
    [(False, 500), (True, 1000)],
    ids=["normal-expired-previous", "no-overlap-live-previous"],
)
def test_rotation_cli_refuses_duplicate_instruction_pair_before_side_effects(
        tmp_path, monkeypatch, no_overlap, previous_expiry):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    current = _record()
    previous = dict(current)
    previous["expires_at"] = previous_expiry
    store["devices"]["dev-1"].update({
        "instr_key": current,
        "instr_key_prev": previous,
    })
    secrets_store.save(store, str(path))
    before = path.read_bytes()
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    trace = []
    monkeypatch.setattr(
        module.secrets_store.secrets, "token_hex",
        lambda nbytes: trace.append("entropy") or "0b" * nbytes)
    monkeypatch.setattr(
        module.secretfs, "persist_store",
        lambda *args, **kwargs: trace.append("persist"))

    with pytest.raises(secrets_store.InstructionKeyError,
                       match="invalid instruction key relationship"):
        module.rotate_device(
            "dev-1", no_overlap=no_overlap,
            restamp=lambda *_: trace.append("callback"), now=lambda: 500)

    assert trace == []
    assert path.read_bytes() == before


@pytest.mark.parametrize("option", ["--no", "--undeclared"])
def test_cli_rejects_abbreviated_or_unknown_option_before_side_effects(
        tmp_path, monkeypatch, capsys, option):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    store["devices"]["dev-1"]["instr_key_prev"] = _record(
        "02" * 32, created_at=10, expires_at=1000)
    secrets_store.save(store, str(path))
    before = path.read_bytes()
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    trace = []
    monkeypatch.setattr(
        module.secrets_store.secrets, "token_hex",
        lambda nbytes: trace.append("entropy") or "0c" * nbytes)
    monkeypatch.setattr(
        module.secrets_store, "store_lock",
        lambda *_: trace.append("lock"))
    monkeypatch.setattr(
        module.secretfs, "persist_store",
        lambda *args, **kwargs: trace.append("persist"))

    assert module.main(
        ["rotate", option, "dev-1"],
        restamp=lambda *_: trace.append("callback"), now=lambda: 500) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert trace == []
    assert path.read_bytes() == before


def test_cli_exact_no_overlap_rotates_and_hands_off(tmp_path, monkeypatch,
                                                    capsys):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    store["devices"]["dev-1"]["instr_key_prev"] = _record(
        "02" * 32, created_at=10, expires_at=1000)
    secrets_store.save(store, str(path))
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    trace = []
    monkeypatch.setattr(
        module.secrets_store.secrets, "token_hex", lambda nbytes: "0d" * nbytes)

    def persist(candidate, plain_path, **kwargs):
        trace.append("persist")
        secrets_store.save(candidate, plain_path)

    monkeypatch.setattr(module.secretfs, "persist_store", persist)
    assert module.main(
        ["rotate", "--no-overlap", "dev-1"],
        restamp=lambda device_id, key_id: trace.append(
            ("callback", device_id, key_id)), now=lambda: 500) == 0

    result = json.loads(capsys.readouterr().out)
    final = secrets_store.load(str(path))["devices"]["dev-1"]
    assert result == {
        "device_id": "dev-1",
        "key_id": final["instr_key"]["key_id"],
        "state": "rotated",
    }
    assert final["instr_key"]["value"] == "0d" * 32
    assert "instr_key_prev" not in final
    assert trace == [
        "persist", ("callback", "dev-1", final["instr_key"]["key_id"])]


def test_rotation_cli_refuses_truthy_revoked_legacy_record(
        tmp_path, monkeypatch):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    store["devices"]["dev-1"]["rpc_secret"]["revoked"] = 1
    secrets_store.save(store, str(path))
    before = path.read_bytes()
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    trace = []
    monkeypatch.setattr(
        module.secrets_store.secrets, "token_hex",
        lambda nbytes: trace.append("entropy") or "0e" * nbytes)
    monkeypatch.setattr(
        module.secretfs, "persist_store",
        lambda *args, **kwargs: trace.append("persist"))

    with pytest.raises(secrets_store.InstructionKeyError,
                       match="device revoked"):
        module.rotate_device(
            "dev-1", restamp=lambda *_: trace.append("callback"),
            now=lambda: 500)

    assert trace == []
    assert path.read_bytes() == before


def test_instruction_record_requires_boolean_revoked():
    record = _record()
    record["revoked"] = 1
    with pytest.raises(secrets_store.InstructionKeyError,
                       match="invalid instruction key record"):
        secrets_store.validate_instruction_key_record(record)


@pytest.mark.parametrize("damage", ["current-revoked", "other-revoked",
                                     "malformed-current", "malformed-prev"])
def test_rotation_refuses_revoked_or_malformed_owned_state(damage):
    store = _store_with_device()
    dev = store["devices"]["dev-1"]
    dev["instr_key"] = _record()
    if damage == "current-revoked":
        dev["instr_key"]["revoked"] = True
    elif damage == "other-revoked":
        dev["rpc_secret"]["revoked"] = True
    elif damage == "malformed-current":
        dev["instr_key"]["key_id"] = "canary-secret-fragment"
    else:
        dev["instr_key_prev"] = {"value": "canary-secret-fragment"}
    before = copy.deepcopy(store)
    with pytest.raises(secrets_store.InstructionKeyError) as caught:
        secrets_store.rotate_instruction_key(store, "dev-1", 500)
    assert store == before
    assert "canary" not in str(caught.value)


def test_rotation_cli_preflights_missing_stamper_without_mutation(
        tmp_path, monkeypatch, capsys):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    secrets_store.save(store, str(path))
    before = path.read_bytes()
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    # Task 13 now exists. Preserve the sentinel's missing dependency fixture
    # through explicit import failure, so it still proves zero mutation.
    monkeypatch.setattr(
        module.importlib, "import_module",
        lambda _name: (_ for _ in ()).throw(ImportError("injected")))

    assert module.main(["rotate", "dev-1"]) == 1
    assert path.read_bytes() == before
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "iris-instr-key: instruction stamper unavailable\n"


def test_rotation_handoff_runs_after_persist_and_lock_release(
        tmp_path, monkeypatch):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    secrets_store.save(store, str(path))
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    trace = []

    def persist(candidate, plain_path, **kwargs):
        trace.append("persist")
        secrets_store.save(candidate, plain_path)

    def restamp(device_id, key_id):
        lock_fd = os.open(str(path) + ".lock", os.O_RDWR)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            trace.append((device_id, key_id))
        finally:
            os.close(lock_fd)

    monkeypatch.setattr(module.secretfs, "persist_store", persist)
    key_id = module.rotate_device(
        "dev-1", restamp=restamp, now=lambda: 500)
    assert trace == ["persist", ("dev-1", key_id)]
    module.handoff_restamp(restamp, "dev-1", key_id)
    assert trace[-1] == ("dev-1", key_id)


def test_rotation_failure_messages_never_disclose_key_material(
        tmp_path, monkeypatch):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    secrets_store.save(store, str(path))
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    canary = store["devices"]["dev-1"]["instr_key"]["value"]

    def fail_persist(*args, **kwargs):
        raise RuntimeError("tool exposed %s" % canary)

    monkeypatch.setattr(module.secretfs, "persist_store", fail_persist)
    with pytest.raises(module.InstructionKeyCLIError) as caught:
        module.rotate_device("dev-1", restamp=lambda *_: None, now=lambda: 500)
    assert canary not in str(caught.value)

    monkeypatch.setattr(
        module.secretfs, "persist_store",
        lambda candidate, plain_path, **kwargs:
            secrets_store.save(candidate, plain_path))
    with pytest.raises(module.RestampIncomplete) as caught:
        module.rotate_device(
            "dev-1", restamp=lambda *_: (_ for _ in ()).throw(
                RuntimeError("callback exposed %s" % canary)), now=lambda: 500)
    assert "rotation persisted; restamping is incomplete" in str(caught.value)
    assert canary not in str(caught.value)
    committed = secrets_store.load(str(path))["devices"]["dev-1"]
    assert committed["instr_key"]["key_id"] != store["devices"]["dev-1"][
        "instr_key"]["key_id"]
    assert committed["instr_key_prev"]["key_id"] == store["devices"][
        "dev-1"]["instr_key"]["key_id"]


def test_two_rotations_serialize_and_one_refuses_live_overlap(
        tmp_path, monkeypatch):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    secrets_store.save(store, str(path))
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    real_lock = secrets_store.store_lock
    reached = threading.Condition()
    waiting = {"count": 0}

    @contextlib.contextmanager
    def announced_lock(lock_path):
        with reached:
            waiting["count"] += 1
            reached.notify_all()
        with real_lock(lock_path):
            yield

    monkeypatch.setattr(module.secrets_store, "store_lock", announced_lock)
    outcomes = []

    def rotate():
        try:
            outcomes.append(("ok", module.rotate_device(
                "dev-1", restamp=lambda *_: None, now=lambda: 500)))
        except Exception as exc:
            outcomes.append(("error", str(exc)))

    with real_lock(str(path)):
        threads = [threading.Thread(target=rotate) for _ in range(2)]
        for thread in threads:
            thread.start()
        with reached:
            assert reached.wait_for(lambda: waiting["count"] == 2, timeout=3)
    for thread in threads:
        thread.join(timeout=3)
        assert not thread.is_alive()

    assert sorted(kind for kind, _ in outcomes) == ["error", "ok"]
    assert any("overlap is active" in detail
               for kind, detail in outcomes if kind == "error")
    final = secrets_store.load(str(path))["devices"]["dev-1"]
    assert set(("instr_key", "instr_key_prev")) <= set(final)


def test_revoke_winning_lock_prevents_stale_rotation(
        tmp_path, monkeypatch):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    secrets_store.save(store, str(path))
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    real_lock = secrets_store.store_lock
    reached = threading.Event()
    callback_called = []

    @contextlib.contextmanager
    def announced_lock(lock_path):
        reached.set()
        with real_lock(lock_path):
            yield

    monkeypatch.setattr(module.secrets_store, "store_lock", announced_lock)
    outcome = {}

    def rotate():
        try:
            module.rotate_device(
                "dev-1", restamp=lambda *_: callback_called.append(True),
                now=lambda: 500)
            outcome["ok"] = True
        except Exception as exc:
            outcome["error"] = str(exc)

    with real_lock(str(path)):
        thread = threading.Thread(target=rotate)
        thread.start()
        assert reached.wait(timeout=3)
        revoked = secrets_store.load(str(path))
        secrets_store.revoke(revoked, "dev-1")
        secrets_store.save(revoked, str(path))
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert "device revoked" in outcome["error"]
    assert callback_called == []
    final = secrets_store.load(str(path))["devices"]["dev-1"]
    assert all(record["revoked"] for record in final.values())


def test_cli_mode_dockerfile_and_device_transport_scope():
    assert CLI_PATH.is_file()
    mode = CLI_PATH.stat().st_mode
    assert mode & 0o111 == 0o111
    assert mode & 0o002 == 0
    dockerfile = (SERVER_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "/opt/iris/server/iris-instructions" in dockerfile
    assert "/opt/iris/server/iris-instr-key" in dockerfile

    device_paths = [
        REPO_ROOT / "device/bootstrap.sh",
        REPO_ROOT / "device/device-install.sh",
        REPO_ROOT / "device/router-install.sh",
        REPO_ROOT / "device/guestshell-start.sh",
        REPO_ROOT / "device/iox/install.sh",
        REPO_ROOT / "device/xr-install.sh",
        REPO_ROOT / "device/container/entrypoint.sh",
    ]
    for path in device_paths:
        source = path.read_text(encoding="utf-8")
        assert "IRIS_INSTR_KEY" not in source
        assert "instr_key" not in source


def test_task13_behavioral_red_default_callback_and_resume_are_real(
        tmp_path, monkeypatch, capsys):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    secrets_store.save(store, str(path))
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    calls = []

    def callback(device_id, key_id):
        calls.append((device_id, key_id))
        return "unchanged"

    fake_stamper = types.SimpleNamespace(restamp_instruction_key=callback)
    monkeypatch.setattr(
        module.importlib, "import_module",
        lambda name: fake_stamper if name == "instruction_stamper" else None)
    assert module.resolve_default_restamp() is callback

    assert module.main(["restamp", "dev-1"], restamp=callback) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {"device_id": "dev-1", "state": "unchanged"}
    assert calls == [("dev-1", _record()["key_id"])]


def test_task13_default_callback_resolves_the_real_stamper():
    module = _load_cli()
    callback = module.resolve_default_restamp()
    assert callback.__module__ == "instruction_stamper"
    assert callable(getattr(callback, "_iris_rotation_context"))


def test_task13_restamp_snapshots_key_under_lock_then_calls_after_release(
        tmp_path, monkeypatch):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    secrets_store.save(store, str(path))
    before = path.read_bytes()
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    calls = []

    def callback(device_id, key_id):
        fd = os.open(str(path) + ".lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            calls.append((device_id, key_id))
        finally:
            os.close(fd)
        return "updated"

    assert module.restamp_device("dev-1", restamp=callback) == "updated"
    assert calls == [("dev-1", _record()["key_id"])]
    assert path.read_bytes() == before


def test_task13_initialize_and_recover_commands_use_exact_parser(capsys):
    module = _load_cli()
    calls = []

    def producer(mode, now=None):
        calls.append((mode, now))
        return {"epoch": 123}

    assert module.main(["initialize"], producer=producer, now=lambda: 9) == 0
    assert json.loads(capsys.readouterr().out) == {
        "epoch": 123, "state": "initialize"}
    assert module.main(["recover"], producer=producer, now=lambda: 10) == 0
    assert json.loads(capsys.readouterr().out) == {
        "epoch": 123, "state": "recover"}
    assert [item[0] for item in calls] == ["initialize", "recover"]
    assert module.main(["rec"]) == 2
    capsys.readouterr()

    assert module.main(
        ["recover"], producer=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("private-path-canary"))) == 1
    assert capsys.readouterr().err == \
        "iris-instr-key: instruction operation failed\n"


def test_task13_default_rotation_context_spans_persist_and_handoff(
        tmp_path, monkeypatch):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    secrets_store.save(store, str(path))
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    trace = []

    @contextlib.contextmanager
    def producer_context(device_id):
        trace.append(("enter", device_id))
        yield
        trace.append(("exit", device_id))

    def callback(device_id, key_id):
        trace.append(("callback", device_id, key_id))
        return "updated"

    callback._iris_rotation_context = producer_context
    monkeypatch.setattr(module, "resolve_default_restamp", lambda: callback)
    monkeypatch.setattr(
        module.secrets_store.secrets, "token_hex", lambda count: "0f" * count)

    def persist(candidate, plain_path, **_kwargs):
        trace.append(("persist", candidate["devices"]["dev-1"][
            "instr_key"]["key_id"]))
        secrets_store.save(candidate, plain_path)

    monkeypatch.setattr(module.secretfs, "persist_store", persist)
    key_id = module.rotate_device("dev-1", now=lambda: 500)
    assert trace == [
        ("enter", "dev-1"), ("persist", key_id),
        ("callback", "dev-1", key_id), ("exit", "dev-1")]


def test_task13_failed_no_overlap_handoff_resumes_without_another_key(
        tmp_path, monkeypatch):
    module = _load_cli()
    path = tmp_path / "secrets.json"
    store = _store_with_device()
    store["devices"]["dev-1"]["instr_key"] = _record()
    store["devices"]["dev-1"]["instr_key_prev"] = _record(
        "02" * 32, created_at=10, expires_at=1000)
    secrets_store.save(store, str(path))
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setattr(
        module.secrets_store.secrets, "token_hex", lambda count: "03" * count)
    monkeypatch.setattr(
        module.secretfs, "persist_store",
        lambda candidate, plain_path, **_kwargs:
        secrets_store.save(candidate, plain_path))
    with pytest.raises(module.RestampIncomplete):
        module.rotate_device(
            "dev-1", no_overlap=True,
            restamp=lambda *_args: (_ for _ in ()).throw(OSError("offline")),
            now=lambda: 500)
    committed = path.read_bytes()
    current = secrets_store.load(str(path))["devices"]["dev-1"]["instr_key"]
    seen = []
    assert module.restamp_device(
        "dev-1", restamp=lambda device_id, key_id:
        seen.append((device_id, key_id)) or "unchanged") == "unchanged"
    assert seen == [("dev-1", current["key_id"])]
    assert path.read_bytes() == committed
