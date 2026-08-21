# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Operational preflight and nonsecret CLI coverage for seeder rotation."""
import json

import pytest

import bencode
import rotate_seeder_announce as rot


def _torrent(name=b"image.bin"):
    info = bencode.encode({"name": name, "piece length": 16384,
                           "pieces": b"\0" * 20, "length": 1})
    return b"d8:announce17:http://x/announce4:info" + info + b"e"


def _state(tmp_path, names=("a",)):
    state = tmp_path / "state"
    torrents = state / "torrents"
    images = tmp_path / "images"
    torrents.mkdir(parents=True)
    images.mkdir()
    catalog = {"images": {}}
    hashes = {}
    for name in names:
        filename = name + ".bin"
        data = _torrent(filename.encode())
        path = torrents / (name + ".torrent")
        path.write_bytes(data)
        (images / filename).write_bytes(b"x")
        catalog["images"][name] = {"filename": filename,
                                   "source_dir": str(images)}
        hashes[name] = rot._info_hash(data)
    (state / "catalog.json").write_text(json.dumps(catalog))
    return state, hashes


def test_discover_targets_uses_authoritative_source_dirs_in_order(tmp_path):
    state, hashes = _state(tmp_path, ("z", "a"))
    targets = rot.discover_targets(
        str(state), {}, lambda method, params: [
            {"gid": "g-" + name, "infoHash": h}
            for name, h in hashes.items()])
    assert [target.image_id for target in targets] == ["a", "z"]
    assert all(target.image_dir == str(tmp_path / "images") for target in targets)


def test_discover_targets_refuses_catalog_with_missing_canonical_before_rpc(tmp_path):
    state, _ = _state(tmp_path, ("a", "b"))
    (state / "torrents" / "b.torrent").unlink()

    with pytest.raises(ValueError, match="canonical torrent unavailable"):
        rot.discover_targets(str(state), {}, lambda *args: pytest.fail("RPC called"))


def test_discover_targets_refuses_empty_catalog_before_rpc(tmp_path):
    state, _ = _state(tmp_path, ())

    with pytest.raises(ValueError, match="no published torrent targets"):
        rot.discover_targets(str(state), {}, lambda *args: pytest.fail("RPC called"))


def test_cli_missing_catalog_target_does_not_mutate(tmp_path, monkeypatch):
    state, _ = _state(tmp_path, ("a", "b"))
    (state / "torrents" / "b.torrent").unlink()
    called = []
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1recipient")
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "s.age"))
    monkeypatch.setenv("IRIS_RPC_SECRET", "x")
    monkeypatch.setattr(rot.telemetry, "make_jsonrpc_caller",
                        lambda *args: lambda *rpc_args: called.append(rpc_args))
    monkeypatch.setattr(rot, "rotate_seeder_announce",
                        lambda *args: pytest.fail("core called"))

    assert rot.main(["--maintenance-frozen", "--state", str(state)]) == 2
    assert called == []
    assert not (state / "seeder-rotation-recovery.json").exists()


def test_cli_preflight_failures_do_not_call_core(tmp_path, monkeypatch, capsys):
    state, _ = _state(tmp_path)
    called = []
    monkeypatch.setattr(rot, "rotate_seeder_announce", lambda *a: called.append(a))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1recipient")
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "s.age"))
    monkeypatch.delenv("IRIS_RPC_SECRET", raising=False)
    monkeypatch.setenv("IRIS_RPC_SECRET_FILE", str(tmp_path / "missing"))
    assert rot.main(["--maintenance-frozen", "--state", str(state)]) == 2
    assert called == []
    assert not (state / "seeder-rotation-recovery.json").exists()
    assert "token" not in (capsys.readouterr().out + capsys.readouterr().err).lower()


def test_cli_existing_manifest_refuses_before_rpc_or_core(tmp_path, monkeypatch):
    state, _ = _state(tmp_path)
    (state / "seeder-rotation-recovery.json").write_text("evidence")
    monkeypatch.setattr(rot.telemetry, "make_jsonrpc_caller",
                        lambda *a: (_ for _ in ()).throw(AssertionError()))
    assert rot.main(["--maintenance-frozen", "--state", str(state)]) == 2


def test_cli_uses_production_deps_and_never_outputs_request_values(
        tmp_path, monkeypatch, capsys):
    state, hashes = _state(tmp_path)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1recipient")
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "s.age"))
    monkeypatch.setenv("IRIS_RPC_SECRET", "secret-value")
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.1")
    seen = {}

    def rpc(method, params):
        if method == "aria2.tellActive":
            return [{"gid": "g", "infoHash": next(iter(hashes.values()))}]
        return None
    monkeypatch.setattr(rot.telemetry, "make_jsonrpc_caller", lambda *a: rpc)
    monkeypatch.setattr(rot, "production_deps", lambda *a: seen.setdefault("deps", a) or object())
    monkeypatch.setattr(rot, "rotate_seeder_announce", lambda *a: type(
        "Result", (), {"served_claimed": True, "hard_no_go": False})())
    assert rot.main(["--maintenance-frozen", "--state", str(state)]) == 0
    output = capsys.readouterr().out + capsys.readouterr().err
    assert "secret-value" not in output and "http://" not in output
    assert seen["deps"][2:4] == ("age1recipient", str(tmp_path / "s.age"))


def test_cli_hard_no_go_keeps_manifest_and_returns_one(tmp_path, monkeypatch):
    state, hashes = _state(tmp_path)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1recipient")
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "s.age"))
    monkeypatch.setenv("IRIS_RPC_SECRET", "x")
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.1")
    monkeypatch.setattr(rot.telemetry, "make_jsonrpc_caller", lambda *a: lambda m, p: [
        {"gid": "g", "infoHash": next(iter(hashes.values()))}])
    monkeypatch.setattr(rot, "production_deps", lambda *a: object())
    def failed(*args):
        open(args[1], "w").write("evidence")
        return type("Result", (), {"served_claimed": False, "hard_no_go": True})()
    monkeypatch.setattr(rot, "rotate_seeder_announce", failed)
    assert rot.main(["--maintenance-frozen", "--state", str(state)]) == 1
    assert (state / "seeder-rotation-recovery.json").exists()
