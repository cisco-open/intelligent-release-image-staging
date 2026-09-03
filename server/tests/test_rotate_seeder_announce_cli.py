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


def test_discover_targets_refuses_stale_recorded_source_without_fallback(
        tmp_path):
    state, hashes = _state(tmp_path, ("a",))
    catalog_path = state / "catalog.json"
    catalog = json.loads(catalog_path.read_text())
    catalog["images"]["a"]["source_dir"] = str(tmp_path / "gone")
    catalog_path.write_text(json.dumps(catalog))
    fallback = tmp_path / "fallback"
    fallback.mkdir()
    (fallback / "a.bin").write_bytes(b"wrong same-name bytes")
    called = []

    with pytest.raises(ValueError, match="image directory unavailable"):
        rot.discover_targets(
            str(state), {"IMAGES_ROOT": str(fallback)},
            lambda method, params: called.append((method, params)) or [
                {"gid": "g-a", "infoHash": hashes["a"]}])

    assert called == [], "stale authoritative source must fail before RPC"


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


def test_announce_base_still_refuses_loopback_and_linklocal():
    """Loopback/link-local are not fleet address space; the tracker refuses them
    too, and an announce base pointing there would be advertised to peers."""
    for host in ("127.0.0.1", "169.254.1.1"):
        with pytest.raises(ValueError):
            rot._tracker_announce_base({"IRIS_HOST_IP": host})


def test_swarm_proof_window_outlasts_one_announce_interval():
    """The proof needs every expected info_hash to re-announce after the
    post-add boundary. Clients re-announce on peer_registry.INTERVAL, and only
    the last-added torrent announces inside a short window -- the earlier ones
    announced during their own add, before the boundary. A window shorter than
    one announce interval therefore fails deterministically, which is exactly
    what happened in the lab: exit 1 "not proven" with every torrent applied.
    """
    import peer_registry
    window_s = rot._SWARM_RETRIES * 1.0        # sleep is min(timeout, 1.0)
    assert window_s > peer_registry.INTERVAL, (
        "probe window %.0fs must outlast the %ss announce interval"
        % (window_s, peer_registry.INTERVAL))


def test_announce_base_accepts_any_routable_ipv4():
    """Fleets are not always on RFC1918/RFC6598. The old check used
    ipaddress.is_private, which refused 100.64.0.0/10 (the lab) and every public
    address, so those deployments could never rotate a seeder credential."""
    for host in ("100.90.168.20", "10.1.2.3", "192.168.5.4", "203.0.113.9",
                 "8.8.8.8"):
        assert rot._tracker_announce_base({"IRIS_HOST_IP": host}) == \
            "http://%s:6969/announce" % host


def test_announce_base_refuses_addresses_no_peer_could_dial():
    """This base is handed to every peer as the tracker to dial, so an address
    that cannot serve that role is still refused."""
    for host in ("127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1"):
        with pytest.raises(ValueError):
            rot._tracker_announce_base({"IRIS_HOST_IP": host})


# ---------------------------------------------------------------------------
# Quarantine and rotation are both security controls and must not be
# mutually exclusive: a quarantined image is deliberately not active in the
# seeder, so it is skipped rather than refusing the whole rotation.
# ---------------------------------------------------------------------------

def _quarantine(state, name):
    catalog_path = state / "catalog.json"
    catalog = json.loads(catalog_path.read_text())
    catalog["images"][name]["quarantined"] = True
    catalog["images"][name]["quarantine_actions_complete"] = True
    catalog_path.write_text(json.dumps(catalog))


def test_discover_targets_skips_quarantined_images(tmp_path):
    state, hashes = _state(tmp_path, ("a", "q"))
    _quarantine(state, "q")
    skipped = []
    # aria2 holds only the non-quarantined torrent, as a quarantine leaves it
    targets = rot.discover_targets(
        str(state), {}, lambda method, params: [{"gid": "g-a", "infoHash": hashes["a"]}],
        skipped=skipped)
    assert [t.image_id for t in targets] == ["a"]
    assert skipped == ["q"]


def test_discover_targets_refuses_when_every_image_is_quarantined(tmp_path):
    state, _ = _state(tmp_path, ("q",))
    _quarantine(state, "q")
    with pytest.raises(ValueError, match="every published image is quarantined"):
        rot.discover_targets(str(state), {}, lambda *args: pytest.fail("RPC called"))


def test_cli_rotates_past_a_quarantined_image_and_says_so(tmp_path, monkeypatch, capsys):
    state, hashes = _state(tmp_path, ("a", "q"))
    _quarantine(state, "q")
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1recipient")
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "s.age"))
    monkeypatch.setenv("IRIS_RPC_SECRET", "secret-value")
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.1")
    monkeypatch.setattr(rot.telemetry, "make_jsonrpc_caller", lambda *a: lambda m, p: [
        {"gid": "g-a", "infoHash": hashes["a"]}])
    monkeypatch.setattr(rot, "production_deps", lambda *a: object())
    seen = {}

    def core(secrets_path, manifest, targets, base, deps):
        seen["targets"] = [t.image_id for t in targets]
        return type("Result", (), {"served_claimed": True, "hard_no_go": False})()
    monkeypatch.setattr(rot, "rotate_seeder_announce", core)
    assert rot.main(["--maintenance-frozen", "--state", str(state)]) == 0
    assert seen["targets"] == ["a"]
    output = capsys.readouterr().err
    assert "skipping 1 quarantined image(s)" in output and "q" in output
    assert "secret-value" not in output and "http://" not in output


# ---------------------------------------------------------------------------
# A refusal must name its (nonsecret, fixed-literal) reason: nine different
# preflight conditions all raise ValueError, and "refused (ValueError)" left
# the operator diagnosing a maintenance-window operation blind.
# ---------------------------------------------------------------------------

def test_cli_refusal_prints_the_preflight_reason_without_secrets(tmp_path, monkeypatch, capsys):
    state, hashes = _state(tmp_path, ("a",))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1recipient")
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "s.age"))
    monkeypatch.setenv("IRIS_RPC_SECRET", "secret-value")
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.1")
    # the seeder holds nothing: the image is not uniquely active
    monkeypatch.setattr(rot.telemetry, "make_jsonrpc_caller", lambda *a: lambda m, p: [])
    monkeypatch.setattr(rot, "rotate_seeder_announce",
                        lambda *a: pytest.fail("core called"))
    assert rot.main(["--maintenance-frozen", "--state", str(state)]) == 2
    err = capsys.readouterr().err
    assert "refused (ValueError: canonical torrent is not uniquely active)" in err
    assert "secret-value" not in err and "http://" not in err
    assert "token" not in err.lower()


def test_refusal_reason_falls_back_to_class_name_for_unsafe_text():
    assert rot._refusal_reason(ValueError("catalog unavailable")) == \
        "ValueError: catalog unavailable"
    assert rot._refusal_reason(rot.RotationError("would evict")) == \
        "RotationError: would evict"
    assert rot._refusal_reason(ValueError("http://h/announce?announce_token=x")) == "ValueError"
    assert rot._refusal_reason(ValueError("bad token value")) == "ValueError"
    assert rot._refusal_reason(RuntimeError("aria2 RPC error: anything")) == "RuntimeError"
    assert rot._refusal_reason(ValueError("")) == "ValueError"
