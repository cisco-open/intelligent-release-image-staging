# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Last-known-good instruction custody and contained runtime integration."""

import base64
import copy
import hashlib
import importlib
import json
import os
import time

import pytest

import agent_config
import iris_agent


DEVICE_ID = "device-1"
OTHER_DEVICE_ID = "device-2"
NOW = 2_000_000_000
INSTR_KEY = bytes(range(32))
INSTR_KEY_ID = hashlib.sha256(INSTR_KEY).hexdigest()
SECOND_KEY = bytes(range(32, 64))
THIRD_KEY = bytes(reversed(range(32)))
LKG_KEY = b"l" * 32
ARMOR = (b"-----BEGIN SSH SIGNATURE-----\n"
         b"U1NIU0lHAAAAAQAAABVzc2gtZWQyNTUxOQAAAAE=\n"
         b"-----END SSH SIGNATURE-----\n")


def _instr():
    # Task 15 creates this module.  Keep the import in test execution so the
    # tests-only commit still collects cleanly on the pre-implementation tree.
    return importlib.import_module("instr")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
        "ascii")


def _qos():
    return {
        "max_peers": 10,
        "seed_up_bps": 0,
        "seed_down_bps": 0,
        "leech_up_bps": 0,
        "leech_down_bps": 0,
        "overall_up_bps": 0,
        "overall_down_bps": 0,
        "max_concurrent": 2,
        "request_peer_speed_limit_bps": 0,
    }


def _control():
    return {"catalog_tick_s": 60, "telemetry_every_ticks": 1,
            "telemetry_pause": False}


def _server_instructions():
    return importlib.import_module("server.instructions")


def _verified(serial=7, device_id=DEVICE_ID, on_stale="keep",
              expires_at=NOW + 600):
    role_gen = hashlib.sha256(b"role-generation").hexdigest()
    role = {
        "v": 1,
        "role": "default",
        "restricted": False,
        "role_gen": role_gen,
        "issued_at": NOW,
        "expires_at": expires_at,
        "server_time": NOW,
        "qos": _qos(),
        "control": _control(),
        "on_stale": on_stale,
    }
    role_body = _canonical(role)
    part = {
        "peers": {"mode": "tracker-only", "include_origin": False,
                  "allowed_expires_at": expires_at},
        "qos_override": {"max_peers": serial},
        "control_override": {},
        "server_time": NOW,
    }
    header = {
        "v": 1,
        "device_id": device_id,
        "platform": "guestshell",
        "epoch": NOW,
        "instr_serial": serial,
        "policy_revision": 3,
        "issued_at": NOW,
        "expires_at": expires_at,
        "server_time": NOW,
        "verify_level": "sig",
        "key_id": INSTR_KEY_ID,
        "role": "default",
        "role_gen": role_gen,
        "role_body_sha256": hashlib.sha256(role_body).hexdigest(),
        "ct_len": len(_canonical(part)),
        "allowed_expires_at": expires_at,
        "degraded": False,
    }
    header_bytes = _canonical(header)
    envelope = _server_instructions().seal_parts(
        header, part, role_body, ARMOR, INSTR_KEY)
    return {
        "envelope": envelope,
        "header_bytes": header_bytes,
        "header": header,
        "role_body": role_body,
        "role": role,
        "signature": ARMOR,
        "device": part,
    }


class _Verifier:
    def __init__(self, accepted=True):
        self.accepted = accepted
        self.calls = []

    def verify(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.accepted


def _store(tmp_path, cfg=None, verifier=None):
    module = _instr()
    cfg = {} if cfg is None else cfg
    writes = []

    def persist_config(value):
        writes.append(copy.deepcopy(value))

    store = module.LKGStore(str(tmp_path), cfg, persist_config,
                            verifier or _Verifier())
    return module, store, cfg, writes


def test_lkg_key_is_minted_persisted_once_and_never_rotated_or_sent(
        tmp_path, monkeypatch):
    module, store, cfg, writes = _store(tmp_path)
    monkeypatch.setattr(module.secrets, "token_bytes", lambda size: b"m" * size)

    store.store(_verified(), _verified()["device"], {})
    minted = cfg["lkg_key"]
    assert minted == (b"m" * 32).hex()
    assert writes == [cfg]

    # Neither a normal LKG replacement nor two server instruction-key
    # rotations may rotate the device-local key.
    for serial, key in ((8, SECOND_KEY), (9, THIRD_KEY)):
        cfg["instr_key"] = _canonical({
            "key_id": hashlib.sha256(key).hexdigest(),
            "value": key.hex(),
        }).decode("ascii")
        candidate = _verified(serial=serial)
        store.store(candidate, candidate["device"], {})
        assert cfg["lkg_key"] == minted
    assert len(writes) == 1

    class RefreshCatalog:
        def __init__(self):
            self.token = "old-token"
            self.calls = []

        def refresh_token(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return {"catalog_token": "new-token", "expires_at": NOW + 1000}

    catalog = RefreshCatalog()
    monkeypatch.setattr(agent_config, "write_conf", lambda _path, _cfg: None)
    refreshed = iris_agent._refresh_impl(
        dict(cfg, device_id=DEVICE_ID, catalog_token="old-token"),
        str(tmp_path / "iris-agent.conf"), catalog, lambda *_args: None)
    assert catalog.calls == [((DEVICE_ID,), {})]
    assert refreshed["lkg_key"] == minted
    assert minted not in repr(catalog.calls)


def test_lkg_key_uses_os_urandom_fallback_when_secrets_api_is_unavailable(
        tmp_path, monkeypatch):
    module, store, cfg, writes = _store(tmp_path)
    monkeypatch.setattr(module.secrets, "token_bytes", None)
    seen = []

    def urandom(size):
        seen.append(size)
        return b"u" * size

    monkeypatch.setattr(module.os, "urandom", urandom)
    candidate = _verified()
    store.store(candidate, candidate["device"], {})
    assert seen == [32]
    assert cfg["lkg_key"] == (b"u" * 32).hex()
    assert writes == [cfg]


def test_lkg_preserves_public_components_and_locally_reseals_only_device_part(
        tmp_path):
    verifier = _Verifier()
    cfg = {"lkg_key": LKG_KEY.hex()}
    module, store, _cfg, writes = _store(tmp_path, cfg, verifier)
    assert module.LKG_LABEL == b"iris-lkg-v1"
    first = _verified()

    store.store(first, first["device"], {})
    lkg_path = tmp_path / "iris-instructions.lkg"
    persisted = lkg_path.read_bytes()
    server_ciphertext = _server_instructions().parse_envelope(
        first["envelope"])[4]
    assert server_ciphertext not in persisted
    assert INSTR_KEY.hex().encode("ascii") not in persisted
    assert writes == []

    loaded = store.load(DEVICE_ID, "guestshell", NOW + 1, 10.0,
                        "boot-a", {})
    assert loaded["header_bytes"] == first["header_bytes"]
    assert loaded["header"] == first["header"]
    assert loaded["role_body"] == first["role_body"]
    assert loaded["role"] == first["role"]
    assert loaded["signature"] == ARMOR
    assert loaded["device"] == first["device"]
    assert loaded["instr_state"] == "lkg"
    assert verifier.calls

    # The last-known-good copy is sealed by lkg_key, so it remains readable
    # after two unrelated instruction-key rotations.
    for key in (SECOND_KEY, THIRD_KEY):
        cfg["instr_key"] = _canonical({
            "key_id": hashlib.sha256(key).hexdigest(),
            "value": key.hex(),
        }).decode("ascii")
        again = store.load(DEVICE_ID, "guestshell", NOW + 2, 11.0,
                           "boot-a", {})
        assert again["device"] == first["device"]
        assert again["role_body"] == first["role_body"]


def test_lkg_audience_precedes_local_mac_and_unreadable_or_rejected_is_explicit(
        tmp_path):
    cfg = {"lkg_key": LKG_KEY.hex()}
    verifier = _Verifier()
    module, store, _cfg, _writes = _store(tmp_path, cfg, verifier)
    foreign = _verified(device_id=OTHER_DEVICE_ID)
    store.store(foreign, foreign["device"], {})

    # Remove the key needed to authenticate/decrypt the device part.  A
    # foreign audience must still be identified first.
    cfg.pop("lkg_key")
    with pytest.raises(module.InstructionError) as caught:
        store.load(DEVICE_ID, "guestshell", NOW + 1, 10.0, "boot-a", {})
    assert caught.value.state == "audience_mismatch"
    assert verifier.calls == []

    with pytest.raises(module.InstructionError) as caught:
        store.load(OTHER_DEVICE_ID, "guestshell", NOW + 1, 10.0, "boot-a", {})
    assert caught.value.state == "lkg_unreadable"

    cfg["lkg_key"] = LKG_KEY.hex()
    rejecting = _Verifier(accepted=False)
    rejected_store = module.LKGStore(
        str(tmp_path), cfg, lambda _value: None, rejecting)
    with pytest.raises(module.InstructionError) as caught:
        rejected_store.load(OTHER_DEVICE_ID, "guestshell", NOW + 1, 10.0,
                            "boot-a", {})
    assert caught.value.state == "lkg_rejected"
    assert len(rejecting.calls) == 1


@pytest.mark.parametrize(("on_stale", "keeps_values"), [
    ("keep", True),
    ("defaults", False),
])
def test_expired_lkg_applies_its_signed_stale_posture_without_grace(
        tmp_path, on_stale, keeps_values):
    cfg = {"lkg_key": LKG_KEY.hex()}
    _module, store, _cfg, _writes = _store(tmp_path, cfg)
    candidate = _verified(on_stale=on_stale, expires_at=NOW + 5)
    store.store(candidate, candidate["device"], {})

    # Equality is stale.  There is no extra expiry grace interval.
    loaded = store.load(DEVICE_ID, "guestshell", NOW + 5, 15.0,
                        "boot-a", {})
    assert loaded["instr_state"] == "stale_expired"
    assert loaded["on_stale"] == on_stale
    if keeps_values:
        assert loaded["device"] == candidate["device"]
        assert loaded["role"]["qos"] == candidate["role"]["qos"]
    else:
        assert loaded["device"] is None
        assert loaded["role"] is None


def test_platform_paths_are_exact_and_instruction_state_is_never_an_image(
        tmp_path):
    module = _instr()
    cases = [
        ("guestshell", {"stage_dir": "/flash/guest-share/iris"},
         "/flash/guest-share/iris", "/flash/guest-share/iris"),
        ("router", {"stage_dir": "/bootflash/guest-share/iris",
                    "target_fs": "bootflash:"},
         "/bootflash/guest-share/iris", "/bootflash/guest-share/iris"),
        ("iox", {"stage_dir": "/data/iris"},
         "/data/iris", "/opt/iris/agent"),
        ("xr-appmgr", {"stage_dir": "/hostmount"},
         "/hostmount/iris-work", "/opt/iris/agent"),
    ]
    for platform, cfg, work_dir, trust_dir in cases:
        paths = module.paths_for(platform, cfg)
        assert paths == {
            "work_dir": work_dir,
            "lkg": os.path.join(work_dir, "iris-instructions.lkg"),
            "bootstrap": os.path.join(
                work_dir, "iris-instructions.bootstrap"),
            "keylist": os.path.join(
                work_dir, "iris-instruction-keylist.current"),
            "keylist_state": os.path.join(
                work_dir, "iris-instruction-keylist-state.json"),
            "signers": os.path.join(
                trust_dir, "iris-signers.allowed_signers"),
            "root_signers": os.path.join(
                trust_dir, "iris-root.allowed_signers"),
        }
        for name in (paths["lkg"], paths["bootstrap"], paths["keylist"],
                     paths["keylist_state"]):
            assert not os.path.basename(name).endswith(
                (".bin", ".torrent", ".aria2", ".peers.json"))
    assert "instructions" in iris_agent._RESERVED_STATE_KEYS

    # Reconciliation must ignore the additive instruction state bag and never
    # offer any instruction/keylist/LKG basename to the image purge callback.
    purged = []
    deps = _runtime_deps(
        _RuntimeCatalog({"approved_image_id": None}),
        instruction_step=lambda **_kwargs: {"instr_state": "none"})
    deps = deps._replace(purge_others=lambda keep, ids: purged.append((keep, ids)))
    state = {"instructions": {"lkg_digest": "a" * 64}}
    iris_agent._reconcile_set(deps, state, [], str(tmp_path))
    assert state == {"instructions": {"lkg_digest": "a" * 64}}
    assert purged == []


class _RuntimeCatalog:
    def __init__(self, policy, image=None, authenticated_date=NOW,
                 events=None):
        self.policy = policy
        self.image = image
        self.last_authenticated_date = authenticated_date
        self.events = [] if events is None else events
        self.heartbeats = []

    def get_policy(self, device_id):
        self.events.append("policy")
        return self.policy

    def get_image(self, _image_id):
        return self.image

    def heartbeat(self, device_id, payload):
        self.events.append("heartbeat")
        self.heartbeats.append(copy.deepcopy(payload))
        return None

    def post_telemetry(self, _device_id, _payload):
        return None


def _runtime_deps(catalog, instruction_step):
    values = {
        "catalog": catalog,
        "emit": lambda *_args: None,
        "boot_image": lambda: "running.bin",
        "aria_add": lambda *_args: None,
        "file_size": lambda _path: None,
        "verify": lambda *_args: True,
        "free_bytes": lambda _prefix="flash:": 10 ** 9,
        "version": lambda: "17.18.03",
        "copy_to_root": lambda *_args, **_kwargs: True,
        "purge_others": lambda *_args: None,
        "reclaim": lambda: None,
        "root_present": lambda *_args, **_kwargs: True,
        "remove_stage": lambda _path: None,
        "aria_remove": lambda _name: None,
        "detect_mode": lambda: "bundle",
        "target_fs": lambda: ("flash:", 10 ** 9),
        "running_image": lambda: "running.bin",
        "reclaimable": lambda *_args: [],
        "reclaim_bundle": lambda *_args: None,
        "model": lambda: "C9300-TEST",
        "refresh": lambda: None,
        "aria_stats": lambda _path: None,
        "aria_peers": lambda _path: [],
        "io_transfer": False,
        "checkpoint": lambda _state: None,
        "aria_session": lambda: None,
        "copy_in_place": False,
        "root_file_size": lambda *_args: None,
        "verify_root": lambda *_args: True,
        "instruction_step": instruction_step,
    }
    return iris_agent.Deps(**values)


def _runtime_cfg(tmp_path=None):
    stage_dir = str(tmp_path) if tmp_path is not None else "/stage"
    return {"device_id": DEVICE_ID, "stage_dir": stage_dir,
            "token_expires_at": str(NOW + 604800)}


def test_run_once_orders_contained_instruction_step_after_policy_before_reconcile(
        monkeypatch, tmp_path):
    events = []
    policy = {"approved_image_id": None,
              "instr_rev": {"epoch": NOW, "instr_serial": 7}}
    catalog = _RuntimeCatalog(policy, authenticated_date=NOW, events=events)

    def step(**kwargs):
        events.append("instructions")
        assert kwargs["hints"] is policy
        assert kwargs["catalog_date"] == NOW
        return {
            "instruction": {"private": "instruction-must-not-leak"},
            "effective": {"private": "effective-must-not-leak"},
            "attestation": {
                "instr_state": "applied",
                "instr_serial": 7,
                "verify_level": "sig",
                "arbitrary": "attestation-must-not-leak",
            },
        }

    deps = _runtime_deps(catalog, step)
    original = iris_agent._reconcile_set

    def reconcile(*args, **kwargs):
        events.append("reconcile")
        return original(*args, **kwargs)

    monkeypatch.setattr(iris_agent, "_reconcile_set", reconcile)
    assert iris_agent.run_once(_runtime_cfg(tmp_path), deps, {}) == "no-assignment"
    assert events == ["policy", "instructions", "reconcile", "heartbeat"]
    heartbeat = catalog.heartbeats[-1]
    assert {name for name in heartbeat
            if name.startswith("instr") or name == "verify_level"} == {
                "instr_state", "instr_serial", "verify_level"}
    assert heartbeat["instr_state"] == "applied"
    assert heartbeat["instr_serial"] == 7
    assert heartbeat["verify_level"] == "sig"
    assert "instruction" not in heartbeat
    assert "effective" not in heartbeat
    assert "arbitrary" not in heartbeat
    assert "must-not-leak" not in repr(heartbeat)


def test_instruction_failure_never_sleeps_or_blocks_staging_and_heartbeat(
        monkeypatch, tmp_path):
    events = []
    image = {"id": "image-1", "filename": "image.bin", "size": 1,
             "sha256": "a" * 64, "torrent_sha256": "b" * 64,
             "target_fs": "flash:"}
    catalog = _RuntimeCatalog({"approved_image_id": "image-1"}, image)

    def failing_step(**_kwargs):
        events.append("instructions")
        raise RuntimeError("contained instruction failure")

    def no_sleep(_seconds):
        raise AssertionError("instruction processing slept while tick lock held")

    deps = _runtime_deps(catalog, failing_step)
    monkeypatch.setattr(time, "sleep", no_sleep)
    monkeypatch.setattr(iris_agent, "_reconcile_set",
                        lambda *_args: events.append("reconcile"))
    monkeypatch.setattr(
        iris_agent, "_stage_image",
        lambda *_args, **_kwargs: events.append("stage") or "ready")
    monkeypatch.setattr(
        iris_agent, "_send_set_heartbeat",
        lambda *_args: events.append("heartbeat") or None)

    assert iris_agent.run_once(_runtime_cfg(tmp_path), deps, {}) == "ready"
    assert events == ["instructions", "reconcile", "stage", "heartbeat"]


def test_missing_guestshell_verifier_is_tracker_only_with_verifier_missing_fact(
        tmp_path):
    module = _instr()
    calls = []
    envelope = _verified()["envelope"]

    class MissingVerifier(_Verifier):
        def verify(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            raise module.InstructionError(
                state="verifier_missing", reason="synthetic missing verifier")

    class Catalog:
        def get_instruction_keylist(self, *args, **kwargs):
            calls.append(("keylist", args, kwargs))
            return 404, b"", {"Date": "Wed, 18 May 2033 03:33:20 GMT"}

        def get_instructions(self, *args, **kwargs):
            calls.append(("instructions", args, kwargs))
            return 200, envelope, {
                "Date": "Wed, 18 May 2033 03:33:20 GMT"}

    cfg = {"device_id": DEVICE_ID, "stage_dir": str(tmp_path),
           "instr_key": _canonical({"key_id": INSTR_KEY_ID,
                                     "value": INSTR_KEY.hex()}).decode("ascii")}
    verifier = MissingVerifier()
    result = module.run_instruction_step(
        cfg=cfg, state={}, catalog=Catalog(), platform="guestshell",
        work_dir=str(tmp_path), boot_id="boot-a", monotonic_now=10.0,
        verifier=verifier,
        persist_config=lambda _cfg: None, emit=lambda *_args: None,
        hints={"instr_rev": {"epoch": NOW, "instr_serial": 7}},
        catalog_date=NOW)
    assert result["instruction"] is None
    assert result["effective"]["peers"]["mode"] == "tracker-only"
    assert result["attestation"]["instr_state"] == "verifier_missing"
    assert result["attestation"]["verify_level"] == "sig"
    assert calls and calls[-1][0] == "instructions"
    assert len(verifier.calls) == 1


def test_old_server_and_keyless_old_config_keep_existing_tick_behavior(
        tmp_path):
    module = _instr()

    class OldCatalog:
        def __getattr__(self, name):
            if name in ("get_instructions", "get_instruction_keylist"):
                raise AssertionError("old server without hints was queried")
            raise AttributeError(name)

    cfg = {"catalog_url": "https://192.0.2.1:8443",
           "catalog_token": "token", "device_id": DEVICE_ID,
           "stage_dir": str(tmp_path)}
    assert agent_config.validate_config(dict(cfg)) == cfg
    result = module.run_instruction_step(
        cfg=cfg, state={}, catalog=OldCatalog(), platform="guestshell",
        work_dir=str(tmp_path), boot_id="boot-a", monotonic_now=10.0,
        verifier=_Verifier(), persist_config=lambda _cfg: None,
        emit=lambda *_args: None, hints={}, catalog_date=NOW)
    assert result == {
        "instruction": None,
        "effective": None,
        "attestation": {"instr_state": "none"},
    }
    assert not (tmp_path / "iris-instructions.lkg").exists()


def test_lkg_store_never_leaves_plaintext_or_private_temporary_artifacts(
        tmp_path):
    cfg = {"lkg_key": LKG_KEY.hex()}
    _module, store, _cfg, _writes = _store(tmp_path, cfg)
    candidate = _verified(serial=17)
    store.store(candidate, candidate["device"], {})

    names = sorted(path.name for path in tmp_path.iterdir())
    assert names == ["iris-instructions.lkg"]
    raw = (tmp_path / names[0]).read_bytes()
    server_ciphertext = _server_instructions().parse_envelope(
        candidate["envelope"])[4]
    assert server_ciphertext not in raw
    assert _canonical(candidate["device"]) not in raw
    assert LKG_KEY.hex().encode("ascii") not in raw
    assert base64.b64encode(LKG_KEY) not in raw
    assert base64.b64encode(_canonical(candidate["device"])) not in raw
