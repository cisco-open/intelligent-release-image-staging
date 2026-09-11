# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Verified instruction application, cadence, and private attestation."""

import ast
import base64
import collections
import copy
import gc
import hashlib
import importlib.util
import ipaddress
import json
import os
import urllib.request
import weakref

import pytest

import instr
import iris_agent
from server import instructions as server_instructions


NOW = 2_000_000_000
BOOT = "task16-boot-a"
DEVICE_ID = "device-1"
KEY = bytes(range(32))
KEY_ID = hashlib.sha256(KEY).hexdigest()
LKG_KEY = b"l" * 32
ARMOR = (b"-----BEGIN SSH SIGNATURE-----\n"
         b"U1NIU0lHAAAAAQAAABVzc2gtZWQyNTUxOQAAAAE=\n"
         b"-----END SSH SIGNATURE-----\n")

GLOBAL_NAMES = (
    "bt-max-peers",
    "max-upload-limit",
    "max-download-limit",
    "max-overall-upload-limit",
    "max-overall-download-limit",
    "bt-request-peer-speed-limit",
    "max-concurrent-downloads",
)
LIVE_NAMES = (
    "bt-max-peers",
    "max-upload-limit",
    "max-download-limit",
    "bt-request-peer-speed-limit",
)
APPLIED_NAMES = (
    "bt_max_peers",
    "max_upload_limit",
    "max_download_limit",
    "overall_up",
    "overall_down",
    "request_peer_speed_limit",
    "max_concurrent",
)
QOS = {
    "max_peers": 11,
    "seed_up_bps": 12_000,
    "seed_down_bps": 13_000,
    "leech_up_bps": 14_000,
    "leech_down_bps": 15_000,
    "overall_up_bps": 16_000,
    "overall_down_bps": 17_000,
    "max_concurrent": 3,
    "request_peer_speed_limit_bps": 51_200,
}
CONTROL = {
    "catalog_tick_s": 300,
    "telemetry_every_ticks": 1,
    "telemetry_pause": False,
}
GLOBAL_EXPECTED = {
    "bt-max-peers": "11",
    "max-upload-limit": "14000",
    "max-download-limit": "15000",
    "max-overall-upload-limit": "16000",
    "max-overall-download-limit": "17000",
    "bt-request-peer-speed-limit": "51200",
    "max-concurrent-downloads": "3",
}
APPLIED_EXPECTED = {
    "bt_max_peers": 11,
    "max_upload_limit": 14_000,
    "max_download_limit": 15_000,
    "overall_up": 16_000,
    "overall_down": 17_000,
    "request_peer_speed_limit": 51_200,
    "max_concurrent": 3,
}
FIXED_QOS = {
    "max_peers": 10,
    "seed_up_bps": 0,
    "seed_down_bps": 0,
    "leech_up_bps": 0,
    "leech_down_bps": 0,
    "overall_up_bps": 0,
    "overall_down_bps": 0,
    "max_concurrent": 100,
    "request_peer_speed_limit_bps": 51_200,
}
FIXED_GLOBAL = {
    "bt-max-peers": "10",
    "max-upload-limit": "0",
    "max-download-limit": "0",
    "max-overall-upload-limit": "0",
    "max-overall-download-limit": "0",
    "bt-request-peer-speed-limit": "51200",
    "max-concurrent-downloads": "100",
}


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def _role(on_stale="keep", expires_at=NOW + 600, control=None):
    value = {
        "v": 1,
        "role": "default",
        "restricted": on_stale == "keep",
        "role_gen": hashlib.sha256(b"task16-role").hexdigest(),
        "issued_at": NOW,
        "expires_at": expires_at,
        "server_time": NOW,
        "qos": dict(QOS),
        "control": dict(CONTROL if control is None else control),
        "on_stale": on_stale,
    }
    return value


def _part(peers=None, qos_override=None, control_override=None,
          expires_at=NOW + 600):
    return {
        "peers": copy.deepcopy(peers or {
            "mode": "deny", "rules": ["198.51.100.7"],
            "include_origin": False,
            "allowed_expires_at": expires_at,
        }),
        "qos_override": dict(qos_override or {}),
        "control_override": dict(control_override or {}),
        "server_time": NOW,
    }


def _verified(peers=None, on_stale="keep", expires_at=NOW + 600,
              allowed_expires_at=None, serial=7, control=None,
              qos_override=None, control_override=None):
    role = _role(on_stale=on_stale, expires_at=expires_at, control=control)
    if peers is None:
        peers = {
            "mode": "deny", "rules": ["198.51.100.7"],
            "include_origin": False,
            "allowed_expires_at": expires_at,
        }
    else:
        peers = copy.deepcopy(peers)
    if allowed_expires_at is not None:
        peers["allowed_expires_at"] = allowed_expires_at
    part = _part(peers=peers, expires_at=expires_at,
                 qos_override=qos_override,
                 control_override=control_override)
    role_body = _canonical(role)
    header = {
        "v": 1,
        "device_id": DEVICE_ID,
        "platform": "guestshell",
        "epoch": NOW - 1,
        "instr_serial": serial,
        "policy_revision": 4,
        "issued_at": NOW,
        "expires_at": expires_at,
        "server_time": NOW,
        "verify_level": "sig",
        "key_id": KEY_ID,
        "role": "default",
        "role_gen": role["role_gen"],
        "role_body_sha256": hashlib.sha256(role_body).hexdigest(),
        "ct_len": len(_canonical(part)),
        "allowed_expires_at": peers["allowed_expires_at"],
        "degraded": False,
    }
    envelope = server_instructions.seal_parts(
        header, part, role_body, ARMOR, KEY)
    return {
        "header": header,
        "header_bytes": _canonical(header),
        "role": role,
        "role_body": role_body,
        "signature": ARMOR,
        "device": part,
        "envelope": envelope,
        "instr_state": "lkg",
        "on_stale": on_stale,
    }


def _result(peers=None, state="applied", serial=7, control=None):
    verified = _verified(peers=peers, serial=serial, control=control)
    return {
        "instruction": verified,
        "effective": copy.deepcopy(verified["device"]),
        "effective_peers": copy.deepcopy(verified["device"]["peers"]),
        "attestation": {
            "instr_state": state,
            "instr_epoch": verified["header"]["epoch"],
            "instr_serial": serial,
            "instr_policy_revision": verified["header"]["policy_revision"],
            "verify_level": "sig",
        },
    }


def _cfg(max_peers="999"):
    return {
        "catalog_url": "https://192.0.2.10:8443",
        "catalog_token": "catalog-token",
        "announce_token": "announce-secret",
        "device_id": DEVICE_ID,
        "stage_dir": "/stage",
        "rpc_port": "6800",
        "rpc_secret": "rpc-secret",
        "max_peers": max_peers,
        "token_expires_at": str(NOW + 604_800),
    }


class AcceptVerifier:
    def __init__(self):
        self.calls = []

    def verify(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return True


class TimeoutVerifier:
    def __init__(self):
        self.calls = []

    def verify(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise instr.InstructionError(
            state="verifier_missing", reason="verifier_timeout")


class AriaRPC:
    def __init__(self, active=None, session="session-a"):
        self.calls = []
        self.session = session
        self.active = [] if active is None else copy.deepcopy(active)
        self.global_options = dict(GLOBAL_EXPECTED)
        self.global_options.update({
            "header": ["Authorization: Bearer must-not-leak"],
            "rpc-secret": "must-not-leak",
        })
        self.gid_options = {}
        self.blocklist = {
            "ruleCount": 2,
            "revision": 1,
            "disconnectedPeers": 0,
            "removedPeers": 0,
        }
        self.setter_results = {
            "aria2.changeGlobalOption": "OK",
            "aria2.changeOption": "OK",
        }
        self.fail_method = None

    def __call__(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        if method == self.fail_method:
            raise RuntimeError("remote secret text must-not-leak")
        if method == "aria2.getSessionInfo":
            return {"sessionId": self.session}
        if method == "aria2.getGlobalOption":
            return copy.deepcopy(self.global_options)
        if method == "aria2.tellActive":
            return copy.deepcopy(self.active)
        if method == "aria2.getOption":
            value = dict(self.gid_options.get(params[0], GLOBAL_EXPECTED))
            value["header"] = ["Authorization: Bearer must-not-leak"]
            return value
        if method in ("aria2.changeGlobalOption", "aria2.changeOption"):
            return self.setter_results[method]
        if method == "aria2.setBtPeerBlocklist":
            return copy.deepcopy(self.blocklist)
        raise AssertionError("unexpected RPC method %s" % method)


def _apply(result, rpc=None, cfg=None, state=None, defaults=None):
    rpc = AriaRPC() if rpc is None else rpc
    state = {} if state is None else state
    defaults = {} if defaults is None else defaults
    fact = iris_agent._apply_instruction(
        result=result,
        cfg=_cfg() if cfg is None else cfg,
        state=state,
        rpc=rpc,
        torrent_defaults=defaults)
    return fact, rpc, state, defaults


def _deps(catalog, instruction_step, rpc, torrent_defaults, events=None,
          aria_add=None, refresh=None):
    events = [] if events is None else events
    values = {
        "catalog": catalog,
        "emit": lambda tag, msg: events.append(("emit", tag, msg)),
        "boot_image": lambda: "running.bin",
        "aria_add": (lambda *args: events.append(("add", args)))
        if aria_add is None else aria_add,
        "file_size": lambda _path: None,
        "verify": lambda *_args: True,
        "free_bytes": lambda _prefix="flash:": 10 ** 9,
        "version": lambda: "17.18.03",
        "copy_to_root": lambda *_args: True,
        "purge_others": lambda *_args: events.append(("reconcile",)),
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
        "refresh": (lambda: None) if refresh is None else refresh,
        "aria_stats": lambda _path: None,
        "aria_peers": lambda _path: [],
        "io_transfer": False,
        "checkpoint": lambda _state: None,
        "aria_session": lambda: None,
        "copy_in_place": False,
        "root_file_size": lambda *_args: None,
        "verify_root": lambda *_args: True,
        "instruction_step": instruction_step,
        "aria_rpc": rpc,
        "torrent_defaults": torrent_defaults,
    }
    return iris_agent.Deps(**values)


class RuntimeCatalog:
    def __init__(self, policy=None, heartbeat_response=None):
        self.policy = {"approved_image_id": None} if policy is None else policy
        self.heartbeat_response = heartbeat_response
        self.events = []
        self.heartbeats = []
        self.last_authenticated_date = NOW
        self.response_authenticated_date = NOW
        self.policy_authenticated_date = NOW
        self.heartbeat_authenticated_date = NOW
        self.policy_error = None

    def get_policy(self, device_id):
        self.events.append(("policy", device_id))
        self.response_authenticated_date = self.policy_authenticated_date
        if self.policy_error is not None:
            raise self.policy_error
        return copy.deepcopy(self.policy)

    def get_image(self, image_id):
        self.events.append(("image", image_id))
        raise AssertionError("catalog image request was not expected")

    def heartbeat(self, device_id, payload):
        self.events.append(("heartbeat", device_id))
        self.heartbeats.append(copy.deepcopy(payload))
        self.response_authenticated_date = self.heartbeat_authenticated_date
        return copy.deepcopy(self.heartbeat_response)

    def post_telemetry(self, *_args):
        raise AssertionError("telemetry was not expected")


class InstructionStep:
    def __init__(self, result=None, events=None):
        self.result = _result(control=CONTROL) if result is None else result
        self.events = [] if events is None else events
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        self.events.append(("step", bool(kwargs.get("cache_only"))))
        return copy.deepcopy(self.result)


def test_task16_owned_sources_parse_as_python36():
    paths = (instr.__file__, iris_agent.__file__, __file__)
    for path in paths:
        with open(path, "rb") as source:
            ast.parse(source.read(), filename=path, feature_version=(3, 6))


def _write_lkg(tmp_path, candidate, state, verifier=None):
    cfg = {
        "device_id": DEVICE_ID,
        "stage_dir": str(tmp_path),
        "lkg_key": LKG_KEY.hex(),
        "instr_key": _canonical({"key_id": KEY_ID,
                                  "value": KEY.hex()}).decode("ascii"),
    }
    store = instr.LKGStore(
        str(tmp_path), cfg, lambda _value: None,
        AcceptVerifier() if verifier is None else verifier)
    store.store(candidate, candidate["device"], state)
    return cfg


def _write_recovered_keylist(tmp_path, krl, sequence, artifact_digest):
    value = {
        "schema": instr.KEYLIST_STATE_SCHEMA,
        "keylist_seq": sequence,
        "artifact_sha256": artifact_digest,
        "krl_sha256": hashlib.sha256(krl).hexdigest(),
        "krl_b64": base64.b64encode(krl).decode("ascii"),
        "issued_at": NOW,
        "verified_root_id": "root-a",
    }
    with open(os.path.join(str(tmp_path), instr.KEYLIST_STATE_NAME), "w") as f:
        json.dump(value, f)


def _preview_lkg(cfg, state, tmp_path, verifier, attempts):
    return instr.run_instruction_step(
        cfg, state, object(), {}, None, "guestshell", str(tmp_path), BOOT,
        11.0, verifier, lambda _cfg: None, lambda *_args: None,
        cache_only=True, verification_attempts=attempts)


def test_deps_keeps_29_fields_and_task16_metadata_is_per_instance():
    catalog = RuntimeCatalog()
    a_rpc = AriaRPC()
    b_rpc = AriaRPC(session="session-b")
    a_defaults = {}
    b_defaults = {}
    step = InstructionStep()
    a = _deps(catalog, step, a_rpc, a_defaults)
    b = a._replace(aria_rpc=b_rpc, torrent_defaults=b_defaults)
    c = _deps(catalog, step, b_rpc, {})

    assert len(iris_agent.Deps._fields) == 29
    assert "aria_rpc" not in iris_agent.Deps._fields
    assert "torrent_defaults" not in iris_agent.Deps._fields
    assert a.aria_rpc is a_rpc and a.torrent_defaults is a_defaults
    assert b.aria_rpc is b_rpc and b.torrent_defaults is b_defaults
    assert c is not a and a.aria_rpc is a_rpc
    assert a._replace(emit=lambda *_args: None).aria_rpc is a_rpc


def test_dual_module_wrapper_replace_reaches_canonical_torrent_options(
        tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "task16_launcher_module", iris_agent.__file__)
    launcher_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher_module)
    monkeypatch.setattr(instr, "paths_for", lambda _platform, _cfg: {
        "work_dir": str(tmp_path), "signers": str(tmp_path / "signers"),
        "root_signers": str(tmp_path / "roots")})
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(instr, "SSHVerifier", lambda *_args, **_kwargs:
                        AcceptVerifier())
    observed = []

    def canonical_add(_torrent_path, dest_dir):
        observed.append(iris_agent._aria_torrent_options(_cfg(), dest_dir))
        return "f" * 16

    base = _deps(RuntimeCatalog(), None, None, {}, aria_add=canonical_add)
    wrapped = launcher_module._with_instruction_step(
        base, _cfg(), str(tmp_path / "iris-agent.conf"), "xr-appmgr")
    replacement = {
        "bt-max-peers": "23",
        "max-upload-limit": "24000",
        "max-download-limit": "25000",
        "bt-request-peer-speed-limit": "52000",
    }
    replaced = wrapped._replace(torrent_defaults=replacement)

    replaced.aria_add(str(tmp_path / "image.torrent"), "/stage")

    assert replaced.torrent_defaults is replacement
    assert {name: observed[0][name] for name in LIVE_NAMES} == replacement


@pytest.mark.parametrize("rpc_update,private_value", [
    pytest.param(
        {"rpc_secret": ["rpc-private-sentinel"]},
        "rpc-private-sentinel", id="invalid-secret"),
    pytest.param(
        {"rpc_port": "invalid-port"}, "invalid-port", id="invalid-port"),
])
def test_wrapper_invalid_rpc_metadata_still_fails_closed_as_task16(
        tmp_path, monkeypatch, rpc_update, private_value):
    cfg = dict(_cfg(), **rpc_update)
    events = []
    transport_attempts = []
    catalog = RuntimeCatalog(policy={"approved_image_ids": ["image-a"]})
    base = _deps(catalog, None, None, {}, events=events)
    monkeypatch.setattr(instr, "paths_for", lambda _platform, _cfg: {
        "work_dir": str(tmp_path), "signers": str(tmp_path / "signers"),
        "root_signers": str(tmp_path / "roots")})
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(instr, "SSHVerifier", lambda *_args, **_kwargs:
                        AcceptVerifier())
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: 100.0)

    def urlopen(*args, **kwargs):
        transport_attempts.append((args, kwargs))
        raise AssertionError("invalid RPC metadata reached transport")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(
        iris_agent, "_reconcile_set",
        lambda *_args: events.append(("reconcile",)))
    monkeypatch.setattr(
        iris_agent, "_stage_image",
        lambda *_args, **_kwargs: events.append(("stage",)) or "staging")

    wrapped = iris_agent._with_instruction_step(
        base, cfg, str(tmp_path / "iris-agent.conf"), "guestshell")
    assert iris_agent._task16_runtime(wrapped)
    with pytest.raises(iris_agent.InstructionApplyError) as caught:
        wrapped.aria_rpc("aria2.getSessionInfo", [])
    assert str(caught.value) == "RPC unavailable"
    assert private_value not in repr(caught.value)
    assert transport_attempts == []
    wrapped = wrapped._replace(
        instruction_step=InstructionStep(events=events))

    state = {}
    result = iris_agent.run_once(cfg, wrapped, state)

    assert result == "instruction-apply-unavailable"
    assert len(catalog.heartbeats) == 1
    assert catalog.heartbeats[0]["instr_state"] == "instr_unavailable"
    assert not {"applied", "blocklist_rules", "blocklist_revision"}.intersection(
        catalog.heartbeats[0])
    assert [event[0] for event in catalog.events].count("heartbeat") == 1
    assert not any(event[0] in ("reconcile", "stage", "add")
                   for event in events)
    assert transport_attempts == []
    public = json.dumps({
        "events": events, "state": state,
        "heartbeats": catalog.heartbeats}, sort_keys=True)
    assert private_value not in public


def test_wrapper_rpc_normalizes_empty_secret_and_zero_padded_port(
        tmp_path, monkeypatch):
    cfg = dict(_cfg(), rpc_secret="", rpc_port="06800")
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size=None):
            return _canonical({
                "jsonrpc": "2.0", "id": "p",
                "result": {"sessionId": "session-a"}})

    def urlopen(request, timeout=10):
        requests.append((request, timeout))
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(instr, "paths_for", lambda _platform, _cfg: {
        "work_dir": str(tmp_path), "signers": str(tmp_path / "signers"),
        "root_signers": str(tmp_path / "roots")})
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(instr, "SSHVerifier", lambda *_args, **_kwargs:
                        AcceptVerifier())
    wrapped = iris_agent._with_instruction_step(
        _deps(RuntimeCatalog(), None, None, {}), cfg,
        str(tmp_path / "iris-agent.conf"), "guestshell")

    assert wrapped.aria_rpc("aria2.getSessionInfo", []) == {
        "sessionId": "session-a"}

    request, timeout = requests[0]
    payload = json.loads(request.data.decode("ascii"))
    assert request.full_url == "http://127.0.0.1:6800/jsonrpc"
    assert payload["params"] == ["token:iris"]
    assert timeout == 10


def test_cache_only_preview_is_network_and_lower_hint_neutral_with_real_lkg(
        tmp_path, monkeypatch):
    state = {"instructions": {
        "lower_hint": {"epoch": NOW - 2, "instr_serial": 2},
        "lower_hint_count": 9,
        "pending_reset": {"epoch": NOW - 2, "instr_serial": 2},
        "instruction_clock": {
            "effective": NOW + 1, "monotonic": 10.0, "boot_id": BOOT},
        "catalog_clock": {
            "effective": NOW + 2, "monotonic": 10.0, "boot_id": BOOT},
    }}
    candidate = _verified()
    cfg = _write_lkg(tmp_path, candidate, state)
    before = copy.deepcopy(state["instructions"])

    class NoCatalog:
        def __getattr__(self, name):
            raise AssertionError("cache preview used catalog.%s" % name)

    monkeypatch.setattr(
        instr, "note_hint",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("cache preview observed a hint")))
    result = instr.run_instruction_step(
        cfg, state, NoCatalog(),
        {"instr_rev": {"epoch": NOW - 3, "instr_serial": 1}},
        NOW + 50, "guestshell", str(tmp_path), BOOT, 11.0,
        AcceptVerifier(), lambda _cfg: None, lambda *_args: None,
        cache_only=True, verification_attempts={})

    assert result["instruction"]["header"]["instr_serial"] == 7
    assert result["effective_peers"] == candidate["device"]["peers"]
    assert {name: state["instructions"].get(name) for name in (
        "lower_hint", "lower_hint_count", "pending_reset")} == {
            name: before[name] for name in (
                "lower_hint", "lower_hint_count", "pending_reset")}
    assert state["instructions"]["catalog_clock"] == before["catalog_clock"]


def test_cache_preview_recovers_retained_krl_and_shares_one_timeout_attempt(
        tmp_path):
    state = {"instructions": {"instruction_clock": {
        "effective": NOW + 1, "monotonic": 10.0, "boot_id": BOOT}}}
    candidate = _verified()
    cfg = _write_lkg(tmp_path, candidate, state)
    empty_digest = hashlib.sha256(b"").hexdigest()
    keylist_state = {
        "schema": instr.KEYLIST_STATE_SCHEMA,
        "keylist_seq": 1,
        "artifact_sha256": "a" * 64,
        "krl_sha256": empty_digest,
        "krl_b64": "",
        "issued_at": NOW,
        "verified_root_id": "root-a",
    }
    with open(os.path.join(str(tmp_path), instr.KEYLIST_STATE_NAME), "w") as f:
        json.dump(keylist_state, f)

    class Catalog:
        def __init__(self):
            self.calls = []

        def get_instructions(self, device_id, etag=None):
            self.calls.append((device_id, etag))
            return 200, candidate["envelope"], {
                "Date": "Wed, 18 May 2033 03:33:20 GMT"}

        def get_instruction_keylist(self, *_args, **_kwargs):
            raise AssertionError("unchanged keylist was fetched")

    attempts = {}
    verifier = TimeoutVerifier()
    catalog = Catalog()
    preview = instr.run_instruction_step(
        cfg, state, catalog, {}, None, "guestshell", str(tmp_path), BOOT,
        11.0, verifier, lambda _cfg: None, lambda *_args: None,
        cache_only=True, verification_attempts=attempts)
    due = instr.run_instruction_step(
        cfg, state, catalog,
        {"instr_rev": {"epoch": NOW - 1, "instr_serial": 7}},
        NOW, "guestshell", str(tmp_path), BOOT, 11.0, verifier,
        lambda _cfg: None, lambda *_args: None,
        verification_attempts=attempts)

    assert preview["attestation"]["instr_state"] == "verifier_missing"
    assert due["attestation"]["instr_state"] == "verifier_missing"
    assert preview["effective_peers"]["mode"] == "tracker-only"
    assert due["effective_peers"]["mode"] == "tracker-only"
    assert len(verifier.calls) == 1
    assert verifier.calls[0][1]["krl"] == b""
    assert state["instructions"]["verifier_timeout_count"] == 1
    assert len(catalog.calls) == 1

    changed_krl = b"SSHKRL\n\x00changed"
    keylist_state.update({
        "keylist_seq": 2,
        "artifact_sha256": "b" * 64,
        "krl_sha256": hashlib.sha256(changed_krl).hexdigest(),
        "krl_b64": base64.b64encode(changed_krl).decode("ascii"),
    })
    with open(os.path.join(str(tmp_path), instr.KEYLIST_STATE_NAME), "w") as f:
        json.dump(keylist_state, f)
    changed = instr.run_instruction_step(
        cfg, state, catalog, {}, None, "guestshell", str(tmp_path), BOOT,
        12.0, verifier, lambda _cfg: None, lambda *_args: None,
        cache_only=True, verification_attempts=attempts)
    assert changed["attestation"]["instr_state"] == "verifier_missing"
    assert len(verifier.calls) == 2
    assert verifier.calls[-1][1]["krl"] == changed_krl
    assert state["instructions"]["verifier_timeout_count"] == 1

    absent_work = tmp_path / "absent"
    absent_work.mkdir()
    absent_cfg = dict(cfg, stage_dir=str(absent_work))
    absent = instr.run_instruction_step(
        absent_cfg, {"instructions": {}}, object(), {}, None, "guestshell",
        str(absent_work), BOOT, 12.0, AcceptVerifier(),
        lambda _cfg: None, lambda *_args: None,
        cache_only=True, verification_attempts={})
    assert absent["instruction"] is None
    assert absent["effective_peers"]["mode"] == "tracker-only"


def test_artifact_ahead_preview_and_due_share_retained_krl_timeout_budget(
        tmp_path):
    for label, retained_krl in (
            ("nonempty", b"SSHKRL\n\x00retained"), ("empty", b"")):
        work_dir = tmp_path / label
        work_dir.mkdir()
        state = {"instructions": {"instruction_clock": {
            "effective": NOW + 1, "monotonic": 10.0,
            "boot_id": BOOT}}}
        _write_recovered_keylist(work_dir, retained_krl, 1, "a" * 64)
        metadata = {
            "v": 1, "keylist_seq": 2, "issued_at": NOW,
            "signer_root_id": "root-a",
            "krl_sha256": hashlib.sha256(b"").hexdigest(),
        }
        payload = (b"IRIS-KEYLIST/1\n"
                   + base64.b64encode(_canonical(metadata)) + b"\n\n")
        candidate = payload + base64.b64encode(ARMOR) + b"\n"
        with open(os.path.join(
                str(work_dir), instr.KEYLIST_NAME), "wb") as stream:
            stream.write(candidate)

        class TimeoutRootVerifier:
            def __init__(self):
                self.calls = []

            def validate_krl(self, value):
                assert value == b""

            def root_lines(self):
                return {"root-a": b"unused"}

            def verify(self, body, signature, namespace, identity,
                       verify_time, **kwargs):
                self.calls.append((body, signature, namespace, identity,
                                   verify_time, kwargs))
                raise instr.InstructionError(
                    "verifier_missing", "verifier_timeout")

        class Catalog:
            def __init__(self):
                self.calls = 0

            def get_instruction_keylist(self, device_id, etag=None):
                assert device_id == DEVICE_ID
                self.calls += 1
                return 200, candidate, {
                    "Date": "Wed, 18 May 2033 03:33:20 GMT"}

        cfg = dict(_cfg(), stage_dir=str(work_dir))
        attempts = {}
        verifier = TimeoutRootVerifier()
        catalog = Catalog()
        preview = instr.run_instruction_step(
            cfg, state, catalog, {}, None, "guestshell", str(work_dir),
            BOOT, 11.0, verifier, lambda _cfg: None,
            lambda *_args: None, cache_only=True,
            verification_attempts=attempts)
        due = instr.run_instruction_step(
            cfg, state, catalog, {"keylist_seq": 2}, NOW,
            "guestshell", str(work_dir), BOOT, 11.0, verifier,
            lambda _cfg: None, lambda *_args: None,
            verification_attempts=attempts)

        assert preview["attestation"]["instr_state"] == "verifier_missing"
        assert due["attestation"]["instr_state"] == "verifier_missing"
        assert len(verifier.calls) == 1
        assert verifier.calls[0][-1]["krl"] == retained_krl
        assert state["instructions"]["verifier_timeout_count"] == 1
        assert catalog.calls == 1


def test_verifier_attempt_map_distinguishes_changed_krl_and_keeps_repeat_count(
        tmp_path):
    state = {"instructions": {"instruction_clock": {
        "effective": NOW + 1, "monotonic": 10.0, "boot_id": BOOT}}}
    candidate = _verified()
    cfg = _write_lkg(tmp_path, candidate, state)
    old_krl = b"SSHKRL\n\x00old"
    new_krl = b"SSHKRL\n\x00new"
    _write_recovered_keylist(tmp_path, old_krl, 1, "a" * 64)
    attempts = {}
    verifier = TimeoutVerifier()

    first = _preview_lkg(cfg, state, tmp_path, verifier, attempts)
    _write_recovered_keylist(tmp_path, new_krl, 2, "b" * 64)
    second = _preview_lkg(cfg, state, tmp_path, verifier, attempts)
    third = _preview_lkg(cfg, state, tmp_path, verifier, attempts)

    assert [item["attestation"]["instr_state"]
            for item in (first, second, third)] == [
                "verifier_missing", "verifier_missing", "verifier_missing"]
    assert len(verifier.calls) == 2
    assert all("krl" in kwargs for _args, kwargs in verifier.calls)
    assert [kwargs["krl"] for _args, kwargs in verifier.calls] == [
        old_krl, new_krl]
    assert state["instructions"]["verifier_timeout_count"] == 1


def test_verifier_attempt_map_distinguishes_absent_from_installed_empty_krl(
        tmp_path):
    state = {"instructions": {"instruction_clock": {
        "effective": NOW + 1, "monotonic": 10.0, "boot_id": BOOT}}}
    candidate = _verified()
    cfg = _write_lkg(tmp_path, candidate, state)
    attempts = {}
    verifier = TimeoutVerifier()

    _preview_lkg(cfg, state, tmp_path, verifier, attempts)
    _write_recovered_keylist(tmp_path, b"", 1, "a" * 64)
    _preview_lkg(cfg, state, tmp_path, verifier, attempts)

    assert len(verifier.calls) == 2
    assert all("krl" in kwargs for _args, kwargs in verifier.calls)
    assert verifier.calls[0][1]["krl"] is None
    assert verifier.calls[1][1]["krl"] == b""
    assert state["instructions"]["verifier_timeout_count"] == 1


def test_json_reloaded_saturated_old_krl_timeout_revalidates_changed_krl(
        tmp_path):
    state = {"instructions": {"instruction_clock": {
        "effective": NOW + 1, "monotonic": 10.0, "boot_id": BOOT}}}
    candidate = _verified()
    cfg = _write_lkg(tmp_path, candidate, state)
    old_krl = b"SSHKRL\n\x00old"
    new_krl = b"SSHKRL\n\x00recovered"
    _write_recovered_keylist(tmp_path, old_krl, 1, "a" * 64)

    class Catalog:
        def get_instructions(self, _device_id, etag=None):
            return 200, candidate["envelope"], {
                "Date": "Wed, 18 May 2033 03:33:20 GMT"}

        def get_instruction_keylist(self, *_args, **_kwargs):
            raise AssertionError("keylist fetch was not expected")

    attempts = {}
    first_verifier = TimeoutVerifier()
    _preview_lkg(cfg, state, tmp_path, first_verifier, attempts)
    instr.run_instruction_step(
        cfg, state, Catalog(),
        {"instr_rev": {"epoch": NOW - 1, "instr_serial": 7}},
        NOW, "guestshell", str(tmp_path), BOOT, 11.0, first_verifier,
        lambda _cfg: None, lambda *_args: None,
        verification_attempts=attempts)
    assert set(state["instructions"]["verifier_timeouts"]) == {
        "role", "lkg"}

    reloaded = json.loads(json.dumps(state))
    for record in reloaded["instructions"]["verifier_timeouts"].values():
        record["count"] = 3
    reloaded["instructions"]["verifier_timeout_count"] = 3
    _write_recovered_keylist(tmp_path, new_krl, 2, "b" * 64)
    recovered_verifier = TimeoutVerifier()

    result = _preview_lkg(
        cfg, reloaded, tmp_path, recovered_verifier, {})

    role_artifact = (b"IRIS-ROLE/1\n"
                     + base64.b64encode(candidate["role_body"]) + b"\n"
                     + base64.b64encode(candidate["signature"]) + b"\n")
    role_digest = hashlib.sha256(role_artifact).hexdigest()
    assert result["attestation"]["instr_state"] == "verifier_missing"
    assert len(recovered_verifier.calls) == 1
    assert "krl" in recovered_verifier.calls[0][1]
    assert recovered_verifier.calls[0][1]["krl"] == new_krl
    assert reloaded["instructions"]["verifier_timeout_digest"] == role_digest
    assert reloaded["instructions"]["verifier_timeout_count"] == 1
    assert reloaded["instructions"]["verifier_timeout_boot_id"] == BOOT

    restarted = json.loads(json.dumps(reloaded))
    same_krl_verifier = TimeoutVerifier()
    repeated = _preview_lkg(
        cfg, restarted, tmp_path, same_krl_verifier, {})

    assert repeated["attestation"]["instr_state"] == "verifier_missing"
    assert len(same_krl_verifier.calls) == 1
    assert "krl" in same_krl_verifier.calls[0][1]
    assert same_krl_verifier.calls[0][1]["krl"] == new_krl
    assert restarted["instructions"]["verifier_timeout_digest"] == role_digest
    assert restarted["instructions"]["verifier_timeout_count"] == 2
    assert restarted["instructions"]["verifier_timeout_boot_id"] == BOOT


@pytest.mark.parametrize("mode", ["deny", "allow"], ids=["deny", "allow"])
def test_a3_stale_peer_posture_is_independent_of_defaulted_qos(
        tmp_path, mode):
    peer = ({"mode": "deny", "rules": ["198.51.100.7"],
             "include_origin": False, "allowed_expires_at": NOW + 5}
            if mode == "deny" else
            {"mode": "allow", "allowed": ["198.51.100.7"],
             "include_origin": False, "allowed_expires_at": NOW + 5})
    candidate = _verified(
        peers=peer, on_stale="defaults", expires_at=NOW + 10)
    state = {"instructions": {"instruction_clock": {
        "effective": NOW + 10, "monotonic": 10.0, "boot_id": BOOT}}}
    cfg = _write_lkg(tmp_path, candidate, state)
    result = instr.run_instruction_step(
        cfg, state, object(), {}, None, "guestshell", str(tmp_path), BOOT,
        10.0, AcceptVerifier(), lambda _cfg: None, lambda *_args: None,
        cache_only=True, verification_attempts={})

    assert result["instruction"]["role"] is None
    assert result["instruction"]["device"] is None
    assert result["effective"] is None
    if mode == "deny":
        assert result["effective_peers"] == peer
        assert result["attestation"]["instr_state"] == "stale_expired"
    else:
        assert result["effective_peers"]["mode"] == "tracker-only"
        assert result["attestation"]["instr_state"] == "allowlist_expired"


def test_allowlist_expiry_equality_and_unknown_clock_are_tracker_only(
        tmp_path):
    peers = {"mode": "allow", "allowed": ["198.51.100.7"],
             "include_origin": False, "allowed_expires_at": NOW + 5}
    candidate = _verified(
        peers=peers, expires_at=NOW + 600, allowed_expires_at=NOW + 5)
    for suffix, clock in (("equal", {
            "effective": NOW + 5, "monotonic": 10.0, "boot_id": BOOT}),
            ("unknown", None)):
        work = tmp_path / suffix
        state = {"instructions": {}}
        if clock is not None:
            state["instructions"]["instruction_clock"] = clock
        cfg = _write_lkg(work, candidate, state)
        result = instr.run_instruction_step(
            cfg, state, object(), {}, None, "guestshell", str(work), BOOT,
            10.0, AcceptVerifier(), lambda _cfg: None, lambda *_args: None,
            cache_only=True, verification_attempts={})
        assert result["effective_peers"]["mode"] == "tracker-only"
        assert result["attestation"]["instr_state"] == "allowlist_expired"


def test_role_device_overrides_merge_and_stale_defaults_are_fixed(
        tmp_path, monkeypatch):
    merged_candidate = _verified(
        qos_override={"max_peers": 23, "leech_down_bps": 25_000},
        control_override={"catalog_tick_s": 600})
    merged_state = {"instructions": {"instruction_clock": {
        "effective": NOW + 1, "monotonic": 10.0, "boot_id": BOOT}}}
    merged_cfg = _write_lkg(tmp_path / "merged", merged_candidate,
                            merged_state)
    merged = instr.run_instruction_step(
        merged_cfg, merged_state, object(), {}, None, "guestshell",
        str(tmp_path / "merged"), BOOT, 10.0, AcceptVerifier(),
        lambda _cfg: None, lambda *_args: None,
        cache_only=True, verification_attempts={})
    fact, rpc, _state, defaults = _apply(merged)
    global_write = next(call[1][0] for call in rpc.calls
                        if call[0] == "aria2.changeGlobalOption")
    assert global_write["bt-max-peers"] == "23"
    assert global_write["max-download-limit"] == "25000"
    assert fact["applied"]["bt_max_peers"] == 23
    assert defaults["max-download-limit"] == "25000"

    cadence_clock = [100.0]
    monkeypatch.setattr(iris_agent.time, "monotonic",
                        lambda: cadence_clock[0])
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(iris_agent, "_reconcile_set", lambda *_args: None)
    catalog = RuntimeCatalog()
    cadence_deps = _deps(
        catalog, InstructionStep(result=merged), AriaRPC(), {})
    cadence_state = {}
    iris_agent.run_once(_cfg(), cadence_deps, cadence_state)
    cadence_clock[0] = 699.0
    catalog.events = []
    assert iris_agent.run_once(
        _cfg(), cadence_deps, cadence_state) == "catalog-not-due"
    cadence_clock[0] = 700.0
    catalog.events = []
    iris_agent.run_once(_cfg(), cadence_deps, cadence_state)
    assert catalog.events[0][0] == "policy"

    stale_candidate = _verified(
        on_stale="defaults", expires_at=NOW + 5)
    stale_state = {"instructions": {"instruction_clock": {
        "effective": NOW + 5, "monotonic": 10.0, "boot_id": BOOT}}}
    stale_cfg = _write_lkg(tmp_path / "stale", stale_candidate, stale_state)
    stale = instr.run_instruction_step(
        stale_cfg, stale_state, object(), {}, None, "guestshell",
        str(tmp_path / "stale"), BOOT, 10.0, AcceptVerifier(),
        lambda _cfg: None, lambda *_args: None,
        cache_only=True, verification_attempts={})
    assert stale["effective"] is None
    fact, rpc, _state, defaults = _apply(
        stale, cfg=_cfg(max_peers="999"))
    assert next(call[1][0] for call in rpc.calls
                if call[0] == "aria2.changeGlobalOption") == FIXED_GLOBAL
    assert fact["applied"] == {
        "bt_max_peers": 10, "max_upload_limit": 0,
        "max_download_limit": 0, "overall_up": 0, "overall_down": 0,
        "request_peer_speed_limit": 51_200, "max_concurrent": 100,
    }
    assert defaults == {name: FIXED_GLOBAL[name] for name in LIVE_NAMES}

    cadence_clock[0] = 800.0
    stale_catalog = RuntimeCatalog()
    stale_deps = _deps(
        stale_catalog, InstructionStep(result=stale), AriaRPC(), {})
    stale_runtime_state = {}
    iris_agent.run_once(_cfg(), stale_deps, stale_runtime_state)
    cadence_clock[0] = 859.0
    stale_catalog.events = []
    iris_agent.run_once(_cfg(), stale_deps, stale_runtime_state)
    assert stale_catalog.events[0][0] == "policy"
    cadence_clock[0] = 860.0
    stale_catalog.events = []
    iris_agent.run_once(_cfg(), stale_deps, stale_runtime_state)
    assert stale_catalog.events[0][0] == "policy"


def test_apply_reads_first_then_writes_exact_values_for_seeder_and_leecher():
    active = [
        {"gid": "a" * 16, "files": [], "seeder": "true"},
        {"gid": "b" * 16, "files": [], "seeder": "false"},
    ]
    rpc = AriaRPC(active=active)
    state = {}
    fact, rpc, state, defaults = _apply(_result(), rpc=rpc, state=state)
    methods = [item[0] for item in rpc.calls]
    assert methods == [
        "aria2.getSessionInfo", "aria2.getGlobalOption", "aria2.tellActive",
        "aria2.getOption", "aria2.getOption", "aria2.changeGlobalOption",
        "aria2.changeOption", "aria2.changeOption",
        "aria2.setBtPeerBlocklist",
    ]
    tell = rpc.calls[2][1]
    assert tell == [["gid", "files", "seeder"]]
    global_write = rpc.calls[5][1]
    assert global_write == [GLOBAL_EXPECTED]
    assert set(global_write[0]) == set(GLOBAL_NAMES)
    assert rpc.calls[6] == ("aria2.changeOption", ["a" * 16, {
        "bt-max-peers": "11", "max-upload-limit": "12000",
        "max-download-limit": "13000",
        "bt-request-peer-speed-limit": "51200",
    }])
    assert rpc.calls[7] == ("aria2.changeOption", ["b" * 16, {
        "bt-max-peers": "11", "max-upload-limit": "14000",
        "max-download-limit": "15000",
        "bt-request-peer-speed-limit": "51200",
    }])
    assert fact["applied"] == APPLIED_EXPECTED
    assert defaults == {name: GLOBAL_EXPECTED[name] for name in LIVE_NAMES}
    heartbeat = iris_agent._heartbeat_with_instruction({}, fact)
    public = repr((fact, state, defaults, heartbeat))
    for private in ("Authorization", "must-not-leak", "198.51.100.7",
                    "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"):
        assert private not in public


def test_active_response_objects_are_released_before_the_first_write():
    class ActiveRows(list):
        pass

    class ActiveRow(dict):
        pass

    class ProjectionRPC(AriaRPC):
        def __init__(self):
            super().__init__()
            self.response_refs = None
            self.retained_at_first_write = None

        def __call__(self, method, params):
            if method == "aria2.tellActive":
                self.calls.append((method, copy.deepcopy(params)))
                row = ActiveRow({
                    "gid": "a" * 16, "files": [], "seeder": "false"})
                rows = ActiveRows([row])
                self.response_refs = (weakref.ref(rows), weakref.ref(row))
                return rows
            if (method == "aria2.changeGlobalOption"
                    and self.retained_at_first_write is None):
                gc.collect()
                self.retained_at_first_write = tuple(
                    reference() is not None for reference in self.response_refs)
            return super().__call__(method, params)

    rpc = ProjectionRPC()
    _apply(_result(), rpc=rpc)

    assert rpc.retained_at_first_write == (False, False)


def test_apply_is_unconditional_on_identical_state_and_setters_must_ack():
    state = {}
    defaults = {}
    rpc = AriaRPC(active=[{
        "gid": "c" * 16, "files": [], "seeder": "false"}])
    _apply(_result(), rpc=rpc, state=state, defaults=defaults)
    first = len([call for call in rpc.calls if call[0].startswith("aria2.change")
                 or call[0] == "aria2.setBtPeerBlocklist"])
    _apply(_result(), rpc=rpc, state=state, defaults=defaults)
    writes = [call for call in rpc.calls if call[0].startswith("aria2.change")
              or call[0] == "aria2.setBtPeerBlocklist"]
    assert first == 3 and len(writes) == 6

    for method in ("aria2.changeGlobalOption", "aria2.changeOption"):
        bad = AriaRPC(active=[{
            "gid": "c" * 16, "files": [], "seeder": "false"}])
        bad.setter_results[method] = {"unexpected": "truthy"}
        with pytest.raises(Exception):
            _apply(_result(), rpc=bad, state={}, defaults={})


@pytest.mark.parametrize("bad", [
    [{"gid": "%016x" % n, "files": [], "seeder": "false"}
     for n in range(11)],
    [{"gid": "bad gid", "files": [], "seeder": "false"}],
    [{"gid": "d" * 16, "files": [], "seeder": True}],
    [{"gid": "d" * 16, "files": [], "seeder": "TRUE"}],
    [{"gid": "d" * 16, "files": [], "seeder": "false", "extra": 1}],
    {},
    7,
], ids=["eleven", "gid", "boolean-seeder", "seeder-spelling", "extra",
        "object", "scalar"])
def test_active_rows_are_strict_and_never_partially_applied(bad):
    rpc = AriaRPC(active=bad)
    with pytest.raises(Exception):
        _apply(_result(), rpc=rpc)
    assert not any(call[0].startswith("aria2.change")
                   or call[0] == "aria2.setBtPeerBlocklist"
                   for call in rpc.calls)


@pytest.mark.parametrize("scope,bad", [
    ("global-missing", None),
    ("global-bool", True),
    ("global-overflow", str(2 ** 63)),
    ("gid-negative", "-1"),
    ("gid-space", " 11"),
], ids=["global-missing", "global-bool", "global-overflow",
        "gid-negative", "gid-space"])
def test_owned_readbacks_require_closed_nonnegative_i63_decimals(scope, bad):
    gid = "d" * 16
    rpc = AriaRPC(active=[{"gid": gid, "files": [], "seeder": "false"}])
    if scope == "global-missing":
        del rpc.global_options["bt-max-peers"]
    elif scope.startswith("global-"):
        rpc.global_options["bt-max-peers"] = bad
    else:
        rpc.gid_options[gid] = dict(GLOBAL_EXPECTED)
        rpc.gid_options[gid]["bt-max-peers"] = bad
    with pytest.raises(Exception):
        _apply(_result(), rpc=rpc)
    assert not any(call[0].startswith("aria2.change")
                   or call[0] == "aria2.setBtPeerBlocklist"
                   for call in rpc.calls)


@pytest.mark.parametrize("bad", [
    {"ruleCount": 1, "revision": 1, "disconnectedPeers": 0},
    {"ruleCount": True, "revision": 1,
     "disconnectedPeers": 0, "removedPeers": 0},
    {"ruleCount": 1, "revision": -1,
     "disconnectedPeers": 0, "removedPeers": 0},
    {"ruleCount": 1, "revision": 2 ** 63,
     "disconnectedPeers": 0, "removedPeers": 0},
    {"ruleCount": 1, "revision": 1,
     "disconnectedPeers": 0, "removedPeers": 0, "extra": 0},
], ids=["missing", "bool", "negative", "overflow", "extra"])
def test_blocklist_result_is_closed_exact_i63_and_failed_apply_is_private(bad):
    rpc = AriaRPC()
    rpc.blocklist = bad
    state = {}
    defaults = {}
    with pytest.raises(Exception) as caught:
        _apply(_result(), rpc=rpc, state=state, defaults=defaults)
    public = repr((caught.value.__class__.__name__, state, defaults))
    assert "must-not-leak" not in public
    assert "Authorization" not in public
    assert "applied" not in state.get("instructions", {})


def test_same_session_drift_is_sorted_bounded_and_blocklist_move_is_paired():
    state = {}
    defaults = {}
    active = [{"gid": "%016x" % n, "files": [], "seeder": "false"}
              for n in range(10)]
    rpc = AriaRPC(active=active)
    first, _rpc, state, defaults = _apply(
        _result(), rpc=rpc, state=state, defaults=defaults)
    assert "qos_drift" not in first

    rpc.calls = []
    rpc.global_options = {name: "0" for name in GLOBAL_NAMES}
    for row in active:
        rpc.gid_options[row["gid"]] = {
            name: "0" for name in LIVE_NAMES}
    rpc.blocklist["revision"] = 2
    second, _rpc, state, defaults = _apply(
        _result(), rpc=rpc, state=state, defaults=defaults)
    drift = second["qos_drift"]
    live_applied = (
        "bt_max_peers", "max_upload_limit", "max_download_limit",
        "request_peer_speed_limit",
    )
    expected_rows = collections.Counter(
        (name, APPLIED_EXPECTED[name], 0) for name in APPLIED_NAMES)
    expected_rows.update(collections.Counter(
        (name, APPLIED_EXPECTED[name], 0)
        for _index in range(10) for name in live_applied))
    observed_rows = collections.Counter(
        (row["option"], row["expected"], row["observed"])
        for row in drift["options"])
    assert observed_rows == expected_rows
    assert [row["observed"] for row in drift["options"]] == [0] * 47
    assert all(set(row) == {"option", "expected", "observed"}
               and type(row["expected"]) is int
               and type(row["observed"]) is int
               for row in drift["options"])
    assert drift["blocklist_revision"] == {"expected": 1, "observed": 2}
    assert "gid" not in repr(second)
    assert len(drift["options"]) == server_instructions.QOS_DRIFT_MAX_ROWS
    third, _rpc, _state, _defaults = _apply(
        _result(), rpc=rpc, state=state, defaults=defaults)
    assert third["qos_drift"]["options"] == drift["options"]


@pytest.mark.parametrize("source_state,reason", [
    ("none", None),
    ("applied", None),
    ("lkg", None),
    ("stale_expired", None),
    ("allowlist_expired", None),
    ("rollback_rejected", None),
    ("floor_reset", None),
    ("audience_mismatch", None),
    ("key_rejected", "unknown_key"),
    ("key_rejected", "bad_mac"),
    ("tamper_rejected", None),
    ("verifier_missing", None),
    ("lkg_rejected", None),
    ("lkg_unreadable", None),
    ("oversize", None),
    ("reasserted", None),
    ("instr_unavailable", None),
    ("instr_pending", None),
    ("instr_forbidden", None),
    ("tracker-only", None),
], ids=[
    "none", "applied", "lkg", "stale-expired", "allowlist-expired",
    "rollback-rejected", "floor-reset", "audience-mismatch",
    "key-rejected-unknown-key", "key-rejected-bad-mac",
    "tamper-rejected", "verifier-missing", "lkg-rejected",
    "lkg-unreadable", "oversize", "reasserted", "instr-unavailable",
    "instr-pending", "instr-forbidden", "tracker-only",
])
def test_session_change_suppresses_drift_without_hiding_specific_state(
        source_state, reason):
    assert server_instructions.INSTR_STATES == frozenset({
        "none", "applied", "lkg", "stale_expired", "allowlist_expired",
        "rollback_rejected", "floor_reset", "audience_mismatch",
        "key_rejected", "tamper_rejected", "verifier_missing",
        "lkg_rejected", "lkg_unreadable", "oversize", "reasserted",
        "instr_unavailable", "instr_pending", "instr_forbidden",
        "tracker-only",
    })
    state = {}
    defaults = {}
    rpc = AriaRPC()
    result = _result(state=source_state)
    if reason is not None:
        result["attestation"]["instr_reason"] = reason
    _apply(result, rpc=rpc, state=state,
           defaults=defaults)
    rpc.session = "session-b"
    rpc.global_options["max-overall-upload-limit"] = "1"
    fact, _rpc, _state, _defaults = _apply(
        result, rpc=rpc, state=state,
        defaults=defaults)
    assert "qos_drift" not in fact
    expected = ("reasserted" if source_state in ("none", "applied", "lkg")
                else source_state)
    assert fact["instr_state"] == expected
    if reason is not None:
        assert fact["instr_reason"] == reason


@pytest.mark.parametrize("session", [None, "", 7, {"id": "x"}],
                         ids=["none", "empty", "integer", "object"])
def test_current_session_is_required_and_malformed_values_fail_apply(session):
    rpc = AriaRPC()

    def session_result(method, params):
        if method == "aria2.getSessionInfo":
            rpc.calls.append((method, copy.deepcopy(params)))
            return session
        return AriaRPC.__call__(rpc, method, params)

    with pytest.raises(Exception):
        iris_agent._apply_instruction(
            result=_result(), cfg=_cfg(), state={}, rpc=session_result,
            torrent_defaults={})
    assert [call[0] for call in rpc.calls] == ["aria2.getSessionInfo"]


def test_allow_complement_handles_edges_origin_empty_and_cached_copy_isolation():
    peers = {
        "mode": "allow",
        "allowed": ["0.0.0.0/1", "128.0.0.0/2"],
        "include_origin": False,
        "allowed_expires_at": NOW + 600,
    }
    rpc = AriaRPC()
    _apply(_result(peers=peers), rpc=rpc)
    rules = next(call[1][0] for call in rpc.calls
                 if call[0] == "aria2.setBtPeerBlocklist")
    assert rules == ["192.0.0.0/2", "::/0"]
    rules.append("203.0.113.1")

    second = AriaRPC()
    _apply(_result(peers=peers), rpc=second)
    again = next(call[1][0] for call in second.calls
                 if call[0] == "aria2.setBtPeerBlocklist")
    assert again == ["192.0.0.0/2", "::/0"]

    empty = AriaRPC()
    _apply(_result(peers={
        "mode": "allow", "allowed": [], "include_origin": False,
        "allowed_expires_at": NOW + 600}), rpc=empty)
    assert next(call[1][0] for call in empty.calls
                if call[0] == "aria2.setBtPeerBlocklist") == [
                    "0.0.0.0/0", "::/0"]

    origin = AriaRPC()
    _apply(_result(peers={
        "mode": "allow", "allowed": [], "include_origin": True,
        "allowed_expires_at": NOW + 600}), rpc=origin)
    origin_rules = next(call[1][0] for call in origin.calls
                        if call[0] == "aria2.setBtPeerBlocklist")
    assert "::/0" in origin_rules
    assert not any(ipaddress.ip_address("192.0.2.10") in
                   ipaddress.ip_network(rule) for rule in origin_rules
                   if ":" not in rule)


def test_allow_complement_preserves_lexically_inverted_ipv4_addresses():
    allowed = (ipaddress.ip_address("10.0.0.1"),
               ipaddress.ip_address("2.0.0.1"))
    rpc = AriaRPC()
    _apply(_result(peers={
        "mode": "allow", "allowed": [str(address) for address in allowed],
        "include_origin": False, "allowed_expires_at": NOW + 600,
    }), rpc=rpc)
    rules = next(call[1][0] for call in rpc.calls
                 if call[0] == "aria2.setBtPeerBlocklist")
    blocked = [ipaddress.ip_network(rule) for rule in rules if ":" not in rule]

    assert all(not any(address in network for network in blocked)
               for address in allowed)
    assert any(ipaddress.ip_address("2.0.0.2") in network
               for network in blocked)
    assert "::/0" in rules


def test_deny_uses_only_producer_filtered_rules_and_tracker_only_clears():
    deny = AriaRPC()
    signed = ["198.51.100.7", "203.0.113.0/24"]
    _apply(_result(peers={
        "mode": "deny", "rules": signed, "include_origin": True,
        "allowed_expires_at": NOW + 600}), rpc=deny)
    rules = next(call[1][0] for call in deny.calls
                 if call[0] == "aria2.setBtPeerBlocklist")
    assert rules == signed + ["::/0"]
    assert "192.0.2.10" not in rules

    tracker = AriaRPC()
    _apply(_result(peers={
        "mode": "tracker-only", "include_origin": False,
        "allowed_expires_at": NOW + 600}), rpc=tracker)
    assert next(call[1][0] for call in tracker.calls
                if call[0] == "aria2.setBtPeerBlocklist") == []


@pytest.mark.parametrize("peers", [
    {"mode": "allow", "include_origin": False,
     "allowed_expires_at": NOW + 600},
    {"mode": "allow", "allowed": ["198.51.100.7/24"],
     "include_origin": False, "allowed_expires_at": NOW + 600},
    {"mode": "deny", "rules": ["198.51.100.7-198.51.100.9"],
     "include_origin": False, "allowed_expires_at": NOW + 600},
], ids=["missing-allowed", "noncanonical", "dash-range"])
def test_invalid_rules_never_reach_atomic_blocklist_rpc(peers):
    rpc = AriaRPC()
    result = _result()
    result["effective_peers"] = copy.deepcopy(peers)
    result["effective"]["peers"] = copy.deepcopy(peers)
    with pytest.raises(Exception):
        _apply(result, rpc=rpc)
    assert not any(call[0] == "aria2.setBtPeerBlocklist"
                   for call in rpc.calls)


def test_nonliteral_origin_degrades_only_peer_posture_to_tracker_only():
    rpc = AriaRPC()
    result = _result(peers={
        "mode": "allow", "allowed": ["198.51.100.7"],
        "include_origin": True, "allowed_expires_at": NOW + 600})
    fact, rpc, _state, defaults = _apply(
        result, rpc=rpc, cfg=dict(_cfg(), catalog_url="https://iris.example:8443"))
    assert fact["instr_state"] == "tracker-only"
    assert fact["applied"] == APPLIED_EXPECTED
    assert defaults
    assert next(call[1][0] for call in rpc.calls
                if call[0] == "aria2.setBtPeerBlocklist") == []


def test_future_torrent_defaults_ignore_plaintext_cfg_for_native_and_xr_callers(
        tmp_path, monkeypatch):
    expected = {
        "bt-max-peers": "11",
        "max-upload-limit": "14000",
        "max-download-limit": "15000",
        "bt-request-peer-speed-limit": "51200",
    }
    http_calls = []
    http_urls = []
    order = []
    add_payloads = []
    response_mode = ["normal"]

    class Response:
        def __init__(self, raw):
            self.raw = raw

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, size=None):
            return self.raw if size is None else self.raw[:size]

    def urlopen(request, timeout=10):
        payload = json.loads(request.data.decode("ascii"))
        http_calls.append(copy.deepcopy(payload))
        http_urls.append(request.full_url)
        order.append(payload["method"])
        if response_mode[0] == "malformed":
            return Response(b"{")
        if response_mode[0] == "error":
            return Response(_canonical({
                "jsonrpc": "2.0", "id": payload["id"],
                "error": {"message": "rpc secret must-not-leak"}}))
        method = payload["method"]
        results = {
            "aria2.getSessionInfo": {"sessionId": "session-a"},
            "aria2.getGlobalOption": dict(GLOBAL_EXPECTED),
            "aria2.tellActive": [],
            "aria2.changeGlobalOption": "OK",
            "aria2.setBtPeerBlocklist": dict(
                ruleCount=2, revision=1, disconnectedPeers=0,
                removedPeers=0),
        }
        return Response(_canonical({
            "jsonrpc": "2.0", "id": payload["id"],
            "result": results[method]}))

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(instr, "paths_for", lambda _platform, _cfg: {
        "work_dir": str(tmp_path), "signers": str(tmp_path / "signers"),
        "root_signers": str(tmp_path / "roots")})
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(instr, "SSHVerifier", lambda *_args, **_kwargs:
                        AcceptVerifier())

    def make_add(label, cfg):
        def add_torrent(torrent_path, dest_dir):
            options = iris_agent._aria_torrent_options(
                cfg, dest_dir,
                require_tracker_bearer=(label == "xr-appmgr"))
            payload = {"jsonrpc": "2.0", "id": "a",
                       "method": "aria2.addTorrent",
                       "params": ["token:private", "torrent", [], options]}
            add_payloads.append((label, payload))
            http_calls.append({"method": "wrapped-add", "label": label})
            order.append("wrapped-add")
            return "f" * 16
        return add_torrent

    for platform in ("guestshell", "xr-appmgr"):
        cfg = dict(_cfg(max_peers="999"), device_platform=platform)
        base = _deps(RuntimeCatalog(), None, None, {},
                     aria_add=make_add(platform, cfg))
        wrapped = iris_agent._with_instruction_step(
            base, cfg, str(tmp_path / "iris-agent.conf"), platform)
        assert callable(wrapped.instruction_step)
        assert callable(wrapped.aria_rpc)
        fact, _rpc, _state, defaults = _apply(
            _result(), rpc=wrapped.aria_rpc, cfg=cfg,
            defaults=wrapped.torrent_defaults)
        assert fact["applied"] == APPLIED_EXPECTED
        wrapped.aria_add(str(tmp_path / "image.torrent"), "/stage")
        assert http_calls[-2]["method"] == "aria2.setBtPeerBlocklist"
        assert http_calls[-1] == {"method": "wrapped-add", "label": platform}
        options = add_payloads[-1][1]["params"][3]
        assert {name: options[name] for name in LIVE_NAMES} == expected
        assert options["bt-max-peers"] != "999"
        if platform == "xr-appmgr":
            assert options["header"] == [
                "Authorization: Bearer announce-secret"]
        else:
            assert "header" not in options

    rpc_payloads = [payload for payload in http_calls
                    if payload["method"].startswith("aria2.")]
    assert rpc_payloads
    assert all(payload["params"][0] == "token:rpc-secret"
               for payload in rpc_payloads)
    assert set(http_urls) == {"http://127.0.0.1:6800/jsonrpc"}

    due_catalog = RuntimeCatalog(policy={
        "approved_image_ids": ["image-a"]})
    due_base = _deps(
        due_catalog, None, None, {},
        aria_add=make_add("guestshell", _cfg(max_peers="999")))
    due = iris_agent._with_instruction_step(
        due_base, _cfg(max_peers="999"),
        str(tmp_path / "iris-agent.conf"), "guestshell")
    due = due._replace(instruction_step=InstructionStep(result=_result()))

    def reconcile(*_args):
        order.append("reconcile")

    def stage(_cfg_value, current_deps, *_args, **_kwargs):
        order.append("stage")
        current_deps.aria_add(str(tmp_path / "image.torrent"), "/stage")
        return "downloading"

    monkeypatch.setattr(iris_agent, "_reconcile_set", reconcile)
    monkeypatch.setattr(iris_agent, "_stage_image", stage)
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: 100.0)
    order[:] = []
    iris_agent.run_once(_cfg(max_peers="999"), due, {})
    assert order.index("aria2.setBtPeerBlocklist") < order.index("reconcile")
    assert order.index("reconcile") < order.index("stage")
    assert order.index("stage") < order.index("wrapped-add")

    response_mode[0] = "malformed"
    with pytest.raises(Exception):
        wrapped.aria_rpc("aria2.getSessionInfo", [])
    response_mode[0] = "error"
    with pytest.raises(Exception) as caught:
        wrapped.aria_rpc("aria2.getSessionInfo", [])
    assert "must-not-leak" not in repr(caught.value)


def test_heartbeat_projects_complete_task14_attestation_and_no_private_data():
    attestation = {
        "instr_state": "applied",
        "instr_protocol": 1,
        "instr_epoch": NOW - 1,
        "instr_serial": 7,
        "instr_policy_revision": 4,
        "verify_level": "sig",
        "applied": dict(APPLIED_EXPECTED),
        "blocklist_rules": 2,
        "blocklist_revision": 3,
        "qos_drift": {"options": [{
            "option": "overall_up", "expected": 16_000, "observed": 1}],
            "blocklist_revision": {"expected": 2, "observed": 3}},
        "instruction": {"private": "must-not-leak"},
        "effective": {"private": "must-not-leak"},
        "gid": "f" * 16,
        "rules": ["198.51.100.7"],
        "header": ["Authorization: Bearer must-not-leak"],
    }
    heartbeat = iris_agent._heartbeat_with_instruction(
        {"stage_state": "staging"}, attestation)
    expected = server_instructions.sanitize_instruction_attestation(attestation)
    assert {name: heartbeat[name] for name in expected} == expected
    assert set(heartbeat) == {"stage_state"} | set(expected)
    assert set(heartbeat["applied"]) == set(APPLIED_NAMES)
    public = repr(heartbeat)
    for private in ("must-not-leak", "Authorization", "198.51.100.7",
                    "ffffffffffffffff"):
        assert private not in public


def test_heartbeat_omits_whole_invalid_nested_units():
    invalid = {
        "instr_state": "applied",
        "instr_protocol": 1,
        "instr_epoch": NOW - 1,
        "instr_serial": 7,
        "instr_policy_revision": 4,
        "verify_level": "sig",
        "applied": dict(APPLIED_EXPECTED, overall_up=True),
        "blocklist_rules": 2,
        "qos_drift": {"options": [{
            "option": "overall_up", "expected": 1, "observed": 1}]},
    }
    heartbeat = iris_agent._heartbeat_with_instruction({}, invalid)
    assert heartbeat == {
        "instr_protocol": 1, "instr_state": "applied", "instr_epoch": NOW - 1,
        "instr_serial": 7, "instr_policy_revision": 4, "verify_level": "sig"}


@pytest.mark.parametrize("reason", [
    pytest.param(None, id="absent"),
    pytest.param(False, id="boolean"),
    pytest.param("unsupported", id="unsupported"),
])
def test_heartbeat_omits_malformed_key_rejected_unit_like_server(reason):
    attestation = {"instr_protocol": 1, "instr_state": "key_rejected",
                   "instr_epoch": NOW - 1, "instr_serial": 7,
                   "instr_policy_revision": 4}
    if reason is not None:
        attestation["instr_reason"] = reason

    heartbeat = iris_agent._heartbeat_with_instruction({}, attestation)
    expected = server_instructions.sanitize_instruction_attestation(
        attestation)

    assert heartbeat == expected
    assert "instr_state" not in heartbeat
    assert "instr_reason" not in heartbeat


def test_cadence_first_default_due_skip_reboot_and_regression(
        monkeypatch):
    events = []
    clock = [100.0]
    boot = [BOOT]
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(instr, "boot_id", lambda: boot[0])
    monkeypatch.setattr(iris_agent, "_reconcile_set",
                        lambda *_args: events.append(("reconcile",)))
    catalog = RuntimeCatalog()
    step = InstructionStep(events=events)
    rpc = AriaRPC()
    deps = _deps(catalog, step, rpc, {}, events=events)
    state = {}

    assert iris_agent.run_once(_cfg(), deps, state) == "no-assignment"
    assert len(catalog.events) == 2
    assert catalog.events[0][0] == "policy"
    assert events.count(("reconcile",)) == 1
    valid_poll = copy.deepcopy(state["instructions"]["poll"])
    assert valid_poll == {
        "boot_id": BOOT,
        "monotonic": 100.0,
        "assignment_ids": [],
    }

    clock[0] = 159.0
    catalog.events = []
    events[:] = []
    rpc.calls = []
    assert iris_agent.run_once(_cfg(), deps, state) == "catalog-not-due"
    assert [event[0] for event in catalog.events] == ["heartbeat"]
    assert events == [("step", True)]
    assert [call[0] for call in rpc.calls] == [
        "aria2.getSessionInfo", "aria2.getGlobalOption", "aria2.tellActive",
        "aria2.changeGlobalOption", "aria2.setBtPeerBlocklist",
    ]

    clock[0] = 400.0
    catalog.events = []
    iris_agent.run_once(_cfg(), deps, state)
    assert catalog.events[0][0] == "policy"

    boot[0] = "task16-boot-b"
    clock[0] = 401.0
    catalog.events = []
    iris_agent.run_once(_cfg(), deps, state)
    assert catalog.events[0][0] == "policy"

    boot[0] = "task16-boot-b"
    clock[0] = 10.0
    catalog.events = []
    iris_agent.run_once(_cfg(), deps, state)
    assert catalog.events[0][0] == "policy"

    state["instructions"]["poll"] = dict(valid_poll, unexpected=True)
    clock[0] = 11.0
    catalog.events = []
    iris_agent.run_once(_cfg(), deps, state)
    assert catalog.events[0][0] == "policy"

    fast = InstructionStep(result=_result(control=dict(
        CONTROL, catalog_tick_s=60)))
    fast_deps = _deps(catalog, fast, rpc, {})
    catalog.events = []
    clock[0] = 11.0
    iris_agent.run_once(_cfg(), fast_deps, state)
    assert catalog.events[0][0] == "policy"


def test_due_tick_shares_one_fresh_verification_attempt_map_per_invocation(
        monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(iris_agent, "_reconcile_set", lambda *_args: None)
    result = _result(control=dict(CONTROL, catalog_tick_s=60))

    class IdentityStep:
        def __init__(self):
            self.calls = []

        def __call__(self, **kwargs):
            attempts = kwargs["verification_attempts"]
            self.calls.append((bool(kwargs.get("cache_only")), attempts,
                               dict(attempts)))
            return copy.deepcopy(result)

    catalog = RuntimeCatalog()
    step = IdentityStep()
    deps = _deps(catalog, step, AriaRPC(), {})
    state = {}

    iris_agent.run_once(_cfg(), deps, state)
    clock[0] = 101.0
    iris_agent.run_once(_cfg(), deps, state)

    assert [call[0] for call in step.calls] == [True, False, True, False]
    first_preview, first_due = step.calls[0][1], step.calls[1][1]
    second_preview, second_due = step.calls[2][1], step.calls[3][1]
    assert first_preview is first_due
    assert second_preview is second_due
    assert first_preview is not second_preview
    assert all(snapshot == {} for _cache_only, _raw, snapshot in step.calls)
    assert [event[0] for event in catalog.events].count("policy") == 2


def test_token_refresh_precedes_preview_and_skipped_tick_keeps_assignment(
        monkeypatch):
    events = []
    clock = [100.0]
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(iris_agent, "_reconcile_set",
                        lambda *_args: events.append(("reconcile",)))
    monkeypatch.setattr(iris_agent, "_stage_image",
                        lambda *_args, **_kwargs: events.append(("stage",)) or
                        "downloading")
    policy = {"approved_image_ids": ["image-a", "image-b"]}
    catalog = RuntimeCatalog(policy=policy)
    step = InstructionStep(events=events)
    refreshed = []

    def refresh():
        events.append(("refresh",))
        refreshed.append(True)
        return dict(_cfg(), token_expires_at=str(NOW + 604_800))

    deps = _deps(catalog, step, AriaRPC(), {}, events=events,
                 refresh=refresh)
    state = {}
    cfg = dict(_cfg(), token_expires_at="0")
    iris_agent.run_once(cfg, deps, state)
    assert refreshed == [True]
    assert events.index(("refresh",)) < events.index(("step", True))
    poll = state["instructions"]["poll"]
    assert set(poll) == {"boot_id", "monotonic", "assignment_ids"}
    assert poll["boot_id"] == BOOT and 1 <= len(poll["boot_id"]) <= 128
    assert type(poll["monotonic"]) in (int, float)
    assert poll["monotonic"] >= 0
    assert poll["assignment_ids"] == ["image-a", "image-b"]
    assert len(poll["assignment_ids"]) <= 10
    assert all(isinstance(value, str) and 1 <= len(value) <= 128
               for value in poll["assignment_ids"])
    assert "catalog-token" not in repr(poll)

    clock[0] = 159.0
    catalog.events = []
    events[:] = []
    assert iris_agent.run_once(_cfg(), deps, state) == "catalog-not-due"
    assert not any(event[0] in ("policy", "image") for event in catalog.events)
    assert not any(event[0] in ("reconcile", "stage", "add")
                   for event in events)
    assert catalog.heartbeats[-1]["current_image_id"] == "image-a"
    assert catalog.heartbeats[-1]["stage_state"] != "unassigned"


@pytest.mark.parametrize("fallback", [False, True],
                         ids=["skipped", "policy-fallback"])
def test_saved_multi_assignment_heartbeat_requires_every_image_staged(
        fallback, monkeypatch):
    clock = [400.0 if fallback else 159.0]
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(
        iris_agent, "_reconcile_set",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("saved-set heartbeat reconciled assignments")))
    catalog = RuntimeCatalog()
    if fallback:
        catalog.policy_error = OSError("offline")
    deps = _deps(catalog, InstructionStep(), AriaRPC(), {})
    state = {
        "schema_version": iris_agent._STATE_SCHEMA,
        "instructions": {"poll": {
            "boot_id": BOOT, "monotonic": 100.0,
            "assignment_ids": ["image-a", "image-b"],
        }},
        "image-a": {"done": True, "copied": True},
        "image-b": "truthy-malformed-entry",
    }

    result = iris_agent.run_once(_cfg(), deps, state)

    assert result == ("catalog-unavailable" if fallback
                      else "catalog-not-due")
    assert len(catalog.heartbeats) == 1
    assert catalog.heartbeats[0]["stage_state"] == "staging"
    assert catalog.heartbeats[0]["staged_image_ids"] == ["image-a"]


@pytest.mark.parametrize("bad", [False, 0, "", [], {}],
                         ids=["false", "zero", "empty-string",
                              "empty-list", "empty-object"])
def test_falsey_malformed_singular_assignment_is_retryable_policy_failure(
        bad, monkeypatch):
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: 400.0)
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    reconciles = []
    monkeypatch.setattr(iris_agent, "_reconcile_set",
                        lambda *_args: reconciles.append(True))
    marker = {
        "boot_id": BOOT, "monotonic": 100.0,
        "assignment_ids": ["saved-image"],
    }

    for policy in ({"approved_image_id": copy.deepcopy(bad)},
                   {"approved_image_ids": [],
                    "approved_image_id": copy.deepcopy(bad)}):
        catalog = RuntimeCatalog(policy=policy)
        deps = _deps(catalog, InstructionStep(), AriaRPC(), {})
        state = {
            "schema_version": iris_agent._STATE_SCHEMA,
            "instructions": {"poll": copy.deepcopy(marker)},
        }
        reconciles[:] = []

        result = iris_agent.run_once(_cfg(), deps, state)

        assert result == "catalog-unavailable"
        assert state["instructions"]["poll"] == marker
        assert reconciles == []
        assert len(catalog.heartbeats) == 1


def test_missing_and_none_singular_are_unassigned_and_empty_plural_falls_back():
    assert iris_agent._policy_assignment_ids({}) == []
    assert iris_agent._policy_assignment_ids({
        "approved_image_id": None}) == []
    assert iris_agent._policy_assignment_ids({
        "approved_image_ids": [], "approved_image_id": None}) == []
    assert iris_agent._policy_assignment_ids({
        "approved_image_ids": [],
        "approved_image_id": "image-a"}) == ["image-a"]


def test_huge_integer_poll_monotonic_is_malformed_and_due_without_crash(
        monkeypatch):
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(iris_agent, "_reconcile_set", lambda *_args: None)
    catalog = RuntimeCatalog()
    deps = _deps(catalog, InstructionStep(), AriaRPC(), {})
    state = {
        "schema_version": iris_agent._STATE_SCHEMA,
        "instructions": {"poll": {
            "boot_id": BOOT, "monotonic": 10 ** 1000,
            "assignment_ids": [],
        }},
    }

    result = iris_agent.run_once(_cfg(), deps, state)

    assert result == "no-assignment"
    assert catalog.events[0] == ("policy", DEVICE_ID)
    assert state["instructions"]["poll"] == {
        "boot_id": BOOT, "monotonic": 100.0, "assignment_ids": []}


@pytest.mark.parametrize("hint,heartbeat_date,opens", [
    ({"instr_rev": {"epoch": NOW - 1, "instr_serial": 8}}, NOW, True),
    ({"keylist_seq": 2}, NOW, True),
    ({"instr_rev": {"epoch": NOW - 1, "instr_serial": True}}, NOW, False),
    ({"instr_rev": {"epoch": NOW - 1, "instr_serial": 8}}, None, False),
], ids=["instruction", "keylist", "invalid", "missing-date"])
def test_authenticated_heartbeat_hint_reopens_cadence_gate(
        hint, heartbeat_date, opens, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(iris_agent, "_reconcile_set", lambda *_args: None)
    response = dict(hint, arbitrary={"private": "must-not-persist"})
    catalog = RuntimeCatalog(heartbeat_response=response)
    catalog.heartbeat_authenticated_date = heartbeat_date
    step = InstructionStep()
    deps = _deps(catalog, step, AriaRPC(), {})
    state = {"instructions": {
        "accepted_epoch": NOW - 1, "accepted_serial": 7,
        "keylist_seq": 1,
    }}
    iris_agent.run_once(_cfg(), deps, state)
    allowed = frozenset(("instr_rev", "keylist_seq"))
    caches = [value for value in state["instructions"].values()
              if isinstance(value, dict) and value
              and set(value).issubset(allowed)]
    if opens:
        assert caches == [hint]
        cached = caches[0]
        assert set(cached).issubset(allowed)
        if "instr_rev" in cached:
            assert set(cached["instr_rev"]) == {"epoch", "instr_serial"}
            assert all(type(value) is int and 0 <= value <= 2 ** 63 - 1
                       for value in cached["instr_rev"].values())
        if "keylist_seq" in cached:
            assert type(cached["keylist_seq"]) is int
            assert 1 <= cached["keylist_seq"] <= 2 ** 63 - 1
    else:
        assert caches == []
    assert "must-not-persist" not in repr(state)
    clock[0] = 159.0
    catalog.events = []
    iris_agent.run_once(_cfg(), deps, state)
    assert catalog.events[0][0] == ("policy" if opens else "heartbeat")


@pytest.mark.parametrize("failure", [
    OSError("offline"), [], {"approved_image_ids": "bad"},
], ids=["transport", "non-object", "malformed"])
def test_due_policy_failure_reasserts_heartbeats_and_keeps_marker_retryable(
        failure, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    reconciles = []
    monkeypatch.setattr(iris_agent, "_reconcile_set",
                        lambda *_args: reconciles.append(True))
    catalog = RuntimeCatalog()
    step = InstructionStep()
    rpc = AriaRPC()
    deps = _deps(catalog, step, rpc, {})
    state = {}
    iris_agent.run_once(_cfg(), deps, state)
    marker = copy.deepcopy(state["instructions"]["poll"])
    state["instructions"].update({
        "accepted_epoch": NOW - 1,
        "accepted_serial": 7,
        "lower_hint": {"epoch": NOW - 2, "instr_serial": 6},
        "lower_hint_count": 9,
        "pending_reset": {"epoch": NOW - 2, "instr_serial": 6},
    })
    hint_calls = []
    original_note_hint = instr.note_hint

    def observed_hint(current_state, hint, authenticated=True):
        hint_calls.append((copy.deepcopy(hint), authenticated))
        return original_note_hint(current_state, hint, authenticated)

    monkeypatch.setattr(instr, "note_hint", observed_hint)

    clock[0] = 400.0
    catalog.events = []
    rpc.calls = []
    step.calls = []
    catalog.policy_error = failure if isinstance(failure, Exception) else None
    catalog.policy = failure if not isinstance(failure, Exception) else {}
    reconciles[:] = []
    result = iris_agent.run_once(_cfg(), deps, state)
    assert result == "catalog-unavailable"
    assert reconciles == []
    assert any(event[0] == "heartbeat" for event in catalog.events)
    assert [call.get("cache_only") for call in step.calls] == [True]
    assert [call[0] for call in rpc.calls] == [
        "aria2.getSessionInfo", "aria2.getGlobalOption", "aria2.tellActive",
        "aria2.changeGlobalOption", "aria2.setBtPeerBlocklist",
    ]
    assert state["instructions"].get("poll") == marker
    for name in ("lower_hint", "lower_hint_count", "pending_reset"):
        assert name not in state["instructions"]
    assert hint_calls == [(None, False)]

    catalog.policy_error = None
    catalog.policy = {"approved_image_id": None}
    catalog.events = []
    clock[0] = 401.0
    iris_agent.run_once(_cfg(), deps, state)
    assert catalog.events[0][0] == "policy"


def test_apply_failure_wins_over_policy_failure_and_skips_all_staging(
        monkeypatch):
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: 400.0)
    reconciles = []
    monkeypatch.setattr(iris_agent, "_reconcile_set",
                        lambda *_args: reconciles.append(True))
    catalog = RuntimeCatalog()
    catalog.policy_error = OSError("catalog detail must-not-leak")
    step = InstructionStep()
    rpc = AriaRPC()
    rpc.fail_method = "aria2.changeGlobalOption"
    events = []
    deps = _deps(catalog, step, rpc, {}, events=events)
    result = iris_agent.run_once(_cfg(), deps, {"instructions": {}})
    assert result == "instruction-apply-unavailable"
    assert reconciles == []
    assert any(event[0] == "heartbeat" for event in catalog.events)
    assert not any(event[0] == "add" for event in events)
    emitted = repr([event for event in events if event[0] == "emit"])
    assert "must-not-leak" not in emitted
    heartbeat = catalog.heartbeats[-1]
    assert heartbeat["instr_state"] == "instr_unavailable"
    assert "applied" not in heartbeat
    assert "blocklist_rules" not in heartbeat


@pytest.mark.parametrize("attestation", [None, [], {}, {"instr_state": "instr_pending"},
                                          {"instr_protocol": "private-token"}])
def test_task19_heartbeat_protocol_is_unconditional_and_preserves_ios_version(attestation):
    payload = {"version": "17.18.03", "stage_state": "error"}
    heartbeat = iris_agent._heartbeat_with_instruction(payload, attestation)
    assert type(heartbeat["instr_protocol"]) is int
    assert heartbeat["instr_protocol"] == 1
    assert heartbeat["version"] == "17.18.03"
    assert payload == {"version": "17.18.03", "stage_state": "error"}
    assert "private-token" not in repr(heartbeat)


@pytest.mark.parametrize("field", ["instr_epoch", "instr_serial", "instr_policy_revision"])
def test_task19_heartbeat_accepted_identity_is_complete_or_absent(field):
    identity = {"instr_epoch": NOW - 1, "instr_serial": 7, "instr_policy_revision": 4}
    assert iris_agent._heartbeat_with_instruction({}, identity) == dict(
        identity, instr_protocol=1)
    for invalid in (None, False, True, -1, 2 ** 63, 1.0, "1", {}, []):
        assert iris_agent._heartbeat_with_instruction(
            {}, dict(identity, **{field: invalid})) == {"instr_protocol": 1}
    partial = dict(identity)
    del partial[field]
    assert iris_agent._heartbeat_with_instruction({}, partial) == {"instr_protocol": 1}
    assert iris_agent._heartbeat_with_instruction(
        {}, {"instr_serial": 7}) == {"instr_protocol": 1}


@pytest.mark.parametrize("value", [True, False, None, 0, 1, 3, "true", [], {}])
def test_task19_heartbeat_pointer_skew_boolean_only(value):
    supplied = {"pointer_skew": value, "pointer_skew_count": 3,
                "fetched_pointer": {"epoch": 11, "instr_serial": 100}}
    expected = {"instr_protocol": 1}
    if type(value) is bool:
        expected["pointer_skew"] = value
    assert iris_agent._heartbeat_with_instruction({}, supplied) == expected


@pytest.mark.parametrize("path", ["ordinary", "cached", "pending", "step-error",
                                  "preview-error", "rpc-error", "cached-rpc-error",
                                  "policy-error", "policy-rpc-error", "no-step"])
def test_task19_heartbeat_protocol_pointer_and_identity_on_runtime_paths(path, monkeypatch):
    monkeypatch.setattr(instr, "boot_id", lambda: BOOT)
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: 100.0)
    catalog, rpc = RuntimeCatalog(), AriaRPC()
    result = _result()
    result["attestation"]["pointer_skew"] = True
    state = {"instructions": {"pointer_skew_count": 3}}
    if path in ("cached", "cached-rpc-error"):
        state["instructions"]["poll"] = {
            "boot_id": BOOT, "monotonic": 99.0, "assignment_ids": []}
    if path == "pending":
        result = {"instruction": None, "effective": None,
                  "attestation": {"instr_state": "instr_pending", "pointer_skew": True}}
    def step(**kwargs):
        if ((path == "step-error" and not kwargs.get("cache_only"))
                or (path == "preview-error" and kwargs.get("cache_only"))):
            raise OSError("private-runtime-detail")
        return copy.deepcopy(result)
    if "rpc-error" in path:
        rpc.fail_method = "aria2.setBtPeerBlocklist"
    if path in ("policy-error", "policy-rpc-error", "preview-error"):
        catalog.policy_error = OSError("private-runtime-detail")
    deps = _deps(catalog, None if path == "no-step" else step, rpc, {})
    iris_agent.run_once(_cfg(), deps, state)
    assert len(catalog.heartbeats) == 1
    heartbeat = catalog.heartbeats[0]
    assert heartbeat["instr_protocol"] == 1
    assert type(heartbeat["instr_protocol"]) is int
    assert heartbeat["version"] == "17.18.03"
    if path != "no-step":
        assert heartbeat["pointer_skew"] is True
    fields = {"instr_epoch", "instr_serial", "instr_policy_revision"}
    if path in ("ordinary", "cached", "policy-error"):
        assert {name: heartbeat[name] for name in fields} == {
            "instr_epoch": result["instruction"]["header"]["epoch"],
            "instr_serial": 7, "instr_policy_revision": 4}
    else:
        assert not fields.intersection(heartbeat)
    assert "pointer_skew_count" not in heartbeat
    assert "private-runtime-detail" not in repr(heartbeat)
