# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 17 contracts for plaintext-knob demotion and mechanical cadence."""

import copy
import json
import sys

import pytest

import instr
import iris_agent
import telemetry_report
from device.agent.tests import test_instr_apply as task16
from device.agent.tests import test_instr_verify as verify_vectors


def test_max_peers_compatibility_values_are_value_independent_after_reload(
        monkeypatch):
    messages = []
    for value in ("1", "10", "1000", "1001", "65535"):
        events = []
        clock = [100.0]
        monkeypatch.setattr(iris_agent.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(instr, "boot_id", lambda: task16.BOOT)
        monkeypatch.setattr(iris_agent, "_reconcile_set", lambda *_args: None)
        catalog = task16.RuntimeCatalog()
        rpc = task16.AriaRPC()
        defaults = {}
        deps = task16._deps(
            catalog, task16.InstructionStep(), rpc, defaults, events=events)
        state = {}

        assert iris_agent.run_once(
            task16._cfg(max_peers=value), deps, state,
            tick_seconds=60) == "no-assignment"
        state = json.loads(json.dumps(state))
        clock[0] = 101.0
        assert iris_agent.run_once(
            task16._cfg(max_peers=value), deps, state,
            tick_seconds=60) == "catalog-not-due"

        writes = [params[0] for method, params in rpc.calls
                  if method == "aria2.changeGlobalOption"]
        assert writes == [task16.GLOBAL_EXPECTED, task16.GLOBAL_EXPECTED]
        assert defaults == {name: task16.GLOBAL_EXPECTED[name]
                            for name in task16.LIVE_NAMES}
        notices = [event for event in events
                   if len(event) == 3 and event[:2] ==
                   ("emit", "MAX-PEERS-IGNORED")]
        assert len(notices) == 1
        messages.append(notices[0][2])
        marker_values = [marker for name, marker in state["instructions"].items()
                         if name not in ("poll", "heartbeat_hint")
                         and type(marker) is bool]
        assert len(marker_values) == 1
        assert marker_values[0] is True
        assert all(item is not True for key, item in state.items()
                   if key != "instructions")
    assert len(set(messages)) == 1


def test_max_peers_notice_failure_never_suppresses_the_heartbeat(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(instr, "boot_id", lambda: task16.BOOT)
    monkeypatch.setattr(iris_agent, "_reconcile_set", lambda *_args: None)
    catalog = task16.RuntimeCatalog()
    deps = task16._deps(
        catalog, task16.InstructionStep(), task16.AriaRPC(), {})

    state = {}
    attempts = []
    snapshots = []

    def emit(tag, _message):
        attempts.append(tag)
        if tag == "MAX-PEERS-IGNORED":
            snapshots.append(json.loads(json.dumps(state)))
            raise OSError("syslog unavailable")

    deps = deps._replace(emit=emit)
    assert iris_agent.run_once(
        task16._cfg(max_peers="65535"), deps, state,
        tick_seconds=60) == "no-assignment"
    state = json.loads(json.dumps(state))
    clock[0] = 101.0
    assert iris_agent.run_once(
        task16._cfg(max_peers="65535"), deps, state,
        tick_seconds=60) == "catalog-not-due"
    assert len([tag for tag in attempts if tag == "MAX-PEERS-IGNORED"]) == 1
    assert len(snapshots) == 1
    marker_values = [item for key, item in snapshots[0]["instructions"].items()
                     if key not in ("poll", "heartbeat_hint")
                     and type(item) is bool]
    assert marker_values == [True]
    assert [event[0] for event in catalog.events] == [
        "policy", "heartbeat", "heartbeat"]


@pytest.mark.parametrize("response,expected", [
    ({"stream_every": 7, "stream_pause": True},
     {"every": 7, "pause": True}),
    ({}, {"every": 1, "pause": False}),
    ({"stream_every": "bad", "stream_pause": "yes"},
     {"every": 1, "pause": False}),
    ("captive-portal", {"every": 1, "pause": False}),
    (None, None),
])
def test_cadence_only_heartbeat_directives_are_contained(
        monkeypatch, response, expected):
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: 159.0)
    monkeypatch.setattr(iris_agent.time, "time", lambda: 1234.0)
    monkeypatch.setattr(instr, "boot_id", lambda: task16.BOOT)
    monkeypatch.setattr(iris_agent, "_reconcile_set", lambda *_args: None)
    catalog = task16.RuntimeCatalog(heartbeat_response=response)
    deps = task16._deps(
        catalog, task16.InstructionStep(), task16.AriaRPC(), {})
    state = {"instructions": {"poll": {
        "boot_id": task16.BOOT,
        "monotonic": 100.0,
        "assignment_ids": [],
    }}, "stream_directives": {
        "every": 9, "pause": True, "received_ts": 1000.0}}

    assert iris_agent.run_once(
        task16._cfg(), deps, state,
        tick_seconds=60) == "catalog-not-due"
    assert [event[0] for event in catalog.events] == ["heartbeat"]
    if expected is None:
        assert state["stream_directives"] == {
            "every": 9, "pause": True, "received_ts": 1000.0}
    else:
        assert state["stream_directives"] == dict(
            expected, received_ts=1234.0)
    assert "tick_seconds" not in repr(state)
    assert "mechanical_tick" not in repr(state)


class _AssignedRuntimeCatalog(task16.RuntimeCatalog):
    def __init__(self):
        super().__init__(policy={"approved_image_id": "img-1"})
        self.image = {"id": "img-1", "filename": "img-1.bin",
                      "size": 64, "sha256": "a" * 64}
        self.torrents = []

    def get_image(self, image_id):
        self.events.append(("image", image_id))
        return copy.deepcopy(self.image)

    def download_torrent(self, image_id, dest):
        self.torrents.append((image_id, dest))


@pytest.mark.parametrize("tick_seconds", [1, 60, 300, 900])
def test_real_staging_observation_and_replay_receive_mechanical_tick(
        monkeypatch, tmp_path, tick_seconds):
    catalog = _AssignedRuntimeCatalog()
    deps = task16._deps(
        catalog, task16.InstructionStep(), task16.AriaRPC(), {})
    stage_path = str(tmp_path / "img-1.bin")
    deps = deps._replace(
        file_size=lambda path: 64 if path == stage_path else None,
        aria_stats=lambda _path: {
            "gid": "gid-1", "completedLength": "64",
            "totalLength": "64", "downloadSpeed": "1",
            "uploadSpeed": "1", "connections": "1"},
        aria_peers=lambda _path: [],
        verify=lambda _path, _sha: True)
    cfg = task16._cfg()
    cfg.update(stage_dir=str(tmp_path), telemetry="on",
               telemetry_stream="on")
    observed = {"observation": [], "active": [], "sample": [],
                "replay": []}
    original_observation = iris_agent._build_observation
    original_active = telemetry_report.active_directives
    original_sample = telemetry_report.should_sample
    original_tick = iris_agent._telemetry_tick

    def observation(*args, **kwargs):
        observed["observation"].append(kwargs.get(
            "tick_seconds", kwargs.get("mechanical_tick_s",
                                        args[7] if len(args) > 7 else None)))
        return original_observation(*args, **kwargs)

    def sample(state, tele, tier, now, *args, **kwargs):
        observed["sample"].append(kwargs.get(
            "tick_seconds", kwargs.get("mechanical_tick_s",
                                        args[0] if args else None)))
        return original_sample(state, tele, tier, now, *args, **kwargs)

    def active(state, now, *args, **kwargs):
        observed["active"].append(kwargs.get(
            "tick_seconds", kwargs.get("mechanical_tick_s",
                                        args[0] if args else None)))
        return original_active(state, now, *args, **kwargs)

    def replay_tick(*args, **kwargs):
        observed["replay"].append(kwargs.get(
            "tick_seconds", kwargs.get("mechanical_tick_s",
                                        args[9] if len(args) > 9 else None)))
        return original_tick(*args, **kwargs)

    original_backoff = telemetry_report.next_backoff_ts

    def backoff(attempts, now, *args, **kwargs):
        observed["backoff"].append(kwargs.get(
            "tick_seconds", kwargs.get("mechanical_tick_s",
                                        args[0] if args else None)))
        return original_backoff(attempts, now, *args, **kwargs)

    observed["backoff"] = []
    monkeypatch.setattr(iris_agent, "_build_observation", observation)
    monkeypatch.setattr(telemetry_report, "active_directives", active)
    monkeypatch.setattr(telemetry_report, "should_sample", sample)
    monkeypatch.setattr(telemetry_report, "next_backoff_ts", backoff)
    monkeypatch.setattr(iris_agent, "_telemetry_tick", replay_tick)
    monkeypatch.setattr(iris_agent.time, "time", lambda: 1000.0)
    monkeypatch.setattr(iris_agent, "_reconcile_set", lambda *_args: None)
    monkeypatch.setattr(instr, "boot_id", lambda: task16.BOOT)

    assert iris_agent.run_once(
        cfg, deps, {"link": {"fail_streak": 2}},
        tick_seconds=tick_seconds) == "complete"
    assert observed["observation"] == [tick_seconds]
    assert observed["active"]
    assert all(value == tick_seconds for value in observed["active"])
    assert observed["sample"] == [tick_seconds]
    assert observed["replay"] == [tick_seconds]
    assert observed["backoff"] == [tick_seconds]


def test_signed_catalog_tick_is_separate_from_mechanical_tick(
        monkeypatch, tmp_path):
    clock = [100.0]
    monkeypatch.setattr(iris_agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(instr, "boot_id", lambda: task16.BOOT)
    monkeypatch.setattr(iris_agent, "_reconcile_set", lambda *_args: None)
    catalog = _AssignedRuntimeCatalog()
    result = task16._result(control=dict(
        task16.CONTROL, catalog_tick_s=300))
    deps = task16._deps(
        catalog, task16.InstructionStep(result=result), task16.AriaRPC(), {})
    stage_path = str(tmp_path / "img-1.bin")
    deps = deps._replace(
        file_size=lambda path: 64 if path == stage_path else None,
        verify=lambda _path, _sha: True)
    cfg = task16._cfg()
    cfg["stage_dir"] = str(tmp_path)
    state = {}
    assert iris_agent.run_once(
        cfg, deps, state, tick_seconds=60) == "complete"
    clock[0] = 101.0
    assert iris_agent.run_once(
        cfg, deps, state, tick_seconds=60) == "catalog-not-due"
    clock[0] = 400.0
    assert iris_agent.run_once(
        cfg, deps, state, tick_seconds=60) == "complete"
    writes = [params[0] for method, params in deps.aria_rpc.calls
              if method == "aria2.changeGlobalOption"]
    assert writes == [task16.GLOBAL_EXPECTED] * 3
    assert [event[0] for event in catalog.events].count("heartbeat") == 3
    assert [event[0] for event in catalog.events].count("policy") == 2
    assert [event[0] for event in catalog.events].count("image") == 2


@pytest.mark.parametrize("platform,raw,expected", [
    ("iox", None, 60), ("iox", "1", 1), ("iox", "60", 60),
    ("iox", "300", 300), ("xr-appmgr", "900", 900),
    ("xr-appmgr", "86400", 86400), ("iox", "0", 60),
    ("xr-appmgr", "86401", 60), ("iox", "invalid", 60),
    ("iox", "", 60), ("iox", "60.5", 60),
    (None, "300", 60),
])
def test_main_passes_platform_scoped_mechanical_tick_to_run_once(
        platform, raw, expected, tmp_path, monkeypatch):
    conf = tmp_path / "iris-agent.conf"
    state_path = tmp_path / "iris-agent.state"
    monkeypatch.setenv("IRIS_AGENT_CONF", str(conf))
    monkeypatch.setenv("IRIS_AGENT_STATE", str(state_path))
    if raw is None:
        monkeypatch.delenv("IRIS_TICK_SECONDS", raising=False)
    else:
        monkeypatch.setenv("IRIS_TICK_SECONDS", raw)
    monkeypatch.setattr(sys, "argv", ["iris_agent.py", "--once"])
    cfg = {"device_id": "device-1", "stage_dir": str(tmp_path)}
    if platform is not None:
        cfg["device_platform"] = platform
    monkeypatch.setattr(
        iris_agent.agent_config, "load", lambda _path: dict(cfg))
    sentinel = object()
    monkeypatch.setattr(
        iris_agent, "build_deps", lambda *_args, **_kwargs: sentinel)
    monkeypatch.setattr(
        iris_agent, "_atomic_write_state", lambda *_args, **_kwargs: None)
    observed = []

    def capture(_cfg, deps, _state, *args, **kwargs):
        value = args[0] if args else kwargs.get(
            "tick_seconds", kwargs.get("mechanical_tick_s"))
        observed.append((deps, value))
        return "ok"

    monkeypatch.setattr(iris_agent, "run_once", capture)
    iris_agent.main()
    assert observed == [(sentinel, expected)]


class _InstructionCatalog:
    def __init__(self, raw):
        self.raw = raw

    def get_instructions(self, _device_id, etag=None):
        return 200, self.raw, {"Date": "Mon, 07 Sep 2026 12:00:00 GMT"}

    def get_instruction_keylist(self, *_args, **_kwargs):
        return 503, b"", {}


@pytest.mark.parametrize("name", ["instr_key", "instr_key_prev"])
def test_edited_instruction_keys_only_reject_trust_and_fall_back(
        tmp_path, name):
    cfg = verify_vectors.config()
    cfg[name] = "{broken"
    events = []
    result = instr.run_instruction_step(
        cfg, {}, _InstructionCatalog(verify_vectors.make_envelope()),
        {"instr_rev": {"epoch": verify_vectors.NOW - 1,
                        "instr_serial": 7}}, verify_vectors.NOW,
        "guestshell", str(tmp_path), verify_vectors.BOOT, 10.0,
        verify_vectors.AcceptVerifier(), lambda _cfg: None,
        lambda *args: events.append(args))
    assert result["attestation"]["instr_state"] == "key_rejected"
    assert iris_agent._instruction_values(result)[0] == task16.FIXED_QOS
    assert iris_agent._instruction_values(result)[1] == {
        "catalog_tick_s": 60, "telemetry_every_ticks": 1,
        "telemetry_pause": False}
    fact, rpc, _state, defaults = task16._apply(
        result, cfg=task16._cfg(max_peers="65535"))
    assert next(params[0] for method, params in rpc.calls
                if method == "aria2.changeGlobalOption") == task16.FIXED_GLOBAL
    assert fact["applied"] == {
        "bt_max_peers": 10, "max_upload_limit": 0,
        "max_download_limit": 0, "overall_up": 0, "overall_down": 0,
        "request_peer_speed_limit": 51200, "max_concurrent": 100,
    }
    assert defaults == {key: task16.FIXED_GLOBAL[key]
                        for key in task16.LIVE_NAMES}
    assert next(params[0] for method, params in rpc.calls
                if method == "aria2.setBtPeerBlocklist") == []
    assert "broken" not in repr((result["attestation"], events))


def test_stored_lkg_key_edit_is_unreadable_and_apply_is_safe(tmp_path):
    cfg = verify_vectors.config()
    verified = verify_vectors.verify(instr, cfg=cfg)
    instr.LKGStore(
        str(tmp_path), cfg, lambda _updated: None,
        verify_vectors.AcceptVerifier()).store(
            verified, verified["device"], {})
    edited = copy.deepcopy(cfg)
    edited["lkg_key"] = "{broken"
    result = instr.run_instruction_step(
        edited, {}, object(), {}, None, "guestshell", str(tmp_path),
        verify_vectors.BOOT, 10.0, verify_vectors.AcceptVerifier(),
        lambda _cfg: None, lambda *args: None, cache_only=True,
        verification_attempts={})
    assert result["attestation"]["instr_state"] == "lkg_unreadable"
    assert result["effective_peers"] == {
        "mode": "tracker-only", "include_origin": False}
    assert iris_agent._instruction_values(result)[0] == task16.FIXED_QOS
    assert iris_agent._instruction_values(result)[1] == {
        "catalog_tick_s": 60, "telemetry_every_ticks": 1,
        "telemetry_pause": False}
    fact, rpc, _state, defaults = task16._apply(
        result, cfg=task16._cfg(max_peers="65535"))
    assert next(params[0] for method, params in rpc.calls
                if method == "aria2.changeGlobalOption") == task16.FIXED_GLOBAL
    assert fact["applied"]["bt_max_peers"] == 10
    assert fact["applied"]["max_concurrent"] == 100
    assert defaults == {key: task16.FIXED_GLOBAL[key]
                        for key in task16.LIVE_NAMES}


@pytest.mark.parametrize("name", ["announce_token", "rpc_secret", "catalog_ca"])
def test_valid_custody_inputs_never_supply_policy_values(tmp_path, name):
    secret = (str(tmp_path / "catalog-ca.pem") if name == "catalog_ca"
              else "custody-secret-%s" % name)
    cfg = verify_vectors.config()
    cfg[name] = secret
    role = verify_vectors.role_value()
    role["qos"] = dict(task16.QOS)
    role["control"] = dict(task16.CONTROL)
    events = []
    result = instr.run_instruction_step(
        cfg, {}, _InstructionCatalog(verify_vectors.make_envelope(role=role)),
        {"instr_rev": {"epoch": verify_vectors.NOW - 1,
                        "instr_serial": 7}}, verify_vectors.NOW,
        "guestshell", str(tmp_path), verify_vectors.BOOT, 10.0,
        verify_vectors.AcceptVerifier(), lambda _cfg: None,
        lambda *args: events.append(args))
    assert result["attestation"]["instr_state"] == "applied"
    assert result["effective_peers"] == verify_vectors.part_value()["peers"]
    apply_cfg = task16._cfg(max_peers="65535")
    apply_cfg[name] = secret
    fact, rpc, _state, defaults = task16._apply(result, cfg=apply_cfg)
    assert next(params[0] for method, params in rpc.calls
                if method == "aria2.changeGlobalOption") == task16.GLOBAL_EXPECTED
    assert fact["applied"] == task16.APPLIED_EXPECTED
    assert defaults == {name: task16.GLOBAL_EXPECTED[name]
                        for name in task16.LIVE_NAMES}
    assert iris_agent._instruction_values(result) == (
        task16.QOS, task16.CONTROL)
    public = repr((result["attestation"], fact, defaults, events))
    assert secret not in public
