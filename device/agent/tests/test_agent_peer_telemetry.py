# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import copy
import fcntl
import json
from types import SimpleNamespace

import pytest

import instr
import iris_agent


@pytest.fixture
def runtime():
    cfg = {"device_id": "router", "stage_dir": "/stage", "telemetry": "on",
           "telemetry_stream": "on"}
    state = {"stream_directives": {"every": 1, "pause": False, "received_ts": 1000},
             "image": {"tele": {"transfer_id": "a" * 32, "sample_seq": 4,
                 "stream_last_ts": 1000, "report_v2": {"frozen": True},
                 "live_context": {"stage": "/stage/os.bin", "phase": "downloading",
                                  "monotonic": 900, "boot_id": "boot"}}}}
    control = {"peer_telemetry_interval_s": 10}
    preview = {"attestation": {"instr_state": "lkg"}, "instruction": {
        "role": {"qos": {}, "control": dict(iris_agent._FIXED_CONTROL)},
        "device": {"control_override": control}}}
    events = []

    def step(**kwargs):
        assert kwargs["cache_only"] is True and kwargs["hints"] == {}
        events.append("verify")
        return preview

    def stats(_path):
        events.append("stats")
        return {"status": "active", "downloadSpeed": "123", "uploadSpeed": "0",
                "completedLength": "50", "totalLength": "100", "connections": "1"}

    deps = SimpleNamespace(instruction_step=step, aria_stats=stats,
        aria_peers=lambda _path: [{"ip": "192.0.2.1", "port": 6881, "receive_bps": 123}],
        aria_session=lambda: "session", checkpoint=lambda state: events.append("checkpoint"),
        emit=lambda *args: None,
        catalog=SimpleNamespace(post_live_observation=lambda did, obs: events.append(copy.deepcopy(obs))))
    return cfg, state, deps, control, preview, events


def tick(runtime, now=1010, mono=910, boot="boot"):
    cfg, state, deps, *_ = runtime
    return iris_agent.peer_telemetry_once(cfg, deps, state, now, mono, boot)


def test_acceleration_only_reads_aria_and_posts_after_checkpoint(runtime):
    assert tick(runtime)
    cfg, state, deps, control, preview, events = runtime
    assert events[:3] == ["verify", "stats", "checkpoint"]
    assert events[-1]["sample_seq"] == 5
    assert events[-1]["peer_connections"][0]["receive_bps"] == 123
    assert state["image"]["tele"]["report_v2"] == {"frozen": True}
    assert state["image"]["tele"]["live_context"]["monotonic"] == 900
    assert state["image"]["tele"]["stream_last_ts"] == 1000
    assert state["image"]["tele"]["peer_stream_last_ts"] == 1010
    # No control-plane, file-copy or policy-download dependency even exists.
    assert not hasattr(deps, "copy_to_root")


def test_fast_sampling_does_not_starve_normal_heartbeat_observation(runtime):
    assert tick(runtime, now=1059, mono=959)
    cfg, state, deps = runtime[:3]
    observation, _ = iris_agent._build_observation(cfg, deps, state,
        "image", "/stage/os.bin", "downloading", 1060)
    assert observation["obs_state"] == "observed"
    assert state["image"]["tele"]["peer_stream_last_ts"] == 1059
    assert state["image"]["tele"]["stream_last_ts"] == 1060


@pytest.mark.parametrize("interval", [60, None])
def test_default_policy_has_no_rpc_or_network_calls(runtime, interval):
    control = runtime[3]
    if interval is None:
        control.clear()
    else:
        control["peer_telemetry_interval_s"] = interval
    assert not tick(runtime)
    assert runtime[-1] == ["verify"]


@pytest.mark.parametrize("state_name", ["stale_expired", "none", "tamper_rejected",
                                         "verifier_missing", "lkg_rejected"])
def test_signed_cache_must_be_current_and_verified(runtime, state_name):
    runtime[4]["attestation"]["instr_state"] = state_name
    assert not tick(runtime)
    assert runtime[-1] == ["verify"]


@pytest.mark.parametrize("mutation", ["paused", "slower", "constrained", "bad",
    "wrong_boot", "old_context", "copying", "parked", "path_escape"])
def test_safeguards_never_run_accelerated_rpc(runtime, mutation):
    state, control = runtime[1], runtime[3]
    context = state["image"]["tele"]["live_context"]
    if mutation == "paused": control["telemetry_pause"] = True
    elif mutation == "slower": control["telemetry_every_ticks"] = 4
    elif mutation == "constrained": state["link"] = {"rtt_ms": [5000]}
    elif mutation == "bad": state["link"] = {"fail_streak": 100}
    elif mutation == "wrong_boot": context["boot_id"] = "different"
    elif mutation == "old_context": context["monotonic"] = 1
    elif mutation == "copying": context["phase"] = "copied"
    elif mutation == "parked": state["image"]["parked"] = True
    elif mutation == "path_escape": context["stage"] = "/elsewhere/os.bin"
    assert tick(runtime)
    assert runtime[-1] == ["verify"]


def test_heartbeat_lease_and_master_toggle_stop_the_worker(runtime):
    assert not tick(runtime, now=1181)
    assert not tick(runtime, now=999)
    runtime[0]["telemetry"] = "off"
    assert not tick(runtime)
    assert runtime[-1] == []


def test_failed_checkpoint_prevents_post_and_sequence_advance(runtime):
    def fail(_state): raise OSError("no space")
    runtime[2].checkpoint = fail
    assert tick(runtime)
    assert not any(isinstance(event, dict) for event in runtime[-1])
    assert runtime[1]["image"]["tele"]["sample_seq"] == 4


def test_network_failure_backs_off_without_stopping_regular_agent(runtime):
    def fail(*args): raise OSError("offline")
    runtime[2].catalog.post_live_observation = fail
    assert tick(runtime)
    assert runtime[1]["stream_directives"]["peer_retry_at"] == 1030
    runtime[-1].clear()
    assert tick(runtime, now=1020)
    assert runtime[-1] == ["verify"]


def test_single_idle_zero_clears_old_flow_without_repeated_idle_posts(runtime):
    runtime[1]["image"]["tele"]["live_context"]["phase"] = "steady"
    runtime[2].aria_stats = lambda stage: {"status": "active", "downloadSpeed": "0",
        "uploadSpeed": "0", "completedLength": "100", "totalLength": "100"}
    runtime[2].aria_peers = lambda stage: pytest.fail("idle peer RPC")
    assert tick(runtime)
    assert tick(runtime, now=1020, mono=920)
    assert len([e for e in runtime[-1] if isinstance(e, dict)]) == 1


@pytest.mark.parametrize("interval", [10, 60])
def test_optional_signed_control_accepts_supported_intervals(interval):
    assert instr.validate_control({"peer_telemetry_interval_s": interval}, partial=True)
    assert instr.validate_control(dict(iris_agent._FIXED_CONTROL))


@pytest.mark.parametrize("interval", [True, "10", 0, 5, 11, 61, None])
def test_optional_signed_control_refuses_other_values(interval):
    with pytest.raises(ValueError):
        instr.validate_control({"peer_telemetry_interval_s": interval}, partial=True)


def test_helper_uses_same_lock_and_never_reads_state_during_main_tick(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_AGENT_STATE", str(tmp_path / "state"))
    monkeypatch.setattr(iris_agent.agent_config, "load", lambda _: pytest.fail("read during main tick"))
    monkeypatch.setattr(iris_agent.time, "sleep", lambda _: (_ for _ in ()).throw(RuntimeError("stop test")))
    with (tmp_path / "iris-agent.lock").open("w") as main:
        fcntl.flock(main, fcntl.LOCK_EX | fcntl.LOCK_NB)
        iris_agent.peer_telemetry_loop()


def test_only_one_helper_can_run(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_AGENT_STATE", str(tmp_path / "state"))
    monkeypatch.setattr(iris_agent.agent_config, "load", lambda _: pytest.fail("duplicate helper"))
    with (tmp_path / "iris-peer-telemetry.lock").open("w") as existing:
        fcntl.flock(existing, fcntl.LOCK_EX | fcntl.LOCK_NB)
        iris_agent.peer_telemetry_loop()


def test_stopped_helper_releases_state_lock_without_rewriting_unchanged_state(tmp_path, monkeypatch):
    path = tmp_path / "state"
    path.write_text(json.dumps({"safe": True}))
    monkeypatch.setenv("IRIS_AGENT_STATE", str(path))
    monkeypatch.setattr(iris_agent.agent_config, "load", lambda _: {})
    monkeypatch.setattr(iris_agent, "build_deps", lambda *args: None)
    monkeypatch.setattr(iris_agent, "peer_telemetry_once", lambda *args: False)
    monkeypatch.setattr(iris_agent, "_atomic_write_state", lambda *args: pytest.fail("idle write"))
    iris_agent.peer_telemetry_loop()
    with (tmp_path / "iris-agent.lock").open("w") as main:
        fcntl.flock(main, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_launcher_only_starts_after_applied_opt_in(runtime, monkeypatch):
    calls = []
    monkeypatch.setattr(iris_agent.subprocess, "Popen", lambda *args, **kwargs: calls.append((args, kwargs)))
    cfg, state = runtime[:2]
    iris_agent._start_peer_telemetry(cfg, "/config", "/state", state)
    assert calls == []
    state["instructions"] = {"peer_telemetry_requested": 10}
    iris_agent._start_peer_telemetry(cfg, "/config", "/state", state)
    args, kwargs = calls[0]
    assert args[0][-1] == "--peer-telemetry"
    assert kwargs["start_new_session"] and kwargs["close_fds"]
    assert kwargs["env"]["IRIS_AGENT_STATE"] == "/state"
