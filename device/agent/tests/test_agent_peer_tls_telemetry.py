# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Observe daemon TLS policy without claiming transport from desired config."""
import io
import json
from types import SimpleNamespace

import pytest

import iris_agent
import instr


def _deps(**overrides):
    values = dict.fromkeys(iris_agent.Deps._fields)
    values.update(overrides)
    return iris_agent.Deps(**values)


@pytest.mark.parametrize("configured,runtime", [
    ("disabled", "disabled"), ("required", "required"),
    ("required", "disabled"), ("disabled", "required"),
])
def test_observation_preserves_configured_and_running_mode(configured, runtime):
    calls = []
    def rpc(method, params):
        calls.append((method, params))
        return {"bt-peer-tls": runtime, "rpc-secret": "do-not-export"}
    result = iris_agent._peer_tls_observation({"peer_tls_mode": configured}, rpc)
    assert result == {"configured_mode": configured, "runtime_mode": runtime,
                      "runtime_source": "aria2_rpc"}
    assert calls == [("aria2.getGlobalOption", [])]
    assert "do-not-export" not in json.dumps(result)


@pytest.mark.parametrize("response", [{}, None, [], True,
    {"bt-peer-tls": None}, {"bt-peer-tls": True}, {"bt-peer-tls": []},
    {"bt-peer-tls": "preferred"}])
def test_missing_or_invalid_rpc_mode_defaults_config_off_but_runtime_unknown(response):
    assert iris_agent._peer_tls_observation({}, lambda *_: response) == {
        "configured_mode": "disabled", "runtime_mode": "unknown",
        "runtime_source": "unknown"}


def test_failed_rpc_preserves_desired_mode_without_leaking_error():
    def rpc(*args):
        raise OSError("credential-do-not-export")
    result = iris_agent._peer_tls_observation({"peer_tls_mode": "required"}, rpc)
    assert result == {"configured_mode": "required", "runtime_mode": "unknown",
                      "runtime_source": "unknown"}
    assert "credential" not in json.dumps(result)


def test_dependency_replacement_retains_and_can_replace_callback():
    callback = lambda: {"runtime_mode": "required"}
    original = _deps(peer_tls=callback)
    replaced = original._replace(emit=lambda *_: None)
    assert replaced.peer_tls is callback
    assert replaced._replace(aria_rpc=lambda *_: {}).peer_tls is callback
    substitute = lambda: {"runtime_mode": "disabled"}
    assert replaced._replace(peer_tls=substitute).peer_tls is substitute
    assert replaced._replace(peer_tls=None).peer_tls is None
    assert len(original) == len(iris_agent.Deps._fields)


def test_heartbeat_callback_failure_cannot_suppress_heartbeat_or_leak_error():
    captured, emitted = [], []
    def fail():
        raise ValueError("credential-do-not-export")
    def heartbeat(device_id, body):
        captured.append((device_id, body))
        return {"ok": True}
    deps = _deps(catalog=SimpleNamespace(heartbeat=heartbeat), peer_tls=fail,
                 emit=lambda *args: emitted.append(args))
    payload = {"stage_state": "ready"}
    assert iris_agent._send_heartbeat(deps, "d1", payload) == {"ok": True}
    assert captured == [("d1", {"stage_state": "ready", "instr_protocol": 1})]
    assert payload == {"stage_state": "ready"}
    assert not emitted


def test_heartbeat_observation_does_not_mutate_caller_payload():
    captured = []
    observation = {"configured_mode": "disabled", "runtime_mode": "required",
                   "runtime_source": "aria2_rpc"}
    deps = _deps(catalog=SimpleNamespace(heartbeat=lambda did, body: captured.append(body)),
                 peer_tls=lambda: observation)
    payload = {"stage_state": "ready"}
    iris_agent._send_heartbeat(deps, "d1", payload)
    assert captured == [dict(payload, peer_tls=observation, instr_protocol=1)]
    assert "peer_tls" not in payload


def test_runtime_callback_caches_only_within_one_agent_tick(tmp_path, monkeypatch):
    monkeypatch.setattr(instr, "paths_for", lambda *_: {
        "work_dir": str(tmp_path), "signers": str(tmp_path / "signers"),
        "root_signers": str(tmp_path / "roots")})
    monkeypatch.setattr(instr, "SSHVerifier", lambda *_: None)
    monkeypatch.setattr(instr, "boot_id", lambda: "boot")
    calls = []
    modes = iter(("required", "disabled"))
    def urlopen(request, timeout):
        body = json.loads(request.data)
        assert body["method"] == "aria2.getGlobalOption"
        assert request.full_url == "http://127.0.0.1:6800/jsonrpc"
        assert timeout == 10
        calls.append(body["method"])
        return io.BytesIO(json.dumps({"jsonrpc": "2.0", "id": "p",
            "result": {"bt-peer-tls": next(modes), "rpc-secret": "private"}}).encode())
    monkeypatch.setattr(iris_agent.urllib.request, "urlopen", urlopen)
    cfg = {"rpc_port": "6800", "rpc_secret": "private", "peer_tls_mode": "required"}
    first = iris_agent._with_instruction_step(_deps(), cfg, "unused.conf", "iox")
    result = first.peer_tls()
    assert result["runtime_mode"] == "required"
    result["runtime_mode"] = "tampered"
    assert first._replace(emit=lambda *_: None).peer_tls()["runtime_mode"] == "required"
    assert calls == ["aria2.getGlobalOption"]
    second = iris_agent._with_instruction_step(_deps(), cfg, "unused.conf", "iox")
    assert second.peer_tls() == {"configured_mode": "required", "runtime_mode": "disabled",
                                 "runtime_source": "aria2_rpc"}
    assert len(calls) == 2
