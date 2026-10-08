# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import os
from pathlib import Path
import sys
import threading
from email.message import Message
from types import SimpleNamespace

import pytest
from openapi_schema_validator import OAS32Validator

import deployment_info
import lifecycle_client
import gui_server
import openapi_contract
from test_api_split import policy_tiers

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from iris_installer import deployment_info as inventory
from iris_installer import deploy, lifecycle_worker
from iris_installer.state import InstallError


def sample(layout="docker"):
    return dict(layout=layout, observed_at=1234, instance="iris", namespace=None, note=None,
                components=[dict(role="server", kind="container", name="iris-server", host="host-a",
                                 image="iris:test", address=None, state="running")])


def unavailable(_request):
    raise lifecycle_client.LifecycleUnavailable("Private detail must not be displayed")


def test_runtime_is_allowlisted_and_kubernetes_node_is_not_pod_hostname(monkeypatch):
    monkeypatch.setenv("IRIS_POD_NAME", "iris-console-abc")
    monkeypatch.setenv("IRIS_NODE_NAME", "node-b")
    monkeypatch.setenv("IRIS_POD_IP", "192.0.2.20")
    monkeypatch.setenv("IRIS_MANAGEMENT_API_TOKEN", "never-display-this")
    result = deployment_info.runtime("console")
    assert set(result) == set(deployment_info.FIELDS)
    assert (result["kind"], result["name"], result["host"]) == ("pod", "iris-console-abc", "node-b")
    assert "never-display" not in json.dumps(result)
    assert deployment_info.read_console(deployment_info.console_header()) == result


@pytest.mark.parametrize("value", [None, "!", "x" * 4097, base64.b64encode(b"[]").decode(),
                                    base64.b64encode(b'{"role":"console","token":"secret"}').decode()])
def test_invalid_console_headers_are_ignored(value):
    assert deployment_info.read_console(value) is None


def test_browser_cannot_supply_console_runtime_header(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    server = gui_server.make_server("127.0.0.1", 0, "https://localhost:9",
                                    str(tmp_path / "token"), str(tmp_path / "ca"))
    try:
        headers = Message()
        headers[deployment_info.HEADER] = "forged"
        headers[deployment_info.HEADER.lower()] = "second-forgery"
        handler = SimpleNamespace(headers=headers, path="/api/v1/deployment", client_address=("127.0.0.1", 1))
        result = server.RequestHandlerClass._upstream_headers(handler, 0, "tier-token")
        matching = [value for name, value in result.items() if name.lower() == deployment_info.HEADER.lower()]
        assert len(matching) == 1
        assert deployment_info.read_console(matching[0])["role"] == "console"
        handler.path = "/api/v1/overview"
        assert deployment_info.HEADER not in server.RequestHandlerClass._upstream_headers(handler, 0, "tier-token")
    finally:
        server.server_close()


def test_unmanaged_fallback_never_calls_a_container_id_a_host(monkeypatch):
    monkeypatch.setattr(lifecycle_client, "call", unavailable)
    for name in ("IRIS_NODE_NAME", "IRIS_RUNTIME_HOST", "IRIS_POD_NAMESPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("IRIS_RUNTIME_LAYOUT", "docker-split")
    result = deployment_info.summary()
    assert result["source"] == "runtime" and result["layout"] == "docker-split"
    assert result["components"][0]["host"] is None
    assert "unavailable" in result["note"] and "Private detail" not in json.dumps(result)
    route = next(r for r in openapi_contract.api_routes.ROUTES if r.path == "/api/v1/deployment")
    OAS32Validator(openapi_contract._success(route)[1]["content"]["application/json"]["schema"]).validate(result)


def test_combined_layout_requires_metadata_not_matching_container_names(monkeypatch):
    monkeypatch.setattr(lifecycle_client, "call", unavailable)
    monkeypatch.delenv("IRIS_RUNTIME_LAYOUT", raising=False)
    server = dict(deployment_info.runtime("server"), kind="container", name="same-id")
    monkeypatch.setattr(deployment_info, "runtime", lambda _role: server)
    console = dict(server, role="console")
    assert deployment_info.summary(console)["layout"] == "unknown"
    monkeypatch.setenv("IRIS_RUNTIME_LAYOUT", "single-container")
    assert deployment_info.summary(console)["layout"] == "single-container"
    monkeypatch.setenv("IRIS_RUNTIME_LAYOUT", "docker-split")
    console["name"] = "another-id"
    assert deployment_info.summary(console)["layout"] == "docker-split"


@pytest.mark.parametrize("layout", ["docker", "docker-split", "kubernetes"])
def test_summary_contract_filters_private_worker_fields(monkeypatch, layout):
    value = sample(layout)
    value.update(private_key="secret", mounts=["/private"])
    value["components"][0]["environment"] = {"TOKEN": "secret"}
    monkeypatch.setattr(lifecycle_client, "call", lambda request: value)
    result = deployment_info.summary()
    assert "secret" not in json.dumps(result) and "mounts" not in result
    route = next(r for r in openapi_contract.api_routes.ROUTES if r.path == "/api/v1/deployment")
    schema = openapi_contract._success(route)[1]["content"]["application/json"]["schema"]
    OAS32Validator(schema).validate(result)


@pytest.mark.parametrize("array", [True, False])
def test_compose_versions_and_other_services(array):
    rows = [dict(Service="iris", Name="iris-server", Image="iris:test", State="running", Health="healthy", Env="secret"),
            dict(Service="other-app", Name="unrelated", State="running")]
    raw = json.dumps(rows) if array else "\n".join(map(json.dumps, rows))
    result = inventory.docker_rows(raw.encode(), "host-a", {"iris", "console"})
    assert len(result) == 1 and result[0]["state"] == "running / healthy"
    assert result[0]["host"] == "host-a" and "secret" not in json.dumps(result)


def pod(name, role, node, *, ready=True, phase="Running", owner="owned"):
    from iris_installer.kube_deploy import LABEL, SERVICES
    return dict(metadata={"name": name, "labels": {LABEL: owner, "app.kubernetes.io/name": SERVICES[role]}},
                spec={"nodeName": node, "containers": [{"name": role, "image": "iris:test", "env": [{"SECRET": "hidden"}]}]},
                status={"phase": phase, "podIP": "192.0.2.10", "conditions": [{"type": "Ready", "status": "True" if ready else "False"}]})


def test_all_owned_pods_including_unready_and_pending_are_shown():
    rows = [pod("console-a", "console", "node-a"), pod("server", "iris", "node-b"),
            pod("console-b", "console", "node-c", ready=False),
            pod("console-c", "console", None, phase="Pending"),
            pod("unrelated", "console", "node-z", owner="other")]
    result = inventory.pod_rows({"items": rows}, "owned")
    assert len(result) == 4 and result[0]["role"] == "server"
    assert result[2]["state"] == "Running / not ready"
    assert result[3]["state"] == "Pending" and result[3]["host"] is None
    assert "hidden" not in json.dumps(result) and "unrelated" not in json.dumps(result)


@pytest.mark.parametrize("target", ["docker", "docker-split", "kubernetes"])
def test_collection_uses_only_scoped_reads(tmp_path, monkeypatch, target):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    document = dict(schema=1, id="owned", completed={}, config=dict(target=target, instance="iris",
                    kube_namespace="iris-ns", console_ssh_host="192.0.2.20"))
    journal = state / "installation.json"
    journal.write_text(json.dumps(document))
    before = journal.read_bytes()
    commands = []
    def docker(*args, **kwargs):
        commands.append(args)
        assert args == ("ps", "--all", "--format", "json") and kwargs["timeout"] <= 4
        return b'[{"Service":"iris","Name":"iris-server","State":"running"}]'
    def remote(*args, **kwargs):
        docker(*args, **kwargs)
        return b'[{"Service":"console","Name":"iris-console","State":"running"}]'
    def kube(*args, **kwargs):
        commands.append(args)
        assert args[:3] == ("get", "pods", "-l") and args[3].endswith("=owned")
        assert kwargs["timeout"] <= 4
        return json.dumps({"items": [pod("server", "iris", "node-a")]}).encode()
    monkeypatch.setattr(deploy, "installation", lambda journal: SimpleNamespace(compose=docker, remote_console=remote, kube=kube))
    result = inventory.collect(state)
    assert result["layout"] == target and commands
    assert journal.read_bytes() == before
    assert len(result["components"]) == (2 if target == "docker-split" else 1)


def test_unreachable_remote_console_keeps_known_server_and_marks_configured_host(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "installation.json").write_text(json.dumps(dict(schema=1, id="owned", completed={},
        config=dict(target="docker-split", instance="iris", host="192.0.2.10", console_ssh_host="192.0.2.20"))))
    def remote(*args, **kwargs):
        raise InstallError("do not disclose transport custody")
    adapter = SimpleNamespace(compose=lambda *args, **kwargs: b'[{"Service":"iris","Name":"iris-server","State":"running"}]', remote_console=remote)
    monkeypatch.setattr(deploy, "installation", lambda journal: adapter)
    result = inventory.collect(state)
    assert result["components"][0]["address"] == "192.0.2.10"
    assert result["components"][1]["state"] == "not observed"
    assert result["components"][1]["host"] == "192.0.2.20"
    assert "configured" in result["note"] and "custody" not in json.dumps(result)


def test_worker_caches_success_and_failure_without_changing_jobs(tmp_path, monkeypatch):
    for name in ("state", "backups", "recovery"):
        (tmp_path / name).mkdir(mode=0o700)
    worker = lifecycle_worker.Worker(*(tmp_path / name for name in ("state", "backups", "recovery")))
    calls = []
    monkeypatch.setattr(inventory, "collect", lambda state: calls.append(state) or sample())
    assert worker.deployment_info() == worker.deployment_info()
    assert len(calls) == 1 and worker.jobs == []
    worker.inventory_checked = 0
    def fail(state):
        calls.append(state)
        raise InstallError("private path")
    monkeypatch.setattr(inventory, "collect", fail)
    for _ in range(2):
        with pytest.raises(InstallError, match="^Deployment inventory unavailable$"):
            worker.deployment_info()
    assert len(calls) == 2 and worker.jobs == []


def test_authenticated_console_to_management_to_worker(policy_tiers, tmp_path, monkeypatch):
    endpoint = tmp_path / "inventory.sock"
    monkeypatch.setenv("IRIS_LIFECYCLE_SOCKET", str(endpoint))
    calls = []
    worker = SimpleNamespace(deployment_info=lambda: calls.append(True) or sample())
    server = lifecycle_worker.make_server(endpoint, worker, allowed_uids=(os.geteuid(),))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    request, _, _ = policy_tiers
    try:
        for tier in ("console", "management"):
            assert request(tier, "GET", "/deployment", authorized=False, match=False)[0] == 401
            assert not calls or tier == "management"
            status, _, data = request(tier, "GET", "/deployment", match=False)
            assert status == 200 and data["source"] == "managed-worker"
        assert len(calls) == 2
        with pytest.raises(ValueError):
            lifecycle_client.call({"action": "deployment-info", "command": "anything"})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
