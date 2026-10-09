# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Deterministic guard/measurement tests; these never start Docker or load."""
import importlib.util
import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import subprocess

import pytest

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import api_soak_workload as workload

spec = importlib.util.spec_from_file_location("api_soak_runner", TOOLS / "api-soak.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@pytest.mark.parametrize("url", ["http://127.0.0.1:1234", "https://localhost:1234",
                                    "https://100.90.168.86:1234", "https://127.0.0.1",
                                    "https://user:secret@127.0.0.1:1234",
                                    "https://127.0.0.1:1234/?token=x"])
def test_only_loopback_origin(url):
    with pytest.raises(ValueError):
        workload.origin(url)


def test_valid_origin():
    assert workload.origin("https://127.0.0.1:15443").port == 15443


def test_remote_docker_refused_before_call(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "ssh://production")
    monkeypatch.setattr(runner, "docker", lambda *a: pytest.fail("Docker must not be contacted"))
    with pytest.raises(workload.Failure, match="overrides"):
        runner.validate_host()


@pytest.mark.parametrize("label,identity", [("foreign", "abc"), ("ours", "different")])
def test_cleanup_requires_label_and_identity(monkeypatch, label, identity):
    monkeypatch.setattr(runner, "docker", lambda *a: SimpleNamespace(stdout=json.dumps([
        {"Id": identity, "Config": {"Labels": {runner.LABEL: label}}}])))
    with pytest.raises(workload.Failure):
        runner.owned("container", "abc", "ours")


def test_metrics_are_bounded_and_partial_is_not_success():
    metrics = workload.Metrics()
    for status in (200, 207, 429, 0):
        metrics.add("read", {"status": status, "seconds": .001, "retry_after": "2"})
    metrics.add("read", {"status": 200, "seconds": 100000, "retry_after": None})
    assert max(metrics.rows["read"]["ms"]) == 60000
    report = metrics.report(5)
    assert report["read"]["valid_retry_after"] == 1
    assert workload.objectives(report)
    assert workload.objectives(report, overload=True)


@pytest.mark.parametrize("value", [None, "0", "-1", "1.0", "61", "١", "token"])
def test_retry_after_requires_bounded_ascii_seconds(value):
    assert not workload.valid_retry(value)


def test_unknown_write_is_not_replayed_or_logged(monkeypatch, tmp_path):
    calls = []
    class Broken:
        def request(self, *args):
            calls.append(args)
            raise OSError("SECRET response-cookie payload")
        def close(self):
            pass
    monkeypatch.setattr(workload.ssl, "create_default_context", lambda **kw: None)
    monkeypatch.setattr(workload.http.client, "HTTPSConnection", lambda *a, **kw: Broken())
    client = workload.Client("https://127.0.0.1:1234", "ignored")
    result, data = client.request("POST", "/api/v1/devices", {"model": "synthetic"})
    assert len(calls) == 1 and result["status"] == 0 and result["error"] == "OSError"
    assert "SECRET" not in json.dumps(result) and data == {}


def test_terminal_report_uses_current_contract():
    sys.path.insert(0, str(TOOLS.parent / "server"))
    import catalog
    value = workload.terminal_report("synthetic-image")
    assert catalog._sanitize_report(value)["report_id"] == value["report_id"]
    assert value["content_sha256"]["state"] == "not_checked"


@pytest.mark.parametrize("extra", [["--devices", "1001"], ["--soak-seconds", "1801"],
                                     ["--step-seconds", "121"], ["--steps", "15,2"],
                                     ["--steps", "16"], ["--steps", "nan"]])
def test_duration_and_rate_fences(extra):
    with pytest.raises(SystemExit):
        runner.arguments(["--server-image", "test", "--console-image", "test",
                          "--output", str(TOOLS.parent / "agentinfo/no-created-fixture"),
                          "--accept-isolated-load", *extra])


def test_dry_bounds_cannot_claim_qualification():
    args = runner.arguments(["--server-image", "test", "--console-image", "test",
                             "--output", str(TOOLS.parent / "agentinfo/no-created-fixture"),
                             "--accept-isolated-load", "--step-seconds", "5", "--soak-seconds", "5"])
    assert args.step_seconds < 120 and args.soak_seconds < 1800


@pytest.mark.parametrize("network,address,ports", [
    ("foreign-network", "172.30.0.10", {}),
    ("ours", "172.30.0.12", {}),
    ("ours", "192.0.2.1", {}),
    ("ours", "172.30.0.10", {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}),
])
def test_network_address_and_no_publication_guards(network, address, ports):
    fixture = runner.Fixture.__new__(runner.Fixture)
    fixture.network = "ours"
    fixture.allowed_hosts = ("172.30.0.10", "172.30.0.11", "192.0.2.1")
    fixture.subnet = ipaddress.ip_network("172.30.0.0/24")
    fixture.inspect = lambda _: {"NetworkSettings": {"Ports": ports, "Networks": {
        "n": {"NetworkID": network, "IPAddress": address}}}}
    with pytest.raises(workload.Failure):
        fixture.url("container", "8080/tcp")


def test_console_resource_probe_needs_no_server_modules():
    result = subprocess.run([sys.executable, "-I", str(TOOLS / "api_soak_fixture.py"), "resources"],
                            env={"IRIS_SOAK_FIXTURE": "synthetic-isolated-v1"},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert set(("processes", "fds", "threads", "memory.current")) <= json.loads(result.stdout).keys()


def test_fixture_credentials_are_not_in_console_shared_volume():
    source = (TOOLS / "api_soak_fixture.py").read_text()
    assert 'Path("/run/soak-keys/driver.json")' in source
    assert 'Path("/run/soak-shared/driver.json")' not in source


def test_catalog_under_delivery_cannot_hide_behind_console_success():
    report = {"heartbeat": {"count": 900}, "telemetry": {"count": 50}}
    assert len(workload.delivery_failures(report, 60, 15, 900, 1000)) == 2
    report["heartbeat"]["count"] = 1000
    report["telemetry"]["count"] = 60
    assert not workload.delivery_failures(report, 60, 15, 900, 1000)
    assert workload.delivery_failures(report, 60, 15, 800, 1000)


def test_admission_backoff_does_not_excuse_telemetry_under_delivery():
    assert not workload.delivery_failures({"heartbeat": {"count": 1000}, "telemetry": {"count": 60}},
                                          60, 15, 500, 1000, overload=True)
    assert workload.delivery_failures({}, 60, 15, 500, 1000, overload=True)


@pytest.mark.parametrize("path,data", [
    ("/api/v1/devices?limit=100", {"devices": [{"device_id": "foreign"}]}),
    ("/api/v1/overview", {"devices": 999, "rollout": []}),
    ("/api/v1/peer-policy", {"revision": 0, "degraded": True, "fail_closed": False}),
    ("/api/v1/session", {"username": "different", "csrf": "fixture"}),
])
def test_success_status_cannot_hide_malformed_or_wrong_identity(path, data):
    with pytest.raises(workload.Failure):
        workload.validate_read(path, data, 1000, "soak", "fixture")
