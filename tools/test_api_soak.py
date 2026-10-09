# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Deterministic guard/measurement tests; these never start Docker or load."""
import importlib.util
import ipaddress
import io
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


def test_local_data_root_is_resolved_from_verified_daemon(monkeypatch, tmp_path):
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    calls = []
    def fake_docker(*args):
        calls.append(args)
        value = ([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}]
                 if args[0] == "context" else str(tmp_path))
        return SimpleNamespace(stdout=json.dumps(value))
    monkeypatch.setattr(runner, "docker", fake_docker)
    assert runner.validate_host() == tmp_path.resolve()
    assert calls == [("context", "inspect", "default"), ("info", "--format", "{{json .DockerRootDir}}")]


@pytest.mark.parametrize("data_root", [None, [], "relative", "/nonexistent-iris-soak-data-root"])
def test_invalid_local_data_root_is_refused(monkeypatch, data_root):
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    def fake_docker(*args):
        value = ([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}]
                 if args[0] == "context" else data_root)
        return SimpleNamespace(stdout=json.dumps(value))
    monkeypatch.setattr(runner, "docker", fake_docker)
    with pytest.raises(workload.Failure, match="data root"):
        runner.validate_host()


def test_both_output_and_docker_filesystems_are_measured(monkeypatch, tmp_path):
    checked = []
    def disk_usage(path):
        checked.append(path)
        return SimpleNamespace(free=17 if path == tmp_path else 23)
    monkeypatch.setattr(runner.shutil, "disk_usage", disk_usage)
    result = runner.host_resources(tmp_path, Path("/docker-data-fixture"))
    assert checked == [tmp_path, Path("/docker-data-fixture")]
    assert result["disk_free_bytes"] == 17 and result["docker_disk_free_bytes"] == 23


@pytest.mark.parametrize("initial", [False, True])
@pytest.mark.parametrize("field", ["host_available_kib", "disk_free_bytes", "docker_disk_free_bytes"])
def test_resource_floors_are_enforced_independently(initial, field):
    sample = {"host_available_kib": (14 if initial else 8) * 1024**2,
              "disk_free_bytes": (6 if initial else 5) * 1024**3,
              "docker_disk_free_bytes": (6 if initial else 5) * 1024**3}
    runner.resource_floors(sample, initial)
    sample[field] -= 1
    with pytest.raises(workload.Failure, match="safety floor"):
        runner.resource_floors(sample, initial)


def test_initial_resource_failure_prevents_all_docker_mutations(monkeypatch, tmp_path):
    fixture = runner.Fixture.__new__(runner.Fixture)
    fixture.directory = fixture.docker_root = tmp_path
    fixture.manifest = {}
    fixture.save = lambda: None
    monkeypatch.setattr(runner, "host_resources", lambda *args: {
        "host_available_kib": 13 * 1024**2, "disk_free_bytes": 8 * 1024**3,
        "docker_disk_free_bytes": 8 * 1024**3})
    monkeypatch.setattr(runner, "docker", lambda *args: pytest.fail("preflight must precede Docker mutation"))
    with pytest.raises(workload.Failure, match="safety floor"):
        fixture.start()
    assert fixture.manifest["preflight_resources"]["host_available_kib"] == 13 * 1024**2


def test_volume_collision_is_refused_before_any_mount_or_bootstrap(monkeypatch, tmp_path):
    fixture = runner.Fixture.__new__(runner.Fixture)
    fixture.directory = fixture.docker_root = tmp_path
    fixture.run_id, fixture.prefix = "ours", "fixture"
    fixture.server_image, fixture.console_image = "server-image", "console-image"
    fixture.manifest, fixture.volumes = {"images": {}}, {}
    fixture.resources = {"container": [], "volume": [], "network": []}
    fixture.save = lambda: None
    monkeypatch.setattr(runner, "host_resources", lambda *args: {
        "host_available_kib": 14 * 1024**2, "disk_free_bytes": 6 * 1024**3,
        "docker_disk_free_bytes": 6 * 1024**3})
    calls = []
    def fake_docker(*args):
        calls.append(args)
        if args[:2] == ("image", "inspect"):
            return SimpleNamespace(stdout=json.dumps([{"Id": args[2]}]))
        if args[:2] == ("network", "create"):
            return SimpleNamespace(stdout="owned-network")
        if args[:2] == ("network", "inspect"):
            return SimpleNamespace(stdout=json.dumps([{
                "Id": "owned-network", "Labels": {runner.LABEL: "ours"},
                "Internal": True, "IPAM": {"Config": [{"Subnet": "172.30.0.0/24"}]}}]))
        if args[:2] == ("volume", "create"):
            return SimpleNamespace(stdout="fixture-config")
        if args[:2] == ("volume", "inspect"):
            return SimpleNamespace(stdout=json.dumps([{
                "Name": "fixture-config", "Labels": {runner.LABEL: "foreign"}}]))
        pytest.fail("A colliding volume must never reach mount/bootstrap or mutation")
    monkeypatch.setattr(runner, "docker", fake_docker)
    with pytest.raises(workload.Failure, match="ownership changed"):
        fixture.start()
    assert not fixture.resources["container"]
    assert [args for args in calls if args[0] == "volume"] == [
        ("volume", "create", "--label", runner.LABEL + "=ours", "fixture-config"),
        ("volume", "inspect", "fixture-config")]


@pytest.mark.parametrize("changed", [{"ExitCode": 1}, {"ExitCode": 137},
                                        {"OOMKilled": True}, {"Running": True},
                                        {"Status": "restarting"}, {"Dead": True},
                                        {"Restarting": True}])
def test_unclean_exit_is_evidenced_and_not_restarted(monkeypatch, changed):
    fixture = runner.Fixture.__new__(runner.Fixture)
    fixture.console, fixture.server = "console-owned", "server-owned"
    fixture.manifest = {}
    fixture.save = lambda: None
    state = dict(Status="exited", Running=False, ExitCode=0, OOMKilled=False,
                 Error="SECRET daemon detail")
    state.update(changed)
    inspected, commands = [], []
    def inspect(identity):
        inspected.append(identity)
        return {"State": state}
    fixture.inspect = inspect
    monkeypatch.setattr(runner, "docker", lambda *args: commands.append(args))
    with pytest.raises(workload.Failure, match="did not stop cleanly"):
        fixture.restart()
    assert inspected == ["console-owned", "console-owned"]
    assert commands == [("container", "stop", "--time", "30", "console-owned")]
    assert fixture.manifest["stops"][0]["clean"] is False
    assert "SECRET" not in json.dumps(fixture.manifest)


def test_restart_requires_two_clean_exits_before_start(monkeypatch):
    fixture = runner.Fixture.__new__(runner.Fixture)
    fixture.console, fixture.server = "console-owned", "server-owned"
    fixture.manifest, fixture.previous = {}, {"stale": 1}
    fixture.save = fixture.wait_management = fixture.wait_console = lambda: None
    fixture.inspect = lambda _: {"State": dict(Status="exited", Running=False, ExitCode=0, OOMKilled=False)}
    commands = []
    monkeypatch.setattr(runner, "docker", lambda *args: commands.append(args))
    fixture.restart()
    assert [row[1] for row in commands] == ["stop", "stop", "start", "start"]
    assert [row["clean"] for row in fixture.manifest["stops"]] == [True, True]
    assert not fixture.previous


def test_cleanup_records_unclean_exit_but_still_removes_owned_container(monkeypatch, tmp_path):
    fixture = runner.Fixture.__new__(runner.Fixture)
    fixture.run_id, fixture.directory = "ours", tmp_path
    fixture.resources = {"container": ["owned"], "volume": [], "network": []}
    fixture.manifest, fixture.resource_log = {}, io.StringIO()
    fixture.save = lambda: None
    fixture.stop = lambda identity, reason, require_clean: False
    monkeypatch.setattr(runner, "owned", lambda *args: {"State": {"Running": True}})
    commands = []
    monkeypatch.setattr(runner, "docker", lambda *args: commands.append(args))
    problems = fixture.cleanup()
    assert problems == ["owned service cleanup stop was not clean"]
    assert commands == [("container", "rm", "owned")]


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
    counters = json.loads(result.stdout)
    assert set(counters) == {"processes", "fds", "threads", "cpu.stat", "memory.current",
                             "memory.peak", "memory.events", "memory.stat", "pids.current",
                             "cpu.pressure", "memory.pressure", "io.pressure"}
    memory = dict(line.split() for line in counters["memory.stat"].splitlines())
    assert int(memory["anon"]) >= 0 and int(memory["file"]) >= 0


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
