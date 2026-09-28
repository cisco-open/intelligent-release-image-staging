# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Installer runtime checks; transports are mocked, file verification is real."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "server"))

from iris_installer import cli, probe
import setup_status


def test_doctor_uses_existing_k3s_without_installing_dependencies(monkeypatch):
    monkeypatch.setattr(cli.shutil, 'which', lambda name: '/usr/local/bin/k3s' if name == 'k3s' else None)
    args = cli.parser().parse_args(['doctor', '--target', 'kubernetes', '--context', 'lab',
        '--namespace', 'iris', '--pod', 'server-123', '--container', 'iris'])
    assert cli.runtime_command(args)[:2] == ['k3s', 'kubectl']


@pytest.fixture
def artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 10001)
    monkeypatch.setattr(os, "getegid", lambda: 10001)
    # Small valid PEM encoding is enough for this byte-fingerprint contract;
    # endpoint chain/hostname validation explicitly belongs to another check.
    (tmp_path / "iris-catalog.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n")
    for name, kind, platform, _ in probe.PACKAGES:
        (tmp_path / name).write_bytes(b"package bytes")
        values = {
            "format": "iris-device-wrapper-v1", "wrapper_kind": kind,
            "wrapper_file": name, "platform": platform,
            "wrapper_sha256": hashlib.sha256(b"package bytes").hexdigest(),
            "canonical_index_digest": "sha256:" + "1" * 64,
            "canonical_archive_sha256": "2" * 64,
            "canonical_source_sha256": "3" * 64,
        }
        (tmp_path / (name + ".manifest")).write_text(
            "".join(f"{key}={value}\n" for key, value in values.items()))
    return tmp_path


def test_report_is_scoped_and_requires_both_architectures_and_xr(artifacts):
    report = probe.collect(str(artifacts))
    assert report["state"] == "checks-passed"
    assert report["scope"] == probe.SCOPE
    assert [p["name"] for p in report["packages"]] == [p[0] for p in probe.PACKAGES]
    cli.validate_report(report, optional_xr=False)
    (artifacts / "iris-arm64.tar").unlink()
    assert probe.collect(str(artifacts))["state"] == "checks-failed"


@pytest.mark.parametrize("uid,gid", [(0, 0), (0, 10001), (10001, 0), (1000, 1000)])
def test_root_and_unexpected_service_identities_fail(artifacts, monkeypatch, uid, gid):
    monkeypatch.setattr(os, "geteuid", lambda: uid)
    monkeypatch.setattr(os, "getegid", lambda: gid)
    report = probe.collect(str(artifacts))
    assert report["state"] == "checks-failed"
    assert report["reason"] == "unexpected-runtime-identity"
    assert report["packages"] == []


@pytest.mark.parametrize("filename", ["iris-amd64.tar", "iris-arm64.tar.manifest", "iris-catalog.pem"])
def test_runtime_eacces_is_never_ready(artifacts, monkeypatch, filename):
    real_open = open

    def runtime_open(path, *args, **kwargs):
        if str(path) == str(artifacts / filename):
            raise PermissionError("private host artifact")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(setup_status, "open", runtime_open, raising=False)
    assert probe.collect(str(artifacts))["state"] == "checks-failed"


def test_optional_xr_only_waives_absence(artifacts):
    (artifacts / "iris-xr.rpm").unlink()
    assert probe.collect(str(artifacts))["state"] == "checks-failed"
    assert probe.collect(str(artifacts), optional_xr=True)["state"] == "checks-passed"
    (artifacts / "iris-xr.rpm").write_bytes(b"altered bytes")
    assert probe.collect(str(artifacts), optional_xr=True)["state"] == "checks-failed"


@pytest.mark.parametrize("target,expected", [
    (["--target", "docker", "--context", "lab", "--container", "iris-server"],
     ["docker", "--context", "lab", "exec", "-i", "iris-server", "python3", "-I", "-B", "-"]),
    (["--target", "kubernetes", "--context", "lab", "--namespace", "iris", "--pod", "server-123"],
     ["kubectl", "--context", "lab", "--namespace", "iris", "exec", "-i", "server-123", "-c", "iris",
      "--", "python3", "-I", "-B", "-"]),
])
def test_explicit_transports_stream_read_only_probe(artifacts, monkeypatch, target, expected, capsys):
    def run(command, **kwargs):
        assert command == expected
        assert kwargs["timeout"] == 120
        assert "def collect(" in kwargs["input"]
        assert kwargs.get("shell", False) is False
        return subprocess.CompletedProcess(command, 0, json.dumps(probe.collect(str(artifacts))), "")

    monkeypatch.setattr(subprocess, "run", run)
    assert cli.main(["doctor", *target, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "checks-passed"


@pytest.mark.parametrize("args", [
    ["--target", "kubernetes"],
    ["--target", "kubernetes", "--context", "lab", "--namespace", "iris"],
    ["--target", "docker", "--pod", "server"],
    ["--target", "docker", "--container=--privileged"],
    ["--target", "docker", "--timeout", "0"],
    ["--target", "docker", "--timeout", "nan"],
])
def test_invalid_targets_fail_before_execution(monkeypatch, args):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("must not execute"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["doctor", *args])
    assert exc.value.code == 2


@pytest.mark.parametrize("failure,reason", [
    (FileNotFoundError("secret-path"), "runtime-command-unavailable"),
    (subprocess.TimeoutExpired("secret-command", 1), "runtime-probe-timeout"),
    (subprocess.CompletedProcess([], 1, "secret-output", "secret-token"), "runtime-exec-failed"),
    (subprocess.CompletedProcess([], 0, "not-json secret-output", ""), "invalid-runtime-evidence"),
    (subprocess.CompletedProcess([], 0, '{"schema_version":1,"scope":"native-package-readability-and-provenance","state":"checks-passed"}', ""), "invalid-runtime-evidence"),
    (subprocess.CompletedProcess([], 0, '{"schema_version":1,"scope":"native-package-readability-and-provenance","state":"checks-failed","packages":[null]}', ""), "invalid-runtime-evidence"),
    (subprocess.CompletedProcess([], 0, '{"schema_version":1,"scope":"native-package-readability-and-provenance","state":"checks-failed","reason":"secret-token"}', ""), "invalid-runtime-evidence"),
])
def test_transport_failures_are_redacted(monkeypatch, capsys, failure, reason):
    def run(*args, **kwargs):
        if isinstance(failure, Exception):
            raise failure
        return failure

    monkeypatch.setattr(subprocess, "run", run)
    assert cli.main(["doctor", "--target", "docker", "--format", "json"]) == 1
    output = capsys.readouterr().out
    assert "secret" not in output
    assert json.loads(output)["reason"] == reason


@pytest.mark.parametrize("change", [
    lambda r: r.update(runtime_uid=0),
    lambda r: r.update(packages=[]),
    lambda r: r["packages"][1].update(name="iris-amd64.tar"),
    lambda r: r["packages"][2].update(required=False),
    lambda r: r["catalog_certificate"].update(fingerprint="invalid"),
    lambda r: r["packages"][1].update(state="absent"),
    lambda r: r.update(state="checks-failed"),
])
def test_success_requires_complete_evidence(artifacts, change):
    report = probe.collect(str(artifacts))
    change(report)
    with pytest.raises(ValueError):
        cli.validate_report(report, optional_xr=False)


def test_deployment_command_not_advertised_as_implemented():
    result = subprocess.run([sys.executable, str(REPO / "tools/irisctl"), "install"],
                            capture_output=True, text=True)
    assert result.returncode == 2


def test_missing_local_probe_fails_without_transport(monkeypatch, capsys):
    def missing(*args, **kwargs):
        raise FileNotFoundError("private-path")

    monkeypatch.setattr(Path, "read_text", missing)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("must not execute"))
    assert cli.main(["doctor", "--target", "docker", "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["reason"] == "local-probe-unavailable"


def test_text_reports_certificate_failure(artifacts, monkeypatch, capsys):
    (artifacts / "iris-catalog.pem").unlink()
    monkeypatch.setattr(cli, "diagnose", lambda args: probe.collect(str(artifacts)))
    assert cli.main(["doctor", "--target", "docker"]) == 1
    assert "Distributed catalog certificate: unknown" in capsys.readouterr().out


def test_real_docker_runtime_permissions(tmp_path):
    """Opt-in, actual uid/mount regression. No ports, devices or owner volumes."""
    image = os.environ.get("IRIS_INSTALLER_DOCKER_TEST_IMAGE")
    if not image:
        pytest.skip("set IRIS_INSTALLER_DOCKER_TEST_IMAGE to a trusted local image ID")
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", image), "use an immutable local image ID"
    tmp_path.chmod(0o755)
    for name, kind, platform, _ in probe.PACKAGES:
        data = b"isolated fixture package bytes"
        (tmp_path / name).write_bytes(data)
        (tmp_path / (name + ".manifest")).write_text(
            f"format=iris-device-wrapper-v1\nwrapper_kind={kind}\nwrapper_file={name}\n"
            f"wrapper_sha256={hashlib.sha256(data).hexdigest()}\nplatform={platform}\n"
            f"canonical_index_digest=sha256:{'1' * 64}\n"
            f"canonical_archive_sha256={'2' * 64}\ncanonical_source_sha256={'3' * 64}\n")
    (tmp_path / "iris-catalog.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n")
    for path in tmp_path.iterdir():
        path.chmod(0o444)

    def docker(*args):
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              check=True, timeout=30).stdout.strip()

    container = docker(
        "run", "--detach", "--rm", "--pull=never", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
        "--security-opt", "no-new-privileges", "--user", "10001:10001",
        "--mount", f"type=bind,src={tmp_path},dst=/srv/artifacts",
        "--entrypoint", "python3", image, "-I", "-B", "-c",
        "import time; time.sleep(300)")
    assert re.fullmatch(r"[0-9a-f]{64}", container)
    args = cli.parser().parse_args(["doctor", "--target", "docker", "--container", container])
    try:
        assert cli.diagnose(args)["state"] == "checks-passed"
        for filename in ("iris-amd64.tar", "iris-arm64.tar.manifest", "iris-catalog.pem"):
            # Only this disposable mount is writable. Root exec simulates the
            # exact publication defect without changing any deployed artifact.
            docker("exec", "--user", "0:0", container, "python3", "-I", "-B", "-c",
                   "import os,sys; os.chown(sys.argv[1],0,0); os.chmod(sys.argv[1],0o400)",
                   "/srv/artifacts/" + filename)
            failed = cli.diagnose(args)
            assert failed["runtime_uid"] == 10001
            assert failed["state"] == "checks-failed"
            docker("exec", "--user", "0:0", container, "python3", "-I", "-B", "-c",
                   "import os,sys; os.chmod(sys.argv[1],0o444)", "/srv/artifacts/" + filename)
            assert cli.diagnose(args)["state"] == "checks-passed"
    finally:
        docker("stop", "--time", "1", container)
