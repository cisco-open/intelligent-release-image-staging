# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Separate-host trust provisioning and the effective Compose boundary."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

import tier_auth


ROOT = Path(__file__).resolve().parents[2]
PREPARE = ROOT / "tools/prepare-docker-hosts.py"
_spec = importlib.util.spec_from_file_location("prepare_docker_hosts", PREPARE)
prepare = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prepare)


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL is required for TLS bundle verification")
    destination = tmp_path_factory.mktemp("docker-hosts") / "bundles"
    result = subprocess.run(
        [sys.executable, str(PREPARE), "--out", str(destination),
         "--management-host", "iris-mgmt.example.com",
         "--management-host", "192.0.2.10",
         "--console-host", "console.example.com"],
        capture_output=True, text=True, check=True,
    )
    return destination, result


def test_bundle_keeps_each_private_key_on_its_host_and_never_prints_token(bundle):
    destination, result = bundle
    server = destination / "server"
    console = destination / "console"
    assert sorted(str(p.relative_to(server)) for p in server.rglob("*")
                  if p.is_file()) == [
        "management-tls/tls.crt", "management-tls/tls.key", "tier-auth/current.json"]
    assert sorted(str(p.relative_to(console)) for p in console.rglob("*")
                  if p.is_file()) == [
        "console-tls/tls.crt", "console-tls/tls.key", "management-ca/ca.pem",
        "tier-auth/current.json"]
    server_token = (server / "tier-auth/current.json").read_bytes()
    assert server_token == (console / "tier-auth/current.json").read_bytes()
    assert tier_auth.load_pair(str(server / "tier-auth/current.json"))
    token = json.loads(server_token)["token"]
    assert token not in result.stdout + result.stderr
    assert "PRIVATE KEY" not in result.stdout + result.stderr
    assert (server / "management-tls/tls.key").read_bytes() != \
        (console / "console-tls/tls.key").read_bytes()
    assert (server / "management-tls/tls.crt").read_bytes() == \
        (console / "management-ca/ca.pem").read_bytes()
    for path in [destination, *destination.rglob("*")]:
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
    assert (destination / ".gitignore").read_text() == "*\n"


def test_management_identity_verifies_only_configured_names(bundle):
    destination, _result = bundle
    command = ["openssl", "verify", "-CAfile",
               str(destination / "console/management-ca/ca.pem")]
    certificate = str(destination / "server/management-tls/tls.crt")
    for flag, name in (("-verify_hostname", "iris-mgmt.example.com"),
                       ("-verify_ip", "192.0.2.10")):
        result = subprocess.run(command + [flag, name, certificate], capture_output=True)
        assert result.returncode == 0, result.stderr.decode()
    result = subprocess.run(command + ["-verify_hostname", "other.example.com", certificate],
                            capture_output=True)
    assert result.returncode != 0


@pytest.mark.parametrize("name", ["0.0.0.0", "::", "224.0.0.1", "*.example.com",
                                  "good.example,IP:1.2.3.4", "host\nDNS:evil",
                                  "bad/name", "https://host", "192.0.2.999"])
def test_provisioning_rejects_wildcards_and_san_injection(name, tmp_path):
    result = subprocess.run(
        [sys.executable, str(PREPARE), "--out", str(tmp_path / "output"),
         "--management-host", name, "--console-host", "console.example.com"],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert not (tmp_path / "output").exists()


def test_provisioning_refuses_existing_output_and_symlink(bundle, tmp_path):
    destination, _result = bundle
    before = {p: p.read_bytes() for p in destination.rglob("*") if p.is_file()}
    link = tmp_path / "link"
    link.symlink_to(destination, target_is_directory=True)
    for path in (destination, link):
        with pytest.raises(FileExistsError):
            prepare.prepare(path, ["DNS:management.example.com"], ["DNS:console.example.com"])
    assert all(path.read_bytes() == content for path, content in before.items())


@pytest.fixture(scope="module")
def compose():
    if not shutil.which("docker"):
        pytest.skip("Docker Compose is required to validate the effective deployment")
    result = subprocess.run(["docker", "compose", "version", "--short"],
                            capture_output=True, text=True)
    if result.returncode:
        pytest.skip("Docker Compose is required to validate the effective deployment")
    return ["docker", "compose"]


def _render(compose, filename, values, *, check=True):
    # Explicit --env-file prevents a developer's server/.env being read. No
    # daemon is used by `config`, and these sentinel paths need not exist.
    environment = {"PATH": os.environ["PATH"], **values}
    return subprocess.run(
        compose + ["--env-file", "/dev/null", "-f", str(ROOT / "server" / filename),
                   "config", "--format", "json"],
        env=environment, capture_output=True, text=True, check=check,
    )


SERVER_ENV = {
    "IRIS_HOST_IP": "192.0.2.10",
    "IRIS_CONSOLE_URL": "https://console.example.com:8080",
    "IRIS_MANAGEMENT_BIND_IP": "192.0.2.10",
    "IRIS_AGE_KEY_FILE_HOST": "/test/age-identity",
    "IRIS_AGE_RECIPIENTS": "age1test",
    "IRIS_TIER_AUTH_DIR": "/test/server/tier-auth",
    "IRIS_MANAGEMENT_TLS_DIR": "/test/server/management-tls",
}
CONSOLE_ENV = {
    "IRIS_CONSOLE_BIND_IP": "192.0.2.20",
    "IRIS_MANAGEMENT_API_URL": "https://iris-mgmt.example.com:9443",
    "IRIS_TIER_AUTH_DIR": "/test/console/tier-auth",
    "IRIS_MANAGEMENT_CA_DIR": "/test/console/management-ca",
    "IRIS_CONSOLE_TLS_DIR": "/test/console/console-tls",
}


def test_server_retains_base_services_and_state_with_only_private_management_port(compose):
    base_doc = json.loads(_render(compose, "docker-compose.yml", SERVER_ENV).stdout)
    doc = json.loads(_render(compose, "docker-compose.server.yml", SERVER_ENV).stdout)
    assert set(doc["services"]) == {"iris"}
    assert set(doc["volumes"]) == {"iris-state", "iris-config", "iris-images"}
    base, server = base_doc["services"]["iris"], doc["services"]["iris"]
    assert not any(p["target"] == 9443 for p in base["ports"])
    assert server["ports"] == base["ports"] + [{
        "host_ip": "192.0.2.10", "mode": "ingress", "protocol": "tcp",
        "target": 9443, "published": "9443",
    }]
    base_mounts = {v["target"]: v for v in base["volumes"]}
    mounts = {v["target"]: v for v in server["volumes"]}
    for target in base_mounts.keys() - {"/run/iris-tier", "/run/iris-management-ca"}:
        assert mounts[target] == base_mounts[target]
    assert "/run/iris-management-ca" not in mounts
    assert mounts["/run/iris-tier"]["type"] == "bind"
    assert not mounts["/run/iris-tier"].get("read_only", False)
    assert mounts["/run/iris-management-tls"]["read_only"]
    for field in ("user", "cap_drop", "security_opt", "tmpfs", "secrets", "build"):
        assert server[field] == base[field]
    env = server["environment"]
    for name in ("IRIS_MANAGEMENT_API_GENERATE_TOKEN", "IRIS_MANAGEMENT_API_GENERATE_CERT",
                 "IRIS_GUI_FALLBACK_GENERATE"):
        assert env[name] == "0"
    assert env["IRIS_MANAGEMENT_API_CA_EXPORT"] == ""


def test_console_renders_without_server_configuration_or_shared_state(compose):
    doc = json.loads(_render(compose, "docker-compose.console.yml", CONSOLE_ENV).stdout)
    assert set(doc["services"]) == {"console"}
    assert not doc.get("volumes") and not doc.get("secrets")
    console = doc["services"]["console"]
    assert not console.get("depends_on")
    assert console["ports"][0]["host_ip"] == "192.0.2.20"
    assert {v["target"] for v in console["volumes"]} == {
        "/run/iris-tier", "/run/iris-management-ca", "/run/iris-console-tls",
        "/opt/iris/server/webroot/fonts/SharpSans-Bold.woff2",
    }
    assert all(v["type"] == "bind" and v["read_only"] for v in console["volumes"])
    for mount in console["volumes"]:
        if mount["target"].startswith("/run/"):
            # Compose v2 omits a false create_host_path from `config` output
            # (omitempty); v5 emits it. Absent therefore means false; only an
            # explicit true -- what short-syntax binds get -- is a failure.
            assert not mount["bind"].get("create_host_path", False)
    env = console["environment"]
    assert env["IRIS_MANAGEMENT_API_URL"] == CONSOLE_ENV["IRIS_MANAGEMENT_API_URL"]
    assert env["IRIS_GUI_DEFAULT_CERT"] == "/run/iris-console-tls/tls.crt"
    assert env["IRIS_GUI_DEFAULT_KEY"] == "/run/iris-console-tls/tls.key"
    assert "IRIS_GUI_ALLOW_PLAINTEXT" not in env
    assert console["user"] == "10001:10001"
    assert console["cap_drop"] == ["ALL"]
    assert console["security_opt"] == ["no-new-privileges:true"]


@pytest.mark.parametrize("filename,values,required", [
    ("docker-compose.server.yml", SERVER_ENV, "IRIS_MANAGEMENT_BIND_IP"),
    ("docker-compose.console.yml", CONSOLE_ENV, "IRIS_CONSOLE_BIND_IP"),
    ("docker-compose.console.yml", CONSOLE_ENV, "IRIS_MANAGEMENT_API_URL"),
])
def test_remote_deployment_requires_explicit_addresses(compose, filename, values, required):
    environment = {name: value for name, value in values.items() if name != required}
    result = _render(compose, filename, environment, check=False)
    assert result.returncode != 0
    assert required in result.stderr


def test_remote_server_can_keep_existing_project_volumes(compose):
    environment = {**SERVER_ENV, "COMPOSE_PROJECT_NAME": "server"}
    doc = json.loads(_render(compose, "docker-compose.server.yml", environment).stdout)
    assert doc["name"] == "server"
    assert all(volume["name"] == "server_" + name
               for name, volume in doc["volumes"].items())
