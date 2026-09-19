# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Keep reviewed operator security claims aligned with executable behavior."""

import ast
import json
from pathlib import Path
import re

import pytest

import gui_tls
import tier_auth


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "zensical"


def page(name):
    return " ".join((DOCS / name).read_text().split())


def test_capability_repair_does_not_claim_compose_run_drops_service_limits():
    compose = (ROOT / "server/docker-compose.yml").read_text()
    assert "cap_drop: [ALL]" in compose
    security = page("architecture/security-model.md")
    assert "`docker compose run` inherits `cap_drop: [ALL]`" in security
    assert "separate maintenance container" in security


def test_browser_override_custody_matches_durable_server_path(monkeypatch, tmp_path):
    monkeypatch.setenv("IRIS_CONFIG", str(tmp_path))
    assert Path(gui_tls._durable_key_path()) == tmp_path / "tls/gui-key.pem.age"
    rotations = page("admin-guide/rotations.md")
    assert "`gui-key.pem.age` on the server" in rotations
    assert "authenticated HTTPS" in rotations
    assert "never belongs in the server" not in rotations


@pytest.mark.parametrize("record", [False, True])
def test_management_file_formats_match_reader(record, tmp_path):
    token = "a" * tier_auth.MIN_TOKEN_BYTES
    path = tmp_path / "current"
    path.write_text(json.dumps({"scope": "management", "token": token})
                    if record else token)
    path.chmod(0o600)
    assert tier_auth.load_pair(str(path)) == (token.encode(), None)
    reference = page("reference/server-configuration.md")
    assert "Management files accept a raw token or a JSON record" in reference
    assert "distinct random values for management and observability" in reference
    assert "at least %d bytes long" % tier_auth.MIN_TOKEN_BYTES in reference


def test_idempotency_reference_lists_only_supported_routes():
    source = ast.parse((ROOT / "server/management_api.py").read_text())
    helper = next(node for node in ast.walk(source)
                  if isinstance(node, ast.FunctionDef)
                  and node.name == "idempotency_supported")
    module = ast.Module(body=[helper], type_ignores=[])
    namespace = {"re": re}
    exec(compile(module, "management_api.py", "exec"), namespace)
    supports = namespace["idempotency_supported"]
    reference = page("reference/console-api.md")
    retry = reference.split("## Retry supported POST requests", 1)[1].split("## ", 1)[0]
    routes = re.findall(r"`(/api/v1/[^`]+)`", retry)
    assert len(routes) == 6
    for route in routes:
        assert supports(route.replace("/api/v1/", "/api/"))
    for suffix in ("adopt", "onboard", "undeploy"):
        assert "`.../%s`" % suffix in retry
        assert supports("/api/devices/example/" + suffix)
    assert not supports("/api/devices/example/assign")
    assert "up to 24 hours" in retry
    assert "512-entry" in retry and "evict" in retry and "restart clears" in retry


def test_kubernetes_certificate_rotation_loads_new_listener_identity():
    rotations = page("admin-guide/rotations.md")
    management = rotations.split("## Rotate the management certificate", 1)[1]
    management = management.split("## Rotate the Console browser certificate", 1)[0]
    kubernetes = management.split("### On Kubernetes", 1)[1]
    assert kubernetes.index("Add the new issuing authority") < kubernetes.index(
        "Replace the pair") < kubernetes.index("Restart `deployment/iris-seed-server`")
    browser = rotations.split("## Rotate the Console browser certificate", 1)[1]
    assert "replace `iris-console-tls`, restart `deployment/iris-console`" in browser


def test_onboarding_capability_urls_are_documented_as_credentials():
    data_path = page("architecture/data-path.md")
    assert "Guest Shell uses short-lived capability URLs" in data_path
    assert "Treat those URLs as credentials" in data_path
    assert "Each fetch authenticates with the device id" not in data_path


def test_explicit_ssh_pin_fails_closed_without_changing_unset_default():
    reference = page("reference/device-configuration.md")
    assert "With this setting unset, the IOx agent disables host-key verification" in reference
    assert "configured path that is missing, unreadable, empty or not a regular file" in reference
    assert "stops SSH and SCP before connection" in reference
