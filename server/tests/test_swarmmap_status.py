# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Native swarm provenance plus executable regression coverage of the React map."""
from pathlib import Path
import shutil
import subprocess

import pytest

import auth
import telemetry


def test_react_map_behavior_regressions_use_shipped_model_and_controller():
    """The retired inline-JS harness is now an independent import-based suite.

    Cases retain stage/image provenance, drawer identity, malformed/late reads,
    signed interval preflight/confirmation/uncertainty, exact pull identities,
    and embedded/manual pause checks. The built-page browser suite separately
    checks actual React focus, filters, arrows, dialogs, responsive layout/CSP.
    """
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for map behavior tests")
    frontend = Path(__file__).resolve().parents[1] / "console-ui"
    result = subprocess.run(
        [node, "--test", "tests/swarm-map-acceptance.test.mjs"], cwd=frontend,
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_swarm_preserves_image_identity_and_separates_devices():
    devices = {"one": {"current_image_id": "os", "stage_state": "ready", "staged_image_ids": ["os"]},
               "two": {"current_image_id": "os", "stage_state": "staging", "staged_image_ids": []}}
    observation = {"schema": "v2", "image_id": "other", "obs_state": "observed",
                   "observed_received_at": 95, "valid": True, "aria": {"receive_bps": 123}}
    report = {"v": 2, "image_id": "other", "event": "staging-complete"}
    hub = telemetry.Telemetry(device_info=lambda: devices,
        images_info=lambda: {"os": {"info_hash_hex": "abc", "filename": "os.iso"}},
        live_info=lambda: {"samples": {"one": observation}},
        reports_info=lambda: {"one": [report]})
    for name in devices:
        hub.registry.announce("abc", name, "192.0.2.1", 6881, left=0, now=100,
                              principal=auth.Principal("device", name))
    image = hub.swarm_snapshot(now=100)["images"][0]
    assert image["image_id"] == "os"
    peers = {p["device_id"]: p for p in image["peers"]}
    assert peers["one"]["stage_state"] == "ready"
    assert peers["two"]["stage_state"] == "staging"
    assert peers["one"]["device_observation"]["image_id"] == "other"
    assert peers["one"]["latest_report"]["image_id"] == "other"
    assert "device_observation" not in peers["two"]


def test_shared_nat_ip_does_not_duplicate_one_devices_measured_send_rate():
    hub = telemetry.Telemetry()
    for name, port in (("one", 6881), ("two", 6882)):
        hub.registry.announce("abc", name, "192.0.2.1", port, left=100, now=100,
                              principal=auth.Principal("device", name))
    hub._torrent_observed_at = 100
    hub._peer_up = {"abc": {("192.0.2.1", 50000): 123}}
    peers = hub.swarm_snapshot(now=100)["images"][0]["peers"]
    assert all("server_observation" not in p for p in peers)
    # The origin connected to an unambiguous advertised listen endpoint.
    hub._peer_up = {"abc": {("192.0.2.1", 6882): 321}}
    peers = {p["device_id"]: p for p in hub.swarm_snapshot(now=100)["images"][0]["peers"]}
    assert "server_observation" not in peers["one"]
    assert peers["two"]["server_observation"]["peer"]["send_bps"] == 321


def test_shared_exact_endpoint_also_requires_unique_participant():
    hub = telemetry.Telemetry()
    for name in ("one", "two"):
        hub.registry.announce("abc", name, "192.0.2.1", 6881, left=100, now=100,
                              principal=auth.Principal("device", name))
    hub._torrent_observed_at = 100
    hub._peer_up = {"abc": {("192.0.2.1", 6881): 123}}
    assert all("server_observation" not in p
               for p in hub.swarm_snapshot(now=100)["images"][0]["peers"])


def test_two_aria_clients_on_one_device_do_not_duplicate_address_rate():
    hub = telemetry.Telemetry()
    for peer, port in (("aria-old", 6881), ("aria-new", 6882)):
        hub.registry.announce("abc", peer, "192.0.2.1", port, left=100, now=100,
                              principal=auth.Principal("device", "one"))
    hub._torrent_observed_at = 100
    hub._peer_up = {"abc": {("192.0.2.1", 50000): 123}}
    assert all("server_observation" not in p
               for p in hub.swarm_snapshot(now=100)["images"][0]["peers"])
