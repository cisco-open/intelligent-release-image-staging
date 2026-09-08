# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Direct-store role CLI contracts."""
import csv
import io
import json
import os
import subprocess
import sys

import gui_fleet
import peer_policy


SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(SERVER_DIR, "iris-role")


def _run(tmp_path, *args):
    env = dict(os.environ, IRIS_STATE=str(tmp_path))
    return subprocess.run(
        [sys.executable, CLI] + list(args), env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def _policy(tmp_path):
    return peer_policy.load_policy(
        str(tmp_path / "peer-policy.json"),
        str(tmp_path / "peer-policy.lkg.json"))


def test_iris_role_is_executable_spdx_cli():
    assert os.path.isfile(CLI)
    assert os.access(CLI, os.X_OK)
    text = open(CLI).read()
    assert text.startswith("#!/usr/bin/env python3\n\n# Copyright 2026 Cisco")
    assert "SPDX-License-Identifier: Apache-2.0" in text


def test_iris_role_define_dry_run_writes_nothing_then_define_commits(tmp_path):
    preview = _run(tmp_path, "define", "boat", "--restricted", "--dry-run")
    assert preview.returncode == 0, preview.stderr
    assert "dry-run" in preview.stdout.lower()
    assert not (tmp_path / "peer-policy.json").exists()

    done = _run(tmp_path, "define", "boat", "--restricted")
    assert done.returncode == 0, done.stderr
    doc = _policy(tmp_path).document
    assert doc["roles"]["defs"]["boat"]["restricted"] is True
    assert doc["roles"]["defs"]["boat"]["peers"] == ["boat"]


def test_iris_role_set_bulk_and_explain_use_shared_coordinator(tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    for index in range(2):
        fleet.upsert({"device_id": "d%d" % index,
                      "device_ip": "10.0.0.%d" % (index + 1)})
    assert _run(tmp_path, "define", "boat", "--restricted").returncode == 0
    before = _policy(tmp_path).document
    refused = _run(tmp_path, "bulk", "boat", "d0", "d1")
    assert refused.returncode != 0
    assert "confirmation_required" in refused.stderr
    assert _policy(tmp_path).document == before
    preview = _run(tmp_path, "bulk", "boat", "d0", "d1", "--dry-run")
    token = json.loads(preview.stdout)["confirm_token"]
    result = _run(tmp_path, "bulk", "boat", "d0", "d1",
                  "--confirm", token)
    assert result.returncode == 0, result.stderr
    after = _policy(tmp_path).document
    assert after["revision"] == before["revision"] + 1
    assert after["roles"]["role_of"] == {"d0": "boat", "d1": "boat"}
    assert fleet.get_device("d0")["role"] == "boat"
    explained = _run(tmp_path, "explain", "d0")
    assert explained.returncode == 0, explained.stderr
    body = json.loads(explained.stdout)
    assert body["declared_role"] == body["enforced_role"] == "boat"
    assert body["role_drift"] is False


def test_iris_role_export_import_round_trip_final_wire_units(tmp_path):
    assert _run(tmp_path, "define", "boat", "--restricted",
                "--qos", "seed_up_bps=12500000",
                "--qos", "announce_min_interval_s=60").returncode == 0
    exported = _run(tmp_path, "export")
    assert exported.returncode == 0, exported.stderr
    rows = list(csv.DictReader(io.StringIO(exported.stdout)))
    assert rows[0]["role"] == "boat"
    assert rows[0]["seed_up_bps"] == "12500000"
    assert rows[0]["announce_min_interval_s"] == "60"
    assert "seed_up_mbit" not in rows[0]
    assert "announce_seconds" not in rows[0]
    assert not any(name.startswith("origin_") for name in rows[0])

    restored = tmp_path / "restored"
    restored.mkdir()
    path = restored / "roles.csv"
    path.write_text(exported.stdout)
    preview = _run(restored, "import", str(path), "--dry-run")
    assert preview.returncode == 0, preview.stderr
    token = json.loads(preview.stdout)["confirm_token"]
    result = _run(restored, "import", str(path), "--confirm", token)
    assert result.returncode == 0, result.stderr
    assert _policy(restored).document["roles"]["defs"] == \
        _policy(tmp_path).document["roles"]["defs"]


def test_iris_role_export_omits_state_and_define_replacement_clears_it(
        tmp_path):
    auth = str(tmp_path / "peer-policy.json")
    lkg = str(tmp_path / "peer-policy.lkg.json")
    peer_policy.define_role(auth, lkg, "boat", {
        "restricted": True,
        "qos": {"announce_min_interval_s": 60},
        "qos_state": {"seeder": {"numwant": 8}},
    }, "test", 1)

    exported = _run(tmp_path, "export")
    assert exported.returncode == 0, exported.stderr
    assert "qos_state" not in exported.stdout
    rows = list(csv.DictReader(io.StringIO(exported.stdout)))
    assert len(rows) == 1
    assert rows[0]["role"] == "boat"
    assert rows[0]["announce_min_interval_s"] == "60"

    preview = _run(
        tmp_path, "define", "boat", "--restricted",
        "--qos", "announce_min_interval_s=60", "--dry-run")
    assert preview.returncode == 0, preview.stderr
    payload = json.loads(preview.stdout)
    assert [payload[key] for key in (
        "member_delta", "origin_access_lost", "empty_permitted_sets",
        "role_pairs_stopped")] == [0, 0, 0, 0]
    assert payload["qos_changed"] is True
    assert payload["requires_confirmation"] is True

    refused = _run(
        tmp_path, "define", "boat", "--restricted",
        "--qos", "announce_min_interval_s=60")
    assert refused.returncode != 0
    assert "qos_state" in _policy(tmp_path).document["roles"]["defs"]["boat"]

    applied = _run(
        tmp_path, "define", "boat", "--restricted",
        "--qos", "announce_min_interval_s=60",
        "--confirm", payload["confirm_token"])
    assert applied.returncode == 0, applied.stderr
    definition = _policy(tmp_path).document["roles"]["defs"]["boat"]
    assert definition["qos"] == {"announce_min_interval_s": 60}
    assert "qos_state" not in definition


def test_iris_role_import_replacement_clears_all_omitted_state(tmp_path):
    auth = str(tmp_path / "peer-policy.json")
    lkg = str(tmp_path / "peer-policy.lkg.json")
    for index, role in enumerate(("boat", "fiber"), 1):
        peer_policy.define_role(auth, lkg, role, {
            "restricted": False,
            "qos_state": {"leecher": {
                "announce_min_interval_s": 40 + index}},
        }, "test", index)

    exported = _run(tmp_path, "export")
    assert exported.returncode == 0, exported.stderr
    assert "qos_state" not in exported.stdout
    source = tmp_path / "roles.csv"
    source.write_text(exported.stdout)

    preview = _run(tmp_path, "import", str(source), "--dry-run")
    assert preview.returncode == 0, preview.stderr
    payload = json.loads(preview.stdout)
    assert payload["qos_changed"] is True
    assert payload["requires_confirmation"] is True
    assert [payload[key] for key in (
        "member_delta", "origin_access_lost", "empty_permitted_sets",
        "role_pairs_stopped")] == [0, 0, 0, 0]

    applied = _run(
        tmp_path, "import", str(source), "--confirm", payload["confirm_token"])
    assert applied.returncode == 0, applied.stderr
    definitions = _policy(tmp_path).document["roles"]["defs"]
    assert set(definitions) == {"boat", "fiber"}
    assert all("qos_state" not in definition
               for definition in definitions.values())


def test_iris_role_import_rejects_duplicate_and_undefined_peer_without_write(
        tmp_path):
    header = "role,restricted,peers,origin,nets,on_stale\n"
    duplicate = tmp_path / "duplicate.csv"
    duplicate.write_text(header + "boat,true,boat,true,,\nboat,false,boat,true,,\n")
    result = _run(tmp_path, "import", str(duplicate))
    assert result.returncode != 0
    assert "duplicate role" in result.stderr.lower()
    assert not (tmp_path / "peer-policy.json").exists()

    bad_peer = tmp_path / "bad-peer.csv"
    bad_peer.write_text(header + "boat,true,boat;missing,true,,\n")
    result = _run(tmp_path, "import", str(bad_peer))
    assert result.returncode != 0
    assert "unknown role" in result.stderr.lower()
    assert not (tmp_path / "peer-policy.json").exists()

    duplicate_net = tmp_path / "duplicate-net.csv"
    duplicate_net.write_text(
        header + "boat,true,boat,true,10.0.0.1/24;10.0.0.0/24,\n")
    result = _run(tmp_path, "import", str(duplicate_net))
    assert result.returncode != 0
    assert "duplicate role network" in result.stderr.lower()
    assert not (tmp_path / "peer-policy.json").exists()


def test_iris_role_define_rejects_canonically_duplicate_networks(tmp_path):
    result = _run(tmp_path, "define", "boat", "--restricted",
                  "--net", "10.0.0.1/24", "--net", "10.0.0.0/24")
    assert result.returncode != 0
    assert "duplicate role network" in result.stderr.lower()
    assert not (tmp_path / "peer-policy.json").exists()


def test_iris_role_migrate_defaults_to_dry_run_and_quarantine_is_never_selected(
        tmp_path):
    fleet = gui_fleet.FleetStore(str(tmp_path))
    for device_id in ("d1", "d2"):
        fleet.upsert({"device_id": device_id, "device_ip": "10.0.0.1"})
    auth_path = str(tmp_path / "peer-policy.json")
    lkg_path = str(tmp_path / "peer-policy.lkg.json")
    peer_policy.define_role(auth_path, lkg_path, "boat", {
        "restricted": True, "peers": ["boat"]}, "test", 1)

    def assign(candidate):
        candidate["acls"]["old"] = {
            "rules": [{"seq": 10, "action": "deny",
                       "match": {"type": "any"}}]}
        candidate["assignments"].update(
            {"d1": "old", "d2": peer_policy.RESERVED_QUARANTINE})
    peer_policy.commit_mutation(
        auth_path, lkg_path, "assign", "migration-test", "test", 2, assign)
    before = _policy(tmp_path).document
    result = _run(tmp_path, "migrate", "old", "boat")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    assert payload["devices"] == ["d1"]
    assert payload["shadowed_inert"] == ["d1"]
    assert payload["newly_restricted"] == ["d1"]
    assert payload["candidate_revision"] == before["revision"] + 2
    assert payload["confirm_token"]
    assert _policy(tmp_path).document == before

    stale = _run(tmp_path, "migrate", "old", "boat", "--apply",
                 "--confirm", "0" * 64)
    assert stale.returncode != 0
    assert "confirmation_required" in stale.stderr
    assert _policy(tmp_path).document == before

    applied = _run(tmp_path, "migrate", "old", "boat", "--apply",
                   "--confirm", payload["confirm_token"])
    assert applied.returncode == 0, applied.stderr
    result = json.loads(applied.stdout)
    assert result["newly_restricted"] == ["d1"]
    after = _policy(tmp_path).document
    assert after["revision"] == before["revision"] + 2
    assert after["roles"]["role_of"] == {"d1": "boat"}
    assert after["assignments"] == {
        "d2": peer_policy.RESERVED_QUARANTINE}
    assert fleet.get_device("d1")["role"] == "boat"
