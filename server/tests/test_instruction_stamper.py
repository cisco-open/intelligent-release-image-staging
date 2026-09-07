# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import base64
import copy
import datetime as dt
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import threading
import time

import pytest

import auth
import catalog
import gui_fleet
import instruction_keys
import instruction_stamper as stamper
import instructions
import keyed_state
import live_samples
import peer_endpoints
import peer_handouts
import peer_policy
import secretfs
import secrets_store


NOW = int(dt.datetime(2026, 9, 7, 12, tzinfo=dt.timezone.utc).timestamp())


class Fleet:
    def __init__(self, rows):
        self.rows = {row["device_id"]: row for row in rows}

    def get_device(self, device_id):
        return self.rows.get(device_id)

    def list_devices(self):
        return list(self.rows.values())


def _signature(blob):
    binary = b"SSHSIG" + struct.pack(">I", 1) + struct.pack(">I", len(blob)) + blob
    encoded = base64.b64encode(binary)
    return (b"-----BEGIN SSH SIGNATURE-----\n" + encoded +
            b"\n-----END SSH SIGNATURE-----\n")


def _cert(path, marker=b"certificate-a"):
    blob = struct.pack(">I", len(b"ssh-ed25519-cert-v01@openssh.com")) + \
        b"ssh-ed25519-cert-v01@openssh.com" + marker
    value = b"ssh-ed25519-cert-v01@openssh.com " + base64.b64encode(blob) + b" test\n"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(value)
    return value, blob


def _record(value="01" * 32, created_at=NOW - 10):
    return {"value": value,
            "key_id": hashlib.sha256(bytes.fromhex(value)).hexdigest(),
            "created_at": created_at, "expires_at": created_at + 2592000,
            "revoked": False, "_scope": "instructions"}


def _setup(tmp_path, now=NOW):
    paths = stamper.StamperPaths(
        str(tmp_path / "state"), str(tmp_path / "config"),
        str(tmp_path / "run"), str(tmp_path / "secrets.json"))
    cert, blob = _cert(instruction_keys.InstructionPaths(
        paths.state_dir, paths.config_dir, paths.run_dir).certificate)
    store = {"devices": {"device-1": {"instr_key": _record()}}, "seeder": {}}
    secrets_store.save(store, paths.secrets)
    fleet = Fleet([{"device_id": "device-1", "platform": "guestshell",
                    "registered_at": now - 20}])
    cat = catalog.CatalogStore(paths.state_dir)
    peer_policy.initialize(paths.policy_authoritative, paths.policy_lkg)
    marker = stamper.initialize_producer(
        "initialize", paths=paths, fleet=fleet, now=lambda: now)
    producer = stamper.InstructionStamper(
        paths=paths, fleet=fleet, catalog_store=cat, now=lambda: now,
        signer=lambda _body, _now: _signature(blob),
        certificate_info=lambda _cert, _now: {
            "valid_after": now - 100, "valid_before": now + 30 * 86400})
    return paths, fleet, cat, producer, marker, cert, blob


def _raw_stamp(cat):
    return cat._policies.get("device-1")["instr"]


def _policy_result(document, degraded=False):
    return peer_policy.PolicyResult(
        document, degraded=degraded, fail_closed=False,
        roles=peer_policy.compile_roles(document))


def _write_policy(paths, document):
    peer_policy.validate_document(document)
    peer_policy._atomic_write_json(paths.policy_lkg, document)
    peer_policy._atomic_write_json(paths.policy_authoritative, document)


def _observed_clean(address="10.0.0.2", now=NOW, optional=False):
    source = {
        "v": 2, "obs_state": "observed", "observed_at": now,
        "sample_seq": 7, "sampling_class": "good",
        "aria": {"status": "active", "completed_content_bytes": 1,
                 "total_content_bytes": 2, "receive_bps": 3,
                 "send_bps": 4, "connections": 1},
        "peer_connections": [{"ip": address}],
    }
    if optional:
        source.update({"transfer_id": "a" * 32, "image_id": "image-a",
                       "aria_session_id": "abc123"})
        source["peer_connections"][0].update({
            "port": 6881, "send_bps": 5, "receive_bps": 6,
            "peer_client_name": "aria2", "progress": 50.5})
    clean, truncated = live_samples.sanitize_observation(
        source, ["image-a"], live_samples.LIVE_PEER_ROWS_HARD_CAP)
    assert truncated is False
    return clean


def _observed_snapshot(device_id="device-1", address="10.0.0.2", now=NOW,
                       optional=False):
    table = live_samples.LiveTable()
    clean = _observed_clean(address=address, now=now, optional=optional)
    table.observe(device_id, clean, now, 1)
    return table.snapshot(now)


def _write_live(paths, rows, received=NOW, truncated=False):
    table = live_samples.LiveTable()
    for device_id, addresses in rows.items():
        clean, _was_truncated = live_samples.sanitize_observation({
            "v": 2, "obs_state": "observed", "observed_at": received,
            "sample_seq": 1, "sampling_class": "good",
            "aria": {"status": "active", "completed_content_bytes": 1,
                     "total_content_bytes": 2, "receive_bps": 3,
                     "send_bps": 4, "connections": len(addresses)},
            "peer_connections": [{"ip": address} for address in addresses],
        }, None, 0 if truncated else live_samples.LIVE_PEER_ROWS_HARD_CAP)
        table.observe(device_id, clean, received, 1)
    Path(paths.live_samples).parent.mkdir(parents=True, exist_ok=True)
    Path(paths.live_samples).write_text(json.dumps(
        table.snapshot(received), sort_keys=True))


def test_activation_stamping_role_publication_and_restart_noop(tmp_path):
    paths, fleet, cat, producer, marker, _cert_bytes, _blob = _setup(tmp_path)
    assert marker["mode"] == "initialize"
    assert producer.stamp_device("device-1") == "updated"
    stamp = _raw_stamp(cat)
    instructions.validate_stamp(stamp)
    assert stamp["epoch"] == marker["epoch"]
    assert stamp["instr_serial"] == 1
    assert stamp["role"] == "default"
    assert set(stamp["part"]) == {
        "peers", "qos_override", "control_override", "server_time"}
    shard = cat._policies._shard_path(keyed_state.bucket_of("device-1"))
    identity = (os.stat(shard).st_ino, Path(shard).read_bytes())
    restarted = stamper.InstructionStamper(
        paths=paths, fleet=fleet, catalog_store=catalog.CatalogStore(
            paths.state_dir), now=lambda: NOW,
        signer=producer.signer, certificate_info=producer.certificate_info)
    assert restarted.stamp_device("device-1") == "unchanged"
    assert (os.stat(shard).st_ino, Path(shard).read_bytes()) == identity

    state = stamper._read_role_state(paths)
    metadata = state["generations"][stamp["role_gen"]]
    artifact_path = stamper._artifact_path(
        paths, stamp["role"], stamp["role_gen"])
    body, signature = instructions.parse_role(Path(artifact_path).read_bytes())
    assert hashlib.sha256(body).hexdigest() == stamp["role_body_sha256"]
    assert stamper.signature_certificate_blob(signature) == \
        stamper.certificate_blob(_cert_bytes)
    assert metadata["state"] == "active" and metadata["temp_name"] is None


def test_stamp_seals_deterministically_without_persisting_device_ciphertext(
        tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    producer.stamp_device("device-1")
    stamp = _raw_stamp(cat)
    artifact = Path(stamper._artifact_path(
        paths, stamp["role"], stamp["role_gen"]))
    role_body, signature = instructions.parse_role(artifact.read_bytes())
    key = bytes.fromhex(_record()["value"])
    header = instructions.stamp_header("device-1", stamp)
    first = instructions.seal_parts(
        header, stamp["part"], role_body, signature, key)
    second = instructions.seal_parts(
        header, stamp["part"], role_body, signature, key)
    assert first == second
    opened_header, opened_role, opened_signature, opened_part = \
        instructions.open_parts(first, key)
    assert opened_header == header
    assert (opened_role, opened_signature, opened_part) == (
        role_body, signature, stamp["part"])
    for candidate in Path(paths.directory).rglob("*"):
        if candidate.is_file():
            assert b"IRIS-INSTR/1" not in candidate.read_bytes()
    assert b"device-1" not in artifact.read_bytes()
    assert _record()["value"].encode() not in artifact.read_bytes()


def test_serial_reservation_retry_burned_gap_and_history_loss(tmp_path):
    paths, _fleet, cat, _producer, marker, *_ = _setup(tmp_path)
    first = stamper._reserve(paths, "device-1", marker["epoch"], "a" * 64)
    assert first == stamper._reserve(
        paths, "device-1", marker["epoch"], "a" * 64) == 1
    second = stamper._reserve(paths, "device-1", marker["epoch"], "b" * 64)
    assert second == 2
    stamper._finalize(paths, "device-1", marker["epoch"], 2, "b" * 64)
    assert stamper._history(paths).get("device-1") == {
        "v": 1, "epoch": marker["epoch"], "high_water": 2,
        "reservation": None}
    stamper._history(paths).delete("device-1")
    with pytest.raises(stamper.StamperError, match="history_invalid"):
        stamper._admit(paths, marker, "device-1",
                       {"registered_at": NOW - 20}, _record())
    assert cat._policies.get("device-1") is None


@pytest.mark.parametrize("boundary", ["policy-directory-fsync", "finalize"])
def test_visible_stamp_ambiguity_retries_without_serial_or_inode_churn(
        boundary, tmp_path, monkeypatch):
    paths, _fleet, cat, producer, marker, *_ = _setup(tmp_path)
    real_finalize = stamper._finalize
    real_fsync = keyed_state._fsync_directory
    if boundary == "finalize":
        monkeypatch.setattr(
            stamper, "_finalize",
            lambda *_args: (_ for _ in ()).throw(
                OSError("injected finalize failure")))
    else:
        policy_dir = keyed_state.shard_dir(cat.policy_path)

        def fail_after_visible(directory):
            real_fsync(directory)
            if directory == policy_dir:
                raise OSError("injected policy directory ambiguity")

        monkeypatch.setattr(keyed_state, "_fsync_directory", fail_after_visible)
    with pytest.raises((OSError, stamper.StamperError)):
        producer.stamp_device("device-1")
    visible = _raw_stamp(cat)
    assert visible["instr_serial"] == 1
    shard = cat._policies._shard_path(keyed_state.bucket_of("device-1"))
    identity = (os.stat(shard).st_ino, Path(shard).read_bytes())
    monkeypatch.setattr(stamper, "_finalize", real_finalize)
    monkeypatch.setattr(keyed_state, "_fsync_directory", real_fsync)
    assert producer.stamp_device("device-1") == "unchanged"
    assert _raw_stamp(cat) == visible
    # Finalizing history is a different shard; the policy row is untouched.
    assert (os.stat(shard).st_ino, Path(shard).read_bytes()) == identity
    assert stamper._history(paths).get("device-1") == {
        "v": 1, "epoch": marker["epoch"], "high_water": 1,
        "reservation": None}


def test_missing_stamp_with_intact_history_uses_the_next_serial(tmp_path):
    _paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    producer.stamp_device("device-1")
    first = _raw_stamp(cat)
    cat._policies.update("device-1", lambda row: {
        key: value for key, value in row.items() if key != "instr"})
    assert producer.stamp_device("device-1") == "updated"
    assert _raw_stamp(cat)["instr_serial"] == first["instr_serial"] + 1


@pytest.mark.parametrize("row_first", [False, True], ids=["before-row", "after-row"])
def test_pending_post_activation_admission_resumes(row_first, tmp_path):
    paths, fleet, _cat, _producer, marker, *_ = _setup(tmp_path)
    device_id = "new-device"
    facts = {"state": "pending", "registered_at": NOW + 1,
             "created_at": NOW + 1}
    document = stamper._read_admissions(paths)
    document["devices"][device_id] = facts
    stamper._atomic_json(paths.admissions, document)
    if row_first:
        stamper._history(paths).put(
            device_id, stamper._zero_history(marker["epoch"]))
    stamper._admit(paths, marker, device_id,
                   {"registered_at": NOW + 1}, _record(created_at=NOW + 1))
    assert stamper._read_admissions(paths)["devices"][device_id]["state"] == "active"
    assert stamper._history(paths).get(device_id)["high_water"] == 0


def test_pending_admission_refuses_changed_lineage_and_nonzero_history(tmp_path):
    paths, _fleet, _cat, _producer, marker, *_ = _setup(tmp_path)
    document = stamper._read_admissions(paths)
    document["devices"]["new-device"] = {
        "state": "pending", "registered_at": NOW + 1,
        "created_at": NOW + 1}
    stamper._atomic_json(paths.admissions, document)
    stamper._history(paths).put("new-device", {
        "v": 1, "epoch": marker["epoch"], "high_water": 1,
        "reservation": None})
    with pytest.raises(stamper.StamperError):
        stamper._admit(paths, marker, "new-device",
                       {"registered_at": NOW + 2},
                       _record(created_at=NOW + 1))


def test_post_activation_admission_requires_both_frozen_times(tmp_path):
    paths, _fleet, _cat, _producer, marker, *_ = _setup(tmp_path)
    for registered, created in ((None, NOW + 1), (NOW + 1, NOW - 1)):
        with pytest.raises(stamper.StamperError, match="admission_refused"):
            stamper._admit(paths, marker, "new-%s" % created,
                           {"registered_at": registered},
                           _record(created_at=created))


def test_initialize_refuses_active_and_recover_advances_epoch(tmp_path):
    paths, fleet, _cat, _producer, marker, *_ = _setup(tmp_path)
    with pytest.raises(stamper.StamperError, match="activation_invalid"):
        stamper.initialize_producer(
            "initialize", paths=paths, fleet=fleet, now=lambda: NOW + 1)
    recovered = stamper.initialize_producer(
        "recover", paths=paths, fleet=fleet, now=lambda: NOW + 2)
    assert recovered["epoch"] > marker["epoch"]
    assert recovered["mode"] == "recover"
    assert stamper._history(paths).get("device-1") == \
        stamper._zero_history(recovered["epoch"])

    shard = stamper._history(paths)._shard_path(
        keyed_state.bucket_of("device-1"))
    Path(shard).write_text("{corrupt")
    recovered_again = stamper.initialize_producer(
        "recover", paths=paths, fleet=fleet, now=lambda: NOW + 3)
    assert recovered_again["epoch"] > recovered["epoch"]
    assert stamper._history(paths).get("device-1") == \
        stamper._zero_history(recovered_again["epoch"])


def test_daytime_recovery_issues_at_or_after_future_epoch_but_signs_real_now(
        tmp_path):
    paths, fleet, cat, producer, marker, *_ = _setup(tmp_path)
    recovered = stamper.initialize_producer(
        "recover", paths=paths, fleet=fleet, now=lambda: NOW)
    assert recovered["epoch"] == marker["epoch"] + 1
    sign_times = []
    original = producer.signer

    def signer(body, current):
        sign_times.append(current)
        return original(body, current)

    producer.signer = signer
    assert producer.stamp_device("device-1") == "updated"
    stamp = _raw_stamp(cat)
    assert stamp["issued_at"] >= recovered["epoch"]
    assert stamp["issued_at"] == stamp["part"]["server_time"]
    assert sign_times == [NOW]


def test_recovery_publishes_marker_last_and_preserves_established_handouts(
        tmp_path):
    paths, fleet, _cat, _producer, marker, *_ = _setup(tmp_path)
    peer_handouts.record_handout(
        paths.handouts, auth.Principal("device", "device-1"),
        [{"ip": "10.0.0.2", "port": 6881}], "a" * 40, NOW)
    os.unlink(peer_handouts.admissions_path(paths.handouts))
    with pytest.raises(stamper.StamperError, match="handout_unavailable"):
        stamper.initialize_producer(
            "recover", paths=paths, fleet=fleet, now=lambda: NOW + 1)
    assert stamper.read_activation(paths) == marker
    assert stamper._validated_activation_epoch(paths) == marker

    other = tmp_path / "missing-handout-row"
    paths2, fleet2, _cat2, _producer2, marker2, *_ = _setup(other)
    peer_handouts.record_handout(
        paths2.handouts, auth.Principal("device", "device-1"),
        [{"ip": "10.0.0.2", "port": 6881}], "a" * 40, NOW)
    rows = keyed_state.KeyedState(paths2.handouts)
    os.unlink(rows._shard_path(keyed_state.bucket_of("device-1")))
    with pytest.raises(stamper.StamperError, match="handout_unavailable"):
        stamper.initialize_producer(
            "recover", paths=paths2, fleet=fleet2, now=lambda: NOW + 1)
    assert stamper.read_activation(paths2) == marker2
    assert stamper._validated_activation_epoch(paths2) == marker2


def test_pass_preflight_detects_epoch_marker_mismatch_with_empty_fleet(tmp_path):
    paths, _fleet, _cat, producer, _marker, *_ = _setup(tmp_path)
    instruction_keys.new_epoch(instruction_keys.InstructionPaths(
        paths.state_dir, paths.config_dir, paths.run_dir), now=NOW + 1)
    producer.fleet = Fleet([])
    counts, errors, state = producer.run_once()
    assert counts == {"seen": 0, "updated": 0, "unchanged": 0, "failed": 0}
    assert errors == {"activation_invalid": 1}
    assert state == "degraded"


def test_active_admission_with_simultaneous_history_and_stamp_loss_refuses(
        tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    assert producer.stamp_device("device-1") == "updated"
    stamper._history(paths).delete("device-1")
    cat._policies.update("device-1", lambda row: {
        key: value for key, value in row.items() if key != "instr"})
    with pytest.raises(stamper.StamperError, match="history_invalid"):
        producer.stamp_device("device-1")


def test_same_device_concurrency_uses_one_serial(tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    outcomes = []
    threads = [threading.Thread(
        target=lambda: outcomes.append(producer.stamp_device("device-1")))
        for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert sorted(outcomes) == ["unchanged", "updated"]
    assert _raw_stamp(cat)["instr_serial"] == 1


def test_different_shard_admission_linearizes_at_19999_20000(tmp_path):
    paths, _fleet, _cat, _producer, marker, *_ = _setup(tmp_path)
    devices = {
        "seed-%05d" % index: {
            "state": "pending" if index == 19998 else "active",
            "registered_at": NOW - 20, "created_at": NOW - 10,
        }
        for index in range(stamper.MAX_DEVICES - 1)
    }
    stamper._atomic_json(paths.admissions, {
        "schema": stamper.ADMISSIONS_SCHEMA, "epoch": marker["epoch"],
        "devices": devices,
    })
    candidates = ["new-a", "new-b"]
    assert keyed_state.bucket_of(candidates[0]) != keyed_state.bucket_of(
        candidates[1])
    barrier = threading.Barrier(2)
    outcomes = []

    def work(device_id):
        try:
            barrier.wait()
            stamper._admit(
                paths, marker, device_id, {"registered_at": NOW + 1},
                _record(created_at=NOW + 1))
            outcomes.append("active")
        except stamper.StamperError:
            outcomes.append("refused")

    threads = [threading.Thread(target=work, args=(value,))
               for value in candidates]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert sorted(outcomes) == ["active", "refused"]
    assert len(stamper._read_admissions(paths)["devices"]) == \
        stamper.MAX_DEVICES
    # An existing active device never needs the full-registry lock to reserve.
    stamper._history(paths).put(
        "seed-00000", stamper._zero_history(marker["epoch"]))
    assert stamper._reserve(
        paths, "seed-00000", marker["epoch"], "e" * 64) == 1


def test_corrupt_or_regressed_history_is_found_before_noop(tmp_path):
    paths, _fleet, _cat, producer, marker, *_ = _setup(tmp_path)
    assert producer.stamp_device("device-1") == "updated"
    stamper._history(paths).put("device-1", {
        "v": 1, "epoch": marker["epoch"], "high_water": 0,
        "reservation": None})
    with pytest.raises(stamper.StamperError, match="history_invalid"):
        producer.stamp_device("device-1")


def test_superseded_callback_converges_to_current_key(tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    assert producer.stamp_device("device-1") == "updated"
    old = _raw_stamp(cat)
    store = secrets_store.load(paths.secrets)
    current = _record("02" * 32, created_at=NOW)
    store["devices"]["device-1"]["instr_key"] = current
    secrets_store.save(store, paths.secrets)
    assert producer.stamp_device(
        "device-1", expected_key_id=old["key_id"]) == "superseded"
    new = _raw_stamp(cat)
    assert new["key_id"] == current["key_id"]
    assert new["instr_serial"] == old["instr_serial"] + 1
    assert producer.stamp_device(
        "device-1", expected_key_id=current["key_id"]) == "unchanged"


def test_rotation_context_reuses_held_locks_without_recursive_acquisition(
        tmp_path, monkeypatch):
    paths, *_ = _setup(tmp_path)
    calls = []
    monkeypatch.setattr(
        stamper.InstructionStamper, "_stamp_locked",
        lambda _self, device_id, activation, expected_key_id=None:
        calls.append((device_id, activation["epoch"], expected_key_id))
        or "unchanged")
    with stamper.rotation_context("device-1", paths=paths):
        assert stamper.restamp_instruction_key(
            "device-1", expected_key_id="a" * 64) == "unchanged"
    assert calls == [("device-1", stamper.read_activation(paths)["epoch"],
                      "a" * 64)]


def test_rotation_context_epoch_mismatch_enters_no_mutation_body(tmp_path):
    paths, _fleet, cat, _producer, _marker, *_ = _setup(tmp_path)
    secret_before = Path(paths.secrets).read_bytes()
    policy_before = cat._policies.snapshot()
    instruction_keys.new_epoch(
        instruction_keys.InstructionPaths(
            paths.state_dir, paths.config_dir, paths.run_dir),
        now=NOW + 1)
    entered = []

    with pytest.raises(stamper.StamperError, match="activation_invalid"):
        with stamper.rotation_context("device-1", paths=paths):
            entered.append(True)

    assert entered == []
    assert Path(paths.secrets).read_bytes() == secret_before
    assert cat._policies.snapshot() == policy_before


def test_revoke_after_precommit_snapshot_removes_only_matching_stamp(
        tmp_path, monkeypatch):
    paths, _fleet, cat, producer, marker, *_ = _setup(tmp_path)
    cat._policies.put("device-1", {
        "approved_image_id": "image-a", "approved_image_ids": ["image-a"],
        "plans": {}})
    real_same_key = stamper._same_key
    calls = []

    def revoke_after_snapshot(candidate_paths, device_id, key_id):
        result = real_same_key(candidate_paths, device_id, key_id)
        calls.append(result)
        if len(calls) == 1:
            store = secrets_store.load(paths.secrets)
            store["devices"][device_id]["instr_key"]["revoked"] = True
            secrets_store.save(store, paths.secrets)
        return result

    monkeypatch.setattr(stamper, "_same_key", revoke_after_snapshot)
    with pytest.raises(stamper.StamperError, match="key_superseded"):
        producer.stamp_device("device-1")
    row = cat._policies.get("device-1")
    assert row == {
        "approved_image_id": "image-a", "approved_image_ids": ["image-a"],
        "plans": {}}
    history = stamper._history(paths).get("device-1")
    assert history["epoch"] == marker["epoch"]
    assert history["high_water"] == 1 and history["reservation"] is not None
    assert calls == [True, False]


def test_postcommit_cleanup_preserves_a_newer_current_key_stamp(
        tmp_path, monkeypatch):
    paths, _fleet, cat, producer, marker, *_ = _setup(tmp_path)
    real_same_key = stamper._same_key
    current = _record("04" * 32, created_at=NOW)
    calls = []
    newer = {}

    def replace_between_commit_and_cleanup(candidate_paths, device_id, key_id):
        result = real_same_key(candidate_paths, device_id, key_id)
        calls.append(result)
        if len(calls) == 1:
            store = secrets_store.load(paths.secrets)
            store["devices"][device_id]["instr_key"] = current
            secrets_store.save(store, paths.secrets)
            return result
        old = _raw_stamp(cat)
        desired = dict(old)
        desired.pop("instr_serial")
        desired["key_id"] = current["key_id"]
        digest = instructions.desired_digest(desired)
        serial = stamper._reserve(
            paths, device_id, marker["epoch"], digest)
        newer.update(desired, instr_serial=serial)
        cat._policies.update(device_id, lambda row: dict(row, instr=dict(newer)))
        stamper._finalize(paths, device_id, marker["epoch"], serial, digest)
        return False

    monkeypatch.setattr(stamper, "_same_key", replace_between_commit_and_cleanup)
    with pytest.raises(stamper.StamperError, match="key_superseded"):
        producer.stamp_device("device-1")
    assert _raw_stamp(cat) == newer
    assert newer["key_id"] == current["key_id"]
    assert newer["instr_serial"] == 2


def test_default_role_ignores_fleet_role_and_qos_schema_is_filtered(tmp_path):
    paths, fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    fleet.rows["device-1"]["role"] = "operator-string-must-not-win"
    producer.stamp_device("device-1")
    stamp = _raw_stamp(cat)
    assert stamp["role"] == "default"
    body, _signature_bytes = instructions.parse_role(Path(
        stamper._artifact_path(paths, "default", stamp["role_gen"])).read_bytes())
    role = instructions.parse_json(body)
    assert set(role["qos"]) == set(instructions.QOS_FIELDS)
    assert set(role["control"]) == set(instructions.CONTROL_FIELDS)
    forbidden = {"per_peer_bps", "fanout", "announce_min_interval_s",
                 "numwant", "handout_budget", "origin_up_bps"}
    assert forbidden.isdisjoint(role["qos"])


def test_role_global_base_and_only_differing_device_overrides(tmp_path):
    paths, *_ = _setup(tmp_path)
    document = peer_policy.base_document()
    document["roles"] = {
        "defs": {"edge": {"restricted": False,
                            "qos": {"max_peers": 20}}},
        "role_of": {"device-1": "edge"},
        "qos_default": {"max_peers": 10, "telemetry_pause": False},
        "qos_device": {"device-1": {
            "max_peers": 30, "telemetry_pause": True}},
    }
    peer_policy.validate_document(document)
    policy = _policy_result(document)
    semantic, base, effective = stamper.semantic_role(
        document, policy.roles, "device-1")
    assert semantic["qos"]["max_peers"] == base["max_peers"] == 20
    assert semantic["control"]["telemetry_pause"] is False
    part = stamper._effective_part(
        paths, policy, "device-1", "edge", False,
        document["roles"]["defs"]["edge"], base, effective, NOW,
        NOW + 600)
    assert part["qos_override"] == {"max_peers": 30}
    assert part["control_override"] == {"telemetry_pause": True}


def test_platform_is_only_resolved_from_trusted_fleet(tmp_path):
    paths, fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    fleet.rows["device-1"].pop("platform")
    cat.record_heartbeat("device-1", {"platform": "guestshell"})
    with pytest.raises(stamper.StamperError, match="platform_unresolved"):
        producer.stamp_device("device-1")
    assert cat._policies.get("device-1") is None


def test_embedded_certificate_match_rejects_a_to_b_to_a(tmp_path):
    paths, _fleet, cat, producer, marker, cert_a, _blob_a = _setup(tmp_path)
    cert_path = instruction_keys.InstructionPaths(
        paths.state_dir, paths.config_dir, paths.run_dir).certificate
    _cert_b, blob_b = _cert(str(tmp_path / "b.pub"), b"certificate-b")

    attempts = []

    def interleaved(_body, _now):
        attempts.append(True)
        Path(cert_path).write_bytes(_cert_b)
        signature = _signature(blob_b)
        Path(cert_path).write_bytes(cert_a)
        return signature

    producer.signer = interleaved
    with stamper.role_lock(paths):
        with pytest.raises(stamper.StamperError, match="role_unavailable"):
            stamper._publish_role_locked(
                paths, cat, *stamper.semantic_role(
                    peer_policy.load_policy(paths.policy_authoritative,
                                            paths.policy_lkg).document,
                    peer_policy.load_policy(paths.policy_authoritative,
                                            paths.policy_lkg).roles,
                    "device-1")[:1],
                marker["epoch"], NOW, signer=interleaved,
                certificate_info=producer.certificate_info)
    assert not stamper._read_role_state(paths)["generations"]
    assert len(attempts) == stamper.SIGN_RETRIES


def test_signer_change_a_b_a_has_distinct_b_and_reuses_original_a(tmp_path):
    paths, _fleet, cat, producer, marker, cert_a, blob_a = _setup(tmp_path)
    policy = peer_policy.load_policy(paths.policy_authoritative, paths.policy_lkg)
    semantic = stamper.semantic_role(
        policy.document, policy.roles, "device-1")[0]
    cert_path = instruction_keys.InstructionPaths(
        paths.state_dir, paths.config_dir, paths.run_dir).certificate
    with stamper.role_lock(paths):
        gen_a, body_a, *_ = stamper._publish_role_locked(
            paths, cat, semantic, marker["epoch"], NOW,
            signer=lambda *_args: _signature(blob_a),
            certificate_info=producer.certificate_info)

    cert_b, blob_b = _cert(str(tmp_path / "online-b.pub"), b"certificate-b")
    Path(cert_path).write_bytes(cert_b)
    with stamper.role_lock(paths):
        gen_b, body_b, *_ = stamper._publish_role_locked(
            paths, cat, semantic, marker["epoch"], NOW,
            signer=lambda *_args: _signature(blob_b),
            certificate_info=producer.certificate_info)
    assert gen_b != gen_a and body_b != body_a

    Path(cert_path).write_bytes(cert_a)
    with stamper.role_lock(paths):
        reused, reused_body, *_ = stamper._publish_role_locked(
            paths, cat, semantic, marker["epoch"], NOW,
            signer=lambda *_args: (_ for _ in ()).throw(
                AssertionError("existing A generation was re-signed")),
            certificate_info=producer.certificate_info)
    assert (reused, reused_body) == (gen_a, body_a)
    assert len(stamper._read_role_state(paths)["generations"]) == 2


def test_frozen_certificate_snapshot_is_validated_and_revocation_blocks_reuse(
        tmp_path, monkeypatch):
    paths, _fleet, cat, _producer, marker, certificate, blob = _setup(tmp_path)
    policy = peer_policy.load_policy(paths.policy_authoritative, paths.policy_lkg)
    semantic = stamper.semantic_role(
        policy.document, policy.roles, "device-1")[0]
    configured = instruction_keys.InstructionPaths(
        paths.state_dir, paths.config_dir, paths.run_dir).certificate
    candidates = []

    def validate(_paths, candidate, _roots, now=None):
        assert candidate != configured
        candidates.append(Path(candidate).read_bytes())
        return {"valid_after": NOW - 100,
                "valid_before": NOW + 30 * 86400}

    monkeypatch.setattr(
        instruction_keys, "validate_online_certificate", validate)
    with stamper.role_lock(paths):
        generation, *_ = stamper._publish_role_locked(
            paths, cat, semantic, marker["epoch"], NOW,
            signer=lambda *_args: _signature(blob))
    assert candidates == [certificate]

    def revoked(*_args, **_kwargs):
        raise instruction_keys.InstructionKeyError("revoked certificate")

    monkeypatch.setattr(
        instruction_keys, "validate_online_certificate", revoked)
    with stamper.role_lock(paths):
        with pytest.raises(stamper.StamperError, match="role_unavailable"):
            stamper._publish_role_locked(
                paths, cat, semantic, marker["epoch"], NOW,
                signer=lambda *_args: (_ for _ in ()).throw(
                    AssertionError("revoked generation was re-signed")))
    assert generation in stamper._read_role_state(paths)["generations"]

    paths2, _fleet2, cat2, producer2, _marker2, *_ = _setup(
        tmp_path / "no-op")
    assert producer2.stamp_device("device-1") == "updated"
    prior = _raw_stamp(cat2)
    producer2.certificate_info = revoked
    with pytest.raises(stamper.StamperError, match="role_unavailable"):
        producer2.stamp_device("device-1")
    assert _raw_stamp(cat2) == prior


@pytest.mark.parametrize("failure", [
    FileNotFoundError("missing signing key"),
    instruction_keys.InstructionKeyError("revoked certificate"),
    subprocess.TimeoutExpired("ssh-keygen", 10),
], ids=["missing", "revoked", "timeout"])
def test_signing_failures_are_fixed_code_and_publish_nothing(
        failure, tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)

    def fail(*_args):
        raise failure

    producer.signer = fail
    with pytest.raises(stamper.StamperError, match="^role_unavailable$"):
        producer.stamp_device("device-1")
    assert cat._policies.get("device-1") is None
    assert stamper._read_role_state(paths)["generations"] == {}


def test_role_pending_reconciliation_crash_boundaries_and_corruption(tmp_path):
    paths, _fleet, cat, producer, marker, *_ = _setup(tmp_path)
    policy = peer_policy.load_policy(paths.policy_authoritative, paths.policy_lkg)
    semantic = stamper.semantic_role(
        policy.document, policy.roles, "device-1")[0]
    with stamper.role_lock(paths):
        generation, *_ = stamper._publish_role_locked(
            paths, cat, semantic, marker["epoch"], NOW,
            signer=producer.signer, certificate_info=producer.certificate_info)
    state = stamper._read_role_state(paths)
    row = state["generations"][generation]
    final = stamper._artifact_path(paths, row["role"], generation)
    pending = os.path.join(paths.roles, ".pending-" + generation)
    os.replace(final, pending)
    row["state"], row["temp_name"] = "pending", ".pending-" + generation
    stamper._atomic_json(paths.role_state, state)
    with stamper.role_lock(paths):
        reconciled = stamper.reconcile_roles(paths, cat)
    assert reconciled["generations"][generation]["state"] == "active"
    assert os.path.exists(final) and not os.path.exists(pending)

    artifact = Path(final).read_bytes()
    Path(pending).write_bytes(artifact)
    row = reconciled["generations"][generation]
    row["state"], row["temp_name"] = "pending", ".pending-" + generation
    stamper._atomic_json(paths.role_state, reconciled)
    with stamper.role_lock(paths):
        reconciled = stamper.reconcile_roles(paths, cat)
    assert reconciled["generations"][generation]["state"] == "active"
    assert Path(final).read_bytes() == artifact and not os.path.exists(pending)

    Path(final).write_bytes(artifact[:-2] + b"X\n")
    with stamper.role_lock(paths):
        with pytest.raises(stamper.StamperError, match="role_unavailable"):
            stamper._validated_active_artifact(
                paths, generation, reconciled["generations"][generation])
    Path(final).write_bytes(artifact)

    state = stamper._read_role_state(paths)
    row = state["generations"][generation]
    row["state"], row["temp_name"] = "pending", ".pending-" + generation
    row["unreferenced_at"] = None
    stamper._atomic_json(paths.role_state, state)
    os.unlink(final)
    with stamper.role_lock(paths):
        with pytest.raises(stamper.StamperError, match="role_unavailable"):
            stamper.reconcile_roles(paths, cat)
    assert stamper._read_role_state(paths)["generations"][generation][
        "state"] == "pending"


@pytest.mark.parametrize("boundary", [
    "pending-file-fsync", "pending-index", "final-directory-fsync",
    "active-index",
])
def test_role_publication_fault_boundaries_retry_without_unsafe_reference(
        boundary, tmp_path, monkeypatch):
    paths, _fleet, cat, producer, marker, *_ = _setup(tmp_path)
    policy = peer_policy.load_policy(paths.policy_authoritative, paths.policy_lkg)
    semantic = stamper.semantic_role(
        policy.document, policy.roles, "device-1")[0]
    real_atomic_json = stamper._atomic_json
    real_fsync = stamper._fsync_directory
    sign_calls = []
    original_signer = producer.signer

    def signer(body, current):
        sign_calls.append((body, current))
        return original_signer(body, current)

    role_json_calls = []
    role_fsync_calls = []

    def atomic_json(path, value):
        real_atomic_json(path, value)
        if path == paths.role_state:
            role_json_calls.append(value)
            target = 1 if boundary == "pending-index" else 2
            if boundary in ("pending-index", "active-index") \
                    and len(role_json_calls) == target:
                raise OSError("injected indexed publication ambiguity")

    def fsync(directory):
        real_fsync(directory)
        if directory == paths.roles:
            role_fsync_calls.append(directory)
            target = 1 if boundary == "pending-file-fsync" else 2
            if boundary in ("pending-file-fsync", "final-directory-fsync") \
                    and len(role_fsync_calls) == target:
                raise OSError("injected role directory ambiguity")

    monkeypatch.setattr(stamper, "_atomic_json", atomic_json)
    monkeypatch.setattr(stamper, "_fsync_directory", fsync)
    with stamper.role_lock(paths):
        with pytest.raises(OSError):
            stamper._publish_role_locked(
                paths, cat, semantic, marker["epoch"], NOW, signer=signer,
                certificate_info=producer.certificate_info)
    assert cat._policies.get("device-1") is None

    monkeypatch.setattr(stamper, "_atomic_json", real_atomic_json)
    monkeypatch.setattr(stamper, "_fsync_directory", real_fsync)
    with stamper.role_lock(paths):
        generation, body, *_ = stamper._publish_role_locked(
            paths, cat, semantic, marker["epoch"], NOW, signer=signer,
            certificate_info=producer.certificate_info)
    assert instructions.parse_json(body)["issued_at"] == marker["epoch"]
    assert stamper._read_role_state(paths)["generations"][generation][
        "state"] == "active"
    assert len(sign_calls) == (2 if boundary == "pending-file-fsync" else 1)


def test_unindexed_pending_cleanup_requires_no_policy_reference(tmp_path):
    paths, _fleet, cat, _producer, _marker, *_ = _setup(tmp_path)
    orphan = os.path.join(paths.roles, ".pending-" + "f" * 64)
    Path(paths.roles).mkdir(parents=True, exist_ok=True)
    Path(orphan).write_bytes(b"unindexed")
    with stamper.role_lock(paths):
        stamper.reconcile_roles(paths, cat)
    assert not os.path.exists(orphan)

    referenced_generation = "e" * 64
    referenced = os.path.join(
        paths.roles, ".pending-" + referenced_generation)
    Path(referenced).write_bytes(b"referenced must not be deleted")
    _paths, _fleet, other_cat, other_producer, _marker, *_ = _setup(
        tmp_path / "other")
    other_producer.stamp_device("device-1")
    referenced_stamp = dict(_raw_stamp(other_cat),
                            role_gen=referenced_generation)
    cat._policies.put("device-1", {
        "approved_image_id": None, "approved_image_ids": [], "plans": {},
        "instr": referenced_stamp})
    with stamper.role_lock(paths):
        with pytest.raises(stamper.StamperError, match="role_unavailable"):
            stamper.reconcile_roles(paths, cat)
    assert Path(referenced).read_bytes() == b"referenced must not be deleted"


def test_role_state_exact_generation_cap_and_duplicate_active_tuple():
    generations = {}
    for index in range(stamper.MAX_GENERATIONS):
        generation = "%064x" % index
        generations[generation] = {
            "state": "pending", "epoch": 1, "role": "role-%04d" % index,
            "day": "2026-09-07", "semantic_body_sha256": "%064x" % index,
            "cert_sha256": "a" * 64, "issued_at": NOW,
            "expires_at": NOW + 1, "artifact_sha256": "b" * 64,
            "temp_name": ".pending-" + generation,
            "unreferenced_at": None,
        }
    document = {"schema": stamper.ROLE_STATE_SCHEMA,
                "generations": generations}
    assert stamper._validate_role_state(document) is document
    generations["f" * 64] = dict(next(iter(generations.values())),
                                  temp_name=".pending-" + "f" * 64)
    with pytest.raises(stamper.StamperError, match="role_unavailable"):
        stamper._validate_role_state(document)

    one = dict(next(iter(generations.values())), state="active",
               temp_name=None)
    duplicate = dict(one)
    duplicate["artifact_sha256"] = "c" * 64
    with pytest.raises(stamper.StamperError, match="role_unavailable"):
        stamper._validate_role_state({
            "schema": stamper.ROLE_STATE_SCHEMA,
            "generations": {"1" * 64: one, "2" * 64: duplicate}})


def test_role_gc_retention_before_equal_after_and_reference_reappearance(
        tmp_path):
    paths, _fleet, cat, producer, marker, *_ = _setup(tmp_path)
    producer.stamp_device("device-1")
    stamp = _raw_stamp(cat)
    expiry = stamp["expires_at"]
    cat._policies.update("device-1", lambda row: {
        key: value for key, value in row.items() if key != "instr"})
    assert stamper.gc_roles(paths, cat, now=expiry)
    state = stamper._read_role_state(paths)
    first = state["generations"][stamp["role_gen"]]["unreferenced_at"]
    assert not stamper.gc_roles(paths, cat, now=first + stamper.MAX_TTL - 1)
    cat._policies.update("device-1", lambda row: dict(row, instr=stamp))
    assert stamper.gc_roles(paths, cat, now=first + stamper.MAX_TTL)
    assert stamper._read_role_state(paths)["generations"][
        stamp["role_gen"]]["unreferenced_at"] is None
    cat._policies.update("device-1", lambda row: {
        key: value for key, value in row.items() if key != "instr"})
    stamper.gc_roles(paths, cat, now=first + stamper.MAX_TTL)
    second = stamper._read_role_state(paths)["generations"][
        stamp["role_gen"]]["unreferenced_at"]
    assert stamper.gc_roles(paths, cat, now=second + stamper.MAX_TTL)
    assert stamp["role_gen"] not in stamper._read_role_state(paths)["generations"]


def test_role_gc_refuses_corrupt_reference_snapshot_and_serializes_reappearance(
        tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    producer.stamp_device("device-1")
    stamp = _raw_stamp(cat)
    artifact = Path(stamper._artifact_path(
        paths, stamp["role"], stamp["role_gen"]))
    cat._policies.put("corrupt", {
        "approved_image_id": None, "approved_image_ids": [], "plans": {},
        "instr": {"unknown": True}})
    with pytest.raises(stamper.StamperError, match="stamp_invalid"):
        stamper.gc_roles(paths, cat, now=stamp["expires_at"] + stamper.MAX_TTL)
    assert artifact.exists()
    corrupt_shard = cat._policies._shard_path(keyed_state.bucket_of("corrupt"))
    assert corrupt_shard != cat._policies._shard_path(
        keyed_state.bucket_of("device-1"))
    os.unlink(corrupt_shard)  # explicit operator repair between test phases

    cat._policies.update("device-1", lambda row: {
        key: value for key, value in row.items() if key != "instr"})
    stamper.gc_roles(paths, cat, now=stamp["expires_at"])
    boundary = stamp["expires_at"] + stamper.MAX_TTL
    completed = []
    with stamper.role_lock(paths):
        worker = threading.Thread(target=lambda: completed.append(
            stamper.gc_roles(paths, cat, now=boundary)))
        worker.start()
        cat._policies.update("device-1", lambda row: dict(row, instr=stamp))
        assert completed == []
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert completed == [True]
    assert artifact.exists()
    assert stamper._read_role_state(paths)["generations"][
        stamp["role_gen"]]["unreferenced_at"] is None


def test_status_loop_is_failure_isolated_and_secret_free(tmp_path):
    paths, *_ = _setup(tmp_path)
    canaries = ["device-secret", "10.23.45.67", "/private/path", "signature"]

    class Broken:
        def __init__(self):
            self.paths = paths

        def now(self):
            return NOW

        def run_once(self):
            raise RuntimeError(" ".join(canaries))

    class Stop:
        def wait(self, _interval):
            return True

    stamper.status_loop(Stop(), stamper=Broken())
    text = Path(paths.status).read_text()
    assert all(value not in text for value in canaries)
    assert json.loads(text) == {
        "schema": stamper.STATUS_SCHEMA, "updated_at": NOW,
        "last_success_at": None, "state": "degraded",
        "counts": {"seen": 0, "updated": 0, "unchanged": 0, "failed": 1},
        "errors": {"stamp_commit": 1}}

    clock_calls = []
    clock_canary = "clock private-path-canary"

    class BrokenClock(Broken):
        def now(self):
            clock_calls.append("now")
            raise RuntimeError(clock_canary)

    stamper.status_loop(Stop(), stamper=BrokenClock())
    clock_text = Path(paths.status).read_text()
    clock_status = json.loads(clock_text)
    assert clock_calls == ["now"]
    assert clock_canary not in clock_text
    assert all(value not in clock_text for value in canaries)
    assert clock_status["state"] == "degraded"
    assert clock_status["errors"] == {"stamp_commit": 1}


def test_role_device_and_status_write_failures_do_not_suppress_next_work(
        tmp_path, monkeypatch):
    paths, fleet, _cat, producer, _marker, *_ = _setup(tmp_path)
    fleet.rows["device-bad"] = {
        "device_id": "device-bad", "platform": "unsupported",
        "registered_at": NOW - 20}
    counts, errors, state = producer.run_once()
    assert counts == {"seen": 2, "updated": 1, "unchanged": 0, "failed": 1}
    assert errors == {"platform_unresolved": 1} and state == "degraded"

    outcomes = iter([
        stamper.StamperError("role_unavailable"), "updated",
        stamper.StamperError("role_unavailable"), "unchanged",
    ])

    def mixed(_device_id):
        value = next(outcomes)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(producer, "stamp_device", mixed)
    calls = []
    real_atomic = stamper._atomic_json

    def fail_first_status(path, document):
        calls.append(document)
        if len(calls) == 1:
            raise OSError("status disk full")
        return real_atomic(path, document)

    class TwoPasses:
        def __init__(self):
            self.calls = 0

        def wait(self, _interval):
            self.calls += 1
            return self.calls == 2

    monkeypatch.setattr(stamper, "_atomic_json", fail_first_status)
    stamper.status_loop(TwoPasses(), stamper=producer, interval=0)
    assert len(calls) == 2
    status = json.loads(Path(paths.status).read_text())
    assert status["counts"] == {
        "seen": 2, "updated": 0, "unchanged": 1, "failed": 1}
    assert status["errors"] == {"role_unavailable": 1}


def test_only_actual_lkg_provenance_sets_degraded_and_fail_closed_preserves(
        tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    Path(peer_policy.roles_watermark_path(
        paths.policy_authoritative)).touch()
    with pytest.raises(stamper.StamperError, match="policy_unavailable"):
        producer.stamp_device("device-1")
    assert cat._policies.get("device-1") is None

    Path(paths.policy_authoritative).write_text("{broken")
    assert producer.stamp_device("device-1") == "updated"
    degraded = _raw_stamp(cat)
    assert degraded["degraded"] is True
    restored = json.loads(Path(paths.policy_lkg).read_text())
    restored["roles"] = {
        "defs": {}, "role_of": {}, "qos_default": {}, "qos_device": {}}
    peer_policy.validate_document(restored)
    Path(paths.policy_authoritative).write_text(json.dumps(restored))
    assert producer.stamp_device("device-1") == "updated"
    healthy = _raw_stamp(cat)
    assert healthy["degraded"] is False
    assert healthy["instr_serial"] == degraded["instr_serial"] + 1

    Path(paths.policy_authoritative).write_text("{broken")
    Path(paths.policy_lkg).write_text("{also-broken")
    with pytest.raises(stamper.StamperError, match="policy_fail_closed"):
        producer.stamp_device("device-1")
    assert _raw_stamp(cat) == healthy


def test_daily_offset_boundaries_and_unrelated_revision_noop(tmp_path,
                                                              monkeypatch):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    producer.stamp_device("device-1")
    old = _raw_stamp(cat)
    doc = json.loads(Path(paths.policy_authoritative).read_text())
    doc["revision"] += 1
    Path(paths.policy_authoritative).write_text(json.dumps(doc))
    offset = instructions.daily_offset("device-1")
    midnight = NOW - NOW % 86400 + 86400
    for delta in (-1, 0, 1):
        producer.now = lambda value=midnight + offset + delta: value
        outcome = producer.stamp_device("device-1")
        if delta < 0:
            assert outcome == "unchanged"
            assert _raw_stamp(cat)["policy_revision"] == old["policy_revision"]
        elif delta == 0:
            assert outcome == "updated"
            assert _raw_stamp(cat)["instr_serial"] == old["instr_serial"] + 1
        else:
            assert outcome == "unchanged"


def test_peer_compiler_static_and_permit_all_do_not_read_dynamic_state(
        tmp_path, monkeypatch):
    paths, *_ = _setup(tmp_path)
    monkeypatch.setattr(
        stamper, "_endpoint_attribution",
        lambda *_args: (_ for _ in ()).throw(AssertionError("dynamic read")))

    document = peer_policy.base_document()
    document["roles"] = {
        "defs": {"edge": {"restricted": True, "nets": [
            "10.2.3.4/24", "192.0.2.9"]}},
        "role_of": {"device-1": "edge"},
        "qos_default": {}, "qos_device": {},
    }
    policy = _policy_result(document)
    static = stamper.compile_peers(
        paths, policy, "device-1", "edge", True,
        document["roles"]["defs"]["edge"], NOW, NOW + 600)
    assert static == {
        "mode": "allow", "allowed": ["10.2.3.0/24", "192.0.2.9/32"],
        "include_origin": True, "allowed_expires_at": NOW + 600,
    }

    open_policy = _policy_result(peer_policy.base_document())
    assert stamper.compile_peers(
        paths, open_policy, "device-1", "default", False, {}, NOW,
        NOW + 600) == {
            "mode": "deny", "rules": [], "include_origin": True,
            "allowed_expires_at": NOW + 600,
        }


def test_peer_compiler_mutual_roles_and_exact_allow_caps(tmp_path,
                                                          monkeypatch):
    paths, *_ = _setup(tmp_path)
    document = peer_policy.base_document()
    role_of = {"device-1": "edge"}
    role_of.update({"peer-%04d" % index: "edge" for index in range(1001)})
    document["roles"] = {
        "defs": {"edge": {"restricted": True, "peers": ["edge"]}},
        "role_of": role_of, "qos_default": {}, "qos_device": {},
    }
    policy = _policy_result(document)
    owner = auth.Principal("device", "device-1")
    by_ip = {"10.255.255.254": {owner}}
    expiries = {"10.255.255.254": NOW + 350}
    for index in range(1001):
        address = "10.%d.%d.%d" % (
            index // 65536, (index // 256) % 256, index % 256)
        by_ip[address] = {auth.Principal("device", "peer-%04d" % index)}
        expiries[address] = NOW + 400 + index % 10
    monkeypatch.setattr(stamper, "_endpoint_attribution",
                        lambda *_args: (by_ip, expiries))
    definition = document["roles"]["defs"]["edge"]

    first = by_ip.pop("10.0.3.232")
    first_expiry = expiries.pop("10.0.3.232")
    at_cap = stamper.compile_peers(
        paths, policy, "device-1", "edge", True, definition, NOW,
        NOW + 600)
    assert at_cap["mode"] == "allow" and len(at_cap["allowed"]) == 1000
    assert at_cap["allowed_expires_at"] == NOW + 350
    by_ip["10.0.3.232"], expiries["10.0.3.232"] = first, first_expiry
    assert stamper.compile_peers(
        paths, policy, "device-1", "edge", True, definition, NOW,
        NOW + 600) == {
            "mode": "tracker-only", "include_origin": True,
            "allowed_expires_at": NOW + 600,
        }


def test_peer_compiler_recipient_privacy_nat_conflict_and_deny_caps(
        tmp_path, monkeypatch):
    paths, *_ = _setup(tmp_path)
    peer_handouts.initialize(paths.handouts)
    document = peer_policy.base_document()
    document["acls"].update({
        "deny-all": {"rules": [{"seq": 10, "action": "deny",
                                  "match": {"type": "any"}}]},
        "mixed": {"rules": [
            {"seq": 10, "action": "permit",
             "match": {"type": "device", "value": "good"}},
            {"seq": 20, "action": "deny", "match": {"type": "any"}},
        ]},
    })
    document["assignments"].update({
        "device-1": "deny-all", "device-2": "deny-all"})
    policy = _policy_result(document)
    principals = {
        "10.0.0.10": {auth.Principal("device", "peer-a")},
        "10.0.0.20": {auth.Principal("device", "peer-b")},
    }
    expiries = {address: NOW + 300 for address in principals}
    monkeypatch.setattr(stamper, "_endpoint_attribution",
                        lambda *_args: (principals, expiries))
    _write_live(paths, {
        "device-1": ["10.0.0.10"], "device-2": ["10.0.0.20"]})
    one = stamper.compile_peers(
        paths, policy, "device-1", "default", False, {}, NOW, NOW + 600)
    two = stamper.compile_peers(
        paths, policy, "device-2", "default", False, {}, NOW, NOW + 600)
    assert one["rules"] == ["10.0.0.10"]
    assert two["rules"] == ["10.0.0.20"]
    assert one["allowed_expires_at"] == two["allowed_expires_at"] == NOW + 120

    shared = "10.0.0.30"
    principals[shared] = {
        auth.Principal("device", "good"), auth.Principal("device", "bad")}
    expiries[shared] = NOW + 300
    _write_live(paths, {"device-1": [shared]})
    document["assignments"]["device-1"] = "mixed"
    mixed = _policy_result(document)
    expiries[shared] = NOW + 30
    mixed_result = stamper.compile_peers(
        paths, mixed, "device-1", "default", False, {}, NOW,
        NOW + 600)
    assert mixed_result["rules"] == []
    assert mixed_result["allowed_expires_at"] == NOW + 30

    cap_addresses = sorted({
        "10.%d.%d.%d" % (index // 65536, (index // 256) % 256, index % 256)
        for index in range(4097)})
    live_address = cap_addresses[-1]
    monkeypatch.setattr(stamper, "_live_connections",
                        lambda *_args: ({live_address}, NOW + 120))
    principals.clear()
    principals.update({address: {auth.Principal("device", "bad")}
                       for address in cap_addresses})
    expiries.clear()
    expiries.update({address: NOW + 300 for address in cap_addresses})
    handouts = [{"address": address, "info_hash": "a" * 40,
                 "expires_at": NOW + 200}
                for address in cap_addresses[:-2]]
    monkeypatch.setattr(peer_handouts, "current_handouts",
                        lambda *_args: list(handouts))
    at_cap = stamper.compile_peers(
        paths, policy, "device-1", "default", False, {}, NOW, NOW + 600)
    assert at_cap["mode"] == "deny" and len(at_cap["rules"]) == 4096
    handouts.append({"address": cap_addresses[-2], "info_hash": "a" * 40,
                     "expires_at": NOW + 200})
    assert stamper.compile_peers(
        paths, policy, "device-1", "default", False, {}, NOW,
        NOW + 600)["mode"] == "tracker-only"


def test_peer_compiler_future_expired_and_truncated_evidence_refuses(
        tmp_path):
    paths, *_ = _setup(tmp_path)
    peer_handouts.initialize(paths.handouts)
    document = peer_policy.base_document()
    document["assignments"]["device-1"] = "quarantine"
    policy = _policy_result(document)
    for received, truncated in ((NOW + 1, False), (NOW - 120, False),
                                (NOW, True)):
        _write_live(paths, {"device-1": ["10.0.0.2"]},
                    received=received, truncated=truncated)
        assert stamper.compile_peers(
            paths, policy, "device-1", "default", False, {}, NOW,
            NOW + 600)["mode"] == "tracker-only"

    peer_endpoints.record_endpoint(
        paths.endpoints, auth.Principal("device", "peer-a"),
        "10.0.0.2", 6881, NOW + 1)
    assert stamper._endpoint_attribution(paths, NOW) == ({}, {})

    ttl = peer_endpoints.endpoint_ttl()
    peer_endpoints.record_endpoint(
        paths.endpoints, auth.Principal("device", "peer-expired"),
        "10.0.0.3", 6881, NOW - ttl)
    by_ip, _expiries = stamper._endpoint_attribution(paths, NOW)
    assert "10.0.0.3" not in by_ip

    peer_endpoints.record_endpoint(
        paths.endpoints, auth.Principal("device", "peer-a"),
        "10.0.0.2", 6881, NOW)
    _write_live(paths, {"device-1": ["10.0.0.2"]})
    live = json.loads(Path(paths.live_samples).read_text())
    live["samples"]["device-1"]["valid"] = False
    Path(paths.live_samples).write_text(json.dumps(live, sort_keys=True))
    assert stamper.compile_peers(
        paths, policy, "device-1", "default", False, {}, NOW,
        NOW + 600)["rules"] == ["10.0.0.2"]

    _write_live(paths, {"device-1": [
        "10.0.0.%d" % index for index in range(1, 34)]})
    assert stamper.compile_peers(
        paths, policy, "device-1", "default", False, {}, NOW,
        NOW + 600)["mode"] == "tracker-only"

    Path(paths.live_samples).write_bytes(
        b"{" + b" " * stamper.LIVE_SNAPSHOT_MAX)
    assert stamper.compile_peers(
        paths, policy, "device-1", "default", False, {}, NOW,
        NOW + 600)["mode"] == "tracker-only"


@pytest.mark.parametrize("delta,expected", [(-1, "unchanged"),
                                              (0, "updated"),
                                              (1, "updated")])
def test_dynamic_lease_renewal_window_boundaries(delta, expected, tmp_path,
                                                  monkeypatch):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    initial_expiry = NOW + 900

    def compiled(_paths, _policy, _device_id, _role, _restricted,
                 _definition, current, stamp_expiry):
        return {"mode": "allow", "allowed": ["10.0.0.2"],
                "include_origin": True,
                "allowed_expires_at": min(int(current) + 900, stamp_expiry)}

    monkeypatch.setattr(stamper, "compile_peers", compiled)
    assert producer.stamp_device("device-1") == "updated"
    assert _raw_stamp(cat)["part"]["peers"]["allowed_expires_at"] == \
        initial_expiry
    producer.now = lambda: initial_expiry - 120 + delta
    assert producer.stamp_device("device-1") == expected
    assert _raw_stamp(cat)["instr_serial"] == (1 if delta < 0 else 2)


def test_real_openssh_role_signature_and_corrupt_body_or_signature_refuses(
        tmp_path):
    key_paths = instruction_keys.InstructionPaths(
        str(tmp_path / "state"), str(tmp_path / "config"),
        str(tmp_path / "run"))
    plaintext = []

    def encrypt(source, destination, _recipients):
        plaintext.append(Path(source).read_bytes())
        Path(destination).parent.mkdir(parents=True, exist_ok=True)
        Path(destination).write_bytes(b"synthetic ciphertext")

    def decrypt(_source, destination, _identity):
        Path(destination).write_bytes(plaintext[0])

    instruction_keys.generate_online_key(
        key_paths, "age1synthetic", identity_file="synthetic-identity",
        encrypt_fn=encrypt, decrypt_fn=decrypt, timeout=10)

    def ssh(*args, data=None):
        return subprocess.run(["ssh-keygen", *map(str, args)], input=data,
                              check=True, capture_output=True, timeout=10)

    roots = {}
    for name in ("root-a", "root-b"):
        private = tmp_path / name
        ssh("-q", "-t", "ed25519", "-N", "", "-f", private)
        roots[name] = private
        target = Path(key_paths.roots_dir) / (name + ".pub")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(private) + ".pub", target)
    ceremony = tmp_path / "online.pub"
    shutil.copyfile(key_paths.public_key, ceremony)
    os.symlink(key_paths.runtime_key, tmp_path / "online")
    start = NOW - 3600
    end = start + instruction_keys.CERTIFICATE_LIFETIME_SECONDS
    stamp = lambda value: dt.datetime.fromtimestamp(
        value, dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    ssh("-q", "-s", roots["root-a"], "-I", "online", "-n", "iris-server",
        "-V", "%s:%s" % (stamp(start), stamp(end)), ceremony)
    certificate = tmp_path / "online-cert.pub"
    instruction_keys.import_online_certificate(
        key_paths, certificate,
        {name: Path(str(path) + ".pub") for name, path in roots.items()},
        now=NOW, timeout=10)

    paths = stamper.StamperPaths(
        key_paths.state_dir, key_paths.config_dir, key_paths.run_dir,
        str(tmp_path / "secrets.json"))
    cat = catalog.CatalogStore(paths.state_dir)
    policy = peer_policy.load_policy(paths.policy_authoritative, paths.policy_lkg)
    semantic = stamper.semantic_role(policy.document, policy.roles, "device-1")[0]
    with stamper.role_lock(paths):
        generation, body, signature, *_ = stamper._publish_role_locked(
            paths, cat, semantic, 1, NOW)
    allowed = tmp_path / "allowed"
    instruction_keys.write_allowed_signers(
        allowed, instruction_keys.ONLINE_PRINCIPAL,
        [Path(str(roots["root-a"]) + ".pub")],
        namespace=instruction_keys.INSTRUCTION_NAMESPACE,
        certificate_authority=True)
    assert instruction_keys.verify_signature(
        body, signature, allowed, instruction_keys.ONLINE_PRINCIPAL,
        instruction_keys.INSTRUCTION_NAMESPACE, verify_time=NOW)

    artifact = stamper._artifact_path(paths, "default", generation)
    original = Path(artifact).read_bytes()
    metadata = stamper._read_role_state(paths)["generations"][generation]
    for changed in (original.replace(base64.b64encode(body),
                                     base64.b64encode(body[:-1] + b"X")),
                    original.replace(base64.b64encode(signature),
                                     base64.b64encode(signature[:-8] + b"X" * 8))):
        Path(artifact).write_bytes(changed)
        with stamper.role_lock(paths):
            with pytest.raises(stamper.StamperError):
                stamper._validated_active_artifact(
                    paths, generation, metadata)
        Path(artifact).write_bytes(original)

    for path in list(roots.values()) + [Path(key_paths.runtime_key)]:
        try:
            Path(path).unlink()
        except FileNotFoundError:
            pass


def test_recover_refuses_total_established_handout_authority_loss_without_recreation(
        tmp_path):
    paths, fleet, _cat, _producer, _marker, *_ = _setup(tmp_path)
    admission = peer_handouts.admissions_path(paths.handouts)
    assert Path(admission).is_file()
    ledger = peer_handouts.HandoutLedger(paths.handouts, ttl=90)
    ledger.record(auth.Principal("device", "device-1"),
                  [{"ip": "10.0.0.2", "port": 6881}], "a" * 40, NOW)
    key_paths = instruction_keys.InstructionPaths(
        paths.state_dir, paths.config_dir, paths.run_dir)
    authority = {
        name: Path(path).read_bytes() for name, path in {
            "activation": paths.activation,
            "epoch": key_paths.epoch,
            "admissions": paths.admissions,
            "history": stamper._history(paths)._shard_path(
                keyed_state.bucket_of("device-1")),
        }.items()
    }
    Path(admission).unlink()
    shutil.rmtree(keyed_state.shard_dir(paths.handouts))

    for offset in (1, 2):
        with pytest.raises(stamper.StamperError, match="handout_unavailable"):
            stamper.initialize_producer(
                "recover", paths=paths, fleet=fleet,
                now=lambda value=NOW + offset: value)
        assert not Path(admission).exists()
        assert not Path(keyed_state.shard_dir(paths.handouts)).exists()
        assert Path(paths.activation).read_bytes() == authority["activation"]
        assert Path(key_paths.epoch).read_bytes() == authority["epoch"]
        assert Path(paths.admissions).read_bytes() == authority["admissions"]
        assert stamper._history(paths).get("device-1") == \
            json.loads(authority["history"])["device-1"]


def test_task13_s11_restrictive_stamp_survives_orphan_handout_admission_loss(
        tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    document = peer_policy.base_document()
    document["assignments"]["device-1"] = "quarantine"
    _write_policy(paths, document)
    peer_endpoints.record_endpoint(
        paths.endpoints, auth.Principal("device", "peer-a"),
        "10.0.0.2", 6881, NOW)
    _write_live(paths, {"device-1": []})
    ledger = peer_handouts.HandoutLedger(paths.handouts, ttl=90)
    assert ledger.record(
        auth.Principal("device", "device-1"),
        [{"ip": "10.0.0.2", "port": 6881}], "a" * 40, NOW)
    assert producer.stamp_device("device-1") == "updated"
    established = _raw_stamp(cat)
    assert established["part"]["peers"]["rules"] == ["10.0.0.2"]
    history_before = stamper._history(paths).get("device-1")

    admission_path = peer_handouts.admissions_path(paths.handouts)
    admissions = json.loads(Path(admission_path).read_text())
    del admissions["devices"]["device-1"]
    peer_handouts._write_document(admission_path, admissions)
    row_path = ledger.rows._shard_path(keyed_state.bucket_of("device-1"))
    row_before = Path(row_path).read_bytes()

    with pytest.raises(stamper.StamperError, match="handout_unavailable"):
        producer.stamp_device("device-1")
    assert _raw_stamp(cat) == established
    assert stamper._history(paths).get("device-1") == history_before
    assert Path(row_path).read_bytes() == row_before


def test_task13_s13_real_default_rotate_failure_resume_and_supersession(
        tmp_path, monkeypatch, capsys):
    now = int(time.time())
    state_dir = tmp_path / "state"
    config_dir = tmp_path / "config"
    run_dir = tmp_path / "run"
    secrets_path = run_dir / "secrets.json"
    encrypted_path = config_dir / "secrets.json.age"
    identity_path = tmp_path / "age-identity"
    for name, value in {
        "IRIS_STATE": state_dir,
        "IRIS_CONFIG": config_dir,
        "IRIS_RUN": run_dir,
        "IRIS_SECRETS": secrets_path,
        "IRIS_SECRETS_ENC": encrypted_path,
        "IRIS_AGE_KEY_FILE": identity_path,
    }.items():
        monkeypatch.setenv(name, os.fspath(value))

    subprocess.run(
        ["age-keygen", "-o", os.fspath(identity_path)], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    recipient = subprocess.run(
        ["age-keygen", "-y", os.fspath(identity_path)], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=10).stdout.strip()
    assert recipient.startswith("age1")
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", recipient)

    key_paths = instruction_keys.InstructionPaths(
        os.fspath(state_dir), os.fspath(config_dir), os.fspath(run_dir))
    instruction_keys.generate_online_key(
        key_paths, recipient, identity_file=identity_path, timeout=10)

    root_private = tmp_path / "root-ca"
    subprocess.run([
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
        os.fspath(root_private)], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10)
    root_public = Path(os.fspath(root_private) + ".pub")
    installed_root = Path(key_paths.roots_dir) / "root-a.pub"
    installed_root.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root_public, installed_root)
    second_root_private = tmp_path / "root-ca-b"
    subprocess.run([
        "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
        os.fspath(second_root_private)], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10)
    second_root_public = Path(os.fspath(second_root_private) + ".pub")
    shutil.copyfile(
        second_root_public, Path(key_paths.roots_dir) / "root-b.pub")
    ceremony = tmp_path / "online.pub"
    shutil.copyfile(key_paths.public_key, ceremony)
    cert_start = now - 3600
    cert_end = cert_start + instruction_keys.CERTIFICATE_LIFETIME_SECONDS
    timestamp = lambda value: dt.datetime.fromtimestamp(
        value, dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    subprocess.run([
        "ssh-keygen", "-q", "-s", os.fspath(root_private),
        "-I", "online", "-n", instruction_keys.ONLINE_PRINCIPAL,
        "-V", "%s:%s" % (timestamp(cert_start), timestamp(cert_end)),
        os.fspath(ceremony)], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10)
    candidate_certificate = tmp_path / "online-cert.pub"
    instruction_keys.import_online_certificate(
        key_paths, candidate_certificate,
        {"root-a": root_public, "root-b": second_root_public},
        now=now, timeout=10)

    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "device-1", "instr_key", now - 10)
    run_dir.mkdir(parents=True, exist_ok=True)
    secretfs.persist_store(
        store, os.fspath(secrets_path), recipients_csv=recipient,
        enc_path=os.fspath(encrypted_path))
    initial_store_digest = hashlib.sha256(json.dumps(
        store, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    old_key_id = store["devices"]["device-1"]["instr_key"]["key_id"]

    fleet = gui_fleet.FleetStore(
        os.fspath(state_dir), now_fn=lambda: now - 20)
    fleet.upsert({"device_id": "device-1", "device_ip": "192.0.2.1",
                  "platform": "guestshell"})
    paths = stamper.StamperPaths.from_env()
    peer_policy.initialize(paths.policy_authoritative, paths.policy_lkg)
    marker = stamper.initialize_producer(
        "initialize", paths=paths, fleet=fleet, now=lambda: now)
    assert stamper._history(paths).get("device-1") == \
        stamper._zero_history(marker["epoch"])

    cli_path = Path(__file__).parents[1] / "iris-instr-key"
    loader = importlib.machinery.SourceFileLoader(
        "iris_instr_key_task13_s13", os.fspath(cli_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    callback = cli.resolve_default_restamp()
    assert callback is stamper.restamp_instruction_key
    assert callback._iris_rotation_context is stamper.rotation_context

    assert cli.main(["restamp", "device-1"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "device_id": "device-1", "state": "updated"}
    cat = catalog.CatalogStore(os.fspath(state_dir))
    initial_stamp = _raw_stamp(cat)
    assert initial_stamp["key_id"] == old_key_id
    assert initial_stamp["instr_serial"] == 1

    certificate_bytes = Path(key_paths.certificate).read_bytes()
    parked_certificate = tmp_path / "parked-online-cert.pub"
    os.replace(key_paths.certificate, parked_certificate)
    callback_entered = threading.Event()
    release_callback = threading.Event()
    trace_timeouts = []
    rotation_results = []
    rotation_errors = []
    callback_code = stamper.restamp_instruction_key.__code__

    def observe_callback(frame, event, _arg):
        if event == "call" and frame.f_code is callback_code:
            sys.settrace(None)
            callback_entered.set()
            if not release_callback.wait(20):
                trace_timeouts.append("callback-release")
        return None

    def rotate_with_observer():
        sys.settrace(observe_callback)
        try:
            rotation_results.append(cli.main(["rotate", "device-1"]))
        except BaseException as exc:  # captured without exposing its value
            rotation_errors.append(type(exc).__name__)
        finally:
            sys.settrace(None)

    rotate_thread = threading.Thread(
        target=rotate_with_observer, name="s13-real-rotate")
    rotate_thread.start()
    try:
        assert callback_entered.wait(10)
        assert rotate_thread.is_alive()

        rotated_live = secrets_store.load(secrets_path)
        rotated_record = rotated_live["devices"]["device-1"]["instr_key"]
        rotated_key_id = rotated_record["key_id"]
        assert rotated_key_id != old_key_id
        assert rotated_live["devices"]["device-1"][
            "instr_key_prev"]["key_id"] == old_key_id
        rotated_store_digest = hashlib.sha256(json.dumps(
            rotated_live, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        assert rotated_store_digest != initial_store_digest
        recovered_path = run_dir / "handoff-decrypted-secrets.json"
        secretfs.decrypt_to(
            os.fspath(encrypted_path), os.fspath(recovered_path),
            os.fspath(identity_path))
        recovered_digest = hashlib.sha256(json.dumps(
            secrets_store.load(recovered_path), sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        assert recovered_digest == rotated_store_digest
        encrypted_digest = hashlib.sha256(
            encrypted_path.read_bytes()).hexdigest()

        lock_available = False
        lock_fd = os.open(os.fspath(secrets_path) + ".lock", os.O_RDWR)
        try:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_available = True
            except BlockingIOError:
                pass
            if lock_available:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
        assert lock_available
        assert rotate_thread.is_alive()
    finally:
        release_callback.set()
        rotate_thread.join(timeout=20)

    assert not rotate_thread.is_alive()
    assert trace_timeouts == []
    assert rotation_errors == []
    assert rotation_results == [1]
    failed_output = capsys.readouterr()
    assert failed_output.out == ""
    assert failed_output.err == (
        "iris-instr-key: instruction key rotation persisted; "
        "restamping is incomplete\n")
    assert _raw_stamp(cat) == initial_stamp
    assert stamper._history(paths).get("device-1")["high_water"] == 1

    os.replace(parked_certificate, key_paths.certificate)
    assert Path(key_paths.certificate).read_bytes() == certificate_bytes
    assert cli.main(["restamp", "device-1"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "device_id": "device-1", "state": "updated"}
    rotated_stamp = _raw_stamp(cat)
    assert rotated_stamp["key_id"] == rotated_key_id
    assert rotated_stamp["key_id"] != old_key_id
    assert rotated_stamp["instr_serial"] == initial_stamp["instr_serial"] + 1
    assert stamper._history(paths).get("device-1") == {
        "v": 1, "epoch": marker["epoch"],
        "high_water": rotated_stamp["instr_serial"], "reservation": None}

    artifact = Path(stamper._artifact_path(
        paths, rotated_stamp["role"], rotated_stamp["role_gen"]))
    role_body, signature = instructions.parse_role(artifact.read_bytes())
    allowed = tmp_path / "allowed-signers"
    instruction_keys.write_allowed_signers(
        allowed, instruction_keys.ONLINE_PRINCIPAL, [root_public],
        namespace=instruction_keys.INSTRUCTION_NAMESPACE,
        certificate_authority=True)
    assert instruction_keys.verify_signature(
        role_body, signature, allowed, instruction_keys.ONLINE_PRINCIPAL,
        instruction_keys.INSTRUCTION_NAMESPACE, verify_time=now)
    assert stamper.signature_certificate_blob(signature) == \
        stamper.certificate_blob(certificate_bytes)

    policy_shard = cat._policies._shard_path(
        keyed_state.bucket_of("device-1"))
    unchanged_identity = (os.stat(policy_shard).st_ino,
                          Path(policy_shard).read_bytes())
    assert cli.main(["restamp", "device-1"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "device_id": "device-1", "state": "unchanged"}
    assert (os.stat(policy_shard).st_ino,
            Path(policy_shard).read_bytes()) == unchanged_identity
    assert stamper.restamp_instruction_key(
        "device-1", expected_key_id=old_key_id) == "superseded"
    assert _raw_stamp(cat) == rotated_stamp
    assert hashlib.sha256(encrypted_path.read_bytes()).hexdigest() == \
        encrypted_digest
    assert hashlib.sha256(json.dumps(
        secrets_store.load(secrets_path), sort_keys=True,
        separators=(",", ":")).encode()).hexdigest() == rotated_store_digest


@pytest.mark.parametrize("version", [1.0, True, False])
def test_serial_history_version_is_an_exact_nonboolean_integer(
        version, tmp_path):
    paths, _fleet, _cat, _producer, _marker, *_ = _setup(tmp_path)
    history = stamper._history(paths)
    shard = history._shard_path(keyed_state.bucket_of("device-1"))
    document = json.loads(Path(shard).read_text())
    document["device-1"]["v"] = version
    Path(shard).write_text(json.dumps(document))
    with pytest.raises(stamper.StamperError, match="history_invalid"):
        stamper._history(paths).get("device-1")


def _two_role_setup(tmp_path):
    paths, fleet, cat, producer, marker, certificate, blob = _setup(tmp_path)
    store = secrets_store.load(paths.secrets)
    store["devices"]["device-2"] = {
        "instr_key": _record("02" * 32, created_at=NOW + 1)}
    secrets_store.save(store, paths.secrets)
    fleet.rows["device-2"] = {
        "device_id": "device-2", "platform": "guestshell",
        "registered_at": NOW + 1}
    producer.now = lambda: NOW + 2
    document = peer_policy.base_document()
    document["revision"] = 2
    document["roles"] = {
        "defs": {
            "role-a": {"restricted": False},
            "role-b": {"restricted": False},
        },
        "role_of": {"device-1": "role-a", "device-2": "role-b"},
        "qos_default": {}, "qos_device": {},
    }
    _write_policy(paths, document)
    return paths, fleet, cat, producer, marker, certificate, blob, document


def test_unrelated_corrupt_active_role_does_not_block_full_publication_after_restart(
        tmp_path):
    paths, fleet, cat, producer, _marker, _certificate, _blob, document = \
        _two_role_setup(tmp_path)
    counts, errors, state = producer.run_once()
    assert counts == {"seen": 2, "updated": 2, "unchanged": 0, "failed": 0}
    assert errors == {} and state == "ok"
    first_a = cat._policies.get("device-1")["instr"]
    first_b = cat._policies.get("device-2")["instr"]
    artifact_a = stamper._artifact_path(
        paths, "role-a", first_a["role_gen"])
    Path(artifact_a).write_bytes(b"corrupt unrelated role")
    document["revision"] += 1
    document["roles"]["defs"]["role-b"]["qos"] = {"max_peers": 9}
    _write_policy(paths, document)

    restarted = stamper.InstructionStamper(
        paths=paths, fleet=fleet,
        catalog_store=catalog.CatalogStore(paths.state_dir),
        now=lambda: NOW + 3, signer=producer.signer,
        certificate_info=producer.certificate_info)
    counts, errors, state = restarted.run_once()
    assert counts == {"seen": 2, "updated": 1, "unchanged": 0, "failed": 1}
    assert errors == {"role_unavailable": 1} and state == "degraded"
    assert cat._policies.get("device-1")["instr"] == first_a
    second_b = cat._policies.get("device-2")["instr"]
    assert second_b["instr_serial"] == first_b["instr_serial"] + 1
    role_b = instructions.parse_json(instructions.parse_role(Path(
        stamper._artifact_path(paths, "role-b", second_b["role_gen"])
    ).read_bytes())[0])
    assert role_b["qos"]["max_peers"] == 9

    restarted_again = stamper.InstructionStamper(
        paths=paths, fleet=fleet,
        catalog_store=catalog.CatalogStore(paths.state_dir),
        now=lambda: NOW + 3, signer=producer.signer,
        certificate_info=producer.certificate_info)
    counts, errors, state = restarted_again.run_once()
    assert counts == {"seen": 2, "updated": 0, "unchanged": 1, "failed": 1}
    assert errors == {"role_unavailable": 1} and state == "degraded"


def test_corrupt_referenced_role_still_fails_closed_after_restart(tmp_path):
    paths, fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    producer.stamp_device("device-1")
    established = _raw_stamp(cat)
    artifact = stamper._artifact_path(
        paths, established["role"], established["role_gen"])
    original = Path(artifact).read_bytes()
    Path(artifact).write_bytes(b"corrupt referenced role")
    restarted = stamper.InstructionStamper(
        paths=paths, fleet=fleet,
        catalog_store=catalog.CatalogStore(paths.state_dir),
        now=lambda: NOW, signer=producer.signer,
        certificate_info=producer.certificate_info)
    with pytest.raises(stamper.StamperError, match="role_unavailable"):
        restarted.stamp_device("device-1")
    assert _raw_stamp(cat) == established

    Path(artifact).write_bytes(original)
    role_state = Path(paths.role_state).read_bytes()
    Path(paths.role_state).unlink()
    with pytest.raises(stamper.StamperError, match="role_unavailable"):
        restarted.stamp_device("device-1")
    assert not Path(paths.role_state).exists()

    Path(paths.role_state).write_bytes(role_state)
    Path(paths.role_state).write_text("{broken")
    with pytest.raises(stamper.StamperError, match="role_unavailable"):
        restarted.stamp_device("device-1")
    assert _raw_stamp(cat) == established


def test_corrupt_unreferenced_deletion_candidate_fails_closed_and_preserves_state(
        tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    producer.stamp_device("device-1")
    stamp = _raw_stamp(cat)
    artifact = Path(stamper._artifact_path(
        paths, stamp["role"], stamp["role_gen"]))
    cat._policies.update("device-1", lambda row: {
        key: value for key, value in row.items() if key != "instr"})
    stamper.gc_roles(paths, cat, now=stamp["expires_at"])
    first = stamper._read_role_state(paths)["generations"][
        stamp["role_gen"]]["unreferenced_at"]
    artifact.write_bytes(b"corrupt deletion candidate")
    before = stamper._read_role_state(paths)
    with pytest.raises(stamper.StamperError, match="role_unavailable"):
        stamper.gc_roles(
            paths, catalog.CatalogStore(paths.state_dir),
            now=first + stamper.MAX_TTL)
    assert stamper._read_role_state(paths) == before
    assert artifact.read_bytes() == b"corrupt deletion candidate"


@pytest.mark.parametrize("unique_count", [1000, 1001])
def test_static_net_cap_uses_full_publication_at_1000_and_tracker_only_at_1001(
        unique_count, tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    networks = ["10.%d.%d.%d" % (
        index // 65536, (index // 256) % 256, index % 256)
        for index in range(unique_count)]
    networks.extend(networks[:2])
    document = peer_policy.base_document()
    document["revision"] = 2
    document["roles"] = {
        "defs": {"edge": {"restricted": True, "nets": networks}},
        "role_of": {"device-1": "edge"},
        "qos_default": {}, "qos_device": {},
    }
    _write_policy(paths, document)
    assert producer.stamp_device("device-1") == "updated"
    stamp = _raw_stamp(cat)
    artifact = Path(stamper._artifact_path(
        paths, "edge", stamp["role_gen"])).read_bytes()
    body_bytes, signature = instructions.parse_role(artifact)
    body = instructions.validate_role_body(instructions.parse_json(body_bytes))
    part = stamp["part"]
    if unique_count == 1000:
        assert len(body["allowed_nets"]) == 1000
        assert part["peers"]["mode"] == "allow"
        assert len(part["peers"]["allowed"]) == 1000
    else:
        assert "allowed_nets" not in body
        assert part["peers"] == {
            "mode": "tracker-only", "include_origin": True,
            "allowed_expires_at": stamp["expires_at"]}
    envelope = instructions.seal_parts(
        instructions.stamp_header("device-1", stamp), part,
        body_bytes, signature, bytes.fromhex(_record()["value"]))
    assert instructions.open_parts(envelope, bytes.fromhex(
        _record()["value"]))[3] == part


def test_live_snapshot_accepts_real_untruncated_v2_shape(tmp_path):
    paths, *_ = _setup(tmp_path)
    snapshot = _observed_snapshot()
    assert "peer_connections_truncated" not in snapshot["samples"]["device-1"]
    Path(paths.live_samples).write_text(json.dumps(snapshot, sort_keys=True))
    assert stamper._live_connections(paths, "device-1", NOW) == (
        {"10.0.0.2"}, NOW + live_samples.LIVE_VALUE_VALIDITY)


def test_live_snapshot_accepts_all_legitimate_stored_families(tmp_path):
    paths, *_ = _setup(tmp_path)
    table = live_samples.LiveTable()
    table.observe("device-1", _observed_clean(optional=True), NOW, 1)

    v1 = live_samples.sanitize_sample({
        "v": 1, "image_id": "image-a", "phase": "downloading",
        "tier": "good", "done_bytes": 1, "down_bps": 2,
        "up_bps": 3, "peers": 1}, ["image-a"])
    table.observe("legacy-v1", v1, NOW, 1)
    state, _ = live_samples.sanitize_observation({
        "v": 2, "obs_state": "not_due", "observed_at": NOW,
        "sample_seq": 2}, None, 32)
    table.observe("state-v2", state, NOW, 1)
    optional = _observed_clean(address="10.0.0.3", optional=True)
    table.observe("optional-v2", optional, NOW, 1)
    table.observe("withdraw-v1", v1, NOW, 1)
    table.withdraw("withdraw-v1")
    table.observe("withdraw-v2", optional, NOW, 1)
    table.withdraw("withdraw-v2", "disabled")
    snapshot = json.loads(json.dumps(table.snapshot(NOW)))
    Path(paths.live_samples).write_text(json.dumps(snapshot, sort_keys=True))
    assert stamper._live_connections(paths, "device-1", NOW)[0] == {
        "10.0.0.2"}


@pytest.mark.parametrize("malformed", [[], {}], ids=["array", "object"])
@pytest.mark.parametrize("site", [
    "v1-phase", "v1-tier", "v1-obs-state", "v2-obs-state",
    "v2-sampling-class", "aria-status",
])
def test_task13_s12_live_enums_require_exact_strings_and_preserve_safe_fallback(
        site, malformed, tmp_path):
    paths, _fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    table = live_samples.LiveTable()
    observed = _observed_clean(optional=True)
    table.observe("device-1", observed, NOW, 1)
    v1 = live_samples.sanitize_sample({
        "v": 1, "image_id": "image-a", "phase": "downloading",
        "tier": "good", "done_bytes": 1, "down_bps": 2,
        "up_bps": 3, "peers": 1}, ["image-a"])
    table.observe("legacy-v1", v1, NOW, 1)
    table.observe("withdraw-v1", v1, NOW, 1)
    table.withdraw("withdraw-v1")
    state, _ = live_samples.sanitize_observation({
        "v": 2, "obs_state": "not_due", "observed_at": NOW,
        "sample_seq": 2}, None, live_samples.LIVE_PEER_ROWS_HARD_CAP)
    table.observe("state-v2", state, NOW, 1)
    table.observe("observed-v2", _observed_clean(
        address="10.0.0.3", optional=True), NOW, 1)
    snapshot = json.loads(json.dumps(table.snapshot(NOW)))
    assert len(snapshot["samples"]) == 5
    Path(paths.live_samples).write_text(json.dumps(snapshot, sort_keys=True))
    assert stamper._live_connections(paths, "device-1", NOW)[0] == {
        "10.0.0.2"}

    document = peer_policy.base_document()
    document["assignments"]["device-1"] = "quarantine"
    _write_policy(paths, document)
    peer_endpoints.record_endpoint(
        paths.endpoints, auth.Principal("device", "peer-a"),
        "10.0.0.2", 6881, NOW)
    assert producer.stamp_device("device-1") == "updated"
    established = _raw_stamp(cat)
    assert established["part"]["peers"]["rules"] == ["10.0.0.2"]

    sample_name, field = {
        "v1-phase": ("legacy-v1", "phase"),
        "v1-tier": ("legacy-v1", "tier"),
        "v1-obs-state": ("withdraw-v1", "obs_state"),
        "v2-obs-state": ("state-v2", "obs_state"),
        "v2-sampling-class": ("observed-v2", "sampling_class"),
        "aria-status": ("observed-v2", "aria.status"),
    }[site]
    if field == "aria.status":
        snapshot["samples"][sample_name]["aria"]["status"] = malformed
    else:
        snapshot["samples"][sample_name][field] = malformed
    Path(paths.live_samples).write_text(json.dumps(snapshot, sort_keys=True))
    expected = {"mode": "tracker-only", "include_origin": True,
                "allowed_expires_at": established["expires_at"]}
    assert stamper.compile_peers(
        paths, _policy_result(document), "device-1", "default", False, {},
        NOW, established["expires_at"]) == expected
    assert producer.stamp_device("device-1") == "updated"
    replacement = _raw_stamp(cat)
    assert replacement["part"]["peers"] == expected
    assert replacement["instr_serial"] == established["instr_serial"] + 1


@pytest.mark.parametrize("damage", [
    "written-bool", "counter-bool", "counter-float", "sample-version-float",
    "sample-extra", "aria-extra", "aria-int-bool", "aria-int-float",
    "peer-port-bool", "peer-port-float", "peer-port-high", "peer-rate-bool",
    "peer-rate-high", "peer-progress-bool", "peer-progress-high",
    "peer-client-long", "truncated", "peer-row-cap", "future-observed-time",
    "retention-bool", "retention-low", "received-time-mismatch", "seq-mismatch",
])
def test_live_snapshot_requires_closed_exact_nested_types(
        damage, tmp_path):
    paths, *_ = _setup(tmp_path)
    snapshot = _observed_snapshot(optional=True)
    sample = snapshot["samples"]["device-1"]
    peer = sample["peer_connections"][0]
    if damage == "written-bool":
        snapshot["written_at"] = True
    elif damage == "counter-bool":
        snapshot["counters"]["samples_rejected_total"] = True
    elif damage == "counter-float":
        snapshot["counters"]["samples_rejected_total"] = 1.0
    elif damage == "sample-version-float":
        sample["v"] = 2.0
    elif damage == "sample-extra":
        sample["extra"] = 1
    elif damage == "aria-extra":
        sample["aria"]["extra"] = 1
    elif damage == "aria-int-bool":
        sample["aria"]["connections"] = True
    elif damage == "aria-int-float":
        sample["aria"]["connections"] = 1.0
    elif damage == "peer-port-bool":
        peer["port"] = True
    elif damage == "peer-port-float":
        peer["port"] = 6881.0
    elif damage == "peer-port-high":
        peer["port"] = 65536
    elif damage == "peer-rate-bool":
        peer["send_bps"] = True
    elif damage == "peer-rate-high":
        peer["receive_bps"] = live_samples._PEER_ROW_BPS_CAP + 1
    elif damage == "peer-progress-bool":
        peer["progress"] = True
    elif damage == "peer-progress-high":
        peer["progress"] = 100.1
    elif damage == "peer-client-long":
        peer["peer_client_name"] = "x" * 65
    elif damage == "truncated":
        sample["peer_connections_truncated"] = True
    elif damage == "peer-row-cap":
        sample["peer_connections"] = [dict(peer) for _ in range(33)]
    elif damage == "future-observed-time":
        sample["observed_received_at"] = NOW + 1
    elif damage == "retention-bool":
        sample["retention_seconds"] = True
    elif damage == "retention-low":
        sample["retention_seconds"] = live_samples.TICK_SECONDS
    elif damage == "received-time-mismatch":
        sample["received_at"] = NOW - 1
    elif damage == "seq-mismatch":
        sample["last_observed_seq"] += 1
    Path(paths.live_samples).write_text(json.dumps(snapshot, sort_keys=True))
    document = peer_policy.base_document()
    document["assignments"]["device-1"] = "quarantine"
    policy = _policy_result(document)
    assert stamper.compile_peers(
        paths, policy, "device-1", "default", False, {}, NOW,
        NOW + 600)["mode"] == "tracker-only"


def test_malformed_other_sample_invalidates_restrictive_deny_evidence(tmp_path):
    paths, *_ = _setup(tmp_path)
    snapshot = _observed_snapshot()
    snapshot["samples"]["other-device"] = dict(
        snapshot["samples"]["device-1"])
    snapshot["samples"]["other-device"]["aria"] = dict(
        snapshot["samples"]["other-device"]["aria"], unknown=1)
    Path(paths.live_samples).write_text(json.dumps(snapshot, sort_keys=True))
    document = peer_policy.base_document()
    document["assignments"]["device-1"] = "quarantine"
    assert stamper.compile_peers(
        paths, _policy_result(document), "device-1", "default", False, {},
        NOW, NOW + 600)["mode"] == "tracker-only"


def test_post_rename_reservation_retry_confirms_history_before_stamp(
        tmp_path, monkeypatch):
    paths, fleet, cat, producer, marker, *_ = _setup(tmp_path)
    history = stamper._history(paths)
    real_fsync = keyed_state._fsync_directory
    failed = []

    def fail_history(directory):
        row = history.get("device-1")
        if directory == history.dir and not failed \
                and row is not None and row["reservation"] is not None:
            failed.append(directory)
            raise OSError("injected pre-directory-fsync failure")
        return real_fsync(directory)

    monkeypatch.setattr(keyed_state, "_fsync_directory", fail_history)
    with pytest.raises(OSError, match="pre-directory-fsync"):
        producer.stamp_device("device-1")
    visible = stamper._history(paths).get("device-1")
    assert visible["high_water"] == 1 and visible["reservation"] is not None
    shard = history._shard_path(keyed_state.bucket_of("device-1"))
    identity = (os.stat(shard).st_ino, Path(shard).read_bytes())

    confirmations = []

    def confirm_history(directory):
        if directory == history.dir:
            confirmations.append(directory)
        return real_fsync(directory)

    monkeypatch.setattr(keyed_state, "_fsync_directory", confirm_history)
    # Isolate the matching reservation confirmation from the independent
    # active-admission history confirmation in this focused regression.
    monkeypatch.setattr(stamper, "_confirm_history", lambda *_args: None)
    original_update = cat._policies.update

    def guarded_commit(key, callback):
        assert confirmations
        assert (os.stat(shard).st_ino, Path(shard).read_bytes()) == identity
        return original_update(key, callback)

    monkeypatch.setattr(cat._policies, "update", guarded_commit)
    restarted = stamper.InstructionStamper(
        paths=paths, fleet=fleet, catalog_store=cat, now=lambda: NOW,
        signer=producer.signer, certificate_info=producer.certificate_info)
    assert restarted.stamp_device("device-1") == "updated"
    assert _raw_stamp(cat)["instr_serial"] == 1


def test_post_rename_policy_retry_confirms_stamp_before_unchanged(
        tmp_path, monkeypatch):
    paths, fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    policy_dir = cat._policies.dir
    real_fsync = keyed_state._fsync_directory
    failed = []

    def fail_policy(directory):
        if directory == policy_dir and not failed:
            failed.append(directory)
            raise OSError("injected pre-directory-fsync failure")
        return real_fsync(directory)

    monkeypatch.setattr(keyed_state, "_fsync_directory", fail_policy)
    with pytest.raises(stamper.StamperError, match="stamp_commit"):
        producer.stamp_device("device-1")
    visible = _raw_stamp(cat)
    shard = cat._policies._shard_path(keyed_state.bucket_of("device-1"))
    identity = (os.stat(shard).st_ino, Path(shard).read_bytes())
    confirmations = []

    def confirm_policy(directory):
        if directory == policy_dir:
            confirmations.append(directory)
        return real_fsync(directory)

    monkeypatch.setattr(keyed_state, "_fsync_directory", confirm_policy)
    restarted = stamper.InstructionStamper(
        paths=paths, fleet=fleet,
        catalog_store=catalog.CatalogStore(paths.state_dir),
        now=lambda: NOW, signer=producer.signer,
        certificate_info=producer.certificate_info)
    assert restarted.stamp_device("device-1") == "unchanged"
    assert confirmations
    assert _raw_stamp(cat) == visible
    assert (os.stat(shard).st_ino, Path(shard).read_bytes()) == identity
    assert visible["instr_serial"] == 1


@pytest.mark.parametrize("boundary", [
    "artifact", "pending-index", "active-index",
])
def test_role_publication_retry_reestablishes_artifact_and_index_durability(
        boundary, tmp_path, monkeypatch):
    paths, fleet, cat, producer, _marker, *_ = _setup(tmp_path)
    real_fsync = stamper._fsync_directory
    failed = []

    def fail_boundary(directory):
        if failed:
            return real_fsync(directory)
        state = None
        if Path(paths.role_state).exists():
            state = json.loads(Path(paths.role_state).read_text())
        generations = state.get("generations", {}) if state else {}
        states = {row["state"] for row in generations.values()}
        hit = (boundary == "artifact" and directory == paths.roles
               and any(Path(paths.roles).glob(".pending-*"))
               and not generations) \
            or (boundary == "pending-index" and directory == paths.directory
                and "pending" in states) \
            or (boundary == "active-index" and directory == paths.directory
                and "active" in states)
        if hit:
            failed.append(boundary)
            raise OSError("injected pre-directory-fsync failure")
        return real_fsync(directory)

    monkeypatch.setattr(stamper, "_fsync_directory", fail_boundary)
    with pytest.raises(OSError, match="pre-directory-fsync"):
        producer.stamp_device("device-1")
    assert failed == [boundary]
    role_files = list(Path(paths.roles).iterdir())
    artifacts = [path for path in role_files if path.is_file()]
    assert len(artifacts) == 1
    artifact_identity = (
        os.stat(artifacts[0]).st_ino, artifacts[0].read_bytes())
    active_state_identity = None
    if boundary == "active-index":
        active_state_identity = (
            os.stat(paths.role_state).st_ino, Path(paths.role_state).read_bytes())

    confirmations = []

    def confirmed(directory):
        confirmations.append(directory)
        return real_fsync(directory)

    monkeypatch.setattr(stamper, "_fsync_directory", confirmed)
    restarted = stamper.InstructionStamper(
        paths=paths, fleet=fleet,
        catalog_store=catalog.CatalogStore(paths.state_dir),
        now=lambda: NOW, signer=producer.signer,
        certificate_info=producer.certificate_info)
    assert restarted.stamp_device("device-1") == "updated"
    stamp = _raw_stamp(cat)
    final = Path(stamper._artifact_path(
        paths, stamp["role"], stamp["role_gen"]))
    assert (os.stat(final).st_ino, final.read_bytes()) == artifact_identity
    assert paths.roles in confirmations and paths.directory in confirmations
    assert stamp["instr_serial"] == 1
    if active_state_identity is not None:
        assert (os.stat(paths.role_state).st_ino,
                Path(paths.role_state).read_bytes()) == active_state_identity


def _task14_role_fixture(tmp_path):
    paths, _fleet, cat, producer, _marker, _certificate, _blob = _setup(tmp_path)
    producer.stamp_device("device-1")
    stamp = copy.deepcopy(_raw_stamp(cat))
    artifact = Path(paths.roles) / (stamp["role"] + "@" + stamp["role_gen"])
    return paths, stamp, artifact


def test_task14_role_snapshot_exact_artifact_and_independent_nested_copies(tmp_path):
    read = stamper.read_role_artifact_snapshot
    paths, stamp, artifact = _task14_role_fixture(tmp_path)
    body, signature = instructions.parse_role(artifact.read_bytes())
    expected = {"body_bytes": body, "signature_bytes": signature,
                "role": instructions.parse_json(body),
                "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}
    first = read(paths, stamp)
    assert first == expected
    first["role"]["control"]["telemetry_pause"] = True
    first["role"]["qos"]["max_peers"] = 999
    first["body_bytes"] = b"caller replacement"
    assert read(paths, stamp) == expected


@pytest.mark.parametrize("damage", ["extra", "missing-part", "boolean-serial",
                                         "unsafe-role", "bad-generation", "part-time"])
def test_task14_role_snapshot_validates_complete_stamp_before_paths(
        tmp_path, monkeypatch, damage):
    read = stamper.read_role_artifact_snapshot
    paths, stamp, _artifact = _task14_role_fixture(tmp_path)
    if damage == "extra":
        stamp["extra"] = 1
    elif damage == "missing-part":
        del stamp["part"]
    elif damage == "boolean-serial":
        stamp["instr_serial"] = True
    elif damage == "unsafe-role":
        stamp["role"] = "../../outside"
    elif damage == "bad-generation":
        stamp["role_gen"] = "../outside"
    else:
        stamp["part"]["server_time"] += 1

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid stamp reached producer paths or custody lock")

    monkeypatch.setattr(stamper, "role_lock", forbidden)
    monkeypatch.setattr(stamper, "_read_role_state", forbidden)
    with pytest.raises(stamper.StamperError) as error:
        read(paths, stamp)
    assert error.value.code == "role_unavailable"


def test_task14_role_snapshot_locks_complete_read_without_producer_side_effects(
        tmp_path, monkeypatch):
    import builtins

    read = stamper.read_role_artifact_snapshot
    paths, stamp, artifact = _task14_role_fixture(tmp_path)
    protected = [artifact, Path(paths.role_state)]
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in protected}
    real_open = builtins.open
    opened = []

    def locked_open(path, *args, **kwargs):
        if os.fspath(path) in {str(artifact), paths.role_state}:
            with real_open(paths.role_lock, "rb") as independent:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(independent.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            opened.append(os.fspath(path))
        return real_open(path, *args, **kwargs)

    def forbidden(*_args, **_kwargs):
        pytest.fail("GET snapshot invoked producer mutation or secrets custody")

    monkeypatch.setattr(builtins, "open", locked_open)
    for name in ("_fsync_directory", "reconcile_roles", "_policy_references",
                 "_atomic_bytes", "_atomic_json"):
        monkeypatch.setattr(stamper, name, forbidden)
    monkeypatch.setattr(secrets_store, "store_lock", forbidden)
    monkeypatch.setattr(instruction_keys, "sign_instruction", forbidden)
    read(paths, stamp)
    assert opened == [paths.role_state, str(artifact)]
    monkeypatch.setattr(builtins, "open", real_open)
    assert {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in protected} == before
    with open(paths.role_lock, "rb") as independent:
        fcntl.flock(independent.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(independent.fileno(), fcntl.LOCK_UN)


def test_task14_role_snapshot_missing_named_artifact_has_distinct_public_error(tmp_path):
    read = stamper.read_role_artifact_snapshot
    missing_type = stamper.RoleArtifactMissing
    assert issubclass(missing_type, stamper.StamperError)
    paths, stamp, artifact = _task14_role_fixture(tmp_path)
    artifact.unlink()
    with pytest.raises(missing_type):
        read(paths, stamp)


def test_task14_role_snapshot_bounds_artifact_read_before_parsing(tmp_path, monkeypatch):
    import builtins

    read = stamper.read_role_artifact_snapshot
    paths, stamp, artifact = _task14_role_fixture(tmp_path)
    artifact.write_bytes(b"x" * (instructions.INSTR_RESPONSE_MAX + 2))
    real_open = builtins.open
    reads = []

    class BoundedArtifact:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.stream.close()

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def read(self, size=-1):
            assert 0 <= size
            reads.append(size)
            assert sum(reads) <= instructions.INSTR_RESPONSE_MAX + 1
            return self.stream.read(size)

    def bounded_open(path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        return BoundedArtifact(stream) if os.fspath(path) == str(artifact) else stream

    monkeypatch.setattr(builtins, "open", bounded_open)
    with pytest.raises(stamper.StamperError) as error:
        read(paths, stamp)
    assert error.value.code == "role_unavailable"
    assert sum(reads) <= instructions.INSTR_RESPONSE_MAX + 1


@pytest.mark.parametrize("damage", [
    "missing-state", "missing-metadata", "pending-metadata", "extra-generation-field",
    "metadata-role", "metadata-epoch", "metadata-issued", "metadata-expiry",
    "metadata-semantic-digest", "metadata-certificate-digest", "artifact-digest",
    "stamp-body-digest", "stamp-epoch", "signature-only", "signature-structure",
    "body-identity", "oversize", "artifact-directory", "unreadable",
])
def test_task14_role_snapshot_rejects_corrupt_identity_signature_and_state(
        tmp_path, monkeypatch, damage):
    import builtins

    read = stamper.read_role_artifact_snapshot
    missing_type = stamper.RoleArtifactMissing
    paths, stamp, artifact = _task14_role_fixture(tmp_path)
    state_path = Path(paths.role_state)
    state = json.loads(state_path.read_text())
    metadata = state["generations"][stamp["role_gen"]]
    if damage == "missing-state":
        state_path.unlink()
    elif damage == "missing-metadata":
        state["generations"].clear()
    elif damage == "pending-metadata":
        metadata.update(state="pending", temp_name=".pending-" + stamp["role_gen"],
                        unreferenced_at=None)
    elif damage == "extra-generation-field":
        metadata["generation"] = stamp["role_gen"]
    elif damage == "metadata-role":
        metadata["role"] = "another-role"
    elif damage == "metadata-epoch":
        metadata["epoch"] -= 1
    elif damage == "metadata-issued":
        metadata["issued_at"] += 1
    elif damage == "metadata-expiry":
        metadata["expires_at"] -= 1
    elif damage == "metadata-semantic-digest":
        metadata["semantic_body_sha256"] = "0" * 64
    elif damage == "metadata-certificate-digest":
        metadata["cert_sha256"] = "0" * 64
    elif damage == "artifact-digest":
        metadata["artifact_sha256"] = "0" * 64
    elif damage == "stamp-body-digest":
        stamp["role_body_sha256"] = "0" * 64
    elif damage == "stamp-epoch":
        stamp["epoch"] -= 1
    elif damage in {"signature-only", "signature-structure", "body-identity"}:
        body, signature = instructions.parse_role(artifact.read_bytes())
        if damage == "signature-only":
            signature = _signature(b"different certificate")
        elif damage == "signature-structure":
            signature = b"not an armored ssh signature"
        else:
            parsed = instructions.parse_json(body)
            parsed["role"] = "another-role"
            body = instructions.canonical_json(parsed)
        changed = instructions.frame_role(body, signature)
        artifact.write_bytes(changed)
        if damage != "signature-only":
            # Remove the outer digest failure: structural and identity checks
            # must still reject even with internally updated artifact metadata.
            metadata["artifact_sha256"] = hashlib.sha256(changed).hexdigest()
    elif damage == "oversize":
        artifact.write_bytes(b"x" * (instructions.INSTR_RESPONSE_MAX + 1))
    elif damage == "artifact-directory":
        artifact.unlink()
        artifact.mkdir()
    elif damage == "unreadable":
        real_open = builtins.open

        def denied(path, *args, **kwargs):
            if os.fspath(path) == str(artifact):
                raise PermissionError("injected unavailable artifact")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", denied)
    if damage != "missing-state":
        state_path.write_text(json.dumps(state))
    with pytest.raises(stamper.StamperError) as error:
        read(paths, stamp)
    assert not isinstance(error.value, missing_type)
    assert error.value.code == "role_unavailable"
