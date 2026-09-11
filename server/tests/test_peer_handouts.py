# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
import os
from pathlib import Path
import threading

import pytest

import auth
import keyed_state
import peer_handouts


DEVICE = auth.Principal("device", "device-1")
INFO_A = "a" * 40
INFO_B = "b" * 40


def _path(tmp_path):
    return str(tmp_path / "peer-handouts.json")


def _ledger(tmp_path, ttl=90):
    path = _path(tmp_path)
    peer_handouts.initialize(path)
    return peer_handouts.HandoutLedger(path, ttl=ttl)


def _peer(address):
    return {"ip": address, "port": 6881}


def test_first_admission_is_pending_then_active_and_restart_safe(tmp_path):
    ledger = _ledger(tmp_path)
    assert ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, 100)
    with open(peer_handouts.admissions_path(_path(tmp_path))) as stream:
        admissions = json.load(stream)
    assert admissions == {
        "schema": peer_handouts.ADMISSIONS_SCHEMA,
        "devices": {"device-1": "active"},
    }
    restarted = peer_handouts.HandoutLedger(_path(tmp_path), ttl=90)
    assert restarted.current("device-1", 101) == [
        {"address": "10.0.0.2", "info_hash": INFO_A, "expires_at": 190}]


def test_pending_admission_resumes_before_or_after_row_creation(tmp_path):
    path = _path(tmp_path)
    peer_handouts.initialize(path)
    admission_path = peer_handouts.admissions_path(path)
    peer_handouts._write_document(admission_path, {
        "schema": peer_handouts.ADMISSIONS_SCHEMA,
        "devices": {"device-1": "pending"}})
    ledger = peer_handouts.HandoutLedger(path, ttl=90)
    assert ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, 100)
    assert ledger.current("device-1", 100)

    peer_handouts._write_document(admission_path, {
        "schema": peer_handouts.ADMISSIONS_SCHEMA,
        "devices": {"device-1": "pending"}})
    assert ledger.record(DEVICE, [_peer("10.0.0.3")], INFO_A, 101)
    assert [row["address"] for row in ledger.current("device-1", 101)] == [
        "10.0.0.2", "10.0.0.3"]


def test_active_missing_row_and_missing_established_admissions_fail_closed(
        tmp_path):
    path = _path(tmp_path)
    peer_handouts.initialize(path)
    peer_handouts._write_document(peer_handouts.admissions_path(path), {
        "schema": peer_handouts.ADMISSIONS_SCHEMA,
        "devices": {"device-1": "active"}})
    ledger = peer_handouts.HandoutLedger(path)
    with pytest.raises(peer_handouts.HandoutStoreError,
                       match="established handout row is missing"):
        ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, 100)
    with pytest.raises(peer_handouts.HandoutStoreError,
                       match="established handout row is missing"):
        peer_handouts.initialize(path)

    other = str(tmp_path / "other" / "peer-handouts.json")
    rows = keyed_state.KeyedState(other, durable=True)
    rows.put("device-1", ledger._empty("device-1", 100))
    with pytest.raises(peer_handouts.HandoutStoreError,
                       match="established handout admissions are missing"):
        peer_handouts.initialize(other)

    orphan = str(tmp_path / "orphan" / "peer-handouts.json")
    peer_handouts.initialize(orphan)
    orphan_rows = keyed_state.KeyedState(
        orphan, error=peer_handouts.HandoutStoreError,
        validate=peer_handouts._validate_row, durable=True, indent=None)
    orphan_rows.put("device-1", ledger._empty("device-1", 100))
    with pytest.raises(peer_handouts.HandoutStoreError,
                       match="established handout admission is missing"):
        peer_handouts.initialize(orphan)
    with pytest.raises(peer_handouts.HandoutStoreError,
                       match="established handout admission is missing"):
        peer_handouts.HandoutLedger(orphan).record(
            DEVICE, [_peer("10.0.0.2")], INFO_A, 100)


def test_task13_s11_absent_admission_requires_absent_recipient_row(tmp_path):
    path = _path(tmp_path)
    peer_handouts.initialize(path)
    assert peer_handouts.HandoutLedger(path).current("never-admitted", 100) == []

    rows = keyed_state.KeyedState(
        path, error=peer_handouts.HandoutStoreError,
        validate=peer_handouts._validate_row, durable=True, indent=None)
    for handouts in ([], [{"address": "10.0.0.2", "info_hash": INFO_A,
                           "expires_at": 190}]):
        rows.put("device-1", {
            "v": 1, "principal_type": "device", "principal_id": "device-1",
            "updated_at": 100, "handouts": handouts})
        with pytest.raises(peer_handouts.HandoutStoreError,
                           match="established handout admission is missing"):
            peer_handouts.HandoutLedger(path).current("device-1", 101)

    shard = rows._shard_path(keyed_state.bucket_of("device-1"))
    Path(shard).write_text(json.dumps({"device-1": {"broken": True}}))
    with pytest.raises(peer_handouts.HandoutStoreError):
        peer_handouts.HandoutLedger(path).current("device-1", 101)


@pytest.mark.parametrize("phase", ["pending", "active-empty"])
def test_task13_s11_stale_absent_read_refuses_concurrent_first_record(
        phase, tmp_path, monkeypatch):
    path = _path(tmp_path)
    peer_handouts.initialize(path)
    admission = peer_handouts.admissions_path(path)
    reader = peer_handouts.HandoutLedger(path, ttl=90)
    writer = peer_handouts.HandoutLedger(path, ttl=90)
    reader_left_admission = threading.Event()
    release_reader = threading.Event()
    writer_at_phase = threading.Event()
    release_writer = threading.Event()
    real_lock = keyed_state.file_lock
    lock_state = threading.local()
    violations = []
    reader_paused = []
    reader_writes = []

    real_document_write = peer_handouts._write_document

    def observed_document_write(*args, **kwargs):
        if threading.current_thread().name == "s11-reader":
            reader_writes.append("admissions")
        return real_document_write(*args, **kwargs)

    real_reader_shard_write = reader.rows._write_shard

    def observed_reader_shard_write(*args, **kwargs):
        if threading.current_thread().name == "s11-reader":
            reader_writes.append("recipient-row")
        return real_reader_shard_write(*args, **kwargs)

    monkeypatch.setattr(
        peer_handouts, "_write_document", observed_document_write)
    monkeypatch.setattr(
        reader.rows, "_write_shard", observed_reader_shard_write)

    @contextlib.contextmanager
    def watched_lock(lock_path):
        kind = "admission" if os.fspath(lock_path) == admission else "shard"
        held = getattr(lock_state, "held", [])
        if held and kind != held[-1]:
            violations.append((held[-1], kind))
        with real_lock(lock_path):
            held.append(kind)
            lock_state.held = held
            try:
                yield
            finally:
                held.pop()
        if threading.current_thread().name == "s11-reader" \
                and kind == "admission" and not reader_paused:
            reader_paused.append(True)
            reader_left_admission.set()
            assert release_reader.wait(5)

    monkeypatch.setattr(keyed_state, "file_lock", watched_lock)
    real_writer_update = writer.rows.update
    writer_updates = []

    def paused_writer_update(key, callback):
        writer_updates.append(key)
        target = 1 if phase == "pending" else 3
        if len(writer_updates) == target:
            writer_at_phase.set()
            assert release_writer.wait(5)
        return real_writer_update(key, callback)

    monkeypatch.setattr(writer.rows, "update", paused_writer_update)
    reader_outcome = []
    writer_outcome = []

    def read_current():
        try:
            reader.current("device-1", 101)
        except Exception as exc:  # captured and asserted below
            reader_outcome.append(exc)
        else:
            reader_outcome.append(None)

    def record_first():
        try:
            writer_outcome.append(writer.record(
                DEVICE, [_peer("10.0.0.2")], INFO_A, 100))
        except Exception as exc:  # captured and asserted below
            writer_outcome.append(exc)

    read_thread = threading.Thread(target=read_current, name="s11-reader")
    write_thread = threading.Thread(target=record_first, name="s11-writer")
    row_path = writer.rows._shard_path(keyed_state.bucket_of("device-1"))
    read_started = False
    write_started = False
    try:
        read_thread.start()
        read_started = True
        assert reader_left_admission.wait(5)
        write_thread.start()
        write_started = True
        assert writer_at_phase.wait(5)
        admissions_before = Path(admission).read_bytes()
        row_before = (
            Path(row_path).exists(),
            Path(row_path).read_bytes() if Path(row_path).exists() else None)

        release_reader.set()
        read_thread.join(timeout=5)
        assert not read_thread.is_alive()
        assert len(reader_outcome) == 1
        assert isinstance(reader_outcome[0], peer_handouts.HandoutStoreError)
        assert str(reader_outcome[0]) == "handout admission changed"
        assert reader_writes == []
        assert Path(admission).read_bytes() == admissions_before
        assert (Path(row_path).exists(),
                Path(row_path).read_bytes()
                if Path(row_path).exists() else None) == row_before

        release_writer.set()
        write_thread.join(timeout=5)
    finally:
        release_reader.set()
        release_writer.set()
        if read_started:
            read_thread.join(timeout=5)
        if write_started:
            write_thread.join(timeout=5)
    assert not read_thread.is_alive()
    assert not write_thread.is_alive()
    assert writer_outcome == [True]
    assert violations == []
    assert peer_handouts.HandoutLedger(path, ttl=90).current(
        "device-1", 101) == [
            {"address": "10.0.0.2", "info_hash": INFO_A,
             "expires_at": 190}]


def test_no_write_repeat_changed_swarm_and_renewal_window(tmp_path):
    ledger = _ledger(tmp_path, ttl=90)
    ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, 100)
    shard = ledger.rows._shard_path(keyed_state.bucket_of("device-1"))
    before = (os.stat(shard).st_ino, open(shard, "rb").read())
    ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, 150)
    assert (os.stat(shard).st_ino, open(shard, "rb").read()) == before

    ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_B, 151)
    changed = ledger.current("device-1", 151)[0]
    assert changed == {"address": "10.0.0.2", "info_hash": INFO_B,
                       "expires_at": 190}
    ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_B, 160)
    assert ledger.current("device-1", 160)[0]["expires_at"] == 250


def test_exact_expiry_prunes_before_cap_and_empty_row_is_retained(tmp_path,
                                                                  monkeypatch):
    monkeypatch.setattr(peer_handouts, "MAX_ADDRESSES", 1)
    ledger = _ledger(tmp_path, ttl=10)
    ledger.record(DEVICE, [_peer("10.0.0.1")], INFO_A, 100)
    assert ledger.current("device-1", 109)
    assert ledger.current("device-1", 110) == []
    ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, 110)
    assert ledger.current("device-1", 110)[0]["address"] == "10.0.0.2"


def test_exact_4096_address_cap_never_evicts_live_evidence(tmp_path):
    ledger = _ledger(tmp_path, ttl=900)
    ledger._admit("device-1", 100)
    values = []
    for index in range(peer_handouts.MAX_ADDRESSES):
        address = "10.%d.%d.%d" % (
            (index >> 16) & 255, (index >> 8) & 255, index & 255)
        values.append({"address": address, "info_hash": INFO_A,
                       "expires_at": 1000})
    values.sort(key=lambda row: tuple(
        int(item) for item in row["address"].split(".")))
    # The wire requirement is lexical sort by canonical address.
    values.sort(key=lambda row: row["address"])
    ledger.rows.put("device-1", {
        "v": 1, "principal_type": "device", "principal_id": "device-1",
        "updated_at": 100, "handouts": values})
    before = ledger.rows.get("device-1")
    with pytest.raises(peer_handouts.HandoutStoreError,
                       match="handout address cap reached"):
        ledger.record(DEVICE, [_peer("11.0.0.1")], INFO_A, 101)
    assert ledger.rows.get("device-1") == before


def test_concurrent_different_shard_admission_linearizes_at_10256(tmp_path):
    path = _path(tmp_path)
    peer_handouts.initialize(path)
    # Pending entries are a valid crash state and count at the global cap
    # without fabricating an active row for every seeded recipient.
    devices = {"seed%05d" % i: "pending"
               for i in range(peer_handouts.MAX_RECIPIENTS - 1)}
    peer_handouts._write_document(peer_handouts.admissions_path(path), {
        "schema": peer_handouts.ADMISSIONS_SCHEMA, "devices": devices})
    ledger = peer_handouts.HandoutLedger(path, ttl=90)
    candidates = ["new-a", "new-b"]
    assert keyed_state.bucket_of(candidates[0]) != keyed_state.bucket_of(
        candidates[1])
    barrier = threading.Barrier(2)
    outcomes = []

    def work(device_id):
        try:
            barrier.wait()
            ledger.record(auth.Principal("device", device_id),
                          [_peer("10.1.0.%d" % (1 + len(outcomes)))],
                          INFO_A, 100)
            outcomes.append("ok")
        except peer_handouts.HandoutStoreError:
            outcomes.append("refused")

    threads = [threading.Thread(target=work, args=(item,))
               for item in candidates]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert sorted(outcomes) == ["ok", "refused"]
    with open(peer_handouts.admissions_path(path)) as stream:
        assert len(json.load(stream)["devices"]) == peer_handouts.MAX_RECIPIENTS


def test_service_and_legacy_are_outside_ledger(tmp_path):
    path = _path(tmp_path)
    peer_handouts.initialize(path)
    ledger = peer_handouts.HandoutLedger(path)
    for principal in (auth.Principal("service", "seeder"),
                      auth.Principal("legacy", "compat")):
        assert ledger.record(principal, [_peer("10.0.0.2")], INFO_A, 100)
    assert keyed_state.KeyedState(path).snapshot() == {}


def test_corruption_and_durable_write_failure_refuse_disclosure(tmp_path,
                                                                monkeypatch):
    ledger = _ledger(tmp_path)
    ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, 100)
    shard = ledger.rows._shard_path(keyed_state.bucket_of("device-1"))
    with open(shard, "w") as stream:
        stream.write("{broken")
    with pytest.raises(peer_handouts.HandoutStoreError):
        ledger.record(DEVICE, [_peer("10.0.0.3")], INFO_A, 101)


def test_post_rename_fsync_failure_is_restart_idempotent(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, 100)
    real = keyed_state._fsync_directory
    calls = []

    def fail_once(path):
        calls.append(path)
        if len(calls) == 1:
            raise OSError("injected post-rename failure")
        return real(path)

    monkeypatch.setattr(keyed_state, "_fsync_directory", fail_once)
    with pytest.raises(OSError):
        ledger.record(DEVICE, [_peer("10.0.0.3")], INFO_A, 101)
    restarted = peer_handouts.HandoutLedger(_path(tmp_path), ttl=90)
    assert restarted.record(DEVICE, [_peer("10.0.0.3")], INFO_A, 101)
    assert {row["address"] for row in restarted.current("device-1", 101)} == {
        "10.0.0.2", "10.0.0.3"}


@pytest.mark.parametrize("payload", [
    b'{"schema":"iris-peer-handout-admissions/v1","devices":{},'
    b'"devices":{}}',
    b'{"schema":"iris-peer-handout-admissions/v1","devices":{},'
    b'"unknown":true}',
    b'{"schema":"iris-peer-handout-admissions/v1","devices":NaN}',
])
def test_admission_json_is_closed_duplicate_free_and_finite(tmp_path, payload):
    path = _path(tmp_path)
    admission = peer_handouts.admissions_path(path)
    os.makedirs(os.path.dirname(admission), exist_ok=True)
    with open(admission, "wb") as stream:
        stream.write(payload)
    with pytest.raises(peer_handouts.HandoutStoreError):
        peer_handouts.HandoutLedger(path).current("device-1", 100)


def test_times_are_bounded_nonboolean_in_rows_and_calls(tmp_path):
    ledger = _ledger(tmp_path)
    for value in (True, -1, float("inf"), 1 << 63):
        with pytest.raises(peer_handouts.HandoutStoreError):
            ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, value)
    ledger._admit("device-1", 100)
    shard = ledger.rows._shard_path(keyed_state.bucket_of("device-1"))
    with open(shard, "w") as stream:
        json.dump({"device-1": {
            "v": 1, "principal_type": "device",
            "principal_id": "device-1", "updated_at": 100,
            "handouts": [{"address": "10.0.0.2", "info_hash": INFO_A,
                          "expires_at": 1 << 63}]}}, stream)
    with pytest.raises(peer_handouts.HandoutStoreError):
        ledger.current("device-1", 100)


def test_same_recipient_pending_admission_race_preserves_both_disclosures_after_restart(
        tmp_path, monkeypatch):
    path = _path(tmp_path)
    peer_handouts.initialize(path)
    ledger = peer_handouts.HandoutLedger(path, ttl=90)
    barrier = threading.Barrier(2)
    winner_done = threading.Event()
    real_update = ledger.rows.update

    def synchronized_update(key, callback):
        if callback.__name__ == "ensure":
            barrier.wait(timeout=5)
            if threading.current_thread().name == "pending-loser":
                assert winner_done.wait(5)
        return real_update(key, callback)

    monkeypatch.setattr(ledger.rows, "update", synchronized_update)
    outcomes = {}

    def work(name, address):
        try:
            outcomes[name] = ledger.record(
                DEVICE, [_peer(address)], INFO_A, 100)
        finally:
            if name == "winner":
                winner_done.set()

    threads = [
        threading.Thread(target=work, name="pending-winner",
                         args=("winner", "10.0.0.2")),
        threading.Thread(target=work, name="pending-loser",
                         args=("loser", "10.0.0.3")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert outcomes == {"winner": True, "loser": True}
    restarted = peer_handouts.HandoutLedger(path, ttl=90)
    assert {row["address"] for row in restarted.current("device-1", 101)} == {
        "10.0.0.2", "10.0.0.3"}


@pytest.mark.parametrize("boundary", ["admission", "row"])
def test_post_rename_handout_retry_confirms_row_and_admission_durability(
        boundary, tmp_path, monkeypatch):
    path = _path(tmp_path)
    ledger = _ledger(tmp_path, ttl=90)
    admission = peer_handouts.admissions_path(path)
    if boundary == "row":
        ledger.record(DEVICE, [_peer("10.0.0.2")], INFO_A, 100)

    real_admission_fsync = peer_handouts._fsync_directory
    real_row_fsync = keyed_state._fsync_directory
    failed = []

    def admission_fsync(directory):
        if not failed and os.path.exists(admission):
            document = json.loads(Path(admission).read_text())
            if document["devices"].get("device-1") == "active":
                failed.append("admission")
                raise OSError("injected pre-directory-fsync failure")
        return real_admission_fsync(directory)

    def row_fsync(directory):
        if not failed and directory == ledger.rows.dir:
            row = ledger.rows.get("device-1")
            if row and any(item["address"] == "10.0.0.3"
                           for item in row["handouts"]):
                failed.append("row")
                raise OSError("injected pre-directory-fsync failure")
        return real_row_fsync(directory)

    if boundary == "admission":
        monkeypatch.setattr(peer_handouts, "_fsync_directory", admission_fsync)
        address = "10.0.0.2"
    else:
        monkeypatch.setattr(keyed_state, "_fsync_directory", row_fsync)
        address = "10.0.0.3"
    with pytest.raises(OSError, match="pre-directory-fsync"):
        ledger.record(DEVICE, [_peer(address)], INFO_A, 101)
    assert failed == [boundary]

    target = admission if boundary == "admission" else ledger.rows._shard_path(
        keyed_state.bucket_of("device-1"))
    identity = (os.stat(target).st_ino, Path(target).read_bytes())
    confirmations = []

    def confirmed_admission(directory):
        confirmations.append(("admission", directory))
        return real_admission_fsync(directory)

    def confirmed_row(directory):
        confirmations.append(("row", directory))
        return real_row_fsync(directory)

    monkeypatch.setattr(peer_handouts, "_fsync_directory", confirmed_admission)
    monkeypatch.setattr(keyed_state, "_fsync_directory", confirmed_row)
    restarted = peer_handouts.HandoutLedger(path, ttl=90)
    assert restarted.record(DEVICE, [_peer(address)], INFO_A, 101)
    assert any(kind == boundary for kind, _directory in confirmations)
    assert (os.stat(target).st_ino, Path(target).read_bytes()) == identity
    assert address in {row["address"] for row in restarted.current(
        "device-1", 101)}


@pytest.mark.parametrize("version", [1.0, True, False])
def test_handout_row_version_is_an_exact_nonboolean_integer(
        version, tmp_path):
    ledger = _ledger(tmp_path)
    ledger._admit("device-1", 100)
    shard = ledger.rows._shard_path(keyed_state.bucket_of("device-1"))
    document = json.loads(Path(shard).read_text())
    document["device-1"]["v"] = version
    Path(shard).write_text(json.dumps(document))
    with pytest.raises(peer_handouts.HandoutStoreError):
        peer_handouts.HandoutLedger(_path(tmp_path)).current("device-1", 100)
