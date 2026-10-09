# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Restore keeps reviewed origin authority, never an old applied-status claim."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
import uuid

import pytest

import auth
import origin_enforcement as oe
import peer_endpoints
import tracker
from test_cross_process_peer_policy import FakeAria, _paths
from test_origin_enforcement import DEVICE, ORIGIN, approve, fixture as origin_fixture
from test_installer_restore import producer, put

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from iris_installer import restore, restore_storage
from iris_installer.state import InstallError


@pytest.fixture
def origin(tmp_path):
    current, archived = tmp_path / "current", tmp_path / "archived"
    current.mkdir()
    store, rec, aria, paths, clock = origin_fixture.__wrapped__(current)
    return current, archived, store, rec, aria, paths, clock


def snapshot(current, archived):
    shutil.copytree(current, archived)


def restarted_tracker(root, aria, clock, origin=ORIGIN):
    # Unlike the fresh-install fixture builder, a restart must not initialize
    # or replace the historical policy files under review.
    paths = _paths(root)
    return tracker.TrackerReconciler(
        policy_paths=(paths["policy"], paths["lkg"]), endpoints_path=paths["endpoints"],
        enforcement_path=paths["enforcement"], aria=aria,
        pending_queue=peer_endpoints.PendingEndpointQueue(),
        active_participants=lambda: [], revoked_principals=lambda: set(),
        protected_seeder_ip=origin, now=clock)


def assert_preserved(current, archived):
    for name in ("origin-enforcement.json", "origin-enforcement.application.json"):
        left, right = current / name, archived / name
        assert left.read_bytes() == right.read_bytes()
        assert restore_storage.inventory(left) == restore_storage.inventory(right)
    assert not (archived / "origin-enforcement.status.json").exists()


def test_old_pre_opt_in_backup_preserves_current_review(origin):
    current, archived, store, rec, _, _, _ = origin
    snapshot(current, archived)
    approve(store)
    rec.run_once()
    restore.state_authority(current, archived)
    assert_preserved(current, archived)
    assert oe.load_control(oe.paths(archived)[0])["revision"] == 1


def test_old_enforced_backup_cannot_undo_newer_reviewed_disable(origin):
    current, archived, store, rec, _, _, _ = origin
    approve(store)
    rec.run_once()
    snapshot(current, archived)
    approve(store, mode="preflight")
    rec.run_once()
    restore.state_authority(current, archived)
    assert_preserved(current, archived)
    result = oe.load_control(oe.paths(archived)[0])
    assert (result["revision"], result["mode"]) == (2, "preflight")


def test_restored_get_needs_new_tracker_session_acknowledgement(origin):
    current, archived, store, rec, _, _, clock = origin
    approve(store)
    rec.run_once()
    assert store.read()["state"] == "enforced"
    snapshot(current, archived)
    restore.state_authority(current, archived)
    restored = oe.Store(str(archived), ORIGIN, now=clock)
    before = restored.read()
    assert not (archived / "origin-enforcement.status.json").exists()
    assert before["state"] != "enforced"
    assert before["applied_ip_count"] is None
    assert before["last_verified_at"] is None
    aria = FakeAria(session="restored-session")
    fresh = restarted_tracker(archived, aria, clock)
    fresh.run_once()
    assert aria.calls == [[DEVICE]]
    assert restored.read()["state"] == "enforced"
    control, application, _ = oe.paths(archived)
    assert oe.load_application_for(oe.load_control(control), application)[
        "last_applied"]["session"] == "restored-session"


def test_restore_preserves_uncertain_intent_and_unknown_origin_freeze(origin):
    current, archived, store, rec, aria, _, clock = origin
    snapshot(current, archived)
    approve(store)
    aria.raise_on_call = True
    rec.run_once()
    application = oe.load_application(oe.paths(current)[1])
    assert application["intent"] is not None
    restore.state_authority(current, archived)
    assert_preserved(current, archived)
    restarted = FakeAria(session="restored-session")
    fresh = restarted_tracker(archived, restarted, clock, origin=None)
    fresh.run_once()
    assert restarted.calls == []
    assert oe.load_application(oe.paths(archived)[1])["intent"] == application["intent"]


def test_restore_preserves_shared_address_latch_after_observation_expires(origin):
    current, archived, store, rec, _, paths, clock = origin
    approve(store)
    rec.run_once()
    snapshot(current, archived)
    peer_endpoints.record_endpoint(paths["endpoints"], auth.Principal("device", "allowed"),
                                   DEVICE, 6881, clock())
    rec.run_once()
    application = oe.load_application(oe.paths(current)[1])
    assert application["shared_ips"] == [DEVICE]
    restore.state_authority(current, archived)
    assert_preserved(current, archived)
    clock.t += peer_endpoints.ENDPOINT_TTL + 1
    restored_endpoints = str(archived / "peer-endpoints.json")
    peer_endpoints.record_endpoint(restored_endpoints, auth.Principal("service", "seeder"),
                                   ORIGIN, 6881, clock())
    restarted = FakeAria(session="restored-session")
    fresh = restarted_tracker(archived, restarted, clock)
    fresh.run_once()
    assert restarted.calls == [[]]
    assert oe.load_application(oe.paths(archived)[1])["shared_ips"] == [DEVICE]
    assert oe.Store(str(archived), ORIGIN, now=clock).read()["state"] != "enforced"


@pytest.mark.parametrize("damage", [
    "missing-control", "null-control", "missing-application", "null-application",
    "symlink-control", "symlink-application", "directory-control", "oversized-application",
    "hardlink-application", "fifo-control",
])
def test_missing_or_corrupt_live_origin_authority_refuses_restore(origin, damage):
    current, archived, store, rec, _, _, _ = origin
    approve(store)
    rec.run_once()
    snapshot(current, archived)
    control, application, _ = map(Path, oe.paths(current))
    target = application if "application" in damage else control
    if damage.startswith("missing"):
        target.unlink()
    elif damage.startswith("null"):
        target.write_text("null")
    elif damage.startswith("symlink"):
        target.unlink()
        target.symlink_to(archived / target.name)
    elif damage.startswith("directory"):
        target.unlink()
        target.mkdir()
    elif damage.startswith("hardlink"):
        os.link(target, current / "extra-link")
    elif damage.startswith("fifo"):
        target.unlink()
        os.mkfifo(target)
    else:
        with target.open("wb") as stream:
            stream.truncate(oe.MAX_APPLICATION_BYTES + 1)
    before = restore_storage.inventory(archived)
    with pytest.raises(InstallError, match="[Oo]rigin|[Dd]istribution"):
        restore.state_authority(current, archived)
    assert restore_storage.inventory(archived) == before


def test_fresh_deployment_cannot_adopt_established_backup_authority(origin):
    current, archived, store, rec, _, _, _ = origin
    approve(store)
    rec.run_once()
    snapshot(current, archived)
    for path in oe.paths(current):
        Path(path).unlink()
    with pytest.raises(InstallError, match="[Oo]rigin|[Dd]istribution"):
        restore.state_authority(current, archived)


@pytest.mark.parametrize("damage", ["changed-same-review", "lost-shared", "lost-intent"])
def test_live_origin_authority_must_dominate_backup(origin, damage):
    current, archived, store, rec, aria, _, _ = origin
    approve(store)
    if damage == "lost-intent":
        aria.raise_on_call = True
    rec.run_once()
    control, application, _ = oe.paths(current)
    if damage == "lost-shared":
        document = oe.load_application(application)
        document.update(shared_revision=1, shared_ips=[DEVICE])
        oe.write_json(application, document)
    snapshot(current, archived)
    if damage == "changed-same-review":
        document = oe.load_control(control)
        document["max_new_ips"] += 1
        oe.write_json(control, document)
        # Keep the current pair internally valid; restore must detect the
        # same review revision differing from its earlier archived authority.
        document = oe.load_application(application)
        document["last_applied"]["control_hash"] = oe._hash(oe.load_control(control))
        oe.write_json(application, document)
    else:
        document = oe.load_application(application)
        document["shared_ips" if damage == "lost-shared" else "intent"] = (
            [] if damage == "lost-shared" else None)
        oe.write_json(application, document)
    with pytest.raises(InstallError, match="[Oo]rigin|[Dd]istribution"):
        restore.state_authority(current, archived)


def test_genuinely_fresh_origin_state_stays_absent(origin):
    current, archived, _, _, _, _, _ = origin
    snapshot(current, archived)
    restore.state_authority(current, archived)
    assert all(not Path(path).exists() for path in oe.paths(archived))


@pytest.mark.parametrize("journal_present", [False, True])
def test_first_review_materialization_is_preserved_without_becoming_enforced(origin, journal_present):
    current, archived, _, _, _, _, clock = origin
    snapshot(current, archived)
    control, application, _ = oe.paths(current)
    oe.write_json(control, oe.default_control())
    if journal_present:
        oe.write_json(application, oe.validate_application(None))
    restore.state_authority(current, archived)
    assert oe.load_control(oe.paths(archived)[0]) == oe.default_control()
    assert Path(oe.paths(archived)[1]).exists() == journal_present
    result = oe.Store(str(archived), ORIGIN, now=clock).read()
    assert result["state"] == "preflight" and result["applied_ip_count"] is None


@pytest.mark.parametrize("damage", ["missing-journal", "malformed-control", "future-review"])
def test_invalid_or_future_archived_origin_authority_is_not_adopted(origin, damage):
    current, archived, store, rec, _, _, _ = origin
    approve(store)
    rec.run_once()
    snapshot(current, archived)
    control, application, _ = oe.paths(archived)
    if damage == "missing-journal":
        Path(application).unlink()
    elif damage == "malformed-control":
        Path(control).write_text("null")
    else:
        prior = oe.load_control(control)
        prior["revision"] += 1
        oe.write_json(control, prior)
    before = restore_storage.inventory(current)
    with pytest.raises(InstallError, match="[Dd]istribution"):
        restore.state_authority(current, archived)
    assert restore_storage.inventory(current) == before


@pytest.mark.parametrize("damage", ["oversized-file", "directory"])
def test_origin_size_and_type_guard_precedes_inventory_or_json_read(origin, monkeypatch, damage):
    current, archived, store, rec, _, _, _ = origin
    approve(store)
    rec.run_once()
    snapshot(current, archived)
    target = Path(oe.paths(current)[0])
    target.unlink()
    if damage == "directory":
        target.mkdir()
    else:
        with target.open("wb") as stream:
            stream.truncate(oe.MAX_BYTES + 1)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("An unsafe origin state must be rejected before reading")

    monkeypatch.setattr(restore.storage, "inventory", forbidden)
    monkeypatch.setattr(oe, "read_json", forbidden)
    with pytest.raises(InstallError, match="distribution access authority"):
        restore.state_authority(current, archived)


def test_acknowledged_uncertain_attempt_is_valid_current_authority(origin):
    current, archived, store, rec, aria, _, _ = origin
    approve(store)
    aria.raise_on_call = True
    rec.run_once()
    snapshot(current, archived)
    aria.raise_on_call = False
    rec.run_once()
    restore.state_authority(current, archived)
    assert_preserved(current, archived)
    assert oe.load_application(oe.paths(archived)[1])["intent"] is None


@pytest.mark.parametrize("target", ["docker", "docker-split", "kubernetes"])
@pytest.mark.parametrize("old_mode", ["absent", "enforce"])
def test_all_topologies_stage_current_origin_authority_before_publication(
        origin, tmp_path, monkeypatch, target, old_mode):
    """Exercise real restore staging; stub transport, not the shared overlay."""
    current, archived, store, rec, _, _, _ = origin
    producer(current, 3)
    if old_mode == "enforce":
        approve(store)
        rec.run_once()
    snapshot(current, archived)
    producer(current, 9)
    approve(store, mode="enforce" if old_mode == "absent" else "preflight")
    rec.run_once()

    base = tmp_path / "installation"
    base.mkdir(mode=0o700)
    document = {"config": {"target": target}, "root_digests": {}, "source_manifest": {}}
    sources = {}
    for name in ("source", "roots", "images", "artifacts", "volume-iris-config"):
        sources[name] = base / name
        sources[name].mkdir(mode=0o700)
    sources["volume-iris-state"] = current
    for name, value in (("deployment", {}), ("environment", {}), ("installation", document)):
        sources[name] = base / name
        put(sources[name], value)
    if target == "docker-split":
        for name in ("console-deployment", "console-build"):
            sources[name] = base / name
            put(sources[name], {})
    if target == "kubernetes":
        sources["lifecycle-custody"] = base / "lifecycle-custody"
        sources["lifecycle-custody"].mkdir(mode=0o700)
        sources["kubernetes-resources"] = base / "kubernetes-resources"
        put(sources["kubernetes-resources"], [])
    archive_root = tmp_path / "data-archive"
    archive_root.mkdir(mode=0o700)
    for name, path in sources.items():
        original = archived if name == "volume-iris-state" else path
        if original.is_dir():
            shutil.copytree(original, archive_root / name)
        else:
            shutil.copy2(original, archive_root / name)
    if target == "docker-split":
        put(archive_root / "remote-console-custody", {})
    keys = tmp_path / "key-archive"
    keys.mkdir(mode=0o700)
    for path in (keys / "service-identity", base / "age.txt"):
        path.write_bytes(b"synthetic service identity, no key")
        path.chmod(0o600)
    captured = []

    def command(argv, **_kwargs):
        assert target == "docker-split" and argv[:2] == ["age", "-d"]
        return b"{}"

    install = SimpleNamespace(base=base, config=document["config"],
        journal=SimpleNamespace(document=document), command=command,
        console_custody_snapshot=lambda: b"{}",
        capture_backup_extras=lambda _sources: captured.append("stopped-kubernetes-snapshot"))
    transaction = restore.Transaction.__new__(restore.Transaction)
    transaction.base = base
    transaction.backups, transaction.recoveries = base / "backups", base / "recovery"
    transaction.id, transaction.backup_id = str(uuid.uuid4()), str(uuid.uuid4())
    transaction.identity, transaction.signer = base / "identity", base / "signer"
    transaction.directory = base / "restore-operation"
    transaction.directory.mkdir(mode=0o700)
    transaction.record = {"operation_id": transaction.id, "instance_id": str(uuid.uuid4()), "plan": []}

    def extract(path, _identity, _signer, *, destination):
        if path == transaction.backups / transaction.backup_id:
            shutil.copytree(archive_root, destination)
            put(destination / "RESTORE-INVENTORY.json", {"files": restore_storage.inventory(archive_root)})
        else:
            assert path == transaction.recoveries / transaction.backup_id
            shutil.copytree(keys, destination)

    @contextmanager
    def memory(_install):
        directory = tmp_path / "memory"
        directory.mkdir(mode=0o700)
        yield directory

    staged = {}

    def stage(_install, _operation, component, source, records):
        candidate = tmp_path / ("pvc-" + component)
        restore_storage.candidate(source, candidate, records)
        staged[component] = candidate

    monkeypatch.setattr(restore.backup_archive, "read", extract)
    monkeypatch.setattr(restore, "_memory", memory)
    monkeypatch.setattr(restore, "_producer_proof", lambda _install: {"signing_authority": "verified"})
    monkeypatch.setattr(restore.restore_topology, "stage", stage)
    live_before = restore_storage.inventory(current)
    transaction._prepare(install, sources)
    assert transaction.record["phase"] == "staged"
    if target == "kubernetes":
        assert captured == ["stopped-kubernetes-snapshot"]
        candidate = staged["state"]
    else:
        assert captured == []
        candidate = Path(next(row["staged"] for row in transaction.record["plan"]
                              if row.get("target") == str(current)))
    assert_preserved(current, candidate)
    assert restore_storage.inventory(current) == live_before
    assert (current / "origin-enforcement.status.json").exists()
