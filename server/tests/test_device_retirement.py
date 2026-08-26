# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Device retirement / revocation lifecycle (spec §7 retirement).

Fail-closed contract under test:

- ``secrets_store.revoked_device_principals`` derives a device principal as
  revoked ONLY when every owned record is durably revoked — never from
  transient catalog-token expiry.
- The tracker's ``_make_revoked_view`` provider reads the durable store fresh
  and fails SAFE: a corrupt read never shrinks the known-revoked set.
- A revoked principal + its RETAINED endpoint derives a deny from the pure
  reconciler regardless of policy — the guarantee that survives a restart.
- ``iris-revoke`` persists durable-first (abort on persist failure) and never
  un-revokes on a policy-cleanup failure.
- ``iris-mint-enrollment`` clears the device's old endpoint rows BEFORE minting;
  a clear failure aborts before any new credential exists. ``device:<id>`` is
  distinct from the ``service:seeder`` namespace.
"""
import collections
import json
import os
import time
import types
from importlib.machinery import SourceFileLoader

import pytest

import auth
import blocklist_reconciler as br
import peer_endpoints
import peer_policy
import secrets_store
import tracker


# ---------------------------------------------------------------------------
# CLI loaders (iris-revoke / iris-mint-enrollment have no .py extension)
# ---------------------------------------------------------------------------

def _load_cli(basename, modname):
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), basename)
    loader = SourceFileLoader(modname, path)
    mod = types.ModuleType(modname)
    mod.__file__ = path
    loader.exec_module(mod)
    return mod


def _pr(document):
    return peer_policy.PolicyResult(document, False, False)


def _endpoint_snapshot(key, ptype, pid, ip):
    return {key: {"principal_type": ptype, "principal_id": pid,
                  "endpoints": [{"ipv4": ip, "port": 6881,
                                 "observed_at": 1000.0, "source": "announce"}]}}


# ---------------------------------------------------------------------------
# revoked_device_principals: durable-revoke view semantics
# ---------------------------------------------------------------------------

def test_all_records_revoked_is_retired():
    store = secrets_store.load("/nonexistent")
    now = time.time()
    secrets_store.mint(store, "dev-1", "catalog_token", now)
    secrets_store.mint(store, "dev-1", "announce_token", now)
    secrets_store.revoke(store, "dev-1")
    assert secrets_store.revoked_device_principals(store) == {"device:dev-1"}


def test_expired_catalog_but_valid_announce_is_not_retired():
    """An expired-but-not-revoked catalog token while announce stays valid is
    ordinary expiry, NOT retirement (spec §7: durable revoke, not expiry)."""
    store = secrets_store.load("/nonexistent")
    now = time.time()
    secrets_store.mint(store, "dev-1", "catalog_token", now)
    secrets_store.mint(store, "dev-1", "announce_token", now)
    # Force the catalog token expired (but NOT revoked); announce still valid.
    store["devices"]["dev-1"]["catalog_token"]["expires_at"] = int(now) - 10
    assert secrets_store.revoked_device_principals(store) == set()


def test_partial_revoke_is_not_retired():
    store = secrets_store.load("/nonexistent")
    now = time.time()
    secrets_store.mint(store, "dev-1", "catalog_token", now)
    secrets_store.mint(store, "dev-1", "announce_token", now)
    store["devices"]["dev-1"]["catalog_token"]["revoked"] = True
    assert secrets_store.revoked_device_principals(store) == set()


def test_empty_device_record_is_not_retired():
    store = secrets_store.load("/nonexistent")
    store["devices"]["dev-empty"] = {}
    assert secrets_store.revoked_device_principals(store) == set()


def test_seeder_pseudo_device_never_retired():
    store = secrets_store.load("/nonexistent")
    now = time.time()
    secrets_store.mint(store, "seeder", "announce_token", now)
    store["seeder"]["announce_token"]["revoked"] = True
    assert secrets_store.revoked_device_principals(store) == set()


# ---------------------------------------------------------------------------
# _make_revoked_view: fresh read + fail-safe
# ---------------------------------------------------------------------------

def test_revoked_view_reads_store_fresh(tmp_path):
    sp = str(tmp_path / "secrets.json")
    store = secrets_store.load(sp)
    secrets_store.mint(store, "dev-1", "catalog_token", time.time())
    secrets_store.save(store, sp)
    view = tracker._make_revoked_view(sp)
    assert view() == set()  # not revoked yet
    # Revoke and persist; the SAME view picks it up without a restart.
    secrets_store.revoke(store, "dev-1")
    secrets_store.save(store, sp)
    assert view() == {"device:dev-1"}


def test_revoked_view_fails_safe_on_corrupt_read(tmp_path):
    """A corrupt store read must never shrink the known-revoked set (spec §7
    fail-closed: never silently permit a known-revoked device)."""
    sp = str(tmp_path / "secrets.json")
    store = secrets_store.load(sp)
    secrets_store.mint(store, "dev-1", "catalog_token", time.time())
    secrets_store.revoke(store, "dev-1")
    secrets_store.save(store, sp)
    view = tracker._make_revoked_view(sp)
    assert view() == {"device:dev-1"}
    # Corrupt the file: the view retains the last-known revoked principal.
    with open(sp, "w") as f:
        f.write("{ this is not valid json")
    assert view() == {"device:dev-1"}


def test_revoked_view_missing_file_is_empty(tmp_path):
    view = tracker._make_revoked_view(str(tmp_path / "absent.json"))
    assert view() == set()


# ---------------------------------------------------------------------------
# Restart derives deny from RETAINED endpoint after revoke
# ---------------------------------------------------------------------------

def test_restart_derives_deny_from_retained_endpoint_after_revoke(tmp_path):
    """After a revoke, a fresh tracker (new reconciler view + the retained
    durable endpoint) derives a deny for the device's IP even though policy has
    no deny assignment — the restart-surviving guarantee."""
    sp = str(tmp_path / "secrets.json")
    ep_path = str(tmp_path / "peer-endpoints.json")
    now = time.time()

    store = secrets_store.load(sp)
    secrets_store.mint(store, "dev-1", "announce_token", now)
    secrets_store.save(store, sp)
    # Device announced -> durable endpoint retained.
    peer_endpoints.record_endpoint(
        ep_path, auth.Principal("device", "dev-1"), "10.0.0.5", 6881, now)

    # Revoke durably (as iris-revoke / GUI delete would).
    secrets_store.revoke(store, "dev-1")
    secrets_store.save(store, sp)

    # Fresh reconciler view (simulates a tracker restart re-reading the store).
    view = tracker._make_revoked_view(sp)
    durable = peer_endpoints.fresh_endpoints(ep_path, now)
    assert "device:dev-1" in durable  # endpoint RETAINED, not removed

    # Policy has NO deny for dev-1 (empty base document).
    result = br.derive_denied_set(
        _pr(peer_policy.base_document()),
        durable_endpoints=durable, pending_endpoints={},
        active_participants=[], revoked_principals=view(),
        protected_seeder_ip=None)
    assert result.denied_ips == ["10.0.0.5"]  # derived-denied via revocation


# ---------------------------------------------------------------------------
# iris-revoke: durable-first abort + cleanup never un-revokes
# ---------------------------------------------------------------------------

def _seed_secrets(tmp_path, device_id="dev-1"):
    sp = str(tmp_path / "secrets.json")
    store = secrets_store.load(sp)
    now = time.time()
    secrets_store.mint(store, device_id, "catalog_token", now)
    secrets_store.mint(store, device_id, "announce_token", now)
    secrets_store.save(store, sp)
    return sp


def test_iris_revoke_aborts_when_durable_persist_fails(tmp_path, monkeypatch):
    sp = _seed_secrets(tmp_path)
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_cli("iris-revoke", "iris_revoke_fail")

    def _boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(mod.secretfs, "persist_store", _boom)

    rc = mod.main(["dev-1"])
    assert rc == 1
    # The on-disk store must be UNCHANGED (no phantom revoke committed).
    store = secrets_store.load(sp)
    assert store["devices"]["dev-1"]["catalog_token"]["revoked"] is False


def test_iris_revoke_cleanup_failure_keeps_revoke_applied(tmp_path, monkeypatch):
    sp = _seed_secrets(tmp_path)
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_cli("iris-revoke", "iris_revoke_cleanup")

    def _boom(*a, **k):
        raise RuntimeError("policy store unavailable")
    monkeypatch.setattr(mod.peer_policy, "unassign_device", _boom)

    rc = mod.main(["dev-1"])
    assert rc == 1  # degraded (nonzero) …
    # … but the durable revoke STAYS applied (never un-revoked).
    store = secrets_store.load(sp)
    for rec in store["devices"]["dev-1"].values():
        assert rec["revoked"] is True


def test_iris_revoke_success_unassigns_policy(tmp_path, monkeypatch):
    sp = _seed_secrets(tmp_path)
    # Pre-assign the device to the reserved quarantine ACL.
    ap = str(tmp_path / "peer-policy.json")
    lk = str(tmp_path / "peer-policy.lkg.json")
    peer_policy.commit_mutation(
        ap, lk, "assign", "dev-1", "op", 1.0,
        lambda c: c["assignments"].__setitem__("dev-1", "quarantine"))
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_cli("iris-revoke", "iris_revoke_ok")
    assert mod.main(["dev-1"]) == 0
    doc = peer_policy.load_policy(ap, lk).document
    assert "dev-1" not in doc["assignments"]


# ---------------------------------------------------------------------------
# iris-mint-enrollment: clear endpoints BEFORE mint
# ---------------------------------------------------------------------------

def _load_mint():
    return _load_cli("iris-mint-enrollment", "iris_mint_enrollment_ret")


def test_reonboard_clears_endpoints_before_mint(tmp_path, monkeypatch):
    sp = str(tmp_path / "secrets.json")
    ep_path = str(tmp_path / "peer-endpoints.json")
    now = time.time()
    # A stale retained endpoint from the device's prior life.
    peer_endpoints.record_endpoint(
        ep_path, auth.Principal("device", "dev-1"), "10.0.0.5", 6881, now)
    assert "device:dev-1" in peer_endpoints.fresh_endpoints(ep_path, now)

    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_mint()
    assert mod.main(["dev-1"]) == 0

    # Old endpoint rows are gone; the freshly enrolled device is not stale-denied.
    assert "device:dev-1" not in peer_endpoints.fresh_endpoints(ep_path, now)
    store = secrets_store.load(sp)
    assert "catalog_token" in store["devices"]["dev-1"]


def test_reonboard_aborts_when_endpoint_clear_fails(tmp_path, monkeypatch):
    sp = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", sp)
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_mint()

    def _boom(*a, **k):
        raise OSError("endpoints volume unavailable")
    monkeypatch.setattr(mod.peer_endpoints, "clear_principal", _boom)

    rc = mod.main(["dev-1"])
    assert rc == 1
    # No credential was minted (abort BEFORE any new credential is usable).
    store = secrets_store.load(sp)
    assert "dev-1" not in store.get("devices", {})


def test_device_seeder_id_is_reserved_at_enrollment(tmp_path, monkeypatch):
    """The secret store cannot represent this typed namespace safely."""
    ep_path = str(tmp_path / "peer-endpoints.json")
    now = time.time()
    peer_endpoints.record_endpoint(
        ep_path, auth.Principal("device", "seeder"), "10.0.0.9", 6881, now)
    peer_endpoints.record_endpoint(
        ep_path, auth.Principal("service", "seeder"), "10.0.0.1", 6881, now)

    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "secrets.json"))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    mod = _load_mint()
    assert mod.main(["seeder"]) == 2

    fresh = peer_endpoints.fresh_endpoints(ep_path, now)
    assert "device:seeder" in fresh
    assert "service:seeder" in fresh


# ---------------------------------------------------------------------------
# GUI delete: revoke-first abort + partial cleanup never permits
# ---------------------------------------------------------------------------

def test_gui_revoke_helper_aborts_on_persist_failure(tmp_path, monkeypatch):
    """_revoke_device_secrets re-raises on a persist failure so the caller
    aborts the delete with no state change."""
    import gui_server
    import gui_app
    sp = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(sp)
    store = secrets_store.load(sp)
    secrets_store.mint(store, "dev-1", "catalog_token", time.time())
    secrets_store.save(store, sp)

    monkeypatch.setattr(
        gui_server.secretfs, "persist_store",
        lambda *a, **k: (_ for _ in ()).throw(OSError("no space")))
    with pytest.raises(OSError):
        gui_server._revoke_device_secrets(app, "dev-1")
    # Store unchanged: no phantom revoke.
    assert secrets_store.load(sp)["devices"]["dev-1"][
        "catalog_token"]["revoked"] is False


def test_gui_revoke_helper_absent_device(tmp_path):
    import gui_server
    import gui_app
    sp = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(sp)
    secrets_store.save(secrets_store.load(sp), sp)
    assert gui_server._revoke_device_secrets(app, "ghost") == "absent"


def test_partial_policy_cleanup_still_derives_deny(tmp_path):
    """Even if policy cleanup is skipped entirely (partial/degraded delete),
    the revoked principal + retained endpoint still derives a deny — cleanup
    order can never permit the device."""
    ep_path = str(tmp_path / "peer-endpoints.json")
    now = time.time()
    peer_endpoints.record_endpoint(
        ep_path, auth.Principal("device", "dev-1"), "10.0.0.5", 6881, now)
    durable = peer_endpoints.fresh_endpoints(ep_path, now)
    # Policy STILL assigns the device (cleanup failed) — no deny in policy.
    doc = peer_policy.base_document()
    result = br.derive_denied_set(
        _pr(doc), durable_endpoints=durable, pending_endpoints={},
        active_participants=[], revoked_principals={"device:dev-1"},
        protected_seeder_ip=None)
    assert result.denied_ips == ["10.0.0.5"]
