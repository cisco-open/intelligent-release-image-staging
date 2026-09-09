# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import gzip
import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
import contextlib
from pathlib import Path

import pytest

import catalog
import instructions
import keyed_state
import secrets_store


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _secrets_path(tmp_path):
    """Return a path to a secrets.json under tmp_path."""
    return str(tmp_path / "secrets.json")


def _mint_catalog_token(secrets_path, device_id, now=None):
    """Mint a catalog_token for device_id into secrets.json; return the token."""
    now = now if now is not None else time.time()
    store = secrets_store.load(secrets_path)
    tok = secrets_store.mint(store, device_id, "catalog_token", now)
    secrets_store.save(store, secrets_path)
    return tok


def _instruction_record(value, created_at, expires_at=None, revoked=False):
    """Build the frozen Task 12 instruction record without logging its value."""
    if expires_at is None:
        expires_at = created_at + 2592000
    return {
        "value": value,
        "key_id": hashlib.sha256(bytes.fromhex(value)).hexdigest(),
        "created_at": created_at,
        "expires_at": expires_at,
        "revoked": revoked,
        "_scope": "instructions",
    }


def _store(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    (tmp_path / "torrents").mkdir(exist_ok=True)
    (tmp_path / "torrents" / "img1.torrent").write_bytes(b"d4:infod}fakeee")
    s.save_image({"id": "img1", "filename": "img1.bin", "size": 5,
                  "sha256": "ab" * 32, "cisco_signature_verified": False,
                  "info_hash_hex": "cc" * 20, "published_at": 111})
    return s


def _store_with_images(tmp_path, ids):
    """A CatalogStore whose catalog.json carries a minimal published entry
    for each id in *ids* (multi-image assignment tests need more than the
    single img1 that _store() seeds)."""
    s = catalog.CatalogStore(str(tmp_path))
    for iid in ids:
        s.save_image({"id": iid, "filename": iid + ".bin", "size": 5,
                      "sha256": "ab" * 32, "cisco_signature_verified": False,
                      "info_hash_hex": "cc" * 20, "published_at": 111})
    return s


def _write_policy_json(store, rows):
    """Write *rows* (device_id -> raw policy record) straight into the keyed
    policy store, bypassing set_policy -- stands in for a row written by a
    previous release. Policy is keyed per device now, so this writes rows,
    not a whole-fleet document."""
    for device_id, row in rows.items():
        store._policies.put(device_id, row)


# ---------------------------------------------------------------------------
# Ported CatalogStore unit tests (unchanged behaviour)
# ---------------------------------------------------------------------------

def test_store_roundtrip_and_atomic(tmp_path):
    s = _store(tmp_path)
    s2 = catalog.CatalogStore(str(tmp_path))           # fresh read from disk
    assert s2.get_image("img1")["sha256"] == "ab" * 32
    assert [i["id"] for i in s2.list_images()] == ["img1"]


def test_store_heartbeat_and_policy(tmp_path):
    s = _store(tmp_path)
    s.record_heartbeat("sw-1", {"current_image_id": "img1",
                                "free_flash_bytes": 9, "version": "17.18"}, now=222)
    assert s.get_device("sw-1")["last_seen"] == 222
    s.set_policy("sw-1", approved_image_id="img1")
    assert s.get_policy("sw-1") == {"approved_image_id": "img1",
                                     "approved_image_ids": ["img1"]}


def test_set_policy_serializes_with_image_deletion_across_processes(tmp_path):
    """set_policy's image-existence check must serialize with image deletion
    through an OS-level lock, not a process-local RLock: `docker exec ...
    iris-assign` is a SEPARATE Python process, so only a shared lock file
    stops it from validating an image a concurrent console delete is
    removing, then persisting a dangling assignment afterward.

    The test plays the deleting process: it holds the image-policy flock,
    fires set_policy on a thread (a stand-in for the other process — flock
    on a fresh fd blocks either way), commits the delete, releases, and
    expects the assignment to have been rejected, not persisted."""
    s = _store(tmp_path)
    result = {}

    def assign():
        try:
            s.set_policy("sw-1", approved_image_id="img1")
            result["outcome"] = "assigned"
        except ValueError:
            result["outcome"] = "rejected"

    with s.image_policy_lock():
        t = threading.Thread(target=assign)
        t.start()
        time.sleep(0.3)   # let set_policy reach (and block on) the lock
        # the delete commits while the lock is held
        s.delete_image("img1")
    t.join(timeout=5)

    assert result.get("outcome") == "rejected"
    assert s.get_policy("sw-1")["approved_image_id"] is None


def test_forget_device_drops_heartbeat_leaves_policy(tmp_path):
    s = _store(tmp_path)
    s.record_heartbeat("sw-1", {"current_image_id": "img1",
                                "stage_state": "ready"}, now=222)
    s.set_policy("sw-1", approved_image_id="img1")
    assert s.forget_device("sw-1") is True
    # the staging/heartbeat record is gone (so the console stops calling it
    # 'deployed'), but the image ASSIGNMENT survives for a future re-onboard
    assert s.get_device("sw-1") is None
    assert "sw-1" not in [d["device_id"] for d in s.list_devices()]
    assert s.get_policy("sw-1")["approved_image_id"] == "img1"
    # idempotent: forgetting an unknown / already-forgotten device is False
    assert s.forget_device("sw-1") is False
    assert s.forget_device("never-seen") is False


def test_purge_device_clears_all_state(tmp_path):
    s = _store(tmp_path)
    s.record_heartbeat("sw-1", {"current_image_id": "img1",
                                "stage_state": "ready"}, now=222)
    s.set_policy("sw-1", approved_image_id="img1")
    s.record_telemetry("sw-1", {"event": "staging-complete"})
    s.request_report("sw-1", now=1000)
    assert s.purge_device("sw-1") is True
    # deleted-and-re-added devices must come back unassigned: EVERY
    # per-device store is emptied, unlike forget_device()
    assert s.get_device("sw-1") is None
    assert s.get_policy("sw-1") == {"approved_image_id": None,
                                     "approved_image_ids": []}
    assert s.get_telemetry("sw-1") == []
    assert s.pending_report("sw-1", now=1001) is None
    # idempotent on a purged / never-seen device
    assert s.purge_device("sw-1") is False
    assert s.purge_device("never-seen") is False


# ---------------------------------------------------------------------------
# Multi-image assignment: policy holds an ordered set (issue: multi-image
# assignment, task 1 -- storage layer only)
# ---------------------------------------------------------------------------

def test_policy_list_round_trip_and_order(tmp_path):
    store = _store_with_images(tmp_path, ["img-a", "img-b", "img-c"])
    store.set_policy("d1", approved_image_ids=["img-c", "img-a"])
    pol = store.get_policy("d1")
    assert pol["approved_image_ids"] == ["img-c", "img-a"]   # order preserved
    assert pol["approved_image_id"] == "img-c"               # singular = first


def test_policy_singular_write_reads_as_one_element_list(tmp_path):
    store = _store_with_images(tmp_path, ["img-a"])
    store.set_policy("d1", approved_image_id="img-a")
    assert store.get_policy("d1")["approved_image_ids"] == ["img-a"]


def test_policy_legacy_row_on_disk_reads_as_list(tmp_path):
    # A row written by the PREVIOUS release must read cleanly.
    store = _store_with_images(tmp_path, ["img-a"])
    _write_policy_json(store, {"d1": {"approved_image_id": "img-a"}})
    assert store.get_policy("d1")["approved_image_ids"] == ["img-a"]
    assert store.get_policy("d1")["approved_image_id"] == "img-a"


def test_policy_cap_ten(tmp_path):
    ids = ["img-%02d" % i for i in range(11)]
    store = _store_with_images(tmp_path, ids)
    with pytest.raises(ValueError, match="at most 10"):
        store.set_policy("d1", approved_image_ids=ids)
    store.set_policy("d1", approved_image_ids=ids[:10])      # 10 is fine


def test_policy_rejects_unknown_and_duplicate_ids(tmp_path):
    store = _store_with_images(tmp_path, ["img-a"])
    with pytest.raises(ValueError):
        store.set_policy("d1", approved_image_ids=["img-a", "nope"])
    with pytest.raises(ValueError):
        store.set_policy("d1", approved_image_ids=["img-a", "img-a"])


def test_policy_unassign_with_empty_list(tmp_path):
    store = _store_with_images(tmp_path, ["img-a"])
    store.set_policy("d1", approved_image_ids=["img-a"])
    store.set_policy("d1", approved_image_ids=[])
    assert store.get_policy("d1") == {"approved_image_id": None,
                                      "approved_image_ids": []}


def test_policy_compare_and_set_refuses_a_stale_expectation(tmp_path):
    """Two operators with the picker open on the same device both applied and
    the second silently overwrote the first: the write path had no
    compare-and-set at all, unlike the peer-policy PUT beside it in the API.

    Passing the set the caller believes is stored makes the write conditional:
    it goes through when the expectation still holds, and raises
    PolicyConflict carrying the CURRENT set when it does not, with nothing
    written. Omitting it keeps the unconditional write older callers rely
    on."""
    store = _store_with_images(tmp_path, ["img-a", "img-b", "img-c"])
    # a device with nothing assigned: the empty list is a real expectation,
    # not "no expectation"
    store.set_policy("d1", approved_image_ids=["img-a"], expect_image_ids=[])
    assert store.get_policy("d1")["approved_image_ids"] == ["img-a"]

    with pytest.raises(catalog.PolicyConflict) as exc:
        store.set_policy("d1", approved_image_ids=["img-b"],
                         expect_image_ids=[])
    assert exc.value.current_ids == ["img-a"]
    assert store.get_policy("d1")["approved_image_ids"] == ["img-a"]

    # order is part of the set: applying rewrites it, so a caller that saw a
    # different order did not see this row
    with pytest.raises(catalog.PolicyConflict):
        store.set_policy("d1", approved_image_ids=["img-c"],
                         expect_image_ids=["img-a", "img-b"])

    # unassign is conditional the same way, and no expectation still writes
    with pytest.raises(catalog.PolicyConflict):
        store.set_policy("d1", approved_image_ids=[], expect_image_ids=["img-b"])
    store.set_policy("d1", approved_image_ids=[], expect_image_ids=["img-a"])
    assert store.get_policy("d1")["approved_image_ids"] == []
    store.set_policy("d1", approved_image_ids=["img-c"])
    assert store.get_policy("d1")["approved_image_ids"] == ["img-c"]


def test_heartbeat_stores_stage_state(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.record_heartbeat("sw-1", {"current_image_id": "img1",
                                "free_flash_bytes": 9, "version": "17.18",
                                "stage_state": "flash_full_seeding_only"},
                       now=222)
    assert s.get_device("sw-1")["stage_state"] == "flash_full_seeding_only"


def test_heartbeat_stores_target_fs(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.record_heartbeat("sw-1", {"current_image_id": "img1",
                                "free_flash_bytes": 9, "version": "17.15",
                                "stage_state": "ready", "target_fs": "sdflash:"},
                       now=222)
    assert s.get_device("sw-1")["target_fs"] == "sdflash:"


# ---------------------------------------------------------------------------
# Heartbeat records model + source IP, routed through the REAL auth guard.
# (These previously called cat.route_post() directly, bypassing _guard, so the
#  device-binding auth was never exercised — review finding.)
# ---------------------------------------------------------------------------

def test_route_post_records_model_and_source_ip(tmp_path):
    """A heartbeat over the real HTTP path (exercising _guard's device-bound
    auth) records the device-supplied model and the source IP."""
    srv, port = _serve(tmp_path, "tok", device_id="203.0.113.3")
    try:
        status, _, _ = _req(
            port, "POST", "/v1/devices/203.0.113.3/heartbeat", token="tok",
            body=json.dumps({"current_image_id": "img1", "free_flash_bytes": 9,
                             "version": "26.01.01",
                             "model": "C9300-48UXM"}))
        assert status == 200
    finally:
        srv.shutdown()
    rec = catalog.CatalogStore(str(tmp_path)).get_device("203.0.113.3")
    assert rec["model"] == "C9300-48UXM"
    # swarm_ip is the real connection's source address (127.0.0.1 in-test),
    # captured by the handler, not a value the test fabricated past the guard.
    assert rec["swarm_ip"] == "127.0.0.1"


def test_route_post_rejects_wrong_device_token(tmp_path):
    """The real guard must reject a heartbeat for device A presented with a
    token bound to device B — and must NOT record any heartbeat for A.  This is
    the device-binding the direct route_post() call used to skip."""
    sp = _secrets_path(tmp_path)
    tok_b = _mint_catalog_token(sp, "device-b")
    s = _store(tmp_path)
    srv = catalog.make_server("127.0.0.1", 0, s, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        status, _, _ = _req(
            port, "POST", "/v1/devices/device-a/heartbeat", token=tok_b,
            body=json.dumps({"current_image_id": "img1",
                             "model": "C9300-48UXM"}))
        assert status == 401
    finally:
        srv.shutdown()
    # No heartbeat must have been recorded for the spoofed device.
    assert catalog.CatalogStore(str(tmp_path)).get_device("device-a") is None


def test_route_post_forwards_target_fs(tmp_path):
    """The HTTP heartbeat path (do_POST -> _guard -> route_post) must forward
    the heartbeat's target_fs through to record_heartbeat — the #24 IE3400
    sdflash staging field.  The unit test test_heartbeat_stores_target_fs hits
    record_heartbeat directly and so passes even if the HTTP path drops it."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        status, _, _ = _req(
            port, "POST", "/v1/devices/sw-1/heartbeat", token="tok",
            body=json.dumps({"current_image_id": "img1", "version": "17.15",
                             "stage_state": "ready", "target_fs": "sdflash:"}))
        assert status == 200
    finally:
        srv.shutdown()
    assert (catalog.CatalogStore(str(tmp_path))
            .get_device("sw-1")["target_fs"] == "sdflash:")


# ---------------------------------------------------------------------------
# HTTP server helpers (ported to secrets_path fixture)
# ---------------------------------------------------------------------------

def _serve(tmp_path, token, device_id="sw-9", audit_path=None):
    """Start a catalog HTTP server; return (srv, port, token)."""
    sp = _secrets_path(tmp_path)
    _mint_catalog_token(sp, device_id)
    # re-mint with the given token value via store manipulation so we control
    # the exact token string
    store = secrets_store.load(sp)
    store["devices"].setdefault(device_id, {})["catalog_token"] = {
        "value": token,
        "created_at": time.time(),
        "expires_at": time.time() + 3600,
        "revoked": False,
    }
    secrets_store.save(store, sp)
    s = _store(tmp_path)
    # Device catalog views are assignment projections, not shared inventory.
    s.set_policy(device_id, approved_image_id="img1")
    kwargs = {}
    if audit_path is not None:
        kwargs["audit_path"] = audit_path
    srv = catalog.make_server("127.0.0.1", 0, s, sp, **kwargs)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _req(port, method, path, token=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Authorization": "Bearer " + token} if token else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    return r.status, r.getheader("Content-Type"), r.read()


# ---------------------------------------------------------------------------
# Task 1 — ported HTTP tests (now use secrets_path fixture)
# ---------------------------------------------------------------------------

def test_requires_bearer(tmp_path):
    srv, port = _serve(tmp_path, "tok")
    try:
        status, _, _ = _req(port, "GET", "/v1/images")
        assert status == 401
    finally:
        srv.shutdown()


def test_list_and_get_image(tmp_path):
    srv, port = _serve(tmp_path, "tok")
    try:
        status, ctype, body = _req(port, "GET", "/v1/images", token="tok")
        assert status == 200 and ctype == "application/json"
        assert json.loads(body)["images"][0]["id"] == "img1"
        status, _, body = _req(port, "GET", "/v1/images/img1", token="tok")
        assert json.loads(body)["sha256"] == "ab" * 32
        status, _, _ = _req(port, "GET", "/v1/images/none", token="tok")
        assert status == 404
    finally:
        srv.shutdown()


def test_device_wire_strips_internal_quarantine_bookkeeping_fields(tmp_path):
    """The device-facing /v1/images and /v1/images/<id> routes must not leak
    catalog.py's own internal bookkeeping fields to agents --
    quarantine_actions_complete (convergence-retry state) and
    quarantine_override_sha512 (the re-quarantine-suppression ack). Mirrors
    gui_server._image_view's console-side projection rationale;
    hash_verification and quarantined stay wire-visible -- an agent
    benefits from knowing its own image's verification state."""
    srv, port = _serve(tmp_path, "tok")
    try:
        store = catalog.CatalogStore(str(tmp_path))
        entry = store.get_image("img1")
        entry["quarantined"] = True
        entry["quarantine_actions_complete"] = False
        entry["quarantine_override_sha512"] = "aa" * 64
        entry["hash_verification"] = {
            "state": "mismatch", "checked_at": 1, "feed_published_at": None,
            "source": "scheduled", "deferral": False}
        store.save_image(entry)

        status, _, body = _req(port, "GET", "/v1/images", token="tok")
        img = json.loads(body)["images"][0]
        assert img["quarantined"] is True
        assert img["hash_verification"]["state"] == "mismatch"
        assert "quarantine_actions_complete" not in img
        assert "quarantine_override_sha512" not in img

        status, _, body = _req(port, "GET", "/v1/images/img1", token="tok")
        img2 = json.loads(body)
        assert img2["quarantined"] is True
        assert img2["hash_verification"]["state"] == "mismatch"
        assert "quarantine_actions_complete" not in img2
        assert "quarantine_override_sha512" not in img2
    finally:
        srv.shutdown()


def test_torrent_download_device_without_announce_fails_closed(tmp_path):
    # A device catalog principal with NO announce credential must fail CLOSED
    # (spec §6) — never a canonical/seeder-token fallback. The _store fixture's
    # device (from _serve) has no announce_token minted.
    srv, port = _serve(tmp_path, "tok")
    try:
        status, ctype, body = _req(
            port, "GET", "/v1/torrents/img1.torrent", token="tok")
        assert status == 500
        # No token, announce URL, or query string leaks into the error body.
        assert b"tok" not in body
        assert b"announce_token" not in body
    finally:
        srv.shutdown()


def test_heartbeat_and_policy_endpoints(tmp_path):
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        status, _, _ = _req(port, "POST", "/v1/devices/sw-9/heartbeat",
                            token="tok",
                            body=json.dumps({"current_image_id": "img1",
                                             "free_flash_bytes": 9,
                                             "version": "17.18",
                                             "stage_state": "ready"}))
        assert status == 200
        # Fleet enumeration moved to the management API; a device credential
        # has no catalog-wide device collection.
        status, _, _ = _req(port, "GET", "/v1/devices", token="tok")
        assert status == 404
        assert catalog.CatalogStore(str(tmp_path)).get_device(
            "sw-9")["stage_state"] == "ready"
        status, _, body = _req(
            port, "GET", "/v1/devices/sw-9/policy", token="tok")
        assert status == 200          # default policy when none set
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Task 1 NEW: per-request load (token minted AFTER server start is accepted)
# ---------------------------------------------------------------------------

def test_per_request_load_accepts_token_minted_after_server_start(tmp_path):
    """A catalog token minted AFTER make_server() is called must be accepted
    on the next request — no server restart needed."""
    sp = _secrets_path(tmp_path)
    s = _store(tmp_path)
    srv = catalog.make_server("127.0.0.1", 0, s, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        # No tokens yet — 401
        status, _, _ = _req(port, "GET", "/v1/images")
        assert status == 401
        # Mint a token AFTER the server is already running
        new_tok = _mint_catalog_token(sp, "any-device")
        # Should be accepted immediately (per-request load)
        status, _, body = _req(port, "GET", "/v1/images", token=new_tok)
        assert status == 200
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Task 1 NEW: device-bound route rejects token for a different device
# ---------------------------------------------------------------------------

def test_device_bound_route_rejects_wrong_device_token(tmp_path):
    """A heartbeat for device A must be rejected with device B's token."""
    sp = _secrets_path(tmp_path)
    tok_b = _mint_catalog_token(sp, "device-b")
    s = _store(tmp_path)
    srv = catalog.make_server("127.0.0.1", 0, s, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        # device-b's token trying to POST a heartbeat for device-a
        status, _, _ = _req(port, "POST", "/v1/devices/device-a/heartbeat",
                            token=tok_b,
                            body=json.dumps({"current_image_id": "img1"}))
        assert status == 401
        # Same token IS allowed for device-b's heartbeat
        status, _, _ = _req(port, "POST", "/v1/devices/device-b/heartbeat",
                            token=tok_b,
                            body=json.dumps({"current_image_id": "img1"}))
        assert status == 200
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Task 1 NEW: shared route accepts any valid catalog token
# ---------------------------------------------------------------------------

def test_shared_route_accepts_any_valid_catalog_token(tmp_path):
    """GET /v1/images (shared) accepts a token not bound to a specific device."""
    sp = _secrets_path(tmp_path)
    tok_a = _mint_catalog_token(sp, "device-a")
    tok_b = _mint_catalog_token(sp, "device-b")
    s = _store(tmp_path)
    srv = catalog.make_server("127.0.0.1", 0, s, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        # Both tokens can list images
        assert _req(port, "GET", "/v1/images", token=tok_a)[0] == 200
        assert _req(port, "GET", "/v1/images", token=tok_b)[0] == 200
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Task 2: token-refresh success path
# ---------------------------------------------------------------------------

def _serve_with_device(tmp_path, device_id="dev-1"):
    """Helper: create a secrets store with announce+rpc minted too, return
    (srv, port, catalog_token)."""
    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    cat_tok = secrets_store.mint(store, device_id, "catalog_token", now)
    secrets_store.mint(store, device_id, "announce_token", now)
    secrets_store.mint(store, device_id, "rpc_secret", now)
    secrets_store.save(store, sp)
    s = _store(tmp_path)
    os.environ["IRIS_AGE_RECIPIENTS"] = ""   # skip encrypt_from in tests
    audit_path = str(tmp_path / "audit.jsonl")
    srv = catalog.make_server("127.0.0.1", 0, s, sp, audit_path=audit_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], cat_tok


def test_token_refresh_returns_new_token_and_secret_bag(tmp_path):
    """Refresh lazily provisions and returns the closed instruction-key bag."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-1")
    try:
        status, ctype, body_bytes = _req(
            port, "POST",
            "/v1/devices/dev-1/token-refresh",
            token=old_tok,
            body=b"{}")
        assert status == 200
        resp = json.loads(body_bytes)
        assert "catalog_token" in resp
        assert "expires_at" in resp
        assert "announce_token" in resp
        assert "rpc_secret" in resp
        assert set(resp["instr_key"]) == {"value", "key_id"}
        assert "instr_key_prev" not in resp
        assert resp["catalog_token"] != old_tok
    finally:
        srv.shutdown()

    persisted = secrets_store.load(_secrets_path(tmp_path))["devices"]["dev-1"]
    assert resp["instr_key"] == {
        "value": persisted["instr_key"]["value"],
        "key_id": persisted["instr_key"]["key_id"],
    }
    with open(str(tmp_path / "audit.jsonl"), encoding="utf-8") as stream:
        audit_text = stream.read()
    assert persisted["instr_key"]["value"] not in audit_text


def test_token_refresh_omits_absent_announce_and_rpc(tmp_path):
    """If a device has a catalog_token but NO announce_token / rpc_secret
    records, token-refresh must OMIT those keys from the response rather than
    send empty strings.

    The agent persists a returned secret only when `bag.get(name) is not None`
    (device/agent/iris_agent.py:_refresh_impl) so it can skip fields the server
    has no value for.  An empty string is `not None`, so sending "" would make
    the agent overwrite its working announce_token / rpc_secret with "",
    wiping the secrets that let it join the swarm and talk to aria2.  Omitting
    the field is what the agent's guard expects."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    # _serve mints ONLY a catalog_token for the device (no announce/rpc).
    srv, port = _serve(tmp_path, "tok", device_id="dev-bare",
                       audit_path=str(tmp_path / "audit.jsonl"))
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-bare/token-refresh",
            token="tok", body=b"{}")
        assert status == 200
        resp = json.loads(body)
        assert "catalog_token" in resp and resp["catalog_token"] != "tok"
        # The absent secrets must NOT be present as empty strings.
        assert "announce_token" not in resp, (
            "absent announce_token sent as %r (would wipe agent secret)"
            % resp.get("announce_token"))
        assert "rpc_secret" not in resp, (
            "absent rpc_secret sent as %r (would wipe agent secret)"
            % resp.get("rpc_secret"))
    finally:
        srv.shutdown()


def test_token_refresh_includes_present_announce_and_rpc(tmp_path):
    """When the device DOES have announce_token / rpc_secret, token-refresh
    returns their real values (the omit-when-absent fix must not drop present
    secrets)."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-full")
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-full/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
        resp = json.loads(body)
        assert resp.get("announce_token"), "present announce_token was dropped"
        assert resp.get("rpc_secret"), "present rpc_secret was dropped"
    finally:
        srv.shutdown()


def _serve_with_instruction_records(tmp_path, current, previous=None,
                                    device_id="dev-instr"):
    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    token = secrets_store.mint(store, device_id, "catalog_token", now)
    secrets_store.mint(store, device_id, "announce_token", now)
    secrets_store.mint(store, device_id, "rpc_secret", now)
    dev = store["devices"][device_id]
    if current is not None:
        dev["instr_key"] = current
    if previous is not None:
        dev["instr_key_prev"] = previous
    secrets_store.save(store, sp)
    srv = catalog.make_server(
        "127.0.0.1", 0, _store(tmp_path), sp,
        audit_path=str(tmp_path / "audit.jsonl"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], token


def test_token_refresh_delivers_expired_current_and_live_previous(tmp_path):
    now = int(time.time())
    current = _instruction_record(
        "11" * 32, now - 2592001, now - 1)
    previous = _instruction_record(
        "12" * 32, now - 200, now + 200)
    srv, port, token = _serve_with_instruction_records(
        tmp_path, current, previous)
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-instr/token-refresh",
            token=token, body=b"{}")
        assert status == 200
        bag = json.loads(body)
        assert bag["instr_key"] == {
            "value": current["value"], "key_id": current["key_id"]}
        assert bag["instr_key_prev"] == {
            "value": previous["value"], "key_id": previous["key_id"]}
    finally:
        srv.shutdown()


@pytest.mark.parametrize("previous_state", ["absent", "expired", "boundary",
                                             "revoked"])
def test_token_refresh_omits_ineligible_instruction_previous(
        tmp_path, previous_state):
    now = int(time.time())
    current = _instruction_record("13" * 32, now - 100)
    previous = None
    if previous_state != "absent":
        expiry = now if previous_state == "boundary" else now - 1
        if previous_state == "revoked":
            expiry = now + 100
        previous = _instruction_record(
            "14" * 32, now - 200, expiry,
            revoked=previous_state == "revoked")
    srv, port, token = _serve_with_instruction_records(
        tmp_path, current, previous)
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-instr/token-refresh",
            token=token, body=b"{}")
        assert status == 200
        assert "instr_key_prev" not in json.loads(body)
    finally:
        srv.shutdown()


@pytest.mark.parametrize("previous_state", ["live", "expired", "revoked"])
def test_token_refresh_refuses_duplicate_instruction_pair_before_omission(
        tmp_path, previous_state):
    now = int(time.time())
    current = _instruction_record("1a" * 32, now - 100)
    previous = dict(current)
    if previous_state == "live":
        previous["expires_at"] = now + 100
    elif previous_state == "expired":
        previous["expires_at"] = now - 1
    else:
        previous["expires_at"] = now + 100
        previous["revoked"] = True
    srv, port, token = _serve_with_instruction_records(
        tmp_path, current, previous)
    path = Path(_secrets_path(tmp_path))
    before = path.read_bytes()
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-instr/token-refresh",
            token=token, body=b"{}")
        assert status == 503
        assert json.loads(body)["error"] == "service unavailable"
        assert current["value"].encode() not in body
    finally:
        srv.shutdown()
    assert path.read_bytes() == before


def test_previous_token_recovery_refuses_duplicate_instruction_pair(
        tmp_path):
    now = int(time.time())
    current = _instruction_record("1b" * 32, now - 100)
    srv, port, token = _serve_with_instruction_records(tmp_path, current)
    path = _secrets_path(tmp_path)
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-instr/token-refresh",
            token=token, body=b"{}")
        assert status == 200
        with secrets_store.store_lock(path):
            stored = secrets_store.load(path)
            duplicate = dict(stored["devices"]["dev-instr"]["instr_key"])
            duplicate["expires_at"] = now + 100
            stored["devices"]["dev-instr"]["instr_key_prev"] = duplicate
            secrets_store.save(stored, path)
        before = Path(path).read_bytes()

        status, _, body = _req(
            port, "POST", "/v1/devices/dev-instr/token-refresh",
            token=token, body=b"{}")
        assert status == 503
        assert json.loads(body)["error"] == "service unavailable"
        assert current["value"].encode() not in body
    finally:
        srv.shutdown()
    assert Path(path).read_bytes() == before


def test_token_refresh_refuses_present_null_instruction_previous(tmp_path):
    now = int(time.time())
    current = _instruction_record("1c" * 32, now - 100)
    srv, port, token = _serve_with_instruction_records(tmp_path, current)
    path = _secrets_path(tmp_path)
    with secrets_store.store_lock(path):
        stored = secrets_store.load(path)
        stored["devices"]["dev-instr"]["instr_key_prev"] = None
        secrets_store.save(stored, path)
    before = Path(path).read_bytes()
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-instr/token-refresh",
            token=token, body=b"{}")
        assert status == 503
        assert json.loads(body)["error"] == "service unavailable"
    finally:
        srv.shutdown()
    assert Path(path).read_bytes() == before


@pytest.mark.parametrize("damage", ["missing-current", "bad-current-id",
                                    "extra-current-field", "bad-previous"])
def test_token_refresh_refuses_malformed_or_inconsistent_instruction_state(
        tmp_path, damage):
    now = int(time.time())
    current = _instruction_record("15" * 32, now - 100)
    previous = _instruction_record("16" * 32, now - 50, now + 100)
    if damage == "missing-current":
        current = None
    elif damage == "bad-current-id":
        current["key_id"] = "canary-malicious-field"
        previous = None
    elif damage == "extra-current-field":
        current["extra"] = "canary-malicious-field"
        previous = None
    else:
        previous["value"] = "canary-malicious-field"
    srv, port, token = _serve_with_instruction_records(
        tmp_path, current, previous)
    path = Path(_secrets_path(tmp_path))
    before = path.read_bytes()
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-instr/token-refresh",
            token=token, body=b"{}")
        assert status == 503
        assert json.loads(body)["error"] == "service unavailable"
        assert b"canary" not in body
    finally:
        srv.shutdown()
    assert path.read_bytes() == before


def test_token_refresh_refuses_revoked_instruction_current_without_disclosure(
        tmp_path):
    now = int(time.time())
    current = _instruction_record("17" * 32, now - 100, revoked=True)
    srv, port, token = _serve_with_instruction_records(tmp_path, current)
    path = Path(_secrets_path(tmp_path))
    before = path.read_bytes()
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-instr/token-refresh",
            token=token, body=b"{}")
        assert status == 409
        assert json.loads(body)["error"] == "device revoked"
        assert current["value"].encode() not in body
    finally:
        srv.shutdown()
    assert path.read_bytes() == before


def test_instruction_rotation_winning_lock_is_preserved_by_refresh(
        tmp_path, monkeypatch):
    now = int(time.time())
    old_instruction = _instruction_record("18" * 32, now - 100)
    srv, port, token = _serve_with_instruction_records(
        tmp_path, old_instruction)
    path = _secrets_path(tmp_path)
    real_lock = secrets_store.store_lock
    reached = threading.Event()

    @contextlib.contextmanager
    def announced_lock(lock_path):
        reached.set()
        with real_lock(lock_path):
            yield

    monkeypatch.setattr(secrets_store, "store_lock", announced_lock)
    result = {}

    def refresh():
        result["status"], _, result["body"] = _req(
            port, "POST", "/v1/devices/dev-instr/token-refresh",
            token=token, body=b"{}")

    try:
        with real_lock(path):
            thread = threading.Thread(target=refresh)
            thread.start()
            assert reached.wait(timeout=3)
            rotated = secrets_store.load(path)
            secrets_store.rotate_instruction_key(rotated, "dev-instr", now + 1)
            secrets_store.save(rotated, path)
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert result["status"] == 200
        bag = json.loads(result["body"])
    finally:
        srv.shutdown()

    final = secrets_store.load(path)["devices"]["dev-instr"]
    assert bag["instr_key"]["key_id"] == final["instr_key"]["key_id"]
    assert bag["instr_key_prev"]["key_id"] == old_instruction["key_id"]
    assert final["catalog_token"]["value"] != token


def test_refresh_audit_ids_are_hashes_not_token_prefixes(tmp_path):
    """The refresh audit line must record a truncated sha256 of each token,
    never a prefix of the live token value.  audit.jsonl lives on the
    unencrypted /etc/iris volume, so value[:8] would leak 32 bits of a live
    secret (see audit.py invariant)."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-1")
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-1/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
        new_tok = json.loads(body)["catalog_token"]

        with open(str(tmp_path / "audit.jsonl")) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        refresh = [e for e in lines if e["event"] == "refresh"][-1]

        # Must NOT be raw token prefixes (the bug being fixed).
        assert refresh["old_id"] != old_tok[:8]
        assert refresh["new_id"] != new_tok[:8]
        # Must be the truncated sha256 — correlatable but non-secret.
        assert refresh["old_id"] == hashlib.sha256(old_tok.encode()).hexdigest()[:8]
        assert refresh["new_id"] == hashlib.sha256(new_tok.encode()).hexdigest()[:8]
    finally:
        srv.shutdown()


def test_token_refresh_prev_stash_uses_int_epochs(tmp_path):
    """The catalog_token_prev stash written on refresh must hold INT epoch
    seconds (created_at / expires_at), not the float time.time().  A float
    expires_at violates the store's int-epoch invariant and trips
    int('...9') ValueError in the agent's run_once on the next tick."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-int")
    original_expiry = secrets_store.load(
        _secrets_path(tmp_path))["devices"]["dev-int"]["catalog_token"][
            "expires_at"]
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-int/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
    finally:
        srv.shutdown()

    store = secrets_store.load(_secrets_path(tmp_path))
    prev = store["devices"]["dev-int"]["catalog_token_prev"]
    assert isinstance(prev["expires_at"], int), (
        "catalog_token_prev.expires_at must be int, got %r"
        % type(prev["expires_at"]))
    assert isinstance(prev["created_at"], int), (
        "catalog_token_prev.created_at must be int, got %r"
        % type(prev["created_at"]))
    assert isinstance(prev["refresh_expires_at"], int)
    assert prev["refresh_expires_at"] == original_expiry


# ---------------------------------------------------------------------------
# Task 3: 401 on wrong-device, expired; auth_fail audit line
# ---------------------------------------------------------------------------

def test_token_refresh_wrong_device_401(tmp_path):
    """Device B's token cannot refresh device A."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    secrets_store.mint(store, "dev-a", "catalog_token", now)
    tok_b = secrets_store.mint(store, "dev-b", "catalog_token", now)
    secrets_store.save(store, sp)
    s = _store(tmp_path)
    audit_path = str(tmp_path / "audit.jsonl")
    srv = catalog.make_server("127.0.0.1", 0, s, sp, audit_path=audit_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        status, _, _ = _req(port, "POST",
                            "/v1/devices/dev-a/token-refresh",
                            token=tok_b, body=b"{}")
        assert status == 401
    finally:
        srv.shutdown()


def test_token_refresh_expired_token_401(tmp_path):
    """An expired catalog token gets a 401 on token-refresh."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    sp = _secrets_path(tmp_path)
    past = time.time() - 10000    # well in the past
    store = secrets_store.load(sp)
    expired_tok = "expiredtokendeadbeef00000000dead"   # 32 hex chars
    store["devices"]["dev-x"] = {
        "catalog_token": {
            "value": expired_tok,
            "created_at": past - 3600,
            "expires_at": past,   # expired; grace=300 so well outside window
            "revoked": False,
        }
    }
    secrets_store.save(store, sp)
    s = _store(tmp_path)
    srv = catalog.make_server("127.0.0.1", 0, s, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        status, _, _ = _req(port, "POST",
                            "/v1/devices/dev-x/token-refresh",
                            token=expired_tok,
                            body=b"{}")
        assert status == 401
    finally:
        srv.shutdown()


def test_auth_fail_writes_audit_line(tmp_path):
    """A failed token-refresh writes an auth_fail audit line with result='fail'."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    secrets_store.mint(store, "dev-a", "catalog_token", now)
    tok_b = secrets_store.mint(store, "dev-b", "catalog_token", now)
    secrets_store.save(store, sp)
    s = _store(tmp_path)
    audit_path = str(tmp_path / "audit.jsonl")
    srv = catalog.make_server("127.0.0.1", 0, s, sp, audit_path=audit_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        _req(port, "POST", "/v1/devices/dev-a/token-refresh",
             token=tok_b, body=b"{}")
        # Read audit file
        with open(audit_path) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        fail_events = [e for e in lines if e["event"] == "auth_fail"]
        assert fail_events, "expected auth_fail audit line"
        assert fail_events[-1]["result"] == "fail"
        # The path identity is unauthenticated attacker input; the audit line
        # records the refusal without persisting that unbounded string.
        assert fail_events[-1]["device_id"] == "unresolved"
        attacker_id = "x" * 32000
        _req(port, "POST", "/v1/devices/" + attacker_id + "/token-refresh",
             token=tok_b, body=b"{}")
        with open(audit_path, encoding="utf-8") as stream:
            raw_audit = stream.read()
        assert attacker_id not in raw_audit
        assert max(len(line) for line in raw_audit.splitlines()) < 2048
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Task 4: old token overlap grace after refresh
# ---------------------------------------------------------------------------

def test_old_token_still_valid_within_overlap_after_refresh(tmp_path):
    """After a refresh, the OLD catalog token is still accepted within OVERLAP
    seconds (rotate_catalog sets old.expires_at = now + overlap)."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-ol")
    try:
        # Do the refresh
        status, _, body_bytes = _req(
            port, "POST",
            "/v1/devices/dev-ol/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
        new_tok = json.loads(body_bytes)["catalog_token"]
        assert new_tok != old_tok

        # OLD token must still work on GET /v1/images (shared route)
        status, _, _ = _req(port, "GET", "/v1/images", token=old_tok)
        assert status == 200, "old token should still be valid within overlap"

        # NEW token also works
        status, _, _ = _req(port, "GET", "/v1/images", token=new_tok)
        assert status == 200
    finally:
        srv.shutdown()


def test_lost_refresh_response_retry_reissues_current_token(tmp_path):
    """Losing the first 200 must not make a retry rotate a second time.

    The caller deliberately discards the first response, then retries with the
    only token it durably knows.  The previous token may recover the current
    bag on this route, but it must not mint another token.
    """
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-lost")
    try:
        status, _, first_body = _req(
            port, "POST", "/v1/devices/dev-lost/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
        first_bag = json.loads(first_body)
        current_tok = first_bag["catalog_token"]
        instruction = first_bag["instr_key"]

        # Model a lost/truncated response: the next request still carries OLD.
        status, _, retry_body = _req(
            port, "POST", "/v1/devices/dev-lost/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
        assert json.loads(retry_body) == first_bag
    finally:
        srv.shutdown()

    final = secrets_store.load(_secrets_path(tmp_path))["devices"]["dev-lost"]
    assert final["catalog_token"]["value"] == current_tok
    assert final["catalog_token_prev"]["value"] == old_tok
    assert instruction == {
        "value": final["instr_key"]["value"],
        "key_id": final["instr_key"]["key_id"],
    }


def test_previous_token_recovery_lazily_persists_missing_instruction_key(
        tmp_path):
    """A legacy store can first encounter Task 12 on the recovery branch."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_token = _serve_with_device(tmp_path, "dev-recovery-lazy")
    path = _secrets_path(tmp_path)
    try:
        status, _, first_body = _req(
            port, "POST", "/v1/devices/dev-recovery-lazy/token-refresh",
            token=old_token, body=b"{}")
        assert status == 200
        current_token = json.loads(first_body)["catalog_token"]

        # Reconstruct the valid legacy shape that can exist during a rolling
        # upgrade: current+recovery catalog credentials but no instruction key.
        with secrets_store.store_lock(path):
            legacy = secrets_store.load(path)
            legacy["devices"]["dev-recovery-lazy"].pop("instr_key")
            secrets_store.save(legacy, path)

        status, _, recovery_body = _req(
            port, "POST", "/v1/devices/dev-recovery-lazy/token-refresh",
            token=old_token, body=b"{}")
        assert status == 200
        recovery_bag = json.loads(recovery_body)
        assert recovery_bag["catalog_token"] == current_token
        assert set(recovery_bag["instr_key"]) == {"value", "key_id"}
    finally:
        srv.shutdown()

    persisted = secrets_store.load(path)["devices"]["dev-recovery-lazy"]
    assert recovery_bag["instr_key"]["key_id"] == (
        persisted["instr_key"]["key_id"])


def test_previous_token_recovers_after_conf_write_failure_on_next_tick(
        tmp_path):
    """A next process may recover even after the shared-route overlap elapsed.

    This models _refresh_impl receiving the new bag but failing its atomic conf
    rewrite: the next one-shot process reloads OLD from disk.  Recovery is
    scoped to token-refresh and lasts while the missed CURRENT token itself is
    valid; it does not extend OLD's access to shared catalog routes.
    """
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-write-fail")
    sp = _secrets_path(tmp_path)
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-write-fail/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
        current_tok = json.loads(body)["catalog_token"]

        # Advance only the persisted previous-token deadline beyond overlap
        # (and the normal skew grace) without expiring the current token.
        with secrets_store.store_lock(sp):
            store = secrets_store.load(sp)
            store["devices"]["dev-write-fail"]["catalog_token_prev"][
                "expires_at"] = int(time.time()) - 1000
            secrets_store.save(store, sp)

        assert _req(port, "GET", "/v1/images", token=old_tok)[0] == 401
        status, _, retry_body = _req(
            port, "POST", "/v1/devices/dev-write-fail/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
        assert json.loads(retry_body)["catalog_token"] == current_tok
    finally:
        srv.shutdown()


def test_previous_token_recovery_does_not_outlive_original_expiry(tmp_path):
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-expired-recovery")
    sp = _secrets_path(tmp_path)
    try:
        assert _req(
            port, "POST", "/v1/devices/dev-expired-recovery/token-refresh",
            token=old_tok, body=b"{}")[0] == 200
        with secrets_store.store_lock(sp):
            store = secrets_store.load(sp)
            prev = store["devices"]["dev-expired-recovery"][
                "catalog_token_prev"]
            # Keep ordinary overlap auth live while expiring recovery itself.
            # token-refresh must honor the original credential deadline rather
            # than accidentally inheriting the later shared-route deadline.
            prev["expires_at"] = int(time.time()) + 1000
            prev["refresh_expires_at"] = int(time.time()) - 1000
            secrets_store.save(store, sp)

        assert _req(
            port, "GET", "/v1/images", token=old_tok)[0] == 200
        assert _req(
            port, "POST", "/v1/devices/dev-expired-recovery/token-refresh",
            token=old_tok, body=b"{}")[0] == 401
    finally:
        srv.shutdown()


def test_previous_token_cannot_reissue_an_expired_current_token(tmp_path):
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-current-expired")
    sp = _secrets_path(tmp_path)
    try:
        assert _req(
            port, "POST", "/v1/devices/dev-current-expired/token-refresh",
            token=old_tok, body=b"{}")[0] == 200
        with secrets_store.store_lock(sp):
            store = secrets_store.load(sp)
            current = store["devices"]["dev-current-expired"][
                "catalog_token"]
            current["expires_at"] = int(time.time()) - 1000
            secrets_store.save(store, sp)

        assert _req(
            port, "POST", "/v1/devices/dev-current-expired/token-refresh",
            token=old_tok, body=b"{}")[0] == 401
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Task 5 NEW: overlap asymmetry — recovery is token-refresh-only
# ---------------------------------------------------------------------------

def test_old_token_rejected_on_heartbeat_and_telemetry_after_refresh(tmp_path):
    """Recovery never grants OLD access to heartbeat or telemetry.

    The previous token remains accepted on shared routes during the ordinary
    overlap and on token-refresh for idempotent recovery only.  The two
    state-mutating device-bound report routes still require CURRENT.
    """
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-asym")
    try:
        # Perform the refresh to roll the token
        status, _, body_bytes = _req(
            port, "POST",
            "/v1/devices/dev-asym/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
        new_tok = json.loads(body_bytes)["catalog_token"]
        assert new_tok != old_tok

        # OLD token on device-bound heartbeat → 401.
        status, _, _ = _req(port, "POST",
                            "/v1/devices/dev-asym/heartbeat",
                            token=old_tok,
                            body=json.dumps({"current_image_id": "img1"}))
        assert status == 401, "old token must be rejected on heartbeat"

        status, _, _ = _req(port, "POST",
                            "/v1/devices/dev-asym/telemetry",
                            token=old_tok, body=b"{}")
        assert status == 401, "old token must be rejected on telemetry"

        # OLD token on shared route GET /v1/images → still 200 within overlap
        status, _, _ = _req(port, "GET", "/v1/images", token=old_tok)
        assert status == 200, "old token must still work on shared route within overlap"

        # Recovery is the sole device-bound exception and reissues CURRENT.
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-asym/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200
        assert json.loads(body)["catalog_token"] == new_tok
    finally:
        srv.shutdown()


def test_previous_token_cannot_recover_a_different_device(tmp_path):
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    tok_a = secrets_store.mint(store, "dev-a", "catalog_token", now)
    tok_b = secrets_store.mint(store, "dev-b", "catalog_token", now)
    secrets_store.save(store, sp)
    srv = catalog.make_server(
        "127.0.0.1", 0, _store(tmp_path), sp,
        audit_path=str(tmp_path / "audit.jsonl"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        status, _, _ = _req(
            port, "POST", "/v1/devices/dev-b/token-refresh",
            token=tok_b, body=b"{}")
        assert status == 200

        status, _, _ = _req(
            port, "POST", "/v1/devices/dev-a/token-refresh",
            token=tok_b, body=b"{}")
        assert status == 401
        # Device A's own current token remains usable.
        assert _req(
            port, "POST", "/v1/devices/dev-a/token-refresh",
            token=tok_a, body=b"{}")[0] == 200
    finally:
        srv.shutdown()


def test_concurrent_same_token_refresh_reissues_one_rotation(tmp_path):
    """Two in-flight requests carrying one token converge on one successor."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-same")
    barrier = threading.Barrier(2)
    results = []
    errors = []

    def refresh():
        try:
            barrier.wait()
            status, _, body = _req(
                port, "POST", "/v1/devices/dev-same/token-refresh",
                token=old_tok, body=b"{}")
            results.append((status, json.loads(body)))
        except Exception as exc:  # pragma: no cover - surfaced via assert
            errors.append(exc)

    try:
        threads = [threading.Thread(target=refresh) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert not errors, errors
        assert all(not thread.is_alive() for thread in threads)
        assert [status for status, _ in results] == [200, 200]
        assert results[0][1] == results[1][1]
    finally:
        srv.shutdown()


def test_revoke_wins_over_previous_token_recovery(tmp_path):
    """Recovery must re-check the current store after taking its write lock."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-recover-revoke")
    sp = _secrets_path(tmp_path)
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-recover-revoke/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200

        result = {}

        def recover():
            result["status"], _, result["body"] = _req(
                port, "POST",
                "/v1/devices/dev-recover-revoke/token-refresh",
                token=old_tok, body=b"{}")

        with secrets_store.store_lock(sp):
            thread = threading.Thread(target=recover)
            thread.start()
            time.sleep(0.3)
            store = secrets_store.load(sp)
            secrets_store.revoke(store, "dev-recover-revoke")
            secrets_store.save(store, sp)
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert result.get("status") == 409, result.get("body")
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Concurrency: unique temp file + serialized writes (review finding — race)
# ---------------------------------------------------------------------------

def test_atomic_write_json_uses_unique_temp(tmp_path, monkeypatch):
    """Two _atomic_write_json calls to the same target must use DISTINCT temp
    paths so concurrent writers never truncate/interleave one shared `.tmp`."""
    import glob
    p = str(tmp_path / "state.json")
    seen = []
    real_replace = os.replace

    def spy_replace(src, dst):
        seen.append(src)
        return real_replace(src, dst)

    monkeypatch.setattr(catalog.os, "replace", spy_replace)
    catalog._atomic_write_json(p, {"a": 1})
    catalog._atomic_write_json(p, {"b": 2})

    assert len(seen) == 2
    assert seen[0] != seen[1], (
        "_atomic_write_json reused a shared temp path; concurrent writers "
        "would clobber each other")
    assert not os.path.exists(p + ".tmp")
    assert not glob.glob(str(tmp_path / "*.tmp"))


def test_concurrent_heartbeats_lose_no_records(tmp_path):
    """N threads recording a heartbeat for a DIFFERENT device id concurrently
    against one CatalogStore must leave a record for EVERY device on disk and
    a valid devices.json (no lost-update / torn-tmp race)."""
    s = catalog.CatalogStore(str(tmp_path))
    n = 40
    barrier = threading.Barrier(n)
    errors = []

    def beat(i):
        try:
            barrier.wait()
            s.record_heartbeat("dev-%d" % i,
                               {"current_image_id": "img1",
                                "free_flash_bytes": i, "version": "17.18"})
        except Exception as exc:  # pragma: no cover - surfaced via assert
            errors.append(exc)

    threads = [threading.Thread(target=beat, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    s2 = catalog.CatalogStore(str(tmp_path))      # fresh read from disk
    devices = s2.list_devices()
    assert len(devices) == n, "lost heartbeat records: %d of %d" % (
        len(devices), n)


def test_concurrent_token_refresh_keeps_all_new_tokens(tmp_path):
    """Many devices refresh their catalog token concurrently against the
    threaded server.  Each device whose refresh returned 200 with a NEW token
    must still find that token valid afterwards — i.e. no rotation was silently
    lost to a whole-file last-writer-wins race, and the store stays valid JSON."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    n = 24
    old_toks = {}
    for i in range(n):
        did = "dev-%d" % i
        old_toks[did] = secrets_store.mint(store, did, "catalog_token", now)
    secrets_store.save(store, sp)
    s = _store(tmp_path)
    audit_path = str(tmp_path / "audit.jsonl")
    srv = catalog.make_server("127.0.0.1", 0, s, sp, audit_path=audit_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    new_toks = {}
    lock = threading.Lock()
    barrier = threading.Barrier(n)
    errors = []

    def refresh(i):
        did = "dev-%d" % i
        try:
            barrier.wait()
            status, _, body = _req(
                port, "POST", "/v1/devices/%s/token-refresh" % did,
                token=old_toks[did], body=b"{}")
            assert status == 200
            with lock:
                new_toks[did] = json.loads(body)["catalog_token"]
        except Exception as exc:  # pragma: no cover - surfaced via assert
            errors.append(exc)

    try:
        threads = [threading.Thread(target=refresh, args=(i,))
                   for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors
        assert len(new_toks) == n

        # Every returned new token must still authenticate (be present in the
        # persisted store).  A lost rotation would 401 here.
        for did, tok in new_toks.items():
            status, _, _ = _req(port, "GET", "/v1/images", token=tok)
            assert status == 200, (
                "device %s lost its rotated token (got %d)" % (did, status))
    finally:
        srv.shutdown()

    # Persisted store is valid JSON and holds every rotated token.
    final = secrets_store.load(sp)
    assert len(final["devices"]) == n


# ---------------------------------------------------------------------------
# Durability: a failed durable (.age) write must NOT diverge the live tmpfs
# store from the durable store (review finding — revoke/rotate durability)
# ---------------------------------------------------------------------------

def test_token_refresh_durable_write_failure_keeps_old_token(tmp_path,
                                                              monkeypatch):
    """If the durable age-encrypted write fails during a token-refresh, the
    live tmpfs plaintext store must NOT have been mutated: the device's OLD
    catalog token must still authenticate (no tmpfs/durable divergence) and
    the rotation must not be reported/persisted.  Otherwise a routine restart
    would decrypt the stale durable store and the rotation would be lost."""
    import secretfs
    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    old_tok = secrets_store.mint(store, "dev-dur", "catalog_token", now)
    secrets_store.mint(store, "dev-dur", "announce_token", now)
    secrets_store.mint(store, "dev-dur", "rpc_secret", now)
    secrets_store.save(store, sp)
    s = _store(tmp_path)
    # Recipients SET so the durable re-encrypt branch runs, but make the
    # durable write fail.
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1fakerecipient")
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "secrets.json.age"))

    def boom(*a, **k):
        raise RuntimeError("age binary exploded")

    monkeypatch.setattr(secretfs, "encrypt_from", boom)

    audit_path = str(tmp_path / "audit.jsonl")
    srv = catalog.make_server("127.0.0.1", 0, s, sp, audit_path=audit_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        # The refresh must NOT report success (durable write failed).
        status, _, _ = _req(port, "POST",
                            "/v1/devices/dev-dur/token-refresh",
                            token=old_tok, body=b"{}")
        assert status != 200, "refresh reported success despite durable failure"

        # The OLD token must still authenticate on a device-bound route: the
        # tmpfs store was NOT rotated, so it has not diverged from the (stale)
        # durable store.
        status, _, _ = _req(port, "POST",
                            "/v1/devices/dev-dur/heartbeat",
                            token=old_tok,
                            body=json.dumps({"current_image_id": "img1"}))
        assert status == 200, "old token lost after a failed durable write"
    finally:
        srv.shutdown()

    # On disk the tmpfs plaintext still holds the ORIGINAL catalog token.
    final = secrets_store.load(sp)
    assert final["devices"]["dev-dur"]["catalog_token"]["value"] == old_tok
    # No half-applied rotation: no catalog_token_prev stash either.
    assert "catalog_token_prev" not in final["devices"]["dev-dur"]
    assert "instr_key" not in final["devices"]["dev-dur"]


# ---------------------------------------------------------------------------
# Revoke-then-refresh TOCTOU: a device revoked between the pre-lock auth check
# and the under-lock re-read must NOT be handed a fresh live token (review
# finding — the store_lock made the worst-case outcome deterministic).
# ---------------------------------------------------------------------------

def test_revoke_then_refresh_is_rejected(tmp_path):
    """iris-revoke and a token-refresh serialize on the same store_lock.  If
    revoke wins the lock first and marks the device revoked, the subsequently
    unblocked refresh re-reads the (now revoked) store under the lock and must
    REFUSE to rotate — otherwise rotate_catalog/mint would hand the just-revoked
    device a fresh, working catalog_token (revoked=False), silently un-revoking
    it.  We make the race deterministic: hold the lock externally (standing in
    for iris-revoke), fire the refresh so it blocks on store_lock, then revoke +
    save and release the lock.  The refresh must then return 409."""
    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    old_tok = secrets_store.mint(store, "dev-rev", "catalog_token", now)
    secrets_store.save(store, sp)
    s = _store(tmp_path)
    # No durable copy so the persist path is a plain atomic plaintext write.
    os.environ["IRIS_AGE_RECIPIENTS"] = ""

    audit_path = str(tmp_path / "audit.jsonl")
    srv = catalog.make_server("127.0.0.1", 0, s, sp, audit_path=audit_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    result = {}

    def do_refresh():
        # Pre-lock auth (in _guard) sees a still-valid token, so the request
        # gets into _handle_token_refresh and blocks on store_lock below.
        status, _, body = _req(port, "POST",
                               "/v1/devices/dev-rev/token-refresh",
                               token=old_tok, body=b"{}")
        result["status"] = status
        result["body"] = body

    try:
        # iris-revoke wins the lock first and is mid-revoke.
        with secrets_store.store_lock(sp):
            t = threading.Thread(target=do_refresh)
            t.start()
            # Give the refresh time to clear the pre-lock auth check and block
            # on store_lock (it cannot proceed until we exit this with-block).
            time.sleep(0.3)
            revoked_store = secrets_store.load(sp)
            secrets_store.revoke(revoked_store, "dev-rev")
            secrets_store.save(revoked_store, sp)
        # Lock released: the refresh now re-reads the revoked store under it.
        t.join(timeout=5)
        assert not t.is_alive(), "refresh thread hung"
        assert result.get("status") == 409, (
            "revoke-then-refresh handed back %r (expected 409 device revoked)"
            % (result.get("status"),))
        # the refresh_fail line says WHY (distinguishes the two fail causes)
        with open(audit_path) as f:
            fails = [json.loads(l) for l in f if '"refresh_fail"' in l]
        assert fails and fails[-1]["detail"] == "device is revoked"
    finally:
        srv.shutdown()

    # The device must still be fully revoked: no fresh catalog_token slipped in.
    final = secrets_store.load(sp)
    cat_rec = final["devices"]["dev-rev"]["catalog_token"]
    assert cat_rec["revoked"] is True, "refresh un-revoked the device"
    assert cat_rec["value"] == old_tok, "refresh minted a new token post-revoke"
    # And the revoked token must not authenticate on a device-bound route.
    srv2 = catalog.make_server("127.0.0.1", 0, _store(tmp_path), sp,
                               audit_path=audit_path)
    threading.Thread(target=srv2.serve_forever, daemon=True).start()
    port2 = srv2.server_address[1]
    try:
        status, _, _ = _req(port2, "POST",
                            "/v1/devices/dev-rev/heartbeat",
                            token=old_tok,
                            body=json.dumps({"current_image_id": "img1"}))
        assert status == 401, "revoked token still authenticated"
    finally:
        srv2.shutdown()


# ---------------------------------------------------------------------------
# Durable re-encryption coverage: a token-refresh with recipients SET must
# rewrite the at-rest .age volume with the NEW catalog token (review finding —
# the re-encrypt branch was never exercised by any test)
# ---------------------------------------------------------------------------

# Minimal fake `age`: encrypt prepends a header, decrypt strips it.  Mirrors the
# stub in test_secretfs.py so the durable round-trip needs no real age binary.
_FAKE_AGE = r'''#!/usr/bin/env bash
set -euo pipefail
mode="$1"; shift
out=""; inp=""
if [ "$mode" = "-d" ]; then
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -i) shift 2 ;;
      -o) out="$2"; shift 2 ;;
      *) inp="$1"; shift ;;
    esac
  done
  head -n1 "$inp" | grep -q '^AGEFAKE$' || { echo "age: bad ciphertext" >&2; exit 1; }
  tail -n +2 "$inp" > "$out"
else
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -r) shift 2 ;;
      -o) out="$2"; shift 2 ;;
      *) inp="$1"; shift ;;
    esac
  done
  { echo "AGEFAKE"; cat "$inp"; } > "$out"
fi
'''


def test_token_refresh_reencrypts_to_at_rest_age_volume(tmp_path, monkeypatch):
    """With IRIS_AGE_RECIPIENTS set, a token-refresh must rewrite the durable
    .age ciphertext so it decrypts to a store holding the NEW catalog token.

    This covers the production re-encrypt branch (catalog persists the rotated
    store to the persistent age volume): if it were broken, the device would
    get and apply a new token while the durable store kept the OLD one, locking
    the device out after the next restart."""
    import secretfs
    # Inject a fake `age` binary so persist_store's encrypt_from does a real
    # (round-trippable) durable write without a real age install.
    fake_age = tmp_path / "fake-age"
    fake_age.write_text(_FAKE_AGE)
    fake_age.chmod(0o755)
    fake = str(fake_age)

    real_encrypt = secretfs.encrypt_from
    real_decrypt = secretfs.decrypt_to
    monkeypatch.setattr(
        secretfs, "encrypt_from",
        lambda p, e, r, age_bin=fake: real_encrypt(p, e, r, age_bin=fake))

    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    old_tok = secrets_store.mint(store, "dev-enc", "catalog_token", now)
    secrets_store.mint(store, "dev-enc", "announce_token", now)
    secrets_store.mint(store, "dev-enc", "rpc_secret", now)
    secrets_store.save(store, sp)
    s = _store(tmp_path)

    enc_path = str(tmp_path / "secrets.json.age")
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1primary,age1breakglass")
    monkeypatch.setenv("IRIS_SECRETS_ENC", enc_path)

    audit_path = str(tmp_path / "audit.jsonl")
    srv = catalog.make_server("127.0.0.1", 0, s, sp, audit_path=audit_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        status, _, body = _req(port, "POST",
                               "/v1/devices/dev-enc/token-refresh",
                               token=old_tok, body=b"{}")
        assert status == 200
        new_tok = json.loads(body)["catalog_token"]
        assert new_tok != old_tok
    finally:
        srv.shutdown()

    # The durable .age file must exist, be ciphertext (NOT plaintext), and
    # decrypt to a store holding the NEW catalog token.
    assert os.path.exists(enc_path), "durable .age volume was not written"
    with open(enc_path) as f:
        assert f.readline().strip() == "AGEFAKE", "durable copy is plaintext"

    key = tmp_path / "key"
    key.write_text("AGE-SECRET-KEY-FAKE\n")
    back = str(tmp_path / "decrypted-secrets.json")
    real_decrypt(enc_path, back, str(key), age_bin=fake)
    durable = secrets_store.load(back)
    assert (durable["devices"]["dev-enc"]["catalog_token"]["value"]
            == new_tok), "durable store did not get the rotated token"


def test_token_refresh_replace_after_encrypt_failure_keeps_old_token(
        tmp_path, monkeypatch):
    """Companion to the encrypt-fails test: cover the OTHER durable-failure
    path — encrypt_from SUCCEEDS (the .age volume is rewritten) but the
    subsequent os.replace of the new plaintext over the live store then raises.

    persist_store must roll the durable copy back to the OLD store and re-raise,
    so the refresh returns 500, the live tmpfs store keeps the OLD token, and a
    restart (decrypt_to of enc_path) reproduces the OLD store — no divergence,
    no silently-applied rotation."""
    import secretfs
    fake_age = tmp_path / "fake-age"
    fake_age.write_text(_FAKE_AGE)
    fake_age.chmod(0o755)
    fake = str(fake_age)

    real_encrypt = secretfs.encrypt_from
    real_decrypt = secretfs.decrypt_to
    monkeypatch.setattr(
        secretfs, "encrypt_from",
        lambda p, e, r, age_bin=fake: real_encrypt(p, e, r, age_bin=fake))

    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    old_tok = secrets_store.mint(store, "dev-rep", "catalog_token", now)
    secrets_store.save(store, sp)
    s = _store(tmp_path)

    enc_path = str(tmp_path / "secrets.json.age")
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1primary,age1breakglass")
    monkeypatch.setenv("IRIS_SECRETS_ENC", enc_path)

    # Fail ONLY the temp -> live plaintext commit; encrypt_from's own
    # temp -> enc_path swaps (and the rollback re-encrypt) must still work.
    real_replace = os.replace

    def flaky_replace(src, dst):
        if str(dst) == str(sp):
            raise OSError("ENOSPC committing live plaintext")
        return real_replace(src, dst)

    monkeypatch.setattr(secretfs.os, "replace", flaky_replace)

    audit_path = str(tmp_path / "audit.jsonl")
    srv = catalog.make_server("127.0.0.1", 0, s, sp, audit_path=audit_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        status, _, _ = _req(port, "POST",
                            "/v1/devices/dev-rep/token-refresh",
                            token=old_tok, body=b"{}")
        assert status == 500, "refresh reported success despite replace failure"

        # OLD token still authenticates: the live store was not rotated.
        status, _, _ = _req(port, "POST",
                            "/v1/devices/dev-rep/heartbeat",
                            token=old_tok,
                            body=json.dumps({"current_image_id": "img1"}))
        assert status == 200, "old token lost after a failed live commit"
    finally:
        srv.shutdown()

    # Live plaintext keeps the OLD catalog token, no half-applied rotation.
    final = secrets_store.load(sp)
    assert final["devices"]["dev-rep"]["catalog_token"]["value"] == old_tok
    assert "catalog_token_prev" not in final["devices"]["dev-rep"]
    assert "instr_key" not in final["devices"]["dev-rep"]

    # Durable .age was rolled back to the OLD store: a restart's decrypt would
    # reproduce the old token (durable is NOT left ahead of live).
    key = tmp_path / "key"
    key.write_text("AGE-SECRET-KEY-FAKE\n")
    back = str(tmp_path / "restart-secrets.json")
    real_decrypt(enc_path, back, str(key), age_bin=fake)
    durable = secrets_store.load(back)
    assert (durable["devices"]["dev-rep"]["catalog_token"]["value"]
            == old_tok), "durable copy left ahead of live — restart loses token"


# ---------------------------------------------------------------------------
# Robustness: a malformed Content-Length must not crash the POST handler
# (review finding — unhandled ValueError dropped the connection)
# ---------------------------------------------------------------------------

def _raw_post(port, path, token, content_length, body=b""):
    """Send a raw HTTP POST with an explicit (possibly malformed)
    Content-Length header and return the numeric status from the status line
    (or None if the connection was dropped with no response)."""
    req = (
        "POST %s HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Authorization: Bearer %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %s\r\n"
        "Connection: close\r\n"
        "\r\n"
    ) % (path, token, content_length)
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(req.encode() + body)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    if not data:
        return None
    status_line = data.split(b"\r\n", 1)[0]
    # b"HTTP/1.1 400 Bad Request" -> 400
    try:
        return int(status_line.split(b" ")[1])
    except (IndexError, ValueError):
        return None


def test_malformed_content_length_returns_400_not_crash(tmp_path):
    """A non-numeric Content-Length on a POST must yield a 400, not an
    unhandled ValueError that drops the connection with no response."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        status = _raw_post(port, "/v1/devices/sw-9/heartbeat", "tok",
                           content_length="abc", body=b"{}")
        assert status == 400, (
            "malformed Content-Length should be a 400, got %r" % status)
    finally:
        srv.shutdown()


def test_delete_image(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    s.save_image({"id": "img1", "filename": "img1.bin", "size": 5, "sha256": "ab",
                  "info_hash_hex": "cc", "published_at": 1})
    assert s.get_image("img1") is not None
    assert s.delete_image("img1") is True
    assert s.get_image("img1") is None
    assert s.delete_image("img1") is False       # already gone


# ---------------------------------------------------------------------------
# Device telemetry reports (issue #13): ingest, bounded ring, pull directives
# ---------------------------------------------------------------------------

def _report(event="staging-complete", **over):
    """A representative agent telemetry report (spec section 2)."""
    rep = {
        "ts": 1783000000,
        "image_id": "img1",
        "event": event,
        "transfer": {"total_bytes": 1000000, "elapsed_s": 12, "avg_bps": 83333,
                     "sha_ok": True, "stage_state": "ready"},
        "link": {"tier": "good", "rtt_ms_median": 12, "rtt_samples": 8,
                 "hb_failures": 0, "trimmed": False},
        "peers": [{"ip": "10.0.0.7"}], "peers_total": 1,
        "agent": {"version": "2026.07.02", "runtime_mode": "guestshell"},
    }
    rep.update(over)
    return rep


def _post(port, path, token, body, gzip_body=False):
    """POST raw bytes; optionally flag Content-Encoding: gzip.  Returns
    (status, parsed-json-or-raw-bytes)."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Authorization": "Bearer " + token,
               "Content-Type": "application/json"}
    if gzip_body:
        headers["Content-Encoding"] = "gzip"
    c.request("POST", path, body=body, headers=headers)
    r = c.getresponse()
    raw = r.read()
    try:
        return r.status, json.loads(raw)
    except ValueError:
        return r.status, raw


# --- _sanitize_report (pure unit tests) ------------------------------------

def test_sanitize_report_whitelists_and_trims():
    """Unknown top-level keys dropped; peers re-trimmed to 64 rows of exactly
    {ip[:64]} — legacy byte fields are never stored; every other string
    capped at 128.  The trim is REPORTED, not silent: peers_rows_dropped
    counts the rows the server dropped and peers_total keeps the real count
    of rows the device sent."""
    data = _report()
    data["evil_key"] = "drop me"
    data["install"] = True                       # never store install intents
    data["image_id"] = "A" * 300
    data["link"]["tier"] = "B" * 300
    data["peers"] = [{"ip": "10.0.%d.%d" % (i // 250, i % 250),
                      "rx_bytes": i * 10, "extra": "drop"}
                     for i in range(70)]
    data["peers"][0]["ip"] = "C" * 100
    data["peers"].insert(5, "junk-row")          # non-dict rows are skipped
    data.pop("peers_total", None)                # absent -> floored at rows
    out = catalog._sanitize_report(data)
    assert set(out) <= {"ts", "image_id", "event", "transfer", "link",
                        "peers", "peers_total", "peers_rows_dropped",
                        "agent", "schema"}
    assert "evil_key" not in out and "install" not in out
    assert out["schema"] == "v1"
    assert out["image_id"] == "A" * 128
    assert out["link"]["tier"] == "B" * 128
    # peers: exactly 64 rows of exactly {ip}, ip capped at 64 chars
    assert len(out["peers"]) == 64
    assert all(set(row) == {"ip"} for row in out["peers"])
    assert out["peers"][0]["ip"] == "C" * 64
    assert out["peers"][1] == {"ip": "10.0.0.1"}
    # absent peers_total floors at the rows the device SENT (70 dict rows,
    # the junk row is not one), not at the 64 that survived our trim — the
    # stored record must never assert a smaller swarm than was reported.
    assert out["peers_total"] == 70
    assert out["peers_rows_dropped"] == 6
    assert out["ts"] == 1783000000
    assert out["transfer"]["sha_ok"] is True


def test_sanitize_report_drops_legacy_byte_fields():
    """Per-peer byte fields are not part of the contract and must never be
    stored — a row is exactly {ip}."""
    data = _report(peers=[{"ip": "10.0.0.7", "rx_bytes": 100, "tx_bytes": 5,
                           "avg_bps": 4200}], peers_total=1)
    assert catalog._sanitize_report(data)["peers"] == [{"ip": "10.0.0.7"}]


def test_sanitize_report_null_ip_becomes_empty_string():
    """An explicit JSON null for ip must not become the string 'None'."""
    out = catalog._sanitize_report(_report(peers=[{"ip": None}], peers_total=1))
    assert out["peers"] == [{"ip": ""}]


def test_sanitize_report_peers_total_coerced_and_floored():
    """peers_total is stored as an int (the drawer interpolates it as a
    number — same stored-XSS discipline as the link fields) and floored at
    len(peers) so 'and N more' arithmetic can never go negative."""
    out = catalog._sanitize_report(
        _report(peers=[{"ip": "10.0.0.7"}], peers_total=9))
    assert out["peers_total"] == 9
    out = catalog._sanitize_report(
        _report(peers=[{"ip": "10.0.0.7"}], peers_total="junk"))
    assert out["peers_total"] == 1
    out = catalog._sanitize_report(_report(peers=[], peers_total=-3))
    assert out["peers_total"] == 0
    # clamped at int32 max so a hostile device can't push a value outside
    # OTLP intValue encoding
    out = catalog._sanitize_report(_report(peers=[], peers_total=10**300))
    assert out["peers_total"] == 2**31 - 1


def test_sanitize_report_v1_trim_is_visible():
    """A v1 report trimmed by the server says so in a number: the drop count
    is explicit and peers_total still reflects what the device sent."""
    data = _report(peers=[{"ip": "10.1.%d.%d" % (i // 250, i % 250)}
                          for i in range(100)], peers_total=100)
    out = catalog._sanitize_report(data)
    assert len(out["peers"]) == 64
    assert out["peers_rows_dropped"] == 36
    assert out["peers_total"] == 100
    # nothing dropped -> an explicit zero, not a missing key
    assert catalog._sanitize_report(_report())["peers_rows_dropped"] == 0


def test_sanitize_report_coerces_link_numeric_fields():
    """The numeric link fields are stored as ints — the swarm-map drawer
    interpolates rtt_ms_median into its HTML unescaped (it reads as a number),
    so a device-supplied string surviving to storage would be stored XSS."""
    data = _report()
    data["link"]["rtt_ms_median"] = "<img src=x onerror=alert(1)>"
    data["link"]["rtt_samples"] = "8"            # numeric string round-trips
    data["link"]["hb_failures"] = None
    out = catalog._sanitize_report(data)
    assert out["link"]["rtt_ms_median"] == 0
    assert out["link"]["rtt_samples"] == 8
    assert out["link"]["hb_failures"] == 0
    # an agent-shaped link section passes through unchanged (tier/trimmed
    # untouched, legit ints intact); an absent field stays absent, it does
    # not materialize as 0
    assert catalog._sanitize_report(_report())["link"] == {
        "tier": "good", "rtt_ms_median": 12, "rtt_samples": 8,
        "hb_failures": 0, "trimmed": False}
    trimmed = _report()
    del trimmed["link"]["rtt_ms_median"]
    assert "rtt_ms_median" not in catalog._sanitize_report(trimmed)["link"]


def test_sanitize_report_rejects_garbage():
    """Non-dict bodies and events outside the allowed set raise ValueError
    (the route maps that to a 400)."""
    with pytest.raises(ValueError):
        catalog._sanitize_report(["not", "a", "dict"])
    with pytest.raises(ValueError):
        catalog._sanitize_report("nope")
    with pytest.raises(ValueError):
        catalog._sanitize_report(_report(event="install-now"))
    with pytest.raises(ValueError):
        catalog._sanitize_report({"ts": 1})      # missing event


# --- CatalogStore ring + directives (unit tests) ----------------------------

def test_record_telemetry_ring_keeps_newest_five(tmp_path):
    """The per-device ring holds the NEWEST TELEMETRY_RING reports,
    oldest→newest, each stamped with received_at on ingest."""
    s = catalog.CatalogStore(str(tmp_path))
    for i in range(7):
        s.record_telemetry("dev-1", {"ts": i, "event": "pull"})
    reports = catalog.CatalogStore(str(tmp_path)).get_telemetry("dev-1")
    assert catalog.CatalogStore.TELEMETRY_RING == 5
    assert len(reports) == 5
    assert [r["ts"] for r in reports] == [2, 3, 4, 5, 6]
    assert all("received_at" in r for r in reports)
    # unknown device -> empty list, never raises
    assert s.get_telemetry("ghost") == []


def test_a_verified_terminal_report_is_attested_past_ring_eviction(tmp_path):
    """The ring is five deep PER DEVICE, shared by every image assigned to it
    and every report kind, and the tracker reads it at most once per sample
    pass. A device finishing several images inside one agent tick pushes the
    earliest terminal report out before any pass sees it, and the plan it
    attested then has no derivable checksum precondition anywhere: it sits at
    `planned` and never emits seeding_started.

    The fact is therefore recorded at INGEST into a durable per-device ledger
    keyed by transfer, which outlives the ring by design.
    """
    s = catalog.CatalogStore(str(tmp_path))
    first = _v2(report_id="a" * 32, transfer_id="1" * 32, image_id="img-a")
    s.record_telemetry("dev-1", first)
    for n in range(6):
        s.record_telemetry("dev-1", _v2(report_id="%032x" % n,
                                        transfer_id="%032x" % (n + 100),
                                        image_id="img-%d" % n))

    ring = s.get_telemetry("dev-1")
    assert len(ring) == catalog.CatalogStore.TELEMETRY_RING
    assert not any(r["transfer_id"] == "1" * 32 for r in ring)   # evicted

    rows = s.get_transfer_attestations()["dev-1"]
    kept = [r for r in rows if r["transfer_id"] == "1" * 32]
    assert len(kept) == 1
    assert kept[0]["image_id"] == "img-a"
    assert kept[0]["observed_at"] == 90.0            # window.end, device clock
    assert kept[0]["report_created_at"] == 100.0     # device clock
    assert kept[0]["received_at"] > 0                # server ingest clock
    # Read back through a second store object: it is on disk, not in memory.
    assert catalog.CatalogStore(str(tmp_path)).get_transfer_attestations() \
        == s.get_transfer_attestations()


def test_an_attestation_is_first_write_wins_and_bounded_per_device(tmp_path):
    """The tracker latches the EARLIEST attesting instant, so a retry, or the
    `staging-complete` upgrade of an already-attested `seeding-only`
    transfer, must not move the recorded value. One slot per transfer, bounded
    FIFO like the report-id ledger beside it."""
    s = catalog.CatalogStore(str(tmp_path))
    s.record_telemetry("dev-1", _v2(report_id="a" * 32, transfer_id="1" * 32,
                                    event="seeding-only"))
    first = s.get_transfer_attestations()["dev-1"][0]["received_at"]
    s.record_telemetry("dev-1", _v2(report_id="b" * 32, transfer_id="1" * 32,
                                    event="staging-complete"))
    rows = s.get_transfer_attestations()["dev-1"]
    assert len(rows) == 1
    assert rows[0]["received_at"] == first

    cap = catalog.CatalogStore.ATTESTATIONS
    for n in range(cap + 3):
        s.record_telemetry("dev-1", _v2(report_id="%032x" % (n + 500),
                                        transfer_id="%032x" % (n + 500)))
    rows = s.get_transfer_attestations()["dev-1"]
    assert len(rows) == cap
    assert not any(r["transfer_id"] == "1" * 32 for r in rows)   # oldest first


def test_a_report_that_attests_nothing_leaves_no_attestation(tmp_path):
    """Only a terminal report with a VERIFIED content sha256 and a well-formed
    transfer id attests. A pull snapshot is not a completion claim, a mismatch
    is not a verification, and a v1 report carries no transfer id to bind."""
    s = catalog.CatalogStore(str(tmp_path))
    s.record_telemetry("dev-1", _v2(report_id="a" * 32, event="pull",
                                    report_request_id="c" * 32))
    s.record_telemetry("dev-1", _v2(report_id="b" * 32,
                                    content_sha256={"state": "mismatch"}))
    s.record_telemetry("dev-1", _v2(report_id="c" * 32, transfer_id="short"))
    s.record_telemetry("dev-1", _report())          # v1: no transfer id
    assert s.get_transfer_attestations() == {}


def test_purge_device_takes_the_attestations_with_it(tmp_path):
    """A device deleted and added back must not inherit an attestation for a
    transfer that happened on the old one -- the same rule that empties every
    other per-device store."""
    s = catalog.CatalogStore(str(tmp_path))
    s.record_telemetry("dev-1", _v2(report_id="a" * 32))
    s.record_telemetry("dev-2", _v2(report_id="b" * 32))
    assert set(s.get_transfer_attestations()) == {"dev-1", "dev-2"}
    assert s.purge_device("dev-1") is True
    assert set(s.get_transfer_attestations()) == {"dev-2"}


def test_concurrent_record_telemetry_loses_no_reports(tmp_path):
    """N threads recording one report each for a DIFFERENT device against one
    CatalogStore must leave every report on disk and telemetry.json valid —
    same store_lock + _atomic_write_json discipline as devices.json."""
    s = catalog.CatalogStore(str(tmp_path))
    n = 40
    barrier = threading.Barrier(n)
    errors = []

    def post(i):
        try:
            barrier.wait()
            s.record_telemetry("dev-%d" % i, {"ts": i, "event": "pull"})
        except Exception as exc:  # pragma: no cover - surfaced via assert
            errors.append(exc)

    threads = [threading.Thread(target=post, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    s2 = catalog.CatalogStore(str(tmp_path))      # fresh read from disk
    for i in range(n):
        assert len(s2.get_telemetry("dev-%d" % i)) == 1, (
            "lost telemetry report for dev-%d" % i)


def test_pull_directive_lifecycle_with_ttl(tmp_path):
    """request -> pending -> duplicate refused -> TTL expiry (injected now)
    lazily deletes the entry -> re-request works -> explicit clear works."""
    s = catalog.CatalogStore(str(tmp_path))
    now = 1000.0
    assert catalog.CatalogStore.PULL_TTL == 600
    assert s.pending_report("dev-1", now) is None
    # request -> pending
    assert s.request_report("dev-1", now) is True
    assert s.pending_report("dev-1", now + 1)["report_requested"] is True
    # one pending per device: duplicate refused while unexpired
    assert s.request_report("dev-1", now + 10) is False
    # TTL expiry: at now + PULL_TTL the directive is expired...
    assert s.pending_report("dev-1", now + 600) is None
    # ...and was lazily deleted from the device's keyed pull row
    assert s._pulls.get("dev-1") is None
    # a new request after expiry succeeds
    assert s.request_report("dev-1", now + 600) is True
    # explicit clear
    s.clear_report_request("dev-1")
    assert s.pending_report("dev-1", now + 601) is None


def test_list_devices_does_not_reap_expired_pull_directive(tmp_path):
    """GET-backed fleet enumeration is side-effect free; expiration cleanup
    belongs to a heartbeat/write path rather than this read."""
    s = catalog.CatalogStore(str(tmp_path))
    now = 1000.0
    assert s.request_report("ghost", now) is True
    assert s._pulls.get("ghost") is not None      # row exists before expiry

    # ghost never heartbeats or reports again; time passes well past the TTL,
    # and nothing ever queries "ghost" directly again.
    later = now + catalog.CatalogStore.PULL_TTL + 1
    s.list_devices(later)

    assert s._pulls.get("ghost") is not None      # read did not rewrite state


def test_list_devices_leaves_unexpired_pull_directive_alone(tmp_path):
    """A read does not clear an unexpired directive either."""
    s = catalog.CatalogStore(str(tmp_path))
    now = 1000.0
    assert s.request_report("dev-1", now) is True
    s.list_devices(now + 1)
    assert s._pulls.get("dev-1") is not None


def test_record_telemetry_clears_pull_request(tmp_path):
    """An arriving report answers (or supersedes) the pending pull directive
    for THAT device only."""
    s = catalog.CatalogStore(str(tmp_path))
    assert s.request_report("dev-1", 1000.0) is True
    assert s.request_report("dev-2", 1000.0) is True
    assert s.pending_report("dev-1", 1001.0)["report_requested"] is True
    s.record_telemetry("dev-1", _report(event="pull"))
    assert s.pending_report("dev-1", 1002.0) is None
    # dev-2's directive is untouched
    assert s.pending_report("dev-2", 1002.0)["report_requested"] is True


# --- HTTP path: route, auth binding, body caps, gzip ------------------------

def test_telemetry_post_roundtrip(tmp_path):
    """POST /v1/devices/<id>/telemetry with the device's own token stores the
    sanitized report; received_at is stamped server-side."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                             json.dumps(_report()).encode())
        assert status == 200 and resp == {"ok": True}
    finally:
        srv.shutdown()
    stored = catalog.CatalogStore(str(tmp_path)).get_telemetry("sw-9")
    assert len(stored) == 1
    assert stored[0]["image_id"] == "img1"
    assert stored[0]["event"] == "staging-complete"
    assert stored[0]["peers"] == [{"ip": "10.0.0.7"}]
    assert stored[0]["peers_total"] == 1
    assert "received_at" in stored[0]


def test_telemetry_rejects_wrong_device_token(tmp_path):
    """Device B's VALID catalog token must NOT post telemetry as device A —
    'telemetry' must be in _guard's device-bound tuple, otherwise any device
    could spoof any other device's reports (same binding as heartbeat)."""
    sp = _secrets_path(tmp_path)
    tok_b = _mint_catalog_token(sp, "device-b")
    s = _store(tmp_path)
    srv = catalog.make_server("127.0.0.1", 0, s, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        status, _ = _post(port, "/v1/devices/device-a/telemetry", tok_b,
                          json.dumps(_report()).encode())
        assert status == 401, "wrong-device token must be rejected"
        # nothing stored for the spoofed device
        assert catalog.CatalogStore(
            str(tmp_path)).get_telemetry("device-a") == []
        # the same token IS accepted for its own device
        status, _ = _post(port, "/v1/devices/device-b/telemetry", tok_b,
                          json.dumps(_report()).encode())
        assert status == 200
    finally:
        srv.shutdown()


def test_policy_rejects_wrong_device_token(tmp_path):
    """Device B's VALID catalog token must NOT read device A's policy —
    'policy' must be in _guard's device-bound tuple, otherwise any enrolled
    device could walk /v1/devices then /v1/devices/<id>/policy for every id
    and read every other device's plan_id/transfer_id (#42)."""
    sp = _secrets_path(tmp_path)
    tok_a = _mint_catalog_token(sp, "device-a")
    tok_b = _mint_catalog_token(sp, "device-b")
    s = _store(tmp_path)
    s.set_policy("device-a", approved_image_ids=["img1"])
    srv = catalog.make_server("127.0.0.1", 0, s, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        status, _, body = _req(port, "GET", "/v1/devices/device-a/policy",
                               token=tok_b)
        assert status == 401, "wrong-device token must be rejected"
        assert b"plan_id" not in body and b"transfer_id" not in body
        # the same token IS accepted for its own device
        status, _, body = _req(port, "GET", "/v1/devices/device-b/policy",
                               token=tok_b)
        assert status == 200
        # and device A's own token still works for device A
        status, _, body = _req(port, "GET", "/v1/devices/device-a/policy",
                               token=tok_a)
        assert status == 200
        assert b"plan_id" in body and b"transfer_id" in body
    finally:
        srv.shutdown()


def test_post_body_over_cap_is_413(tmp_path):
    """Content-Length over 64 KiB -> 413 on ANY POST route (global do_POST
    cap), nothing stored."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    big = b"x" * (65536 + 1)
    try:
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok", big)
        assert status == 413
        assert resp["status"] == 413
        assert resp["type"].endswith("payload-too-large")
        # the cap is global to do_POST, not telemetry-specific
        status, resp = _post(port, "/v1/devices/sw-9/heartbeat", "tok", big)
        assert status == 413
    finally:
        srv.shutdown()
    assert catalog.CatalogStore(str(tmp_path)).get_telemetry("sw-9") == []


def test_telemetry_gzip_roundtrip(tmp_path):
    """A gzip-compressed report (Content-Encoding: gzip) is decoded and
    stored — this is what the agent sends when the body exceeds 1 KiB."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        gz = gzip.compress(json.dumps(_report(event="pull")).encode())
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok", gz,
                             gzip_body=True)
        assert status == 200 and resp == {"ok": True}
    finally:
        srv.shutdown()
    stored = catalog.CatalogStore(str(tmp_path)).get_telemetry("sw-9")
    assert len(stored) == 1 and stored[0]["event"] == "pull"


def test_telemetry_gzip_bomb_is_413(tmp_path):
    """A small compressed body that INFLATES over the 64 KiB cap is rejected
    after decode (bomb guard: size re-checked post-decompress), nothing
    stored."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        bomb = gzip.compress(b"\x00" * (4 * 1024 * 1024))
        assert len(bomb) < 65536, "bomb must pass the Content-Length cap"
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok", bomb,
                             gzip_body=True)
        assert status == 413
        assert resp["status"] == 413
        assert resp["type"].endswith("payload-too-large")
    finally:
        srv.shutdown()
    assert catalog.CatalogStore(str(tmp_path)).get_telemetry("sw-9") == []


def test_telemetry_bad_gzip_is_400(tmp_path):
    """Content-Encoding: gzip with a body that is not gzip -> 400, not a
    500/traceback."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                             b"this is not gzip data", gzip_body=True)
        assert status == 400
        assert resp["status"] == 400
        assert resp["type"].endswith("invalid-request-body")
    finally:
        srv.shutdown()
    assert catalog.CatalogStore(str(tmp_path)).get_telemetry("sw-9") == []


def test_telemetry_bad_report_is_400(tmp_path):
    """Reports failing _sanitize_report (bad event / non-dict) -> 400 and are
    never stored."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        status, _ = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                          json.dumps(_report(event="install-now")).encode())
        assert status == 400
        status, _ = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                          json.dumps(["not", "a", "dict"]).encode())
        assert status == 400
        status, _ = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                          b"{not json")
        assert status == 400
    finally:
        srv.shutdown()
    assert catalog.CatalogStore(str(tmp_path)).get_telemetry("sw-9") == []


def test_telemetry_oversized_sanitized_report_is_400(tmp_path):
    """The per-string (128) and per-peer-row (20) caps don't bound the KEY
    COUNT in nested transfer/link/agent dicts — a report can sanitize down to
    well over the documented 16 KiB/report bound while its wire body still
    fits under the 64 KiB transport cap. Server-side must reject that (spec
    section 6: ring of 5 x <=16 KB/device), not just accept-and-store it."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        huge = _report()
        huge["transfer"] = {"k%d" % i: "A" * 128 for i in range(200)}
        body = json.dumps(huge).encode()
        assert len(body) < 65536, "fixture must clear the wire cap, not the store cap"
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok", body)
        assert status == 400
        assert resp["status"] == 400 and resp["error"] == "bad report"
        assert resp["type"].endswith("invalid-request")
        # a normal full-shape report is well under the bound and still stores.
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                             json.dumps(_report()).encode())
        assert status == 200 and resp == {"ok": True}
    finally:
        srv.shutdown()
    stored = catalog.CatalogStore(str(tmp_path)).get_telemetry("sw-9")
    assert len(stored) == 1              # only the normal report was stored


def test_v2_report_accepted_for_any_member_of_the_set(tmp_path):
    """A device holding an ORDERED SET of approved images (multi-image
    assignment) must accept a v2 terminal report naming ANY member, not just
    the first -- the old equality-with-singular check would 400 a truthful
    report for the second image. A report for an id NOT in the set stays
    400. Uses the file's _v2() v2-report fixture (defined below, alongside
    the other _sanitize_report/v2 unit tests it already serves)."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        store = catalog.CatalogStore(str(tmp_path))
        store.save_image({"id": "img2", "filename": "img2.bin", "size": 5,
                          "sha256": "cd" * 32, "info_hash_hex": "dd" * 20,
                          "published_at": 112})
        store.set_policy("sw-9", approved_image_ids=["img1", "img2"])
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                             json.dumps(_v2(image_id="img2")).encode())
        assert status == 200 and resp == {"ok": True}
        # an id NOT in the assigned set is still rejected
        status, resp = _post(
            port, "/v1/devices/sw-9/telemetry", "tok",
            json.dumps(_v2(image_id="img-not-assigned",
                           report_id="8c1f0b9a2d3e4f5061728394a5b6c7d9")
                      ).encode())
        assert status == 400
    finally:
        srv.shutdown()


# --- heartbeat: staged_image_ids / errored_image_ids whitelist -------------
#
# Task 3/4 land staged_image_ids and errored_image_ids on the multi-image
# heartbeat, and every consumer (device rows, the deployed badge, rollout,
# staging counts) reads them off the STORED record. record_heartbeat() itself
# has no allowlist -- but the real HTTP ingest handler above builds the
# stored record from an explicit key whitelist, so a field missing from that
# whitelist is silently dropped in production even though a direct
# record_heartbeat() call (as most consumer-side tests use) would see it.
# Same rationale as test_route_post_forwards_target_fs.

def test_route_post_forwards_staged_and_errored_image_ids(tmp_path):
    """The HTTP heartbeat path must forward both multi-image fields through
    the whitelist to record_heartbeat."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        status, _, _ = _req(
            port, "POST", "/v1/devices/sw-1/heartbeat", token="tok",
            body=json.dumps({"current_image_id": "img1",
                             "staged_image_ids": ["img1", "img2"],
                             "errored_image_ids": ["img3"]}))
        assert status == 200
    finally:
        srv.shutdown()
    rec = catalog.CatalogStore(str(tmp_path)).get_device("sw-1")
    assert rec["staged_image_ids"] == ["img1", "img2"]
    assert rec["errored_image_ids"] == ["img3"]


def test_route_post_absent_staged_errored_image_ids_stores_none(tmp_path):
    """A heartbeat that omits the fields (a legacy single-image agent) must
    store None, not []  -- consumers key the legacy fallback off the field
    being absent/None; an invented [] would read as 'a multi-image agent
    that has staged nothing', not 'a legacy agent'."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        status, _, _ = _req(
            port, "POST", "/v1/devices/sw-1/heartbeat", token="tok",
            body=json.dumps({"current_image_id": "img1"}))
        assert status == 200
    finally:
        srv.shutdown()
    rec = catalog.CatalogStore(str(tmp_path)).get_device("sw-1")
    assert rec["staged_image_ids"] is None
    assert rec["errored_image_ids"] is None


def test_route_post_malformed_staged_errored_image_ids_sanitised(tmp_path):
    """Malformed device-supplied values -- a bare string instead of a list,
    or a list of non-string entries -- must sanitise to None (not crash the
    request with a 500, and not silently filter down to a meaningful-looking
    [])."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        status, _, _ = _req(
            port, "POST", "/v1/devices/sw-1/heartbeat", token="tok",
            body=json.dumps({"current_image_id": "img1",
                             "staged_image_ids": "junk-string",
                             "errored_image_ids": [1, 2]}))
        assert status == 200
    finally:
        srv.shutdown()
    rec = catalog.CatalogStore(str(tmp_path)).get_device("sw-1")
    assert rec["staged_image_ids"] is None
    assert rec["errored_image_ids"] is None


# --- heartbeat: telemetry_enabled whitelist + report_requested flag ---------

def test_heartbeat_forwards_telemetry_enabled(tmp_path):
    """The HTTP heartbeat path must forward telemetry_enabled through the
    field whitelist to record_heartbeat.  The whitelist silently drops
    unlisted fields, so only an HTTP-path test catches a missing entry
    (same rationale as test_route_post_forwards_target_fs)."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        status, _, _ = _req(
            port, "POST", "/v1/devices/sw-1/heartbeat", token="tok",
            body=json.dumps({"current_image_id": "img1",
                             "telemetry_enabled": False}))
        assert status == 200
    finally:
        srv.shutdown()
    rec = catalog.CatalogStore(str(tmp_path)).get_device("sw-1")
    assert rec["telemetry_enabled"] is False


def test_heartbeat_response_report_requested_roundtrip(tmp_path):
    """Full pull-directive round trip over real HTTP: no directive -> plain
    {'ok': True}; directive pending -> response carries report_requested:
    True; report arrival clears it -> next heartbeat is plain again."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    hb = json.dumps({"current_image_id": "img1"})
    try:
        # 1. no directive -> no flag
        status, _, body = _req(port, "POST", "/v1/devices/sw-9/heartbeat",
                               token="tok", body=hb)
        assert status == 200
        assert "report_requested" not in json.loads(body)

        # 2. the console requests a report (the gui process shares the state
        #    dir, so a second CatalogStore over the same dir stands in for it)
        assert catalog.CatalogStore(str(tmp_path)).request_report(
            "sw-9", time.time()) is True
        status, _, body = _req(port, "POST", "/v1/devices/sw-9/heartbeat",
                               token="tok", body=hb)
        assert status == 200
        assert json.loads(body).get("report_requested") is True

        # 3. the device answers with a pull report -> directive cleared
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                             json.dumps(_report(event="pull")).encode())
        assert status == 200 and resp == {"ok": True}

        # 4. next heartbeat: flag gone
        status, _, body = _req(port, "POST", "/v1/devices/sw-9/heartbeat",
                               token="tok", body=hb)
        assert status == 200
        assert "report_requested" not in json.loads(body)
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Task 7 — typed personalized torrent serving (spec §6)
# ---------------------------------------------------------------------------

import bencode  # noqa: E402
import torrent_personalize  # noqa: E402


def _valid_torrent_bytes(announce=b"http://old:6969/announce"):
    info = bencode.encode({"name": "img.bin", "piece length": 16384,
                           "pieces": b"\x00" * 20, "length": 100})
    return (b"d8:announce" + bencode.encode(announce)
            + b"4:info" + info + b"e")


def _serve_torrent(tmp_path, device_id="dev-t", catalog_tok="ctok",
                   announce_val="annVAL", host_ip="10.0.0.1"):
    """Start a catalog server whose device has a catalog_token AND an
    announce_token, with a VALID canonical torrent for img1 on disk."""
    sp = _secrets_path(tmp_path)
    now = time.time()
    store = secrets_store.load(sp)
    dev = store["devices"].setdefault(device_id, {})
    dev["catalog_token"] = {"value": catalog_tok, "created_at": now,
                            "expires_at": now + 3600, "revoked": False}
    if announce_val is not None:
        dev["announce_token"] = {"value": announce_val, "created_at": now,
                                 "expires_at": 0, "revoked": False}
    secrets_store.save(store, sp)
    s = catalog.CatalogStore(str(tmp_path))
    (tmp_path / "torrents").mkdir(exist_ok=True)
    (tmp_path / "torrents" / "img1.torrent").write_bytes(_valid_torrent_bytes())
    s.save_image({"id": "img1", "filename": "img1.bin", "size": 5,
                  "sha256": "ab" * 32, "cisco_signature_verified": False,
                  "info_hash_hex": "cc" * 20, "published_at": 111})
    s.set_policy(device_id, approved_image_id="img1")
    os.environ["IRIS_HOST_IP"] = host_ip
    srv = catalog.make_server("127.0.0.1", 0, s, sp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _req_headers(port, path, token, extra_headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Authorization": "Bearer " + token}
    headers.update(extra_headers or {})
    c.request("GET", path, headers=headers)
    r = c.getresponse()
    body = r.read()
    return r.status, dict(r.getheaders()), body


def test_device_gets_token_free_torrent_for_header_announce_auth(tmp_path):
    srv, port = _serve_torrent(tmp_path, announce_val="ANNTOKEN")
    try:
        status, headers, body = _req_headers(
            port, "/v1/torrents/img1.torrent", "ctok",
            {"X-IRIS-Tracker-Auth": "bearer"})
        assert status == 200
        meta = bencode.decode(body)
        assert meta[b"announce"] == b"https://10.0.0.1:6969/announce"
        assert b"ANNTOKEN" not in body
        assert b"announce-list" not in meta
        # info hash unchanged vs canonical
        canon = _valid_torrent_bytes()
        canon_info = bencode.decode(canon)[b"info"]
        assert bencode.encode(meta[b"info"]) == bencode.encode(canon_info)
    finally:
        srv.shutdown()


def test_tracker_auth_selector_is_interpreted_only_on_torrent_route(tmp_path):
    srv, port = _serve_torrent(tmp_path, announce_val="ANNTOKEN")
    try:
        status, _, _ = _req_headers(
            port, "/v1/images", "ctok",
            {"X-IRIS-Tracker-Auth": "not-a-supported-selector"})
        assert status == 200
        status, headers, body = _req_headers(
            port, "/v1/torrents/img1.torrent", "ctok",
            {"X-IRIS-Tracker-Auth": "not-a-supported-selector"})
        assert status == 400
        assert headers["Content-Type"] == "application/problem+json"
        assert json.loads(body)["code"] == "invalid-tracker-auth-selector"
    finally:
        srv.shutdown()


def test_device_gets_legacy_query_torrent_without_opt_in_header(tmp_path):
    """Unchanged Guest Shell requests remain byte-for-wire compatible."""
    srv, port = _serve_torrent(tmp_path, announce_val="ANNTOKEN")
    try:
        status, headers, body = _req_headers(
            port, "/v1/torrents/img1.torrent", "ctok")
        assert status == 200
        meta = bencode.decode(body)
        assert meta[b"announce"] == (
            b"https://10.0.0.1:6969/announce?announce_token=ANNTOKEN")
        assert headers.get("Vary") == (
            "Authorization, X-IRIS-Tracker-Auth")
    finally:
        srv.shutdown()


def test_personalized_response_cache_headers(tmp_path):
    srv, port = _serve_torrent(tmp_path)
    try:
        status, headers, body = _req_headers(
            port, "/v1/torrents/img1.torrent", "ctok")
        assert status == 200
        assert headers.get("Cache-Control") == "private, no-store"
        assert headers.get("Vary") == (
            "Authorization, X-IRIS-Tracker-Auth")
    finally:
        srv.shutdown()


def test_device_missing_announce_fails_closed_no_leak(tmp_path):
    srv, port = _serve_torrent(tmp_path, announce_val=None)
    try:
        status, headers, body = _req_headers(
            port, "/v1/torrents/img1.torrent", "ctok")
        assert status == 500
        # No token, announce URL, or query string leaks (the generic word
        # "announce" in a message is fine; a secret/URL is not).
        assert b"ctok" not in body
        assert b"announce_token=" not in body
        assert b"http://" not in body
        assert b"?" not in body
    finally:
        srv.shutdown()


def test_canonical_disk_bytes_unchanged_after_personalized_get(tmp_path):
    srv, port = _serve_torrent(tmp_path, announce_val="ANNX")
    disk = tmp_path / "torrents" / "img1.torrent"
    before = disk.read_bytes()
    try:
        status, _, body = _req_headers(
            port, "/v1/torrents/img1.torrent", "ctok")
        assert status == 200
        assert body != before  # personalized in memory
        assert disk.read_bytes() == before  # canonical on disk untouched
    finally:
        srv.shutdown()


def test_torrent_personalization_failure_is_500_no_leak(tmp_path):
    # Corrupt canonical torrent -> personalize raises -> 500, no token leak.
    srv, port = _serve_torrent(tmp_path, announce_val="ANNZ")
    (tmp_path / "torrents" / "img1.torrent").write_bytes(b"d4:infod}fakeee")
    try:
        status, _, body = _req_headers(
            port, "/v1/torrents/img1.torrent", "ctok")
        assert status == 500
        assert b"ANNZ" not in body
    finally:
        srv.shutdown()


def test_service_principal_receives_canonical_bytes(tmp_path):
    # A non-device (service/internal) principal receives canonical bytes with
    # no personalization. Exercised at the route level with a synthetic typed
    # AuthContext (Day-1 mints no service catalog credential).
    import auth
    s = catalog.CatalogStore(str(tmp_path))
    (tmp_path / "torrents").mkdir(exist_ok=True)
    canon = _valid_torrent_bytes()
    (tmp_path / "torrents" / "img1.torrent").write_bytes(canon)
    s.save_image({"id": "img1", "filename": "img1.bin", "size": 5,
                  "sha256": "ab" * 32, "cisco_signature_verified": False,
                  "info_hash_hex": "cc" * 20, "published_at": 111})
    cat = catalog.Catalog(s, str(tmp_path / "secrets.json"))
    ctx = auth.AuthContext(
        principal=auth.Principal("service", "seeder"),
        secret_name="catalog_token", scope="catalog")
    result = cat.route_get("/v1/torrents/img1.torrent",
                           auth_ctx=ctx, store_dict={})
    status, ctype, body = result[0], result[1], result[2]
    assert status == 200 and ctype == "application/x-bittorrent"
    assert body == canon  # canonical, unmodified


# ---------------------------------------------------------------------------
# v2 peer_transfer_records: exact device-measured per-peer received bytes
#
# These are aria2-next session counters read ONCE by the
# --on-bt-download-complete hook, not the rates-integrated rx_bytes/tx_bytes
# retired in 2026.08.20.  The tests below pin the three properties that make
# them trustworthy: absent is not zero, the server's own truncation loses no
# bytes and states its own mass, and a malformed block is rejected loudly.
# ---------------------------------------------------------------------------

def _v2(**over):
    """A minimal valid v2 terminal report (spec §10.2)."""
    rep = {"v": 2, "report_id": "7c1f0b9a2d3e4f5061728394a5b6c7d8",
           "transfer_id": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4",
           "report_request_id": None, "report_created_at": 100.0,
           "image_id": "img1", "event": "staging-complete",
           "window": {"start": 1.0, "end": 90.0, "complete": True},
           "content": {"completed_content_bytes": 10,
                       "total_content_bytes": 10},
           "content_sha256": {"state": "verified", "algo": "sha256"},
           "ios_copy_verify": {"state": "ok"},
           "sampling": {"sampling_class": "good"},
           "stage_state": "ready", "peers": [], "peers_total": 0,
           "peers_truncated": False, "peers_saturated": False,
           "agent": {"version": "x", "runtime_mode": "guestshell"}}
    rep.update(over)
    return rep


def _transfer_records(rows=None, **over):
    rows = [{"ip": "10.0.0.7", "port": 6881,
             "session_bytes_from_peer": 41943040,
             "session_bytes_to_peer": 1048576, "has_complete_file": True}] \
        if rows is None else rows
    named = [r for r in rows if isinstance(r, dict)] \
        if isinstance(rows, list) else []
    block = {"source": "aria2_session_counters", "captured_at": 50.0,
             "complete": True, "rows": rows, "rows_total": len(named),
             "rows_omitted": 0,
             "bytes_from_all_senders_total": sum(
                 r.get("session_bytes_from_peer") or 0 for r in named),
             "bytes_from_all_senders_omitted": 0}
    block.update(over)
    return block


def test_peer_transfer_records_total_includes_the_origin_and_says_so():
    """The origin seeder is an ordinary BitTorrent peer of the device, so its
    row is in the transfer records and its bytes are in the total. The field is named
    bytes_from_all_senders_total for exactly that reason: a "from peers" total
    here would have read as peer-delivered. Splitting origin from device is
    telemetry.classify_peer_transfer_records's job, off the authenticated
    service:seeder principal -- the sanitizer stores the measurement as made
    and adds no attribution of its own."""
    rows = [{"ip": "192.0.2.10", "session_bytes_from_peer": 7110,
             "session_bytes_to_peer": 0, "has_complete_file": True},
            {"ip": "10.0.0.7", "session_bytes_from_peer": 2890,
             "session_bytes_to_peer": 0, "has_complete_file": True}]
    block = catalog._sanitize_report(
        _v2(peer_transfer_records=_transfer_records(rows=rows)))["peer_transfer_records"]
    assert block["bytes_from_all_senders_total"] == 10000
    assert {r["ip"] for r in block["rows"]} == {"192.0.2.10", "10.0.0.7"}
    # has_complete_file is aria2's isSeeder(): "holds the whole file", true for
    # both rows here. It never marks the origin, and nothing stored claims it
    # does -- no origin/peer key is invented at ingest.
    assert all(r["has_complete_file"] is True for r in block["rows"])
    assert not any(k.startswith(("origin", "peer_bytes")) for k in block)


def test_peer_transfer_records_absent_stays_absent():
    """Absent means NOT MEASURED — the sanitizer must not invent an empty
    block or a zero total, because 0 bytes from peers is a real, different
    answer (origin served everything)."""
    out = catalog._sanitize_report(_v2())
    assert "peer_transfer_records" not in out
    # ... and a measured zero survives as a measured zero
    zero = _transfer_records(rows=[{"ip": "10.0.0.7", "session_bytes_from_peer": 0,
                            "session_bytes_to_peer": 0}])
    out = catalog._sanitize_report(_v2(peer_transfer_records=zero))
    assert out["peer_transfer_records"]["rows"][0]["session_bytes_from_peer"] == 0
    assert out["peer_transfer_records"]["bytes_from_all_senders_total"] == 0


def test_old_agent_peer_receipts_key_is_dropped_not_rejected():
    """The rename retired the wire key `peer_receipts` in favour of
    `peer_transfer_records` with no compatibility alias (declared break 6): an
    old, not-yet-redeployed agent still sends the OLD key. The allow-list
    reconstruction in _sanitize_report_v2 only ever reads the NEW key, so the
    old one is silently absent from the stored report -- exactly like a device
    that measured nothing -- rather than raising and losing the whole report
    over one obsolete field."""
    stale = _v2(peer_receipts=_transfer_records())
    out = catalog._sanitize_report(stale)          # must not raise
    assert "peer_transfer_records" not in out
    assert "peer_receipts" not in out
    # Dropping the stale key must be surgical: every other field -- report_id,
    # peers_total, and the rest -- sanitizes identically to a report that
    # never carried the obsolete key at all.
    clean = catalog._sanitize_report(_v2())
    assert out == clean
    assert out["report_id"] == clean["report_id"]
    assert out["peers_total"] == clean["peers_total"]


def test_peer_transfer_records_round_trip_whitelisted():
    """Rows are rebuilt from a whitelist: the exact byte counters, ip, and the
    optional port/has_complete_file survive; anything else the device sends is dropped."""
    rows = [{"ip": "10.0.0.7", "port": 6881, "session_bytes_from_peer": 41943040,
             "session_bytes_to_peer": 1048576, "has_complete_file": True,
             "rx_bytes": 999, "peerClientName": "<script>"}]
    out = catalog._sanitize_report(_v2(peer_transfer_records=_transfer_records(rows=rows)))
    block = out["peer_transfer_records"]
    assert block["source"] == "aria2_session_counters"
    assert block["captured_at"] == 50.0
    assert block["complete"] is True
    assert block["rows"] == [{"ip": "10.0.0.7", "port": 6881,
                              "session_bytes_from_peer": 41943040,
                              "session_bytes_to_peer": 1048576,
                              "has_complete_file": True}]
    assert block["rows_total"] == 1 and block["rows_omitted"] == 0
    assert block["rows_dropped_by_server"] == 0
    assert block["bytes_from_all_senders_total"] == 41943040
    assert block["bytes_from_all_senders_omitted"] == 0
    # the participation table is untouched by all of this — the two sets sit
    # apart and are joined by ip at read time
    assert out["peers"] == []


def test_peer_transfer_records_optional_row_fields_stay_absent():
    """port/has_complete_file absent must not materialize as 0/False — an unknown port is
    not port 0 and an unknown role is not "leecher"."""
    rows = [{"ip": "10.0.0.7", "session_bytes_from_peer": 5,
             "session_bytes_to_peer": 0}]
    block = catalog._sanitize_report(
        _v2(peer_transfer_records=_transfer_records(rows=rows)))["peer_transfer_records"]
    assert block["rows"][0] == {"ip": "10.0.0.7", "session_bytes_from_peer": 5,
                                "session_bytes_to_peer": 0}


def test_peer_transfer_records_device_omission_preserved():
    """The device's own cap already omitted rows: their count AND their byte
    mass arrive as numbers, and the server stores both verbatim."""
    rows = [{"ip": "10.0.0.7", "session_bytes_from_peer": 100,
             "session_bytes_to_peer": 0}]
    block = catalog._sanitize_report(_v2(peer_transfer_records=_transfer_records(
        rows=rows, rows_total=9, rows_omitted=8,
        bytes_from_all_senders_total=1100,
        bytes_from_all_senders_omitted=1000)))["peer_transfer_records"]
    assert block["rows_total"] == 9 and block["rows_omitted"] == 8
    assert block["bytes_from_all_senders_total"] == 1100
    assert block["bytes_from_all_senders_omitted"] == 1000
    assert block["rows_dropped_by_server"] == 0


def test_peer_transfer_records_server_truncation_is_lossless_and_counted():
    """The server's own 32-row cap keeps the LARGEST contributors, moves the
    dropped tail into the omitted counters (never discarding its bytes), and
    reports its own drop as an explicit count."""
    rows = [{"ip": "10.0.1.%d" % i, "session_bytes_from_peer": (i + 1) * 1000,
             "session_bytes_to_peer": 0} for i in range(50)]
    total = sum(r["session_bytes_from_peer"] for r in rows)
    block = catalog._sanitize_report(
        _v2(peer_transfer_records=_transfer_records(rows=rows)))["peer_transfer_records"]
    assert len(block["rows"]) == 32
    assert block["rows_dropped_by_server"] == 18
    # kept rows are the biggest, sorted descending — what is lost is the tail
    kept = [r["session_bytes_from_peer"] for r in block["rows"]]
    assert kept == sorted(kept, reverse=True)
    assert kept[0] == 50000 and kept[-1] == 19000
    # the totals are unchanged by our trim and the identity still holds
    assert block["bytes_from_all_senders_total"] == total
    assert sum(kept) + block["bytes_from_all_senders_omitted"] == total
    assert block["rows_omitted"] == 18
    assert block["rows_total"] == len(block["rows"]) + block["rows_omitted"]


def test_peer_transfer_records_server_truncation_adds_to_device_omission():
    """Device-omitted and server-omitted mass accumulate in the same counters
    rather than either one overwriting the other."""
    rows = [{"ip": "10.0.1.%d" % i, "session_bytes_from_peer": 1000,
             "session_bytes_to_peer": 0} for i in range(40)]
    block = catalog._sanitize_report(_v2(peer_transfer_records=_transfer_records(
        rows=rows, rows_total=45, rows_omitted=5,
        bytes_from_all_senders_total=40000 + 77,
        bytes_from_all_senders_omitted=77)))["peer_transfer_records"]
    assert block["rows_omitted"] == 5 + 8
    assert block["bytes_from_all_senders_omitted"] == 77 + 8000
    assert block["rows_dropped_by_server"] == 8
    assert (sum(r["session_bytes_from_peer"] for r in block["rows"])
            + block["bytes_from_all_senders_omitted"]
            == block["bytes_from_all_senders_total"] == 40077)


def test_peer_transfer_records_incomplete_capture_is_carried_not_repaired():
    """complete:false says the hook could not read the whole peer list, so the
    total is a floor.  The server stores that fact; it never patches it up."""
    block = catalog._sanitize_report(_v2(peer_transfer_records=_transfer_records(
        complete=False)))["peer_transfer_records"]
    assert block["complete"] is False
    assert block["bytes_from_all_senders_total"] == 41943040


def test_peer_transfer_records_bytes_may_exceed_content_bytes():
    """aria2 counts WIRE bytes, so hashfailed/duplicate pieces can push the
    peer sum above the content length.  Rejecting the report over that would
    throw away the whole measurement — it is explicitly allowed."""
    rows = [{"ip": "10.0.0.7", "session_bytes_from_peer": 10 ** 6,
             "session_bytes_to_peer": 0}]
    out = catalog._sanitize_report(_v2(peer_transfer_records=_transfer_records(rows=rows)))
    assert out["content"]["completed_content_bytes"] == 10
    assert out["peer_transfer_records"]["bytes_from_all_senders_total"] == 10 ** 6


def test_peer_transfer_records_rejects_malformed_block():
    """A malformed block is a device bug and must raise, never be dropped —
    a silently missing block would be indistinguishable from "not measured"."""
    bad = [
        _transfer_records(source="guesswork"),                     # unknown provenance
        _transfer_records(source=None),
        {"captured_at": 50.0, "complete": True, "rows": []},   # no source
        _transfer_records(complete="true"),                        # not a strict bool
        _transfer_records(captured_at="50"),
        _transfer_records(captured_at=float("inf")),
        _transfer_records(captured_at=0.5),        # before window.start
        _transfer_records(captured_at=101.0),      # after report_created_at
        _transfer_records(rows="nope"),
        _transfer_records(rows=[{"ip": "not-an-ip", "session_bytes_from_peer": 1,
                         "session_bytes_to_peer": 0}]),
        _transfer_records(rows=["junk"]),
        _transfer_records(rows=[{"session_bytes_from_peer": 1,
                         "session_bytes_to_peer": 0}]),     # no ip
        _transfer_records(rows=[{"ip": "10.0.0.7", "session_bytes_from_peer": -1,
                         "session_bytes_to_peer": 0}]),
        _transfer_records(rows=[{"ip": "10.0.0.7", "session_bytes_from_peer": True,
                         "session_bytes_to_peer": 0}]),     # bool is not a count
        _transfer_records(rows=[{"ip": "10.0.0.7", "session_bytes_from_peer": 2 ** 53 + 1,
                         "session_bytes_to_peer": 0}]),
        _transfer_records(rows=[{"ip": "10.0.0.7", "session_bytes_from_peer": 1,
                         "session_bytes_to_peer": 0, "port": 70000}]),
        _transfer_records(rows=[{"ip": "10.0.0.7", "session_bytes_from_peer": 1,
                         "session_bytes_to_peer": 0, "has_complete_file": 1}]),
    ]
    for block in bad:
        with pytest.raises(ValueError):
            catalog._sanitize_report(_v2(peer_transfer_records=block))
    for block in ("nope", 5, ["rows"]):
        with pytest.raises(ValueError):
            catalog._sanitize_report(_v2(peer_transfer_records=block))


def test_peer_transfer_records_rejects_duplicate_peer_ip():
    """Two transfer records for one peer have no defined meaning: summing them would
    invent bytes, choosing one would discard measured bytes."""
    rows = [{"ip": "10.0.0.7", "session_bytes_from_peer": 5,
             "session_bytes_to_peer": 0},
            {"ip": "10.0.0.7", "session_bytes_from_peer": 7,
             "session_bytes_to_peer": 0}]
    with pytest.raises(ValueError):
        catalog._sanitize_report(_v2(peer_transfer_records=_transfer_records(rows=rows)))


def test_peer_transfer_records_rejects_broken_arithmetic():
    """The aggregate identities are the whole point: a total that does not
    account for its rows is not a measurement."""
    rows = [{"ip": "10.0.0.7", "session_bytes_from_peer": 100,
             "session_bytes_to_peer": 0}]
    with pytest.raises(ValueError):        # bytes do not add up
        catalog._sanitize_report(_v2(peer_transfer_records=_transfer_records(
            rows=rows, bytes_from_all_senders_total=999,
            bytes_from_all_senders_omitted=0)))
    with pytest.raises(ValueError):        # rows do not add up
        catalog._sanitize_report(_v2(peer_transfer_records=_transfer_records(
            rows=rows, rows_total=9, rows_omitted=0)))
    with pytest.raises(ValueError):        # rows_total below named rows
        catalog._sanitize_report(_v2(peer_transfer_records=_transfer_records(
            rows=rows, rows_total=0, rows_omitted=0)))


def test_v2_peer_rows_dropped_is_reported():
    """The v2 path used to trim 70 rows to 64 and still store
    peers_truncated:false — the drop left no trace.  Now the count is stored
    and the truncated flag is raised by the server's own trim."""
    rows = [{"ip": "10.0.2.%d" % i, "first_observed": 1.0,
             "last_observed": 2.0, "observations": 1} for i in range(70)]
    out = catalog._sanitize_report(_v2(peers=rows, peers_total=70))
    assert len(out["peers"]) == 64
    assert out["peers_rows_dropped"] == 6
    assert out["peers_truncated"] is True
    # untrimmed report: an explicit zero and the device's own flag preserved
    out = catalog._sanitize_report(_v2())
    assert out["peers_rows_dropped"] == 0 and out["peers_truncated"] is False
    out = catalog._sanitize_report(_v2(peers_truncated=True))
    assert out["peers_truncated"] is True


def test_v2_peers_total_checked_before_truncation():
    """peers_total is compared against the rows SENT, so over-sending rows can
    no longer shrink the declared distinct-peer count."""
    rows = [{"ip": "10.0.2.%d" % i, "first_observed": 1.0,
             "last_observed": 2.0, "observations": 1} for i in range(70)]
    with pytest.raises(ValueError):
        catalog._sanitize_report(_v2(peers=rows, peers_total=64))


def test_peer_transfer_records_survives_the_store_bound(tmp_path):
    """A full report — 64 participation rows plus 32 transfer-record rows — still fits
    the per-report store bound, and is stored and read back intact."""
    peers = [{"ip": "10.0.3.%d" % i, "first_observed": 1.0,
              "last_observed": 2.0, "observations": 3} for i in range(64)]
    rows = [{"ip": "10.0.4.%d" % i, "port": 6881,
             "session_bytes_from_peer": (i + 1) * 4096,
             "session_bytes_to_peer": 512, "has_complete_file": bool(i % 2)}
            for i in range(32)]
    rep = _v2(peers=peers, peers_total=64, peer_transfer_records=_transfer_records(rows=rows))
    s = catalog.CatalogStore(str(tmp_path))
    s.record_telemetry("d1", catalog._sanitize_report(rep))
    stored = s.get_telemetry("d1")[0]
    assert len(stored["peers"]) == 64
    assert len(stored["peer_transfer_records"]["rows"]) == 32
    assert stored["peer_transfer_records"]["bytes_from_all_senders_total"] == sum(
        r["session_bytes_from_peer"] for r in rows)


# ---------------------------------------------------------------------------
# Transfer plans: set_policy is the SOLE mint site for (plan_id, transfer_id)
#
# A plan is the server's durable name for one intended transfer of one image
# to one device. Minting it at assignment time -- rather than on the device at
# download time -- is what makes two consecutive assignments of the SAME image
# distinguishable: an unassign+reassign inside one agent tick window is
# invisible to the agent, so a device-minted id would silently merge the two
# transfers into one. Everything below pins the two facts the tracker's
# lifecycle telemetry rests on: a plan is NEVER re-minted while its image
# stays assigned, and a re-assignment after a real unassign ALWAYS gets a new
# one.
#
# The exact-dict-equality assertions on get_policy() further up this file
# (test_store_heartbeat_and_policy, test_policy_unassign_with_empty_list,
# test_purge_device_clears_all_state) are deliberately left as they were: they
# are the regression guard that the internal contract did not widen when the
# wire projection did.
# ---------------------------------------------------------------------------

def _plans(store, device_id):
    """The device's RAW plans map straight off policy.json.

    Read through list_policies() rather than get_policy(): get_policy()
    deliberately does not expose plans, and reading the raw row is also how
    the tracker's lifecycle pass sees it, so these tests fail if the on-disk
    shape drifts even when the wire projection still looks right."""
    rec = store.list_policies().get(device_id) or {}
    return rec.get("plans") or {}


def _is_hex32(value):
    return isinstance(value, str) and catalog._HEX32.match(value) is not None


def test_get_policy_still_returns_exactly_two_keys(tmp_path):
    """Named explicitly so the guarantee is a stated one rather than an
    accident of the older assertions above.

    get_policy() is the INTERNAL contract: set_policy's own compare-and-set,
    the heartbeat live-sample admission gate and the v2 ingest gate all read
    it. Widening it would change what those three see; the plans map reaches
    the device through device_policy_view() instead."""
    store = _store_with_images(tmp_path, ["img-a"])
    store.set_policy("d1", approved_image_ids=["img-a"])
    assert set(store.get_policy("d1")) == {"approved_image_id",
                                           "approved_image_ids"}
    # and on a device that has never been assigned anything
    assert set(store.get_policy("never-seen")) == {"approved_image_id",
                                                   "approved_image_ids"}


def test_assignment_mints_a_plan_and_transfer_id_on_every_caller_shape(tmp_path):
    """set_policy is the single funnel for every production assignment path --
    the console /assign route, the iris-assign CLI (and so every
    apply-assignments row), and this class's own quarantine auto-unassign --
    so a plan can only be missed if set_policy itself misses it. All three
    shapes are exercised here."""
    # the plural kwarg: the console and the CLI's multi-image form
    store = _store_with_images(tmp_path, ["img-a", "img-b"])
    store.set_policy("d1", approved_image_ids=["img-a", "img-b"])
    assert sorted(_plans(store, "d1")) == ["img-a", "img-b"]

    # the singular kwarg: rows and callers from the single-image era
    store.set_policy("d2", approved_image_id="img-a")
    assert sorted(_plans(store, "d2")) == ["img-a"]

    # the quarantine auto-unassign path, which rewrites the row from inside
    # the catalog itself. Imported locally: this module's own imports are the
    # older set and this is the only test here that needs the reconciler's
    # state constants.
    import bulkhash
    store.apply_hash_verification(
        {"img-b": {"state": bulkhash.STATE_MISMATCH, "feed_sha512": "bb" * 64,
                   "publish_date": "2026-08-01", "deferral": False}},
        source="scheduled", now=1000)
    # the quarantined image is gone from the set AND from the plans map, and
    # the survivor still has a plan -- the auto-unassign rewrites the whole
    # row, so a dropped plans map would show up here
    assert store.get_policy("d1")["approved_image_ids"] == ["img-a"]
    assert sorted(_plans(store, "d1")) == ["img-a"]
    assert _is_hex32(_plans(store, "d1")["img-a"]["transfer_id"])


def test_minted_ids_are_32_lowercase_hex_and_distinct_from_each_other(tmp_path):
    """The shape is a hard requirement, not a convention: transfer_id is
    re-validated against _HEX32 on ingest (_sanitize_report_v2 and the live
    sample path), and a value that failed it would fail the device's WHOLE
    report. plan_id shares the shape; the two must never be the same value,
    or a plan and its transfer would be indistinguishable in telemetry."""
    store = _store_with_images(tmp_path, ["img-a", "img-b"])
    store.set_policy("d1", approved_image_ids=["img-a", "img-b"])
    seen = set()
    for image_id, row in _plans(store, "d1").items():
        assert _is_hex32(row["plan_id"]), image_id
        assert _is_hex32(row["transfer_id"]), image_id
        assert row["plan_id"] != row["transfer_id"]
        seen.add(row["plan_id"])
        seen.add(row["transfer_id"])
    # four distinct ids across the two plans: no id is shared between images
    assert len(seen) == 4


def test_repeat_apply_of_the_same_set_carries_the_same_plan_and_transfer_id_forward(tmp_path):
    """Re-applying an unchanged set must be a no-op for identity.

    The row write replaces the WHOLE record, so without the explicit
    merge-forward every Apply would re-mint a transfer_id for every image the
    device is already pulling -- restarting each in-flight transfer's identity
    and orphaning every report already on the wire under the old id."""
    store = _store_with_images(tmp_path, ["img-a", "img-b"])
    store.set_policy("d1", approved_image_ids=["img-a", "img-b"])
    before = _plans(store, "d1")
    store.set_policy("d1", approved_image_ids=["img-a", "img-b"])
    store.set_policy("d1", approved_image_ids=["img-a", "img-b"])
    assert _plans(store, "d1") == before
    # re-ordering the same membership is still the same set of transfers
    store.set_policy("d1", approved_image_ids=["img-b", "img-a"])
    assert _plans(store, "d1") == before


def test_adding_an_image_mints_only_the_new_plan_and_leaves_the_others_alone(tmp_path):
    """Adding a third image to a device already pulling two must not disturb
    the two in flight -- the common console Apply, and the one that would
    otherwise restart every transfer on the device."""
    store = _store_with_images(tmp_path, ["img-a", "img-b", "img-c"])
    store.set_policy("d1", approved_image_ids=["img-a", "img-b"])
    before = _plans(store, "d1")
    store.set_policy("d1", approved_image_ids=["img-a", "img-b", "img-c"])
    after = _plans(store, "d1")
    assert after["img-a"] == before["img-a"]
    assert after["img-b"] == before["img-b"]
    assert _is_hex32(after["img-c"]["plan_id"])
    assert after["img-c"]["plan_id"] not in (before["img-a"]["plan_id"],
                                             before["img-b"]["plan_id"])
    # removing one leaves the others verbatim and drops only its own plan
    store.set_policy("d1", approved_image_ids=["img-a", "img-c"])
    assert "img-b" not in _plans(store, "d1")
    assert _plans(store, "d1")["img-a"] == before["img-a"]
    assert _plans(store, "d1")["img-c"] == after["img-c"]


def test_unassign_then_reassign_mints_a_distinct_plan_and_transfer_id(tmp_path):
    """The replan case, and the reason the ids are minted here at all.

    An image id that LEAVES the set has no entry in the new plans map, so the
    re-assignment mints a genuinely new plan. On the device this whole cycle
    can happen inside one ~60s tick window and is invisible to the agent --
    which is exactly why a device-minted id cannot keep the two transfers
    apart, and why the server must."""
    store = _store_with_images(tmp_path, ["img-a"])
    store.set_policy("d1", approved_image_ids=["img-a"])
    first = _plans(store, "d1")["img-a"]
    store.set_policy("d1", approved_image_ids=[])
    assert _plans(store, "d1") == {}
    store.set_policy("d1", approved_image_ids=["img-a"])
    second = _plans(store, "d1")["img-a"]
    assert second["plan_id"] != first["plan_id"]
    assert second["transfer_id"] != first["transfer_id"]
    assert _is_hex32(second["plan_id"]) and _is_hex32(second["transfer_id"])


def test_a_refused_conditional_apply_mints_nothing(tmp_path):
    """PolicyConflict is raised inside the policy lock and BEFORE any plan is
    computed, so a losing race leaves no orphan plan behind -- a plan row for
    an image the device was never assigned would be a transfer the tracker
    waits on forever."""
    store = _store_with_images(tmp_path, ["img-a", "img-b"])
    store.set_policy("d1", approved_image_ids=["img-a"])
    before = _plans(store, "d1")
    with pytest.raises(catalog.PolicyConflict):
        store.set_policy("d1", approved_image_ids=["img-b"],
                         expect_image_ids=[])
    assert _plans(store, "d1") == before
    assert "img-b" not in _plans(store, "d1")


def test_a_quarantined_image_mints_nothing(tmp_path):
    """QuarantinedImage is likewise raised before any plan is computed. A
    quarantined image is never staged, so it must never acquire the plan that
    would tell the tracker to expect a transfer of it."""
    store = _store_with_images(tmp_path, ["img-a"])
    entry = store.get_image("img-a")
    entry["quarantined"] = True
    store.save_image(entry)
    store.set_policy("d1", approved_image_ids=[])
    with pytest.raises(catalog.QuarantinedImage):
        store.set_policy("d1", approved_image_ids=["img-a"])
    assert _plans(store, "d1") == {}
    assert store.get_policy("d1")["approved_image_ids"] == []


def test_device_policy_view_carries_plans_and_get_policy_does_not(tmp_path):
    """device_policy_view() is the WIRE projection -- what GET
    /v1/devices/<id>/policy serves the agent -- and carries exactly the two
    ids the agent adopts. planned_at and info_hash stay server-side: the
    agent has no use for either (its info_hash comes from the personalised
    torrent), and shipping a field is a promise to keep shipping it.

    'plans' is ALWAYS present, possibly empty, so the agent's adoption loop
    can read it unconditionally."""
    store = _store_with_images(tmp_path, ["img-a", "img-b"])
    store.set_policy("d1", approved_image_ids=["img-a", "img-b"])
    view = store.device_policy_view("d1")
    assert set(view) == {"approved_image_id", "approved_image_ids", "plans"}
    assert view["approved_image_ids"] == ["img-a", "img-b"]
    assert sorted(view["plans"]) == ["img-a", "img-b"]
    for image_id, row in view["plans"].items():
        assert set(row) == {"plan_id", "transfer_id"}, image_id
        assert row["plan_id"] == _plans(store, "d1")[image_id]["plan_id"]
        assert row["transfer_id"] == _plans(store, "d1")[image_id]["transfer_id"]
    # the internal contract is untouched by the projection
    assert set(store.get_policy("d1")) == {"approved_image_id",
                                           "approved_image_ids"}
    # an unassigned device still gets the key, so the agent can read it blind
    assert store.device_policy_view("never-seen") == {
        "approved_image_id": None, "approved_image_ids": [], "plans": {}}


def test_a_hand_edited_plan_row_is_not_served_and_is_re_minted_on_the_next_apply(tmp_path):
    """policy.json is an operator-editable file on disk. A truncated or
    hand-edited id must not reach the device: transfer_id is re-validated
    against _HEX32 on ingest, so a malformed one would fail the device's
    whole report on the way back. Such a row is omitted from the wire
    projection and re-minted at the next set_policy rather than carried
    forward."""
    store = _store_with_images(tmp_path, ["img-a"])
    store.set_policy("d1", approved_image_ids=["img-a"])
    raw = store.list_policies()
    raw["d1"]["plans"]["img-a"]["transfer_id"] = "NOT-HEX"
    _write_policy_json(store, raw)
    assert store.device_policy_view("d1")["plans"] == {}
    store.set_policy("d1", approved_image_ids=["img-a"])
    row = _plans(store, "d1")["img-a"]
    assert _is_hex32(row["plan_id"]) and _is_hex32(row["transfer_id"])
    assert store.device_policy_view("d1")["plans"]["img-a"]["transfer_id"] \
        == row["transfer_id"]


def test_plan_row_captures_the_catalog_info_hash(tmp_path):
    """The plan captures the info_hash the tracker will see announced, from
    the catalog entry set_policy already has in hand, so the lifecycle pass
    can join an announce back to this plan without re-reading catalog.json at
    a later, possibly changed, moment."""
    store = _store_with_images(tmp_path, ["img-a"])
    store.set_policy("d1", approved_image_ids=["img-a"])
    row = _plans(store, "d1")["img-a"]
    assert row["info_hash"] == "cc" * 20
    assert isinstance(row["planned_at"], float)
    assert row["planned_at"] <= time.time()


def test_plan_row_info_hash_is_none_on_the_legacy_bootstrap_path(tmp_path):
    """set_policy stays usable with no catalog.json at all (the legacy
    bootstrap callers -- the existence check is explicitly skipped then), and
    a plan is still minted. There is simply no info_hash to capture, and the
    row says so with a null rather than omitting the key."""
    store = catalog.CatalogStore(str(tmp_path))       # no save_image() at all
    assert not os.path.exists(store.catalog_path)
    store.set_policy("d1", approved_image_ids=["img-a"])
    row = _plans(store, "d1")["img-a"]
    assert row["info_hash"] is None
    assert _is_hex32(row["plan_id"]) and _is_hex32(row["transfer_id"])


def test_purge_device_removes_the_plans_with_the_policy_row(tmp_path):
    """The plans live IN the policy row, so purge_device already takes them
    with it -- no second store to keep in step. A device deleted and added
    back must get brand-new plan ids, or it could inherit an 'already seeded'
    marker for a transfer that never happened on the new device."""
    store = _store_with_images(tmp_path, ["img-a"])
    store.set_policy("d1", approved_image_ids=["img-a"])
    first = _plans(store, "d1")["img-a"]
    assert store.purge_device("d1") is True
    assert _plans(store, "d1") == {}
    assert store.device_policy_view("d1")["plans"] == {}
    store.set_policy("d1", approved_image_ids=["img-a"])
    second = _plans(store, "d1")["img-a"]
    assert second["plan_id"] != first["plan_id"]
    assert second["transfer_id"] != first["transfer_id"]
    # forget_device (undeploy) deliberately keeps the assignment, so it also
    # keeps the plan: the same transfer is still the one in flight
    kept = _plans(store, "d1")["img-a"]
    store.record_heartbeat("d1", {"current_image_id": "img-a"}, now=222)
    assert store.forget_device("d1") is True
    assert _plans(store, "d1")["img-a"] == kept


def test_a_legacy_row_with_no_plans_key_reads_back_and_gains_plans_on_the_next_apply(tmp_path):
    """A row written by a previous release has no plans key at all. It must
    read back cleanly through both accessors -- with an empty plans map on
    the wire, which the agent treats as 'no plan, mint your own as before' --
    and gain a real plan at the next set_policy, with no migration step."""
    store = _store_with_images(tmp_path, ["img-a"])
    _write_policy_json(store, {"d1": {"approved_image_id": "img-a",
                                      "approved_image_ids": ["img-a"]}})
    assert store.get_policy("d1")["approved_image_ids"] == ["img-a"]
    view = store.device_policy_view("d1")
    assert view["approved_image_ids"] == ["img-a"]
    assert view["plans"] == {}
    # the single-image-era row shape (no plural key) reads the same way
    _write_policy_json(store, {"d1": {"approved_image_id": "img-a"}})
    assert store.device_policy_view("d1")["plans"] == {}
    store.set_policy("d1", approved_image_ids=["img-a"])
    assert _is_hex32(_plans(store, "d1")["img-a"]["transfer_id"])
    assert set(store.device_policy_view("d1")["plans"]["img-a"]) == {
        "plan_id", "transfer_id"}


# ===========================================================================
# Review wave: shard 02 (catalog protocol) regressions
# ===========================================================================

# --- IRIS-02-001: a corrupt/unreadable state file fails closed -------------

def test_corrupt_policy_state_is_not_read_as_empty_and_is_never_rewritten(tmp_path):
    """Reviewer probe P1: a trailing comma in the policy state used to make
    every device's policy read as the empty set (a fleet-wide unassign the
    agent acts on) and the next set_policy rewrote the file with a single row,
    losing every other assignment and its plan ids for good.

    Policy is keyed per device now, so the corruption is injected into the
    shard that actually holds dev-2 -- and the blast radius is narrower on
    purpose: a device in another shard keeps working, while every read or
    write that must touch the damaged shard still fails closed and never
    overwrites it."""
    s = _store_with_images(tmp_path, ["img-a", "img-b"])
    s.set_policy("dev-1", approved_image_ids=["img-a"])
    s.set_policy("dev-2", approved_image_ids=["img-b"])
    shard = os.path.join(keyed_state.shard_dir(s.policy_path),
                         "%02x.json" % keyed_state.bucket_of("dev-2"))
    good = open(shard).read()
    with open(shard, "w") as f:
        f.write(good.rstrip().rstrip("}") + ",}\n")
    corrupt = open(shard).read()
    for call in (lambda: s.get_policy("dev-2"),
                 lambda: s.device_policy_view("dev-2"),
                 lambda: s.list_policies(),
                 lambda: s.set_policy("dev-2", approved_image_ids=["img-b"])):
        with pytest.raises(catalog.StateFileError):
            call()
    assert open(shard).read() == corrupt      # untouched
    # Repairing the file restores everything that was there.
    with open(shard, "w") as f:
        f.write(good)
    assert s.get_policy("dev-2")["approved_image_ids"] == ["img-b"]
    assert s.get_policy("dev-1")["approved_image_ids"] == ["img-a"]


def test_missing_state_file_is_still_the_empty_store(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    assert s.get_policy("nobody") == {"approved_image_id": None,
                                      "approved_image_ids": []}
    assert s.list_devices() == []
    assert s.get_device("nobody") is None


def test_state_file_that_is_not_an_object_or_is_unreadable_fails_closed(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    with open(s.devices_path, "w") as f:
        f.write("[]")
    with pytest.raises(catalog.StateFileError):
        s.list_devices()
    with pytest.raises(catalog.StateFileError):
        s.record_heartbeat("sw-1", {"model": "x"})
    assert open(s.devices_path).read() == "[]"
    os.remove(s.devices_path)
    os.mkdir(s.devices_path)                 # exists, unreadable as a file
    with pytest.raises(catalog.StateFileError):
        s.list_devices()


def test_corrupt_policy_json_is_503_on_the_wire_not_an_empty_policy(tmp_path):
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        s = catalog.CatalogStore(str(tmp_path))
        s.set_policy("sw-9", approved_image_ids=["img1"])
        # Policy has already migrated to keyed shards; corrupt the live row,
        # not the deliberately retired legacy rollback-guard document.
        shard = os.path.join(keyed_state.shard_dir(s.policy_path),
                             "%02x.json" % keyed_state.bucket_of("sw-9"))
        with open(shard, "w") as f:
            f.write("{not json")
        status, _, body = _req(port, "GET", "/v1/devices/sw-9/policy",
                               token="tok")
        assert status == 503
        problem = json.loads(body)
        assert problem["status"] == 503
        assert problem["type"].endswith("service-unavailable")
        # The heartbeat consults the policy for the live-sample gate: the
        # heartbeat itself must not be lost to a 500 with no body either.
        status, _, body = _req(port, "POST", "/v1/devices/sw-9/heartbeat",
                               token="tok", body=json.dumps({"model": "x"}))
        assert status in (200, 503)
        assert json.loads(body)
    finally:
        srv.shutdown()


# --- IRIS-02-002 / IRIS-02-004: heartbeat and report ingest validation -----

def _hand_post(port, path, body, token="tok", extra_headers=""):
    """POST with a hand-built request so the header set is exactly ours."""
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    req = ("POST %s HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
           "Content-Type: application/json\r\n%s" % (path, token, extra_headers))
    if body is not None:
        req += "Content-Length: %d\r\n" % len(body)
    c.sendall(req.encode() + b"\r\n" + (body or b""))
    data = b""
    try:
        while True:
            chunk = c.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                head, _, rest = data.partition(b"\r\n\r\n")
                clen = [ln for ln in head.split(b"\r\n")
                        if ln.lower().startswith(b"content-length:")]
                if clen and len(rest) >= int(clen[0].split(b":")[1]):
                    break
    except socket.timeout:
        pass
    c.close()
    if not data:
        return None, b""
    head, _, rest = data.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), rest


def test_heartbeat_rejects_nan_and_infinity_literals(tmp_path):
    """Reviewer probe P2b: NaN/Infinity parsed, were stored verbatim and
    re-emitted as bare tokens in devices.json and /api/devices, which no
    browser JSON parser accepts -- one device broke the fleet view."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        status, body = _hand_post(
            port, "/v1/devices/sw-1/heartbeat",
            b'{"free_flash_bytes": NaN, "version": Infinity}')
        assert status == 400
        problem = json.loads(body)
        assert problem["status"] == 400 and problem["error"] == "bad json"
        status, _ = _hand_post(port, "/v1/devices/sw-1/telemetry",
                              b'{"event": "pull", "ts": NaN}')
        assert status == 400
    finally:
        srv.shutdown()
    assert catalog.CatalogStore(str(tmp_path)).get_device("sw-1") is None


def test_heartbeat_fields_are_typed_and_capped(tmp_path):
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        body = json.dumps({
                "current_image_id": "img1",
                "version": 7,                       # wrong type
                "model": {"nested": [1, 2, 3]},     # wrong type
                "stage_state": 12345,
                "stage_error": "E" * 40000,
                "target_fs": "flash:",
                "telemetry_enabled": "yes",
                "staged_image_ids": ["S" * 20000],
                "errored_image_ids": ["img1", "bad id"]})
        # 1e999 is a legal JSON number that Python parses as inf (it is not
        # one of the literals parse_constant refuses).
        body = body[:-1] + ', "free_flash_bytes": 1e999}'
        status, _, _ = _req(port, "POST", "/v1/devices/sw-1/heartbeat",
                            token="tok", body=body)
        assert status == 200
    finally:
        srv.shutdown()
    rec = catalog.CatalogStore(str(tmp_path)).get_device("sw-1")
    assert rec["current_image_id"] == "img1"
    assert rec["free_flash_bytes"] is None
    assert rec["version"] is None
    assert rec["model"] is None
    assert rec["stage_state"] is None
    assert len(rec["stage_error"]) == 1024
    assert rec["target_fs"] == "flash:"
    assert rec["telemetry_enabled"] is None
    assert rec["staged_image_ids"] is None       # not an image id shape
    assert rec["errored_image_ids"] is None      # rejected wholesale
    assert "NaN" not in json.dumps(
        keyed_state.read_all(os.path.join(str(tmp_path), "devices.json")))


def test_heartbeat_well_typed_fields_round_trip_unchanged(tmp_path):
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        _req(port, "POST", "/v1/devices/sw-1/heartbeat", token="tok",
             body=json.dumps({"current_image_id": "img1",
                              "free_flash_bytes": 123456789,
                              "version": "17.18.1", "model": "C9300-48P",
                              "stage_state": "ready", "stage_error": None,
                              "target_fs": "flash:", "telemetry_enabled": True,
                              "telemetry_stream_enabled": False,
                              "staged_image_ids": ["img1"],
                              "errored_image_ids": []}))
    finally:
        srv.shutdown()
    rec = catalog.CatalogStore(str(tmp_path)).get_device("sw-1")
    assert rec["free_flash_bytes"] == 123456789
    assert rec["version"] == "17.18.1" and rec["model"] == "C9300-48P"
    assert rec["telemetry_enabled"] is True
    assert rec["telemetry_stream_enabled"] is False
    assert rec["staged_image_ids"] == ["img1"]
    assert rec["errored_image_ids"] == []


def test_v1_report_with_non_finite_float_is_400(tmp_path):
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    try:
        rep = {"event": "pull", "ts": 1e999, "transfer": {"total_bytes": 5}}
        status, _ = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                          json.dumps(rep).encode())
        assert status == 400
    finally:
        srv.shutdown()
    assert catalog.CatalogStore(str(tmp_path)).get_telemetry("sw-9") == []


def test_state_writer_and_json_response_refuse_nan(tmp_path):
    with pytest.raises(ValueError):
        catalog._atomic_write_json(str(tmp_path / "x.json"),
                                   {"v": float("nan")})
    assert not os.path.exists(str(tmp_path / "x.json"))
    with pytest.raises(ValueError):
        catalog.Catalog._json(200, {"v": float("inf")})


def test_heartbeat_non_object_or_deeply_nested_body_is_400(tmp_path):
    """Reviewer probe P2a / nest.py: a list/null/string body raised
    AttributeError and a 60 KiB nest of brackets RecursionError -- both
    escaped the handler and closed the socket with no status line."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        for body in (b"[]", b"null", b'"x"',
                     b"[" * 30000 + b"]" * 30000):
            status, resp = _hand_post(port, "/v1/devices/sw-1/heartbeat", body)
            assert status == 400, body[:10]
            problem = json.loads(resp)
            assert problem["status"] == 400 and problem["error"] == "bad json"
        status, resp = _hand_post(port, "/v1/devices/sw-1/telemetry",
                                 b"[" * 30000 + b"]" * 30000)
        assert status == 400
    finally:
        srv.shutdown()


# --- IRIS-02-006: a length-less (chunked) POST is 411, not an empty body ---

def test_chunked_post_is_411_and_does_not_blank_the_heartbeat(tmp_path):
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    try:
        _req(port, "POST", "/v1/devices/sw-1/heartbeat", token="tok",
             body=json.dumps({"current_image_id": "img1", "model": "C9300"}))
        status, resp = _hand_post(
            port, "/v1/devices/sw-1/heartbeat", None,
            extra_headers="Transfer-Encoding: chunked\r\n")
        assert status == 411
        problem = json.loads(resp)
        assert problem["status"] == 411
        assert problem["type"].endswith("content-length-required")
        status, _ = _hand_post(port, "/v1/devices/sw-1/heartbeat", None)
        assert status == 411                   # no length header at all
    finally:
        srv.shutdown()
    rec = catalog.CatalogStore(str(tmp_path)).get_device("sw-1")
    assert rec["current_image_id"] == "img1" and rec["model"] == "C9300"


# --- IRIS-02-003: the handler has a socket timeout -------------------------

def test_handler_socket_timeout_releases_a_stalled_connection(tmp_path):
    """Reviewer probe P4: six stalled clients pinned six handler threads
    forever. With the handler timeout, the server hangs up on its own and
    the thread count returns to baseline."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-1")
    assert srv.RequestHandlerClass.timeout == catalog.HANDLER_TIMEOUT
    assert catalog.handler_timeout({"IRIS_HTTP_TIMEOUT": "-1"}) == \
        catalog.HANDLER_TIMEOUT
    assert catalog.handler_timeout({"IRIS_HTTP_TIMEOUT": "12"}) == 12.0
    srv.RequestHandlerClass.timeout = 0.5
    try:
        base = threading.active_count()
        stalled = []
        for i in range(2):
            c = socket.create_connection(("127.0.0.1", port), timeout=5)
            if i == 0:
                c.sendall(b"POST /v1/devices/sw-1/heart")     # partial line
            else:
                c.sendall(b"POST /v1/devices/sw-1/heartbeat HTTP/1.1\r\n"
                          b"Host: x\r\nAuthorization: Bearer tok\r\n"
                          b"Content-Length: 5000\r\n\r\n{\"a\":")  # short body
            stalled.append(c)
        for c in stalled:
            assert c.recv(16) == b""       # server closed it on its own
            c.close()
        deadline = time.time() + 5
        while threading.active_count() > base and time.time() < deadline:
            time.sleep(0.05)
        assert threading.active_count() <= base
    finally:
        srv.shutdown()


# --- IRIS-02-005: plan rows are matched whole -------------------------------

def test_plan_row_with_trailing_newline_is_not_served_and_is_re_minted(tmp_path):
    s = _store_with_images(tmp_path, ["img-a"])
    s.set_policy("d1", approved_image_ids=["img-a"])
    rows = s.list_policies()
    rows["d1"]["plans"]["img-a"]["transfer_id"] = "c" * 32 + "\n"
    _write_policy_json(s, rows)
    assert s.device_policy_view("d1")["plans"] == {}
    s.set_policy("d1", approved_image_ids=["img-a"])
    tid = s.list_policies()["d1"]["plans"]["img-a"]["transfer_id"]
    assert catalog._HEX32.fullmatch(tid)


# --- IRIS-02-009: stage-only wording -----------------------------------------

def test_module_prose_no_longer_describes_an_install_approval():
    src = open(catalog.__file__).read()
    assert "install-approval flag" not in src
    assert "install-approval gate" not in src


def test_catalog_tls_handshake_is_not_on_the_accept_thread(tmp_path):
    """The device-facing listener must not hand its whole accept loop to one
    silent client, and must not use the stdlib backlog of 5.

    Wrapping the LISTENING socket makes socketserver run the TLS handshake
    inside accept() on the single serve_forever thread, so a client that
    connects and never sends a ClientHello (a port scan, a TCP health check,
    a stalled NAT'd agent) stalls every device in the fleet. The handshake
    belongs in the worker thread, as it already does for the console and the
    artifact server.
    """
    import ssl as _ssl
    import subprocess
    key = str(tmp_path / "k.pem")
    crt = str(tmp_path / "c.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-keyout", key, "-out", crt, "-subj", "/CN=iris"],
        check=True, capture_output=True)
    combined = str(tmp_path / "combined.pem")
    with open(combined, "w") as out:
        for part in (crt, key):
            with open(part) as f:
                out.write(f.read())

    state = str(tmp_path / "state")
    os.makedirs(state, exist_ok=True)
    store = catalog.CatalogStore(state)
    srv = catalog.make_server("127.0.0.1", 0, store,
                              str(tmp_path / "secrets.json"),
                              certfile=combined)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert srv.request_queue_size >= 128        # not the stdlib 5
        assert not isinstance(srv.socket, _ssl.SSLSocket)  # listener stays plain
        idle = socket.create_connection(("127.0.0.1", port), timeout=5)
        time.sleep(0.3)                              # never sends a ClientHello
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx,
                                           timeout=5)
        conn.request("GET", "/v1/does-not-exist")    # served, so TLS completed
        assert conn.getresponse().status in (401, 404)
        conn.close()
        idle.close()
    finally:
        srv.shutdown()


_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_main_refuses_plaintext_without_opt_in_then_serves_with_it(tmp_path):
    """IRIS-105: catalog.main() used to silently fall back to plain HTTP
    whenever no certificate was found -- every route on this listener answers
    a device bearer token, so a plaintext catalog serves them in the clear.
    Now it fails CLOSED (exit 2, naming the opt-in) exactly like the console's
    IRIS_GUI_ALLOW_PLAINTEXT contract, unless IRIS_CATALOG_ALLOW_PLAINTEXT=1
    opts in explicitly; port 0 so no fixed port is ever bound."""
    host = "127.0.0.1"
    env = dict(os.environ)
    env["IRIS_CATALOG_HOST"] = host
    env["IRIS_CATALOG_PORT"] = "0"
    env["IRIS_STATE"] = str(tmp_path / "state")
    env["IRIS_SECRETS"] = str(tmp_path / "secrets.json")
    env["IRIS_CERT"] = str(tmp_path / "nonexistent-cert.pem")
    env.pop("IRIS_CATALOG_ALLOW_PLAINTEXT", None)
    refused = subprocess.run([sys.executable, "catalog.py"], cwd=_SERVER_DIR,
                             env=env, capture_output=True, timeout=30)
    assert refused.returncode == 2
    assert b"IRIS_CATALOG_ALLOW_PLAINTEXT=1" in refused.stderr

    env["IRIS_CATALOG_ALLOW_PLAINTEXT"] = "1"
    proc = subprocess.Popen([sys.executable, "catalog.py"], cwd=_SERVER_DIR,
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        line = proc.stdout.readline()
        assert b"catalog on http://" in line, (line, proc.stderr.read())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def test_task13_behavioral_red_set_policy_preserves_instruction_stamp(tmp_path):
    store = catalog.CatalogStore(str(tmp_path))
    stamp = {
        "epoch": 100,
        "instr_serial": 7,
        "policy_revision": 3,
        "platform": "guestshell",
        "role": "default",
        "role_gen": "a" * 64,
        "role_body_sha256": "b" * 64,
        "key_id": "c" * 64,
        "verify_level": "sig",
        "issued_at": 101,
        "expires_at": 101 + 604800,
        "degraded": False,
        "part": {
            "peers": {
                "mode": "tracker-only",
                "include_origin": False,
                "allowed_expires_at": 101 + 604800,
            },
            "qos_override": {},
            "control_override": {},
            "server_time": 101,
        },
    }
    store._policies.put("d1", {
        "approved_image_id": None,
        "approved_image_ids": [],
        "plans": {},
        "instr": stamp,
    })

    store.set_policy("d1", approved_image_ids=[])

    assert store._policies.get("d1")["instr"] == stamp


def test_task13_malformed_established_stamp_refuses_policy_rewrite(tmp_path):
    store = catalog.CatalogStore(str(tmp_path))
    bucket = keyed_state.bucket_of("d1")
    directory = keyed_state.shard_dir(store.policy_path)
    os.makedirs(directory, exist_ok=True)
    shard = os.path.join(directory, "%02x.json" % bucket)
    malformed = {"d1": {"approved_image_id": None,
                        "approved_image_ids": [], "plans": {},
                        "instr": {"instr_serial": 7}}}
    with open(shard, "w") as stream:
        json.dump(malformed, stream)
    before = open(shard, "rb").read()
    with pytest.raises(catalog.StateFileError,
                       match="keyed state row is corrupt"):
        store.set_policy("d1", approved_image_ids=[])
    assert open(shard, "rb").read() == before


def test_task13_unassign_and_concurrent_apply_merge_preserve_stamp(tmp_path):
    store = catalog.CatalogStore(str(tmp_path))
    store.set_policy("d1", approved_image_ids=["img-a"])
    stamp = {
        "epoch": 100, "instr_serial": 7, "policy_revision": 3,
        "platform": "guestshell", "role": "default", "role_gen": "a" * 64,
        "role_body_sha256": "b" * 64, "key_id": "c" * 64,
        "verify_level": "sig", "issued_at": 101, "expires_at": 604901,
        "degraded": False,
        "part": {"peers": {"mode": "tracker-only", "include_origin": False,
                            "allowed_expires_at": 604901},
                 "qos_override": {}, "control_override": {},
                 "server_time": 101}}
    store._policies.update("d1", lambda row: dict(row, instr=stamp))
    barrier = threading.Barrier(2)

    def apply():
        barrier.wait()
        store.set_policy("d1", approved_image_ids=[])

    def stamp_merge():
        barrier.wait()
        store._policies.update("d1", lambda row: dict(row, instr=stamp))

    threads = [threading.Thread(target=apply), threading.Thread(target=stamp_merge)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    row = store._policies.get("d1")
    assert row["approved_image_ids"] == []
    assert row["instr"] == stamp
    store.set_policy("d1", approved_image_ids=["img-a"])
    assert store._policies.get("d1")["instr"] == stamp


def test_task13_quarantine_auto_unassign_carries_instruction_stamp(tmp_path):
    store = catalog.CatalogStore(str(tmp_path))
    store.save_image({
        "id": "img-a", "filename": "img-a.bin", "size": 5,
        "sha256": "ab" * 32, "sha512": "aa" * 64,
        "cisco_signature_verified": False,
        "info_hash_hex": "cc" * 20, "published_at": 111,
    })
    store.set_policy("d1", approved_image_ids=["img-a"])
    stamp = {
        "epoch": 100, "instr_serial": 7, "policy_revision": 3,
        "platform": "guestshell", "role": "default", "role_gen": "a" * 64,
        "role_body_sha256": "b" * 64, "key_id": "c" * 64,
        "verify_level": "sig", "issued_at": 101, "expires_at": 604901,
        "degraded": False,
        "part": {"peers": {"mode": "tracker-only", "include_origin": False,
                            "allowed_expires_at": 604901},
                 "qos_override": {}, "control_override": {},
                 "server_time": 101}}
    store._policies.update("d1", lambda row: dict(row, instr=stamp))
    store.apply_hash_verification({
        "img-a": {"state": "mismatch", "feed_sha512": "bb" * 64,
                  "publish_date": "2026-09-07", "deferral": False}},
        source="scheduled", now=1000)
    row = store._policies.get("d1")
    assert row["approved_image_ids"] == []
    assert row["plans"] == {}
    assert row["instr"] == stamp


# --- Task 14: one raw policy snapshot and catalog regression seams ---------

def _task14_stamp(serial=7):
    issued, expires = 100, 200
    return {
        "epoch": 100, "instr_serial": serial, "policy_revision": 3,
        "platform": "guestshell", "role": "default",
        "role_gen": "a" * 64, "role_body_sha256": "b" * 64,
        "key_id": "c" * 64, "verify_level": "sig",
        "issued_at": issued, "expires_at": expires, "degraded": False,
        "part": {"peers": {"mode": "tracker-only",
                            "include_origin": False,
                            "allowed_expires_at": expires},
                 "qos_override": {}, "control_override": {},
                 "server_time": issued}}


def _task14_write_policy_rows(store, rows):
    grouped = {}
    for device_id, row in rows.items():
        grouped.setdefault(keyed_state.bucket_of(device_id), {})[device_id] = row
    for bucket, shard_rows in grouped.items():
        path = (Path(keyed_state.shard_dir(store.policy_path)) /
                ("%02x.json" % bucket))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(shard_rows, allow_nan=False))


def test_task14_raw_policy_snapshot_migrates_structurally_raw_first_and_durable(
        tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    policy = state / "policy.json"
    policy.write_text(json.dumps({
        "device-a": {"approved_image_id": "legacy"},
        # Structurally valid and therefore migrated by the raw view, while a
        # later strict policy consumer must reject the malformed stamp.
        "device-b": {"approved_image_id": None, "instr": {"epoch": 1}},
    }))
    shard_dir = Path(keyed_state.shard_dir(str(policy)))
    shard_dir.mkdir()
    bucket = keyed_state.bucket_of("device-a")
    (shard_dir / ("%02x.json" % bucket)).write_text(json.dumps({
        "device-a": {"approved_image_id": "newer-shard"}}))
    barriers = []
    real_fsync = keyed_state._fsync_directory

    def counted(directory):
        barriers.append(os.fspath(directory))
        return real_fsync(directory)

    monkeypatch.setattr(keyed_state, "_fsync_directory", counted)
    store = catalog.CatalogStore(str(state))
    assert store.read_policy_row_snapshot("device-a") == {
        "approved_image_id": "newer-shard"}
    assert barriers and Path(str(policy) + ".migrated").exists()
    assert policy.exists() and "not valid JSON" in policy.read_text()
    first = store.read_policy_row_snapshot("device-b")
    assert first["instr"] == {"epoch": 1}
    first["instr"]["epoch"] = 99
    assert store.read_policy_row_snapshot("device-b")["instr"] == {"epoch": 1}
    with pytest.raises(catalog.StateFileError):
        store.get_policy("device-b")


def test_task14_raw_policy_snapshot_rejects_recursive_nonfinite_duplicate_and_shape(
        tmp_path, monkeypatch):
    cases = (
        '{"device-a":{"nested":[1e999]}}',
        '{"device-a":{},"device-a":{}}',
        '[]',
        '{"device-a":[]}',
    )
    for index, payload in enumerate(cases):
        state = tmp_path / str(index)
        state.mkdir()
        policy = state / "policy.json"
        original = payload.encode()
        policy.write_bytes(original)
        store = catalog.CatalogStore(str(state))
        with pytest.raises(catalog.StateFileError):
            store.read_policy_row_snapshot("device-a")
        assert policy.read_bytes() == original
        assert not Path(str(policy) + ".migrated").exists()
        shard_dir = Path(keyed_state.shard_dir(str(policy)))
        assert not shard_dir.exists() or not list(shard_dir.glob("*.json"))

    state = tmp_path / "copy-errors"
    state.mkdir()
    store = catalog.CatalogStore(str(state))
    row = {"approved_image_id": None, "approved_image_ids": [],
           "copy_failure": True}
    _task14_write_policy_rows(store, {"device-a": row})
    real_deepcopy = catalog.copy.deepcopy
    for error_type in (RecursionError, OverflowError):
        def fail_copy(_value, selected=error_type):
            raise selected("synthetic copy depth failure")

        monkeypatch.setattr(catalog.copy, "deepcopy", fail_copy)
        with pytest.raises(catalog.StateFileError):
            store.read_policy_row_snapshot("device-a")
        with pytest.raises(catalog.StateFileError):
            store.device_policy_view_from_row("device-a", row)
    monkeypatch.setattr(catalog.copy, "deepcopy", real_deepcopy)


def test_task14_device_policy_projection_adds_only_stored_instr_rev_with_one_read(
        tmp_path):
    store = catalog.CatalogStore(str(tmp_path))
    stamp = _task14_stamp()
    _task14_write_policy_rows(store, {"device-a": {
        "approved_image_id": None, "approved_image_ids": [],
        "plans": {}, "instr": stamp}})
    view = store.device_policy_view("device-a")
    assert view == {"approved_image_id": None, "approved_image_ids": [],
                    "plans": {},
                    "instr_rev": {"epoch": 100, "instr_serial": 7}}
    row = store.read_policy_row_snapshot("device-a")
    assert store.device_policy_view_from_row("device-a", row) == view
    row["instr"] = {"epoch": 1}
    with pytest.raises(catalog.StateFileError):
        store.device_policy_view_from_row("device-a", row)


def test_task14_complete_handler_policy_read_counts_and_legacy_behavior(
        tmp_path, monkeypatch):
    real_read = catalog.CatalogStore.read_policy_row_snapshot
    srv, port = _serve(tmp_path, "tok", device_id="device-a")
    store = catalog.CatalogStore(str(tmp_path))
    counts = []

    def counted(state, device_id):
        if state.policy_path == store.policy_path:
            counts.append(device_id)
        return real_read(state, device_id)

    monkeypatch.setattr(catalog.CatalogStore, "read_policy_row_snapshot",
                        counted)
    try:
        checks = (
            ("GET", "/v1/devices/device-a/policy", None, 200, 1),
            ("GET", "/v1/devices/device-a/instructions", None, 404, 1),
            ("GET", "/v1/devices/device-a/instruction-keylist", None, 404, 0),
            ("POST", "/v1/devices/device-a/heartbeat", "{}", 200, 1),
        )
        for method, path, body, expected, reads in checks:
            counts[:] = []
            status, _, _ = _req(port, method, path, token="tok", body=body)
            assert status == expected and len(counts) == reads
        counts[:] = []
        status, _, body = _req(port, "GET", "/v1/images", token="tok")
        assert status == 200 and json.loads(body)["images"][0]["id"] == "img1"
    finally:
        srv.shutdown()
        srv.server_close()


def test_task14_heartbeat_uses_authoritative_attestation_sanitizer():
    data = {
        "current_image_id": "img1", "instr_state": "key_rejected",
        "instr_reason": "bad_mac", "instr_serial": 4,
        "verify_level": "sig",
        "applied": {name: index for index, name in enumerate(
            instructions.APPLIED_FIELDS, 1)},
    }
    expected = instructions.sanitize_instruction_attestation(data)
    sanitized = catalog.sanitize_heartbeat(data, "192.0.2.1")
    assert {key: sanitized[key] for key in expected} == expected
    assert set(sanitized) == {
        "current_image_id", "free_flash_bytes", "version", "stage_state",
        "stage_error", "target_fs", "model", "telemetry_enabled",
        "telemetry_stream_enabled", "staged_image_ids", "errored_image_ids",
        "swarm_ip", *expected}


def test_assignment_result_and_unchanged_cas_are_decided_inside_policy_callback(tmp_path):
    store = catalog.CatalogStore(str(tmp_path))
    first = store.set_policy("d1", approved_image_ids=["a", "b"])
    assert first.before_ids == []
    assert first.after_ids == ["a", "b"]
    result = store.set_policy("d1", approved_image_ids=["b"],
                              expect_image_ids=["a", "b"], skip_unchanged=True)
    assert result.before_ids == ["a", "b"]
    assert result.after_ids == ["b"]
    assert result.removed_ids == ["a"]
    with pytest.raises(catalog.PolicyConflict):
        store.set_policy("d1", approved_image_ids=["b"],
                         expect_image_ids=["a", "b"], skip_unchanged=True)
