# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import gzip
import hashlib
import http.client
import json
import os
import socket
import threading
import time

import pytest

import catalog
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


def _store(tmp_path):
    s = catalog.CatalogStore(str(tmp_path))
    (tmp_path / "torrents").mkdir(exist_ok=True)
    (tmp_path / "torrents" / "img1.torrent").write_bytes(b"d4:infod}fakeee")
    s.save_image({"id": "img1", "filename": "img1.bin", "size": 5,
                  "sha256": "ab" * 32, "cisco_signature_verified": False,
                  "info_hash_hex": "cc" * 20, "published_at": 111})
    return s


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
    s.set_policy("sw-1", approved_image_id="img1", install_allowed=True)
    assert s.get_policy("sw-1") == {"approved_image_id": "img1",
                                    "install_allowed": True}


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
    srv, port = _serve(tmp_path, "tok", device_id="100.92.9.3")
    try:
        status, _, _ = _req(
            port, "POST", "/v1/devices/100.92.9.3/heartbeat", token="tok",
            body=json.dumps({"current_image_id": "img1", "free_flash_bytes": 9,
                             "version": "26.01.01",
                             "model": "C9300-48UXM"}))
        assert status == 200
    finally:
        srv.shutdown()
    rec = catalog.CatalogStore(str(tmp_path)).get_device("100.92.9.3")
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


def test_torrent_download_bytes(tmp_path):
    srv, port = _serve(tmp_path, "tok")
    try:
        status, ctype, body = _req(
            port, "GET", "/v1/torrents/img1.torrent", token="tok")
        assert status == 200 and ctype == "application/x-bittorrent"
        assert body == b"d4:infod}fakeee"
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
        status, _, body = _req(port, "GET", "/v1/devices", token="tok")
        devices = json.loads(body)["devices"]
        assert any(s["device_id"] == "sw-9" for s in devices)
        device9 = [s for s in devices if s["device_id"] == "sw-9"][0]
        assert device9["stage_state"] == "ready"
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
    """POST /v1/devices/<id>/token-refresh → new catalog_token + all 4 keys."""
    os.environ["IRIS_AGE_RECIPIENTS"] = ""
    srv, port, old_tok = _serve_with_device(tmp_path, "dev-1")
    try:
        status, ctype, body_bytes = _req(
            port, "POST",
            "/v1/devices/dev-1/token-refresh",
            token=old_tok,
            body=b"{}")
        assert status == 200, body_bytes
        resp = json.loads(body_bytes)
        assert "catalog_token" in resp
        assert "expires_at" in resp
        assert "announce_token" in resp
        assert "rpc_secret" in resp
        assert resp["catalog_token"] != old_tok
    finally:
        srv.shutdown()


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
        assert status == 200, body
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
        assert status == 200, body
        resp = json.loads(body)
        assert resp.get("announce_token"), "present announce_token was dropped"
        assert resp.get("rpc_secret"), "present rpc_secret was dropped"
    finally:
        srv.shutdown()


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
        assert status == 200, body
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
    try:
        status, _, body = _req(
            port, "POST", "/v1/devices/dev-int/token-refresh",
            token=old_tok, body=b"{}")
        assert status == 200, body
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
        assert fail_events[-1]["device_id"] == "dev-a"
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


# ---------------------------------------------------------------------------
# Task 5 NEW: overlap asymmetry — old token rejected on device-bound routes
# ---------------------------------------------------------------------------

def test_old_token_rejected_on_device_bound_after_refresh(tmp_path):
    """After a token-refresh, the OLD token is rejected on device-bound routes
    (heartbeat) but still accepted on shared routes (GET /v1/images) within the
    overlap window — the asymmetry is intentional per _guard design."""
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

        # OLD token on device-bound heartbeat → 401 (auth.authorize rejects
        # catalog_token_prev because it has no SECRET_TYPES entry)
        status, _, _ = _req(port, "POST",
                            "/v1/devices/dev-asym/heartbeat",
                            token=old_tok,
                            body=json.dumps({"current_image_id": "img1"}))
        assert status == 401, "old token must be rejected on heartbeat"

        # OLD token on shared route GET /v1/images → still 200 within overlap
        status, _, _ = _req(port, "GET", "/v1/images", token=old_tok)
        assert status == 200, "old token must still work on shared route within overlap"
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
            assert status == 200, body
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
        assert status == 200, body
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
        "peers": [{"ip": "10.0.0.7", "rx_bytes": 123456, "tx_bytes": 0,
                   "avg_bps": 10288}],
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
    """Unknown top-level keys dropped; peers re-trimmed to 20 rows of exactly
    {ip[:64], rx_bytes:int, tx_bytes:int, avg_bps:int}; every other string
    capped at 128."""
    data = _report()
    data["evil_key"] = "drop me"
    data["install"] = True                       # never store install intents
    data["image_id"] = "A" * 300
    data["link"]["tier"] = "B" * 300
    data["peers"] = [{"ip": "10.0.0.%d" % i, "rx_bytes": i * 10,
                      "tx_bytes": str(i), "avg_bps": i, "extra": "drop"}
                     for i in range(30)]
    data["peers"][0]["ip"] = "C" * 100
    data["peers"].insert(5, "junk-row")          # non-dict rows are skipped
    out = catalog._sanitize_report(data)
    # unknown top-level keys dropped
    assert set(out) <= {"ts", "image_id", "event", "transfer", "link",
                        "peers", "agent"}
    assert "evil_key" not in out and "install" not in out
    # strings capped at 128 (top-level and nested)
    assert out["image_id"] == "A" * 128
    assert out["link"]["tier"] == "B" * 128
    # peers: exactly 20 rows, exact row shape, ip capped at 64, ints coerced
    assert len(out["peers"]) == 20
    assert set(out["peers"][0]) == {"ip", "rx_bytes", "tx_bytes", "avg_bps"}
    assert out["peers"][0]["ip"] == "C" * 64
    assert out["peers"][1] == {"ip": "10.0.0.1", "rx_bytes": 10, "tx_bytes": 1,
                               "avg_bps": 1}
    # untouched fields survive
    assert out["ts"] == 1783000000
    assert out["transfer"]["sha_ok"] is True


def test_sanitize_report_accepts_and_coerces_avg_bps():
    """The per-peer avg_bps int round-trips; a non-int value coerces to 0
    (same int-coercion as rx_bytes/tx_bytes)."""
    data = _report(peers=[
        {"ip": "10.0.0.7", "rx_bytes": 100, "tx_bytes": 0, "avg_bps": 4200},
        {"ip": "10.0.0.8", "rx_bytes": 200, "tx_bytes": 0,
         "avg_bps": "not-a-number"},
        {"ip": "10.0.0.9", "rx_bytes": 300, "tx_bytes": 0},   # avg_bps absent
    ])
    out = catalog._sanitize_report(data)
    assert out["peers"] == [
        {"ip": "10.0.0.7", "rx_bytes": 100, "tx_bytes": 0, "avg_bps": 4200},
        {"ip": "10.0.0.8", "rx_bytes": 200, "tx_bytes": 0, "avg_bps": 0},
        {"ip": "10.0.0.9", "rx_bytes": 300, "tx_bytes": 0, "avg_bps": 0}]


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
    assert s.pending_report("dev-1", now) is False
    # request -> pending
    assert s.request_report("dev-1", now) is True
    assert s.pending_report("dev-1", now + 1) is True
    # one pending per device: duplicate refused while unexpired
    assert s.request_report("dev-1", now + 10) is False
    # TTL expiry: at now + PULL_TTL the directive is expired...
    assert s.pending_report("dev-1", now + 600) is False
    # ...and was lazily deleted from pull_requests.json
    with open(str(tmp_path / "pull_requests.json")) as f:
        assert "dev-1" not in json.load(f)
    # a new request after expiry succeeds
    assert s.request_report("dev-1", now + 600) is True
    # explicit clear
    s.clear_report_request("dev-1")
    assert s.pending_report("dev-1", now + 601) is False


def test_record_telemetry_clears_pull_request(tmp_path):
    """An arriving report answers (or supersedes) the pending pull directive
    for THAT device only."""
    s = catalog.CatalogStore(str(tmp_path))
    assert s.request_report("dev-1", 1000.0) is True
    assert s.request_report("dev-2", 1000.0) is True
    assert s.pending_report("dev-1", 1001.0) is True
    s.record_telemetry("dev-1", _report(event="pull"))
    assert s.pending_report("dev-1", 1002.0) is False
    # dev-2's directive is untouched
    assert s.pending_report("dev-2", 1002.0) is True


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
    assert stored[0]["peers"] == [{"ip": "10.0.0.7", "rx_bytes": 123456,
                                   "tx_bytes": 0, "avg_bps": 10288}]
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


def test_post_body_over_cap_is_413(tmp_path):
    """Content-Length over 64 KiB -> 413 on ANY POST route (global do_POST
    cap), nothing stored."""
    srv, port = _serve(tmp_path, "tok", device_id="sw-9")
    big = b"x" * (65536 + 1)
    try:
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok", big)
        assert status == 413
        assert resp == {"error": "body too large"}
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
        assert resp == {"error": "body too large"}
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
        assert resp == {"error": "bad request body"}
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
        assert resp == {"error": "bad report"}
        # a normal full-shape report is well under the bound and still stores.
        status, resp = _post(port, "/v1/devices/sw-9/telemetry", "tok",
                             json.dumps(_report()).encode())
        assert status == 200 and resp == {"ok": True}
    finally:
        srv.shutdown()
    stored = catalog.CatalogStore(str(tmp_path)).get_telemetry("sw-9")
    assert len(stored) == 1              # only the normal report was stored


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
