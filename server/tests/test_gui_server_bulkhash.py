# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""HTTP-level tests for the KGV / Cisco Bulk Hash reconciler's Task 4
routes (server/gui_server.py): GET/POST /api/settings/image-verification,
POST /api/image-verification/refresh, POST /api/image-verification/offline,
and POST /api/images/<id>/release-quarantine, plus the images-list row
projection (_image_view).

Real HTTP against a real gui_server instance throughout (the
test_gui_server.py idiom); fixture-tar builders replicate
test_bulkhash_refresh.py's own helpers rather than importing them -- this
repo's test files do not import helpers from one another (see that file's
module docstring).

Two things this file deliberately does NOT attempt, and why:

* A true end-to-end "ok" outcome for /refresh or /offline (real
  fetch/verify against the pinned Cisco certificate) is not reachable from
  a test: run_refresh()'s `cert_path`/`feed_url` default to the module-
  level FEED_URL/_CERT_PATH constants, bound once at function-definition
  time (ordinary Python default-argument semantics), and neither Task 4's
  routes nor this test file may reach for the underscored `_fetch_fn` /
  `_verify_fn` / ... test seams (out of scope per the brief -- those exist
  for test_bulkhash_refresh.py's own pipeline tests). The "ok" tests below
  instead monkeypatch bulkhash_refresh.run_refresh itself (a full,
  ordinary dependency substitution at the module boundary -- NOT one of
  the underscored seams) to verify the ROUTE's own contract: it calls
  run_refresh with the right arguments and relays its result verbatim.
  Real pipeline correctness (fetch/verify/parse/reconcile/apply) is
  test_bulkhash_refresh.py's job, already covered there.
* The offline "unsigned tar" fail case, by contrast, needs no fetch and no
  signature ever matches an absent one -- verify_tar rejects a missing
  .signature member before it ever reads cert_path's key material -- so
  that one test drives the REAL run_refresh/bulkhash pipeline hermetically,
  with a throwaway-signed (or unsigned) fixture tar, same as
  test_bulkhash_refresh.py."""
import io
import json
import os
import socket
import subprocess
import tarfile
import threading

import pytest

import bulkhash_refresh
import catalog as catalog_mod
import gui_app
import gui_creds
import gui_fleet
import gui_images
import gui_server

# ---------------------------------------------------------------------------
# Fixture-tar builders (replicated from test_bulkhash_refresh.py -- see the
# module docstring above)
# ---------------------------------------------------------------------------

CSV_HEADER = "FILE_NAME,MD5_CHECKSUM,SHA512_CHECKSUM,PUBLISH_DATE,DEFERRAL_STATUS,IMAGE_SIZE"


def _throwaway_keypair(dirpath, cn):
    key = os.path.join(str(dirpath), cn + "-key.pem")
    crt = os.path.join(str(dirpath), cn + "-crt.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-keyout", key, "-out", crt, "-subj", "/CN=" + cn],
        check=True, capture_output=True)
    return crt, key


def _build_tar(tar_path, members):
    with tarfile.open(tar_path, mode="w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _csv_bytes(rows_text):
    return (CSV_HEADER + "\r\n" + rows_text).encode("utf-8")


def _unsigned_fixture(tmp_path, csv_text, name="unsigned",
                      csv_name="Cisco_BulkHash_CSV.csv",
                      dirprefix="Cisco_BulkHash_CSV.csv_2026.08.29.08.29.48"):
    """A tar with NO .signature member -- verify_tar must reject it before
    ever reading cert_path's key material, so this is reachable WITHOUT the
    real pinned Cisco certificate or any of run_refresh's test seams."""
    tar_path = os.path.join(str(tmp_path), name + ".tar")
    csv_bytes = _csv_bytes(csv_text)
    _build_tar(tar_path, [
        (dirprefix + "/", b""),
        ("%s/%s" % (dirprefix, csv_name), csv_bytes),
    ])
    return tar_path


REAL_ROW = (
    "image1.bin,D949B99A104B23B2129718220C78F28E," + ("aa" * 64).upper() +
    ",August 03 2016 00:00:00 PDT-0700,,5\r\n")


# ---------------------------------------------------------------------------
# Server bootstrap + small HTTP helpers (test_gui_server.py idiom,
# replicated rather than imported)
# ---------------------------------------------------------------------------

def _serve(tmp_path, audited=True, seeder_add_fn=None):
    """Boot gui_server wired the way main() wires it for these routes: a
    real CatalogStore with audit_path SET (unlike test_gui_server.py's
    _serve_full_audit, whose CatalogStore is NOT audit-wired -- catalog.py
    methods like release_quarantine() write their own audit entries
    straight to catalog.audit_path, so a test asserting on those needs the
    catalog instance itself wired, not just the server's audit_path kwarg).
    Returns (host, port, (app, fleet, creds, cat), state_dir, audit_path,
    stop_fn). Callers must monkeypatch IRIS_STATE to state_dir themselves --
    every settings-route test in test_gui_server.py already follows this
    convention, since these routes read os.environ per-request."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    state_dir = str(tmp_path / "state")
    audit_path = str(tmp_path / "audit.jsonl") if audited else None
    images = gui_images.ImageService(
        state_dir, str(tmp_path / "imgs"),
        tracker_url_fn=lambda: "http://t/announce?key=k",
        import_root=str(tmp_path / "opt-images"))
    fleet = gui_fleet.FleetStore(state_dir)
    creds = gui_creds.CredentialStore(secrets_path)
    cat = catalog_mod.CatalogStore(
        state_dir, audit_path=audit_path,
        seeder_remove_fn=lambda info_hash: None,
        seeder_add_fn=seeder_add_fn)
    srv = gui_server.make_server(
        "127.0.0.1", 0, app, images, fleet, creds, cat,
        audit_path=audit_path, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return ("127.0.0.1", port, (app, fleet, creds, cat), state_dir,
            audit_path, srv.shutdown)


def _req(host, port, method, path, body=None, headers=None, raw=None):
    import http.client
    c = http.client.HTTPConnection(host, port, timeout=5)
    hdrs = dict(headers or {})
    if raw is not None:
        payload = raw
    elif body is not None:
        payload = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    else:
        payload = None
    c.request(method, path, body=payload, headers=hdrs)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, dict(r.getheaders()), data


def _auth(host, port):
    s, h, b = _req(host, port, "POST", "/api/login",
                   {"username": "admin", "password": "pw"})
    assert s == 200
    return h["Set-Cookie"].split(";")[0], json.loads(b)["csrf"]


def _read_audit_lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _entry(image_id="img1", filename="img1.bin", sha512="aa" * 64, **over):
    e = {"id": image_id, "filename": filename, "size": 5,
        "sha256": "ab" * 32, "sha512": sha512,
        "cisco_signature_verified": False, "info_hash_hex": "cc" * 20,
        "published_at": 111}
    e.update(over)
    return e


# ---------------------------------------------------------------------------
# Auth gate: every new route requires a session (and POSTs require CSRF)
# ---------------------------------------------------------------------------

def test_all_new_routes_reject_unauthenticated_requests(tmp_path):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry())
        assert _req(host, port, "GET",
                    "/api/settings/image-verification")[0] == 401
        assert _req(host, port, "POST", "/api/settings/image-verification",
                    {"mode": "off", "hour_utc": 0})[0] == 401
        assert _req(host, port, "POST",
                    "/api/image-verification/refresh")[0] == 401
        assert _req(host, port, "POST", "/api/image-verification/offline",
                    raw=b"x")[0] == 401
        assert _req(host, port, "POST",
                    "/api/images/img1/release-quarantine",
                    {"override": False})[0] == 401
    finally:
        stop()


def test_settings_post_requires_csrf(tmp_path):
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    try:
        cookie, _csrf = _auth(host, port)
        status, _, _ = _req(host, port, "POST",
                            "/api/settings/image-verification",
                            {"mode": "off", "hour_utc": 0},
                            headers={"Cookie": cookie})
        assert status == 403
    finally:
        stop()


# ---------------------------------------------------------------------------
# GET/POST /api/settings/image-verification
# ---------------------------------------------------------------------------

def test_settings_get_defaults_when_unconfigured(tmp_path, monkeypatch):
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    try:
        cookie, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET",
                               "/api/settings/image-verification",
                               headers={"Cookie": cookie})
        assert status == 200
        assert json.loads(body) == {
            "mode": "off", "hour_utc": 0,
            "last_run": {"at": None, "source": None, "outcome": None,
                        "matched": None, "mismatched": None,
                        "not_in_feed": None}}
    finally:
        stop()


def test_settings_post_round_trip_then_get_reflects_it(tmp_path, monkeypatch):
    host, port, _ctx, state_dir, audit_path, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/settings/image-verification",
                               {"mode": "daily", "hour_utc": 3}, headers)
        assert status == 200
        assert json.loads(body)["mode"] == "daily"
        assert json.loads(body)["hour_utc"] == 3
        status, _, body = _req(host, port, "GET",
                               "/api/settings/image-verification",
                               headers={"Cookie": cookie})
        assert status == 200
        got = json.loads(body)
        assert got["mode"] == "daily" and got["hour_utc"] == 3
        # hyphenated, matching its siblings ca-trust-config/bulkhash-refresh
        events = [e for e in _read_audit_lines(audit_path)
                 if e.get("event") == "bulkhash-schedule-config"]
        assert len(events) == 1
        assert events[0]["actor"] == "console:admin"
    finally:
        stop()


def test_settings_post_preserves_last_run_across_edits(tmp_path, monkeypatch):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    try:
        spath = bulkhash_refresh.settings_path(state_dir)
        bulkhash_refresh.write_settings(
            spath, "off", 0,
            {"at": 500, "source": "scheduled", "outcome": "ok",
             "matched": 2, "mismatched": 0, "not_in_feed": 1})
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/settings/image-verification",
                               {"mode": "weekly", "hour_utc": 9}, headers)
        assert status == 200
        got = json.loads(body)
        assert got["mode"] == "weekly" and got["hour_utc"] == 9
        assert got["last_run"] == {
            "at": 500, "source": "scheduled", "outcome": "ok",
            "matched": 2, "mismatched": 0, "not_in_feed": 1}
    finally:
        stop()


@pytest.mark.parametrize("body,label", [
    ({"mode": "sometimes", "hour_utc": 0}, "bad-mode"),
    ({"mode": "daily", "hour_utc": 24}, "hour-24"),
    ({"mode": "daily", "hour_utc": -1}, "hour-negative"),
    ({"mode": "daily", "hour_utc": "5"}, "hour-string"),
    ({"mode": "daily", "hour_utc": True}, "hour-bool"),
    ({"hour_utc": 5}, "missing-mode"),
])
def test_settings_post_rejects_bad_input(tmp_path, monkeypatch, body, label):
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body_out = _req(host, port, "POST",
                                   "/api/settings/image-verification",
                                   body, headers)
        assert status == 400, label
        assert "error" in json.loads(body_out)
        # rejected input must never be persisted
        got = bulkhash_refresh.read_settings(
            bulkhash_refresh.settings_path(state_dir))
        assert got["mode"] == "off"
    finally:
        stop()


def test_settings_post_rejects_malformed_json(tmp_path, monkeypatch):
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf,
                  "Content-Type": "application/json"}
        status, _, body = _req(host, port, "POST",
                               "/api/settings/image-verification",
                               headers=headers, raw=b"{not json")
        assert status == 400
        assert json.loads(body)["error"] == "bad json"
    finally:
        stop()


# ---------------------------------------------------------------------------
# POST /api/image-verification/refresh
# ---------------------------------------------------------------------------

def test_refresh_ok_delegates_and_returns_200(tmp_path, monkeypatch):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    calls = []

    def fake_run_refresh(source, sdir, catalog, tar_path=None,
                         audit_fn=None):
        calls.append((source, sdir, catalog is cat, tar_path,
                     audit_fn is not None))
        return {"outcome": "ok", "matched": 3, "mismatched": 1,
               "not_in_feed": 2}

    monkeypatch.setattr(bulkhash_refresh, "run_refresh", fake_run_refresh)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/image-verification/refresh",
                               headers=headers)
        assert status == 200
        assert json.loads(body) == {"outcome": "ok", "matched": 3,
                                    "mismatched": 1, "not_in_feed": 2}
        assert calls == [("manual", state_dir, True, None, True)]
    finally:
        stop()


def test_refresh_fail_maps_to_502(tmp_path, monkeypatch):
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    monkeypatch.setattr(
        bulkhash_refresh, "run_refresh",
        lambda *a, **k: {"outcome": "fail", "detail": "boom",
                         "matched": None, "mismatched": None,
                         "not_in_feed": None})
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/image-verification/refresh",
                               headers=headers)
        assert status == 502
        assert json.loads(body)["outcome"] == "fail"
        assert json.loads(body)["detail"] == "boom"
    finally:
        stop()


def test_refresh_already_running_maps_to_409(tmp_path, monkeypatch):
    """No fake needed: the process-wide single-flight flag is real module
    state (bulkhash_refresh._RUNNING) -- forcing it True (and restoring it
    via monkeypatch) exercises the REAL run_refresh's own short-circuit,
    without any network fetch or test seam."""
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    monkeypatch.setattr(bulkhash_refresh, "_RUNNING", True)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/image-verification/refresh",
                               headers=headers)
        assert status == 409
        assert json.loads(body) == {"outcome": "already_running"}
    finally:
        stop()


def test_refresh_audit_uses_the_session_actor_not_system(tmp_path, monkeypatch):
    """run_refresh calls its audit_fn with the event fully keyword-formed,
    actor="system" included (bulkhash_refresh.py:363-365/:380-384) -- the
    route must relay every other field verbatim but override actor to the
    console session that triggered THIS run, the same pattern
    /api/settings/audit-export/run and /api/settings/ca-trust/refresh use.
    fake_run_refresh calls audit_fn exactly the way the real run_refresh
    does (proving the WRAPPER, independent of whether the pipeline
    underneath is real or faked -- real pipeline correctness is
    test_bulkhash_refresh.py's job)."""
    host, port, _ctx, state_dir, audit_path, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)

    def fake_run_refresh(source, sdir, catalog, tar_path=None,
                         audit_fn=None):
        audit_fn(event="bulkhash-refresh", category="settings",
                 action="refresh", target="bulkhash", actor="system",
                 result="ok", detail="matched=1 mismatched=0 not_in_feed=0")
        return {"outcome": "ok", "matched": 1, "mismatched": 0,
               "not_in_feed": 0}

    monkeypatch.setattr(bulkhash_refresh, "run_refresh", fake_run_refresh)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, _ = _req(host, port, "POST",
                            "/api/image-verification/refresh",
                            headers=headers)
        assert status == 200
        events = [e for e in _read_audit_lines(audit_path)
                 if e.get("event") == "bulkhash-refresh"]
        assert len(events) == 1
        assert events[0]["actor"] == "console:admin"
        assert events[0]["result"] == "ok"
        assert events[0]["detail"] == "matched=1 mismatched=0 not_in_feed=0"
    finally:
        stop()


def test_scheduled_run_refresh_still_audits_as_system(tmp_path):
    """Regression guard for the actor-override fix above: this drives the
    REAL bulkhash_refresh.run_refresh (hermetic -- the unsigned-tar fail
    path needs no network and no real Cisco cert) with a PLAIN,
    non-wrapping audit_fn -- exactly how bulkhash_refresh_loop/main() wires
    scheduled runs via _bg_audit -- and confirms actor is still "system".
    gui_server.py's routes are not exercised here at all; this proves the
    HTTP-layer wrapping in the routes above cannot leak into (and Task 3's
    bulkhash_refresh.py was not touched to make) every OTHER caller of
    run_refresh keep seeing the source-agnostic "system" default."""
    events = []

    def plain_audit(**kw):
        events.append(kw)

    state_dir = str(tmp_path / "state")
    cat = catalog_mod.CatalogStore(state_dir)
    tar_path = _unsigned_fixture(tmp_path, REAL_ROW)
    result = bulkhash_refresh.run_refresh(
        "scheduled", state_dir, cat, tar_path=tar_path,
        audit_fn=plain_audit)
    assert result["outcome"] == "fail"
    assert len(events) == 1
    assert events[0]["actor"] == "system"


# ---------------------------------------------------------------------------
# POST /api/image-verification/offline
# ---------------------------------------------------------------------------

def test_offline_ok_streams_body_to_a_temp_file_and_delegates(
        tmp_path, monkeypatch):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    payload = b"PRETEND-TAR-BYTES" * 100
    seen = {}

    def fake_run_refresh(source, sdir, catalog, tar_path=None,
                         audit_fn=None):
        with open(tar_path, "rb") as f:
            seen["bytes"] = f.read()
        seen["path"] = tar_path
        seen["source"] = source
        seen["catalog_is_real"] = catalog is cat
        return {"outcome": "ok", "matched": 1, "mismatched": 0,
               "not_in_feed": 0}

    monkeypatch.setattr(bulkhash_refresh, "run_refresh", fake_run_refresh)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/image-verification/offline",
                               headers=headers, raw=payload)
        assert status == 200
        assert json.loads(body) == {"outcome": "ok", "matched": 1,
                                    "mismatched": 0, "not_in_feed": 0}
        assert seen["source"] == "offline"
        assert seen["bytes"] == payload
        assert seen["catalog_is_real"] is True
        # the private temp dir is cleaned up once the request completes
        assert not os.path.exists(seen["path"])
        assert not os.path.exists(os.path.dirname(seen["path"]))
    finally:
        stop()


def test_offline_audit_uses_the_session_actor_not_system(tmp_path, monkeypatch):
    """Same fix as the /refresh route's own actor-override test above,
    exercised through /offline's separate _handle_offline_refresh code
    path."""
    host, port, _ctx, state_dir, audit_path, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)

    def fake_run_refresh(source, sdir, catalog, tar_path=None,
                         audit_fn=None):
        audit_fn(event="bulkhash-refresh", category="settings",
                 action="refresh", target="bulkhash", actor="system",
                 result="ok", detail="matched=0 mismatched=0 not_in_feed=0")
        return {"outcome": "ok", "matched": 0, "mismatched": 0,
               "not_in_feed": 0}

    monkeypatch.setattr(bulkhash_refresh, "run_refresh", fake_run_refresh)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, _ = _req(host, port, "POST",
                            "/api/image-verification/offline",
                            headers=headers, raw=b"x")
        assert status == 200
        events = [e for e in _read_audit_lines(audit_path)
                 if e.get("event") == "bulkhash-refresh"]
        assert len(events) == 1
        assert events[0]["actor"] == "console:admin"
    finally:
        stop()


def test_offline_rejects_missing_csrf_403(tmp_path, monkeypatch):
    """/offline self-gates via _require_session_csrf() BEFORE do_POST's
    shared "every other POST requires a live session + CSRF" gate ever
    runs (it is diverted out of do_POST entirely, ahead of that gate, so
    it can stream the body instead of the generic eager-read) -- so its
    own CSRF check is unique code, not exercised by the shared-gate test
    for the OTHER routes."""
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    try:
        cookie, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "POST",
                               "/api/image-verification/offline",
                               headers={"Cookie": cookie}, raw=b"x")
        assert status == 403
        assert "error" in json.loads(body)
    finally:
        stop()


def test_offline_oversize_reject_is_audited(tmp_path, monkeypatch):
    """Mirrors the PUT /api/images/upload/<name> precedent's own oversize
    rejection audit: rejected before run_refresh is ever reached, so
    without this the attempt would leave no trail at all."""
    host, port, _ctx, state_dir, audit_path, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    try:
        cookie, csrf = _auth(host, port)
        s = socket.create_connection((host, port), timeout=5)
        head = ("POST /api/image-verification/offline HTTP/1.0\r\n"
                "Host: x\r\nCookie: %s\r\nX-CSRF-Token: %s\r\n"
                "Content-Type: application/octet-stream\r\n"
                "Content-Length: 999999999\r\n\r\n" % (cookie, csrf)).encode()
        s.sendall(head + b"not-really-that-many-bytes")
        s.shutdown(socket.SHUT_WR)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        assert b" 413 " in resp.split(b"\r\n", 1)[0]
        events = [e for e in _read_audit_lines(audit_path)
                 if e.get("event") == "bulkhash-offline-upload"]
        assert len(events) == 1
        assert events[0]["result"] == "fail"
        assert events[0]["actor"] == "console:admin"
        assert "oversized" in events[0]["detail"]
    finally:
        stop()


def test_offline_unsigned_tar_fails_and_leaves_catalog_untouched(
        tmp_path, monkeypatch):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    cat.save_image(_entry(sha512="aa" * 64))
    tar_path = _unsigned_fixture(tmp_path, REAL_ROW)
    with open(tar_path, "rb") as f:
        payload = f.read()
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/image-verification/offline",
                               headers=headers, raw=payload)
        assert status == 502
        result = json.loads(body)
        assert result["outcome"] == "fail"
        assert result["matched"] is None
        # catalog genuinely untouched
        entry = cat.get_image("img1")
        assert "hash_verification" not in entry
        assert not entry.get("quarantined")
        # and the failure landed in last_run
        settings = bulkhash_refresh.read_settings(
            bulkhash_refresh.settings_path(state_dir))
        assert settings["last_run"]["source"] == "offline"
        assert settings["last_run"]["outcome"].startswith("fail")
    finally:
        stop()


def test_offline_accepts_a_body_bigger_than_the_generic_json_cap(
        tmp_path, monkeypatch):
    """The generic do_POST body cap (_MAX_BODY, 64 KiB) is NOT what guards
    this route -- a body comfortably over 64 KiB but well under
    _MAX_OFFLINE_TAR must still be accepted (and reach run_refresh), or
    this route would silently be no more permissive than any ordinary JSON
    settings POST despite the whole point of a separate, much larger cap."""
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    payload = b"x" * (200 * 1024)   # 200 KiB: > _MAX_BODY, << _MAX_OFFLINE_TAR
    seen = {}
    monkeypatch.setattr(
        bulkhash_refresh, "run_refresh",
        lambda source, sdir, catalog, tar_path=None, audit_fn=None:
            seen.update(n=os.path.getsize(tar_path)) or
            {"outcome": "ok", "matched": 0, "mismatched": 0,
             "not_in_feed": 0})
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/image-verification/offline",
                               headers=headers, raw=payload)
        assert status == 200
        assert seen["n"] == len(payload)
    finally:
        stop()


def test_offline_rejects_oversized_body_413(tmp_path, monkeypatch):
    """Mirrors test_gui_server.py's test_csv_import_rejects_oversized: a
    raw socket declares a Content-Length far above _MAX_OFFLINE_TAR and
    sends only a few bytes -- the route must reject on the header alone,
    never attempting to read (let alone buffer) that many bytes."""
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    try:
        cookie, csrf = _auth(host, port)
        s = socket.create_connection((host, port), timeout=5)
        head = ("POST /api/image-verification/offline HTTP/1.0\r\n"
                "Host: x\r\nCookie: %s\r\nX-CSRF-Token: %s\r\n"
                "Content-Type: application/octet-stream\r\n"
                "Content-Length: 999999999\r\n\r\n" % (cookie, csrf)).encode()
        s.sendall(head + b"not-really-that-many-bytes")
        s.shutdown(socket.SHUT_WR)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        assert b" 413 " in resp.split(b"\r\n", 1)[0]
    finally:
        stop()


def test_offline_rejects_empty_body_413(tmp_path, monkeypatch):
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    monkeypatch.setenv("IRIS_STATE", state_dir)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/image-verification/offline",
                               headers=headers, raw=b"")
        assert status == 413
        assert "error" in json.loads(body)
    finally:
        stop()


# ---------------------------------------------------------------------------
# POST /api/images/<id>/release-quarantine
# ---------------------------------------------------------------------------

def _quarantine(cat, image_id="img1", feed_sha512="bb" * 64, source="scheduled"):
    cat.apply_hash_verification(
        {image_id: {"state": "mismatch", "feed_sha512": feed_sha512,
                    "publish_date": "2026-08-01", "deferral": False}},
        source=source, now=1000)


def test_release_quarantine_clean_release_200_and_audited(tmp_path):
    host, port, (_, _, _, cat), state_dir, audit_path, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry(sha512="bb" * 64))   # already-corrected sha512
        _quarantine(cat, feed_sha512="bb" * 64)
        assert cat.get_image("img1")["quarantined"] is True
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/images/img1/release-quarantine",
                               {"override": False}, headers)
        assert status == 200
        result = json.loads(body)
        # seeding_resumed: the release re-adds the torrent to the seeder
        # (unwired here, so vacuously True) instead of leaving no origin.
        assert result == {"released": True, "override": False,
                          "state": "verified", "seeding_resumed": True}
        assert cat.get_image("img1")["quarantined"] is False
        releases = [e for e in _read_audit_lines(audit_path)
                   if e.get("event") == "image_quarantine_release"]
        assert len(releases) == 1
        assert releases[0]["action"] == "release"
        assert releases[0]["actor"] == "console:admin"
        assert releases[0]["target"] == "img1"
    finally:
        stop()


def test_release_quarantine_still_mismatched_without_override_409(tmp_path):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry(sha512="aa" * 64))   # never corrected
        _quarantine(cat, feed_sha512="bb" * 64)
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/images/img1/release-quarantine",
                               {"override": False}, headers)
        assert status == 409
        result = json.loads(body)
        assert result["error"] == "quarantine_still_mismatched"
        assert result["image_id"] == "img1"
        assert result["verdict"]["state"] == "mismatch"
        assert cat.get_image("img1")["quarantined"] is True   # unchanged
    finally:
        stop()


def test_release_quarantine_override_correct_confirm_text_200_and_audited(
        tmp_path):
    host, port, (_, _, _, cat), state_dir, audit_path, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry(sha512="aa" * 64))
        _quarantine(cat, feed_sha512="bb" * 64)
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/images/img1/release-quarantine",
                               {"override": True, "confirm_text": "img1.bin"},
                               headers)
        assert status == 200
        result = json.loads(body)
        assert result == {"released": True, "override": True,
                          "state": "mismatch",    # truthful: still unresolved
                          "seeding_resumed": True}
        assert cat.get_image("img1")["quarantined"] is False
        releases = [e for e in _read_audit_lines(audit_path)
                   if e.get("event") == "image_quarantine_release"]
        assert len(releases) == 1
        assert releases[0]["action"] == "release_override"
        assert releases[0]["actor"] == "console:admin"
    finally:
        stop()


def test_release_quarantine_override_wrong_confirm_text_400(tmp_path):
    host, port, (_, _, _, cat), state_dir, audit_path, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry(sha512="aa" * 64))
        _quarantine(cat, feed_sha512="bb" * 64)
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/images/img1/release-quarantine",
                               {"override": True,
                                "confirm_text": "not-the-filename"},
                               headers)
        assert status == 400
        assert "error" in json.loads(body)
        # nothing touched: still quarantined, and no release audit fired
        assert cat.get_image("img1")["quarantined"] is True
        releases = [e for e in _read_audit_lines(audit_path)
                   if e.get("event") == "image_quarantine_release"]
        assert releases == []
    finally:
        stop()


def test_release_quarantine_unknown_image_404(tmp_path):
    host, port, _ctx, state_dir, _audit, stop = _serve(tmp_path)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/images/nope/release-quarantine",
                               {"override": False}, headers)
        assert status == 404
        # the route-specific message, not the generic do_POST 404 fallback
        # every unmatched path also returns
        assert json.loads(body)["error"] == "no such image"
    finally:
        stop()


def test_release_quarantine_toctou_delete_returns_404(tmp_path, monkeypatch):
    """catalog.release_quarantine() raises KeyError when the image is gone
    (catalog.py:1126-1127) -- reachable in production as a genuine TOCTOU
    between this route's own get_image() pre-check and the call (another
    request deletes the image in between). Simulated directly rather than
    racing real threads: the route must answer a clean 404, not let the
    exception escape and drop the connection."""
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry())
        _quarantine(cat, feed_sha512="bb" * 64)

        def _raise_keyerror(image_id, actor, override=False):
            raise KeyError(image_id)

        monkeypatch.setattr(cat, "release_quarantine", _raise_keyerror)
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/images/img1/release-quarantine",
                               {"override": False}, headers)
        assert status == 404
        assert json.loads(body)["error"] == "no such image"
    finally:
        stop()


def test_release_quarantine_not_currently_quarantined_400(tmp_path):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry())   # never quarantined
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/images/img1/release-quarantine",
                               {"override": False}, headers)
        assert status == 400
    finally:
        stop()


@pytest.mark.parametrize("body,label", [
    ({"override": "yes"}, "override-not-bool"),
    ({"override": True, "confirm_text": 123}, "confirm-text-not-string"),
])
def test_release_quarantine_rejects_bad_input_shapes(tmp_path, body, label):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry())
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body_out = _req(host, port, "POST",
                                   "/api/images/img1/release-quarantine",
                                   body, headers)
        assert status == 400, label
    finally:
        stop()


# ---------------------------------------------------------------------------
# Images list row projection (_image_view)
# ---------------------------------------------------------------------------

def test_images_list_rows_carry_verdict_and_quarantined_bool(tmp_path):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry(sha512="aa" * 64))
        _quarantine(cat, feed_sha512="bb" * 64)
        cookie, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/images",
                               headers={"Cookie": cookie})
        assert status == 200
        row = json.loads(body)["images"][0]
        assert row["quarantined"] is True
        assert row["hash_verification"] == {
            "state": "mismatch", "checked_at": 1000,
            "feed_published_at": "2026-08-01", "source": "scheduled",
            "deferral": False}
        # existing fields untouched (additive projection)
        assert row["id"] == "img1" and row["filename"] == "img1.bin"
    finally:
        stop()


def test_images_list_rows_default_for_a_never_checked_image(tmp_path):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry())
        cookie, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/images",
                               headers={"Cookie": cookie})
        row = json.loads(body)["images"][0]
        assert row["quarantined"] is False
        assert row["hash_verification"] is None
    finally:
        stop()


def test_images_list_rows_never_carry_internal_bookkeeping_fields(tmp_path):
    host, port, (_, _, _, cat), state_dir, _audit, stop = _serve(tmp_path)
    try:
        cat.save_image(_entry(sha512="bb" * 64))   # already matches
        _quarantine(cat, feed_sha512="bb" * 64)
        cat.release_quarantine("img1", actor="console:admin")
        # release_quarantine's own write leaves quarantine_actions_complete
        # on the raw entry -- confirm the row projection strips it (and its
        # sibling) even though the raw catalog entry still carries them.
        raw = cat.get_image("img1")
        assert "quarantine_actions_complete" in raw
        cookie, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/images",
                               headers={"Cookie": cookie})
        row = json.loads(body)["images"][0]
        assert "quarantine_actions_complete" not in row
        assert "quarantine_override_sha512" not in row
    finally:
        stop()


def test_release_quarantine_route_resumes_origin_seeding(tmp_path):
    """The quarantine force-removed the torrent from aria2; the release must
    put it back (from the recorded source_dir, re-synced to the current
    credential by publish.resume_torrent_rpc in production) and say so."""
    added = []
    host, port, (_, _, _, cat), state_dir, audit_path, stop = _serve(
        tmp_path, seeder_add_fn=lambda *a: added.append(a))
    try:
        src = tmp_path / "images"; src.mkdir()
        cat.save_image(_entry(sha512="bb" * 64, source_dir=str(src),
                              info_hash_hex="cc" * 20))
        (tmp_path / "state" / "torrents" / "img1.torrent").write_bytes(b"d")
        _quarantine(cat, feed_sha512="bb" * 64)
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(host, port, "POST",
                               "/api/images/img1/release-quarantine",
                               {"override": False}, headers)
        assert status == 200
        assert json.loads(body)["seeding_resumed"] is True
        assert added == [(cat.torrent_path("img1"), str(src), "cc" * 20)]
        seed = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "image_quarantine_release_seeding"]
        assert len(seed) == 1 and seed[0]["result"] == "ok"
        assert seed[0]["actor"] == "console:admin"
    finally:
        stop()
