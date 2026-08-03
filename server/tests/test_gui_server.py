# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import os

import gui_server


def test_webroot_assets_exist():
    for name in ("login.html", "index.html", "styles.css", "login.js", "app.js",
                 "setup.html", "setup.js"):
        assert os.path.isfile(os.path.join(gui_server.WEBROOT, name)), name


def test_csv_download_buttons_and_multiselect_onboard_wired():
    """Source guards for two console fixes:
    (1) Export/Example CSV must be plain <button>s, not <a download> anchors —
        Chrome blocks download-attribute navigations over connections with
        certificate errors (self-signed labs), which made the old anchors dead.
    (2) The devices table supports selecting multiple rows and bulk-onboarding
        them via a shared 'Onboard selected' button."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert '<button class="btn ghost" id="export-csv">' in html
    assert '<button class="btn ghost" id="example-csv">' in html
    assert 'id="export-csv" href' not in html
    assert 'id="example-csv" href' not in html
    assert 'download' not in html.split('id="example-csv"')[1].split('>')[0]
    assert 'id="onboard-selected"' in html
    assert 'id="mark-all"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "function downloadCsv(" in js
    assert "'export-csv'" in js and "'example-csv'" in js
    assert "#dev-rows .cred" in js
    assert "/credential'" in js or '/credential"' in js
    assert "onboard-selected" in js
    assert "#dev-rows .mark" in js


def test_import_from_disk_panel_wired():
    """Source guards for importing images already on disk: an Images-view panel
    fed by GET /api/images/importable, a per-row import posting the candidate's
    exact path with the CSRF header, and reuse of the existing publish poll."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="import-panel"' in html
    assert 'id="import-rows"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'/api/images/importable'" in js or '"/api/images/importable"' in js
    assert "/api/images/import'" in js or '/api/images/import"' in js
    assert "#import-rows .do-import" in js
    # the exact discovered path is echoed back — the server authorizes on
    # candidate identity, so the client must not reconstruct or edit it
    assert "data-path" in js
    # the import POST carries the CSRF header, like every other mutating call
    post_call = js.split("/api/images/import'")[1][:400]
    assert "csrfHdr(" in post_call
    # publish progress reuses the upload path's poller rather than a second one
    assert "pollJob((await res.json()).job_id)" in js
    # the panel stays hidden only when there is nothing to show at all
    assert "cands.length === 0 && skipped.length === 0" in js
    # the distinguishing path is rendered — two roots can hold one basename
    assert "esc(c.path)" in js
    # deleting a catalogued image makes its name importable again
    assert "refreshImages(); refreshImportable();" in js


def test_bulk_row_actions_wired():
    """Adopt/delete selected, a bulk credential assign, and a confirmation on
    every destructive delete (per-row included — it previously had none)."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    for el in ('id="adopt-selected"', 'id="delete-selected"',
               'id="cred-selected"', 'id="apply-cred-selected"'):
        assert el in html, el

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'adopt-selected'" in js and "'delete-selected'" in js
    assert "'apply-cred-selected'" in js
    assert "/adopt'" in js and "acknowledge_adopt: true" in js
    # bulk assign reuses the per-device credential route
    assert "'/credential'" in js or "+ '/credential'" in js
    # BOTH delete paths confirm first, via one shared warning
    assert "function delWarning(" in js
    assert js.count("confirm(delWarning(") == 2
    # the warning must say deletion is not an undeploy — the dangerous part
    assert "does NOT " in js and "undeploy" in js
    # creating or deleting a profile re-renders the device rows, so a device
    # imported before any profile existed becomes assignable immediately
    assert js.count("renderCreds(); refreshDevices();") == 2
    assert "function syncCredSelected(" in js


def test_all_selected_actions_share_one_busy_lock():
    """Every selected-action must hold the same lock. Onboard/undeploy used to
    guard only each other, so a delete could remove inventory out from under a
    starting onboard batch."""
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "var BULK_BTNS = [" in js
    for el in ("onboard-selected", "undeploy-selected", "adopt-selected",
               "delete-selected", "apply-cred-selected"):
        block = js.split("var BULK_BTNS = [")[1].split("]")[0]
        assert el in block, "%s is not covered by the bulk busy lock" % el
    # every action claims the lock rather than reading another button's state
    assert js.count("claimSelection()") == 5
    assert "onBtn.disabled" not in js and "unBtn.disabled" not in js
    # a declined confirmation must release the lock, not wedge the toolbar
    assert js.count("setBulkBusy(false); return;") >= 2


def test_batch_onboard_panel_wired():
    """Source guards for parallel onboarding: bulk-onboard opens a batch panel
    with per-device live status (polled from GET /api/onboard/jobs), a per-row
    log action reusing the SSE log panel, and a cancel-queued control."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="batch-panel"' in html
    assert 'id="batch-rows"' in html
    assert 'id="batch-summary"' in html
    assert 'id="batch-cancel"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'/api/onboard/jobs'" in js or '"/api/onboard/jobs"' in js
    assert "/api/onboard/cancel-queued" in js
    assert "batch-rows" in js and "batch-cancel" in js
    # cancel is SCOPED to this panel's jobs — a bare cancel-all would nuke
    # other sessions' queued batches
    assert "job_ids: Object.keys(batchJobs)" in js
    # durations come from the server clock in the listing, not Date.now()
    assert "listing.now" in js
    # a reload re-attaches to still-running onboards instead of losing them
    assert "restoreBatch" in js


def test_undeploy_and_status_ui_wired():
    """Source guards for the console-feedback round: (1) an Undeploy-selected
    button that confirms before firing (destructive), (2) batch rows labeled
    with the job action, (3) queue position on queued rows, (4) a real
    deployed/staging indicator in the devices table."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="undeploy-selected"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "undeploy-selected" in js
    assert "startBatch('undeploy')" in js        # button fires the undeploy action
    assert "confirm(" in js                      # destructive: must confirm
    assert "j.action" in js                      # batch rows show the action
    assert "queuePos" in js                      # queued rows show #N in line
    assert "deployed" in js                      # devices tab staged indicator
    # job-aware statuses: post-onboard boot gap must not read as "not enrolled"
    assert "waiting for heartbeat" in js
    assert "onboarding…" in js and "undeploying…" in js
    assert "Waiting for heartbeat" in js         # overview card


def test_swarmmap_peer_resolution_wired():
    """Source guards for the swarm-map fixes: (1) peers deduped by ip so a
    re-announce or multi-image device can't render twice, (2) stored-report
    peer rows resolve device identity through the FLEET too (guest ips of
    devices that left the swarm), (3) the seed host row is labeled."""
    with open(gui_server.SWARMMAP_PATH) as f:
        src = f.read()
    assert "dedupePeers" in src
    assert "/api/devices" in src
    assert "seed server" in src
    # per-peer report columns carry ↓/↑ direction + a legend so received-vs-sent
    # asymmetry reads as expected, not as missing data
    assert "↓ received" in src and "↑ sent" in src
    assert "avg download" in src           # renamed from the ambiguous "avg throughput"
    assert "0 sent" in src                 # the legend that explains the asymmetry


def test_monitoring_timeline_wired():
    """Source guards for the Monitoring time-travel timeline:
    (1) index.html has the timeline container + range-preset chips.
    (2) app.js talks to /api/audit/histogram, builds bars from it, and the
        audit code has no inline on*= handlers (nonce-only CSP in console
        mode forbids them -- everything must go through addEventListener)."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="audit-timeline"' in html
    assert 'id="audit-range-chips"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "/api/audit/histogram" in js
    assert "addEventListener" in js
    # No inline event handler attributes anywhere in the audit/timeline code
    import re
    assert not re.search(r'\bon[a-z]+\s*=\s*["\']', js)


def test_monitoring_brush_wired():
    """Source guards for the draggable time brush (#19):
    (1) index.html carries the two-layer SVG (bars layer re-rendered per fetch,
        persistent brush overlay layer) plus the clear affordance.
    (2) app.js drives the brush with Pointer Events registered via
        addEventListener (nonce CSP forbids inline on*=), refetches the
        histogram with since_ts/until_ts on selection change, auto-rezooms
        via pickBucketCount, and clears the selection on Escape."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="audit-bars"' in html
    assert 'id="audit-brush"' in html
    assert 'id="audit-clear-selection"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    for ev in ("'pointerdown'", "'pointermove'", "'pointerup'",
               "'pointercancel'", "'lostpointercapture'"):
        assert "addEventListener(" + ev in js, ev
    assert "setPointerCapture" in js and "releasePointerCapture" in js
    # selection refetch uses the explicit-window contract + auto-rezoom
    assert "since_ts=" in js and "until_ts=" in js
    assert "function pickBucketCount(" in js
    assert "bucket_seconds" in js
    # selection lifecycle: commit/clear plumbing + Escape
    assert "function commitSelection(" in js and "function clearSelection(" in js
    assert "'Escape'" in js
    # bars render into their own layer so the brush overlay survives refetches
    assert "barsG.innerHTML" in js
    import re
    assert not re.search(r'\bon[a-z]+\s*=\s*["\']', js)


def test_audit_message_composer_wired():
    """Source guards for the operator-readable audit table (#19): 4-column
    layout (Time | Actor | Message | Result), a verb map covering console
    events plus the legacy broker shapes (mint/refresh/auth_fail carry
    device_id instead of actor/target/detail), colored category tags and
    result badges — everything composed through esc()."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert "<th>Time</th><th>Actor</th><th>Message</th><th>Result</th>" in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "function auditVerb(" in js
    # verb coverage: console + legacy broker events
    for ev in ("login_fail", "password_change_fail", "stage_host_clear",
               "device_csv_import", "device_credential_change",
               "onboard_finished", "credential_profile_delete",
               "image_publish_finished", "request_report",
               "mint", "refresh_fail", "auth_fail", "revoke"):
        assert ev in js, ev
    # legacy fallbacks: device_id fills actor/target; token rotation detail
    assert "'device:' + e.device_id" in js
    assert "e.secret_name" in js and "e.old_id" in js and "e.new_id" in js
    # badges + category tags come from esc()'d helpers, relative time on hover
    assert "badge-ok" in js and "badge-fail" in js
    assert "cat-tag" in js
    assert "function fmtAgo(" in js
    # empty non-append result shows the empty state AND resets the pager cursor
    assert "No events in this range." in js

    with open(os.path.join(gui_server.WEBROOT, "styles.css")) as f:
        css = f.read()
    assert ".badge-ok" in css and ".badge-fail" in css
    assert ".cat-token" in css and ".brush-handle" in css


def test_buttons_have_tactile_states():
    """Guard: console buttons must keep hover/active/focus-visible affordance
    (styles.css) so the press feels tactile instead of dead -- a future edit
    that strips these rules should fail this test, not just look worse."""
    with open(os.path.join(gui_server.WEBROOT, "styles.css")) as f:
        css = f.read()
    assert ':active' in css
    assert ':focus-visible' in css
    assert '.chip' in css


def test_device_form_has_model_field():
    """Source guard: the add-device form must expose a model input (used for
    platform auto-detection; see gui_onboard.resolve_platform) and post it."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="df-model"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "df-model" in js
    assert "model:" in js


def test_read_version_env_handling(monkeypatch):
    monkeypatch.setenv("IRIS_VERSION", " 2026.07.02\n")
    assert gui_server._read_version() == "2026.07.02"
    # compose passes "${IRIS_VERSION:-}": an EMPTY or blank env var must be
    # treated as unset (fall through to a VERSION file / "unknown") and must
    # NEVER surface as an empty version string on the Settings page.
    for blank in ("", "   ", "\n"):
        monkeypatch.setenv("IRIS_VERSION", blank)
        v = gui_server._read_version()
        assert v and v == v.strip()


import http.client
import json
import threading

import gui_app


def _serve(tmp_path):
    """Start gui_server on an ephemeral port (no TLS) with a preset admin.
    Returns (host, port, app, stop_fn)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return "127.0.0.1", port, app, srv.shutdown


def _req(host, port, method, path, body=None, headers=None, raw=None):
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


def test_login_bad_credentials_401(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, _, _ = _req(host, port, "POST", "/api/login",
                            {"username": "admin", "password": "nope"})
        assert status == 401
    finally:
        stop()


def test_login_sets_cookie_and_returns_csrf(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, headers, body = _req(host, port, "POST", "/api/login",
                                     {"username": "admin", "password": "pw"})
        assert status == 200
        assert "iris_sid=" in headers.get("Set-Cookie", "")
        assert "HttpOnly" in headers["Set-Cookie"]
        assert "SameSite=Strict" in headers["Set-Cookie"]
        assert "Secure" in headers["Set-Cookie"]
        assert "Path=/" in headers["Set-Cookie"]
        assert json.loads(body)["csrf"]
    finally:
        stop()


def test_session_requires_cookie(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, _, _ = _req(host, port, "GET", "/api/session")
        assert status == 401
    finally:
        stop()


def test_full_login_session_logout_flow(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, headers, body = _req(host, port, "POST", "/api/login",
                                     {"username": "admin", "password": "pw"})
        cookie = headers["Set-Cookie"].split(";")[0]           # iris_sid=...
        csrf = json.loads(body)["csrf"]

        status, _, body = _req(host, port, "GET", "/api/session",
                               headers={"Cookie": cookie})
        assert status == 200 and json.loads(body)["username"] == "admin"

        # logout without CSRF -> 403
        status, _, _ = _req(host, port, "POST", "/api/logout",
                            headers={"Cookie": cookie})
        assert status == 403

        # logout with CSRF -> 200, then session is dead
        status, _, _ = _req(host, port, "POST", "/api/logout",
                            headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        status, _, _ = _req(host, port, "GET", "/api/session",
                            headers={"Cookie": cookie})
        assert status == 401
    finally:
        stop()


def test_static_index_served_and_traversal_blocked(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, headers, body = _req(host, port, "GET", "/")
        assert status == 200 and b"Intelligent Release" in body
        assert "text/html" in headers.get("Content-Type", "")
        # SPA assets must revalidate so a redeploy is not masked by a stale
        # browser cache (else new UI like the Monitoring tab stays invisible).
        assert "no-cache" in headers.get("Cache-Control", "")
        status, _, _ = _req(host, port, "GET", "/../secrets.json")
        assert status == 404
    finally:
        stop()


def test_oversized_login_body_rejected(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        big = {"username": "admin", "password": "x" * 70000}
        status, _, _ = _req(host, port, "POST", "/api/login", big)
        assert status == 413
    finally:
        stop()


def test_logout_unknown_session_401(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, _, _ = _req(host, port, "POST", "/api/logout",
                            headers={"Cookie": "iris_sid=bogus"})
        assert status == 401
    finally:
        stop()


def test_login_non_ascii_username_401(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, _, _ = _req(host, port, "POST", "/api/login",
                            {"username": "admén", "password": "pw"})
        assert status == 401
    finally:
        stop()


def test_security_headers_present(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, headers, _ = _req(host, port, "GET", "/")
        assert status == 200
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    finally:
        stop()


import socket
import subprocess
import sys
import time

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_port(host, port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def test_module_run_as_script_actually_starts_the_server(tmp_path):
    # Regression: gui_server.py defines main() but must also call it when run
    # as `python3 gui_server.py` (the container entrypoint). Without the
    # `if __name__ == "__main__"` guard, the process exits immediately and
    # the container crash-loops.
    host = "127.0.0.1"
    port = _free_port()
    secrets_path = str(tmp_path / "secrets.json")
    env = dict(os.environ)
    env["IRIS_GUI_HOST"] = host
    env["IRIS_GUI_PORT"] = str(port)
    env["IRIS_SECRETS"] = secrets_path
    env["IRIS_STATE"] = str(tmp_path / "state")
    env["IRIS_IMAGES_DIR"] = str(tmp_path / "images")
    env["IRIS_CERT"] = "/nonexistent-so-plain-http"

    proc = subprocess.Popen(
        [sys.executable, "gui_server.py"],
        cwd=_SERVER_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert _wait_for_port(host, port, timeout=5.0), (
            "gui_server.py did not start listening on %s:%d -- process likely "
            "exited immediately (missing __main__ guard)" % (host, port)
        )
        status, _, _ = _req(host, port, "GET", "/api/session")
        assert status == 401
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


import gui_images


def _serve_with_images(tmp_path, publish_fn=None, tracker_url="http://t/announce?key=k",
                       import_root=None):
    """Start gui_server with a preset admin AND an ImageService (fake publish)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")

    def default_publish(image_path, store, url, **kw):
        entry = {"id": "img1", "filename": os.path.basename(image_path),
                 "size": os.path.getsize(image_path), "sha256": "ab" * 32,
                 "sha512": "cd" * 64, "cisco_signature_verified": False,
                 "info_hash_hex": "ee" * 20, "published_at": 1}
        store.save_image(entry)
        return entry

    images = gui_images.ImageService(
        str(tmp_path / "state"), str(tmp_path / "imgs"),
        tracker_url_fn=lambda: tracker_url,
        publish_fn=publish_fn or default_publish,
        import_root=import_root or str(tmp_path / "opt-images"))
    srv = gui_server.make_server("127.0.0.1", 0, app, images, certfile=None)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return "127.0.0.1", port, app, images, srv.shutdown


def _login(host, port):
    status, headers, body = _req(host, port, "POST", "/api/login",
                                 {"username": "admin", "password": "pw"})
    assert status == 200
    return headers["Set-Cookie"].split(";")[0], json.loads(body)["csrf"]


def test_images_list_requires_auth(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        status, _, _ = _req(host, port, "GET", "/api/images")
        assert status == 401
    finally:
        stop()


def test_upload_streams_publishes_and_lists(tmp_path):
    host, port, _, images, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        status, _, body = _req(
            host, port, "PUT", "/api/images/upload/img.bin",
            raw=b"IMAGE-CONTENTS",
            headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        job_id = json.loads(body)["job_id"]
        assert os.path.isfile(str(tmp_path / "imgs" / "img.bin"))
        import time as _t
        deadline = _t.time() + 3
        state = None
        while _t.time() < deadline:
            s, _, jb = _req(host, port, "GET", "/api/images/jobs/" + job_id,
                            headers={"Cookie": cookie})
            assert s == 200
            state = json.loads(jb)["state"]
            if state in ("done", "error"):
                break
            _t.sleep(0.02)
        assert state == "done"
        s, _, lb = _req(host, port, "GET", "/api/images", headers={"Cookie": cookie})
        assert s == 200
        ids = [i["id"] for i in json.loads(lb)["images"]]
        assert "img1" in ids
    finally:
        stop()


def _seed_importable(tmp_path, name="staged.26.01.01.SPA.bin"):
    """Drop an unpublished image into the read-only-style import root."""
    d = tmp_path / "opt-images" / "iosxe" / "c9300"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(b"STAGED-ON-DISK")
    return str(d / name)


def test_importable_list_requires_auth(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/images/importable")[0] == 401
    finally:
        stop()


def test_importable_lists_unpublished_disk_images(tmp_path):
    _seed_importable(tmp_path)
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, _csrf = _login(host, port)
        status, _, body = _req(host, port, "GET", "/api/images/importable",
                               headers={"Cookie": cookie})
        assert status == 200
        found = json.loads(body)["importable"]
        assert [c["filename"] for c in found] == ["staged.26.01.01.SPA.bin"]
        assert found[0]["root"] == "import"
    finally:
        stop()


def test_import_requires_csrf(tmp_path):
    path = _seed_importable(tmp_path)
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, _csrf = _login(host, port)
        status, _, _ = _req(host, port, "POST", "/api/images/import",
                            {"path": path}, headers={"Cookie": cookie})
        assert status == 403
    finally:
        stop()


def test_import_requires_a_session(tmp_path):
    path = _seed_importable(tmp_path)
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        assert _req(host, port, "POST", "/api/images/import",
                    {"path": path})[0] in (401, 403)
    finally:
        stop()


def test_importable_reports_skipped_with_reason(tmp_path):
    """A file the operator expects must not silently fail to appear: an
    ambiguous same-named pair is reported as skipped, with the reason."""
    _seed_importable(tmp_path)
    (tmp_path / "imgs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "imgs" / "staged.26.01.01.SPA.bin").write_bytes(b"twin")
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, _csrf = _login(host, port)
        s, _, body = _req(host, port, "GET", "/api/images/importable",
                          headers={"Cookie": cookie})
        assert s == 200
        out = json.loads(body)
        assert out["importable"] == []
        assert {c["reason"] for c in out["skipped"]} == {
            "ambiguous name in more than one location"}
    finally:
        stop()


def test_import_rejection_is_audited(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        st, _, _ = _req(host, port, "POST", "/api/images/import",
                        {"path": "/etc/shadow"},
                        headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert st == 400
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "image_import" and e.get("result") == "fail"]
        assert ev and "/etc/shadow" in ev[0]["detail"]
    finally:
        stop()


def test_import_publishes_in_place_without_copying(tmp_path):
    path = _seed_importable(tmp_path)
    seen = {}

    def publish_fn(image_path, store, url, **kw):
        seen["path"] = image_path
        entry = {"id": "staged.26.01.01", "filename": os.path.basename(image_path),
                 "size": 14, "published_at": 1}
        store.save_image(entry)
        return entry

    host, port, _, _, stop = _serve_with_images(tmp_path, publish_fn=publish_fn)
    try:
        cookie, csrf = _login(host, port)
        status, _, body = _req(host, port, "POST", "/api/images/import",
                               {"path": path},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        job_id = json.loads(body)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            s, _, jb = _req(host, port, "GET", "/api/images/jobs/" + job_id,
                            headers={"Cookie": cookie})
            if json.loads(jb)["state"] in ("done", "error"):
                break
            _t.sleep(0.02)
        assert json.loads(jb)["state"] == "done"
        # published from where it already lived — never copied into the volume
        assert seen["path"] == path
        assert not os.path.exists(str(tmp_path / "imgs" / "staged.26.01.01.SPA.bin"))
        # and it drops out of the importable set once catalogued
        _s, _h, lb = _req(host, port, "GET", "/api/images/importable",
                          headers={"Cookie": cookie})
        assert json.loads(lb)["importable"] == []
    finally:
        stop()


def test_import_rejects_path_outside_the_candidate_set(tmp_path):
    _seed_importable(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"not-ours")
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        hdrs = {"Cookie": cookie, "X-CSRF-Token": csrf}
        for bad in (str(outside / "secret.bin"),
                    # starts inside a real root but escapes via traversal, so a
                    # prefix check would wrongly accept it
                    str(tmp_path / "opt-images" / ".." / "outside" / "secret.bin"),
                    "/etc/shadow", ""):
            status, _, _ = _req(host, port, "POST", "/api/images/import",
                                {"path": bad}, headers=hdrs)
            assert status == 400, "expected 400 for %r" % bad
    finally:
        stop()


def test_import_of_vanished_file_is_404(tmp_path):
    path = _seed_importable(tmp_path)
    host, port, _, images, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        real_check = images.is_importable_path
        # authorize the path, then delete it before start_publish runs
        def racy(p):
            ok = real_check(p)
            os.remove(path)
            return ok
        images.is_importable_path = racy
        status, _, body = _req(host, port, "POST", "/api/images/import",
                               {"path": path},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 404
        # specifically the vanished-file branch, not a generic route miss
        assert json.loads(body)["error"] == "image no longer on disk"
    finally:
        stop()


def test_import_emits_audit_event(tmp_path):
    path = _seed_importable(tmp_path)
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        st, _, _ = _req(host, port, "POST", "/api/images/import", {"path": path},
                        headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert st == 200
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "image_import"]
        assert ev and ev[0]["actor"] == "console:admin"
        assert ev[0]["target"] == "staged.26.01.01.SPA.bin"
        assert path in ev[0]["detail"]
    finally:
        stop()


def test_upload_requires_csrf(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, _csrf = _login(host, port)
        status, _, _ = _req(host, port, "PUT", "/api/images/upload/img.bin",
                            raw=b"x", headers={"Cookie": cookie})
        assert status == 403
    finally:
        stop()


def test_upload_rejects_bad_filename(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        status, _, _ = _req(host, port, "PUT", "/api/images/upload/bad%20name",
                            raw=b"x", headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 400
    finally:
        stop()


import socket as _socket


def test_upload_rejects_truncated_body(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        s = _socket.create_connection((host, port), timeout=5)
        head = ("PUT /api/images/upload/trunc.bin HTTP/1.0\r\n"
                "Host: x\r\n"
                "Cookie: %s\r\n"
                "X-CSRF-Token: %s\r\n"
                "Content-Length: 100\r\n"
                "\r\n" % (cookie, csrf)).encode()
        s.sendall(head + b"12345")        # promises 100 bytes, sends 5
        s.shutdown(_socket.SHUT_WR)        # EOF: server sees only 5 of 100
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        assert b" 400 " in resp.split(b"\r\n", 1)[0]        # status line is 400
        assert not os.path.isfile(str(tmp_path / "imgs" / "trunc.bin"))
    finally:
        stop()


import gui_fleet
import gui_creds
import catalog as catalog_mod


def _serve_full(tmp_path):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    images = gui_images.ImageService(state, str(tmp_path / "imgs"),
                                     tracker_url_fn=lambda: "http://t/announce?key=k",
                                     publish_fn=lambda p, s, u, **k: s.save_image(
                                         {"id": "img1", "filename": "img1.bin",
                                          "sha256": "ab", "published_at": 1}) or
                                     {"id": "img1"},
                                     import_root=str(tmp_path / "opt-images"))
    fleet = gui_fleet.FleetStore(state)
    creds = gui_creds.CredentialStore(secrets_path)
    cat = catalog_mod.CatalogStore(state)
    cat.save_image({"id": "img1", "filename": "img1.bin", "sha256": "ab",
                    "published_at": 1})
    srv = gui_server.make_server("127.0.0.1", 0, app, images, fleet, creds, cat,
                                 certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, (app, fleet, creds, cat), srv.shutdown


def _auth(host, port):
    s, h, b = _req(host, port, "POST", "/api/login",
                   {"username": "admin", "password": "pw"})
    return h["Set-Cookie"].split(";")[0], json.loads(b)["csrf"]


def test_devices_crud_and_list_requires_auth(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/devices")[0] == 401
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
                         "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                         "guest_ip": "10.0.0.3"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        devs = json.loads(b)["devices"]
        assert devs and devs[0]["device_id"] == "d1"
        st, _, _ = _req(host, port, "DELETE", "/api/devices/d1", headers=hh)
        assert st == 200
        assert json.loads(_req(host, port, "GET", "/api/devices",
                               headers={"Cookie": ck})[2])["devices"] == []
    finally:
        stop()


def test_device_post_requires_csrf(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, _ = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "device_ip": "1.2.3.4"},
                        headers={"Cookie": ck})
        assert st == 403
    finally:
        stop()


def test_csv_import_export(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        csv_body = ("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n"
                    "d9,10.9.9.1,666,10.9.9.2,255.255.255.252,10.9.9.3\n")
        st, _, b = _req(host, port, "POST", "/api/devices/import-csv",
                        raw=csv_body.encode(),
                        headers={"Cookie": ck, "X-CSRF-Token": csrf,
                                 "Content-Type": "text/csv"})
        assert st == 200 and json.loads(b)["imported"] == 1
        st, hd, b = _req(host, port, "GET", "/api/devices/export-csv",
                         headers={"Cookie": ck})
        assert st == 200 and "text/csv" in hd.get("Content-Type", "")
        assert b.decode().splitlines()[0] == \
            ("device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,"
             "app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,"
             "vpg_number,nat_interface,platform")
        assert "d9,10.9.9.1" in b.decode()
    finally:
        stop()


def test_credentials_crud_never_leaks_password(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/credentials",
                        {"id": "lab", "name": "Lab", "device_user": "admin",
                         "device_pass": "topsecret"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/credentials", headers={"Cookie": ck})
        body = b.decode()
        assert "lab" in body and "admin" in body
        assert "topsecret" not in body     # password NEVER returned
        st, _, _ = _req(host, port, "DELETE", "/api/credentials/lab", headers=hh)
        assert st == 200
    finally:
        stop()


def test_assign_image_sets_policy(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "img1"}, headers=hh)
        assert st == 200
        assert cat.get_policy("d1")["approved_image_id"] == "img1"
        assert cat.get_policy("d1")["install_allowed"] is False   # stage-only
        # unknown image -> 400
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "nope"}, headers=hh)
        assert st == 400
    finally:
        stop()


def test_csv_import_accepts_large_body(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        rows = ["device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip"]
        for i in range(2000):   # ~2000 rows -> well over the 64 KiB JSON cap
            rows.append("d%d,10.0.%d.%d,666,10.0.0.2,255.255.255.252,10.0.0.3"
                        % (i, i // 256, i % 256))
        body = ("\n".join(rows) + "\n").encode()
        assert len(body) > 64 * 1024
        st, _, b = _req(host, port, "POST", "/api/devices/import-csv", raw=body,
                        headers={"Cookie": ck, "X-CSRF-Token": csrf,
                                 "Content-Type": "text/csv"})
        assert st == 200 and json.loads(b)["imported"] == 2000
    finally:
        stop()


def test_device_view_merges_policy_and_heartbeat(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_id="img1")
        cat.record_heartbeat("d1", {"stage_state": "verified", "stage_error": "copy denied", "model": "C9300"}, now=123)
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        row = [d for d in json.loads(b)["devices"] if d["device_id"] == "d1"][0]
        assert row["assigned_image_id"] == "img1"
        assert row["stage_state"] == "verified"
        assert row["stage_error"] == "copy denied"
        assert row["last_seen"] == 123
        assert row["heartbeat_model"] == "C9300"
    finally:
        stop()


def test_device_view_mixed_policy_defaults(tmp_path):
    """Devices WITHOUT a policy entry still get assigned_image_id: null in the
    /api/devices rows — the single list_policies() read must yield the same
    output as the old per-device get_policy() (which defaulted the field)."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d2", "device_ip": "10.0.0.2"}, headers=hh)
        cat.set_policy("d1", approved_image_id="img1")   # d2 has NO policy
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        assert st == 200
        rows = {d["device_id"]: d for d in json.loads(b)["devices"]}
        assert rows["d1"]["assigned_image_id"] == "img1"
        assert "assigned_image_id" in rows["d2"]
        assert rows["d2"]["assigned_image_id"] is None
    finally:
        stop()


def test_policy_read_once_per_request(tmp_path):
    """policy.json is parsed exactly once per /api/devices or /api/overview
    request, regardless of fleet size — the console polls both endpoints, so
    a per-device get_policy() re-read would grow linearly with the fleet."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        for i in range(3):
            _req(host, port, "POST", "/api/devices",
                 {"device_id": "d%d" % i, "device_ip": "10.0.0.%d" % (i + 1)},
                 headers=hh)
        cat.set_policy("d0", approved_image_id="img1")

        reads = {"policy": 0}
        orig_read = cat._read

        def counting_read(path):
            if path == cat.policy_path:
                reads["policy"] += 1
            return orig_read(path)

        cat._read = counting_read
        st, _, _ = _req(host, port, "GET", "/api/devices",
                        headers={"Cookie": ck})
        assert st == 200
        assert reads["policy"] == 1
        reads["policy"] = 0
        st, _, _ = _req(host, port, "GET", "/api/overview",
                        headers={"Cookie": ck})
        assert st == 200
        assert reads["policy"] == 1
    finally:
        stop()


def test_csv_import_rejects_oversized(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        s = _socket.create_connection((host, port), timeout=5)
        head = ("POST /api/devices/import-csv HTTP/1.0\r\nHost: x\r\n"
                "Cookie: %s\r\nX-CSRF-Token: %s\r\nContent-Type: text/csv\r\n"
                "Content-Length: 9000000\r\n\r\n" % (ck, csrf)).encode()
        s.sendall(head + b"device_id,device_ip\n")   # declares 9 MB, sends a few bytes
        s.shutdown(_socket.SHUT_WR)
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


import gui_onboard


def _serve_onboard(tmp_path, run_fn, **svc_kw):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "model": "C9300",
                  "credential_profile_id": "lab"})
    fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2", "model": "C9300",
                  "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    onboard = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                         mint_fn=lambda d: "TOK", run_fn=run_fn,
                                         **svc_kw)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, srv.shutdown


def test_onboard_start_status_and_stream(tmp_path):
    def run_fn(p, e, on):
        on("[1/6] hello"); on("[6/6] done"); return 0
    host, port, stop = _serve_onboard(tmp_path, run_fn)
    try:
        ck, csrf = _auth(host, port)
        # start requires CSRF
        assert _req(host, port, "POST", "/api/devices/d1/onboard",
                    {}, headers={"Cookie": ck})[0] == 403
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        job_id = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            s, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + job_id,
                            headers={"Cookie": ck})
            job = json.loads(jb)
            if job["state"] in ("done", "error"):
                break
            _t.sleep(0.02)
        assert job["state"] == "done"
        assert "[6/6] done" in job["lines"]
        # SSE stream returns text/event-stream and the data lines + an end event
        s, hd, sb = _req(host, port, "GET",
                         "/api/onboard/jobs/" + job_id + "/stream",
                         headers={"Cookie": ck})
        assert s == 200 and "text/event-stream" in hd.get("Content-Type", "")
        body = sb.decode()
        assert "data: [1/6] hello" in body and "event: end" in body
    finally:
        stop()


def test_onboard_status_requires_auth(tmp_path):
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0)
    try:
        assert _req(host, port, "GET", "/api/onboard/jobs/x")[0] == 401
        assert _req(host, port, "GET", "/api/onboard/jobs/x/stream")[0] == 401
    finally:
        stop()


def test_onboard_jobs_list_endpoint(tmp_path):
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0,
                                      max_concurrent=7)
    try:
        assert _req(host, port, "GET", "/api/onboard/jobs")[0] == 401
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        job_id = json.loads(b)["job_id"]
        st, _, lb = _req(host, port, "GET", "/api/onboard/jobs",
                         headers={"Cookie": ck})
        assert st == 200
        listing = json.loads(lb)
        assert listing["max_concurrent"] == 7
        # server clock rides along so the UI's running-duration math never
        # mixes client and server clocks (skewed lab VMs)
        assert isinstance(listing["now"], int)
        mine = [j for j in listing["jobs"] if j["id"] == job_id]
        assert mine and mine[0]["device_id"] == "d1"
        assert "lines" not in mine[0]
    finally:
        stop()


def test_onboard_unknown_device_is_404(tmp_path):
    """Unknown device ids are rejected at the route, BEFORE a job (and its
    parked worker thread) is created — no thread/job accumulation from junk."""
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        st, _, _b = _req(host, port, "POST", "/api/devices/ghost/onboard", {},
                         headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 404
        _, _, lb = _req(host, port, "GET", "/api/onboard/jobs",
                        headers={"Cookie": ck})
        assert json.loads(lb)["jobs"] == []
    finally:
        stop()


def test_onboard_cancel_queued_endpoint_and_sse_end(tmp_path):
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5); return 0

    host, port, audit_path, stop = _serve_onboard_audit(
        tmp_path, run_fn, max_concurrent=1)
    try:
        ck, csrf = _auth(host, port)
        # CSRF-gated like every state-changing POST
        assert _req(host, port, "POST", "/api/onboard/cancel-queued", {},
                    headers={"Cookie": ck})[0] == 403
        jids = []
        for did in ("d1", "d2"):
            st, _, b = _req(host, port, "POST",
                            "/api/devices/%s/onboard" % did, {},
                            headers={"Cookie": ck, "X-CSRF-Token": csrf})
            assert st == 200
            jids.append(json.loads(b)["job_id"])
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            _, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jids[0],
                            headers={"Cookie": ck})
            if json.loads(jb)["state"] == "running":
                break
            _t.sleep(0.02)
        # scoped to job_ids: an unrelated id cancels nothing...
        st, _, b = _req(host, port, "POST", "/api/onboard/cancel-queued",
                        {"job_ids": ["deadbeef"]},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200 and json.loads(b)["cancelled"] == 0
        # ...and the queued job's id cancels exactly it
        st, _, b = _req(host, port, "POST", "/api/onboard/cancel-queued",
                        {"job_ids": jids},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200 and json.loads(b)["cancelled"] == 1
        # the cancelled job is terminal: its SSE stream ends immediately
        s, hd, sb = _req(host, port, "GET",
                         "/api/onboard/jobs/" + jids[1] + "/stream",
                         headers={"Cookie": ck})
        assert s == 200 and "event: end\ndata: cancelled" in sb.decode()
        # the cancel is audited
        events = _read_audit_lines(audit_path)
        cancels = [e for e in events if e.get("event") == "onboard_cancel"]
        assert cancels and "1" in (cancels[0].get("detail") or "")
    finally:
        release.set()
        stop()


def test_devices_view_carries_onboard_state_and_overview_awaits_heartbeat(tmp_path):
    """After a successful onboard, the device has no heartbeat yet (the agent
    needs a couple of minutes to bootstrap) — the devices view must carry the
    job outcome so the UI shows 'waiting for heartbeat' instead of the
    misleading 'not enrolled', and the overview counts such devices."""
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        jid = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            _, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jid,
                            headers={"Cookie": ck})
            if json.loads(jb)["state"] == "done":
                break
            _t.sleep(0.02)
        _, _, db = _req(host, port, "GET", "/api/devices",
                        headers={"Cookie": ck})
        rows = {r["device_id"]: r for r in json.loads(db)["devices"]}
        assert rows["d1"]["onboard_state"] == "done"
        assert rows["d1"]["onboard_action"] == "onboard"
        assert rows["d1"]["onboard_finished_at"] is not None
        assert "onboard_state" not in rows["d2"] or rows["d2"].get("onboard_state") is None
        # no catalog heartbeat in this harness -> d1 is awaiting its first one
        _, _, ob = _req(host, port, "GET", "/api/overview",
                        headers={"Cookie": ck})
        assert json.loads(ob)["awaiting_heartbeat"] == 1
    finally:
        stop()


def test_undeploy_route_starts_job_and_conflicts_409(tmp_path):
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5); return 0

    host, port, stop = _serve_onboard(tmp_path, run_fn, max_concurrent=1)
    try:
        ck, csrf = _auth(host, port)
        assert _req(host, port, "POST", "/api/devices/ghost/undeploy", {},
                    headers={"Cookie": ck, "X-CSRF-Token": csrf})[0] == 404
        st, _, b = _req(host, port, "POST", "/api/devices/d1/undeploy", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        jid = json.loads(b)["job_id"]
        # same action again -> joins the active job
        st, _, b2 = _req(host, port, "POST", "/api/devices/d1/undeploy", {},
                         headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200 and json.loads(b2)["job_id"] == jid
        # opposite action while active -> 409 with a self-explanatory error
        st, _, b3 = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                         headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 409 and "undeploy" in json.loads(b3)["error"]
        # the jobs listing tags the action so the batch panel can label rows
        _, _, lb = _req(host, port, "GET", "/api/onboard/jobs",
                        headers={"Cookie": ck})
        mine = [j for j in json.loads(lb)["jobs"] if j["id"] == jid]
        assert mine and mine[0]["action"] == "undeploy"
    finally:
        release.set()
        stop()


def test_sse_stream_survives_queue_wait(tmp_path, monkeypatch):
    """The SSE idle cap must not count time spent queued for a pool slot: an
    operator opens a deep-queued job's log, the stream stays open (with
    keepalives) until the job runs, then delivers the lines and the end event."""
    monkeypatch.setattr(gui_server, "_SSE_IDLE", 1)      # 1s idle cap
    monkeypatch.setattr(gui_server, "_SSE_KEEPALIVE", 0.2)
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5); on("hello from " + e["DEVICE_ID"]); return 0

    host, port, stop = _serve_onboard(tmp_path, run_fn, max_concurrent=1)
    try:
        ck, csrf = _auth(host, port)
        jids = []
        for did in ("d1", "d2"):
            st, _, b = _req(host, port, "POST",
                            "/api/devices/%s/onboard" % did, {},
                            headers={"Cookie": ck, "X-CSRF-Token": csrf})
            assert st == 200
            jids.append(json.loads(b)["job_id"])
        # d2 is queued behind blocked d1; stream its log while it waits
        import http.client
        conn = http.client.HTTPConnection(host, port, timeout=15)
        conn.request("GET", "/api/onboard/jobs/" + jids[1] + "/stream",
                     headers={"Cookie": ck})
        resp = conn.getresponse()
        chunks = []
        done_reading = threading.Event()

        def read_all():
            while True:
                b = resp.read1(4096)
                if not b:
                    break
                chunks.append(b)
            done_reading.set()

        t = threading.Thread(target=read_all, daemon=True)
        t.start()
        time.sleep(2.5)                       # 2.5x the idle cap, still queued
        assert not done_reading.is_set()      # queue wait didn't close it
        assert b": keepalive" in b"".join(chunks)
        release.set()
        assert done_reading.wait(10)
        body = b"".join(chunks).decode()
        assert "data: hello from d2" in body
        assert "event: end\ndata: done" in body
        conn.close()
    finally:
        release.set()
        stop()


def _serve_inband(tmp_path, run_fn, device=None):
    import deployment_receipts
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert(device or {"device_id": "edge", "device_ip": "192.0.2.10",
                  "management_type": "inband", "inband_vlan": "120",
                  "app_ip": "192.0.2.11", "app_mask": "255.255.255.0",
                  "app_gateway": "192.0.2.1", "model": "C9300",
                  "platform": "guestshell", "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    receipts = deployment_receipts.ReceiptStore(state)
    art = str(tmp_path / "artifacts"); os.makedirs(art, exist_ok=True)
    for pkg in ("iris-arm64.tar", "iris-amd64.tar"):
        open(os.path.join(art, pkg), "w").close()   # IOx package-presence gate
    onboard = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                         mint_fn=lambda d: "TOK", run_fn=run_fn,
                                         receipts=receipts, artifacts_dir=art)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, receipts=receipts)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, srv.shutdown


def test_inband_iox_onboard_defaults_ssh_host_to_mgmt_ip(tmp_path):
    """Inband IOx resolves the iox platform and, with no explicit ios_ssh_host,
    the app SSHes to the switch's management IP (device_ip)."""
    ran = []
    host, port, stop = _serve_inband(
        tmp_path, lambda p, e, on: (ran.append(dict(e)), 0)[1],
        device={"device_id": "ie", "device_ip": "192.0.2.30",
                "management_type": "inband", "inband_vlan": "120",
                "app_ip": "192.0.2.31", "app_mask": "255.255.255.0",
                "app_gateway": "192.0.2.1", "model": "IE-3400", "platform": "iox",
                "credential_profile_id": "lab"})
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "GET", "/api/devices/ie/plan",
                        headers={"Cookie": ck})
        assert st == 200
        resolved = json.loads(b)["plan"]["resolved"]
        assert resolved["attachment"] == "inband" and resolved["platform"] == "iox"
        assert resolved["ios_ssh_host"] == "192.0.2.30"    # defaults to device_ip
        st, _, b = _req(host, port, "POST", "/api/devices/ie/onboard", {}, headers=hh)
        assert st == 200
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            if ran:
                break
            _t.sleep(0.02)
        assert ran and ran[-1]["NETWORK_ATTACHMENT"] == "inband"
        assert ran[-1]["IOS_SSH_HOST"] == "192.0.2.30"
    finally:
        stop()


def test_reonboard_then_undeploy_starts(tmp_path):
    """Re-onboarding a device (idempotent redeploy) and then undeploying it
    must work: the second onboard's receipt supersedes the first, so the
    undeploy start finds exactly one active receipt. This is the lab-observed
    failure: two active receipts made active_for_device() raise and the
    Console reported 'failed to start' with no reason."""
    host, port, stop = _serve_inband(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        import time as _t

        def _wait_done(jid):
            deadline = _t.time() + 3
            while _t.time() < deadline:
                _, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jid,
                                headers={"Cookie": ck})
                if json.loads(jb)["state"] in ("done", "error"):
                    return json.loads(jb)["state"]
                _t.sleep(0.02)
            return "timeout"

        for _ in range(2):    # onboard TWICE — the re-onboard mints receipt #2
            st, _, b = _req(host, port, "POST", "/api/devices/edge/onboard", {},
                            headers=hh)
            assert st == 200
            assert _wait_done(json.loads(b)["job_id"]) == "done"
        st, _, b = _req(host, port, "POST", "/api/devices/edge/undeploy", {},
                        headers=hh)
        assert st == 200, "undeploy refused after re-onboard: %s" % b
    finally:
        stop()


def test_inband_onboard_is_one_click_and_drives_inband_renderer(tmp_path):
    """Inband onboards exactly like routed: a plain POST starts a job, records a
    receipt, and runs the installer with NETWORK_ATTACHMENT=inband."""
    ran = []
    host, port, stop = _serve_inband(
        tmp_path, lambda p, e, on: (ran.append(dict(e)), 0)[1])
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # plan preview reports the inband attachment
        st, _, b = _req(host, port, "GET", "/api/devices/edge/plan",
                        headers={"Cookie": ck})
        assert st == 200 and json.loads(b)["plan"]["resolved"]["attachment"] == "inband"
        # a plain onboard POST starts the job (no gate, no acknowledgement dance)
        st, _, b = _req(host, port, "POST", "/api/devices/edge/onboard", {},
                        headers=hh)
        assert st == 200
        jid = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            _, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jid,
                            headers={"Cookie": ck})
            if json.loads(jb)["state"] in ("done", "error"):
                break
            _t.sleep(0.02)
        assert ran and ran[-1]["NETWORK_ATTACHMENT"] == "inband"
    finally:
        stop()


def _serve_router(tmp_path, run_fn, preflight_fn=None, mint_fn=None, device=None):
    """Receipt-backed server with one C8000V router inventory row."""
    import deployment_receipts
    os.makedirs(tmp_path, exist_ok=True)
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert(device or {
        "device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
        "management_type": "router-nat", "vpg_number": "10",
        "nat_interface": "GigabitEthernet1", "app_ip": "10.8.0.2",
        "app_mask": "255.255.255.252", "app_gateway": "10.8.0.1",
        "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    receipts = deployment_receipts.ReceiptStore(state)
    onboard = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=mint_fn or (lambda d: "TOK"),
        run_fn=run_fn, receipts=receipts, preflight_fn=preflight_fn)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, receipts=receipts)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, fleet, receipts, srv.shutdown


def _wait_onboard_job(host, port, cookie, job_id):
    deadline = time.time() + 3
    while time.time() < deadline:
        _, _, body = _req(host, port, "GET", "/api/onboard/jobs/" + job_id,
                          headers={"Cookie": cookie})
        job = json.loads(body)
        if job["state"] in ("done", "error", "cancelled"):
            return job
        time.sleep(0.02)
    raise AssertionError("onboard job did not finish: %s" % job_id)


def test_c8000v_router_plan_auto_resolves_blank_platform_and_fields(tmp_path):
    host, port, _fleet, receipts, stop = _serve_router(
        tmp_path, lambda p, e, on: 0,
        preflight_fn=lambda dev, env, resolved: {
            "status": "passed", "device_identity": "9ABC123",
            "detected_model": "C8000V"},
        device={"device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
                "management_type": "router-routed", "vpg_number": "7",
                "app_ip": "10.7.0.2", "app_mask": "255.255.255.252",
                "app_gateway": "10.7.0.1", "credential_profile_id": "lab"})
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/devices/r1/plan",
                               headers={"Cookie": cookie})
        assert status == 200
        plan = json.loads(body)["plan"]
        assert plan["ownership"] == "creates only a clean IRIS-owned VirtualPortGroup"
        assert plan["resolved"] == {
            "attachment": "router-routed", "device_ip": "192.0.2.10",
            "iris_vlan": "", "svi_ip": "",
            "svi_mask": "", "app_ip": "10.7.0.2", "app_mask": "255.255.255.252",
            "app_gateway": "10.7.0.1", "inband_vlan": "", "vpg_number": "7",
            "nat_interface": "", "swarm_port": "6881", "ios_ssh_host": "",
            "model": "C8000V", "platform": "router", "renderer": "v1"}
        status, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        assert _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])["state"] == "done"
        assert [resource["kind"] for resource in receipts.active_for_device("r1")["resources"]] == [
            "virtualportgroup", "eem-applets", "agent-files",
            "logging-discriminator", "pki-trustpoint", "http-client-trustpoint",
            "iox-global", "file-prompt-quiet",
            "guestshell"]
    finally:
        stop()


def test_router_onboard_uses_router_recipe_env_and_router_resource_kinds(tmp_path):
    events, ran = [], []
    host, port, _fleet, receipts, stop = _serve_router(
        tmp_path, lambda path, env, on: (ran.append((path, dict(env))), 0)[1],
        preflight_fn=lambda dev, env, resolved: (events.append("preflight") or {
            "status": "passed", "device_identity": "9ABC123",
            "detected_model": "C8000V", "nat_interface": "GigabitEthernet1",
            "nat_outside_preexisting": False}),
        mint_fn=lambda did: events.append("mint") or "TOK")
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        job = _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])
        assert job["state"] == "done"
        assert events == ["preflight", "preflight", "mint"]
        path, env = ran[-1]
        assert path.endswith("device/router-install.sh")
        assert {key: env[key] for key in ("NETWORK_ATTACHMENT", "VPG_NUMBER",
                                           "NAT_INTERFACE", "BT_LISTEN_PORT")} == {
            "NETWORK_ATTACHMENT": "router-nat", "VPG_NUMBER": "10",
            "NAT_INTERFACE": "GigabitEthernet1", "BT_LISTEN_PORT": "6881"}
        receipt = receipts.active_for_device("r1")
        assert [resource["kind"] for resource in receipt["resources"]] == [
            "virtualportgroup", "eem-applets", "agent-files",
            "logging-discriminator", "pki-trustpoint", "http-client-trustpoint",
            "iox-global", "file-prompt-quiet",
            "guestshell",
            "nat-acl", "nat-overload", "nat-static", "nat-outside-marking"]
        assert receipt["resources"][-1]["ownership"] == "iris-created"
    finally:
        stop()


def test_router_preflight_failure_mints_nothing_and_creates_no_receipt(tmp_path):
    minted, ran = [], []

    def reject(*_args):
        raise ValueError("VirtualPortGroup10 already exists")

    host, port, _fleet, receipts, stop = _serve_router(
        tmp_path, lambda p, e, on: ran.append(1) or 0, preflight_fn=reject,
        mint_fn=lambda did: minted.append(did) or "TOK")
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 409 and "preflight failed" in json.loads(body)["error"]
        assert minted == [] and ran == [] and receipts.list("r1") == []
    finally:
        stop()


def test_router_nat_preflight_ownership_persists_and_undeploy_uses_receipt(tmp_path):
    for preexisting, expected in ((True, "0"), (False, "1")):
        ran = []
        host, port, _fleet, receipts, stop = _serve_router(
            tmp_path / ("existing" if preexisting else "created"),
            lambda path, env, on: (ran.append((path, dict(env))), 0)[1],
            preflight_fn=lambda dev, env, resolved, preexisting=preexisting: {
                "status": "passed", "device_identity": "9ABC123",
                "detected_model": "C8000V", "nat_interface": "GigabitEthernet1",
                "nat_outside_preexisting": preexisting})
        try:
            cookie, csrf = _auth(host, port)
            headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
            _, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                              headers=headers)
            onboard_job = _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])
            assert onboard_job["state"] == "done"
            receipt = receipts.active_for_device("r1")
            assert receipt["resolved"]["nat_outside_owned"] == expected
            marking = [r for r in receipt["resources"] if r["kind"] == "nat-outside-marking"]
            assert marking == [{"kind": "nat-outside-marking", "interface": "GigabitEthernet1",
                                "ownership": "pre-existing" if preexisting else "iris-created"}]
            _, _, body = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                              headers=headers)
            job = _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])
            assert job["state"] == "done"
            assert ran[-1][0].endswith("device/router-uninstall.sh")
            assert ran[-1][1]["NAT_OUTSIDE_OWNED"] == expected
        finally:
            stop()


def test_platform_endpoint_allows_router_only_for_router_management_types(tmp_path):
    host, port, fleet, _receipts, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        fleet.upsert({"device_id": "switch", "device_ip": "192.0.2.20",
                      "management_type": "routed", "iris_vlan": "120",
                      "svi_ip": "10.20.0.1", "svi_mask": "255.255.255.252",
                      "app_ip": "10.20.0.2", "app_mask": "255.255.255.252",
                      "app_gateway": "10.20.0.1", "model": "C9300"})
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        assert _req(host, port, "POST", "/api/devices/r1/platform", {"platform": "router"},
                    headers=headers)[0] == 200
        assert _req(host, port, "POST", "/api/devices/r1/platform", {"platform": "guestshell"},
                    headers=headers)[0] == 400
        assert _req(host, port, "POST", "/api/devices/switch/platform", {"platform": "router"},
                    headers=headers)[0] == 400
    finally:
        stop()


def test_router_adopt_is_refused_without_live_ownership_evidence(tmp_path):
    host, port, _fleet, receipts, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(
            host, port, "POST", "/api/devices/r1/adopt",
            {"acknowledge_adopt": True},
            headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 409 and "cannot be adopted" in json.loads(body)["error"]
        assert receipts.list("r1") == []
    finally:
        stop()


def test_router_undeploy_uses_receipt_ip_after_inventory_edit(tmp_path):
    ran = []
    evidence = {"status": "passed", "device_identity": "9ABC123",
                "detected_model": "C8000V", "nat_interface": "GigabitEthernet1",
                "nat_outside_preexisting": False}
    host, port, fleet, _receipts, stop = _serve_router(
        tmp_path, lambda path, env, on: (ran.append(dict(env)), 0)[1],
        preflight_fn=lambda *args: dict(evidence))
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        _, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                          headers=headers)
        assert _wait_onboard_job(host, port, cookie,
                                 json.loads(body)["job_id"])["state"] == "done"
        fleet.upsert({"device_id": "r1", "device_ip": "192.0.2.99"})
        _, _, body = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                          headers=headers)
        assert _wait_onboard_job(host, port, cookie,
                                 json.loads(body)["job_id"])["state"] == "done"
        assert ran[-1]["DEVICE_IP"] == "192.0.2.10"
        assert ran[-1]["EXPECTED_DEVICE_IDENTITY"] == "9ABC123"
        assert ran[-1]["ROUTER_RESOURCES_OWNED"] == "1"
    finally:
        stop()


def test_router_undeploy_refuses_incomplete_or_mismatched_receipt(tmp_path):
    host, port, _fleet, receipts, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        plan = {"platform": "router", "attachment": "router-routed",
                "device_ip": "192.0.2.10", "device_identity": "9ABC123",
                "vpg_number": "10", "model": "C8000V"}
        receipt = receipts.create({"controller_id": "iris", "device_id": "r1",
            "inventory_revision": 1, "plan_hash": "a" * 64,
            "resolved": plan, "preflight": {"status": "passed"},
            "resources": [{"kind": "virtualportgroup", "ownership": "iris-created",
                           "id": "99"}]})
        receipts.transition(receipt["receipt_id"], "applying")
        receipts.transition(receipt["receipt_id"], "active")
        status, _, body = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                               headers=headers)
        assert status == 409 and "does not prove ownership" in json.loads(body)["error"]
        assert receipts.get(receipt["receipt_id"])["state"] == "needs-reconcile"
    finally:
        stop()


def test_router_routes_fail_closed_without_receipt_store(tmp_path):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    fleet = gui_fleet.FleetStore(str(tmp_path / "state"))
    fleet.upsert({"device_id": "r1", "device_ip": "192.0.2.10",
                  "model": "C8000V", "management_type": "router-routed",
                  "vpg_number": "10", "app_ip": "10.8.0.2",
                  "app_mask": "255.255.255.252", "app_gateway": "10.8.0.1",
                  "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    onboard = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=lambda p, e, on: 0)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, receipts=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cookie, csrf = _auth("127.0.0.1", port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        for action in ("onboard", "undeploy"):
            status, _, body = _req(
                "127.0.0.1", port, "POST", "/api/devices/r1/" + action, {},
                headers=headers)
            assert status == 503 and "receipt" in json.loads(body)["error"]
    finally:
        srv.shutdown()


def _serve_onboard_audit(tmp_path, run_fn, **svc_kw):
    """_serve_onboard, but the OnboardService is built with an audit_fn wired
    to a real audit.jsonl under tmp_path (via gui_server's audit_path kwarg,
    same file the route-level emissions use)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    audit_path = str(tmp_path / "audit.jsonl")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "model": "C9300",
                  "credential_profile_id": "lab"})
    fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2", "model": "C9300",
                  "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})

    def audit_fn(**kw):
        audit_mod.append_event(audit_path, kw.pop("event"), **kw)

    onboard = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                         mint_fn=lambda d: "TOK", run_fn=run_fn,
                                         audit_fn=audit_fn, **svc_kw)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, audit_path=audit_path, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, audit_path, srv.shutdown


def test_onboard_start_and_finish_emit_audit(tmp_path):
    def run_fn(p, e, on):
        on("ok"); return 0
    host, port, audit_path, stop = _serve_onboard_audit(tmp_path, run_fn)
    try:
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        job_id = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            lines = _read_audit_lines(audit_path)
            if any(e.get("event") == "onboard_finished" for e in lines):
                break
            _t.sleep(0.02)
        lines = _read_audit_lines(audit_path)
        onboard_events = [e for e in lines if e.get("category") == "onboard"]
        started = [e for e in onboard_events if e.get("event") == "onboard_start"]
        finished = [e for e in onboard_events if e.get("event") == "onboard_finished"]
        assert started and started[0]["target"] == "d1"
        # start/finish correlate through the job id (concurrent onboards)
        assert started[0]["detail"] == "job " + job_id
        assert finished and finished[0]["result"] == "ok"
        assert finished[0]["detail"].startswith("job %s " % job_id)
        assert "platform=guestshell rc=0" in finished[0]["detail"]
    finally:
        stop()


def _serve_overview(tmp_path, swarm_fetch=None):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
    fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2"})
    fleet.upsert({"device_id": "d3", "device_ip": "10.0.0.3"})
    cat = catalog_mod.CatalogStore(state)
    cat.save_image({"id": "img1", "filename": "img1.bin", "sha256": "ab",
                    "published_at": 1})
    cat.set_policy("d1", approved_image_id="img1")
    cat.set_policy("d2", approved_image_id="img1")
    cat.set_policy("d3", approved_image_id="img1")
    # d1 finished staging (stage_state=ready); d3 is mid-download (staging); d2 never checked in
    cat.record_heartbeat("d1", {"current_image_id": "img1", "stage_state": "ready"}, now=10)
    cat.record_heartbeat("d3", {"current_image_id": "img1", "stage_state": "staging"}, now=11)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat, None,
                                 swarm_fetch, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, srv.shutdown


def test_overview_aggregates(tmp_path):
    host, port, stop = _serve_overview(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/overview")[0] == 401
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/overview", headers={"Cookie": ck})
        assert st == 200
        ov = json.loads(b)
        assert ov["images"] == 1 and ov["devices"] == 3
        assert ov["assigned"] == 3 and ov["staged"] == 1   # only d1 (ready) counts
        assert ov["staging_now"] == 2                       # d2 + d3 not yet staged
        r = [x for x in ov["rollout"] if x["image_id"] == "img1"][0]
        assert r["assigned"] == 3 and r["staged"] == 1
    finally:
        stop()


def test_swarm_proxy_and_error(tmp_path):
    host, port, stop = _serve_overview(tmp_path, swarm_fetch=lambda: b'{"peers":[1,2,3]}')
    try:
        assert _req(host, port, "GET", "/api/swarm")[0] == 401
        ck, _csrf = _auth(host, port)
        st, hd, b = _req(host, port, "GET", "/api/swarm", headers={"Cookie": ck})
        assert st == 200 and json.loads(b)["peers"] == [1, 2, 3]
    finally:
        stop()

    def boom():
        raise OSError("tracker down")
    host, port, stop = _serve_overview(tmp_path, swarm_fetch=boom)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/swarm", headers={"Cookie": ck})
        assert st == 200 and "error" in json.loads(b)   # graceful on tracker down
    finally:
        stop()


def _serve_fresh(tmp_path):
    """A server whose store has NO admin yet (first-run/setup state)."""
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, app, srv.shutdown


def test_setup_serves_wizard_and_creates_admin(tmp_path):
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        # while no admin exists, GET / serves the setup wizard
        st, hd, b = _req(host, port, "GET", "/")
        assert st == 200 and b"setup" in b.lower()
        # /api/setup (no auth) creates the admin
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "admin", "password": "pw"})
        assert st == 200
        assert app.needs_setup() is False
        # it is now self-disabled (409) and the login flow works
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "x", "password": "y"})
        assert st == 409
        st, _, _ = _req(host, port, "POST", "/api/login",
                        {"username": "admin", "password": "pw"})
        assert st == 200
    finally:
        stop()


def test_setup_requires_fields(tmp_path):
    host, port, _app, stop = _serve_fresh(tmp_path)
    try:
        st, _, _ = _req(host, port, "POST", "/api/setup", {"username": "", "password": ""})
        assert st == 400
    finally:
        stop()


def test_normal_mode_serves_login_not_setup(tmp_path):
    # once an admin exists, / serves the console shell (app.js), /login.html the login
    app = gui_app.GuiApp(str(tmp_path / "secrets.json")); app.set_admin("admin", "pw")
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st, _, b = _req("127.0.0.1", port, "GET", "/login.html")
        assert st == 200 and b"Sign in" in b
        # GET / serves the console shell (app.js), NOT the setup wizard, once set up
        st, _, b = _req("127.0.0.1", port, "GET", "/")
        assert st == 200 and b"/app.js" in b and b"First-run setup" not in b
        # setup is refused now
        st, _, _ = _req("127.0.0.1", port, "POST", "/api/setup",
                        {"username": "x", "password": "y"})
        assert st == 409
    finally:
        srv.shutdown()


def test_delete_image_route(tmp_path):
    host, port, images, _stop = None, None, None, None
    host, port, _app, images, stop = _serve_with_images(tmp_path)
    try:
        ck, csrf = _login(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # publish img1 through the fake publish path
        store = images._store()
        store.save_image({"id": "img1", "filename": "img1.bin", "info_hash_hex": "x",
                          "published_at": 1})
        # delete requires CSRF
        assert _req(host, port, "DELETE", "/api/images/img1",
                    headers={"Cookie": ck})[0] == 403
        # 404 for unknown
        assert _req(host, port, "DELETE", "/api/images/nope", headers=hh)[0] == 404
        # blocked (409) when assigned
        store.set_policy("d1", approved_image_id="img1")
        st, _, b = _req(host, port, "DELETE", "/api/images/img1", headers=hh)
        assert st == 409 and "d1" in json.loads(b)["assigned"]
        # unassign -> deletes (200)
        store.set_policy("d1", approved_image_id=None)
        st, _, _ = _req(host, port, "DELETE", "/api/images/img1", headers=hh)
        assert st == 200
        assert store.get_image("img1") is None
    finally:
        stop()


def test_delete_image_stale_policy_after_device_removed(tmp_path):
    # A policy for a device that was later removed from the fleet must NOT keep an
    # image permanently un-deletable: the route intersects the assigned check with
    # the live fleet inventory.
    host, port, ctx, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = ctx
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # img1 preexists in _serve_full's catalog; add d1 and assign it img1
        assert _req(host, port, "POST", "/api/devices",
                    {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
                     "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                     "guest_ip": "10.0.0.3"}, headers=hh)[0] == 200
        cat.set_policy("d1", approved_image_id="img1")
        # a live assigned device blocks deletion (409)
        st, _, b = _req(host, port, "DELETE", "/api/images/img1", headers=hh)
        assert st == 409 and "d1" in json.loads(b)["assigned"]
        # remove d1 from the fleet -> its policy is now stale
        assert _req(host, port, "DELETE", "/api/devices/d1", headers=hh)[0] == 200
        # the stale policy must no longer block: the image is deletable (200)
        st, _, _ = _req(host, port, "DELETE", "/api/images/img1", headers=hh)
        assert st == 200
        assert cat.get_image("img1") is None
    finally:
        stop()


def test_settings_get(tmp_path):
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/settings")[0] == 401   # no session
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert st == 200
        s = json.loads(b)
        assert s["admin_username"] == "admin"
        assert s["ports"]["console"] == 8080 and s["ports"]["catalog"] == 8443
        assert "enabled" in s["observability"]
        assert s["sessions"]["active"] >= 1
        assert "version" in s and "host_ip" in s
    finally:
        stop()


def test_settings_console_port_is_dynamic(tmp_path, monkeypatch):
    """The Settings page must show the actual published console port
    (IRIS_GUI_PUBLISH), not a hardcoded 8080."""
    monkeypatch.setenv("IRIS_GUI_PUBLISH", "8082")
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert st == 200 and json.loads(b)["ports"]["console"] == 8082
    finally:
        stop()


def test_settings_password_change(tmp_path):
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        ck2, _ = _auth(host, port)                       # a 2nd session to be revoked
        # CSRF required
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "pw", "new": "newlongpw", "confirm": "newlongpw"},
                    headers={"Cookie": ck})[0] == 403
        # too short / mismatch / wrong current -> 400
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "pw", "new": "short", "confirm": "short"}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "pw", "new": "newlongpw", "confirm": "nope12345"}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "bad", "new": "newlongpw", "confirm": "newlongpw"}, headers=hh)[0] == 400
        # success
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "pw", "new": "newlongpw", "confirm": "newlongpw"}, headers=hh)[0] == 200
        # old password rejected, new accepted
        assert _req(host, port, "POST", "/api/login",
                    {"username": "admin", "password": "pw"})[0] == 401
        assert _req(host, port, "POST", "/api/login",
                    {"username": "admin", "password": "newlongpw"})[0] == 200
        # caller kept, other session revoked
        assert _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})[0] == 200
        assert _req(host, port, "GET", "/api/settings", headers={"Cookie": ck2})[0] == 401
    finally:
        stop()


def test_settings_revoke_others(tmp_path):
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        ck2, _ = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/settings/sessions/revoke-others", {},
                        headers=hh)
        assert st == 200 and json.loads(b)["revoked"] >= 1
        assert _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})[0] == 200
        assert _req(host, port, "GET", "/api/settings", headers={"Cookie": ck2})[0] == 401
    finally:
        stop()


def test_json_body_non_object_returns_400(tmp_path):
    # A valid-JSON-but-non-object body (list/int/str/bool/null) must yield a clean
    # 400, not an AttributeError that drops the connection with no HTTP response.
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf, "Content-Type": "application/json"}
        for bad in (b"[]", b"123", b'"x"', b"true", b"null"):
            st, _, _ = _req(host, port, "POST", "/api/settings/password",
                            raw=bad, headers=hh)
            assert st == 400, (bad, st)
        # a pre-session endpoint takes the same guard
        st, _, _ = _req(host, port, "POST", "/api/login", raw=b"[]",
                        headers={"Content-Type": "application/json"})
        assert st == 400
    finally:
        stop()


def test_devices_example_csv_download(tmp_path):
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/devices/example-csv")[0] == 401
        ck, _csrf = _auth(host, port)
        st, hd, b = _req(host, port, "GET", "/api/devices/example-csv",
                         headers={"Cookie": ck})
        assert st == 200
        assert "filename=devices-example.csv" in hd.get("Content-Disposition", "")
        assert "device_id,device_ip,management_type,iris_vlan" in b.decode()
    finally:
        stop()


def test_settings_stage_host_roundtrip(tmp_path):
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # auth: no session -> 401; session without CSRF -> 403
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "u", "password": "p"})[0] == 401
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "u", "password": "p"},
                    headers={"Cookie": ck})[0] == 403
        # starts unconfigured; GET /api/settings shows the redacted view
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["stage_host"] == {"configured": False, "username": ""}
        # validation: missing/null/non-string fields and non-object JSON -> 400
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "", "password": "p"}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "u", "password": ""}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "u", "password": None}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": 42, "password": "p"}, headers=hh)[0] == 400
        hh_json = dict(hh); hh_json["Content-Type"] = "application/json"
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    raw=b"[]", headers=hh_json)[0] == 400
        # set, then the settings view reflects it — but NEVER the password
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "svc-iris", "password": "hostpw"},
                    headers=hh)[0] == 200
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert json.loads(b)["stage_host"] == {"configured": True,
                                               "username": "svc-iris"}
        assert b"hostpw" not in b
        # clear
        st, _, b = _req(host, port, "DELETE", "/api/settings/stage-host", headers=hh)
        assert st == 200 and json.loads(b)["deleted"] is True
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert json.loads(b)["stage_host"]["configured"] is False
    finally:
        stop()


# ---- issue #13: console swarm map + device telemetry reports ----

import re

_MAP_FIXTURE = """<!DOCTYPE html>
<html><head><title>map</title>
<style>
  body { background: #000; }
</style>
</head><body>
<script>
window.IRIS_MAP_CFG = null;
const MAP = window.IRIS_MAP_CFG || {swarmUrl: "/swarm", pull: false};
</script>
</body></html>
"""

_CANNED_REPORT = {
    "ts": 1783000000, "image_id": "img1", "event": "staging-complete",
    "transfer": {"total_bytes": 1234, "elapsed_s": 60, "avg_bps": 20,
                 "sha_ok": True, "stage_state": "ready"},
    "link": {"tier": "good", "rtt_ms_median": 12, "rtt_samples": 8,
             "hb_failures": 0, "trimmed": False},
    "peers": [{"ip": "10.0.0.7", "rx_bytes": 1234, "tx_bytes": 0}],
    "agent": {"version": "x", "runtime_mode": "guestshell"},
}


def _serve_reports(tmp_path):
    """gui_server wired to a real CatalogStore (telemetry ring + pull
    directives live in JSON files under tmp_path/state)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    cat = catalog_mod.CatalogStore(str(tmp_path / "state"))
    srv = gui_server.make_server("127.0.0.1", 0, app, None, None, None, cat,
                                 certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, cat, srv.shutdown


def test_swarmmap_requires_session(tmp_path):
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        status, _, _ = _req(host, port, "GET", "/swarmmap")
        assert status == 401
    finally:
        stop()


def test_swarmmap_injects_cfg_nonce_and_csp(tmp_path, monkeypatch):
    map_path = tmp_path / "swarmmap.html"
    map_path.write_text(_MAP_FIXTURE)
    monkeypatch.setattr(gui_server, "SWARMMAP_PATH", str(map_path))
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, hd, b = _req(host, port, "GET", "/swarmmap", headers={"Cookie": ck})
        assert st == 200 and "text/html" in hd.get("Content-Type", "")
        body = b.decode()
        cfg = 'window.IRIS_MAP_CFG = {"swarmUrl":"/api/swarm","pull":true};'
        assert body.count(cfg) == 1                       # substituted exactly once
        assert "window.IRIS_MAP_CFG = null;" not in body  # placeholder consumed
        m = re.search(r'<script nonce="([^"]+)">', body)
        assert m, "script tag did not get a nonce"
        nonce = m.group(1)
        assert '<style nonce="%s">' % nonce in body
        assert hd.get("Content-Security-Policy", "") == (
            "default-src 'self'; script-src 'nonce-%s'; style-src 'nonce-%s'; "
            "connect-src 'self'; img-src 'self'" % (nonce, nonce))
        # the console embeds this page in a same-origin iframe: the global
        # DENY / frame-ancestors 'none' policy must NOT apply to this route
        assert hd.get("X-Frame-Options") != "DENY"
        assert "frame-ancestors" not in hd.get("Content-Security-Policy", "")
        # nonce is per-request: a second GET carries a different one
        _, _, b2 = _req(host, port, "GET", "/swarmmap", headers={"Cookie": ck})
        m2 = re.search(r'<script nonce="([^"]+)">', b2.decode())
        assert m2 and m2.group(1) != nonce
    finally:
        stop()


def test_swarmmap_serves_real_file_with_nonced_csp(tmp_path):
    # Against the checked-in server/swarmmap.html (single-source file). Only
    # the nonce/CSP mechanics are asserted here — the CFG substitution is
    # covered by the fixture test above, so this stays green whether or not
    # the swarmmap.html client-side task has landed yet.
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, hd, b = _req(host, port, "GET", "/swarmmap", headers={"Cookie": ck})
        assert st == 200 and "text/html" in hd.get("Content-Type", "")
        assert "script-src 'nonce-" in hd.get("Content-Security-Policy", "")
        assert b'<script nonce="' in b and b'<style nonce="' in b
    finally:
        stop()


def test_device_reports_roundtrip(tmp_path):
    host, port, cat, stop = _serve_reports(tmp_path)
    cat.record_telemetry("d1", dict(_CANNED_REPORT))
    try:
        assert _req(host, port, "GET", "/api/devices/d1/reports")[0] == 401
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices/d1/reports",
                        headers={"Cookie": ck})
        assert st == 200
        reports = json.loads(b)["reports"]
        assert len(reports) == 1
        assert reports[0]["image_id"] == "img1"
        assert reports[0]["event"] == "staging-complete"
        assert reports[0]["peers"][0]["ip"] == "10.0.0.7"
        assert "received_at" in reports[0]      # stamped by record_telemetry
        # unknown device -> empty ring, still 200
        st, _, b = _req(host, port, "GET", "/api/devices/ghost/reports",
                        headers={"Cookie": ck})
        assert st == 200 and json.loads(b)["reports"] == []
    finally:
        stop()


def test_request_report_session_csrf_and_429(tmp_path):
    host, port, cat, stop = _serve_reports(tmp_path)
    try:
        # no session -> 401; session without CSRF -> 403
        assert _req(host, port, "POST", "/api/devices/d1/request-report",
                    {})[0] == 401
        ck, csrf = _auth(host, port)
        assert _req(host, port, "POST", "/api/devices/d1/request-report",
                    {}, headers={"Cookie": ck})[0] == 403
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices/d1/request-report",
                        {}, headers=hh)
        assert st == 200
        res = json.loads(b)
        assert res["ok"] is True and res["expires_at"] > time.time()
        assert cat.pending_report("d1", time.time()) is True
        # duplicate while pending -> 429
        st, _, b = _req(host, port, "POST", "/api/devices/d1/request-report",
                        {}, headers=hh)
        assert st == 429 and json.loads(b)["error"] == "request already pending"
        # a report arriving clears the directive; a new request succeeds again
        cat.record_telemetry("d1", dict(_CANNED_REPORT))
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/request-report",
                        {}, headers=hh)
        assert st == 200
    finally:
        stop()


def test_overview_swarm_map_url_is_console_relative(tmp_path):
    host, port, stop = _serve_overview(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/overview", headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["swarm_map_url"] == "/swarmmap"
    finally:
        stop()


# ---- per-device credential profile selection ----

def test_device_credential_requires_session_and_csrf(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": "lab"})
        assert st == 401
        ck, _csrf = _auth(host, port)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": "lab"}, headers={"Cookie": ck})
        assert st == 403
    finally:
        stop()


def test_device_credential_unknown_device_404(tmp_path):
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/nope/credential",
                        {"credential_profile_id": "lab"}, headers=hh)
        assert st == 404
    finally:
        stop()


def test_device_credential_unknown_profile_400(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": "nope"}, headers=hh)
        assert st == 400
    finally:
        stop()


def test_device_credential_happy_path_preserves_other_fields(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
                     "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                     "guest_ip": "10.0.0.3"})
        creds.set_profile("lab", {"name": "Lab", "device_user": "admin",
                                  "device_pass": "pw"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": "lab"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        dev = json.loads(b)["devices"][0]
        assert dev["credential_profile_id"] == "lab"
        # other fields must survive the patch untouched
        assert dev["device_ip"] == "10.0.0.1"
        assert dev["vlan"] == "666"
        assert dev["svi_ip"] == "10.0.0.2"
        assert dev["svi_mask"] == "255.255.255.252"
        assert dev["guest_ip"] == "10.0.0.3"
    finally:
        stop()


def test_device_credential_empty_string_clears_profile(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1",
                     "credential_profile_id": "lab"})
        creds.set_profile("lab", {"name": "Lab", "device_user": "admin",
                                  "device_pass": "pw"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": ""}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        dev = json.loads(b)["devices"][0]
        assert dev.get("credential_profile_id") == ""
        assert dev["device_ip"] == "10.0.0.1"   # untouched
    finally:
        stop()


# ---- per-device platform override selection ----

def test_device_platform_requires_session_and_csrf(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": "iox"})
        assert st == 401
        ck, _csrf = _auth(host, port)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": "iox"}, headers={"Cookie": ck})
        assert st == 403
    finally:
        stop()


def test_device_platform_unknown_device_404(tmp_path):
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/nope/platform",
                        {"platform": "iox"}, headers=hh)
        assert st == 404
    finally:
        stop()


def test_device_platform_invalid_value_400(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": "bogus"}, headers=hh)
        assert st == 400
    finally:
        stop()


def test_device_platform_happy_path_and_clear(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # set iox
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": "iox"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        dev = json.loads(b)["devices"][0]
        assert dev["platform"] == "iox"
        assert dev["vlan"] == "666"          # other fields untouched
        # empty clears back to auto
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": ""}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        dev = json.loads(b)["devices"][0]
        assert dev.get("platform") == ""
    finally:
        stop()


def test_device_platform_iox_on_inband_is_allowed(tmp_path):
    """Setting platform=iox on an inband device now succeeds and persists (the
    app SSHes to the switch's management IP by default)."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "edge", "device_ip": "192.0.2.10",
                      "management_type": "inband", "inband_vlan": "120",
                      "app_ip": "192.0.2.11", "app_mask": "255.255.255.0",
                      "app_gateway": "192.0.2.1", "platform": "guestshell"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/edge/platform",
                        {"platform": "iox"}, headers=hh)
        assert st == 200
        assert fleet.get_device("edge")["platform"] == "iox"
    finally:
        stop()


# ---- audit-trail wiring: /api/audit + emission points ----

import audit as audit_mod


def _read_audit_lines(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _serve_full_audit(tmp_path):
    """_serve_full, but wired to a real audit.jsonl at tmp_path so emission
    points can be asserted against the raw file."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    audit_path = str(tmp_path / "audit.jsonl")
    images = gui_images.ImageService(state, str(tmp_path / "imgs"),
                                     tracker_url_fn=lambda: "http://t/announce?key=k",
                                     publish_fn=lambda p, s, u, **k: s.save_image(
                                         {"id": "img1", "filename": "img1.bin",
                                          "sha256": "ab", "published_at": 1}) or
                                     {"id": "img1"},
                                     import_root=str(tmp_path / "opt-images"))
    fleet = gui_fleet.FleetStore(state)
    creds = gui_creds.CredentialStore(secrets_path)
    cat = catalog_mod.CatalogStore(state)
    cat.save_image({"id": "img1", "filename": "img1.bin", "sha256": "ab",
                    "size": 3, "published_at": 1})
    cat.save_image({"id": "img2", "filename": "img2.bin", "sha256": "cd",
                    "size": 1288490188, "published_at": 2})
    srv = gui_server.make_server("127.0.0.1", 0, app, images, fleet, creds, cat,
                                 audit_path=audit_path, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, (app, fleet, creds, cat), audit_path, srv.shutdown


def test_api_audit_requires_session(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/audit")[0] == 401
    finally:
        stop()


def test_api_audit_bad_category_400(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?category=nonsense", headers={"Cookie": ck})
        assert st == 400
        assert "error" in json.loads(b)
    finally:
        stop()


def test_api_audit_happy_path_newest_first(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        audit_mod.append_event(audit_path, "e2", category="device", ts=2000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/audit", headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        # login itself emits an event, so just check relative order + presence
        evnames = [e["event"] for e in events]
        assert evnames.index("e2") < evnames.index("e1")
    finally:
        stop()


def test_api_audit_limit_cap(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        for i in range(10):
            audit_mod.append_event(audit_path, "e%d" % i, category="device",
                                   ts=1000 + i)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?limit=999999&category=device",
                        headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        assert len(events) <= 500
    finally:
        stop()


def test_api_audit_before_ts_and_category_filter(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        audit_mod.append_event(audit_path, "e2", category="image", ts=2000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?category=device", headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        assert all(e["category"] == "device" for e in events)
        assert any(e["event"] == "e1" for e in events)
    finally:
        stop()


def test_api_audit_after_ts_window(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        audit_mod.append_event(audit_path, "e2", category="device", ts=2000)
        audit_mod.append_event(audit_path, "e3", category="device", ts=3000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?category=device&after_ts=2000",
                        headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        evnames = {e["event"] for e in events}
        assert evnames == {"e2", "e3"}
    finally:
        stop()


def test_api_audit_after_ts_unparseable_ignored(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?category=device&after_ts=notanumber",
                        headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        assert any(e["event"] == "e1" for e in events)
    finally:
        stop()


# ---- audit histogram: /api/audit/histogram ----

def test_api_audit_histogram_requires_session(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/audit/histogram")[0] == 401
    finally:
        stop()


def test_api_audit_histogram_bad_category_400(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit/histogram?category=nonsense",
                        headers={"Cookie": ck})
        assert st == 400
        assert "error" in json.loads(b)
    finally:
        stop()


def test_api_audit_histogram_happy_path_shape(tmp_path, monkeypatch):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        monkeypatch.setattr(gui_server.time, "time", lambda: 10000.0)
        audit_mod.append_event(audit_path, "e1", category="device", ts=9000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit/histogram?window=1000&buckets=10&category=device",
                        headers={"Cookie": ck})
        assert st == 200
        body = json.loads(b)
        assert body["now"] == 10000
        assert len(body["buckets"]) == 10
        assert sum(bk["count"] for bk in body["buckets"]) >= 1
        assert all(set(bk) == {"start", "count"} for bk in body["buckets"])
    finally:
        stop()


def test_api_audit_histogram_defaults(tmp_path, monkeypatch):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        monkeypatch.setattr(gui_server.time, "time", lambda: 50000.0)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/audit/histogram",
                        headers={"Cookie": ck})
        assert st == 200
        body = json.loads(b)
        assert len(body["buckets"]) == 30  # default buckets
        assert body["now"] == 50000
    finally:
        stop()


def test_api_audit_histogram_buckets_capped(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit/histogram?buckets=99999",
                        headers={"Cookie": ck})
        assert st == 200
        body = json.loads(b)
        assert len(body["buckets"]) == 200
    finally:
        stop()


def test_login_failure_and_success_emit_audit(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        st, _, _ = _req(host, port, "POST", "/api/login",
                        {"username": "admin", "password": "wrong"})
        assert st == 401
        st, _, _ = _req(host, port, "POST", "/api/login",
                        {"username": "admin", "password": "pw"})
        assert st == 200
        lines = _read_audit_lines(audit_path)
        auth_events = [e for e in lines if e.get("category") == "auth"]
        fail = [e for e in auth_events if e["result"] == "fail"]
        ok = [e for e in auth_events if e["result"] == "ok"
              and e.get("action") == "login"]
        assert fail and fail[0]["src_ip"] == "127.0.0.1"
        assert fail[0]["detail"] == "invalid credentials"
        assert ok and ok[0]["actor"] == "console:admin"
    finally:
        stop()


def test_device_assign_credential_and_request_report_emit_audit(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "img1"}, headers=hh)
        assert st == 200
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": ""}, headers=hh)
        assert st == 200
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/request-report",
                        {}, headers=hh)
        assert st == 200
        lines = _read_audit_lines(audit_path)
        cats = [e.get("category") for e in lines]
        assert "device" in cats
        assert "telemetry" in cats
        assign_events = [e for e in lines if e.get("category") == "device"
                         and e.get("action") == "assign"]
        assert assign_events and assign_events[0]["target"] == "d1"
        # detail names the image (filename + size + retrievable id), not a bare id
        assert assign_events[0]["detail"] == "assigned img1.bin (3 B) id=img1"
        cred_events = [e for e in lines if e.get("action") == "credential"]
        assert cred_events[0]["detail"] == "profile (none) -> (cleared)"
        report_events = [e for e in lines if e.get("category") == "telemetry"]
        assert report_events[0]["detail"] == \
            "fresh telemetry report requested (valid 10m)"
    finally:
        stop()


def test_device_assign_detail_notes_previous_image(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        assert _req(host, port, "POST", "/api/devices/d1/assign",
                    {"image_id": "img1"}, headers=hh)[0] == 200
        assert _req(host, port, "POST", "/api/devices/d1/assign",
                    {"image_id": "img2"}, headers=hh)[0] == 200
        assigns = [e for e in _read_audit_lines(audit_path)
                   if e.get("action") == "assign"]
        assert assigns[-1]["detail"] == \
            "assigned img2.bin (1.2 GiB) id=img2, was img1.bin"
    finally:
        stop()


def test_stage_host_set_emits_without_password_in_file(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/settings/stage-host",
                        {"username": "svc-iris", "password": "supersecretpw"},
                        headers=hh)
        assert st == 200
        raw = open(audit_path).read()
        assert "supersecretpw" not in raw
        lines = _read_audit_lines(audit_path)
        settings_events = [e for e in lines if e.get("category") == "settings"]
        # the username belongs in detail (before -> after); target is the key
        ev = [e for e in settings_events if e.get("event") == "stage_host_set"]
        assert ev and ev[0]["target"] == "stage-host"
        assert ev[0]["detail"] == "user (none) -> svc-iris"
    finally:
        stop()


def test_audit_emission_failure_does_not_break_route(tmp_path, monkeypatch):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        monkeypatch.setattr(audit_mod, "append_event",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        assert st == 200
    finally:
        stop()


# ---- audit histogram: explicit since_ts/until_ts window (timeline brush) ----

def test_api_audit_histogram_since_until_window(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        audit_mod.append_event(audit_path, "e2", category="device", ts=2000)
        audit_mod.append_event(audit_path, "e3", category="device", ts=3000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit/histogram?since_ts=1500&until_ts=3500"
                        "&buckets=2&category=device",
                        headers={"Cookie": ck})
        assert st == 200
        body = json.loads(b)
        assert body["bucket_seconds"] == 1000.0
        assert [bk["start"] for bk in body["buckets"]] == [1500, 2500]
        assert [bk["count"] for bk in body["buckets"]] == [1, 1]  # e2, e3; not e1
    finally:
        stop()


def test_api_audit_histogram_until_not_after_since_400(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        for q in ("since_ts=100&until_ts=100", "since_ts=200&until_ts=100"):
            st, _, b = _req(host, port, "GET", "/api/audit/histogram?" + q,
                            headers={"Cookie": ck})
            assert st == 400
            assert "error" in json.loads(b)
    finally:
        stop()


def test_api_audit_histogram_single_bound_falls_back_to_window(tmp_path,
                                                               monkeypatch):
    """since_ts/until_ts only define the window when BOTH are present (and
    parseable); otherwise the window=<secs>-ending-now behavior applies."""
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        monkeypatch.setattr(gui_server.time, "time", lambda: 10000.0)
        audit_mod.append_event(audit_path, "old", category="device", ts=500)
        audit_mod.append_event(audit_path, "recent", category="device", ts=9500)
        ck, _csrf = _auth(host, port)
        for q in ("since_ts=1&", "until_ts=9600&", "since_ts=abc&until_ts=def&"):
            st, _, b = _req(host, port, "GET",
                            "/api/audit/histogram?%swindow=1000&buckets=10"
                            "&category=device" % q,
                            headers={"Cookie": ck})
            assert st == 200
            body = json.loads(b)
            assert body["bucket_seconds"] == 100.0
            assert body["buckets"][0]["start"] == 9000
            assert sum(bk["count"] for bk in body["buckets"]) == 1  # 'recent' only
    finally:
        stop()


def test_api_audit_histogram_default_window_bucket_seconds(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/audit/histogram",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["bucket_seconds"] == 604800 / 30
    finally:
        stop()


# ---- enriched emissions: operator-readable details (issue #19) ----

def test_fmt_bytes():
    f = gui_server._fmt_bytes
    assert f(3) == "3 B"
    assert f(12 * 1024) == "12 KiB"
    assert f(356515840) == "340 MiB"
    assert f(1288490188) == "1.2 GiB"
    assert f(None) == "?"          # audit details must never raise
    assert f("garbage") == "?"


def test_setup_emits_enriched_audit(tmp_path):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)          # no admin yet -> needs_setup
    audit_path = str(tmp_path / "audit.jsonl")
    srv = gui_server.make_server("127.0.0.1", 0, app, audit_path=audit_path,
                                 certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st, _, _ = _req("127.0.0.1", port, "POST", "/api/setup",
                        {"username": "root", "password": "pw12345678"})
        assert st == 200
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "setup"][0]
        assert ev["target"] == "root"
        assert ev["detail"] == "initial admin account created"
        assert ev["src_ip"] == "127.0.0.1"
    finally:
        srv.shutdown()


def test_auth_ops_emit_enriched_audit(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)     # session A
        _auth(host, port)                # session B (to be revoked)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/settings/password",
                        {"current": "wrong", "new": "newpass123",
                         "confirm": "newpass123"}, headers=hh)
        assert st == 400
        st, _, _ = _req(host, port, "POST", "/api/settings/password",
                        {"current": "pw", "new": "newpass123",
                         "confirm": "newpass123"}, headers=hh)
        assert st == 200
        st, _, _ = _req(host, port, "POST",
                        "/api/settings/sessions/revoke-others", {}, headers=hh)
        assert st == 200
        st, _, _ = _req(host, port, "POST", "/api/logout", {}, headers=hh)
        assert st == 200
        lines = _read_audit_lines(audit_path)
        by_event = {}
        for e in lines:
            by_event.setdefault(e["event"], e)
        assert by_event["password_change_fail"]["detail"] == \
            "current password incorrect"
        assert by_event["password_change_fail"]["src_ip"] == "127.0.0.1"
        assert by_event["password_change"]["detail"] == \
            "password changed; 1 other session(s) revoked"
        assert by_event["password_change"]["src_ip"] == "127.0.0.1"
        assert by_event["revoke_other_sessions"]["detail"] == \
            "revoked 0 other session(s)"
        assert by_event["logout"]["src_ip"] == "127.0.0.1"
    finally:
        stop()


def test_stage_host_update_and_clear_details(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/settings/stage-host",
             {"username": "svc-a", "password": "stagepw1"}, headers=hh)
        _req(host, port, "POST", "/api/settings/stage-host",
             {"username": "svc-b", "password": "stagepw2"}, headers=hh)
        _req(host, port, "DELETE", "/api/settings/stage-host", headers=hh)
        _req(host, port, "DELETE", "/api/settings/stage-host", headers=hh)
        sets = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "stage_host_set"]
        clears = [e for e in _read_audit_lines(audit_path)
                  if e.get("event") == "stage_host_clear"]
        assert [e["detail"] for e in sets] == \
            ["user (none) -> svc-a", "user svc-a -> svc-b"]
        assert [e["detail"] for e in clears] == \
            ["cleared (was user svc-b)", "nothing was configured"]
        assert all(e["target"] == "stage-host" for e in sets + clears)
        raw = open(audit_path).read()
        assert "stagepw1" not in raw and "stagepw2" not in raw
    finally:
        stop()


def test_device_upsert_create_and_update_details(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
              "model": "C9300"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "model": "IE-3400"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "model": "IE-3400"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.9", "vlan": "777",
              "svi_ip": "1.1.1.1", "guest_ip": "2.2.2.2"}, headers=hh)
        ups = [e for e in _read_audit_lines(audit_path)
               if e.get("event") == "device_upsert"]
        assert [e["action"] for e in ups] == \
            ["create", "update", "update", "update"]
        assert ups[0]["detail"] == "ip 10.0.0.1, vlan 666, model C9300"
        assert ups[1]["detail"] == "changed model: C9300 -> IE-3400"
        assert ups[2]["detail"] == "no fields changed"
        # 4 changed fields -> first 3 alphabetically + a (+1 more) suffix
        assert ups[3]["detail"] == ("changed device_ip: 10.0.0.1 -> 10.0.0.9, "
                                    "guest_ip: (none) -> 2.2.2.2, "
                                    "svi_ip: (none) -> 1.1.1.1 (+1 more)")
    finally:
        stop()


def test_csv_import_route_stats_and_detail(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.9"}, headers=hh)
        csv_in = ("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n"
                  "# comment\n"
                  "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3\n"
                  "d2,10.0.0.5,777,10.0.0.6,255.255.255.252,10.0.0.7\n")
        st, _, b = _req(host, port, "POST", "/api/devices/import-csv",
                        headers=dict(hh, **{"Content-Type": "text/csv"}),
                        raw=csv_in.encode())
        assert st == 200
        body = json.loads(b)
        assert body == {"imported": 2, "new": 1, "updated": 1, "skipped": 2}
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "device_csv_import"][0]
        assert ev["detail"] == \
            "imported 2 devices (1 new, 1 updated; 2 rows skipped)"
    finally:
        stop()


def test_device_delete_details_ok_and_fail(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        assert _req(host, port, "DELETE", "/api/devices/d1", headers=hh)[0] == 200
        assert _req(host, port, "DELETE", "/api/devices/d1", headers=hh)[0] == 200
        dels = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "device_delete"]
        assert dels[0]["result"] == "ok"
        assert dels[0]["detail"] == "removed (ip 10.0.0.1, model -)"
        # deleting a device that never existed is a FAIL, not a phantom ok
        assert dels[1]["result"] == "fail"
        assert dels[1]["detail"] == "no such device"
    finally:
        stop()


def test_credential_profile_set_and_delete_details(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/credentials",
             {"id": "lab", "name": "Lab", "device_user": "admin",
              "device_pass": "supersecretpw"}, headers=hh)
        _req(host, port, "POST", "/api/credentials",
             {"id": "lab", "name": "Lab2", "device_user": "admin",
              "device_pass": "supersecretpw"}, headers=hh)
        assert _req(host, port, "DELETE", "/api/credentials/lab",
                    headers=hh)[0] == 200
        assert _req(host, port, "DELETE", "/api/credentials/lab",
                    headers=hh)[0] == 200
        lines = _read_audit_lines(audit_path)
        sets = [e for e in lines if e.get("event") == "credential_profile_set"]
        dels = [e for e in lines
                if e.get("event") == "credential_profile_delete"]
        assert [e["action"] for e in sets] == ["create", "update"]
        assert sets[0]["detail"] == "name 'Lab', device user admin"
        assert dels[0]["result"] == "ok"
        assert dels[0]["detail"] == "removed profile 'Lab2'"
        assert dels[1]["result"] == "fail"
        assert dels[1]["detail"] == "no such profile"
        assert "supersecretpw" not in open(audit_path).read()
    finally:
        stop()


def test_image_delete_details_and_blocked_emission(tmp_path):
    host, port, ctx, audit_path, stop = _serve_full_audit(tmp_path)
    _app, fleet, _creds, _cat = ctx
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        assert _req(host, port, "POST", "/api/devices/d1/assign",
                    {"image_id": "img1"}, headers=hh)[0] == 200
        # blocked delete (409) must leave an audit trace, not stay silent
        assert _req(host, port, "DELETE", "/api/images/img1",
                    headers=hh)[0] == 409
        fleet.delete("d1")                 # stale policy no longer blocks
        assert _req(host, port, "DELETE", "/api/images/img1",
                    headers=hh)[0] == 200
        dels = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "image_delete"]
        assert dels[0]["result"] == "fail"
        assert dels[0]["detail"] == "blocked: assigned to 1 device(s): d1"
        assert dels[1]["result"] == "ok"
        assert dels[1]["detail"] == "deleted img1.bin (3 B)"
    finally:
        stop()


def test_image_upload_success_detail_names_publish_job(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf,
              "Content-Type": "application/octet-stream"}
        st, _, b = _req(host, port, "PUT", "/api/images/upload/new.bin",
                        headers=hh, raw=b"xyz")
        assert st == 200
        job_id = json.loads(b)["job_id"]
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "image_upload"][0]
        assert ev["target"] == "new.bin"
        assert ev["detail"] == "3 B uploaded, publish job %s started" % job_id
    finally:
        stop()


def test_image_upload_oversized_emits_fail_audit(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        s = _socket.create_connection((host, port), timeout=5)
        head = ("PUT /api/images/upload/huge.bin HTTP/1.0\r\nHost: x\r\n"
                "Cookie: %s\r\nX-CSRF-Token: %s\r\n"
                "Content-Length: 4294967297\r\n\r\n" % (ck, csrf)).encode()
        s.sendall(head)                    # declares >4 GiB; sends nothing
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        assert b" 413 " in resp.split(b"\r\n", 1)[0]
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "image_upload"][0]
        assert ev["result"] == "fail"
        assert ev["target"] == "huge.bin"
        assert ev["detail"] == "rejected: oversized (cap 4 GiB)"
    finally:
        stop()


def test_source_guard_monitoring_nav_and_view():
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="nav-monitoring"' in html
    assert 'id="view-monitoring"' in html
    assert "System" in html
    assert 'id="audit-load-older"' in html
    assert "Load older" in html
    assert 'id="audit-category"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'monitoring'" in js
    assert "refreshMonitoring" in js
    assert "audit-load-older" in js
    assert "audit-category" in js
