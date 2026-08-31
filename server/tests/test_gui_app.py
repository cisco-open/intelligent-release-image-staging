# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import os

import gui_app
import gui_auth
import gui_server
import secrets_store


def _app(tmp_path):
    # no recipients_csv -> persistence uses secrets_store.save (no age needed)
    secrets_path = str(tmp_path / "secrets.json")
    return gui_app.GuiApp(secrets_path), secrets_path


def test_set_admin_persists_to_disk(tmp_path):
    app, secrets_path = _app(tmp_path)
    app.set_admin("admin", "pw")
    reloaded = secrets_store.load(secrets_path)
    assert gui_auth.verify_admin(reloaded, "admin", "pw") is True


def test_login_success_and_session_info(tmp_path):
    app, _ = _app(tmp_path)
    app.set_admin("admin", "pw")
    res = app.login("admin", "pw")
    assert res is not None
    sid, csrf = res
    info = app.session_info(sid)
    assert info == {"username": "admin", "csrf": csrf}


def test_login_wrong_password_returns_none(tmp_path):
    app, _ = _app(tmp_path)
    app.set_admin("admin", "pw")
    assert app.login("admin", "bad") is None
    assert app.login("admin", "pw") is not None


def test_logout_invalidates_session(tmp_path):
    app, _ = _app(tmp_path)
    app.set_admin("admin", "pw")
    sid, _ = app.login("admin", "pw")
    app.logout(sid)
    assert app.session_info(sid) is None


def test_needs_setup(tmp_path):
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    assert app.needs_setup() is True          # no admin yet
    app.set_admin("admin", "pw")
    assert app.needs_setup() is False          # admin exists


def test_set_admin_encrypted_path_threads_recipients(tmp_path, monkeypatch):
    calls = {}

    def fake_persist(store, plain_path, recipients_csv=None, enc_path=None):
        calls["recipients_csv"] = recipients_csv
        calls["enc_path"] = enc_path
        secrets_store.save(store, plain_path)  # still persist so nothing is lost

    monkeypatch.setattr(gui_app.secretfs, "persist_store", fake_persist)
    enc = str(tmp_path / "secrets.json.age")
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"),
                         recipients_csv="age1example", secrets_enc=enc)
    app.set_admin("admin", "pw")
    assert calls["recipients_csv"] == "age1example"
    assert calls["enc_path"] == enc
    # and the credential is actually usable afterward
    reloaded = secrets_store.load(str(tmp_path / "secrets.json"))
    assert gui_auth.verify_admin(reloaded, "admin", "pw") is True


def test_change_password(tmp_path):
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "oldpassw")
    assert app.change_password("wrong", "newpassw") is False   # bad current
    assert app.login("admin", "oldpassw") is not None          # unchanged
    assert app.change_password("oldpassw", "newpassw") is True
    assert app.login("admin", "oldpassw") is None              # old rejected
    assert app.login("admin", "newpassw") is not None          # new accepted


def test_session_helpers(tmp_path):
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "oldpassw")
    r1 = app.login("admin", "oldpassw"); r2 = app.login("admin", "oldpassw")
    assert app.active_sessions() == 2
    assert app.idle_ttl_minutes() == 30                        # default 1800s
    assert app.revoke_other_sessions(r1[0]) == 1               # drops r2's session
    assert app.session_info(r1[0]) is not None
    assert app.session_info(r2[0]) is None


# ---------------------------------------------------------------------------
# Facelift Task 10: single-owner polling. Devices used to be refreshed by
# two independent 10s loops -- scheduleDevices(), a self-perpetuating
# setTimeout chain started once, unconditionally, for the page's lifetime
# regardless of which hash-routed view was on screen; and the hash router's
# view-scoped startViewPoll(), which already knew to poll only while Devices
# was the visible view. Both called refreshDevices() every ~10s while
# Devices was on screen -- redundant, unsynchronized traffic. The router is
# now the sole owner of visible-view polling, Devices included.
# ---------------------------------------------------------------------------

def _app_js():
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        return f.read()


def test_devices_polling_has_a_single_owner():
    js = _app_js()
    # the standalone loop is gone outright, not just disconnected
    assert "function scheduleDevices" not in js
    assert "scheduleDevices()" not in js
    # the router's setInterval is the only interval-based poll mechanism in
    # the console -- no second timer reintroduced under another name
    assert js.count("setInterval(") == 1
    # the devices refresh is now wired into the router as its named poll fn
    assert "function pollDevices() {" in js
    assert "poll = pollDevices;" in js


def test_devices_poll_wrapper_keeps_the_focused_row_and_error_guards():
    """The retired scheduleDevices() never redrew #dev-rows while the
    operator's focus was inside it (would yank an open dropdown/select out
    from under a mid-edit operator), and surfaced a failed refresh via
    devStatus rather than failing silently. Both guards must survive inside
    the function the router now polls Devices with."""
    js = _app_js()
    fn = js.split("function pollDevices() {", 1)[1].split("\n  }", 1)[0]
    assert "document.activeElement" in fn
    assert "a.closest('#dev-rows')" in fn
    assert "refreshDevices()" in fn
    assert "Device refresh unavailable; retrying" in fn


def test_devices_poll_wrapper_is_the_devices_view_poll_fn():
    """The guard is not just present somewhere -- it has to be the actual
    function the router arms via startViewPoll() for the devices view."""
    js = _app_js()
    show_fn = js.split("function show(view) {", 1)[1].split("\n  }", 1)[0]
    assert "poll = pollDevices;" in show_fn
    assert "startViewPoll(poll)" in show_fn


def test_overview_refresh_has_generation_and_abort_protection():
    """Task 7 review carry: refreshOverview()'s triple-fetch
    (/api/overview + /api/devices + /api/images) had no generation/abort
    protection, unlike refreshDevices() (which already guards a stale
    response against clobbering a newer one via a generation counter and an
    AbortController). Folding Devices' poll into the router alongside
    Overview's under one owner makes overlapping refreshOverview() calls
    (a racing visibilitychange-return and interval tick, or a rapid
    nav-away-and-back) a real possibility, so it needs the same guard."""
    js = _app_js()
    assert "overviewRefreshGeneration" in js
    fn = js.split("async function refreshOverview() {", 1)[1].split("\n  }", 1)[0]
    assert "overviewRefreshGeneration" in fn
    assert "overviewRefreshController" in fn
    assert "new AbortController()" in fn
    assert "AbortError" in fn
    # the pre-existing honesty behaviors (Task 7) must survive unchanged
    assert "failed: true" in fn
    assert "dbody.failed || imgsBody.failed" in fn
    assert "renderOverviewAttention(devs, devNow, imgs, fleetDataUnavailable)" in fn
