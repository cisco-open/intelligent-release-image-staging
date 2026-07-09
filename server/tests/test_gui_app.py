# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import gui_app
import gui_auth
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
