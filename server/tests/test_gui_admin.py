# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import gui_admin
import gui_auth
import secrets_store


def test_gui_admin_sets_password_from_env(tmp_path, monkeypatch):
    secrets_path = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", secrets_path)
    monkeypatch.setenv("IRIS_GUI_ADMIN_PASSWORD", "pw123")
    monkeypatch.delenv("IRIS_AGE_RECIPIENTS", raising=False)

    rc = gui_admin.main(["admin"])
    assert rc == 0

    store = secrets_store.load(secrets_path)
    assert gui_auth.verify_admin(store, "admin", "pw123") is True


def test_gui_admin_usage_error(tmp_path):
    assert gui_admin.main([]) == 2


def test_gui_admin_rejects_empty_password(tmp_path, monkeypatch):
    import getpass
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "secrets.json"))
    monkeypatch.setenv("IRIS_GUI_ADMIN_PASSWORD", "")
    monkeypatch.delenv("IRIS_AGE_RECIPIENTS", raising=False)
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: "")
    assert gui_admin.main(["admin"]) == 1


def test_gui_admin_reset_stamps_session_floor(tmp_path, monkeypatch):
    """IRIS-01-003: the break-glass CLI must invalidate the console's live
    sessions; the only channel to another process is the store record."""
    secrets_path = str(tmp_path / "secrets.json")
    monkeypatch.setenv("IRIS_SECRETS", secrets_path)
    monkeypatch.setenv("IRIS_GUI_ADMIN_PASSWORD", "pw123")
    monkeypatch.delenv("IRIS_AGE_RECIPIENTS", raising=False)
    import time
    before = int(time.time())
    assert gui_admin.main(["admin"]) == 0
    store = secrets_store.load(secrets_path)
    assert gui_auth.sessions_not_before(store) >= before
