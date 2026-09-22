# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import gui_admin
import gui_auth
import secrets_store
import pytest


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


@pytest.mark.parametrize("recipients", ["age1test", ""])
@pytest.mark.parametrize("damaged_runtime", [False, True])
def test_reset_without_runtime_store_preserves_ciphertext(
        tmp_path, monkeypatch, capsys, recipients, damaged_runtime):
    """compose run has an empty tmpfs but mounts the existing ciphertext."""
    plain = tmp_path / "secrets.json"
    encrypted = tmp_path / "secrets.json.age"
    encrypted.write_bytes(b"existing encrypted device credentials")
    if damaged_runtime:
        plain.write_bytes(b"invalid runtime store")
    monkeypatch.setenv("IRIS_SECRETS", str(plain))
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(encrypted))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", recipients)
    monkeypatch.setenv("IRIS_GUI_ADMIN_PASSWORD", "do-not-print")

    def forbidden_write(*args, **kwargs):
        pytest.fail("a reset with no live store must never persist")

    monkeypatch.setattr(gui_admin.gui_app.secretfs, "persist_store", forbidden_write)
    assert gui_admin.main(["admin"]) == 1
    assert encrypted.read_bytes() == b"existing encrypted device credentials"
    if damaged_runtime:
        assert plain.read_bytes() == b"invalid runtime store"
    else:
        assert not plain.exists()
    output = capsys.readouterr()
    assert "running server" in output.err
    assert "do-not-print" not in output.out + output.err


def test_reset_preserves_existing_device_credentials(tmp_path, monkeypatch):
    plain = tmp_path / "secrets.json"
    secrets_store.save({
        "devices": {"switch-a": {"token": "existing-device-token"}},
        "seeder": {"token": "existing-seeder-token"}}, str(plain))
    monkeypatch.setenv("IRIS_SECRETS", str(plain))
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "secrets.json.age"))
    monkeypatch.delenv("IRIS_AGE_RECIPIENTS", raising=False)
    monkeypatch.setenv("IRIS_GUI_ADMIN_PASSWORD", "new-password")
    assert gui_admin.main(["admin"]) == 0
    store = secrets_store.load(str(plain))
    assert store["devices"]["switch-a"]["token"] == "existing-device-token"
    assert store["seeder"]["token"] == "existing-seeder-token"
    assert gui_auth.verify_admin(store, "admin", "new-password")
