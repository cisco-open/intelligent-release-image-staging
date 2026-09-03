# server/tests/test_gui_creds.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import gui_creds
import secrets_store


def _cs(tmp_path):
    # no recipients -> plaintext persist (secretfs degrades); fine for tests
    return gui_creds.CredentialStore(str(tmp_path / "secrets.json"))


def test_set_list_get_delete(tmp_path):
    cs = _cs(tmp_path)
    assert cs.list_profiles() == []
    cs.set_profile("lab", {"name": "Lab default", "device_user": "admin",
                           "device_pass": "s3cret", "enable_secret": "en"})
    # list NEVER returns secrets
    listed = cs.list_profiles()
    assert listed == [{"id": "lab", "name": "Lab default", "device_user": "admin"}]
    # get_secrets returns the full record (server-side only, for onboarding)
    full = cs.get_secrets("lab")
    assert full["device_pass"] == "s3cret" and full["enable_secret"] == "en"
    assert cs.delete("lab") is True
    assert cs.list_profiles() == []
    assert cs.get_secrets("lab") is None


def test_set_requires_fields(tmp_path):
    cs = _cs(tmp_path)
    for bad in ({}, {"name": "x"}, {"name": "x", "device_user": "u"}):
        try:
            cs.set_profile("p", bad)
            assert False
        except ValueError:
            pass


def test_persists_encrypted_path(tmp_path, monkeypatch):
    calls = {}

    def fake_persist(store, plain_path, recipients_csv=None, enc_path=None):
        calls["recipients"] = recipients_csv
        secrets_store.save(store, plain_path)

    monkeypatch.setattr(gui_creds.secretfs, "persist_store", fake_persist)
    cs = gui_creds.CredentialStore(str(tmp_path / "secrets.json"),
                                   recipients_csv="age1x", secrets_enc="/enc.age")
    cs.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    assert calls["recipients"] == "age1x"
    # stored under the credential_profiles key, alongside other store sections
    store = secrets_store.load(str(tmp_path / "secrets.json"))
    assert "lab" in store["credential_profiles"]


def test_stage_host_set_get_clear(tmp_path):
    cs = _cs(tmp_path)
    # unset: redacted view says unconfigured, server-side accessor returns None
    assert cs.get_stage_host() == {"configured": False, "username": ""}
    assert cs.stage_host_secrets() is None
    cs.set_stage_host("svc-iris", "hostpw")
    # redacted view NEVER contains the password
    assert cs.get_stage_host() == {"configured": True, "username": "svc-iris"}
    full = cs.stage_host_secrets()
    assert full["username"] == "svc-iris" and full["password"] == "hostpw"
    assert cs.clear_stage_host() is True
    assert cs.clear_stage_host() is False
    assert cs.get_stage_host() == {"configured": False, "username": ""}
    assert cs.stage_host_secrets() is None


def test_stage_host_requires_fields(tmp_path):
    cs = _cs(tmp_path)
    for user, pw in (("", "p"), ("   ", "p"), ("u", "")):
        try:
            cs.set_stage_host(user, pw)
            assert False
        except ValueError:
            pass


def test_stage_host_persists_encrypted_path(tmp_path, monkeypatch):
    calls = {}

    def fake_persist(store, plain_path, recipients_csv=None, enc_path=None):
        calls["recipients"] = recipients_csv
        secrets_store.save(store, plain_path)

    monkeypatch.setattr(gui_creds.secretfs, "persist_store", fake_persist)
    cs = gui_creds.CredentialStore(str(tmp_path / "secrets.json"),
                                   recipients_csv="age1x", secrets_enc="/enc.age")
    cs.set_stage_host("u", "p")
    assert calls["recipients"] == "age1x"
    # stored under the top-level stage_host key, alongside other store sections
    store = secrets_store.load(str(tmp_path / "secrets.json"))
    assert store["stage_host"]["username"] == "u"


def test_audit_export_secret_set_get_clear(tmp_path):
    cs = _cs(tmp_path)
    # unset: server-side accessor returns None
    assert cs.audit_export_secrets() is None
    # the setter only ever reports the flag, never the password
    assert cs.set_audit_export_secret("exportpw") == {"password_set": True}
    full = cs.audit_export_secrets()
    assert full["password"] == "exportpw" and full["updated_at"] > 0
    assert cs.clear_audit_export_secret() is True
    assert cs.clear_audit_export_secret() is False
    assert cs.audit_export_secrets() is None


def test_audit_export_secret_requires_password(tmp_path):
    cs = _cs(tmp_path)
    for bad in ("", None):
        try:
            cs.set_audit_export_secret(bad)
            assert False
        except ValueError:
            pass


def test_audit_export_secret_persists_encrypted_path(tmp_path, monkeypatch):
    calls = {}

    def fake_persist(store, plain_path, recipients_csv=None, enc_path=None):
        calls["recipients"] = recipients_csv
        secrets_store.save(store, plain_path)

    monkeypatch.setattr(gui_creds.secretfs, "persist_store", fake_persist)
    cs = gui_creds.CredentialStore(str(tmp_path / "secrets.json"),
                                   recipients_csv="age1x", secrets_enc="/enc.age")
    cs.set_audit_export_secret("p")
    assert calls["recipients"] == "age1x"
    # stored under the top-level audit_export key, alongside other sections
    store = secrets_store.load(str(tmp_path / "secrets.json"))
    assert store["audit_export"]["password"] == "p"


def test_set_rejects_non_string_values(tmp_path):
    """IRIS-01-007: values land in a subprocess environment (strings only);
    reject other JSON types at save time, like the stage-host route does."""
    cs = _cs(tmp_path)
    import pytest
    for bad in ({"name": "x", "device_user": "u", "device_pass": 123},
                {"name": ["x"], "device_user": "u", "device_pass": "p"},
                {"name": "x", "device_user": {"u": 1}, "device_pass": "p"},
                {"name": "x", "device_user": "u", "device_pass": "p",
                 "enable_secret": 42}):
        with pytest.raises(ValueError):
            cs.set_profile("p", bad)
    assert cs.list_profiles() == []
    cs.set_profile("p", {"name": "x", "device_user": "u", "device_pass": "p",
                         "enable_secret": None})
    assert cs.get_secrets("p")["enable_secret"] == ""
