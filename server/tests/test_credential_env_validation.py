# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Invalid subprocess environment values must be refused before persistence."""
import json
from pathlib import Path

import pytest

import gui_creds
import test_gui_server as gui
import test_audit_export as audit


def test_device_environment_fields_refuse_nul_without_persistence(tmp_path):
    path = tmp_path / "secrets.json"
    creds = gui_creds.CredentialStore(str(path))
    valid = {"name": "Synthetic", "device_user": "user", "device_pass": "secret", "enable_secret": "enable"}
    creds.set_profile("existing", valid)
    before = path.read_bytes()
    for field in ("device_user", "device_pass", "enable_secret"):
        for identity in ("existing", "new"):
            with pytest.raises(ValueError, match="NUL"):
                creds.set_profile(identity, dict(valid, **{field: "synthetic\0invalid"}))
            assert path.read_bytes() == before


def test_audit_store_refuses_invalid_types_and_nul_without_persistence(tmp_path):
    path = tmp_path / "secrets.json"
    creds = gui_creds.CredentialStore(str(path))
    creds.set_audit_export_secret("old-password")
    before = path.read_bytes()
    for value in ({"synthetic": True}, ["synthetic"], True, 7, None, "", "synthetic\0invalid"):
        with pytest.raises(ValueError):
            creds.set_audit_export_secret(value)
        assert path.read_bytes() == before


def test_valid_environment_credentials_preserve_exact_non_nul_characters(tmp_path):
    creds = gui_creds.CredentialStore(str(tmp_path / "secrets.json"))
    value = "  unicode-å '\"$=\\\n\t  "
    creds.set_profile("valid", {"name": "Synthetic", "device_user": "synthetic-user",
                                "device_pass": value, "enable_secret": None})
    assert creds.get_secrets("valid")["device_pass"] == value
    assert creds.get_secrets("valid")["enable_secret"] == ""
    creds.set_profile("valid", {"name": "Synthetic", "device_user": value,
                                "device_pass": value, "enable_secret": value})
    assert all(creds.get_secrets("valid")[field] == value
               for field in ("device_user", "device_pass", "enable_secret"))
    creds.set_audit_export_secret(value)
    assert creds.audit_export_secrets()["password"] == value
    creds.set_audit_export_secret("   ")
    assert creds.audit_export_secrets()["password"] == "   "


def test_device_api_nul_refusal_preserves_existing_and_does_not_create(tmp_path):
    host, port, (_, _, creds, _), stop = gui._serve_full(tmp_path)
    try:
        cookie, csrf = gui._auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        valid = {"id": "existing", "name": "Synthetic", "device_user": "synthetic-user",
                 "device_pass": "synthetic-password", "enable_secret": "synthetic-enable"}
        assert gui._req(host, port, "POST", "/api/credentials", valid, headers)[0] == 200
        before = Path(creds.secrets_path).read_bytes()
        for field in ("device_user", "device_pass", "enable_secret"):
            for identity in ("existing", "new"):
                body = dict(valid, id=identity, **{field: "synthetic\0invalid"})
                status, _, response = gui._req(host, port, "POST", "/api/credentials", body, headers)
                assert status == 400
                assert "synthetic" not in json.loads(response)["error"]
                assert Path(creds.secrets_path).read_bytes() == before
        assert creds.get_secrets("new") is None
    finally:
        stop()


def test_audit_api_invalid_secret_refuses_before_settings_disable(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, creds, audit_path, stop = audit._serve_export(tmp_path)
    try:
        cookie, csrf = audit._auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        assert audit._req(host, port, "POST", "/api/settings/audit-export",
                          audit._cfg_body(auto=False), headers)[0] == 200
        settings = tmp_path / "state/audit-export-settings.json"
        paths = (settings, Path(creds.secrets_path), Path(audit_path))
        before = [path.read_bytes() for path in paths]
        for value in ("synthetic\0invalid", {"synthetic": True}, ["synthetic"], 7, True):
            status, _, response = audit._req(host, port, "POST", "/api/settings/audit-export",
                audit._cfg_body(host="changed.example.invalid", password=value, auto=False), headers)
            assert status == 400
            assert "synthetic" not in json.loads(response)["error"]
            assert [path.read_bytes() for path in paths] == before
        assert creds.audit_export_secrets()["password"] == "scp-pw"
    finally:
        stop()
