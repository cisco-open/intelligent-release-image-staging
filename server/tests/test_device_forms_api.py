# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run the shipped form serializers through the real Console/management API.

The Console's local browser hop is HTTP; its management hop verifies the fixture
CA over HTTPS. Inventory-only writes, temporary stores, no device connections.
"""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

import catalog
import gui_app
import gui_creds
import gui_fleet
import gui_server
import management_api
from test_api_split import _certificate, _request, _thread, _write_secret


@pytest.mark.parametrize("management,model,platform", [
    ("routed", "C9xxx", "guestshell"),
    ("inband", "C9xxx", "iox"),
    ("router-routed", "C8xxx", "router"),
    ("router-nat", "C8xxx", "iox"),
    ("xr-host", "XR8000", "xr-appmgr"),
])
def test_form_serializers_roundtrip_through_authenticated_console(
        tmp_path, monkeypatch, request, management, model, platform):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required to run the shipped form serializer")
    module = (Path(__file__).resolve().parents[1]
              / "console-ui/src/device-forms-model.mjs").as_uri()
    form = {"id": "form-device", "ip": "192.0.2.10", "model": model,
            "management": management, "platform": platform,
            "credential": "operator", "vlan": "100", "svi": "198.51.100.1",
            "guest": "198.51.100.2", "mask": "255.255.255.0",
            "gateway": "198.51.100.1", "vpg": "0", "nat": "GigabitEthernet1"}
    serialized = subprocess.run([node, "--input-type=module", "-e", """
      import {deviceBody, credentialBody} from %s;
      console.log(JSON.stringify({device: deviceBody(%s), credential: credentialBody({
        id: 'operator', name: 'Operators', user: 'admin', password: 'fixture-secret',
        confirm: 'fixture-secret', enable: 'fixture-enable'
      })}));
    """ % (json.dumps(module), json.dumps(form))],
        capture_output=True, text=True, check=True, timeout=10)
    bodies = json.loads(serialized.stdout)

    secret_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secret_path)
    app.set_admin("admin", "fixture-login")
    fleet = gui_fleet.FleetStore(str(tmp_path / "state"))
    creds = gui_creds.CredentialStore(secret_path)
    store = catalog.CatalogStore(str(tmp_path / "state"))
    cert, key = _certificate(tmp_path, "forms")
    token = tmp_path / "management-token"
    _write_secret(token, "f" * 64)

    def start(server):
        thread = _thread(server)

        def stop():
            try:
                server.shutdown()
            finally:
                server.server_close()
                thread.join(timeout=3)

        request.addfinalizer(stop)
        return server

    backend = start(management_api.make_server(
        "127.0.0.1", 0, app, fleet=fleet, creds=creds, catalog=store,
        certfile=str(cert), keyfile=str(key), management_token_file=str(token)))
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    console = start(gui_server.make_server(
        "127.0.0.1", 0, "https://localhost:%d" % backend.server_address[1],
        str(token), str(cert)))
    port = console.server_address[1]
    status, login_headers, raw = _request(
        port, "/api/v1/login", "POST", {"Content-Type": "application/json"},
        json.dumps({"username": "admin", "password": "fixture-login"}))
    assert status == 200, raw
    headers = {"Cookie": login_headers["Set-Cookie"].split(";", 1)[0],
               "X-CSRF-Token": json.loads(raw)["csrf"],
               "Content-Type": "application/json"}
    for path, body in (("/api/v1/credentials", bodies["credential"]),
                       ("/api/v1/devices", bodies["device"])):
        # Neither an unauthenticated caller nor a session without CSRF may save.
        assert _request(port, path, "POST", body=json.dumps(body))[0] == 401
        assert _request(port, path, "POST", {"Cookie": headers["Cookie"]},
                        json.dumps(body))[0] == 403
        status, _, raw = _request(port, path, "POST", headers, json.dumps(body))
        assert status == 200, raw
        assert b"fixture-secret" not in raw and b"fixture-enable" not in raw
        saved = json.loads(raw)
        if path.endswith("credentials"):
            assert saved["profile"] == {"id": "operator", "name": "Operators", "device_user": "admin"}
        else:
            assert saved["device"]["device_id"] == "form-device"
            assert saved["device"]["management_type"] == management
            assert saved["device"]["platform"] == platform
    assert fleet.get_device("form-device")["credential_profile_id"] == "operator"
    status, _, raw = _request(port, "/api/v1/credentials", headers=headers)
    assert status == 200 and json.loads(raw)["profiles"][0]["id"] == "operator"
    assert b"fixture-secret" not in raw and b"fixture-enable" not in raw
    for deleted in (True, False):
        status, _, raw = _request(port, "/api/v1/credentials/operator", "DELETE", headers)
        assert status == 200 and json.loads(raw) == {"deleted": deleted}
