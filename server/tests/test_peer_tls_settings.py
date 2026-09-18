# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Persistent peer mode, admission safety, and authenticated UI/API control."""
import json
import threading
import time
from types import SimpleNamespace

import pytest
import gui_app
import management_api
import peer_tls_settings as settings
from test_gui_server import _auth, _req


@pytest.fixture
def paths(tmp_path, monkeypatch):
    monkeypatch.setenv('IRIS_CONFIG', str(tmp_path / 'config'))
    monkeypatch.setenv('IRIS_RUN', str(tmp_path / 'run'))
    monkeypatch.delenv('IRIS_PEER_TLS_MODE', raising=False)
    return tmp_path


def test_mode_default_override_and_corruption(paths, monkeypatch):
    assert settings.mode() == 'disabled'
    monkeypatch.setenv('IRIS_PEER_TLS_MODE', 'required')
    assert settings.mode() == 'required'
    settings.save('disabled')
    assert settings.mode() == 'disabled'
    assert settings.settings_path().stat().st_mode & 0o777 == 0o600
    settings.settings_path().write_text('{broken')
    with pytest.raises(ValueError):
        settings.mode()


def test_stale_origin_status_is_not_running(paths):
    settings.atomic_json(settings.status_path(), {
        'active_mode': 'required', 'state': 'running', 'updated_at': time.time()-60})
    assert settings.origin_status() == {'active_mode': None, 'state': 'unavailable'}


def test_onboarding_admission_waits_for_mode_transaction():
    entered = threading.Event()
    @settings.serialized
    def admit():
        entered.set()
    with settings.LOCK:
        thread = threading.Thread(target=admit)
        thread.start()
        assert not entered.wait(.05)
    thread.join(2)
    assert entered.is_set()


def test_peer_tls_api_auth_guard_conflict_and_persistence(paths, monkeypatch):
    active = []
    jobs = []
    records = SimpleNamespace(list=lambda strict=False: active)
    fleet = SimpleNamespace(list_devices=lambda: [{"device_id": "edge-1"}])
    onboard = SimpleNamespace(list_jobs=lambda: jobs)
    app = gui_app.GuiApp(str(paths / 'secrets.json'))
    app.set_admin('admin', 'pw')
    server = management_api.make_server('127.0.0.1', 0, app, onboard=onboard,
                                        record_store=records, fleet=fleet, certfile=None)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    prepares = []
    monkeypatch.setattr(management_api.peer_tls_issuer.Issuer, 'prepare', lambda self: prepares.append(True))
    settings.atomic_json(settings.status_path(), {
        'active_mode': 'disabled', 'state': 'running', 'updated_at': time.time()})
    payload = {'mode': 'required', 'expected_mode': 'disabled'}
    try:
        assert _req(host, port, 'GET', '/api/settings/peer-tls')[0] == 401
        assert _req(host, port, 'POST', '/api/settings/peer-tls', payload)[0] == 401
        cookie, csrf = _auth(host, port)
        assert _req(host, port, 'POST', '/api/settings/peer-tls', payload, headers={'Cookie': cookie})[0] == 403
        headers = {'Cookie': cookie, 'X-CSRF-Token': csrf}
        active.append({'device_id': 'edge-1', 'state': 'verified'})
        assert _req(host, port, 'POST', '/api/settings/peer-tls', payload, headers=headers)[0] == 409
        assert settings.mode() == 'disabled' and not prepares
        active[:] = [{'device_id': 'deleted-device', 'state': 'unknown'}]
        code, _, body = _req(host, port, 'GET', '/api/settings/peer-tls', headers=headers)
        assert code == 200 and json.loads(body)['active_devices'] == 0
        assert json.loads(body)['can_change'] is True
        jobs.append({'state': 'queued'})
        assert _req(host, port, 'POST', '/api/settings/peer-tls', payload, headers=headers)[0] == 409
        jobs.clear()
        code, _, body = _req(host, port, 'POST', '/api/settings/peer-tls', payload, headers=headers)
        assert code == 200, body
        response = json.loads(body)
        assert response['mode'] == 'required' and response['applied'] is True
        assert response['origin']['active_mode'] == 'disabled', 'Desired mode must not fake observed state'
        assert settings.mode() == 'required' and prepares == [True]
        assert _req(host, port, 'POST', '/api/settings/peer-tls', payload, headers=headers)[0] == 409
        assert _req(host, port, 'POST', '/api/settings/peer-tls', {'mode': 'disabled', 'expected_mode': 'required'}, headers=headers)[0] == 200
        assert settings.mode() == 'disabled'
    finally:
        server.shutdown()
        server.server_close()


def test_missing_inventory_cannot_enable_mode(paths):
    settings.atomic_json(settings.status_path(), {
        'active_mode': 'disabled', 'state': 'running', 'updated_at': time.time()})
    records = SimpleNamespace(list=lambda strict=False: [])
    onboard = SimpleNamespace(list_jobs=lambda: [])
    assert settings.describe(records, onboard)['can_change'] is False


def test_inventory_read_failure_does_not_treat_fleet_as_empty(paths):
    def broken():
        raise OSError('inventory unavailable')
    with pytest.raises(OSError):
        settings.describe(SimpleNamespace(list=lambda strict=False: []),
                          SimpleNamespace(list_jobs=lambda: []),
                          SimpleNamespace(list_devices=broken))
