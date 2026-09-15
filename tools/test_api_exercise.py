# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("api_exercise", Path(__file__).with_name("api-exercise.py"))
exercise = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exercise)


def test_summary_distinguishes_successful_capacity_from_errors():
    records = [{"status": status, "seconds": seconds} for status, seconds in
               [(200, .01), (200, .02), (429, .03), (503, .04), (0, .05)]]
    result = exercise.summary(records, 2)
    assert result["requests_per_second"] == 2.5
    assert result["successful_per_second"] == 1
    assert result["statuses"] == {"200": 2, "429": 1, "503": 1, "0": 1}
    assert result["p95_ms"] == 50


def test_empty_summary_does_not_invent_latency():
    assert exercise.summary([], 0)["p50_ms"] is None


def test_multistatus_is_not_a_clean_success():
    result = exercise.summary([{"status": 207, "seconds": .1}], .1)
    assert result["successful"] == 0
    assert result["partial_responses"] == 1


def test_client_refuses_plaintext_and_path_base():
    import pytest
    for base in ("http://localhost", "https://localhost/api"):
        with pytest.raises(ValueError):
            exercise.Client(base, None)


@pytest.mark.parametrize("base", [
    "https://", "https://user:example-password@example.invalid",
    "https://user@example.invalid", "https://example.invalid?token=example",
    "https://example.invalid#secret",
])
def test_client_rejects_non_origin_and_secret_bearing_base_before_tls(base, monkeypatch):
    def forbidden(**kwargs):
        pytest.fail("Invalid origins must be rejected before reading TLS inputs")
    monkeypatch.setattr(exercise.ssl, "create_default_context", forbidden)
    with pytest.raises(ValueError, match="HTTPS origin") as error:
        exercise.Client(base, None)
    assert base not in str(error.value)


def test_pacer_spaces_starts_without_catch_up(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(exercise.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(exercise.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    pacer = exercise.Pacer(20)
    pacer.wait()
    pacer.wait()
    assert clock[0] == .05
    clock[0] = 100
    pacer.wait()
    pacer.wait()
    assert clock[0] == 100.05


@pytest.mark.parametrize("extra", [[], ["--mutate", "--devices", "11", "--concurrency", "1"],
                                  ["--mutate", "--devices", "1", "--concurrency", "1,4"]])
def test_existing_inventory_requires_small_serial_mutation(monkeypatch, extra):
    monkeypatch.setattr(exercise.sys, "argv", ["api-exercise", "--base", "https://example.invalid",
        "--cafile", "unused", "--password-file", "unused", "--output", "unused",
        "--allow-existing-inventory", *extra])
    with pytest.raises(SystemExit) as exc:
        exercise.main()
    assert exc.value.code == 2


@pytest.mark.parametrize('get_failure,delete_status', [(False, 200), (True, 200), (False, 207)])
def test_small_smoke_preserves_existing_inventory_and_reports_failures(monkeypatch, tmp_path, get_failure, delete_status):
    import json
    import sys
    from types import SimpleNamespace

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.cookie = 'session'
            self.csrf = ''
            self.records = []
            self.devices = {'owner-device'}
            self.deleted = []
            self.logged_out = False

        def request(self, method, path, body=None, phase='coverage', **kwargs):
            status, response = 200, {}
            if path == '/api/v1/login':
                response = {'csrf': 'fixture'}
            elif path == '/api/v1/logout':
                self.logged_out = True
            elif self.logged_out:
                status = 401
            elif path == '/api/v1/failure':
                status = 503 if get_failure else 200
            elif method == 'POST' and path == '/api/v1/devices':
                self.devices.add(body['device_id'])
            elif method == 'DELETE':
                did = path.rsplit('/', 1)[-1]
                self.deleted.append(did)
                self.devices.remove(did)
                status = delete_status
            elif path.startswith('/api/v1/devices'):
                response = {'devices': [{'device_id': did} for did in sorted(self.devices)]}
            self.records.append({'method': method, 'path': path, 'phase': phase,
                                 'status': status, 'seconds': .01})
            return status, response

        def call(self, *args, expected=(200,), **kwargs):
            status, response = self.request(*args, **kwargs)
            assert status in expected
            return status, response

    client = FakeClient()
    monkeypatch.setattr(exercise, 'Client', lambda *args, **kwargs: client)
    monkeypatch.setattr(exercise, 'ROUTES', [SimpleNamespace(service='console', method='GET',
        path='/api/v1/failure', security='none')])
    monkeypatch.setattr(exercise, 'match', lambda *args: None)
    fixture_calls = []
    def fixtures(client, did, prefix):
        fixture_calls.append(did)
        assert did != 'owner-device'
        return {'checks': []}
    monkeypatch.setitem(sys.modules, 'api_exercise_fixtures', SimpleNamespace(exercise=fixtures))
    password = tmp_path / 'password'
    password.write_text('fixture-only')
    output = tmp_path / 'report.json'
    monkeypatch.setattr(sys, 'argv', ['api-exercise', '--base', 'https://example.invalid',
        '--cafile', 'unused', '--password-file', str(password), '--output', str(output),
        '--mutate', '--allow-existing-inventory', '--devices', '3', '--concurrency', '1',
        '--seconds', '.01', '--max-requests', '1'])
    assert exercise.main() == (1 if get_failure or delete_status == 207 else 0)
    report = json.loads(output.read_text())
    assert client.devices == {'owner-device'}
    assert set(client.deleted) == set(report['owned_device_ids'])
    assert len(fixture_calls) == 1
    assert report['existing_devices_preserved'] is True
    assert report['remaining_owned_devices'] == []
    assert report['logout_verified'] is True
    assert 'fixture-only' not in output.read_text()
