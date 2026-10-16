# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Invalid OTLP URL ports must be refused before an override is saved."""
import management_api
import test_gui_server as gui


def test_otlp_malformed_or_overflow_port_is_refused_without_new_port_policy():
    for port in ("bad", "65536", "-1", "1.5"):
        normalized, error = management_api._validate_otlp_endpoint("https://collector.invalid:" + port)
        assert normalized is None and error
    for authority in ("collector.invalid", "collector.invalid:443", "collector.invalid:4318",
                      "collector.invalid:0", "[2001:db8::1]:4318"):
        endpoint = "https://" + authority + "/base"
        assert management_api._validate_otlp_endpoint("  " + endpoint + "/// ") == (endpoint, None)
    assert management_api._validate_otlp_endpoint("http://collector.invalid:4318") == (
        "http://collector.invalid:4318", None)


def test_otlp_api_bad_ports_refuse_before_creating_or_replacing_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _, stop = gui._serve_full(tmp_path)
    try:
        cookie, csrf = gui._auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        path = tmp_path / "state/telemetry-destination.json"
        for initialized in (False, True):
            if initialized:
                assert gui._req(host, port, "POST", "/api/settings/telemetry-destination",
                    {"endpoint": "https://unchanged.invalid:4318", "enabled": False}, headers)[0] == 200
            before = path.read_bytes() if initialized else None
            for value in ("https://collector.invalid:bad", "https://collector.invalid:65536"):
                status, _, _ = gui._req(host, port, "POST", "/api/settings/telemetry-destination",
                    {"endpoint": value, "enabled": False}, headers)
                assert status == 400
                assert (path.read_bytes() if path.exists() else None) == before
    finally:
        stop()
