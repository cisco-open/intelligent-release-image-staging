# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import http.client
import os
import threading
import time
from urllib.parse import quote_from_bytes

import bencode
import peer_handouts
import pytest
import secrets_store
import tracker

import tracker_announce


def test_resolve_derives_https_url_with_default_or_configured_port():
    assert tracker_announce.resolve({"IRIS_HOST_IP": "100.64.0.1"}) == \
        "https://100.64.0.1:6969/announce"
    assert tracker_announce.resolve({
        "IRIS_HOST_IP": "10.1.2.3",
        "IRIS_TRACKER_PORT": "7443",
    }) == "https://10.1.2.3:7443/announce"


def test_configured_url_takes_precedence_and_normalizes_empty_path():
    env = {
        "IRIS_TRACKER_ANNOUNCE": "https://8.8.8.8:7443",
        "IRIS_HOST_IP": "10.1.2.3",
        "IRIS_TRACKER_PORT": "6969",
    }
    assert tracker_announce.resolve(env) == \
        "https://8.8.8.8:7443/announce"


def test_empty_configured_url_falls_back_to_host_and_default_port():
    assert tracker_announce.resolve({
        "IRIS_TRACKER_ANNOUNCE": "",
        "IRIS_HOST_IP": "192.168.5.4",
        "IRIS_TRACKER_PORT": "",
    }) == "https://192.168.5.4:6969/announce"


def test_resolve_uses_process_environment(monkeypatch):
    monkeypatch.setenv("IRIS_TRACKER_ANNOUNCE", "https://8.8.4.4/announce")
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.1")
    assert tracker_announce.resolve() == "https://8.8.4.4/announce"


@pytest.mark.parametrize("host", [
    "100.64.0.1",       # RFC 6598 shared address space
    "10.1.2.3",         # private address space
    "192.168.5.4",      # private address space
    "203.0.113.9",      # routed documentation prefix
    "8.8.8.8",          # public address space
])
def test_validate_accepts_same_routable_ipv4_classes_as_rotation(host):
    url = "https://%s:6969/announce" % host
    assert tracker_announce.validate(url) == url


@pytest.mark.parametrize("host", [
    "127.0.0.1",
    "169.254.1.1",
    "0.0.0.0",
    "224.0.0.1",
    "240.0.0.1",
    "::1",
    "tracker.example.com",
])
def test_validate_refuses_nonusable_or_nonnumeric_hosts(host):
    if ":" in host:
        host = "[%s]" % host
    with pytest.raises(ValueError, match="^invalid tracker announce URL$"):
        tracker_announce.validate("https://%s:6969/announce" % host)


@pytest.mark.parametrize("url", [
    "http://8.8.8.8:6969/announce",
    "ftp://8.8.8.8:6969/announce",
    "//8.8.8.8:6969/announce",
    "https://user@8.8.8.8:6969/announce",
    "https://user:password@8.8.8.8:6969/announce",
    "https://8.8.8.8:6969/announce?token=value",
    "https://8.8.8.8:6969/announce?",
    "https://8.8.8.8:6969/announce#fragment",
    "https://8.8.8.8:6969/announce#",
    "https://8.8.8.8:6969/other",
    "https://8.8.8.8:6969/announce/",
    " https://8.8.8.8:6969/announce",
    "https://8.8.8.8:6969/announce\n",
])
def test_validate_requires_token_free_https_announce_endpoint(url):
    with pytest.raises(ValueError, match="^invalid tracker announce URL$"):
        tracker_announce.validate(url)


@pytest.mark.parametrize("port", ["", "0", "65536", "abc", "-1", "٦٩٦٩"])
def test_validate_refuses_invalid_explicit_ports(port):
    with pytest.raises(ValueError, match="^invalid tracker announce URL$"):
        tracker_announce.validate(
            "https://8.8.8.8:%s/announce" % port)


def test_validate_normalizes_numeric_port_and_empty_path():
    assert tracker_announce.validate("https://8.8.8.8:06969") == \
        "https://8.8.8.8:6969/announce"


def test_resolve_requires_a_configured_url_or_host():
    with pytest.raises(ValueError, match="^tracker announce URL unavailable$"):
        tracker_announce.resolve({})


def test_validation_errors_never_echo_misconfigured_credentials():
    secret = "do-not-echo-this-value"
    url = "https://operator:%s@8.8.8.8/announce?token=%s" % (
        secret, secret)
    with pytest.raises(ValueError) as error:
        tracker_announce.validate(url)
    assert secret not in str(error.value)
    assert url not in str(error.value)


def test_task13_behavioral_red_tracker_refuses_unrecorded_selected_peers(
        tmp_path):
    info_hash = quote_from_bytes(hashlib.sha1(b"task13-red").digest())
    secrets_path = str(tmp_path / "secrets.json")
    store = secrets_store.load(secrets_path)
    device_token = secrets_store.mint(
        store, "device-1", "announce_token", time.time())
    service_token = secrets_store.mint(
        store, "seeder", "announce_token", time.time())
    secrets_store.save(store, secrets_path)
    failures = []

    def refuse_handout(*_args, **_kwargs):
        failures.append(True)
        raise OSError("injected durable handout failure")

    server = tracker.make_server(
        "127.0.0.1", 0, secrets_path,
        handout_path=str(tmp_path / "peer-handouts.json"),
        record_handout=refuse_handout,
        scrape_authorizer=lambda *_: True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    def announce(token, peer_id, peer_port, extra=""):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        path = ("/announce?info_hash=%s&peer_id=%s&port=%s&left=0"
                "&announce_token=%s%s" %
                (info_hash, peer_id, peer_port, token, extra))
        conn.request("GET", path)
        response = conn.getresponse()
        body = bencode.decode(response.read())
        conn.close()
        return response.status, body

    try:
        assert announce(service_token, "origin", 6881,
                        "&ip=10.0.0.2&numwant=0")[0] == 200
        status, body = announce(
            device_token, "requester", 0, "&numwant=1&compact=0")
        assert status == 200
        assert failures == [True]
        assert body[b"peers"] == []
    finally:
        server.shutdown()
        server.server_close()


def test_task13_main_wires_state_handout_path_through_real_construction(
        tmp_path, monkeypatch):
    state = tmp_path / "state"
    certificate = tmp_path / "cert.pem"
    certificate.write_text("disposable")
    monkeypatch.setenv("IRIS_STATE", str(state))
    monkeypatch.setenv("IRIS_CERT", str(certificate))
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "secrets.json"))

    class Hub:
        registry = tracker.PeerRegistry()
        export_health = type("Health", (), {"as_dict": lambda self: {}})()

        def start(self):
            calls.append("hub-start")

        def note_announce(self):
            pass

        def note_announce_refused(self, **_kwargs):
            pass

        def emit_policy_event(self, *_args, **_kwargs):
            pass

    class Reconciler:
        _pending = object()

        def wake(self):
            pass

        def start(self):
            calls.append("reconciler-start")

    class Server:
        def serve_forever(self):
            calls.append("serve")

    calls = []
    captured = {}
    monkeypatch.setattr(tracker.telemetry, "from_env", lambda: Hub())
    monkeypatch.setattr(tracker.telemetry, "metrics_port", lambda: None)
    monkeypatch.setattr(tracker, "_start_pruner", lambda _registry: None)
    monkeypatch.setattr(
        tracker, "_build_reconciler_from_env",
        lambda *_args, **_kwargs: Reconciler())

    def construction_boundary(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return Server()

    monkeypatch.setattr(tracker, "make_server", construction_boundary)
    tracker.main()
    assert captured["kwargs"]["handout_path"] == os.path.join(
        str(state), "peer-handouts.json")
    assert calls == ["hub-start", "reconciler-start", "serve"]


@pytest.mark.parametrize("request_port", [0, 65536, 6882],
                         ids=["zero-port", "high-port", "registered-peer"])
@pytest.mark.parametrize("compact", [0, 1], ids=["dictionary", "compact"])
def test_task13_both_tracker_selection_branches_and_encodings_are_covered(
        tmp_path, request_port, compact):
    info_bytes = hashlib.sha1(b"task13-real-path").digest()
    info_hash = quote_from_bytes(info_bytes)
    info_hex = info_bytes.hex()
    secrets_path = str(tmp_path / "secrets.json")
    handout_path = str(tmp_path / "peer-handouts.json")
    peer_handouts.initialize(handout_path)
    store = secrets_store.load(secrets_path)
    device_token = secrets_store.mint(
        store, "device-1", "announce_token", time.time())
    service_token = secrets_store.mint(
        store, "seeder", "announce_token", time.time())
    secrets_store.save(store, secrets_path)
    server = tracker.make_server(
        "127.0.0.1", 0, secrets_path, handout_path=handout_path,
        scrape_authorizer=lambda *_: True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    def request(token, peer_id, peer_port, suffix=""):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", ("/announce?info_hash=%s&peer_id=%s&port=%s"
                             "&left=0&announce_token=%s%s" %
                             (info_hash, peer_id, peer_port, token, suffix)))
        response = conn.getresponse()
        value = bencode.decode(response.read())
        conn.close()
        return response.status, value

    try:
        assert request(service_token, "origin", 6881,
                       "&ip=10.0.0.2&numwant=0")[0] == 200
        status, body = request(
            device_token, "requester", request_port,
            "&numwant=1&compact=%d" % compact)
        assert status == 200
        if compact:
            assert body[b"peers"] == bytes((10, 0, 0, 2, 0x1a, 0xe1))
        else:
            assert body[b"peers"][0][b"ip"] == b"10.0.0.2"
        rows = peer_handouts.current_handouts(
            handout_path, "device-1", time.time())
        assert [(row["address"], row["info_hash"])
                for row in rows] == [("10.0.0.2", info_hex)]
    finally:
        server.shutdown()
        server.server_close()


def test_task13_zero_numwant_and_service_requesters_do_not_write_handouts(
        tmp_path):
    info_hash = quote_from_bytes(hashlib.sha1(b"task13-bypass").digest())
    secrets_path = str(tmp_path / "secrets.json")
    store = secrets_store.load(secrets_path)
    device_token = secrets_store.mint(
        store, "device-1", "announce_token", time.time())
    service_token = secrets_store.mint(
        store, "seeder", "announce_token", time.time())
    secrets_store.save(store, secrets_path)
    calls = []
    server = tracker.make_server(
        "127.0.0.1", 0, secrets_path, handout_path=str(tmp_path / "ledger.json"),
        record_handout=lambda *args: calls.append(args) or True,
        scrape_authorizer=lambda *_: True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    def request(token, peer_id, peer_port, suffix=""):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", ("/announce?info_hash=%s&peer_id=%s&port=%s"
                             "&left=0&announce_token=%s%s" %
                             (info_hash, peer_id, peer_port, token, suffix)))
        response = conn.getresponse()
        response.read()
        conn.close()

    try:
        request(service_token, "origin", 6881, "&ip=10.0.0.2&numwant=0")
        request(device_token, "device", 6882, "&numwant=0")
        request(service_token, "origin-2", 6883, "&ip=10.0.0.3&numwant=2")
        assert calls == []
    finally:
        server.shutdown()
        server.server_close()


def test_task13_socket_failure_after_persistence_keeps_disclosure_evidence(
        tmp_path):
    info_bytes = hashlib.sha1(b"task13-socket-failure").digest()
    info_hash = quote_from_bytes(info_bytes)
    secrets_path = str(tmp_path / "secrets.json")
    handout_path = str(tmp_path / "peer-handouts.json")
    peer_handouts.initialize(handout_path)
    store = secrets_store.load(secrets_path)
    device_token = secrets_store.mint(
        store, "device-1", "announce_token", time.time())
    service_token = secrets_store.mint(
        store, "seeder", "announce_token", time.time())
    secrets_store.save(store, secrets_path)
    server = tracker.make_server(
        "127.0.0.1", 0, secrets_path, handout_path=handout_path,
        scrape_authorizer=lambda *_: True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    def request(token, peer_id, peer_port, suffix=""):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", (
            "/announce?info_hash=%s&peer_id=%s&port=%s&left=0"
            "&announce_token=%s%s" %
            (info_hash, peer_id, peer_port, token, suffix)))
        response = connection.getresponse()
        body = response.read()
        connection.close()
        return body

    try:
        request(service_token, "origin", 6881,
                "&ip=10.0.0.2&numwant=0")

        def disconnect(handler, *_args, **_kwargs):
            handler.connection.shutdown(2)
            handler.connection.close()

        server.RequestHandlerClass._send = disconnect
        with pytest.raises((http.client.RemoteDisconnected, OSError)):
            request(device_token, "requester", 0, "&numwant=1&compact=1")
        rows = peer_handouts.current_handouts(
            handout_path, "device-1", time.time())
        assert [(row["address"], row["info_hash"])
                for row in rows] == [("10.0.0.2", info_bytes.hex())]
    finally:
        server.shutdown()
        server.server_close()
