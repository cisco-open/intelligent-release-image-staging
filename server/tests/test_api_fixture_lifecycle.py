# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Native fixture teardown cannot leave a handler using the next test's globals."""

import socket
import ssl
import threading
import time

import pytest

import gui_server
import management_api
from test_api_split import _NoSessionApp, _certificate, _fixture_server, _request, _write_secret


def fixture_server(tmp_path, monkeypatch, kind):
    cert, key = _certificate(tmp_path, 'fixture-lifetime')
    token = tmp_path / 'tier-token'
    _write_secret(token, 'fixture-only-' + 't' * 64)
    monkeypatch.setenv('IRIS_GUI_ALLOW_PLAINTEXT', '1')
    monkeypatch.setenv('IRIS_STATE', str(tmp_path / 'state'))
    monkeypatch.setenv('IRIS_CONFIG', str(tmp_path / 'config'))
    if kind.startswith('management'):
        server = management_api.make_server('127.0.0.1', 0, _NoSessionApp(),
            certfile=str(cert), keyfile=str(key), management_token_file=str(token))
    else:
        combined = tmp_path / 'console.pem'
        combined.write_bytes(cert.read_bytes() + key.read_bytes())
        combined.chmod(0o600)
        server = gui_server.make_server('127.0.0.1', 0,
            'https://127.0.0.1:1', str(token), str(cert),
            certfile=str(combined) if kind == 'console-tls' else None)
    return server, cert


def wait_for_request(server):
    deadline = time.monotonic() + 2
    while not server._request_lifecycle_state()['active']:
        assert time.monotonic() < deadline, 'Native fixture did not accept the test connection'
        time.sleep(0.01)


@pytest.mark.parametrize('kind', ['console', 'console-tls', 'management-tls', 'management-handshake'])
def test_fixture_closes_delayed_native_request_before_next_test_globals(
        tmp_path, monkeypatch, kind):
    server, cert = fixture_server(tmp_path, monkeypatch, kind)
    finalizers = []
    class Request:
        addfinalizer = staticmethod(finalizers.append)
    listener = _fixture_server(server, Request())
    client = socket.create_connection(server.server_address, timeout=3)
    client.settimeout(3)
    try:
        if kind.endswith('-tls'):
            client = ssl.create_default_context(cafile=str(cert)).wrap_socket(
                client, server_hostname='localhost')
        if kind != 'management-handshake':
            client.sendall(b'GET /api/v1/settings HTTP/1.0\r\nHost:')
        wait_for_request(server)
        finalizers.pop()()
        state = server._test_listener_fixture
        assert not listener.is_alive() and server.socket.fileno() == -1
        assert not server._request_lifecycle_state()['active']
        assert not state.sockets and not any(t.is_alive() for t in state.workers)
        calls = []
        monkeypatch.setattr(gui_server, '_tls_client_context', lambda *_args: calls.append(True))
        try:
            client.sendall(b' localhost\r\n\r\n')
            assert client.recv(4096) == b''
        except OSError:
            pass  # Already-closed plain/TLS sockets may reject the attempted send.
        assert calls == []
        server.server_close()  # Repeated explicit/finalizer cleanup is harmless.
    finally:
        client.close()
        for stop in finalizers:
            stop()
        server.server_close()


def test_native_fixture_normal_reply_and_repeated_close(tmp_path, monkeypatch):
    server, _ = fixture_server(tmp_path, monkeypatch, 'console')
    finalizers = []
    class Request:
        addfinalizer = staticmethod(finalizers.append)
    listener = _fixture_server(server, Request())
    assert _request(server.server_address[1], '/healthz')[0] == 200
    finalizers.pop()()
    server.server_close()
    state = server._test_listener_fixture
    assert state.closed and not state.sockets
    assert not listener.is_alive() and all(not t.is_alive() for t in state.workers)


def test_native_fixture_failed_listener_start_closes_before_reraise(tmp_path, monkeypatch):
    server, _ = fixture_server(tmp_path, monkeypatch, 'console')
    finalizers = []
    class Request:
        addfinalizer = staticmethod(finalizers.append)
    failure = RuntimeError('fixture-only start failure')
    monkeypatch.setattr(threading.Thread, 'start', lambda _self: (_ for _ in ()).throw(failure))
    with pytest.raises(RuntimeError) as caught:
        _fixture_server(server, Request())
    assert caught.value is failure and server.socket.fileno() == -1
    assert len(finalizers) == 1
    finalizers.pop()()
    assert server._test_listener_fixture.closed


def test_native_fixture_handler_failure_is_not_reported_as_surviving_worker(tmp_path, monkeypatch):
    server, _ = fixture_server(tmp_path, monkeypatch, 'console')
    finalizers = []
    class Request:
        addfinalizer = staticmethod(finalizers.append)
    listener = _fixture_server(server, Request())
    server._request_lifecycle_state()['failed'] = True
    with pytest.raises(AssertionError, match='owned workers and sockets were drained'):
        finalizers.pop()()
    state = server._test_listener_fixture
    assert state.closed and not state.sockets and not listener.is_alive()
    assert not server._request_lifecycle_state()['active']
    server.server_close()


def test_native_fixture_stops_session_if_owned_handler_cannot_be_drained(tmp_path, monkeypatch):
    server, _ = fixture_server(tmp_path, monkeypatch, 'console')
    finalizers = []
    class Request:
        addfinalizer = staticmethod(finalizers.append)
    entered, release = threading.Event(), threading.Event()
    original = server.RequestHandlerClass.do_GET

    def held_handler(handler):
        entered.set()
        assert release.wait(timeout=5), 'fixture release was not signaled'
        original(handler)

    monkeypatch.setattr(server.RequestHandlerClass, 'do_GET', held_handler)
    listener = _fixture_server(server, Request())
    state = server._test_listener_fixture
    state.drain_seconds = 0.05
    client = socket.create_connection(server.server_address, timeout=3)
    try:
        client.sendall(b'GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n')
        assert entered.wait(timeout=2)
        with pytest.raises(pytest.exit.Exception, match='Owned native fixture workers survived') as stopped:
            finalizers.pop()()
        assert stopped.value.returncode == 1
        assert server.socket.fileno() == -1 and not state.sockets
        assert any(worker.is_alive() for worker in state.workers)
        # This regression catches the exit solely to release its controlled
        # handler. Real fixtures must not continue into the next test.
    finally:
        release.set()
        client.close()
        assert server.drain_requests(timeout=3)
        state.drain_seconds = 2
        server.server_close()
        for stop in finalizers:
            stop()
    assert not listener.is_alive() and all(not t.is_alive() for t in state.workers)
