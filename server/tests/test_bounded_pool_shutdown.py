# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shutdown completion includes daemon request writers and admission races."""

import threading
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import ssl

import pytest

import bounded_pool


class Server(bounded_pool.BoundedThreadingMixin):
    daemon_threads = True
    block_on_close = True

    def __init__(self, callback):
        self.callback = callback
        self.closed = []

    def process_request_thread(self, request, address):
        self.callback()

    def close_request(self, request):
        self.closed.append(request)


def test_daemon_request_writer_must_complete_before_clean_drain():
    started, release = threading.Event(), threading.Event()
    def write():
        started.set()
        release.wait()
    server = Server(write)
    server.process_request('request', None)
    try:
        assert started.wait(2)
        assert not server.drain_requests(timeout=0.01)
        server.process_request('new request', None)
        assert server.closed == ['new request']
    finally:
        release.set()
    assert server.drain_requests(timeout=2)


def test_failed_request_callback_never_gets_clean_proof(capsys):
    def write():
        raise RuntimeError('private fixture exception')
    server = Server(write)
    server.process_request('request', None)
    assert not server.drain_requests(timeout=2)
    assert 'private fixture exception' not in capsys.readouterr().err


def test_interrupted_thread_start_retains_uncertain_admission(monkeypatch):
    class Interrupted(BaseException):
        pass
    monkeypatch.setattr(bounded_pool.threading.Thread, 'start', lambda self: (_ for _ in ()).throw(Interrupted()))
    server = Server(lambda: None)
    with pytest.raises(Interrupted):
        server.process_request('request', None)
    assert not server.drain_requests(timeout=0.01)


def test_failed_thread_creation_releases_capacity_but_retains_failure(monkeypatch):
    monkeypatch.setattr(bounded_pool.threading.Thread, 'start', lambda self: (_ for _ in ()).throw(RuntimeError('unavailable')))
    server = Server(lambda: None)
    with pytest.raises(RuntimeError):
        server.process_request('request', None)
    assert not server.drain_requests(timeout=0)
    assert not server._request_lifecycle_state()['active']


def test_closing_fence_is_rechecked_after_semaphore_wait():
    server = Server(lambda: pytest.fail('request admitted after fence'))
    class Semaphore:
        released = False
        def acquire(self, **kwargs):
            server.stop_request_admission()
            return True
        def release(self):
            self.released = True
    semaphore = Semaphore()
    server.__dict__['_admission_semaphore'] = semaphore
    server.process_request('request', None)
    assert server.closed == ['request'] and semaphore.released
    assert server.drain_requests(timeout=0)


@pytest.mark.parametrize('error,clean', [
    (OSError(errno.ENOSPC, 'private filesystem path'), False),
    (RuntimeError('private request payload'), False),
    (TimeoutError('private filesystem operation'), False),
    (BrokenPipeError('peer disconnected'), True),
    (ConnectionResetError('peer disconnected'), True),
    (ConnectionAbortedError('peer disconnected'), True),
    (ssl.SSLEOFError('peer disconnected'), True),
    (ssl.SSLZeroReturnError('peer disconnected'), True),
])
def test_stdlib_swallowed_handler_failure_is_in_shutdown_proof(error, clean, capsys):
    started = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            started.set()
            raise error
        def log_message(self, *args):
            pass
    class HTTPServer(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
        daemon_threads = True
    server = HTTPServer(('127.0.0.1', 0), Handler)
    acceptor = threading.Thread(target=server.handle_request)
    acceptor.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as connection:
            connection.sendall(b'GET / HTTP/1.0\r\n\r\n')
            assert started.wait(2)
            assert server.drain_requests(timeout=2) is clean
        assert 'private' not in capsys.readouterr().err
    finally:
        server.server_close()
        acceptor.join(timeout=2)
    assert not acceptor.is_alive()


@pytest.mark.parametrize('body_read', [False, True])
def test_normal_idle_peer_read_timeout_does_not_poison_shutdown(body_read):
    started = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(0.02)
            started.set()
        def do_GET(self):
            pytest.fail('idle peer did not submit an application request')
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
        def log_message(self, *args):
            pass
    class HTTPServer(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
        daemon_threads = True
    server = HTTPServer(('127.0.0.1', 0), Handler)
    acceptor = threading.Thread(target=server.handle_request)
    acceptor.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as connection:
            if body_read:
                connection.sendall(b'POST / HTTP/1.0\r\nContent-Length: 100\r\n\r\n')
            assert started.wait(2)
            assert server.drain_requests(timeout=2)
    finally:
        server.server_close()
        acceptor.join(timeout=2)
    assert not acceptor.is_alive()
