# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Real network-worker deadlines, including hidden HTTP protocol reads."""
import contextlib
import http.server
from pathlib import Path
import subprocess
import threading
import time

import pytest

import bulkhash


def _birth(pid):
    try:
        return int(Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
    except (FileNotFoundError, ProcessLookupError):
        return None


@pytest.fixture
def owned_children(monkeypatch):
    """Observe real children; do not replace or reap the production worker."""
    original = subprocess.Popen
    observed = []

    def capture(*args, **kwargs):
        child = original(*args, **kwargs)
        observed.append((child, _birth(child.pid), args[0] if args else kwargs["args"]))
        return child

    monkeypatch.setattr(subprocess, "Popen", capture)
    try:
        yield observed
    finally:
        # A failing regression must not strand its test-owned child in CI.
        # Assertions below run before this emergency test-only cleanup.
        for child, birth, _argv in observed:
            if child.returncode is None and _birth(child.pid) == birth:
                child.kill()
                child.wait(timeout=3)


def _assert_reaped(observed):
    assert len(observed) == 1, "One actual network worker is required"
    child, birth, _argv = observed[0]
    assert child.returncode is not None, "fetch returned without reaping its worker"
    assert birth is not None and _birth(child.pid) != birth


@contextlib.contextmanager
def _server(mode):
    stop = threading.Event()
    entered = threading.Event()
    sent = []
    payload = b"complete feed transport fixture"

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def send_bytes(self, value):
            self.wfile.write(value)
            self.wfile.flush()
            sent.append(len(value))

        def trickle(self):
            while not stop.wait(0.03):
                self.send_bytes(b"a")

        def do_GET(self):
            entered.set()
            try:
                if mode == "headers":
                    self.send_bytes(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    self.trickle()
                    return
                if mode == "error":
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                if mode in {"chunk-body", "chunk-size", "trailers", "chunked-success"}:
                    self.send_header("Transfer-Encoding", "chunked")
                elif mode in {"body", "length-success"}:
                    self.send_header("Content-Length", str(len(payload) if mode == "length-success" else 1000000))
                else:
                    self.send_header("Connection", "close")
                self.end_headers()
                if mode == "chunk-body":
                    self.send_bytes(b"f4240\r\n")
                elif mode == "trailers":
                    self.send_bytes(b"1\r\nx\r\n0\r\nX-Slow-Trailer: ")
                elif mode == "length-success":
                    self.send_bytes(payload)
                    return
                elif mode == "chunked-success":
                    self.send_bytes(f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n")
                    return
                # chunk-size deliberately never finishes its first size line.
                # no-length-body never closes before the parent deadline.
                self.trickle()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                self.close_connection = True

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/feed", entered, sent, payload
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize("mode", ["headers", "body", "no-length-body", "chunk-body", "chunk-size", "trailers"])
@pytest.mark.parametrize("prior_good_file", [False, True])
def test_total_deadline_interrupts_real_trickled_http(
        tmp_path, owned_children, mode, prior_good_file):
    destination = tmp_path / "feed.tar"
    prior = b"previous verified feed must survive"
    if prior_good_file:
        destination.write_bytes(prior)
    with _server(mode) as (url, entered, sent, _payload):
        started = time.monotonic()
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.fetch(url, timeout=3, out_path=str(destination), total_timeout=0.8)
        elapsed = time.monotonic() - started
        assert entered.is_set() and len(sent) >= 3, "The actual HTTP trickle must start before its deadline"
        assert elapsed < 2.5, "Socket activity must not renew the total deadline"
        _assert_reaped(owned_children)
        if prior_good_file:
            assert destination.read_bytes() == prior
        else:
            assert not destination.exists()
        assert sorted(path.name for path in tmp_path.iterdir()) == (["feed.tar"] if prior_good_file else [])


@pytest.mark.parametrize("mode", ["length-success", "chunked-success"])
def test_finite_network_worker_preserves_successful_http_contract(
        tmp_path, owned_children, mode):
    destination = tmp_path / "feed.tar"
    with _server(mode) as (url, entered, _sent, payload):
        assert bulkhash.fetch(url, timeout=3, out_path=str(destination), total_timeout=3) == str(destination)
        assert entered.is_set() and destination.read_bytes() == payload
        _assert_reaped(owned_children)
        assert list(tmp_path.iterdir()) == [destination]


def test_total_deadline_reaps_real_worker_blocked_in_dns(
        tmp_path, monkeypatch, owned_children):
    # Inject only a non-returning resolver into the actual fresh interpreter.
    # The original worker parser, urllib opener, TLS context, descriptor and
    # parent timeout/kill/wait path remain in use. No external DNS is queried.
    marker = b"TEST-DNS-ENTERED"
    prefix = """import socket,sys,time
def blocked_dns(*args, **kwargs):
    sys.stdout.buffer.write(b'TEST-DNS-ENTERED');sys.stdout.buffer.flush()
    time.sleep(60)
socket.getaddrinfo=blocked_dns
"""
    monkeypatch.setattr(bulkhash, "_FETCH_WORKER", prefix + bulkhash._FETCH_WORKER)
    destination = tmp_path / "feed.tar"
    prior = b"previous verified feed"
    destination.write_bytes(prior)
    started = time.monotonic()
    with pytest.raises(bulkhash.BulkHashError, match="total download deadline") as raised:
        bulkhash.fetch("https://dns-fixture.invalid/feed", timeout=3,
                       out_path=str(destination), total_timeout=0.8)
    assert time.monotonic() - started < 2.5
    assert isinstance(raised.value.__cause__, subprocess.TimeoutExpired)
    assert marker in (raised.value.__cause__.output or b""), "The actual resolver must block before timeout"
    _assert_reaped(owned_children)
    assert destination.read_bytes() == prior
    assert list(tmp_path.iterdir()) == [destination]


def test_worker_url_and_proxy_canaries_never_enter_argv_or_failure(
        tmp_path, monkeypatch, owned_children):
    url_canary = "synthetic-url-secret-do-not-log"
    proxy_canary = "synthetic-proxy-secret-do-not-log"
    monkeypatch.setenv("http_proxy", f"http://user:{proxy_canary}@127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    destination = tmp_path / "feed.tar"
    prior = b"old verified feed"
    destination.write_bytes(prior)
    with _server("error") as (url, entered, _sent, _payload):
        with pytest.raises(bulkhash.BulkHashError) as raised:
            bulkhash.fetch(url + "?token=" + url_canary, timeout=3,
                           out_path=str(destination), total_timeout=3)
        assert entered.is_set()
        _assert_reaped(owned_children)
        argv = repr(owned_children[0][2])
        assert url_canary not in argv and proxy_canary not in argv
        assert url_canary not in str(raised.value) and proxy_canary not in str(raised.value)
        assert destination.read_bytes() == prior
        assert list(tmp_path.iterdir()) == [destination]
