# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Clean-stop proof waits for real HTTP callbacks and background writers."""
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

import pytest

import artifact_server
import service_shutdown
import telemetry
import tracker


def test_drain_fences_all_listeners_before_request_or_writer_drain():
    calls = []

    class Server:
        def __init__(self, name):
            self.name = name

        def stop_request_admission(self):
            calls.append((self.name, "fence"))

        def shutdown(self):
            calls.append((self.name, "accept-stop"))

        def drain_requests(self, timeout):
            assert timeout > 0
            calls.append((self.name, "requests"))
            return True

        def server_close(self):
            calls.append((self.name, "close"))

    def writer(timeout):
        calls.append(("background", "writer"))
        return True

    assert service_shutdown.drain([Server("a"), Server("b")], [writer])
    assert calls == [("a", "fence"), ("b", "fence"),
                     ("a", "accept-stop"), ("b", "accept-stop"),
                     ("a", "requests"), ("b", "requests"),
                     ("background", "writer"),
                     ("a", "close"), ("b", "close")]


def test_drain_has_one_deadline_even_for_broken_callbacks():
    release = threading.Event()
    started = time.monotonic()
    try:
        assert not service_shutdown.drain(
            [], [lambda _left: release.wait(), lambda _left: release.wait()],
            timeout=0.12)
        assert time.monotonic() - started < 0.5
    finally:
        release.set()


@pytest.mark.parametrize("result", [None, False, 1])
def test_writer_must_explicitly_confirm_completion(result):
    assert not service_shutdown.drain([], [lambda _left: result])


def test_callback_exception_is_not_a_clean_stop():
    def broken(_left):
        raise RuntimeError("writer failed")

    assert not service_shutdown.drain([], [broken])


@pytest.mark.parametrize("crash", [True, False])
def test_dead_writer_cannot_be_laundered_by_later_stop(crash):
    stop = threading.Event()

    def work():
        if crash:
            raise RuntimeError("abnormal termination")

    thread = service_shutdown.WriterThread(target=work, stop_event=stop, daemon=True)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert service_shutdown.stop_thread(thread, stop, 1) is False


def test_writer_exception_during_requested_shutdown_is_not_clean():
    stop = threading.Event()

    def work():
        stop.wait()
        raise RuntimeError("failed while finishing write")

    thread = service_shutdown.WriterThread(target=work, stop_event=stop, daemon=True)
    thread.start()
    assert service_shutdown.stop_thread(thread, stop, 1) is False


@pytest.mark.parametrize("crash", [True, False])
def test_failed_listener_cannot_claim_clean_shutdown(crash):
    class Server:
        def serve_forever(self):
            if crash:
                raise RuntimeError("accept loop failed")

        def stop_request_admission(self):
            pass

        def shutdown(self):
            pass

        def drain_requests(self, timeout):
            return True

        def server_close(self):
            pass

    before = signal.getsignal(signal.SIGTERM)
    assert service_shutdown.serve([Server()], timeout=1) == 1
    assert signal.getsignal(signal.SIGTERM) is before


@pytest.mark.parametrize("kind", ["sweeper", "pruner", "telemetry", "reconciler"])
def test_background_stop_waits_for_active_work_and_reports_timeout(kind, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    stop = threading.Event()

    def write(*_args):
        entered.set()
        release.wait(5)

    if kind == "sweeper":
        monkeypatch.setattr(artifact_server, "sweep_staging", write)
        thread = artifact_server.start_sweeper("unused", stop_event=stop)
        finish = lambda timeout: service_shutdown.stop_thread(thread, stop, timeout)
    elif kind == "pruner":
        registry = type("Registry", (), {"prune_all": write})()
        thread = tracker._start_pruner(registry, stop)
        finish = lambda timeout: service_shutdown.stop_thread(thread, stop, timeout)
    else:
        if kind == "telemetry":
            worker = telemetry.Telemetry.__new__(telemetry.Telemetry)
            worker.run_forever = write
        else:
            worker = tracker.TrackerReconciler.__new__(tracker.TrackerReconciler)
            worker._loop = write
            worker._wake = threading.Event()
        worker._stop = stop
        worker._thread = None
        worker.start()
        finish = worker.stop
    try:
        assert entered.wait(2)
        assert finish(0.02) is False
        assert stop.is_set()
    finally:
        release.set()
    assert finish(2) is True


_PROCESS = r'''
import os, pathlib, socket, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import bounded_pool, service_shutdown

root = pathlib.Path(sys.argv[1])
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        (root / 'active').write_text('request')
        while not (root / 'release').exists():
            time.sleep(.01)
        (root / 'complete').write_text('durable result')
    def log_message(self, *args):
        pass
class Server(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
    daemon_threads = True
server = Server(('127.0.0.1', 0), Handler)
(root / 'port').write_text(str(server.server_port))
sys.exit(service_shutdown.serve([server], timeout=float(sys.argv[2])))
'''


def _wait_file(path, process):
    deadline = time.monotonic() + 5
    while not path.exists():
        assert process.poll() is None
        assert time.monotonic() < deadline
        time.sleep(0.01)


@pytest.mark.parametrize("complete", [True, False])
def test_sigterm_proves_request_write_completed_or_exits_nonzero(tmp_path, complete):
    env = dict(os.environ, PYTHONPATH=str(Path(service_shutdown.__file__).parent))
    process = subprocess.Popen([sys.executable, "-c", _PROCESS, str(tmp_path),
                                "2" if complete else "0.2"], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    connection = None
    try:
        _wait_file(tmp_path / "port", process)
        connection = socket.create_connection(
            ("127.0.0.1", int((tmp_path / "port").read_text())), timeout=3)
        connection.sendall(b"GET / HTTP/1.0\r\n\r\n")
        _wait_file(tmp_path / "active", process)
        process.send_signal(signal.SIGTERM)
        if complete:
            time.sleep(0.15)
            assert process.poll() is None
            (tmp_path / "release").write_text("finish")
        _, stderr = process.communicate(timeout=5)
        assert process.returncode == (0 if complete else 1), stderr.decode()
        assert (tmp_path / "complete").exists() is complete
    finally:
        if connection:
            connection.close()
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
