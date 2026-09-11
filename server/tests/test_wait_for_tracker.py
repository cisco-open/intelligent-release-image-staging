# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The supervised seeder must wait for the tracker and remain cancellable."""

from contextlib import contextmanager
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
from types import SimpleNamespace

import pytest

import wait_for_tracker as gate


@pytest.fixture(autouse=True)
def restore_signal_handlers():
    previous = {number: signal.getsignal(number)
                for number in (signal.SIGTERM, signal.SIGINT)}
    yield
    for number, handler in previous.items():
        signal.signal(number, handler)


@contextmanager
def bound_tracker(*, listening=True):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        if listening:
            listener.listen()
        yield listener


def test_ready_tracker_accepts_a_connection_on_custom_port():
    with bound_tracker() as listener:
        assert gate.wait_for_tracker(*listener.getsockname(), timeout=1.0)
        listener.settimeout(1.0)
        connection, _ = listener.accept()
        connection.close()


@pytest.mark.parametrize("host", ["", "0.0.0.0"])
def test_wildcard_bind_is_probed_through_loopback(host):
    with bound_tracker() as listener:
        assert gate.wait_for_tracker(host, listener.getsockname()[1], timeout=1.0)
        listener.settimeout(1.0)
        connection, _ = listener.accept()
        connection.close()


def test_delayed_tracker_does_not_report_ready_before_listen(monkeypatch):
    first_failure = threading.Event()
    finished = threading.Event()
    result = []
    original_socket = socket.socket

    class ObservedSocket(original_socket):
        def connect(self, address):
            try:
                return super().connect(address)
            except OSError:
                first_failure.set()
                raise

    with bound_tracker(listening=False) as listener:
        monkeypatch.setattr(gate.socket, "socket", ObservedSocket)

        def wait():
            try:
                result.append(gate.wait_for_tracker(
                    *listener.getsockname(), timeout=3.0))
            finally:
                finished.set()

        worker = threading.Thread(target=wait)
        worker.start()
        try:
            assert first_failure.wait(2.0), "no refused connection was observed"
            assert not finished.is_set(), "tracker was declared ready before listen"
            listener.listen()
            assert finished.wait(3.0), "listener readiness was not detected"
            assert result == [True]
        finally:
            worker.join(timeout=4.0)
            assert not worker.is_alive()


def test_tracker_deadline_expires_when_bound_socket_is_not_listening():
    with bound_tracker(listening=False) as listener:
        started = time.monotonic()
        assert not gate.wait_for_tracker(*listener.getsockname(), timeout=0.05)
        assert time.monotonic() - started < 1.0


def test_hostname_resolution_uses_ipv4(monkeypatch):
    original_getaddrinfo = socket.getaddrinfo
    families = []

    def resolve(host, port, family=0, type=0, proto=0, flags=0):
        assert host == "tracker.test.invalid"
        families.append(family)
        return original_getaddrinfo("127.0.0.1", port, family, type, proto, flags)

    monkeypatch.setattr(gate.socket, "getaddrinfo", resolve)
    with bound_tracker() as listener:
        assert gate.wait_for_tracker(
            "tracker.test.invalid", listener.getsockname()[1], timeout=1.0)
    assert families and set(families) == {socket.AF_INET}


def test_hung_dns_is_bounded_by_deadline_and_runs_in_daemon(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    resolver_daemon = []

    def resolve(*args, **kwargs):
        resolver_daemon.append(threading.current_thread().daemon)
        entered.set()
        try:
            release.wait()
            return []
        finally:
            finished.set()

    monkeypatch.setattr(gate.socket, "getaddrinfo", resolve)
    started = time.monotonic()
    try:
        assert not gate.wait_for_tracker("tracker.test.invalid", 6969, timeout=0.05)
        assert time.monotonic() - started < 1.0
        assert entered.wait(3.0)
        assert resolver_daemon == [True]
        assert not finished.is_set()
    finally:
        release.set()
        assert finished.wait(3.0), "resolver test thread did not exit"


def test_dns_multiple_addresses_and_retries_share_one_deadline(monkeypatch):
    now = [0.0]
    attempts = []
    addresses = [("192.0.2.1", 6969), ("192.0.2.2", 6969)]

    def advance(seconds):
        now[0] += seconds

    def resolve(*args, **kwargs):
        advance(0.6)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", address)
                for address in addresses]

    class TimedOutSocket:
        def __init__(self, *args, **kwargs):
            self.timeout = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, address):
            attempts.append((address, self.timeout))
            advance(self.timeout)
            raise TimeoutError()

    monkeypatch.setattr(gate, "time", SimpleNamespace(
        monotonic=lambda: now[0], sleep=advance))
    monkeypatch.setattr(gate.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(gate.socket, "socket", TimedOutSocket)
    assert not gate.wait_for_tracker("tracker.test.invalid", 6969, timeout=1.4)
    assert [address for address, _ in attempts] == [*addresses, addresses[0]]
    assert [timeout for _, timeout in attempts] == pytest.approx([0.25, 0.25, 0.2])
    assert now[0] == pytest.approx(1.4)


class ExecCalled(BaseException):
    """Stand in for exec's successful replacement of the current process."""


@pytest.mark.parametrize(("configured_host", "configured_port", "expected"), [
    (None, None, ("0.0.0.0", 6969)),
    ("", "16969", ("", 16969)),
    ("0.0.0.0", "16970", ("0.0.0.0", 16970)),
    ("127.0.0.2", "16971", ("127.0.0.2", 16971)),
    ("tracker.test.invalid", "16972", ("tracker.test.invalid", 16972)),
])
def test_main_passes_bind_configuration_and_preserves_command_arguments(
        monkeypatch, configured_host, configured_port, expected):
    for name, value in (("IRIS_TRACKER_HOST", configured_host),
                        ("IRIS_TRACKER_PORT", configured_port)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    waits = []
    command = ["bash", "seed-launch.sh", "argument with spaces"]

    def wait(host, port, timeout=30.0):
        waits.append((host, port, timeout))
        return True

    def execute(binary, argv):
        assert binary == command[0]
        assert argv == command
        assert waits == [(*expected, 30.0)]
        raise ExecCalled

    monkeypatch.setattr(gate, "wait_for_tracker", wait)
    monkeypatch.setattr(gate.os, "execvp", execute)
    with pytest.raises(ExecCalled):
        gate.main(command)


def test_main_defaults_to_process_arguments(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["wait_for_tracker.py", "bash", "seed-launch.sh"])
    monkeypatch.delenv("IRIS_TRACKER_PORT", raising=False)
    monkeypatch.setattr(gate, "wait_for_tracker", lambda *args, **kwargs: True)

    def execute(binary, argv):
        assert binary == "bash"
        assert argv == ["bash", "seed-launch.sh"]
        raise ExecCalled

    monkeypatch.setattr(gate.os, "execvp", execute)
    with pytest.raises(ExecCalled):
        gate.main()


def test_main_rejects_missing_command_before_waiting(monkeypatch, capsys):
    def unexpected_wait(*args, **kwargs):
        pytest.fail("a missing command must be rejected before waiting")

    monkeypatch.setattr(gate, "wait_for_tracker", unexpected_wait)
    assert gate.main([]) != 0
    captured = capsys.readouterr()
    assert captured.err.strip()
    assert not captured.out
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("port", ["invalid-port-marker", "0", "65536", "-1"])
def test_main_rejects_invalid_port_without_echoing_configuration(
        monkeypatch, capsys, port):
    monkeypatch.setenv("IRIS_TRACKER_PORT", port)
    monkeypatch.setenv("IRIS_TRACKER_HOST", "private-host-marker")

    def unexpected_wait(*args, **kwargs):
        pytest.fail("an invalid port must be rejected before waiting")

    monkeypatch.setattr(gate, "wait_for_tracker", unexpected_wait)
    assert gate.main(["bash", "seed-launch.sh"]) != 0
    captured = capsys.readouterr()
    assert captured.err.strip()
    assert not captured.out
    assert "invalid-port-marker" not in captured.err
    assert "private-host-marker" not in captured.err
    assert "Traceback" not in captured.err


def test_main_timeout_never_executes_child(monkeypatch, capsys):
    monkeypatch.delenv("IRIS_TRACKER_PORT", raising=False)
    monkeypatch.setenv("IRIS_TRACKER_HOST", "private-host-marker")
    monkeypatch.setattr(gate, "wait_for_tracker", lambda *args, **kwargs: False)

    def unexpected_exec(*args):
        pytest.fail("the seeder must not launch after the readiness deadline")

    monkeypatch.setattr(gate.os, "execvp", unexpected_exec)
    assert gate.main(["bash", "seed-launch.sh", "private-argument-marker"]) != 0
    captured = capsys.readouterr()
    assert captured.err.strip()
    assert not captured.out
    assert "private-host-marker" not in captured.err
    assert "private-argument-marker" not in captured.err
    assert "Traceback" not in captured.err


def test_main_exec_failure_has_fixed_diagnostic(monkeypatch, capsys):
    monkeypatch.delenv("IRIS_TRACKER_PORT", raising=False)
    monkeypatch.setattr(gate, "wait_for_tracker", lambda *args, **kwargs: True)
    diagnostics = []
    for marker in ("first-private-exception-marker", "second-private-exception-marker"):
        def failed_exec(*args):
            raise OSError(marker)

        monkeypatch.setattr(gate.os, "execvp", failed_exec)
        assert gate.main([marker, "private-argument-marker"]) != 0
        captured = capsys.readouterr()
        assert captured.err.strip()
        assert not captured.out
        assert marker not in captured.err
        assert "private-argument-marker" not in captured.err
        assert "Traceback" not in captured.err
        diagnostics.append(captured.err)
    assert diagnostics[0] == diagnostics[1]


@contextmanager
def helper_process(driver, *, port=6969):
    environment = {
        "PATH": os.defpath,
        "PYTHONPATH": str(Path(gate.__file__).resolve().parent),
        "IRIS_TRACKER_HOST": "127.0.0.1",
        "IRIS_TRACKER_PORT": str(port),
    }
    process = subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(driver)],
        env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5.0)


def read_marker(process, *, timeout=5.0):
    """Read one flushed marker without an unbounded readline on a failed child."""
    deadline = time.monotonic() + timeout
    data = b""
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while b"\n" not in data:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "child did not publish its readiness marker"
            assert selector.select(remaining), "child readiness marker timed out"
            chunk = os.read(process.stdout.fileno(), 4096)
            assert chunk, "child exited before publishing its readiness marker"
            data += chunk
    return data


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGINT])
def test_signal_during_wait_exits_immediately_and_never_launches_child(number):
    driver = """
        import os
        import signal
        import sys
        import wait_for_tracker as gate

        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        def wait(*args, **kwargs):
            os.write(1, b"waiting\\n")
            while True:
                signal.pause()

        gate.wait_for_tracker = wait
        gate.main([sys.executable, "-c", "print('unexpected-exec')"])
    """
    with helper_process(driver) as process:
        assert read_marker(process) == b"waiting\n"
        process.send_signal(number)
        output, error = process.communicate(timeout=3.0)
        assert process.returncode == -number
        assert output == b""
        assert error == b""


def test_sigterm_while_dns_is_blocked_exits_without_waiting_for_resolver():
    driver = """
        import os
        import signal
        import sys
        import threading
        import wait_for_tracker as gate

        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        os.environ["IRIS_TRACKER_HOST"] = "tracker.test.invalid"

        def resolve(*args, **kwargs):
            os.write(1, b"resolving\\n")
            threading.Event().wait()

        gate.socket.getaddrinfo = resolve
        gate.main([sys.executable, "-c", "print('unexpected-exec')"])
    """
    with helper_process(driver) as process:
        assert read_marker(process) == b"resolving\n"
        process.send_signal(signal.SIGTERM)
        output, error = process.communicate(timeout=3.0)
        assert process.returncode == -signal.SIGTERM
        assert output == b""
        assert error == b""


def test_actual_exec_preserves_supervised_pid_and_sigterm():
    driver = """
        import sys
        import wait_for_tracker as gate

        child = ("import os,signal; "
                 "os.write(1, (str(os.getpid()) + chr(10)).encode()); "
                 "signal.pause()")
        sys.exit(gate.main([sys.executable, "-c", child]))
    """
    with bound_tracker() as listener:
        with helper_process(driver, port=listener.getsockname()[1]) as process:
            assert read_marker(process) == (str(process.pid) + "\n").encode()
            process.send_signal(signal.SIGTERM)
            output, error = process.communicate(timeout=3.0)
            assert process.returncode == -signal.SIGTERM
            assert output == b""
            assert error == b""
