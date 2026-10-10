# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real loopback TCP probes for local and remote installer preflight."""

import ast
import errno
from pathlib import Path
import shlex
import socket
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import deploy, split_deploy
from iris_installer.state import InstallError


@pytest.fixture
def probe(request, monkeypatch):
    if request.param == 'local':
        return deploy.check_tcp_endpoint
    commands = []
    local_checks = []
    monkeypatch.setattr(split_deploy, 'validate_split_config', lambda _config: None)
    monkeypatch.setattr(split_deploy, 'check_tcp_endpoint', lambda host, port: local_checks.append((host, port)))
    monkeypatch.setattr(split_deploy.SplitDockerInstall, 'ssh_command', lambda _self, command: [command])
    split_deploy.preflight({'host': '192.0.2.1'}, runner=lambda command, **_kwargs: commands.append(command))
    assert local_checks == [('192.0.2.1', port) for port in (6969, 8443, 8000, 6881, 9101, 9443)]
    # Execute the actual socket section sent over SSH, without host setup,
    # sudo, credentials, or dependencies on the runner's existing services.
    remote = ast.parse(shlex.split(commands[0][0])[-1])
    socket_section = [node for node in remote.body if isinstance(node, ast.With)]
    assert len(socket_section) == 1
    code = compile(ast.Module(body=socket_section, type_ignores=[]), '<remote port probe>', 'exec')

    def remote_probe(host, port):
        exec(code, {'socket': socket, 'r': {'console_bind': host, 'console_port': port}})
    return remote_probe


@pytest.mark.parametrize('probe', ['local', 'remote'], indirect=True)
def test_closed_connection_time_wait_is_not_a_live_listener(probe):
    tcp_table = Path('/proc/net/tcp')
    if not tcp_table.exists():
        pytest.skip('This regression requires the Linux TCP state table')
    # Keep the listener apart from the source address chosen for concurrent
    # loopback clients elsewhere in the suite.
    host = '127.42.0.1'
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, 0))
        port = listener.getsockname()[1]
        listener.listen(1)
        with socket.create_connection((host, port), timeout=5) as client:
            connection, peer = listener.accept()
            with connection:
                connection.settimeout(5)
                connection.shutdown(socket.SHUT_WR)
                assert client.recv(1) == b''
                client.shutdown(socket.SHUT_WR)
                assert connection.recv(1) == b''
    # Closing Python's descriptors does not establish which TCP shutdown state
    # the kernel has reached. Observe this exact connection in TIME_WAIT before
    # asking the real product probe to accept it; never retry the product probe.
    def endpoint(address):
        return f'{int.from_bytes(socket.inet_aton(address[0]), sys.byteorder):08X}:{address[1]:04X}'

    local, remote = endpoint((host, port)), endpoint(peer)
    deadline = time.monotonic() + 5
    while True:
        rows = [line.split() for line in tcp_table.read_text().splitlines()[1:]]
        states = [row[3] for row in rows if row[1:3] == [local, remote]]
        if states == ['06']:
            break
        assert time.monotonic() < deadline, f'Test connection did not reach TIME_WAIT: {states}'
        time.sleep(0.01)
    # Reproduce the previous failure before testing the repaired preflight.
    with socket.socket() as plain:
        with pytest.raises(OSError) as error:
            plain.bind((host, port))
        assert error.value.errno == errno.EADDRINUSE
    probe(host, port)


@pytest.mark.parametrize('probe', ['local', 'remote'], indirect=True)
@pytest.mark.parametrize('host', ['127.0.0.1', '0.0.0.0'])
@pytest.mark.parametrize('reuse', [False, True])
def test_active_listener_is_rejected_and_still_works(probe, host, reuse):
    with socket.socket() as listener:
        if reuse:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, 0))
        port = listener.getsockname()[1]
        listener.listen(1)
        with pytest.raises((InstallError, OSError)):
            probe('127.0.0.1', port)
        with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
            connection, _ = listener.accept()
            with connection:
                connection.sendall(b'service preserved')
                assert client.recv(64) == b'service preserved'


def test_single_host_checks_every_published_endpoint(monkeypatch):
    seen = []
    monkeypatch.setattr(deploy, 'check_tcp_endpoint', lambda host, port: seen.append((host, port)))
    deploy.port_preflight({'host': '192.0.2.1', 'console_bind': '127.0.0.1', 'console_port': 18080})
    assert seen == [('192.0.2.1', port) for port in (6969, 8443, 8000, 6881, 9101)] + [('127.0.0.1', 18080)]
