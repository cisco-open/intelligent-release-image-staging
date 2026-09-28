# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real mutual-TLS worker transport rejects untrusted peers and unsafe RPC."""

import http.client
import json
from pathlib import Path
import ssl
import socket
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import lifecycle_network as network
from iris_installer.state import InstallError
import lifecycle_client


def runner(command, capture=False):
    result = subprocess.run(command, capture_output=True, check=True)
    return result.stdout if capture else b''


@pytest.fixture(scope='module')
def custody(tmp_path_factory):
    base = tmp_path_factory.mktemp('worker-tls')
    return network.prepare_network_custody(base, 'https://127.0.0.1:18443', runner)


@pytest.mark.parametrize('url', ['http://worker:8443', 'https://u:p@worker:8443',
    'https://worker', 'https://worker:443', 'https://worker:8443/path',
    'https://worker:8443/?secret=x', 'https://0.0.0.0:8443',
    'https://worker\n.invalid:8443', 'https://-flag:8443', 'https://[::1]:8443'])
def test_rejects_unsafe_endpoint(url):
    with pytest.raises(InstallError):
        network.endpoint(url)


def test_custody_is_stable_and_private(custody):
    before = {name: path.read_bytes() for name, path in custody.items()}
    again = network.prepare_network_custody(custody['ca.key'].parent.parent,
                                            'https://127.0.0.1:18443', runner)
    assert before == {name: path.read_bytes() for name, path in again.items()}
    for name in ('ca.key', 'worker.key', 'client.key'):
        assert custody[name].stat().st_mode & 0o777 == 0o600
    with pytest.raises(InstallError, match='changed'):
        network.prepare_network_custody(custody['ca.key'].parent.parent,
                                       'https://127.0.0.2:18443', runner)


@pytest.fixture
def service(custody):
    class Worker:
        def status(self):
            return {'available': True, 'target': 'kubernetes'}
        def rotation_status(self):
            return {'available': True, 'families': ['management-tls']}
        def submit(self, request):
            raise InstallError('private-path-must-not-escape')
    server = network.make_https_server('127.0.0.1', 0, Worker(), custody)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def client(custody, port, authenticated=True):
    context = ssl.create_default_context(cafile=str(custody['ca.crt']))
    if authenticated:
        context.load_cert_chain(str(custody['client.crt']), str(custody['client.key']))
    return http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=5)


def test_actual_authenticated_network_client(custody, service, monkeypatch):
    monkeypatch.setenv('IRIS_LIFECYCLE_URL', 'https://127.0.0.1:' + str(service))
    for variable, name in (('CA', 'ca.crt'), ('CERT', 'client.crt'), ('KEY', 'client.key')):
        monkeypatch.setenv('IRIS_LIFECYCLE_' + variable, str(custody[name]))
    assert lifecycle_client.call({'action': 'status'}) == {'available': True, 'target': 'kubernetes'}
    assert lifecycle_client.call({'action': 'rotation-status'})['families'] == ['management-tls']
    monkeypatch.delenv('IRIS_LIFECYCLE_KEY')
    with pytest.raises(lifecycle_client.LifecycleUnavailable):
        lifecycle_client.call({'action': 'status'})


def test_no_client_certificate_cannot_reach_worker(custody, service):
    connection = client(custody, service, authenticated=False)
    try:
        with pytest.raises((ssl.SSLError, OSError, http.client.HTTPException)):
            connection.request('POST', '/v1/lifecycle', json.dumps({'action': 'status'}))
            connection.getresponse()
    finally:
        connection.close()


def test_idle_unauthenticated_peer_does_not_block_real_client(custody, service):
    stalled = socket.create_connection(('127.0.0.1', service), timeout=2)
    connection = client(custody, service)
    connection.timeout = 2
    try:
        connection.request('POST', '/v1/lifecycle', json.dumps({'action': 'status'}))
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())['result']['available']
    finally:
        stalled.close()
        connection.close()


@pytest.mark.parametrize('body,path', [(b'{}', '/elsewhere'), (b'x' * 4097, '/v1/lifecycle'),
                                       (b'[]', '/v1/lifecycle'), (b'{"action":"shell"}', '/v1/lifecycle')])
def test_bounded_rpc_rejects_unsafe_requests_without_details(custody, service, body, path):
    connection = client(custody, service)
    try:
        connection.request('POST', path, body)
        response = connection.getresponse()
        assert response.status == 400
        result = response.read()
        assert b'private-path' not in result
        assert json.loads(result)['ok'] is False
    finally:
        connection.close()
